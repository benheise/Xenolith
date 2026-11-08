// Package detect runs the detection layers over an unpacked artifact and merges
// their findings into one component list with evidence and confidence.
package detect

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	_ "modernc.org/sqlite" // Syft needs a registered sqlite driver for newer RPM databases

	"github.com/benheise/Xenolith/scan/internal/fingerprint"
	"github.com/benheise/Xenolith/scan/internal/notices"
	"github.com/benheise/Xenolith/scan/internal/unpack"
)

// Component is one detected third-party component after merging all layers.
type Component struct {
	Name       string   `json:"name"`
	Group      string   `json:"group,omitempty"`
	Version    string   `json:"version,omitempty"`
	Type       string   `json:"type"`
	PURL       string   `json:"purl,omitempty"`
	CPE        string   `json:"cpe,omitempty"`
	Watchlist  string   `json:"watchlist,omitempty"` // Xenolith component id when a fingerprint matched
	Confidence float64  `json:"confidence"`
	Techniques []string `json:"techniques"`
	FoundBy    []string `json:"found_by"`
	Locations  []string `json:"locations"`
	Evidence   []string `json:"evidence,omitempty"`
	Notes      []string `json:"notes,omitempty"`
	Keep       *bool    `json:"keep,omitempty"` // set by `review`
}

// Engine records a tool that contributed findings.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Report is the full local result.
type Report struct {
	Components   []Component       `json:"components"`
	Engines      []Engine          `json:"engines"`
	Distro       string            `json:"distro,omitempty"`
	ImageLabels  map[string]string `json:"image_labels,omitempty"`
	Skipped      []string          `json:"skipped"`
	Log          []string          `json:"log"`
	Duration     string            `json:"duration"`
	SyftPackages int               `json:"syft_packages"`
}

// Options configure a detection run.
type Options struct {
	Pack        *fingerprint.Pack
	SyftVersion string
	ToolVersion string
	Log         func(string)
	Parallelism int
}

// Run runs Syft, the fingerprint pack and the notices-file parser over every tree.
func Run(ctx context.Context, res *unpack.Result, opts Options) (*Report, error) {
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	start := time.Now()
	rep := &Report{Engines: []Engine{{Name: "syft", Version: opts.SyftVersion}, {Name: "xenolith-fingerprint", Version: fmt.Sprintf("pack-v%d", opts.Pack.Version)}}}
	var all []Component

	for _, tree := range res.Trees {
		s, err := runSyft(ctx, tree, opts.Parallelism)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: syft: %v", treeLabel(res, tree), err))
			continue
		}
		if s.Artifacts.LinuxDistribution != nil && rep.Distro == "" {
			rep.Distro = strings.TrimSpace(s.Artifacts.LinuxDistribution.PrettyName)
			if rep.Distro == "" {
				rep.Distro = strings.TrimSpace(s.Artifacts.LinuxDistribution.Name + " " + s.Artifacts.LinuxDistribution.Version)
			}
		}
		n, declared := 0, 0
		for p := range s.Artifacts.Packages.Enumerate() {
			n++
			if declaredByLibrary(p) {
				declared++
				continue
			}
			all = append(all, fromSyft(p, tree, res))
		}
		if declared > 0 {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: %d dependencies declared in the pom.xml of bundled libraries ignored (what a library was built against, often test-only; bundled jars are listed from their own metadata)", treeLabel(res, tree), declared))
		}
		rep.SyftPackages += n
		opts.Log(fmt.Sprintf("syft: %d packages in %s", n, tree))
	}

	fs := fingerprint.New(opts.Pack)
	for _, tree := range res.Trees {
		fs.ScanTree(tree, res.Locate)
	}
	for _, g := range fingerprint.Summarize(fs.Findings) {
		all = append(all, fromFingerprint(g))
	}
	rep.Skipped = append(rep.Skipped, fs.Skipped...)
	opts.Log(fmt.Sprintf("fingerprints: %d findings", len(fs.Findings)))

	var noticeFiles int
	for _, tree := range res.Trees {
		found, nskipped := notices.Scan(tree, res.Locate)
		rep.Skipped = append(rep.Skipped, nskipped...)
		for _, nf := range found {
			noticeFiles++
			for _, c := range nf.Components {
				all = append(all, Component{
					Name: c.Name, Version: c.Version, Type: "library", Confidence: 0.75,
					Techniques: []string{"manifest-analysis"}, FoundBy: []string{"notices-file"},
					Locations: []string{nf.Location}, Evidence: []string{c.Evidence},
					Notes: []string{"listed in a notices file shipped inside the product (" + nf.Format + ")"},
				})
			}
		}
	}
	if noticeFiles > 0 {
		opts.Log(fmt.Sprintf("notices files inside the product: %d", noticeFiles))
	}

	rep.Components = merge(all)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	return rep, nil
}

func runSyft(ctx context.Context, tree string, parallelism int) (s *sbom.SBOM, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			s, err = nil, fmt.Errorf("syft crashed (please report): %v", rec)
		}
	}()
	src, err := directorysource.NewFromPath(tree)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig().WithoutFiles()
	archive := cataloging.DefaultArchiveSearchConfig()
	archive.IncludeIndexedArchives, archive.IncludeUnindexedArchives = true, false // tars were already unpacked
	cfg = cfg.WithArchiveConfig(archive)
	cfg = cfg.WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("directory"))
	if parallelism > 0 {
		cfg = cfg.WithParallelism(parallelism)
	}
	return syft.CreateSBOM(ctx, src, cfg)
}

// RunImage catalogs a container image reference with Syft alone (the image is not
// unpacked to disk, so the fingerprint layer does not run on it).
func RunImage(ctx context.Context, ref string, opts Options) (*Report, source.Description, error) {
	start := time.Now()
	src, err := syft.GetSource(ctx, ref, syft.DefaultGetSourceConfig())
	if err != nil {
		return nil, source.Description{}, err
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig().WithoutFiles()
	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, source.Description{}, err
	}
	rep := &Report{Engines: []Engine{{Name: "syft", Version: opts.SyftVersion}}}
	var all []Component
	for p := range s.Artifacts.Packages.Enumerate() {
		rep.SyftPackages++
		if declaredByLibrary(p) {
			continue
		}
		all = append(all, fromSyft(p, "", nil))
	}
	if s.Artifacts.LinuxDistribution != nil {
		rep.Distro = s.Artifacts.LinuxDistribution.PrettyName
	}
	if im, ok := s.Source.Metadata.(source.ImageMetadata); ok {
		rep.ImageLabels = im.Labels
	}
	rep.Skipped = append(rep.Skipped, "container image: fingerprint and notices layers run only on unpacked files; package catalogers covered the image")
	rep.Components = merge(all)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	return rep, s.Source, nil
}

// catalogerConfidence rates Syft's catalogers: installed-package databases and
// embedded build info are high; declared manifests (lock files) say what a build
// asked for, not what shipped; the binary classifiers read version strings.
func catalogerConfidence(foundBy string) (float64, string, string) {
	f := strings.ToLower(foundBy)
	switch {
	case strings.Contains(f, "binary-classifier"):
		return 0.8, "binary-analysis", ""
	case strings.Contains(f, "elf-binary-package"), strings.Contains(f, "pe-binary"), strings.Contains(f, "portable-executable"),
		strings.Contains(f, "go-module-binary"), strings.Contains(f, "cargo-auditable"), strings.Contains(f, "dotnet-deps"),
		strings.Contains(f, "dotnet-portable"):
		return 0.9, "binary-analysis", ""
	case strings.Contains(f, "lock"), strings.Contains(f, "requirements"), strings.Contains(f, "pipfile"), strings.Contains(f, "pom-cataloger"),
		strings.Contains(f, "go-module-file"), strings.Contains(f, "gemfile"), strings.Contains(f, "package-json"), strings.Contains(f, "cargo-toml"),
		strings.Contains(f, "pubspec"), strings.Contains(f, "composer-json"), strings.Contains(f, "gradle"), strings.Contains(f, "mix-lock"):
		return 0.7, "manifest-analysis", "declared in a manifest found in the artifact; not necessarily installed"
	case strings.Contains(f, "-db-cataloger"), strings.Contains(f, "installed"), strings.Contains(f, "archive-cataloger"),
		strings.Contains(f, "sbom-cataloger"), strings.Contains(f, "egg"), strings.Contains(f, "wheel"), strings.Contains(f, "gem-spec"),
		strings.Contains(f, "conan-info"), strings.Contains(f, "nix"), strings.Contains(f, "snap"), strings.Contains(f, "homebrew"):
		return 0.9, "manifest-analysis", ""
	}
	return 0.8, "manifest-analysis", ""
}

func fromSyft(p pkg.Package, tree string, res *unpack.Result) Component {
	conf, technique, note := catalogerConfidence(p.FoundBy)
	c := Component{
		Name: p.Name, Version: p.Version, Type: "library", PURL: p.PURL, Confidence: conf,
		Techniques: []string{technique}, FoundBy: []string{"syft:" + p.FoundBy},
	}
	if unresolved(c.Version) {
		// Syft reports "UNKNOWN" (or the raw ${property}) when a pom declares a dependency
		// whose version is managed elsewhere; that is no version at all.
		c.PURL = strings.Replace(c.PURL, "@"+c.Version, "", 1)
		c.Version = ""
	}
	if c.Version == "" && note != "" {
		// a dependency a manifest declares, with no version, is not evidence anything
		// shipped: keep it as a lead below the submission threshold
		c.Confidence = 0.5
		note = "declared in a manifest found in the artifact, without a resolved version; not evidence it shipped"
	}
	if strings.Contains(p.FoundBy, "pe-binary") {
		c.Name, c.Version = peName(c.Name), peVersion(c.Version)
	}
	if c.Version == "" && (strings.Contains(p.FoundBy, "pe-binary") || strings.Contains(p.FoundBy, "elf-binary")) {
		// a DLL or ELF file named by its file name, with no version resource or package
		// note: presence of something, not an identified component
		c.Confidence = 0.6
		note = "binary without version information; named from the file"
	}
	if p.Type == pkg.LinuxKernelModulePkg && c.Version == "" {
		// in-tree modules have no version of their own: they are the kernel, which is
		// listed separately; keep them as leads rather than one submission line per .ko
		c.Confidence = 0.6
		note = "kernel module without a version of its own (in-tree modules are part of the kernel)"
		if meta, ok := p.Metadata.(pkg.LinuxKernelModule); ok && meta.KernelVersion != "" {
			note += "; built for kernel " + meta.KernelVersion
		}
	}
	if meta, ok := p.Metadata.(pkg.JavaArchive); ok {
		if meta.PomProperties != nil && meta.PomProperties.GroupID != "" {
			c.Group = meta.PomProperties.GroupID
		} else if n := jarFileArtifact(p); n != "" {
			c.PURL = strings.Replace(c.PURL, "/"+c.Name+"@", "/"+n+"@", 1)
			c.Name = n
		}
	}
	if len(p.CPEs) > 0 {
		c.CPE = p.CPEs[0].Attributes.String()
	}
	switch p.Type {
	case pkg.DebPkg, pkg.RpmPkg, pkg.ApkPkg, pkg.PortagePkg, pkg.AlpmPkg, pkg.NixPkg:
		c.Type = "library"
	case pkg.BinaryPkg:
		c.Type = "library"
	}
	for _, l := range p.Locations.ToSlice() {
		loc := l.RealPath
		if res != nil && tree != "" {
			loc = res.Locate(filepath.Join(tree, filepath.FromSlash(l.RealPath)))
		}
		if l.AccessPath != "" && l.AccessPath != l.RealPath && strings.Contains(l.AccessPath, ":") {
			// Syft renders members of archives it opened itself as outer:inner.
			loc = loc + "!/" + strings.SplitN(l.AccessPath, ":", 2)[1]
		}
		c.Locations = appendUnique(c.Locations, loc)
	}
	if note != "" {
		c.Notes = append(c.Notes, note)
	}
	return c
}

// jarFileArtifact: without pom.properties Syft names a jar from its OSGi symbolic name
// (io.zipkin.brave.context-slf4j -> "context-slf4j"). Maven names the file
// artifactId-version.jar, so when the file name is <something>-<syft name>-<version>.jar
// the longer name is the artifact id.
func jarFileArtifact(p pkg.Package) string {
	if p.Name == "" || p.Version == "" {
		return ""
	}
	for _, l := range p.Locations.ToSlice() {
		// Syft reports a jar it opened inside another archive as outer.jar:inner/path.jar
		for _, where := range []string{l.RealPath, l.AccessPath[strings.LastIndex(l.AccessPath, ":")+1:]} {
			base := path.Base(filepath.ToSlash(where))
			stem, ok := strings.CutSuffix(base, "-"+p.Version+".jar")
			if ok && strings.HasSuffix(stem, "-"+p.Name) && len(stem) > len(p.Name)+1 {
				return stem
			}
		}
	}
	return ""
}

// treeLabel names an extracted tree in messages: its logical location, or "artifact"
// for the top-level work directory (which has no location of its own).
func treeLabel(res *unpack.Result, tree string) string {
	if loc := res.Locate(tree); loc != "" && !filepath.IsAbs(filepath.FromSlash(loc)) {
		return loc
	}
	return "artifact"
}

// declaredByLibrary reports a dependency Syft read from the pom.xml a library ships in
// META-INF/maven/: what that library declared (junit, h2, an old log4j in test scope),
// not what the product contains. Jars that are bundled are found from their own
// pom.properties and manifests.
func declaredByLibrary(p pkg.Package) bool {
	if !strings.Contains(p.FoundBy, "pom-cataloger") {
		return false
	}
	locs := p.Locations.ToSlice()
	if len(locs) == 0 {
		return false
	}
	for _, l := range locs {
		if !strings.Contains(l.AccessPath, "META-INF/maven/") && !strings.Contains(l.RealPath, "META-INF/maven/") {
			return false
		}
	}
	return true
}

// watchlistID links a fingerprint finding to its census watchlist component; detect-only
// fingerprints (zlib, sqlite, Electron...) report the component without that link.
func watchlistID(g fingerprint.Group) string {
	if g.Watchlist {
		return g.Component
	}
	return ""
}

func hasPrefixed(list []string, prefix string) bool {
	for _, x := range list {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}

// trimZero drops a fourth ".0" component (Windows file versions: 6.7.3.0 = 6.7.3).
func trimZero(v string) string {
	if strings.Count(v, ".") == 3 && strings.HasSuffix(v, ".0") {
		return strings.TrimSuffix(v, ".0")
	}
	return v
}

// peName tidies the product names Windows version resources carry ("The c-ares
// library", "XZ Utils <https://tukaani.org/xz/>", "NGHTTP2.", "GNU libintl: accessing
// NLS message catalogs") into component names.
func peName(name string) string {
	n := strings.TrimSpace(name)
	if i := strings.Index(n, " <"); i > 0 {
		n = n[:i]
	}
	if i := strings.Index(n, ": "); i > 0 {
		n = n[:i]
	}
	n = strings.TrimSuffix(strings.TrimSpace(n), ".")
	n = strings.TrimPrefix(n, "The ")
	for _, suffix := range []string{" library", " Library", " DLL", " dll"} {
		if t := strings.TrimSuffix(n, suffix); t != n && t != "" {
			n = t
			break
		}
	}
	if n == "" {
		return name
	}
	return n
}

// peVersion: "1, 0, 0, 0" -> "1.0.0", "6.7.3.0" -> "6.7.3".
func peVersion(v string) string {
	if strings.Contains(v, ", ") {
		v = strings.ReplaceAll(v, ", ", ".")
	}
	return trimZero(strings.TrimSpace(v))
}

func unresolved(v string) bool {
	v = strings.TrimSpace(v)
	return strings.EqualFold(v, "UNKNOWN") || strings.Contains(v, "${")
}

func fromFingerprint(g fingerprint.Group) Component {
	c := Component{
		Name: g.Name, Group: g.Group, Version: g.Version, Type: "library", PURL: g.PURL, Watchlist: watchlistID(g),
		Confidence: g.Confidence, Techniques: g.Techniques, FoundBy: []string{"xenolith-fingerprint"},
		Locations: g.Locations, Evidence: g.Evidence, Notes: g.Notes,
	}
	return c
}

// merge folds the layers together: one entry per (group, name, version), strongest
// evidence first; an unversioned sighting is dropped when a versioned one exists.
func merge(all []Component) []Component {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	byKey := map[string]*Component{}
	var order []string
	for _, c := range all {
		key := norm(c.Group) + "|" + norm(c.Name) + "|" + norm(c.Version)
		if g, ok := byKey[key]; ok {
			if c.Confidence > g.Confidence {
				g.Confidence = c.Confidence
			}
			if g.PURL == "" {
				g.PURL = c.PURL
			}
			if g.CPE == "" {
				g.CPE = c.CPE
			}
			if g.Watchlist == "" {
				g.Watchlist = c.Watchlist
			}
			for _, t := range c.Techniques {
				g.Techniques = appendUnique(g.Techniques, t)
			}
			for _, f := range c.FoundBy {
				g.FoundBy = appendUnique(g.FoundBy, f)
			}
			for _, l := range c.Locations {
				g.Locations = appendUnique(g.Locations, l)
			}
			for _, e := range c.Evidence {
				g.Evidence = appendUnique(g.Evidence, e)
			}
			for _, n := range c.Notes {
				g.Notes = appendUnique(g.Notes, n)
			}
			continue
		}
		cc := c
		byKey[key] = &cc
		order = append(order, key)
	}
	// A layer that saw no group (a pom cataloger, a notices file) folds into the
	// grouped entry for the same name and version.
	grouped := map[string]string{}
	for _, k := range order {
		if c := byKey[k]; c.Group != "" {
			grouped[norm(c.Name)+"|"+norm(c.Version)] = k
		}
	}
	dropped := map[string]bool{}
	for _, k := range order {
		c := byKey[k]
		if c.Group != "" {
			continue
		}
		if gk, ok := grouped[norm(c.Name)+"|"+norm(c.Version)]; ok && gk != k {
			g := byKey[gk]
			if c.Confidence > g.Confidence {
				g.Confidence = c.Confidence
			}
			for _, t := range c.Techniques {
				g.Techniques = appendUnique(g.Techniques, t)
			}
			for _, f := range c.FoundBy {
				g.FoundBy = appendUnique(g.FoundBy, f)
			}
			for _, l := range c.Locations {
				g.Locations = appendUnique(g.Locations, l)
			}
			for _, n := range c.Notes {
				g.Notes = appendUnique(g.Notes, n)
			}
			dropped[k] = true
		}
	}
	// A Windows or ELF binary Syft names from its own version resource is the same
	// component a fingerprint identified in that file at the same version: keep the
	// fingerprint's name (zlib-ng2.dll calls itself "zlib" 2.1.5; the fingerprint knows
	// it is zlib-ng 2.1.5).
	byLoc := map[string][]string{}
	for _, k := range order {
		if c := byKey[k]; !dropped[k] && hasPrefixed(c.FoundBy, "xenolith-fingerprint") {
			for _, l := range c.Locations {
				byLoc[l] = append(byLoc[l], k)
			}
		}
	}
	for _, k := range order {
		c := byKey[k]
		if dropped[k] || len(c.Locations) != 1 || c.Version == "" || hasPrefixed(c.FoundBy, "xenolith-fingerprint") ||
			!(hasPrefixed(c.FoundBy, "syft:pe-binary") || hasPrefixed(c.FoundBy, "syft:elf-binary")) {
			continue
		}
		for _, fk := range byLoc[c.Locations[0]] {
			f := byKey[fk]
			if fk == k || trimZero(f.Version) != trimZero(c.Version) {
				continue
			}
			for _, x := range c.FoundBy {
				f.FoundBy = appendUnique(f.FoundBy, x)
			}
			if c.Confidence > f.Confidence {
				f.Confidence = c.Confidence
			}
			dropped[k] = true
			break
		}
	}
	versioned := map[string]bool{}
	for _, k := range order {
		if c := byKey[k]; c.Version != "" && !dropped[k] {
			versioned[norm(c.Group)+"|"+norm(c.Name)] = true
			versioned["|"+norm(c.Name)] = true
		}
	}
	var out []Component
	for _, k := range order {
		c := byKey[k]
		if dropped[k] {
			continue
		}
		if c.Version == "" && versioned[norm(c.Group)+"|"+norm(c.Name)] {
			continue
		}
		if c.Confidence >= 0.9 {
			// an installed-package or binary layer confirmed it; the declared-manifest caveat no longer applies
			var notes []string
			for _, n := range c.Notes {
				if !strings.HasPrefix(n, "declared in a manifest") {
					notes = append(notes, n)
				}
			}
			c.Notes = notes
		}
		sort.Strings(c.Techniques)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		if norm(out[i].Name) != norm(out[j].Name) {
			return norm(out[i].Name) < norm(out[j].Name)
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
