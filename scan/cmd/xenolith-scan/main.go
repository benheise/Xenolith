// xenolith-scan: what third-party components are inside a commercial product?
//
//	xenolith-scan scan <artifact>...   unpack, detect, write ./xenolith-out/
//	xenolith-scan review <dir>         keep or drop low-confidence findings
//	xenolith-scan submit <dir>         open the pull request (needs gh) or print the upload path
//	xenolith-scan diff <a> <b>         compare two submissions or scan directories
//	xenolith-scan eval <manifest>      scan a corpus and measure recall against known inventories
//	xenolith-scan helpers              show which optional unpackers are installed
//
// See design/xenolith-scan.md in the Xenolith repository.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/syft/syft"

	"github.com/benheise/Xenolith/scan/internal/detect"
	"github.com/benheise/Xenolith/scan/internal/fingerprint"
	"github.com/benheise/Xenolith/scan/internal/identity"
	"github.com/benheise/Xenolith/scan/internal/registry"
	"github.com/benheise/Xenolith/scan/internal/report"
	"github.com/benheise/Xenolith/scan/internal/submit"
	"github.com/benheise/Xenolith/scan/internal/unpack"
)

// Version is set by the release build (-ldflags "-X main.Version=...").
var Version = "dev"

const tool = "xenolith-scan"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "review":
		err = cmdReview(os.Args[2:])
	case "submit":
		err = cmdSubmit(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "eval":
		err = cmdEval(os.Args[2:])
	case "helpers":
		err = cmdHelpers()
	case "version", "--version", "-v":
		fmt.Printf("%s %s (syft %s, fingerprint pack v%d)\n", tool, Version, syftVersion(), packVersion())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `xenolith-scan: what third-party components are inside a commercial product?

  xenolith-scan scan <artifact>...   unpack, detect, write ./xenolith-out/
      --supplier --product --version  product identity (skips the prompts; for CI)
      --type application|firmware|operating-system|container|device|platform
      --out DIR                       output directory (default ./xenolith-out)
      --helpers auto|none             optional external unpackers (7z, innoextract, unblob)
      --max-depth 10 --max-bytes 50G  unpacking limits
      --fingerprints FILE             newer fingerprint pack than the built-in one
      --keep                          keep the extraction directory
      --yes                           accept the prefilled identity without asking
      --attest                        you are permitted to share this component list
      --include-low                   put findings below 0.7 confidence in the submission too
  xenolith-scan review <dir>         keep or drop low-confidence findings (--keep 1,4 --drop 2, or interactive)
  xenolith-scan submit <dir>         --attest [--dry-run]; opens the pull request with gh or prints the upload path
  xenolith-scan diff <a> <b>         compare two submissions or scan directories (--json)
  xenolith-scan eval <manifest>      scan a corpus manifest and measure recall against known inventories
  xenolith-scan helpers              show which optional unpackers are installed
  xenolith-scan version

An artifact is a file (installer, firmware image, archive, disk image), a directory,
or a container image reference (registry:..., docker:..., oci-archive:...).
Scans never execute, mount or emulate anything from the artifact and use no network.
`)
}

func syftVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			if d.Path == "github.com/anchore/syft" {
				return d.Version
			}
		}
	}
	return "unknown"
}

func packVersion() int {
	p, err := fingerprint.LoadEmbedded()
	if err != nil {
		return 0
	}
	return p.Version
}

// ---------------------------------------------------------------- scan

type scanFlags struct {
	supplier, product, version, ptype, out, helpers, fingerprints, sourceURL string
	maxDepth                                                                 int
	maxBytes                                                                 string
	keep, yes, attest, includeLow, quiet, noSummary                          bool
	parallelism                                                              int
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var f scanFlags
	fs.StringVar(&f.supplier, "supplier", "", "vendor name")
	fs.StringVar(&f.product, "product", "", "product name")
	fs.StringVar(&f.version, "version", "", "product version")
	fs.StringVar(&f.ptype, "type", "", "product type")
	fs.StringVar(&f.out, "out", "", "output directory")
	fs.StringVar(&f.helpers, "helpers", "auto", "auto or none")
	fs.StringVar(&f.fingerprints, "fingerprints", "", "fingerprint pack YAML")
	fs.StringVar(&f.sourceURL, "source-url", "", "public link where the artifact can be downloaded")
	fs.IntVar(&f.maxDepth, "max-depth", 10, "nested container depth")
	fs.StringVar(&f.maxBytes, "max-bytes", "", "total extraction budget, e.g. 50G")
	fs.BoolVar(&f.keep, "keep", false, "keep the extraction directory")
	fs.BoolVar(&f.yes, "yes", false, "accept the prefilled identity")
	fs.BoolVar(&f.attest, "attest", false, "you may share this component list")
	fs.BoolVar(&f.includeLow, "include-low", false, "include low-confidence findings in the submission")
	fs.BoolVar(&f.quiet, "quiet", false, "less progress output")
	fs.IntVar(&f.parallelism, "parallelism", 0, "cataloger parallelism (0 = Syft default)")
	artifacts, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("scan: give at least one artifact (file, directory or image reference)")
	}
	pack, err := loadPack(f.fingerprints)
	if err != nil {
		return err
	}
	if f.helpers != "auto" && f.helpers != "none" {
		return fmt.Errorf("--helpers must be auto or none")
	}
	if f.sourceURL != "" {
		if err := validSourceURL(f.sourceURL); err != nil {
			return err
		}
	}
	for i, artifact := range artifacts {
		out := f.out
		if out == "" {
			out = "xenolith-out"
		}
		if len(artifacts) > 1 {
			out = filepath.Join(out, registry.Slug(filepath.Base(artifact)))
		}
		if err := scanOne(artifact, out, f, pack); err != nil {
			return fmt.Errorf("%s: %w", artifact, err)
		}
		if i < len(artifacts)-1 {
			fmt.Println()
		}
	}
	return nil
}

// parseInterleaved lets flags follow positional arguments (scan file.bin --supplier X).
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
		if len(args) == 0 {
			return positional, nil
		}
	}
}

func loadPack(path string) (*fingerprint.Pack, error) {
	if path == "" {
		return fingerprint.LoadEmbedded()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fingerprint.Load(b)
}

func parseBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "T"):
		mult, s = 1<<40, strings.TrimSuffix(s, "T")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

func isImageRef(s string) bool {
	for _, p := range []string{"registry:", "docker:", "podman:", "containerd:", "oci-archive:", "oci-dir:", "docker-archive:", "singularity:"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func scanOne(artifact, out string, f scanFlags, pack *fingerprint.Pack) error {
	syft.SetLogger(discard.New())
	started := time.Now()
	var logLines []string
	logf := func(s string) {
		logLines = append(logLines, time.Now().Format("15:04:05")+" "+s)
		if !f.quiet {
			fmt.Println(s)
		}
	}
	scan := &report.Scan{Tool: tool, ToolVersion: Version, Started: started.UTC().Format(time.RFC3339), Attest: f.attest, SourceURL: f.sourceURL}
	ctx := context.Background()
	opts := detect.Options{Pack: pack, SyftVersion: syftVersion(), ToolVersion: Version, Log: logf, Parallelism: f.parallelism}

	var rep *detect.Report
	var guess identity.Guess
	if isImageRef(artifact) {
		logf("cataloging container image " + artifact + " (Syft; this is the one scan that may use the network)")
		r, src, err := detect.RunImage(ctx, artifact, opts)
		if err != nil {
			return err
		}
		rep = r
		scan.Artifact, scan.ArtifactKind = artifact, "image"
		if src.Metadata != nil {
			if b, err := json.Marshal(src.Metadata); err == nil {
				var m struct {
					ManifestDigest string            `json:"manifestDigest"`
					Labels         map[string]string `json:"labels"`
				}
				if json.Unmarshal(b, &m) == nil {
					if m.ManifestDigest != "" {
						scan.Artifact = artifact + "@" + m.ManifestDigest
					}
					guess = identity.FromTrees(nil, artifact, m.Labels)
				}
			}
		}
		if guess.Product == "" {
			guess = identity.FromTrees(nil, strings.TrimPrefix(artifact, "registry:"), nil)
		}
		scan.Containers = []string{artifact + " (container image, cataloged in place)"}
	} else {
		info, err := os.Stat(artifact)
		if err != nil {
			return err
		}
		if info.IsDir() {
			scan.Artifact, scan.ArtifactKind = filepath.Base(filepath.Clean(artifact)), "directory"
			logf("scanning directory " + artifact)
		} else {
			scan.Artifact, scan.ArtifactKind = filepath.Base(artifact), "file"
			logf("hashing " + artifact)
			sum, err := sha256File(artifact)
			if err != nil {
				return err
			}
			scan.ArtifactSHA256 = sum
		}
		maxBytes, err := parseBytes(f.maxBytes)
		if err != nil {
			return err
		}
		logf("unpacking")
		res, err := unpack.Run(artifact, unpack.Options{MaxDepth: f.maxDepth, MaxBytes: maxBytes, Helpers: f.helpers, Keep: f.keep, Log: logf})
		if err != nil {
			return err
		}
		defer res.Cleanup()
		if f.keep {
			logf("extraction kept at " + res.Root)
		}
		scan.NotInspected = res.NotInspected
		scan.Formats, scan.Helpers = res.Formats, res.Helpers
		for _, c := range res.Containers {
			scan.Containers = append(scan.Containers, fmt.Sprintf("%s (%s, %d files)", c.Location, c.Format, c.Files))
		}
		logf("detecting")
		rep, err = detect.Run(ctx, res, opts)
		if err != nil {
			return err
		}
		guess = identity.FromTrees(res.Trees, artifact, nil)
	}
	scan.NotInspected = append(scan.NotInspected, rep.Skipped...)
	sort.Strings(scan.NotInspected)
	scan.Engines, scan.Components, scan.Distro = rep.Engines, rep.Components, rep.Distro
	scan.Identity = guess

	// Product identity: flags win, then the prefilled guess, confirmed interactively.
	scan.Supplier, scan.Product, scan.Version, scan.ProductType = f.supplier, f.product, f.version, f.ptype
	if scan.Supplier == "" {
		scan.Supplier = guess.Supplier
	}
	if scan.Product == "" {
		scan.Product = guess.Product
	}
	if scan.Version == "" {
		scan.Version = guess.Version
	}
	if scan.ProductType == "" {
		scan.ProductType = guess.Type
	}
	if len(guess.Matches) > 0 && guess.Matches[0].Score >= 0.95 && f.supplier == "" {
		scan.Supplier = guess.Matches[0].Supplier
		if f.product == "" {
			scan.Product = guess.Matches[0].Name
		}
	}
	if !f.yes && (f.supplier == "" || f.product == "" || f.version == "") && isTerminal() {
		confirmIdentity(scan, guess)
	}
	if scan.SourceURL == "" && scan.ArtifactKind != "image" && !f.yes && isTerminal() {
		scan.SourceURL = askSourceURL(stdin, os.Stdout, scan.Artifact)
	}
	if scan.Supplier == "" || scan.Product == "" || scan.Version == "" {
		if f.yes || !isTerminal() {
			logf("identity incomplete; fill in --supplier/--product/--version or run `review` before submitting")
		}
	}
	if m := registry.Find(scan.Supplier, scan.Product, 1); len(m) > 0 && m[0].Score >= 0.95 {
		scan.RegistryKey = m[0].Key
		if len(m[0].CPEs) > 0 && scan.CPE == "" {
			scan.CPE = "cpe:2.3:a:" + m[0].CPEs[0] + ":" + cpeVersion(scan.Version) + ":*:*:*:*:*:*:*"
		}
	}
	if f.includeLow {
		for i := range scan.Components {
			t := true
			scan.Components[i].Keep = &t
		}
	}
	scan.Duration = time.Since(started).Round(time.Millisecond).String()
	scan.Log = logLines
	if err := report.Write(out, scan); err != nil {
		return err
	}
	if !f.noSummary {
		summary(scan, out)
	}
	return nil
}

func cpeVersion(v string) string {
	if v == "" {
		return "*"
	}
	r := strings.NewReplacer(" ", "_", ":", "\\:", "/", "\\/")
	return r.Replace(v)
}

func summary(s *report.Scan, out string) {
	kept, low := 0, 0
	var watch []string
	for _, c := range s.Components {
		if report.Included(c) {
			kept++
		} else {
			low++
		}
		if c.Watchlist != "" {
			label := c.Name
			if c.Version != "" {
				label += " " + c.Version
			}
			watch = append(watch, label)
		}
	}
	fmt.Printf("\n%s %s %s\n", s.Supplier, s.Product, s.Version)
	fmt.Printf("  %d components in the submission, %d below the confidence line (kept locally)\n", kept, low)
	if len(watch) > 0 {
		fmt.Printf("  watchlist: %s\n", strings.Join(watch, "; "))
	}
	fmt.Printf("  containers opened: %d, not inspected: %d, %s\n", len(s.Containers), len(s.NotInspected), s.Duration)
	fmt.Printf("  wrote %s/{submission.cdx.json, report.html, not-inspected.txt, scan.log, findings.json}\n", out)
	if s.SourceURL == "" && s.ArtifactKind != "image" {
		fmt.Println("  no download link recorded: add one with `xenolith-scan review " + out + " --source-url https://…` so others can check the same file")
	}
	if !s.Attest {
		fmt.Println("  next: review the report, then `xenolith-scan submit " + out + " --attest`")
	} else {
		fmt.Println("  next: review the report, then `xenolith-scan submit " + out + "`")
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var stdin = bufio.NewReader(os.Stdin) // one reader, so prompts never lose each other's buffered input

// validSourceURL accepts the public https link others can download the same file from.
func validSourceURL(u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" {
		return fmt.Errorf("--source-url must be an https:// link to the file or its download page, got %q", u)
	}
	return nil
}

// askSourceURL asks where the scanned file can be downloaded, so a reviewer can fetch the
// same bytes and check the hash. An empty answer (or end of input) skips it.
func askSourceURL(in *bufio.Reader, out io.Writer, artifact string) string {
	fmt.Fprintf(out, "\nWhere can others download %s?\n  Paste the https link to the file or its download/release page (Enter to skip): ", artifact)
	for tries := 0; tries < 3; tries++ {
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return ""
		}
		if validSourceURL(line) == nil {
			return line
		}
		if err != nil {
			return ""
		}
		fmt.Fprint(out, "  That is not an https:// link. Paste one, or press Enter to skip: ")
	}
	return ""
}

func confirmIdentity(s *report.Scan, g identity.Guess) {
	in := stdin
	fmt.Println()
	fmt.Printf("Product identity (from %s). Press Enter to accept a value, or type a correction.\n", g.Source)
	if len(g.Matches) > 0 {
		fmt.Println("  Xenolith already knows these products:")
		for i, m := range g.Matches {
			if i >= 3 {
				break
			}
			fmt.Printf("    %d. %s / %s  (%s)\n", i+1, m.Supplier, m.Name, m.Key)
		}
		fmt.Print("  Pick a number or press Enter: ")
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if n := len(line); n == 1 && line[0] >= '1' && line[0] <= '3' && int(line[0]-'1') < len(g.Matches) {
			m := g.Matches[line[0]-'1']
			s.Supplier, s.Product = m.Supplier, m.Name
		}
	}
	ask := func(label string, cur *string) {
		fmt.Printf("  %s [%s]: ", label, *cur)
		line, _ := in.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			*cur = line
		}
	}
	ask("Supplier", &s.Supplier)
	ask("Product", &s.Product)
	ask("Version", &s.Version)
	ask("Type (application, firmware, operating-system, container, device, platform)", &s.ProductType)
}

// ---------------------------------------------------------------- review

func cmdReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	var keep, drop string
	var all, none bool
	fs.StringVar(&keep, "keep", "", "comma-separated numbers of low-confidence findings to include")
	fs.StringVar(&drop, "drop", "", "comma-separated numbers of findings to exclude")
	fs.BoolVar(&all, "keep-all", false, "include every finding")
	fs.BoolVar(&none, "reset", false, "forget earlier review decisions")
	var sourceURL string
	fs.StringVar(&sourceURL, "source-url", "", "public link where the scanned file can be downloaded")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	dir := "xenolith-out"
	if len(pos) > 0 {
		dir = pos[0]
	}
	s, err := report.Load(dir)
	if err != nil {
		return err
	}
	if sourceURL != "" {
		if err := validSourceURL(sourceURL); err != nil {
			return err
		}
		s.SourceURL = sourceURL
	}
	if none {
		for i := range s.Components {
			s.Components[i].Keep = nil
		}
	}
	fmt.Printf("%s %s %s: %d components\n\n", s.Supplier, s.Product, s.Version, len(s.Components))
	fmt.Printf("%4s  %-5s  %-6s  %-40s %-18s %s\n", "#", "conf", "in?", "component", "version", "how")
	for i, c := range s.Components {
		in := "no"
		if report.Included(c) {
			in = "yes"
		}
		name := c.Name
		if c.Group != "" {
			name = c.Group + ":" + c.Name
		}
		fmt.Printf("%4d  %.2f   %-6s  %-40s %-18s %s\n", i+1, c.Confidence, in, trunc(name, 40), trunc(c.Version, 18), strings.Join(c.FoundBy, ","))
	}
	apply := func(list string, keepIt bool) error {
		for _, tok := range strings.Split(list, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			var n int
			if _, err := fmt.Sscanf(tok, "%d", &n); err != nil || n < 1 || n > len(s.Components) {
				return fmt.Errorf("no finding #%s", tok)
			}
			k := keepIt
			s.Components[n-1].Keep = &k
		}
		return nil
	}
	if all {
		for i := range s.Components {
			t := true
			s.Components[i].Keep = &t
		}
	}
	if err := apply(keep, true); err != nil {
		return err
	}
	if err := apply(drop, false); err != nil {
		return err
	}
	if keep == "" && drop == "" && !all && !none && isTerminal() {
		in := stdin
		fmt.Println("\nLow-confidence findings: keep in the submission? [y/N/q]")
		for i, c := range s.Components {
			if report.Included(c) && c.Keep == nil {
				continue
			}
			if c.Keep != nil {
				continue
			}
			fmt.Printf("  #%d %s %s (%.2f, %s)", i+1, c.Name, c.Version, c.Confidence, strings.Join(c.Evidence, "; "))
			if len(c.Locations) > 0 {
				fmt.Printf("\n      at %s", c.Locations[0])
			}
			fmt.Print(" ? ")
			line, _ := in.ReadString('\n')
			line = strings.ToLower(strings.TrimSpace(line))
			if line == "q" {
				break
			}
			k := line == "y" || line == "yes"
			s.Components[i].Keep = &k
		}
	}
	if s.Supplier == "" || s.Product == "" || s.Version == "" {
		if isTerminal() {
			confirmIdentity(s, s.Identity)
		} else {
			fmt.Println("\nidentity incomplete: re-run scan with --supplier/--product/--version")
		}
	}
	if s.SourceURL == "" && s.ArtifactKind != "image" && isTerminal() {
		s.SourceURL = askSourceURL(stdin, os.Stdout, s.Artifact)
	}
	if err := report.Write(dir, s); err != nil {
		return err
	}
	kept := 0
	for _, c := range s.Components {
		if report.Included(c) {
			kept++
		}
	}
	fmt.Printf("\nsubmission now holds %d components; rewrote %s/submission.cdx.json and report.html\n", kept, dir)
	return nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// ---------------------------------------------------------------- submit

func cmdSubmit(args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	var attest, dry bool
	fs.BoolVar(&attest, "attest", false, "you are permitted to share this component list")
	fs.BoolVar(&dry, "dry-run", false, "show what would happen")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	dir := "xenolith-out"
	if len(pos) > 0 {
		dir = pos[0]
	}
	s, err := report.Load(dir)
	if err != nil {
		return err
	}
	if s.Supplier == "" || s.Product == "" || s.Version == "" {
		return fmt.Errorf("the product identity is incomplete; run `xenolith-scan review %s` or re-scan with --supplier/--product/--version", dir)
	}
	if attest {
		s.Attest = true
		if err := report.Write(dir, s); err != nil {
			return err
		}
	}
	if !s.Attest {
		return fmt.Errorf("add --attest to confirm you are permitted to share this component list (see CONTRIBUTING.md §3)")
	}
	kept, watch := 0, []string{}
	for _, c := range s.Components {
		if report.Included(c) {
			kept++
			if c.Watchlist != "" {
				watch = append(watch, c.Name+" "+c.Version)
			}
		}
	}
	if kept == 0 {
		return fmt.Errorf("the submission has no components")
	}
	o := submit.Options{Supplier: s.Supplier, Product: s.Product, Version: s.Version, Submission: filepath.Join(dir, "submission.cdx.json"),
		Components: kept, Watchlist: watch, Artifact: s.Artifact, DryRun: dry, Log: func(m string) { fmt.Println(m) }}
	result, err := submit.Run(o)
	if err != nil {
		if strings.Contains(err.Error(), "gh not found") {
			fmt.Println(submit.ManualInstructions(o))
			return nil
		}
		return err
	}
	fmt.Println(result)
	return nil
}

// ---------------------------------------------------------------- diff

type diffEntry struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

func loadComponents(path string) (string, map[string]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}
	if st.IsDir() {
		path = filepath.Join(path, "submission.cdx.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var bom struct {
		Metadata struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Group   string `json:"group"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &bom); err != nil {
		return "", nil, err
	}
	// one line per name; several shipped versions are listed sorted, so component order
	// in either file never shows up as a change
	versions := map[string]map[string]bool{}
	for _, c := range bom.Components {
		name := c.Name
		if c.Group != "" {
			name = c.Group + ":" + c.Name
		}
		key := strings.ToLower(name)
		if versions[key] == nil {
			versions[key] = map[string]bool{}
		}
		if c.Version != "" {
			versions[key][c.Version] = true
		}
	}
	out := map[string]string{}
	for key, set := range versions {
		vs := make([]string, 0, len(set))
		for v := range set {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		out[key] = strings.Join(vs, ", ")
	}
	return bom.Metadata.Component.Name + " " + bom.Metadata.Component.Version, out, nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "machine-readable output")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("diff: give two submission files or scan directories")
	}
	labelA, a, err := loadComponents(pos[0])
	if err != nil {
		return err
	}
	labelB, b, err := loadComponents(pos[1])
	if err != nil {
		return err
	}
	var added, removed []diffEntry
	var changed []map[string]string
	for k, v := range b {
		if old, ok := a[k]; !ok {
			added = append(added, diffEntry{k, v})
		} else if old != v {
			changed = append(changed, map[string]string{"name": k, "from": old, "to": v})
		}
	}
	for k, v := range a {
		if _, ok := b[k]; !ok {
			removed = append(removed, diffEntry{k, v})
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Name < added[j].Name })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Name < removed[j].Name })
	sort.Slice(changed, func(i, j int) bool { return changed[i]["name"] < changed[j]["name"] })
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"from": labelA, "to": labelB, "added": added, "removed": removed, "changed": changed,
			"unchanged": len(b) - len(added) - len(changed)})
	}
	fmt.Printf("%s  ->  %s\n", labelA, labelB)
	fmt.Printf("  %d unchanged, %d changed, %d added, %d removed\n", len(b)-len(added)-len(changed), len(changed), len(added), len(removed))
	for _, c := range changed {
		fmt.Printf("  ~ %s  %s -> %s\n", c["name"], c["from"], c["to"])
	}
	for _, e := range added {
		fmt.Printf("  + %s %s\n", e.Name, e.Version)
	}
	for _, e := range removed {
		fmt.Printf("  - %s %s\n", e.Name, e.Version)
	}
	return nil
}

// ---------------------------------------------------------------- helpers

func cmdHelpers() error {
	res := &unpack.Result{}
	_ = res
	found := unpack.FindHelpers()
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := found[n]
		role := map[string]string{
			"7z":          "MSI, CAB, NSIS, InstallShield, xar/pkg, DMG, VMDK, qcow2, VHD(X)",
			"innoextract": "Inno Setup installers",
			"unblob":      "firmware blobs, UBI/UBIFS, JFFS2, cramfs and other embedded filesystems",
		}[n]
		if p == "" {
			fmt.Printf("  %-12s not installed   (%s)\n", n, role)
		} else {
			fmt.Printf("  %-12s %s   (%s)\n", n, p, role)
		}
	}
	fmt.Println("\nBuilt in: zip/jar, tar, gzip, bzip2, xz, zstd, lzma, 7z, ar/deb, rpm, cpio, squashfs, ISO 9660, ext4, raw disk images (MBR/GPT), AppImage, Electron asar, container images (via Syft).")
	return nil
}

// ---------------------------------------------------------------- eval

// A corpus manifest lists artifacts with known inventories:
//   - artifact: path or URL
//     sha256: ...
//     inventory: path to a Xenolith inventory JSON (docs/data/inventory/*.json entry or data/notices/*.json)
//     product/version: which entry of the inventory file applies
func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	var out string
	fs.StringVar(&out, "out", "xenolith-eval", "where scan outputs go")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("eval: give the corpus manifest (YAML or JSON)")
	}
	return runEval(pos[0], out)
}
