package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one detection of a component in one file.
type Finding struct {
	Component  string  `json:"component"` // watchlist id
	Name       string  `json:"name"`      // reported component name
	Group      string  `json:"group,omitempty"`
	Version    string  `json:"version"`
	Technique  string  `json:"technique"`  // binary-analysis, manifest-analysis, filename
	Confidence float64 `json:"confidence"` // 0-1
	Location   string  `json:"location"`   // logical path (archive!/member)
	Evidence   string  `json:"evidence,omitempty"`
	Note       string  `json:"note,omitempty"`
	PURL       string  `json:"purl,omitempty"`
}

// Scanner applies a pack to files.
type Scanner struct {
	Pack     *Pack
	Findings []Finding
	Skipped  []string
	wanted   [][]byte
	// MaxBinaryBytes caps how much of an executable is read for string rules.
	MaxBinaryBytes int64
}

// New returns a scanner for a pack.
func New(p *Pack) *Scanner {
	return &Scanner{Pack: p, wanted: p.Wanted(), MaxBinaryBytes: 512 << 20}
}

var execMagic = [][]byte{
	{0x7f, 'E', 'L', 'F'}, {'M', 'Z'},
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe},
}

var notBinary = []string{".class", ".properties", ".xml", ".html", ".htm", ".js", ".mjs", ".css", ".txt", ".md",
	".json", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ttf", ".woff", ".woff2", ".pdf", ".po", ".mo"}

// IsExecutable reports whether the file header looks like a native executable.
func IsExecutable(head []byte) bool {
	for _, m := range execMagic {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// ScanTree walks an extracted tree. locate maps an on-disk path to the logical
// location shown in reports (so files from nested archives read as a!/b!/c).
func (s *Scanner) ScanTree(root string, locate func(string) string) {
	if locate == nil {
		locate = func(p string) string { rel, _ := filepath.Rel(root, p); return filepath.ToSlash(rel) }
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.Skipped = append(s.Skipped, locate(path)+": "+err.Error())
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		s.ScanFile(path, locate(path))
		return nil
	})
}

// ScanFile applies the path rules and, for executables, the binary rules to one file.
func (s *Scanner) ScanFile(path, location string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return
	}
	var content []byte
	read := func() []byte {
		if content == nil {
			if info.Size() < 4<<20 {
				content, _ = os.ReadFile(path)
			}
			if content == nil {
				content = []byte{}
			}
		}
		return content
	}
	s.paths(location, read)
	lower := strings.ToLower(location)
	for _, ext := range notBinary {
		if strings.HasSuffix(lower, ext) {
			return
		}
	}
	f, err := os.Open(path)
	if err != nil {
		s.Skipped = append(s.Skipped, location+": "+err.Error())
		return
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := f.Read(head)
	if !IsExecutable(head[:n]) {
		return
	}
	if info.Size() > s.MaxBinaryBytes {
		s.Skipped = append(s.Skipped, location+": executable larger than the string-scan limit")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.Skipped = append(s.Skipped, location+": "+err.Error())
		return
	}
	s.Binary(data, location)
}

// paths applies the path rules (package metadata, class files, file names).
func (s *Scanner) paths(location string, read func() []byte) {
	for _, fp := range s.Pack.Components {
		for _, rule := range fp.Paths {
			m := rule.Regex.FindStringSubmatch(location)
			if m == nil {
				continue
			}
			groups := named(rule.Regex, m)
			version, how := groups["v"], rule.Version
			if how == "pom" || how == "manifest" || how == "package_json" {
				v, ok := metadataVersion(how, read(), rule)
				if !ok {
					continue // a manifest of some other jar
				}
				version = v
			}
			name := groups["name"]
			if name == "" {
				name = fp.Name
			}
			technique := "binary-analysis"
			if how != "" {
				technique = "manifest-analysis"
			} else if groups["v"] != "" {
				technique = "filename"
			}
			base := location[strings.LastIndex(location, "/")+1:]
			s.add(fp, name, version, technique, rule.Confidence, location, base, rule.Note)
		}
	}
}

func named(re *regexp.Regexp, m []string) map[string]string {
	out := map[string]string{}
	for i, n := range re.SubexpNames() {
		if n != "" && i < len(m) {
			out[n] = m[i]
		}
	}
	return out
}

var (
	pomVersion   = regexp.MustCompile(`(?m)^version\s*[=:]\s*(\S+)`)
	manifestLine = regexp.MustCompile(`(?m)^([\w-]+):\s*(.+?)\s*$`)
)

func metadataVersion(how string, content []byte, rule PathRule) (string, bool) {
	text := string(content)
	switch how {
	case "pom":
		if m := pomVersion.FindStringSubmatch(text); m != nil {
			return m[1], true
		}
		return "", true
	case "manifest":
		fields := map[string]string{}
		for _, m := range manifestLine.FindAllStringSubmatch(text, -1) {
			fields[m[1]] = m[2]
		}
		if rule.ManifestTitle != nil && !rule.ManifestTitle.MatchString(fields["Implementation-Title"]) {
			return "", false
		}
		if v := fields["Implementation-Version"]; v != "" {
			return v, true
		}
		return fields["Bundle-Version"], true
	case "package_json":
		var doc struct {
			Version any `json:"version"`
		}
		if json.Unmarshal(content, &doc) == nil && doc.Version != nil {
			if v, ok := doc.Version.(string); ok {
				return v, true
			}
		}
		return "", true
	}
	return "", true
}

// Binary applies string, marker, symbol and probe rules to executable content.
func (s *Scanner) Binary(data []byte, location string) {
	for _, fp := range s.Pack.Components {
		for _, rule := range fp.Strings {
			if !bytes.Contains(data, rule.Contains) {
				continue
			}
			if len(rule.RequiresAny) > 0 && !anyContains(data, rule.RequiresAny) {
				continue
			}
			if m, v := matchString(rule, data); m != nil {
				name := rule.Name
				if name == "" {
					name = fp.Name
				}
				s.add(fp, name, v, "binary-analysis", 0.9, location, printable(m), "")
			}
		}
		for _, mk := range fp.Markers {
			if bytes.Contains(data, mk.Bytes) {
				s.add(fp, fp.Name, "", "binary-analysis", 0.6, location, "static data marker", mk.Note)
			}
		}
	}
	if !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) || len(s.wanted) == 0 || !anyContains(data, s.wanted) {
		return
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		s.Skipped = append(s.Skipped, location+": ELF parse: "+err.Error())
		return
	}
	defer f.Close()
	defined, err := definedSymbols(f, s.wanted)
	if err != nil {
		s.Skipped = append(s.Skipped, location+": ELF symbols: "+err.Error())
		return
	}
	for _, fp := range s.Pack.Components {
		version := ""
		for _, probe := range fp.Probes {
			addr, ok := defined[probe.Symbol]
			if !ok {
				continue
			}
			if value, ok := returnedConstant(f, addr); ok && value != 0 {
				if v := decodeVersion(probe.Decode, value); versionShape.MatchString(v) {
					version = v
					s.add(fp, fp.Name, v, "binary-analysis", 0.8, location,
						probe.Symbol+"() returns 0x"+strings.ToLower(hex32(value)), "")
					break
				}
			}
		}
		if len(fp.Symbols) > 0 && version == "" {
			all := true
			for _, sym := range fp.Symbols {
				if _, ok := defined[sym]; !ok {
					all = false
					break
				}
			}
			if all {
				s.add(fp, fp.Name, "", "binary-analysis", 0.7, location, "defines "+strings.Join(fp.Symbols, ", "), "")
			}
		}
	}
}

var versionShape = regexp.MustCompile(`^\d{1,2}\.\d{1,4}\.\d{1,4}$`)

func hex32(v uint32) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 8)
	for shift := 28; shift >= 0; shift -= 4 {
		d := (v >> uint(shift)) & 0xF
		if len(out) == 0 && d == 0 && shift > 0 {
			continue
		}
		out = append(out, digits[d])
	}
	return string(out)
}

func anyContains(data []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(data, n) {
			return true
		}
	}
	return false
}

// matchString finds the first match of a string rule, honouring the rewritten
// lookbehind (the optional "pre" group must not have matched a forbidden character).
func matchString(rule StringRule, data []byte) ([]byte, string) {
	names := rule.Regex.SubexpNames()
	pre, v := -1, -1
	for i, n := range names {
		switch n {
		case "pre":
			pre = i
		case "v":
			v = i
		}
	}
	start := 0
	for start < len(data) {
		loc := rule.Regex.FindSubmatchIndex(data[start:])
		if loc == nil {
			return nil, ""
		}
		matched := true
		if pre >= 0 && loc[2*pre] >= 0 {
			matched = false // a forbidden character precedes the token: not a match
		}
		if matched && v >= 0 && loc[2*v] >= 0 {
			from := loc[0]
			if pre >= 0 && loc[2*pre] >= 0 {
				from = loc[2*pre+1]
			}
			return data[start+from : start+loc[1]], string(data[start+loc[2*v] : start+loc[2*v+1]])
		}
		// Skip past this candidate and keep looking.
		next := loc[1]
		if next <= 0 {
			next = 1
		}
		start += next
	}
	return nil, ""
}

func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return string(out)
}

func (s *Scanner) add(fp *Fingerprint, name, version, technique string, confidence float64, location, evidence, note string) {
	version = strings.TrimSpace(version)
	s.Findings = append(s.Findings, Finding{
		Component: fp.ID, Name: name, Group: fp.Group, Version: version, Technique: technique,
		Confidence: confidence, Location: location, Evidence: evidence, Note: note, PURL: fp.PURLFor(name, version),
	})
}

// Group is one line of the summary: a component at a version, with every place it was seen.
type Group struct {
	Component  string   `json:"component"`
	Name       string   `json:"name"`
	Group      string   `json:"group,omitempty"`
	Version    string   `json:"version"`
	PURL       string   `json:"purl,omitempty"`
	Confidence float64  `json:"confidence"`
	Techniques []string `json:"techniques"`
	Locations  []string `json:"locations"`
	Evidence   []string `json:"evidence"`
	Notes      []string `json:"notes,omitempty"`
}

// Summarize merges findings into one entry per (component, name, version). Unversioned
// presence is dropped when the same container already gave a version for the component.
func Summarize(findings []Finding) []Group {
	container := func(loc string) string {
		if i := strings.LastIndex(loc, "!/"); i >= 0 {
			return loc[:i]
		}
		if i := strings.LastIndex(loc, "/"); i >= 0 {
			return loc[:i]
		}
		return ""
	}
	versioned := map[[2]string]bool{}
	for _, f := range findings {
		if f.Version != "" {
			versioned[[2]string{f.Component, container(f.Location)}] = true
		}
	}
	groups := map[[4]string]*Group{}
	var order [][4]string
	for _, f := range findings {
		if f.Version == "" && versioned[[2]string{f.Component, container(f.Location)}] {
			continue
		}
		key := [4]string{f.Component, f.Group, f.Name, f.Version}
		g, ok := groups[key]
		if !ok {
			g = &Group{Component: f.Component, Name: f.Name, Group: f.Group, Version: f.Version, PURL: f.PURL}
			groups[key] = g
			order = append(order, key)
		}
		if f.Confidence > g.Confidence {
			g.Confidence = f.Confidence
		}
		g.Techniques = appendUnique(g.Techniques, f.Technique)
		g.Locations = appendUnique(g.Locations, f.Location)
		if f.Evidence != "" {
			g.Evidence = appendUnique(g.Evidence, f.Evidence)
		}
		if f.Note != "" {
			g.Notes = appendUnique(g.Notes, f.Note)
		}
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		g := groups[k]
		sort.Strings(g.Techniques)
		sort.Strings(g.Notes)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
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
