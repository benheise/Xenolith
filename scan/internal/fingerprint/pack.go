// Package fingerprint detects Xenolith's watchlist components in files: version
// strings, static data markers, defined ELF symbols, the constants returned by
// version functions, and package-metadata paths. It is the Go port of
// xenolith/fingerprint.py and reads the same catalog/fingerprints.yaml.
package fingerprint

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PackYAML is the fingerprint pack pinned into the binary at build time. It is a
// copy of catalog/fingerprints.yaml; `make sync` refreshes it and a test checks it.
//
//go:embed pack.yaml
var PackYAML []byte

// Pack is a parsed fingerprint file.
type Pack struct {
	Version    int
	Components []*Fingerprint
}

// Fingerprint is the detection recipe for one watchlist component.
type Fingerprint struct {
	ID      string
	Name    string
	Group   string
	PURL    string
	Strings []StringRule
	Symbols []string
	Probes  []Probe
	Markers []Marker
	Paths   []PathRule
}

// StringRule finds a version string in an executable.
type StringRule struct {
	Contains    []byte
	Regex       *regexp.Regexp
	RequiresAny [][]byte
	Name        string
}

// Probe reads the constant a version function returns.
type Probe struct {
	Symbol string
	Decode string
}

// Marker is a byte sequence only the component's own code contains.
type Marker struct {
	Bytes []byte
	Note  string
}

// PathRule matches a file path inside a tree or archive.
type PathRule struct {
	Regex         *regexp.Regexp
	Version       string // "", pom, manifest, package_json
	Confidence    float64
	Note          string
	ManifestTitle *regexp.Regexp
	Sibling       *Sibling
}

// Sibling reads the version from another file near the matched one when the matched
// file carries none (Next.js strips "version" from the React packages it vendors).
// Path is relative to the matched file's directory; {group} is replaced by that named
// capture of the path rule.
type Sibling struct {
	Path       string
	Regex      *regexp.Regexp
	Confidence float64
	Note       string
	Rewrite    *regexp.Regexp // replaced by To in the version read (publishing conventions)
	To         string
}

type rawPack struct {
	Version    int                 `yaml:"version"`
	Components map[string]rawEntry `yaml:"components"`
}

type rawEntry struct {
	Name    string      `yaml:"name"`
	Group   string      `yaml:"group"`
	PURL    string      `yaml:"purl"`
	Strings []rawString `yaml:"strings"`
	Symbols []string    `yaml:"symbols"`
	Probes  []Probe     `yaml:"probes"`
	Markers []rawMarker `yaml:"markers"`
	Paths   []rawPath   `yaml:"paths"`
}

type rawString struct {
	Contains    string   `yaml:"contains"`
	Regex       string   `yaml:"regex"`
	RequiresAny []string `yaml:"requires_any"`
	Name        string   `yaml:"name"`
}

type rawMarker struct {
	Bytes string `yaml:"bytes"`
	Note  string `yaml:"note"`
}

type rawPath struct {
	Regex         string  `yaml:"regex"`
	Version       string  `yaml:"version"`
	Confidence    float64 `yaml:"confidence"`
	Note          string  `yaml:"note"`
	ManifestTitle string  `yaml:"manifest_title"`
	Sibling       *struct {
		Path       string  `yaml:"path"`
		Regex      string  `yaml:"regex"`
		Confidence float64 `yaml:"confidence"`
		Note       string  `yaml:"note"`
		Rewrite    *struct {
			Regex string `yaml:"regex"`
			To    string `yaml:"to"`
		} `yaml:"rewrite"`
	} `yaml:"sibling"`
}

// Load parses a fingerprint pack. Python's (?P<name>...) and Go's RE2 syntax agree
// for everything the pack uses except lookbehind, which is rewritten here.
func Load(data []byte) (*Pack, error) {
	var raw rawPack
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("fingerprints: %w", err)
	}
	pack := &Pack{Version: raw.Version}
	ids := make([]string, 0, len(raw.Components))
	for id := range raw.Components {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := raw.Components[id]
		fp := &Fingerprint{ID: id, Name: e.Name, Group: e.Group, PURL: e.PURL, Symbols: e.Symbols, Probes: e.Probes}
		if fp.Name == "" {
			fp.Name = id
		}
		for _, s := range e.Strings {
			re, err := compile(s.Regex)
			if err != nil {
				return nil, fmt.Errorf("fingerprints: %s: %w", id, err)
			}
			rule := StringRule{Contains: []byte(s.Contains), Regex: re, Name: s.Name}
			for _, r := range s.RequiresAny {
				rule.RequiresAny = append(rule.RequiresAny, []byte(r))
			}
			fp.Strings = append(fp.Strings, rule)
		}
		for _, m := range e.Markers {
			fp.Markers = append(fp.Markers, Marker{Bytes: []byte(m.Bytes), Note: m.Note})
		}
		for _, p := range e.Paths {
			re, err := compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("fingerprints: %s: %w", id, err)
			}
			rule := PathRule{Regex: re, Version: p.Version, Confidence: p.Confidence, Note: p.Note}
			if rule.Confidence == 0 {
				rule.Confidence = 0.6
			}
			if p.ManifestTitle != "" {
				mt, err := compile(p.ManifestTitle)
				if err != nil {
					return nil, fmt.Errorf("fingerprints: %s: %w", id, err)
				}
				rule.ManifestTitle = mt
			}
			if sb := p.Sibling; sb != nil {
				sre, err := compile(sb.Regex)
				if err != nil {
					return nil, fmt.Errorf("fingerprints: %s: sibling: %w", id, err)
				}
				if sb.Path == "" || sre.SubexpIndex("v") < 0 {
					return nil, fmt.Errorf("fingerprints: %s: sibling needs a path and a (?P<v>...) group", id)
				}
				rule.Sibling = &Sibling{Path: sb.Path, Regex: sre, Confidence: sb.Confidence, Note: sb.Note}
				if rule.Sibling.Confidence == 0 {
					rule.Sibling.Confidence = rule.Confidence
				}
				if rw := sb.Rewrite; rw != nil {
					rre, err := compile(rw.Regex)
					if err != nil {
						return nil, fmt.Errorf("fingerprints: %s: sibling rewrite: %w", id, err)
					}
					rule.Sibling.Rewrite, rule.Sibling.To = rre, rw.To
				}
			}
			fp.Paths = append(fp.Paths, rule)
		}
		pack.Components = append(pack.Components, fp)
	}
	return pack, nil
}

// LoadEmbedded returns the pack built into the binary.
func LoadEmbedded() (*Pack, error) { return Load(PackYAML) }

// lookbehind rewrites the two Python-only constructs the pack uses, (?<![...]) at the
// start of a pattern, into an RE2 equivalent: a capture of one preceding character
// that is then checked by the caller (see matchString).
var lookbehind = regexp.MustCompile(`^\(\?<!\[([^\]]+)\]\)`)

// compile turns a pack regex into RE2. A leading negative lookbehind on a character
// class becomes an optional leading character group named "pre"; matchString rejects
// matches whose "pre" character is in the forbidden class.
func compile(pattern string) (*regexp.Regexp, error) {
	if m := lookbehind.FindStringSubmatch(pattern); m != nil {
		pattern = `(?P<pre>[` + m[1] + `])?` + pattern[len(m[0]):]
	}
	return regexp.Compile(pattern)
}

// Wanted returns every symbol name the pack reads from ELF symbol tables.
func (p *Pack) Wanted() [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for _, fp := range p.Components {
		for _, s := range fp.Symbols {
			if !seen[s] {
				seen[s] = true
				out = append(out, []byte(s))
			}
		}
		for _, pr := range fp.Probes {
			if !seen[pr.Symbol] {
				seen[pr.Symbol] = true
				out = append(out, []byte(pr.Symbol))
			}
		}
	}
	return out
}

// PURLFor fills the component's purl template.
func (fp *Fingerprint) PURLFor(name, version string) string {
	if fp.PURL == "" || version == "" {
		return ""
	}
	purl := strings.ReplaceAll(fp.PURL, "{version}", version)
	if fp.ID == "react-server-components" {
		purl = strings.ReplaceAll(purl, "react-server-dom-webpack", name)
	}
	return purl
}
