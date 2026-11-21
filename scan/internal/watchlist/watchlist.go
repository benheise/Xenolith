// Package watchlist embeds the census watchlist's name patterns so a scan can link a
// finding to its Xenolith component by name, the same way the census does when it reads
// a submitted SBOM. Fingerprints cover components that carry no usable name (a statically
// linked library, a runtime inside a larger binary); this covers everything a package
// manifest, a jar or a notices file already names.
package watchlist

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

//go:embed watchlist.min.json
var raw []byte

type pattern struct {
	name, version, notVersion *regexp.Regexp
}

// Component is one watchlist entry.
type Component struct {
	ID, Name string
	patterns []pattern
}

var (
	once sync.Once
	all  []Component
	err  error
)

var space = regexp.MustCompile(`\s+`)

// Load parses the embedded snapshot once.
func Load() ([]Component, error) {
	once.Do(func() { all, err = parse(raw) })
	return all, err
}

func parse(data []byte) ([]Component, error) {
	var rows [][]json.RawMessage
	if e := json.Unmarshal(data, &rows); e != nil {
		return nil, e
	}
	out := make([]Component, 0, len(rows))
	for _, r := range rows {
		var c Component
		var pats [][3]string
		if e := json.Unmarshal(r[0], &c.ID); e != nil {
			return nil, e
		}
		if e := json.Unmarshal(r[1], &c.Name); e != nil {
			return nil, e
		}
		if e := json.Unmarshal(r[2], &pats); e != nil {
			return nil, e
		}
		for _, p := range pats {
			var cp pattern
			var e error
			if cp.name, e = regexp.Compile("(?i)^(?:" + p[0] + ")$"); e != nil {
				return nil, e
			}
			if p[1] != "" {
				if cp.version, e = regexp.Compile("(?i)^(?:" + p[1] + ")"); e != nil {
					return nil, e
				}
			}
			if p[2] != "" {
				if cp.notVersion, e = regexp.Compile("(?i)" + p[2]); e != nil {
					return nil, e
				}
			}
			c.patterns = append(c.patterns, cp)
		}
		out = append(out, c)
	}
	return out, nil
}

// Normalize lowercases, trims and collapses whitespace, as the census does.
func Normalize(name string) string {
	return space.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), " ")
}

// Match returns the id of the watchlist component a finding belongs to, or "". The name
// is "group:name" when the finding has a group, the bare name otherwise: the form an
// SBOM component takes when the census ingests it.
func Match(group, name, version string) string {
	comps, e := Load()
	if e != nil {
		return ""
	}
	full := Normalize(name)
	if group != "" {
		full = Normalize(group + ":" + name)
	}
	for _, c := range comps {
		for _, p := range c.patterns {
			if !p.name.MatchString(full) {
				continue
			}
			if p.version != nil && !p.version.MatchString(version) {
				continue
			}
			if p.notVersion != nil && p.notVersion.MatchString(version) {
				continue
			}
			return c.ID
		}
	}
	return ""
}
