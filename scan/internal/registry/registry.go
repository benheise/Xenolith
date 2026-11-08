// Package registry embeds a snapshot of Xenolith's product registry so a scan can
// land on the product page Xenolith already has (and carry its CPE), and offers
// fuzzy matching for the product prompts.
package registry

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Snapshot is produced by tools/export_registry.py: [key, supplier, product, [cpes], kev].
//
//go:embed products.min.json
var Snapshot []byte

// Product is one registry entry.
type Product struct {
	Key      string
	Supplier string
	Name     string
	CPEs     []string
	KEV      int
}

// Match is a candidate with a score in (0, 1].
type Match struct {
	Product
	Score float64
}

var loaded []Product

// Load parses the embedded snapshot once.
func Load() []Product {
	if loaded != nil {
		return loaded
	}
	var rows [][]any
	if err := json.Unmarshal(Snapshot, &rows); err != nil {
		return nil
	}
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		p := Product{Key: str(r[0]), Supplier: str(r[1]), Name: str(r[2])}
		if cpes, ok := r[3].([]any); ok {
			for _, c := range cpes {
				p.CPEs = append(p.CPEs, str(c))
			}
		}
		if k, ok := r[4].(float64); ok {
			p.KEV = int(k)
		}
		loaded = append(loaded, p)
	}
	return loaded
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)
var legal = regexp.MustCompile(`\b(inc|incorporated|llc|ltd|limited|gmbh|ag|se|co|corp|corporation|company|technologies|technology|systems|software|networks)\b`)

// Normalize lowercases and strips punctuation and legal suffixes.
func Normalize(s string) string {
	s = strings.ToLower(s)
	s = legal.ReplaceAllString(s, " ")
	s = nonAlnum.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func tokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Fields(Normalize(s)) {
		out[t] = true
	}
	return out
}

// subset reports whether every token of a is in b.
func subset(a, b map[string]bool) bool {
	if len(a) == 0 {
		return false
	}
	for t := range a {
		if !b[t] {
			return false
		}
	}
	return true
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for t := range a {
		if b[t] {
			inter++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}

// Find ranks registry products against a supplier and product guess. Either may be
// empty. Exact normalised matches score 1; otherwise token overlap, with the
// supplier weighted less than the product name.
func Find(supplier, product string, limit int) []Match {
	if limit <= 0 {
		limit = 5
	}
	ps, pp := Normalize(supplier), Normalize(product)
	ts, tp := tokens(supplier), tokens(product)
	if ps == "" && pp == "" {
		return nil
	}
	var out []Match
	for _, p := range Load() {
		rs, rp := Normalize(p.Supplier), Normalize(p.Name)
		var score float64
		if pp != "" {
			rt := tokens(p.Name)
			switch {
			case rp == pp:
				score = 1
			case len(pp) >= 4 && len(rp) >= 4 && (subset(tp, rt) || subset(rt, tp)):
				score = 0.8 // every word of the shorter name appears in the longer one
			default:
				score = jaccard(tp, rt) * 0.9
			}
			if ps != "" {
				switch {
				case rs == ps:
					score = score*0.8 + 0.2
				case strings.Contains(rs, ps) || strings.Contains(ps, rs) || jaccard(ts, tokens(p.Supplier)) > 0.5:
					score = score*0.8 + 0.15
				default:
					score *= 0.6
				}
			}
		} else {
			switch {
			case rs == ps:
				score = 0.5
			case strings.Contains(rs, ps) || strings.Contains(ps, rs):
				score = 0.3
			}
		}
		if score >= 0.45 {
			out = append(out, Match{Product: p, Score: score})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].KEV != out[j].KEV {
			return out[i].KEV > out[j].KEV
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Slug mirrors xenolith.model.slug for file names and keys.
func Slug(s string) string {
	s = strings.ToLower(s)
	s = nonAlnum.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}
