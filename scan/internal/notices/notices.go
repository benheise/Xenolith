// Package notices finds and parses third-party notices files shipped inside a
// product (THIRD-PARTY-NOTICES.txt, NOTICE, LICENSES.chromium.html, embedded
// CycloneDX/SPDX files). It is a focused port of the text extractors in
// xenolith/sources/notices.py; the same shapes parse the same way.
package notices

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Component is one entry read from a notices file.
type Component struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Evidence string `json:"evidence"`
}

// File is one notices file and what it listed.
type File struct {
	Location   string      `json:"location"`
	Format     string      `json:"format"`
	Components []Component `json:"components"`
}

const maxBytes = 32 << 20

var nameHints = regexp.MustCompile(`(?i)^(?:third[-_ ]?party[-_ ]?(?:notices?|licen[cs]es?|software|components?)[^/]*|` +
	`notices?(?:\.(?:txt|md|html?))?|licenses\.chromium\.html|credits\.html|` +
	`[^/]*open[-_ ]?source[-_ ]?licen[cs]es?[^/]*|[^/]*oss[-_ ]?(?:licen[cs]es?|notice|attribution)[^/]*|` +
	`[^/]*attributions?(?:\.(?:txt|md|html?|pdf))?|[^/]*\.(?:cdx|spdx)\.json|(?:s?bom|sbom)\.json|[^/]*\.spdx)$`)

// Scan walks a tree for notices files and parses them. A parser panic on one file is
// recorded in skipped (location: reason) and the walk goes on.
func Scan(root string, locate func(string) string) (out []File, skipped []string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		base := d.Name()
		if !nameHints.MatchString(base) {
			return nil
		}
		st, err := d.Info()
		if err != nil || st.Size() == 0 || st.Size() > maxBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		loc := p
		if locate != nil {
			loc = locate(p)
		}
		comps, format, perr := safeParse(data, base)
		if perr != nil {
			skipped = append(skipped, loc+": notices parser crashed (please report): "+perr.Error())
			return nil
		}
		if len(comps) > 0 {
			out = append(out, File{Location: loc, Format: format, Components: comps})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Location < out[j].Location })
	return out, skipped
}

func safeParse(data []byte, name string) (comps []Component, format string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			comps, format, err = nil, "", fmt.Errorf("%v", rec)
		}
	}()
	comps, format = Parse(data, name)
	return comps, format, nil
}

// Parse extracts components from a notices document.
func Parse(data []byte, name string) ([]Component, string) {
	text := string(data)
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		if comps := parseSBOM(data); len(comps) > 0 {
			return dedupe(comps), "sbom"
		}
	}
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") || strings.Contains(text[:min(len(text), 2000)], "<html") {
		if comps := parseChromium(text); len(comps) > 0 {
			return dedupe(comps), "chromium-licenses"
		}
		text = htmlToText(text)
	}
	var comps []Component
	format := ""
	add := func(f string, cs []Component) {
		if len(cs) > 0 {
			comps = append(comps, cs...)
			if format == "" {
				format = f
			}
		}
	}
	add("pipe-table", parsePipeTable(text))
	add("black-duck", parseBlackDuck(text))
	add("url-lines", parseURLLines(text))
	add("jar-names", parseJarNames(text))
	if len(comps) == 0 {
		add("name-version-lines", parseNameVersionLines(text))
	}
	return dedupe(comps), format
}

func dedupe(cs []Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, c := range cs {
		c.Name = strings.TrimSpace(strings.Trim(c.Name, " -–:;,"))
		c.Version = strings.TrimSpace(strings.Trim(c.Version, " ,;"))
		if c.Name == "" || !plausible(c.Name) {
			continue
		}
		key := strings.ToLower(c.Name) + "@" + strings.ToLower(c.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(c.Evidence) > 200 {
			c.Evidence = c.Evidence[:200]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	return out
}

var stopWords = regexp.MustCompile(`(?i)\b(licen[cs]e[sd]?|copyright|notices?|appendix|section|table of contents|terms and conditions|general public|all rights reserved|disclaimer|warrant(y|ies)|page \d+)\b`)

func plausible(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 || !hasLetter.MatchString(name) {
		return false
	}
	return !stopWords.MatchString(name)
}

// --- SBOM files ---------------------------------------------------------

func parseSBOM(data []byte) []Component {
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
		Components  []struct {
			Name       string          `json:"name"`
			Group      string          `json:"group"`
			Version    string          `json:"version"`
			Components json.RawMessage `json:"components"`
		} `json:"components"`
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"versionInfo"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Component
	if doc.BomFormat == "CycloneDX" {
		for _, c := range doc.Components {
			name := c.Name
			if c.Group != "" {
				name = c.Group + ":" + c.Name
			}
			out = append(out, Component{Name: name, Version: c.Version, Evidence: "CycloneDX component"})
		}
	} else if strings.HasPrefix(doc.SpdxVersion, "SPDX-") {
		for _, p := range doc.Packages {
			out = append(out, Component{Name: p.Name, Version: p.Version, Evidence: "SPDX package"})
		}
	}
	return out
}

// --- HTML ---------------------------------------------------------------

var chromiumTitle = regexp.MustCompile(`(?is)<span class="title">(.*?)</span>`)
var tagRe = regexp.MustCompile(`(?s)<[^>]+>`)

func parseChromium(html string) []Component {
	var out []Component
	for _, m := range chromiumTitle.FindAllStringSubmatch(html, -1) {
		name := strings.TrimSpace(tagRe.ReplaceAllString(m[1], ""))
		if name != "" {
			out = append(out, Component{Name: name, Evidence: "LICENSES.chromium.html title"})
		}
	}
	return out
}

// RE2 has no backreferences, so each element that holds no text gets its own branch.
var (
	htmlNoText = regexp.MustCompile(`(?is)<script\b.*?</script\s*>|<style\b.*?</style\s*>|<noscript\b.*?</noscript\s*>`)
	htmlBreak  = regexp.MustCompile(`(?i)<br\s*/?>|</(p|div|li|tr|h[1-6]|pre|table|dd|dt)>`)
	htmlCell   = regexp.MustCompile(`(?i)</t[dh]>`)
	hasLetter  = regexp.MustCompile(`[A-Za-z]`)
)

func htmlToText(html string) string {
	html = htmlNoText.ReplaceAllString(html, " ")
	html = htmlBreak.ReplaceAllString(html, "\n")
	html = htmlCell.ReplaceAllString(html, " | ")
	text := tagRe.ReplaceAllString(html, " ")
	for _, r := range [][2]string{{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", `"`}, {"&#39;", "'"}, {"&nbsp;", " "}} {
		text = strings.ReplaceAll(text, r[0], r[1])
	}
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		lines = append(lines, strings.Join(strings.Fields(l), " "))
	}
	return strings.Join(lines, "\n")
}

// --- tables and lists ---------------------------------------------------

var nameHeaders = map[string]bool{"name": true, "component": true, "components": true, "component name": true, "package": true,
	"package name": true, "software": true, "library": true, "project": true, "module": true, "third party software": true,
	"third-party software": true, "product/library": true, "dependency": true}
var versionHeaders = map[string]bool{"version": true, "component version": true, "package version": true, "release": true}

func parsePipeTable(text string) []Component {
	var out []Component
	ni, vi := -1, -1
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue // HTML tables flatten to rows separated by blank lines
		}
		if !strings.Contains(line, "|") {
			ni, vi = -1, -1
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		hn, hv := -1, -1
		for i, c := range cells {
			l := strings.TrimSuffix(strings.ToLower(c), ":")
			if nameHeaders[l] && hn < 0 {
				hn = i
			}
			if versionHeaders[l] && hv < 0 {
				hv = i
			}
		}
		if hn >= 0 && hv >= 0 && hn != hv {
			ni, vi = hn, hv
			continue
		}
		if ni < 0 || ni >= len(cells) || vi >= len(cells) {
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue
		}
		if plausible(cells[ni]) {
			out = append(out, Component{Name: cells[ni], Version: cells[vi], Evidence: strings.TrimSpace(line)})
		}
	}
	return out
}

var (
	componentsHead = regexp.MustCompile(`(?im)^\s*Components:\s*$`)
	bdLine         = regexp.MustCompile(`(?m)^\s*([A-Za-z@][^:\n]{0,120}?)\s+(v?\d[\w.\-+~]*)\s*:\s+(\S.*)$`)
	bdRest         = regexp.MustCompile(`(?i)licen|gpl|\bmit\b|bsd|apache|public domain|https?://|commercial|proprietary|unspecified|unknown|artistic|cddl|\bepl\b|\bmpl\b|internal|\bfree\b|zlib|\bisc\b|openssl|boost|unicode|w3c|eula|agreement|permissive|ms-pl|bouncy|creative|python|eclipse|mozilla|oracle|microsoft|sun\b`)
	urlLine        = regexp.MustCompile(`(?m)^\s*(\S.{0,150}?)\s+(v?\d[\w.\-+~]*):\s+https?://`)
	jarName        = regexp.MustCompile(`([A-Za-z][\w.+-]*?)-(\d[\w.+~-]*)\.jar\b`)
	nvLine         = regexp.MustCompile(`^([A-Za-z.@][\w.+/:@()\-]*(?: [A-Za-z][\w.+/:@()\-]*){0,5})(?:\s+v?|\s+\(v?|@v?)(\d+(?:\.\d+)+[\w.\-+~]*)\)?$`)
	nvGate         = regexp.MustCompile(`(?i)third[- ]party|open[- ]source|notices|attribution|acknowledg`)
)

var nvStopLast = map[string]bool{"version": true, "release": true, "revision": true, "chapter": true, "section": true, "page": true,
	"step": true, "figure": true, "table": true, "part": true, "build": true, "document": true, "copyright": true, "edition": true,
	"volume": true, "issue": true, "rev": true, "draft": true, "update": true, "patch": true, "hotfix": true, "pack": true,
	"v": true, "ver": true, "guide": true, "manual": true, "notes": true, "since": true, "than": true, "to": true, "of": true,
	"for": true, "and": true, "or": true, "in": true, "on": true, "at": true, "by": true}

func parseBlackDuck(text string) []Component {
	if !componentsHead.MatchString(text) {
		return nil
	}
	var out []Component
	for _, m := range bdLine.FindAllStringSubmatch(text, -1) {
		name := strings.TrimSpace(m[1])
		if bdRest.MatchString(m[3]) && plausible(name) && !strings.HasPrefix(strings.ToLower(name), "http") {
			out = append(out, Component{Name: name, Version: m[2], Evidence: strings.TrimSpace(m[0])})
		}
	}
	return out
}

func parseURLLines(text string) []Component {
	var out []Component
	for _, m := range urlLine.FindAllStringSubmatch(text, -1) {
		if plausible(m[1]) {
			out = append(out, Component{Name: strings.TrimSpace(m[1]), Version: m[2], Evidence: strings.TrimSpace(m[0])})
		}
	}
	return out
}

func parseJarNames(text string) []Component {
	var out []Component
	for _, m := range jarName.FindAllStringSubmatch(text, -1) {
		if plausible(m[1]) {
			out = append(out, Component{Name: m[1], Version: m[2], Evidence: m[0]})
		}
	}
	return out
}

func parseNameVersionLines(text string) []Component {
	if !nvGate.MatchString(text) {
		return nil
	}
	var out []Component
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimLeft(raw, "-*•· \t"))
		m := nvLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		words := strings.Fields(name)
		if len(words) == 0 || nvStopLast[strings.ToLower(words[len(words)-1])] || !plausible(name) {
			continue
		}
		out = append(out, Component{Name: name, Version: m[2], Evidence: line})
	}
	if len(out) < 3 {
		return nil
	}
	return out
}
