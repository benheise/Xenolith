// Package report writes a scan's outputs: the public submission (minimal CycloneDX
// 1.6), the local HTML report, the not-inspected list, the log and the full
// findings file that `review` and `diff` read.
package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/benheise/Xenolith/scan/internal/detect"
	"github.com/benheise/Xenolith/scan/internal/identity"
)

// SubmitThreshold is the confidence below which a finding stays local unless kept in review.
const SubmitThreshold = 0.7

// Scan is everything a run produced, saved as findings.json.
type Scan struct {
	Tool           string             `json:"tool"`
	ToolVersion    string             `json:"tool_version"`
	Started        string             `json:"started"`
	Artifact       string             `json:"artifact"`        // file name only
	ArtifactSHA256 string             `json:"artifact_sha256"` // empty for directories and images
	ArtifactKind   string             `json:"artifact_kind"`   // file, directory, image
	Identity       identity.Guess     `json:"identity"`
	Supplier       string             `json:"supplier"`
	Product        string             `json:"product"`
	Version        string             `json:"version"`
	ProductType    string             `json:"product_type"`
	CPE            string             `json:"cpe,omitempty"`
	RegistryKey    string             `json:"registry_key,omitempty"`
	Attest         bool               `json:"attest"`
	SourceURL      string             `json:"source_url,omitempty"`
	Engines        []detect.Engine    `json:"engines"`
	Components     []detect.Component `json:"components"`
	NotInspected   []string           `json:"not_inspected"`
	Containers     []string           `json:"containers"`
	Formats        map[string]int     `json:"formats"`
	Helpers        map[string]string  `json:"helpers"`
	Distro         string             `json:"distro,omitempty"`
	Log            []string           `json:"log"`
	Duration       string             `json:"duration"`
}

// Included reports whether a component goes into the submission.
func Included(c detect.Component) bool {
	if c.Keep != nil {
		return *c.Keep
	}
	return c.Confidence >= SubmitThreshold && strings.TrimSpace(c.Name) != ""
}

// Write writes every output file into dir.
func Write(dir string, s *Scan) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if s.Components == nil {
		s.Components = []detect.Component{}
	}
	if s.NotInspected == nil {
		s.NotInspected = []string{}
	}
	if s.Containers == nil {
		s.Containers = []string{}
	}
	if s.Log == nil {
		s.Log = []string{}
	}
	if err := writeJSON(filepath.Join(dir, "findings.json"), s); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "submission.cdx.json"), Submission(s)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte(HTML(s)), 0o644); err != nil {
		return err
	}
	ni := "Not inspected (" + fmt.Sprint(len(s.NotInspected)) + ")\n" +
		"A scan shows what is present; it can never show that a component is absent. These parts of the artifact were not opened:\n\n"
	for _, n := range s.NotInspected {
		ni += n + "\n"
	}
	if len(s.NotInspected) == 0 {
		ni += "(everything the unpacker met was opened)\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "not-inspected.txt"), []byte(ni), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "scan.log"), []byte(strings.Join(s.Log, "\n")+"\n"), 0o644)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Load reads findings.json back.
func Load(dir string) (*Scan, error) {
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return nil, err
	}
	var s Scan
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// CycloneDX document types, ordered as the spec lists them so the file reads well.
type cdxDoc struct {
	BomFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp  string        `json:"timestamp"`
	Tools      cdxTools      `json:"tools"`
	Supplier   cdxName       `json:"supplier"`
	Component  cdxProduct    `json:"component"`
	Properties []cdxProperty `json:"properties"`
}

type cdxTools struct {
	Components []cdxTool `json:"components"`
}

type cdxTool struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxName struct {
	Name string `json:"name"`
}

type cdxProduct struct {
	Type     string  `json:"type"`
	BomRef   string  `json:"bom-ref"`
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	Supplier cdxName `json:"supplier"`
	CPE      string  `json:"cpe,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BomRef     string        `json:"bom-ref"`
	Group      string        `json:"group,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	CPE        string        `json:"cpe,omitempty"`
	Evidence   cdxEvidence   `json:"evidence"`
	Properties []cdxProperty `json:"properties"`
}

type cdxEvidence struct {
	Identity []cdxIdentity `json:"identity"`
}

type cdxIdentity struct {
	Field      string      `json:"field"`
	Confidence float64     `json:"confidence"`
	Methods    []cdxMethod `json:"methods"`
}

type cdxMethod struct {
	Technique  string  `json:"technique"`
	Confidence float64 `json:"confidence"`
}

// Submission builds the minimal CycloneDX 1.6 document that goes into a pull
// request: product identity, artifact hash, tools, and the kept components with
// their identity evidence. No file paths or evidence strings.
func Submission(s *Scan) cdxDoc {
	tools := []cdxTool{{Type: "application", Name: s.Tool, Version: s.ToolVersion}}
	for _, e := range s.Engines {
		if e.Name != "" && e.Name != s.Tool {
			tools = append(tools, cdxTool{Type: "application", Name: e.Name, Version: e.Version})
		}
	}
	props := []cdxProperty{{"xenolith:evidence", "binary-scan"}, {"xenolith:artifact", s.Artifact}}
	if s.ArtifactSHA256 != "" {
		props = append(props, cdxProperty{"xenolith:artifact_sha256", strings.ToLower(s.ArtifactSHA256)})
	}
	if s.SourceURL != "" {
		props = append(props, cdxProperty{"xenolith:source_url", s.SourceURL})
	}
	attest := "no"
	if s.Attest {
		attest = "yes"
	}
	props = append(props, cdxProperty{"xenolith:attestation", attest})
	if s.ArtifactKind != "" {
		props = append(props, cdxProperty{"xenolith:artifact_kind", s.ArtifactKind})
	}
	if s.RegistryKey != "" {
		props = append(props, cdxProperty{"xenolith:product_key", s.RegistryKey})
	}

	kept := make([]detect.Component, 0, len(s.Components))
	for _, c := range s.Components {
		if Included(c) {
			kept = append(kept, c)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		a, b := strings.ToLower(kept[i].Name), strings.ToLower(kept[j].Name)
		if a != b {
			return a < b
		}
		return kept[i].Version < kept[j].Version
	})
	comps := make([]cdxComponent, 0, len(kept))
	for i, c := range kept {
		methods := make([]cdxMethod, 0, len(c.Techniques))
		for _, t := range c.Techniques {
			methods = append(methods, cdxMethod{Technique: t, Confidence: round2(c.Confidence)})
		}
		cprops := []cdxProperty{
			{"xenolith:found_by", truncate(strings.Join(c.FoundBy, ", "), 200)},
			{"xenolith:confidence", fmt.Sprintf("%.2f", c.Confidence)},
		}
		if c.Watchlist != "" {
			cprops = append(cprops, cdxProperty{"xenolith:component", c.Watchlist})
		}
		if len(c.Notes) > 0 {
			cprops = append(cprops, cdxProperty{"xenolith:note", truncate(strings.Join(c.Notes, "; "), 200)})
		}
		comps = append(comps, cdxComponent{
			Type: c.Type, BomRef: fmt.Sprintf("c%d", i+1), Group: truncate(c.Group, 300), Name: truncate(c.Name, 200),
			Version: truncate(c.Version, 300), PURL: truncate(c.PURL, 300), CPE: truncate(c.CPE, 300),
			Evidence:   cdxEvidence{Identity: []cdxIdentity{{Field: "purl", Confidence: round2(c.Confidence), Methods: methods}}},
			Properties: cprops,
		})
	}
	return cdxDoc{
		BomFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: "urn:uuid:" + uuid4(), Version: 1,
		Metadata: cdxMetadata{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Tools:      cdxTools{Components: tools},
			Supplier:   cdxName{Name: s.Supplier},
			Component:  cdxProduct{Type: s.ProductType, BomRef: "product", Name: s.Product, Version: s.Version, Supplier: cdxName{Name: s.Supplier}, CPE: s.CPE},
			Properties: props,
		},
		Components: comps,
	}
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// HTML renders the local report. It is the only output that carries locations and
// evidence strings; it is written for the person who ran the scan.
func HTML(s *Scan) string {
	var b strings.Builder
	esc := html.EscapeString
	kept, low := 0, 0
	for _, c := range s.Components {
		if Included(c) {
			kept++
		} else {
			low++
		}
	}
	fmt.Fprintf(&b, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>xenolith-scan: %s %s %s</title>
<style>body{font:14px/1.45 system-ui,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem;color:#222}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.25rem}
table{border-collapse:collapse;width:100%%}th,td{text-align:left;vertical-align:top;padding:.35rem .5rem;border-bottom:1px solid #eee;font-size:13px}
th{background:#f6f6f6}code{font:12px/1.4 ui-monospace,monospace;word-break:break-all}.conf{white-space:nowrap}
.low{color:#8a6d00}.hi{color:#1a7f37}.watch{background:#fff7d6}.muted{color:#666}.note{color:#555;font-size:12px}
details summary{cursor:pointer}.card{background:#f6f8fa;padding:.75rem 1rem;border-radius:6px;margin:1rem 0}</style></head><body>`,
		esc(s.Supplier), esc(s.Product), esc(s.Version))
	fmt.Fprintf(&b, "<h1>%s %s %s</h1>", esc(s.Supplier), esc(s.Product), esc(s.Version))
	fmt.Fprintf(&b, `<div class="card"><b>Artifact:</b> <code>%s</code>`, esc(s.Artifact))
	if s.ArtifactSHA256 != "" {
		fmt.Fprintf(&b, ` &nbsp; <b>SHA-256:</b> <code>%s</code>`, s.ArtifactSHA256)
	}
	fmt.Fprintf(&b, `<br><b>Identity from:</b> %s`, esc(s.Identity.Source))
	if s.RegistryKey != "" {
		fmt.Fprintf(&b, ` &nbsp; <b>Xenolith product:</b> <a href="https://benheise.github.io/Xenolith/#p=%s">%s</a>`, esc(s.RegistryKey), esc(s.RegistryKey))
	}
	if s.Distro != "" {
		fmt.Fprintf(&b, ` &nbsp; <b>Base OS:</b> %s`, esc(s.Distro))
	}
	fmt.Fprintf(&b, `<br><b>Components:</b> %d in the submission, %d below the %.1f confidence line (local only) &nbsp; <b>Containers opened:</b> %d &nbsp; <b>Not inspected:</b> %d &nbsp; <b>Took:</b> %s`,
		kept, low, SubmitThreshold, len(s.Containers), len(s.NotInspected), esc(s.Duration))
	fmt.Fprintf(&b, `<br><span class="note">This report stays on your machine. Only <code>submission.cdx.json</code> (no paths, no evidence strings) is meant for a pull request.</span></div>`)

	watch := 0
	for _, c := range s.Components {
		if c.Watchlist != "" {
			watch++
		}
	}
	if watch > 0 {
		b.WriteString("<h2>Watchlist components</h2><table><tr><th>Component</th><th>Version</th><th>Confidence</th><th>How</th><th>Where</th><th>Evidence</th></tr>")
		for _, c := range s.Components {
			if c.Watchlist != "" {
				row(&b, c)
			}
		}
		b.WriteString("</table>")
	}
	b.WriteString("<h2>All components</h2><table><tr><th>Component</th><th>Version</th><th>Confidence</th><th>How</th><th>Where</th><th>Evidence</th></tr>")
	for _, c := range s.Components {
		row(&b, c)
	}
	b.WriteString("</table>")
	b.WriteString("<h2>Not inspected</h2><p class=\"note\">A scan can show what is present, never that something is absent.</p>")
	if len(s.NotInspected) == 0 {
		b.WriteString("<p>Everything the unpacker met was opened.</p>")
	} else {
		b.WriteString("<ul>")
		for _, n := range s.NotInspected {
			fmt.Fprintf(&b, "<li><code>%s</code></li>", esc(n))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("<h2>Containers opened</h2><ul>")
	for _, c := range s.Containers {
		fmt.Fprintf(&b, "<li><code>%s</code></li>", esc(c))
	}
	b.WriteString("</ul><h2>Engines</h2><ul>")
	for _, e := range s.Engines {
		fmt.Fprintf(&b, "<li>%s %s</li>", esc(e.Name), esc(e.Version))
	}
	for name, p := range s.Helpers {
		if p == "" {
			fmt.Fprintf(&b, "<li class=\"muted\">%s: not installed</li>", esc(name))
		} else {
			fmt.Fprintf(&b, "<li>%s: %s</li>", esc(name), esc(p))
		}
	}
	b.WriteString("</ul><details><summary>Log</summary><pre>")
	for _, l := range s.Log {
		b.WriteString(esc(l) + "\n")
	}
	b.WriteString("</pre></details></body></html>\n")
	return b.String()
}

func row(b *strings.Builder, c detect.Component) {
	esc := html.EscapeString
	cls := "hi"
	if !Included(c) {
		cls = "low"
	}
	tr := "<tr>"
	if c.Watchlist != "" {
		tr = `<tr class="watch">`
	}
	name := esc(c.Name)
	if c.Group != "" {
		name = esc(c.Group) + ":" + name
	}
	where := make([]string, 0, len(c.Locations))
	for i, l := range c.Locations {
		if i >= 8 {
			where = append(where, fmt.Sprintf("… %d more", len(c.Locations)-8))
			break
		}
		where = append(where, "<code>"+esc(l)+"</code>")
	}
	ev := make([]string, 0, len(c.Evidence)+len(c.Notes))
	for _, e := range c.Evidence {
		ev = append(ev, "<code>"+esc(e)+"</code>")
	}
	for _, n := range c.Notes {
		ev = append(ev, `<span class="note">`+esc(n)+"</span>")
	}
	kept := ""
	if c.Keep != nil {
		if *c.Keep {
			kept = " (kept)"
		} else {
			kept = " (dropped)"
		}
	}
	fmt.Fprintf(b, `%s<td>%s</td><td>%s</td><td class="conf %s">%.2f%s</td><td>%s<br><span class="muted">%s</span></td><td>%s</td><td>%s</td></tr>`,
		tr, name, esc(c.Version), cls, c.Confidence, kept, esc(strings.Join(c.Techniques, ", ")), esc(strings.Join(c.FoundBy, ", ")),
		strings.Join(where, "<br>"), strings.Join(ev, "<br>"))
}
