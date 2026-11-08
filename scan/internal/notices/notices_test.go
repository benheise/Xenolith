package notices

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func names(cs []Component) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name+"@"+c.Version)
	}
	return strings.Join(out, " ")
}

func TestThirdPartyNoticesList(t *testing.T) {
	text := "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION\n\nThis product incorporates components from the projects listed below.\n\n" +
		"- zlib 1.2.13\n- OpenSSL 3.0.13\n- libcurl (8.5.0)\n- @angular/core@17.3.1\n- Version 2.0\n"
	comps, format := Parse([]byte(text), "THIRD-PARTY-NOTICES.txt")
	if format != "name-version-lines" {
		t.Fatalf("format %s", format)
	}
	got := names(comps)
	for _, w := range []string{"zlib@1.2.13", "OpenSSL@3.0.13", "libcurl@8.5.0", "@angular/core@17.3.1"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
	if strings.Contains(got, "Version@") {
		t.Errorf("'Version 2.0' is a heading, not a component: %s", got)
	}
}

func TestBlackDuckAndTable(t *testing.T) {
	text := "Components:\n\ngreenlet 3.2.5: http://pypi.python.org/pypi/greenlet : MIT License\nCRaSH 1.0.0-beta21 : GNU Lesser General Public License v2.1\n\n" +
		"| Component | Version | License |\n|---|---|---|\n| jackson-databind | 2.15.2 | Apache-2.0 |\n"
	comps, _ := Parse([]byte(text), "notices.md")
	got := names(comps)
	for _, w := range []string{"greenlet@3.2.5", "CRaSH@1.0.0-beta21", "jackson-databind@2.15.2"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
}

func TestEmbeddedSBOMAndChromium(t *testing.T) {
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"brotli","version":"1.1.0"},{"group":"org.apache.logging.log4j","name":"log4j-core","version":"2.20.0"}]}`
	comps, format := Parse([]byte(bom), "bom.json")
	if format != "sbom" || names(comps) != "brotli@1.1.0 org.apache.logging.log4j:log4j-core@2.20.0" {
		t.Fatalf("sbom parse: %s %s", format, names(comps))
	}
	html := `<html><body><h2>Credits</h2><div class="product"><span class="title">libwebp</span><a href="#">show license</a></div><div class="product"><span class="title">zlib</span></div></body></html>`
	comps, format = Parse([]byte(html), "LICENSES.chromium.html")
	if format != "chromium-licenses" || names(comps) != "libwebp@ zlib@" {
		t.Fatalf("chromium parse: %s %s", format, names(comps))
	}
}

func TestNameHints(t *testing.T) {
	for _, n := range []string{"THIRD-PARTY-NOTICES.txt", "ThirdPartyNotices.md", "NOTICE", "LICENSES.chromium.html", "open_source_licenses.txt",
		"OSS_Attribution.pdf", "app.cdx.json", "sbom.json", "credits.html", "third_party_licenses.html"} {
		if !nameHints.MatchString(n) {
			t.Errorf("%s should be a notices candidate", n)
		}
	}
	for _, n := range []string{"LICENSE", "README.md", "main.js", "libssl.so.3"} {
		if nameHints.MatchString(n) {
			t.Errorf("%s should not be a notices candidate", n)
		}
	}
}

// An HTML notices page that is not Chromium's format goes through htmlToText; its
// script/style removal once used a backreference RE2 rejects, which panicked on the
// first such file (a Netgear firmware's open-source page).
func TestHTMLNoticesWithScripts(t *testing.T) {
	page := `<html><head><style>p { color: red }</style><script>var x = "zlib 9.9.9";</script></head>
<body><h1>Open Source Notices</h1><table><tr><th>Component</th><th>Version</th></tr>
<tr><td>BusyBox</td><td>1.36.1</td></tr><tr><td>zlib</td><td>1.2.13</td></tr></table>
<noscript>libfoo 1.0</noscript></body></html>`
	comps, _ := Parse([]byte(page), "open_source_notices.html")
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
	}
	if got["BusyBox"] != "1.36.1" || got["zlib"] != "1.2.13" {
		t.Errorf("table rows: %v", comps)
	}
	for _, c := range comps {
		if c.Version == "9.9.9" || c.Name == "libfoo" {
			t.Errorf("text inside script/noscript was parsed: %+v", c)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "THIRD-PARTY-NOTICES.html"), []byte(page), 0o644); err != nil {
		t.Fatal(err)
	}
	files, skipped := Scan(dir, nil)
	if len(files) != 1 || len(skipped) != 0 {
		t.Errorf("scan: files=%v skipped=%v", files, skipped)
	}
}
