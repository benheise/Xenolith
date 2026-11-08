package notices

import (
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
