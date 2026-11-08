package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benheise/Xenolith/scan/internal/detect"
)

func TestSubmissionShape(t *testing.T) {
	f := false
	s := &Scan{Tool: "xenolith-scan", ToolVersion: "test", Artifact: "acme.bin", ArtifactSHA256: "AB" + strings.Repeat("0", 62),
		ArtifactKind: "file", Supplier: "Acme", Product: "Firewall", Version: "7.2.9", ProductType: "firmware", Attest: true,
		Engines: []detect.Engine{{Name: "syft", Version: "v1"}},
		Components: []detect.Component{
			{Name: "openssl", Version: "3.0.13", Type: "library", PURL: "pkg:generic/openssl@3.0.13", Watchlist: "openssl", Confidence: 0.9,
				Techniques: []string{"binary-analysis"}, FoundBy: []string{"xenolith-fingerprint"}, Locations: []string{"a!/b/libcrypto.so"}, Evidence: []string{"OpenSSL 3.0.13 30 Jan 2024"}},
			{Name: "log4j-core", Group: "org.apache.logging.log4j", Type: "library", Confidence: 0.5, Techniques: []string{"filename"}, FoundBy: []string{"xenolith-fingerprint"}},
			{Name: "dropped", Version: "1", Type: "library", Confidence: 0.95, Keep: &f},
		}}
	dir := t.TempDir()
	if err := Write(dir, s); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "submission.cdx.json"))
	text := string(b)
	if strings.Contains(text, "libcrypto.so") || strings.Contains(text, "30 Jan 2024") {
		t.Fatal("submission must not carry locations or evidence strings")
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	comps := doc["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("only the high-confidence, not-dropped component belongs in the submission: %d", len(comps))
	}
	c := comps[0].(map[string]any)
	if c["name"] != "openssl" || c["purl"] != "pkg:generic/openssl@3.0.13" {
		t.Fatalf("component: %v", c)
	}
	meta := doc["metadata"].(map[string]any)
	props := map[string]string{}
	for _, p := range meta["properties"].([]any) {
		m := p.(map[string]any)
		props[m["name"].(string)] = m["value"].(string)
	}
	if props["xenolith:artifact_sha256"] != "ab"+strings.Repeat("0", 62) || props["xenolith:attestation"] != "yes" || props["xenolith:evidence"] != "binary-scan" {
		t.Fatalf("properties: %v", props)
	}
	if strings.Index(text, `"bomFormat"`) > strings.Index(text, `"metadata"`) {
		t.Fatal("document should start with bomFormat")
	}
	// the local report keeps everything
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	if !strings.Contains(string(html), "libcrypto.so") || !strings.Contains(string(html), "log4j-core") {
		t.Fatal("report.html should show locations and low-confidence findings")
	}
	loaded, err := Load(dir)
	if err != nil || len(loaded.Components) != 3 {
		t.Fatalf("Load: %v %d", err, len(loaded.Components))
	}
}
