package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func findings(t *testing.T, s *Scanner) map[string]Finding {
	t.Helper()
	out := map[string]Finding{}
	for _, f := range s.Findings {
		out[f.Component+"@"+f.Version] = f
	}
	return out
}

func TestVersionStrings(t *testing.T) {
	pack, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	s := New(pack)
	// OpenSSL needs OPENSSLDIR too (PHP carries the header string on its own).
	s.Binary(append([]byte{0x7f, 'E', 'L', 'F'}, []byte("xx OpenSSL 3.0.13 30 Jan 2024\x00OPENSSLDIR: \"/usr/lib/ssl\"")...), "libcrypto.so.3")
	s.Binary(append([]byte{0x7f, 'E', 'L', 'F'}, []byte("X-Powered-By: PHP/8.2.20\x00OpenSSL 3.0.13 30 Jan 2024")...), "php")
	s.Binary(append([]byte("MZ"), []byte("\x00libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3\x00curl_easy_init")...), "libcurl.dll")
	s.Binary(append([]byte("MZ"), []byte("\x00OpenSSH_9.6p1 Ubuntu-3ubuntu13\x00/etc/ssh/sshd_config")...), "sshd")
	s.Binary(append([]byte{0x7f, 'E', 'L', 'F'}, []byte("GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39.")...), "libc.so.6")
	s.Binary(append([]byte{0x7f, 'E', 'L', 'F'}, []byte("xz (XZ Utils) 5.4.5")...), "xz")
	got := findings(t, s)
	for _, want := range []string{"openssl@3.0.13", "php@8.2.20", "curl@8.5.0", "openssh@9.6p1", "glibc@2.39", "xz@5.4.5"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, keys(got))
		}
	}
	if n := count(s.Findings, "openssl"); n != 1 {
		t.Errorf("OpenSSL should be reported once (not from PHP's header string); got %d", n)
	}
	if f := got["xz@5.4.5"]; f.Name != "XZ Utils" {
		t.Errorf("xz string rule should report as 'XZ Utils', got %q", f.Name)
	}
	if f := got["curl@8.5.0"]; f.Evidence != "libcurl/8.5.0" {
		t.Errorf("curl evidence should be the matched token without the preceding character, got %q", f.Evidence)
	}
}

func TestLookbehindRewrite(t *testing.T) {
	pack, _ := LoadEmbedded()
	s := New(pack)
	// "libcurl/8.5.0" must not also produce a bare curl/ match, and "xcurl/1.2.3" is not curl.
	s.Binary(append([]byte("MZ"), []byte("\x00xcurl/1.2.3 curl_easy_init\x00")...), "a.dll")
	if n := count(s.Findings, "curl"); n != 0 {
		t.Fatalf("xcurl/ should not match the curl/ rule, got %+v", s.Findings)
	}
	s.Binary(append([]byte("MZ"), []byte("\x00 curl/8.1.2 curl_easy_init\x00")...), "b.dll")
	if n := count(s.Findings, "curl"); n != 1 {
		t.Fatalf("' curl/8.1.2' should match once, got %+v", s.Findings)
	}
}

func TestPathRules(t *testing.T) {
	pack, _ := LoadEmbedded()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.jar!/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
	write("app.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class", "\xca\xfe\xba\xbe")
	write("lib/spring-beans.jar!/META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nImplementation-Title: spring-beans\r\nImplementation-Version: 5.3.20\r\n")
	write("lib/other.jar!/META-INF/MANIFEST.MF", "Implementation-Title: other\r\nImplementation-Version: 1.0\r\n")
	write("web/node_modules/react-server-dom-webpack/package.json", `{"name":"react-server-dom-webpack","version":"19.0.0"}`)
	write("old/log4j-1.2.17.jar", "PK")
	s := New(pack)
	s.ScanTree(root, nil)
	got := findings(t, s)
	for _, want := range []string{"log4j-core@2.14.1", "spring-framework@5.3.20", "react-server-components@19.0.0", "log4j-1@1.2.17"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, keys(got))
		}
	}
	if f := got["react-server-components@19.0.0"]; f.Name != "react-server-dom-webpack" || f.PURL != "pkg:npm/react-server-dom-webpack@19.0.0" {
		t.Errorf("react rule should name the matched package: %+v", f)
	}
	if f := got["log4j-1@1.2.17"]; f.Technique != "filename" || f.Confidence != 0.5 {
		t.Errorf("file-name-only finding should be low confidence: %+v", f)
	}
	groups := Summarize(s.Findings)
	for _, g := range groups {
		if g.Component == "log4j-core" && g.Version == "" {
			t.Errorf("JndiLookup presence should fold into the versioned log4j-core entry from the same jar")
		}
	}
}

func count(fs []Finding, component string) int {
	n := 0
	for _, f := range fs {
		if f.Component == component {
			n++
		}
	}
	return n
}

func keys(m map[string]Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEmbeddedPackMatchesCatalog(t *testing.T) {
	// The embedded copy must be the catalog's file (make sync).
	catalog, err := os.ReadFile(filepath.Join("..", "..", "..", "catalog", "fingerprints.yaml"))
	if err != nil {
		t.Skip("catalog not available:", err)
	}
	if string(catalog) != string(PackYAML) {
		t.Fatal("scan/internal/fingerprint/pack.yaml differs from catalog/fingerprints.yaml; run `make -C scan sync`")
	}
}
