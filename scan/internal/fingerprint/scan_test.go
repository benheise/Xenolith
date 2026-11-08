package fingerprint

import (
	"debug/elf"
	"encoding/binary"
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

func TestMostSpecificVersionAndPatterns(t *testing.T) {
	pack, _ := LoadEmbedded()
	s := New(pack)
	// Debian's sshd: the bare SSH_VERSION first, a compat table of patterns, then the full release.
	data := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("x\x00OpenSSH_9.2\x00%s\x00OpenSSH_7.0*,OpenSSH_7.1*\x00OpenSSH_10.1*\x00"+
		"OpenSSH_9.2p1 Debian-2+deb12u9\x00sshd_config\x00")...)
	s.Binary(data, "usr/sbin/sshd")
	if len(s.Findings) != 1 || s.Findings[0].Version != "9.2p1" {
		t.Fatalf("want openssh 9.2p1, got %+v", s.Findings)
	}
}

func TestFramedProbes(t *testing.T) {
	pack, _ := LoadEmbedded()
	// Pillow's liblzma keeps frame pointers: push rbp; mov rbp,rsp; mov eax,imm; pop rbp; ret
	x86 := []byte{0x55, 0x48, 0x89, 0xe5, 0xb8, 0xea, 0x8c, 0xfb, 0x02, 0x5d, 0xc3}
	data := makeELF(elf.EM_X86_64, []testSymbol{{"lzma_version_number", x86}, {"lzma_code", []byte{0xc3}}, {"lzma_stream_decoder", []byte{0xc3}}}, nil)
	s := New(pack)
	s.Binary(data, "Pillow.libs/liblzma-1e44b93d.so.5.4.4")
	if len(s.Findings) != 1 || s.Findings[0].Version != "5.4.4" {
		t.Fatalf("framed x86-64 probe: %+v", s.Findings)
	}
	// AArch64 with a frame record: stp x29,x30,[sp,#-16]!; mov x29,sp; movz; movk; ldp; ret
	movz := uint32(0x52800000) | (0x8cea << 5)
	movk := uint32(0x72800000) | (1 << 21) | (0x02fb << 5)
	code := make([]byte, 24)
	for i, ins := range []uint32{0xA9BF7BFD, 0x910003FD, movz, movk, 0xA8C17BFD, 0xD65F03C0} {
		binary.LittleEndian.PutUint32(code[4*i:], ins)
	}
	data = makeELF(elf.EM_AARCH64, []testSymbol{{"lzma_version_number", code}, {"lzma_code", []byte{0, 0, 0, 0}}, {"lzma_stream_decoder", []byte{0, 0, 0, 0}}}, nil)
	s = New(pack)
	s.Binary(data, "liblzma.so.5")
	if len(s.Findings) != 1 || s.Findings[0].Version != "5.4.4" {
		t.Fatalf("framed AArch64 probe: %+v", s.Findings)
	}
}

func TestNextTarballPath(t *testing.T) {
	pack, _ := LoadEmbedded()
	s := New(pack)
	s.paths("next-15.0.4.tgz!/next-15.0.4.tar!/package/dist/compiled/react-server-dom-webpack/package.json",
		func() []byte {
			return []byte(`{"name":"react-server-dom-webpack","version":"19.0.0-rc-66855b96-20241106"}`)
		}, nil)
	if len(s.Findings) != 1 || s.Findings[0].Version != "19.0.0-rc-66855b96-20241106" {
		t.Fatalf("npm tarball layout: %+v", s.Findings)
	}
}

// Next.js strips "version" from the React packages it vendors; the scanner reads it
// from the React build next to them, matching stable and experimental channels.
func TestSiblingVersion(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := "package/dist/compiled/"
	write(c+"react-server-dom-webpack/package.json", `{"name":"react-server-dom-webpack-builtin","main":"index.js"}`)
	write(c+"react-server-dom-webpack-experimental/package.json", `{"name":"react-server-dom-webpack-builtin"}`)
	write(c+"react-server-dom-turbopack/package.json", `{"name":"react-server-dom-turbopack-builtin"}`)
	write(c+"react/cjs/react.production.js", `"use strict";exports.version = "19.0.0-rc-66855b96-20241106";`)
	write(c+"react-experimental/cjs/react.production.js", `exports.version = "19.0.0-experimental-66855b96-20241106";`)
	pack, _ := LoadEmbedded()
	s := New(pack)
	s.ScanTree(root, nil)
	got := map[string]Finding{}
	for _, f := range s.Findings {
		got[f.Location] = f
	}
	want := map[string]string{
		c + "react-server-dom-webpack/package.json":              "19.0.0-rc-66855b96-20241106",
		c + "react-server-dom-webpack-experimental/package.json": "0.0.0-experimental-66855b96-20241106",
		c + "react-server-dom-turbopack/package.json":            "19.0.0-rc-66855b96-20241106",
	}
	for loc, v := range want {
		f, ok := got[loc]
		if !ok || f.Version != v || f.Confidence != 0.8 || f.Note == "" {
			t.Errorf("%s: got %+v, want version %s at 0.8 with a note", loc, f, v)
		}
	}
	if len(s.Findings) != len(want) {
		t.Errorf("findings: %+v", s.Findings)
	}
	// without the sibling the finding stays, unversioned, at the presence confidence
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(c+"react/cjs/react.production.js"))); err != nil {
		t.Fatal(err)
	}
	s = New(pack)
	s.ScanFile(filepath.Join(root, filepath.FromSlash(c+"react-server-dom-turbopack/package.json")), "x/dist/compiled/react-server-dom-turbopack/package.json")
	if len(s.Findings) != 1 || s.Findings[0].Version != "" || s.Findings[0].Confidence != 0.9 {
		t.Errorf("missing sibling: %+v", s.Findings)
	}
}

func FuzzBinary(f *testing.F) {
	pack, _ := LoadEmbedded()
	f.Add(makeELF(elf.EM_X86_64, []testSymbol{{"BrotliDecoderVersion", movEaxRet(0x01001009)}}, nil))
	f.Add([]byte("MZ\x00OpenSSL 3.0.13 30 Jan 2024 OPENSSLDIR:"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := New(pack)
		s.binary(data, "fuzz") // the unrecovered path: any panic fails the fuzz run
	})
}
