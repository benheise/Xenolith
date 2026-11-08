package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blakesmith/ar"
	"github.com/cavaliergopher/cpio"
)

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(files[n]))
	}
	w.Close()
	return buf.Bytes()
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		tw.Write(files[n])
	}
	tw.WriteHeader(&tar.Header{Name: "evil", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func locations(r *Result) []string {
	out := make([]string, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, e.Location)
	}
	sort.Strings(out)
	return out
}

func TestNestedArchives(t *testing.T) {
	jar := zipBytes(t, map[string]string{
		"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": "version=2.14.1\n",
		"org/apache/logging/log4j/core/lookup/JndiLookup.class":             "\xca\xfe\xba\xbe",
	})
	inner := tarGz(t, map[string][]byte{
		"opt/app/lib/log4j-core-2.14.1.jar": jar,
		"usr/lib/libcrypto.so.3":            append([]byte{0x7f, 'E', 'L', 'F'}, []byte("OpenSSL 3.0.13 30 Jan 2024 OPENSSLDIR: \"/x\"")...),
		"../escape.txt":                     []byte("nope"),
	})
	dir := t.TempDir()
	artifact := filepath.Join(dir, "acme-fw-7.2.9.tar.gz")
	if err := os.WriteFile(artifact, inner, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Run(artifact, Options{Root: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	got := locations(r)
	want := []string{
		"acme-fw-7.2.9.tar.gz!/acme-fw-7.2.9.tar",
		"acme-fw-7.2.9.tar.gz!/acme-fw-7.2.9.tar!/opt/app/lib/log4j-core-2.14.1.jar",
		"acme-fw-7.2.9.tar.gz!/acme-fw-7.2.9.tar!/opt/app/lib/log4j-core-2.14.1.jar!/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
		"acme-fw-7.2.9.tar.gz!/acme-fw-7.2.9.tar!/opt/app/lib/log4j-core-2.14.1.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class",
		"acme-fw-7.2.9.tar.gz!/acme-fw-7.2.9.tar!/usr/lib/libcrypto.so.3",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("locations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(r.Containers) != 3 || r.Formats["gzip"] != 1 || r.Formats["tar"] != 1 || r.Formats["zip"] != 1 {
		t.Errorf("containers: %+v formats %v", r.Containers, r.Formats)
	}
	foundEscape := false
	for _, n := range r.NotInspected {
		if strings.Contains(n, "escape.txt") && strings.Contains(n, "unsafe") {
			foundEscape = true
		}
	}
	if !foundEscape {
		t.Errorf("path traversal member should be reported: %v", r.NotInspected)
	}
	// Locate maps the on-disk path of the pom back to its logical location.
	for _, e := range r.Entries {
		if strings.HasSuffix(e.Location, "pom.properties") && r.Locate(e.Path) != e.Location {
			t.Errorf("Locate(%s) = %s, want %s", e.Path, r.Locate(e.Path), e.Location)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); err == nil {
		t.Log("root kept until Cleanup")
	}
}

func TestDebAndCpio(t *testing.T) {
	// A .deb is an ar archive holding control.tar.gz and data.tar.gz.
	data := tarGz(t, map[string][]byte{"usr/bin/tool": []byte("MZ\x00libcurl/8.5.0 curl_easy_init")})
	var deb bytes.Buffer
	w := ar.NewWriter(&deb)
	w.WriteGlobalHeader()
	for _, m := range []struct {
		name string
		body []byte
	}{{"debian-binary", []byte("2.0\n")}, {"data.tar.gz", data}} {
		if err := w.WriteHeader(&ar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body))}); err != nil {
			t.Fatal(err)
		}
		w.Write(m.body)
	}
	var cp bytes.Buffer
	cw := cpio.NewWriter(&cp)
	cw.WriteHeader(&cpio.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len("ID=acme\n"))})
	cw.Write([]byte("ID=acme\n"))
	cw.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tool_1.0_amd64.deb"), deb.Bytes(), 0o644)
	os.WriteFile(filepath.Join(dir, "initrd.cpio"), cp.Bytes(), 0o644)
	r, err := Run(dir, Options{Root: filepath.Join(t.TempDir(), "out"), Helpers: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	got := strings.Join(locations(r), "\n")
	for _, want := range []string{"tool_1.0_amd64.deb!/data.tar.gz!/data.tar!/usr/bin/tool", "initrd.cpio!/etc/os-release"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	if len(r.Trees) != 2 || r.Trees[0] != filepath.Clean(dir) {
		t.Errorf("directory input should be scanned alongside the extraction root: %v", r.Trees)
	}
}

func TestLimits(t *testing.T) {
	big := zipBytes(t, map[string]string{"a.txt": strings.Repeat("x", 3000), "b.txt": strings.Repeat("y", 3000)})
	dir := t.TempDir()
	artifact := filepath.Join(dir, "big.zip")
	os.WriteFile(artifact, big, 0o644)
	r, err := Run(artifact, Options{Root: filepath.Join(dir, "out"), MaxBytes: 4000})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	if len(r.Entries) != 1 {
		t.Fatalf("the byte limit should stop extraction after the first member: %+v", r.Entries)
	}
	if len(r.NotInspected) == 0 || !strings.Contains(r.NotInspected[0], "limit") {
		t.Fatalf("the limit should be reported: %v", r.NotInspected)
	}
}

func TestSniffHelperFormats(t *testing.T) {
	dir := t.TempDir()
	msi := filepath.Join(dir, "setup.msi")
	os.WriteFile(msi, append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, make([]byte, 600)...), 0o644)
	kind, helper := sniff(msi, "setup.msi", 608)
	if kind != "msi" || helper != "7z" {
		t.Errorf("msi sniff: %s %s", kind, helper)
	}
	r, _ := Run(msi, Options{Root: filepath.Join(dir, "out"), Helpers: "none"})
	defer r.Cleanup()
	if len(r.NotInspected) != 1 || !strings.Contains(r.NotInspected[0], "needs 7z") {
		t.Errorf("a missing helper must be reported, got %v", r.NotInspected)
	}
}

func TestStaticLibInsideWheel(t *testing.T) {
	// numpy ships GNU-format static libraries; they used to crash the ar reader.
	whl := zipBytes(t, map[string]string{"numpy/core/lib/libnpymath.a": string(gnuStaticLib()), "numpy/__init__.py": ""})
	dir := t.TempDir()
	p := filepath.Join(dir, "numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.whl")
	os.WriteFile(p, whl, 0o644)
	r, err := Run(p, Options{Root: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	got := strings.Join(locations(r), "\n")
	if !strings.Contains(got, "libnpymath.a!/npy_math_complex_long_name.o") {
		t.Fatalf("static library members should be extracted:\n%s\n%v", got, r.NotInspected)
	}
}

func TestPrependedZipAndInputPlacement(t *testing.T) {
	// Spring Boot "fully executable" jar: a launch script, then the zip.
	jar := append([]byte("#!/bin/bash\n# launch script\nexec java -jar \"$0\" \"$@\"\nexit 0\n"),
		zipBytes(t, map[string]string{"BOOT-INF/lib/log4j-core-2.13.3.jar": string(zipBytes(t, map[string]string{
			"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": "version=2.13.3\n"}))})...)
	dir := t.TempDir()
	p := filepath.Join(dir, "zipkin-server-2.23.8-exec.jar")
	os.WriteFile(p, jar, 0o644)
	r, err := Run(p, Options{Root: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	got := strings.Join(locations(r), "\n")
	if !strings.Contains(got, "zipkin-server-2.23.8-exec.jar!/BOOT-INF/lib/log4j-core-2.13.3.jar!/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties") {
		t.Fatalf("prepended-data jar not unpacked:\n%s\n%v", got, r.NotInspected)
	}
	// The input file itself is in the scanned tree, located by its own name.
	in := filepath.Join(r.Root, "input", "zipkin-server-2.23.8-exec.jar")
	if _, err := os.Stat(in); err != nil {
		t.Fatalf("input not placed in the tree: %v", err)
	}
	if r.Locate(in) != "zipkin-server-2.23.8-exec.jar" {
		t.Fatalf("Locate(input) = %q", r.Locate(in))
	}
}

func TestGzipTrailingData(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(strings.Repeat("firmware", 1000)))
	gz.Close()
	data := append(buf.Bytes(), make([]byte, 4096)...) // OpenWrt pads .img.gz after the stream
	copy(data[buf.Len():], "garbage-not-a-gzip-header")
	dir := t.TempDir()
	p := filepath.Join(dir, "openwrt-x86-64-combined.img.gz")
	os.WriteFile(p, data, 0o644)
	r, err := Run(p, Options{Root: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	if len(r.Entries) != 1 || r.Entries[0].Size != 8000 {
		t.Fatalf("the stream before the padding should be kept: %+v %v", r.Entries, r.NotInspected)
	}
	if len(r.NotInspected) != 1 || !strings.Contains(r.NotInspected[0], "trailing data") {
		t.Fatalf("trailing data should be noted: %v", r.NotInspected)
	}
}
