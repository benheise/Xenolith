package unpack

import (
	"bytes"
	"encoding/binary"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
)

// squashfsImage builds a small squashfs with go-diskfs's writer.
func squashfsImage(t *testing.T, files map[string]string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "root.sqfs")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := squashfs.Create(file.New(f, false), 0, 0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := fsys.Mkdir(path.Dir(name)); err != nil { // squashfs paths are always slash-separated
			t.Fatal(err)
		}
		w, err := fsys.OpenFile(name, os.O_CREATE|os.O_RDWR)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := fsys.Finalize(squashfs.FinalizeOptions{}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A router image laid out like Netgear's .chk: vendor header, TRX header, a compressed
// kernel, then the squashfs root. The carver must open the root without unblob.
func TestFirmwareSquashfsCarving(t *testing.T) {
	// testdata/router-root.sqfs: squashfsImage(t, {"usr/sbin/curl": "\x7fELF curl 7.36.0",
	// "etc/banner": "router"}), generated once on Linux so the test does not depend on the
	// writer's behaviour on each platform
	sq, err := os.ReadFile(filepath.Join("testdata", "router-root.sqfs"))
	if err != nil {
		t.Fatal(err)
	}
	var img bytes.Buffer
	img.WriteString("*#$^")
	img.Write(make([]byte, 54))
	img.WriteString("HDR0")
	img.Write(bytes.Repeat([]byte{0x5d, 0, 0, 0x80, 0}, 4000)) // stand-in kernel
	img.WriteString("hsqs this is not a superblock")           // a false hit to skip
	off := img.Len()
	img.Write(sq)
	img.Write(make([]byte, 1000)) // padding
	dir := t.TempDir()
	art := filepath.Join(dir, "R7000-V1.0.chk")
	if err := os.WriteFile(art, img.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(art)
	got := findSquashfs(f, int64(img.Len()))
	f.Close()
	if len(got) != 1 || got[0] != int64(off) {
		t.Fatalf("findSquashfs: %v, want [%d]", got, off)
	}
	res, err := Run(art, Options{Root: filepath.Join(dir, "out"), Helpers: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Cleanup()
	found := false
	for _, e := range res.Entries {
		if strings.HasSuffix(e.Location, "!/usr/sbin/curl") && strings.Contains(e.Location, "!/squashfs@0x") {
			found = true
		}
	}
	if !found {
		t.Errorf("carved files missing: entries %+v, containers %+v, skipped %+v", res.Entries, res.Containers, res.NotInspected)
	}
}

func TestSquashfsSuperblockChecks(t *testing.T) {
	sb := make([]byte, 96)
	copy(sb, "hsqs")
	binary.LittleEndian.PutUint32(sb[12:], 131072)
	binary.LittleEndian.PutUint16(sb[20:], 4) // xz
	binary.LittleEndian.PutUint16(sb[22:], 17)
	binary.LittleEndian.PutUint16(sb[28:], 4)
	binary.LittleEndian.PutUint64(sb[40:], 1<<20)
	if _, ok := squashfsAt(sb, 0, 2<<20); !ok {
		t.Fatal("valid superblock rejected")
	}
	bad := map[string]func([]byte){
		"version 3":      func(b []byte) { binary.LittleEndian.PutUint16(b[28:], 3) },
		"block log":      func(b []byte) { binary.LittleEndian.PutUint16(b[22:], 16) },
		"compression 9":  func(b []byte) { binary.LittleEndian.PutUint16(b[20:], 9) },
		"runs past file": func(b []byte) { binary.LittleEndian.PutUint64(b[40:], 1<<30) },
	}
	for name, mutate := range bad {
		b := append([]byte{}, sb...)
		mutate(b)
		if _, ok := squashfsAt(b, 0, 2<<20); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// Electron's V8 snapshots are .bin files too; without a firmware header or a
// filesystem they are data, not "firmware: needs unblob".
func TestSmallBinIsNotFirmware(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "snapshot_blob.bin")
	if err := os.WriteFile(p, bytes.Repeat([]byte{0xab, 0xcd}, 300<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	if kind, _ := sniff(p, "app!/snapshot_blob.bin", 600<<10); kind != "" {
		t.Errorf("snapshot sniffed as %q", kind)
	}
	trx := filepath.Join(dir, "fw.bin")
	_ = os.WriteFile(trx, append([]byte("HDR0"), make([]byte, 300<<10)...), 0o644)
	if kind, _ := sniff(trx, "fw.bin", 300<<10+4); kind != "firmware" {
		t.Errorf("TRX image sniffed as %q", kind)
	}
}

func FuzzFindSquashfs(f *testing.F) {
	sb := make([]byte, 96)
	copy(sb, "hsqs")
	binary.LittleEndian.PutUint32(sb[12:], 4096)
	binary.LittleEndian.PutUint16(sb[20:], 1)
	binary.LittleEndian.PutUint16(sb[22:], 12)
	binary.LittleEndian.PutUint16(sb[28:], 4)
	binary.LittleEndian.PutUint64(sb[40:], 200)
	f.Add(append([]byte("HDR0xxxx"), append(sb, make([]byte, 200)...)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, off := range findSquashfs(bytes.NewReader(data), int64(len(data))) {
			if off < 0 || off >= int64(len(data)) {
				t.Fatalf("offset %d outside %d bytes", off, len(data))
			}
		}
	})
}
