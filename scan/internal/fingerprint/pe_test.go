package fingerprint

import (
	"debug/elf"
	"encoding/binary"
	"sort"
	"testing"
)

// makePE builds a minimal PE32+ DLL whose single section holds the functions' code
// followed by an export directory naming them.
func makePE(machine uint16, funcs []testSymbol) []byte {
	const va, raw = 0x1000, 0x200
	var text []byte
	for _, f := range funcs {
		code := append([]byte{}, f.code...)
		for len(code) < 16 {
			code = append(code, 0xcc)
		}
		text = append(text, code...)
	}
	names := make([]string, len(funcs))
	index := map[string]int{}
	for i, f := range funcs {
		names[i] = f.name
		index[f.name] = i
	}
	sort.Strings(names)
	edir := uint32(va + len(text))
	afun := edir + 40
	anames := afun + uint32(4*len(funcs))
	aords := anames + uint32(4*len(names))
	strs := aords + uint32(2*len(names))
	var blob []byte
	var nameRVAs []uint32
	for _, n := range names {
		nameRVAs = append(nameRVAs, strs+uint32(len(blob)))
		blob = append(append(blob, n...), 0)
	}
	exp := make([]byte, 40)
	binary.LittleEndian.PutUint32(exp[16:], 1)
	binary.LittleEndian.PutUint32(exp[20:], uint32(len(funcs)))
	binary.LittleEndian.PutUint32(exp[24:], uint32(len(names)))
	binary.LittleEndian.PutUint32(exp[28:], afun)
	binary.LittleEndian.PutUint32(exp[32:], anames)
	binary.LittleEndian.PutUint32(exp[36:], aords)
	for i := range funcs {
		exp = binary.LittleEndian.AppendUint32(exp, uint32(va+16*i))
	}
	for _, r := range nameRVAs {
		exp = binary.LittleEndian.AppendUint32(exp, r)
	}
	for _, n := range names {
		exp = binary.LittleEndian.AppendUint16(exp, uint16(index[n]))
	}
	section := append(append(text, exp...), blob...)
	size := (len(section) + 0x1ff) &^ 0x1ff
	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt, 0x20b)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	binary.LittleEndian.PutUint32(opt[112:], edir)
	binary.LittleEndian.PutUint32(opt[116:], uint32(len(exp)+len(blob)))
	out := make([]byte, raw)
	copy(out, "MZ")
	binary.LittleEndian.PutUint32(out[0x3c:], 0x40)
	hdr := []byte("PE\x00\x00")
	hdr = binary.LittleEndian.AppendUint16(hdr, machine)
	hdr = binary.LittleEndian.AppendUint16(hdr, 1)
	hdr = append(hdr, make([]byte, 12)...)
	hdr = binary.LittleEndian.AppendUint16(hdr, uint16(len(opt)))
	hdr = binary.LittleEndian.AppendUint16(hdr, 0x2022)
	hdr = append(hdr, opt...)
	sh := make([]byte, 40)
	copy(sh, ".text")
	binary.LittleEndian.PutUint32(sh[8:], uint32(len(section)))
	binary.LittleEndian.PutUint32(sh[12:], va)
	binary.LittleEndian.PutUint32(sh[16:], uint32(size))
	binary.LittleEndian.PutUint32(sh[20:], raw)
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)
	hdr = append(hdr, sh...)
	copy(out[0x40:], hdr)
	padded := make([]byte, size)
	copy(padded, section)
	return append(out, padded...)
}

func TestPEExportProbes(t *testing.T) {
	pack, _ := LoadEmbedded()
	check := func(name string, data []byte, want string) {
		t.Helper()
		s := New(pack)
		s.Binary(data, name)
		got := ""
		for _, f := range s.Findings {
			if f.Version != "" {
				got = f.Component + " " + f.Version
			}
		}
		if got != want {
			t.Errorf("%s: got %q, want %q (%+v)", name, got, want, s.Findings)
		}
	}
	// Wireshark 4.4.19's brotlidec.dll: mov eax, 0x01002000; ret
	check("brotlidec.dll", makePE(0x8664, []testSymbol{{"BrotliDecoderVersion", []byte{0xb8, 0x00, 0x20, 0x00, 0x01, 0xc3}},
		{"BrotliDecoderDecompressStream", []byte{0xc3}}}), "brotli 1.2.0")
	movz := uint32(0x52800000) | (0x3ed4 << 5)
	movk := uint32(0x72800000) | (1 << 21) | (0x02fb << 5)
	code := make([]byte, 12)
	for i, ins := range []uint32{movz, movk, 0xD65F03C0} {
		binary.LittleEndian.PutUint32(code[4*i:], ins)
	}
	check("arm64/liblzma.dll", makePE(0xaa64, []testSymbol{{"lzma_version_number", code}}), "xz 5.2.5")
	check("libsqlite3.dll", makePE(0x8664, []testSymbol{{"sqlite3_libversion_number", []byte{0xb8, 0xea, 0x66, 0x2e, 0x00, 0xc3}}}), "sqlite 3.41.2")
	// an executable that merely has an export of another name, and a DOS-only stub
	check("app.exe", makePE(0x8664, []testSymbol{{"main", []byte{0xc3}}}), "")
	check("stub.exe", append([]byte("MZ"), make([]byte, 200)...), "")
}

func TestDetectOnlyRules(t *testing.T) {
	pack, _ := LoadEmbedded()
	elfHead := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 60)...)
	cases := map[string]struct {
		data []byte
		want string
	}{
		"libz.so.1":     {append(elfHead, " deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler \x00"...), "zlib 1.2.11"},
		"libpng16.so":   {append(elfHead, " libpng version 1.6.40 - June 21, 2023\x00Incompatible libpng version in application and library\x00"...), "libpng 1.6.40"},
		"viewer":        {append(elfHead, "libpng version 1.6.40\x00"...), ""},
		"libtiff.so":    {append(elfHead, "LIBTIFF, Version 4.5.1\x00"...), "libtiff 4.5.1"},
		"libjpeg.so":    {append(elfHead, "libjpeg-turbo version 3.0.0 (build 20230915)\x00"...), "libjpeg-turbo 3.0.0"},
		"libbz2.so":     {append(elfHead, "1.0.8, 13-Jul-2019\x00bzip2/libbzip2: internal error number %d.\x00"...), "bzip2 1.0.8"},
		"libarchive.so": {append(elfHead, "libarchive 3.6.2\x00"...), "libarchive 3.6.2"},
		"libexpat.so":   {append(elfHead, "expat_2.9.0\x00"...), "expat 2.9.0"},
		"zlib-ng2.dll":  {append(elfHead, " deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler \x00 zlib-ng 2.1.5\x00"...), "zlib-ng 2.1.5"},
		"liblcms2.so":   {makeELF(elf.EM_X86_64, []testSymbol{{"cmsGetEncodedCMMversion", movEaxRet(2150)}}, nil), "lcms2 2.15"},
		"libpq.so":      {makeELF(elf.EM_X86_64, []testSymbol{{"PQlibVersion", movEaxRet(160000)}}, nil), "libpq 16.0"},
	}
	for name, c := range cases {
		s := New(pack)
		s.Binary(c.data, name)
		got := ""
		for _, f := range s.Findings {
			got = f.Component + " " + f.Version
			if f.Watchlist {
				t.Errorf("%s: detect-only finding marked as watchlist", name)
			}
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	// Electron apps: Electron, its Chromium and its Node.js from the main binary
	s := New(pack)
	s.Binary(append(elfHead, "%s/%s Chrome/%s Electron/32.2.1\x00Chrome/128.0.6613.186 Electron/32.2.1\x00ELECTRON_RUN_AS_NODE\x00"+
		"https://nodejs.org/download/release/v20.18.0/node-v20.18.0-headers.tar.gz\x00"...), "code")
	got := map[string]string{}
	for _, f := range s.Findings {
		got[f.Component] = f.Version
	}
	if got["electron"] != "32.2.1" || got["chromium"] != "128.0.6613.186" || got["nodejs"] != "20.18.0" || len(got) != 3 {
		t.Errorf("electron app: %v", got)
	}
	// static curl 8: curl_version_info()'s bare string among the feature names
	s = New(pack)
	s.Binary(append(elfHead, "libcurl lacks IDN support\x00alt-svc\x008.5.0\x00AsynchDNS\x00curl_version_info\x00"...), "splunkd")
	if len(s.Findings) != 1 || s.Findings[0].Version != "8.5.0" || s.Findings[0].Confidence != 0.8 {
		t.Errorf("curl version info: %+v", s.Findings)
	}
	// watchlist entries stay linked
	s = New(pack)
	s.Binary(append(elfHead, "libcurl/7.88.1\x00"...), "libcurl.so.4")
	if len(s.Findings) != 1 || !s.Findings[0].Watchlist {
		t.Errorf("curl should be a watchlist finding: %+v", s.Findings)
	}
}

func FuzzPE(f *testing.F) {
	pack, _ := LoadEmbedded()
	f.Add(makePE(0x8664, []testSymbol{{"BrotliDecoderVersion", []byte{0xb8, 0x00, 0x20, 0x00, 0x01, 0xc3}}}))
	f.Add(makePE(0xaa64, []testSymbol{{"lzma_version_number", []byte{0xc0, 0x03, 0x5f, 0xd6}}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := New(pack)
		s.binary(data, "fuzz.dll") // unrecovered: any panic fails the run
	})
}

// Functions that return a version literal: harfbuzz's hb_version_string(), OpenJPEG's
// opj_version(), libopus's opus_get_version_string().
func TestStringProbes(t *testing.T) {
	pack, _ := LoadEmbedded()
	// push rbp; mov rbp,rsp; lea rax,[rip+2]; pop rbp; ret; "8.2.0" (Pillow's libharfbuzz)
	x86 := append([]byte{0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x05, 0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3}, "8.2.0\x00"...)
	run := func(name string, data []byte) map[string]string {
		s := New(pack)
		s.Binary(data, name)
		out := map[string]string{}
		for _, f := range s.Findings {
			out[f.Component] = f.Version
		}
		return out
	}
	if got := run("libharfbuzz.so", makeELF(elf.EM_X86_64, []testSymbol{{"hb_version_string", x86}}, nil)); got["harfbuzz"] != "8.2.0" {
		t.Errorf("x86-64 ELF: %v", got)
	}
	opus := append([]byte{0x48, 0x8d, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3}, "libopus 1.5.1\x00"...)
	if got := run("opus.dll", makePE(0x8664, []testSymbol{{"opus_get_version_string", opus}})); got["opus"] != "1.5.1" {
		t.Errorf("PE: %v", got)
	}
	// AArch64: adrp x0, <page>; add x0, x0, #lo12; ret; "2.5.0". makeELF puts the first
	// function at 0x400078, so the literal after the three instructions is at 0x400084.
	code := make([]byte, 12)
	for i, ins := range []uint32{0x90000000, 0x91000000 | 0x084<<10, 0xD65F03C0} {
		binary.LittleEndian.PutUint32(code[4*i:], ins)
	}
	code = append(code, "2.5.0\x00"...)
	if got := run("libopenjp2.so", makeELF(elf.EM_AARCH64, []testSymbol{{"opj_version", code}}, nil)); got["openjpeg"] != "2.5.0" {
		t.Errorf("AArch64 ELF: %v", got)
	}
	// a function that computes its result is not a literal
	if got := run("libharfbuzz.so", makeELF(elf.EM_X86_64, []testSymbol{{"hb_version_string", []byte{0x31, 0xc0, 0xc3}}}, nil)); len(got) != 0 {
		t.Errorf("non-literal: %v", got)
	}
}

func TestMoreDetectOnlyRules(t *testing.T) {
	pack, _ := LoadEmbedded()
	elfHead := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 60)...)
	cases := map[string][2]any{
		"libssh.dll":  {makePE(0x8664, []testSymbol{{"ssh_init", []byte{0xc3}}}), ""},
		"libssh.so":   {append(elfHead, "SSH-2.0-libssh_0.12.2\x00"...), "libssh 0.12.2"},
		"gnutls.dll":  {append(elfHead, "Enabled GnuTLS 3.8.13 logging...\x00"...), "gnutls 3.8.13"},
		"lua54.dll":   {append(elfHead, "$LuaVersion: Lua 5.4.6  Copyright (C) 1994-2023 Lua.org, PUC-Rio $\x00"...), "lua 5.4.6"},
		"krb5_64.dll": {append(elfHead, "KRB5_BRAND: krb5-1.22.1-final 1.22.1 [date unknown]\x00"...), "krb5 1.22.1"},
		"lz4.dll":     {makePE(0x8664, []testSymbol{{"LZ4_versionNumber", []byte{0xb8, 0xf8, 0x2a, 0x00, 0x00, 0xc3}}}), "lz4 1.10.0"},
		"zstd.dll":    {makePE(0x8664, []testSymbol{{"ZSTD_versionNumber", []byte{0xb8, 0x0a, 0x29, 0x00, 0x00, 0xc3}}}), "zstd 1.5.6"},
	}
	for name, c := range cases {
		s := New(pack)
		s.Binary(c[0].([]byte), name)
		got := ""
		for _, f := range s.Findings {
			got = f.Component + " " + f.Version
		}
		if got != c[1].(string) {
			t.Errorf("%s: got %q, want %q", name, got, c[1])
		}
	}
}
