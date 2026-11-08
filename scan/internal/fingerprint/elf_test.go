package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

// testSymbol is a function the synthetic ELF defines, with its machine code.
type testSymbol struct {
	name string
	code []byte
}

// makeELF builds a minimal ELF64 shared object with one PT_LOAD segment holding
// .text, .dynsym and .dynstr, plus any extra bytes (version strings, markers), so
// debug/elf can read its dynamic symbols. machine is EM_X86_64 or EM_AARCH64.
func makeELF(machine elf.Machine, syms []testSymbol, extra []byte) []byte {
	const base = 0x400000
	ehsize, phsize, shsize := 64, 56, 64
	// Layout: ELF header | 1 program header | .text | .dynstr | .dynsym | extra | section headers
	textOff := ehsize + phsize
	var text bytes.Buffer
	offsets := make([]int, len(syms))
	for i, s := range syms {
		offsets[i] = text.Len()
		text.Write(s.code)
		for text.Len()%16 != 0 {
			text.WriteByte(0)
		}
	}
	dynstrOff := textOff + text.Len()
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	nameOff := make([]int, len(syms))
	for i, s := range syms {
		nameOff[i] = dynstr.Len()
		dynstr.WriteString(s.name)
		dynstr.WriteByte(0)
	}
	shstr := "\x00.text\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
	shstrOff := dynstrOff + dynstr.Len()
	dynsymOff := shstrOff + len(shstr)
	for dynsymOff%8 != 0 {
		dynsymOff++
	}
	var dynsym bytes.Buffer
	dynsym.Write(make([]byte, 24)) // null symbol
	for i := range syms {
		e := make([]byte, 24)
		binary.LittleEndian.PutUint32(e[0:], uint32(nameOff[i]))
		e[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
		binary.LittleEndian.PutUint16(e[6:], 1) // section index of .text
		binary.LittleEndian.PutUint64(e[8:], uint64(base+textOff+offsets[i]))
		binary.LittleEndian.PutUint64(e[16:], uint64(len(syms[i].code)))
		dynsym.Write(e)
	}
	extraOff := dynsymOff + dynsym.Len()
	shOff := extraOff + len(extra)
	for shOff%8 != 0 {
		shOff++
	}
	fileSize := shOff + 5*shsize

	buf := make([]byte, fileSize)
	// ELF header
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(buf[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(buf[18:], uint16(machine))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[24:], uint64(base+textOff)) // entry
	binary.LittleEndian.PutUint64(buf[32:], uint64(ehsize))       // phoff
	binary.LittleEndian.PutUint64(buf[40:], uint64(shOff))        // shoff
	binary.LittleEndian.PutUint16(buf[52:], uint16(ehsize))
	binary.LittleEndian.PutUint16(buf[54:], uint16(phsize))
	binary.LittleEndian.PutUint16(buf[56:], 1)
	binary.LittleEndian.PutUint16(buf[58:], uint16(shsize))
	binary.LittleEndian.PutUint16(buf[60:], 5)
	binary.LittleEndian.PutUint16(buf[62:], 4) // shstrndx
	// Program header: one PT_LOAD covering the whole file
	ph := buf[ehsize:]
	binary.LittleEndian.PutUint32(ph[0:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(ph[4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(ph[8:], 0)
	binary.LittleEndian.PutUint64(ph[16:], base)
	binary.LittleEndian.PutUint64(ph[24:], base)
	binary.LittleEndian.PutUint64(ph[32:], uint64(fileSize))
	binary.LittleEndian.PutUint64(ph[40:], uint64(fileSize))
	binary.LittleEndian.PutUint64(ph[48:], 0x1000)
	copy(buf[textOff:], text.Bytes())
	copy(buf[dynstrOff:], dynstr.Bytes())
	copy(buf[shstrOff:], shstr)
	copy(buf[dynsymOff:], dynsym.Bytes())
	copy(buf[extraOff:], extra)
	// Section headers
	sh := func(i int, name int, typ elf.SectionType, flags elf.SectionFlag, off, size, link, entsize int) {
		s := buf[shOff+i*shsize:]
		binary.LittleEndian.PutUint32(s[0:], uint32(name))
		binary.LittleEndian.PutUint32(s[4:], uint32(typ))
		binary.LittleEndian.PutUint64(s[8:], uint64(flags))
		binary.LittleEndian.PutUint64(s[16:], uint64(base+off))
		binary.LittleEndian.PutUint64(s[24:], uint64(off))
		binary.LittleEndian.PutUint64(s[32:], uint64(size))
		binary.LittleEndian.PutUint32(s[40:], uint32(link))
		binary.LittleEndian.PutUint64(s[48:], 8)
		binary.LittleEndian.PutUint64(s[56:], uint64(entsize))
	}
	sh(1, 1, elf.SHT_PROGBITS, elf.SHF_ALLOC|elf.SHF_EXECINSTR, textOff, text.Len(), 0, 0)
	sh(2, 7, elf.SHT_STRTAB, elf.SHF_ALLOC, dynstrOff, dynstr.Len(), 0, 0)
	sh(3, 15, elf.SHT_DYNSYM, elf.SHF_ALLOC, dynsymOff, dynsym.Len(), 2, 24)
	sh(4, 23, elf.SHT_STRTAB, 0, shstrOff, len(shstr), 0, 0)
	return buf
}

func movEaxRet(v uint32) []byte {
	code := []byte{0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0, 0, 0, 0, 0xc3}
	binary.LittleEndian.PutUint32(code[5:], v)
	return code
}

func TestReturnedConstantAndProbes(t *testing.T) {
	data := makeELF(elf.EM_X86_64, []testSymbol{
		{"BrotliDecoderVersion", movEaxRet(0x01001009)}, // 1.1.9 in brotli's encoding
		{"BrotliDecoderDecompressStream", []byte{0xc3}},
	}, []byte("timedownlifeleftbackcodedatashowonlysitecityopenjustlikefreeworktextyear"))
	pack, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	s := New(pack)
	s.Binary(data, "lib/libbrotli.so")
	var got []string
	for _, f := range s.Findings {
		got = append(got, f.Component+"@"+f.Version+":"+f.Technique)
	}
	want := map[string]bool{"brotli@1.1.9:binary-analysis": false, "brotli@:binary-analysis": false}
	for _, g := range got {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	groups := Summarize(s.Findings)
	if len(groups) != 1 || groups[0].Version != "1.1.9" || groups[0].Confidence != 0.8 {
		t.Fatalf("summary should keep only the versioned brotli entry: %+v", groups)
	}
}

func TestAArch64Probe(t *testing.T) {
	// lzma_version_number() returns 50040002 = 5.4.0 stable (0x02FB8CC2): movz w0,#0x8cc2 ; movk w0,#0x2fb,lsl#16 ; ret
	movz := uint32(0x52800000) | (0x8cc2 << 5)
	movk := uint32(0x72800000) | (1 << 21) | (0x02fb << 5)
	ret := uint32(0xD65F03C0)
	code := make([]byte, 12)
	binary.LittleEndian.PutUint32(code[0:], movz)
	binary.LittleEndian.PutUint32(code[4:], movk)
	binary.LittleEndian.PutUint32(code[8:], ret)
	data := makeELF(elf.EM_AARCH64, []testSymbol{{"lzma_version_number", code}, {"lzma_code", []byte{0, 0, 0, 0}}, {"lzma_stream_decoder", []byte{0, 0, 0, 0}}}, nil)
	pack, _ := LoadEmbedded()
	s := New(pack)
	s.Binary(data, "liblzma.so.5")
	found := false
	for _, f := range s.Findings {
		if f.Component == "xz" && f.Version == "5.4.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected xz 5.4.0 from the AArch64 probe, got %+v", s.Findings)
	}
}

// x86 functions can start at odd addresses (Pillow's liblcms2 has cmsGetEncodedCMMversion
// at 0xed7f); masking the low bit, as for ARM Thumb, read the byte before the function.
func TestProbeAtOddAddress(t *testing.T) {
	code := []byte{0xcc, 0x55, 0x48, 0x89, 0xe5, 0xb8, 0x66, 0x08, 0x00, 0x00, 0x5d, 0xc3}
	data := makeELF(elf.EM_X86_64, []testSymbol{{"cmsGetEncodedCMMversion", code}}, nil)
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	syms, _ := f.DynamicSymbols()
	if v, ok := returnedConstant(f, syms[0].Value+1); !ok || v != 2150 {
		t.Fatalf("odd-address probe: %d %v", v, ok)
	}
}
