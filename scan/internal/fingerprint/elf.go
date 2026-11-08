package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"regexp"
)

var dottedVersion = regexp.MustCompile(`\d+\.\d+(?:\.\d+){0,2}`)

// definedSymbols returns the virtual address of every wanted symbol the ELF file
// defines itself (imports, which have no address, don't count).
func definedSymbols(f *elf.File, wanted [][]byte) (map[string]uint64, error) {
	out := map[string]uint64{}
	want := make(map[string]bool, len(wanted))
	for _, w := range wanted {
		want[string(w)] = true
	}
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			if s.Value == 0 || s.Section == elf.SHN_UNDEF || !want[s.Name] {
				continue
			}
			if t := elf.ST_TYPE(s.Info); t != elf.STT_FUNC && t != elf.STT_OBJECT && t != elf.STT_NOTYPE && t != elf.STT_GNU_IFUNC {
				continue
			}
			if _, ok := out[s.Name]; !ok {
				out[s.Name] = s.Value
			}
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		add(syms)
	}
	if syms, err := f.Symbols(); err == nil {
		add(syms)
	}
	if len(out) == 0 {
		return out, nil
	}
	return out, nil
}

// readAt returns up to n bytes of file content at a virtual address.
func readAt(f *elf.File, vaddr uint64, n int) []byte {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || vaddr < p.Vaddr || vaddr >= p.Vaddr+p.Filesz {
			continue
		}
		off := vaddr - p.Vaddr
		size := n
		if uint64(size) > p.Filesz-off {
			size = int(p.Filesz - off)
		}
		buf := make([]byte, size)
		if _, err := p.ReadAt(buf, int64(off)); err != nil && len(buf) == 0 {
			return nil
		}
		return buf
	}
	return nil
}

// returnedConstant decodes a tiny `return CONSTANT;` function (x86, x86-64, AArch64).
func returnedConstant(f *elf.File, vaddr uint64) (uint32, bool) {
	arch := ""
	switch f.Machine {
	case elf.EM_X86_64, elf.EM_386:
		arch = "x86"
	case elf.EM_AARCH64:
		arch = "arm64"
	}
	// x86 functions may start at odd addresses (Pillow's liblcms2 has one at 0xed7f);
	// only 32-bit ARM uses the low bit, for Thumb, and it is not decoded here.
	return decodeReturn(readAt(f, vaddr, 32), arch)
}

// decodeReturn reads `return CONSTANT;` from the first bytes of a function.
func decodeReturn(code []byte, arch string) (uint32, bool) {
	if len(code) == 0 {
		return 0, false
	}
	switch arch {
	case "x86":
		if bytes.HasPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfa}) || bytes.HasPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfb}) {
			code = code[4:] // endbr64 / endbr32
		}
		framed := false
		switch {
		case bytes.HasPrefix(code, []byte{0x55, 0x48, 0x89, 0xe5}): // push rbp; mov rbp, rsp (frame pointers kept)
			code, framed = code[4:], true
		case bytes.HasPrefix(code, []byte{0x55, 0x89, 0xe5}): // i386: push ebp; mov ebp, esp
			code, framed = code[3:], true
		}
		if len(code) < 6 || code[0] != 0xb8 { // mov eax, imm32
			return 0, false
		}
		value, rest := binary.LittleEndian.Uint32(code[1:5]), code[5:]
		if framed && len(rest) > 0 && (rest[0] == 0x5d || rest[0] == 0xc9) { // pop rbp / leave
			rest = rest[1:]
		}
		if len(rest) > 0 && rest[0] == 0xc3 { // ret
			return value, true
		}
		return 0, false
	case "arm64":
		var value uint32
		seen := false
		for i := 0; i+4 <= len(code); i += 4 {
			ins := binary.LittleEndian.Uint32(code[i:])
			switch ins {
			case 0xD503201F, 0xD503233F, 0xD503245F, 0xD503241F, 0xD50323BF: // nop, paciasp, bti c, bti, autiasp
				continue
			case 0xA9BF7BFD, 0x910003FD, 0xA8C17BFD: // stp x29,x30,[sp,#-16]! / mov x29,sp / ldp x29,x30,[sp],#16
				continue
			case 0xD65F03C0: // ret
				if seen {
					return value, true
				}
				return 0, false
			}
			hw, imm, rd := (ins>>21)&3, (ins>>5)&0xFFFF, ins&0x1F
			if rd != 0 {
				return 0, false
			}
			switch {
			case ins&0x7F800000 == 0x52800000: // movz w0/x0
				value, seen = imm<<(16*hw), true
			case ins&0x7F800000 == 0x72800000 && seen: // movk
				value = (value &^ (0xFFFF << (16 * hw))) | (imm << (16 * hw))
			default:
				return 0, false
			}
		}
	}
	return 0, false
}

// decodeVersion turns a version function's constant into a dotted version.
func decodeVersion(how string, v uint32) string {
	switch how {
	case "brotli_hex":
		return fmt.Sprintf("%d.%d.%d", v>>24, (v>>12)&0xFFF, v&0xFFF)
	case "webp_hex":
		return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xFF, v&0xFF)
	case "lzma_number":
		return fmt.Sprintf("%d.%d.%d", v/10000000, (v/10000)%1000, (v/10)%1000)
	case "sqlite_number": // SQLITE_VERSION_NUMBER: 3041002 = 3.41.2
		return fmt.Sprintf("%d.%d.%d", v/1000000, (v/1000)%1000, v%1000)
	case "lcms_number": // LCMS_VERSION: 2150 = 2.15, 2161 = 2.16.1
		if v%10 != 0 {
			return fmt.Sprintf("%d.%d.%d", v/1000, (v/10)%100, v%10)
		}
		return fmt.Sprintf("%d.%d", v/1000, (v/10)%100)
	case "decimal_mmp": // major*10000 + minor*100 + patch (LZ4 11000 = 1.10.0, zstd 10506 = 1.5.6)
		return fmt.Sprintf("%d.%d.%d", v/10000, (v/100)%100, v%100)
	case "pg_number": // PG_VERSION_NUM: 160000 = 16.0; 90624 = 9.6.24
		if v >= 100000 {
			return fmt.Sprintf("%d.%d", v/10000, v%10000)
		}
		return fmt.Sprintf("%d.%d.%d", v/10000, (v/100)%100, v%100)
	}
	return ""
}

// decodeAddress reads `return "literal";` from the first bytes of a function at addr:
// x86-64 `lea rax, [rip+disp32]; ret` (optionally framed) or AArch64 `adrp x0; add x0,
// x0, #lo12; ret`. It returns the literal's address. harfbuzz's hb_version_string(),
// OpenJPEG's opj_version() and libopus's opus_get_version_string() look like this.
func decodeAddress(code []byte, arch string, addr uint64) (uint64, bool) {
	switch arch {
	case "x86":
		at := 0
		if bytes.HasPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfa}) {
			at = 4
		}
		framed := false
		if bytes.HasPrefix(code[at:], []byte{0x55, 0x48, 0x89, 0xe5}) {
			at, framed = at+4, true
		}
		if len(code) < at+8 || !bytes.HasPrefix(code[at:], []byte{0x48, 0x8d, 0x05}) { // lea rax, [rip+disp32]
			return 0, false
		}
		disp := int32(binary.LittleEndian.Uint32(code[at+3:]))
		next := at + 7
		rest := code[next:]
		if framed && len(rest) > 0 && (rest[0] == 0x5d || rest[0] == 0xc9) {
			rest = rest[1:]
		}
		if len(rest) == 0 || rest[0] != 0xc3 {
			return 0, false
		}
		return uint64(int64(addr) + int64(next) + int64(disp)), true
	case "arm64":
		var target uint64
		page := false
		for i := 0; i+4 <= len(code); i += 4 {
			ins := binary.LittleEndian.Uint32(code[i:])
			pc := addr + uint64(i)
			switch {
			case ins == 0xD503201F || ins == 0xD503233F || ins == 0xD503245F || ins == 0xD503241F || ins == 0xD50323BF ||
				ins == 0xA9BF7BFD || ins == 0x910003FD || ins == 0xA8C17BFD:
				continue
			case ins&0x9F00001F == 0x90000000: // adrp x0, page
				imm := int64((ins>>29)&3) | int64((ins>>5)&0x7FFFF)<<2
				if imm&(1<<20) != 0 {
					imm -= 1 << 21
				}
				target, page = uint64(int64(pc&^0xFFF)+imm<<12), true
			case page && ins&0xFFC003FF == 0x91000000: // add x0, x0, #imm12
				target += uint64((ins >> 10) & 0xFFF)
			case ins == 0xD65F03C0: // ret
				return target, page
			default:
				return 0, false
			}
		}
	}
	return 0, false
}

// versionIn takes the first dotted version out of a short literal ("libopus 1.5.1").
func versionIn(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	if len(b) == 0 || len(b) > 64 {
		return ""
	}
	return string(dottedVersion.Find(b))
}
