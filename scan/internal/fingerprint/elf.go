package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

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
	code := readAt(f, vaddr&^1, 32)
	if len(code) == 0 {
		return 0, false
	}
	switch f.Machine {
	case elf.EM_X86_64, elf.EM_386:
		if bytes.HasPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfa}) || bytes.HasPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfb}) {
			code = code[4:] // endbr64 / endbr32
		}
		if len(code) >= 6 && code[0] == 0xb8 && code[5] == 0xc3 { // mov eax, imm32; ret
			return binary.LittleEndian.Uint32(code[1:5]), true
		}
		return 0, false
	case elf.EM_AARCH64:
		var value uint32
		seen := false
		for i := 0; i+4 <= len(code); i += 4 {
			ins := binary.LittleEndian.Uint32(code[i:])
			switch ins {
			case 0xD503201F, 0xD503233F, 0xD503245F, 0xD503241F: // nop, paciasp, bti
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
	}
	return ""
}
