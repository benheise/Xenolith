package fingerprint

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
)

// peImage gives the probe and symbol rules what they need from a Windows DLL or EXE:
// its exported functions (the PE counterpart of ELF's defined dynamic symbols) and the
// code at an export's address. Windows builds of brotli, libwebp, xz and the like
// export their version functions, so the same `return CONSTANT;` probes apply.
type peImage struct {
	f       *pe.File
	arch    string
	exports map[string]uint32 // name -> RVA
}

const maxExports = 1 << 16

func openPE(data []byte, wanted [][]byte) (*peImage, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	img := &peImage{f: f, exports: map[string]uint32{}}
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_I386:
		img.arch = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		img.arch = "arm64"
	}
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	}
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return img, nil
	}
	hdr := img.read(dir.VirtualAddress, 40)
	if len(hdr) < 40 {
		return img, nil
	}
	nFuncs := binary.LittleEndian.Uint32(hdr[20:])
	nNames := binary.LittleEndian.Uint32(hdr[24:])
	funcs, names, ords := binary.LittleEndian.Uint32(hdr[28:]), binary.LittleEndian.Uint32(hdr[32:]), binary.LittleEndian.Uint32(hdr[36:])
	if nFuncs > maxExports || nNames > maxExports {
		return img, nil
	}
	want := make(map[string]bool, len(wanted))
	maxLen := 0
	for _, w := range wanted {
		want[string(w)] = true
		maxLen = max(maxLen, len(w))
	}
	nameRVAs := img.read(names, int(nNames)*4)
	ordinals := img.read(ords, int(nNames)*2)
	addrs := img.read(funcs, int(nFuncs)*4)
	for i := 0; i < int(nNames) && i*4+4 <= len(nameRVAs) && i*2+2 <= len(ordinals); i++ {
		name := img.read(binary.LittleEndian.Uint32(nameRVAs[i*4:]), maxLen+1)
		if j := bytes.IndexByte(name, 0); j >= 0 {
			name = name[:j]
		} else {
			continue // longer than anything wanted
		}
		if !want[string(name)] {
			continue
		}
		ord := int(binary.LittleEndian.Uint16(ordinals[i*2:]))
		if ord*4+4 > len(addrs) {
			continue
		}
		rva := binary.LittleEndian.Uint32(addrs[ord*4:])
		if rva >= dir.VirtualAddress && rva < dir.VirtualAddress+dir.Size {
			continue // forwarded to another DLL
		}
		img.exports[string(name)] = rva
	}
	return img, nil
}

// read returns up to n bytes at a relative virtual address.
func (img *peImage) read(rva uint32, n int) []byte {
	if n <= 0 || n > 1<<20 {
		return nil
	}
	for _, s := range img.f.Sections {
		size := max(s.VirtualSize, s.Size)
		if rva < s.VirtualAddress || rva >= s.VirtualAddress+size {
			continue
		}
		off := rva - s.VirtualAddress
		if off >= s.Size {
			return nil // in the zero-filled tail
		}
		m := min(uint32(n), s.Size-off)
		buf := make([]byte, m)
		k, _ := s.ReadAt(buf, int64(off))
		return buf[:k]
	}
	return nil
}
