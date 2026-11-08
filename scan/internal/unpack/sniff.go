package unpack

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
)

// sniff identifies a container format from magic bytes (and, where the format has
// none, the file name). It returns the format and a detail: for helper-backed
// formats the helper's name.
func sniff(p, location string, size int64) (kind, detail string) {
	f, err := os.Open(p)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	head := make([]byte, 0x9000)
	n, _ := io_readFull(f, head)
	head = head[:n]
	lower := strings.ToLower(location)
	base := lower[strings.LastIndex(lower, "/")+1:]

	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return "zip", ""
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "gzip", ""
	case bytes.HasPrefix(head, []byte("BZh")) && len(head) > 3 && head[3] >= '1' && head[3] <= '9':
		return "bzip2", ""
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "xz", ""
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd", ""
	case bytes.HasPrefix(head, []byte("7z\xbc\xaf\x27\x1c")):
		return "7z", ""
	case bytes.HasPrefix(head, []byte("!<arch>\n")):
		return "ar", ""
	case bytes.HasPrefix(head, []byte{0xed, 0xab, 0xee, 0xdb}):
		return "rpm", ""
	case bytes.HasPrefix(head, []byte("070701")) || bytes.HasPrefix(head, []byte("070702")) || bytes.HasPrefix(head, []byte("070707")):
		return "cpio", ""
	case bytes.HasPrefix(head, []byte("hsqs")) || bytes.HasPrefix(head, []byte("sqsh")):
		return "squashfs", ""
	case len(head) > 0x8005 && string(head[0x8001:0x8006]) == "CD001":
		return "iso9660", ""
	case bytes.HasPrefix(head, []byte("MSCF")):
		return "cab", "7z"
	case bytes.HasPrefix(head, []byte("xar!")):
		return "xar", "7z"
	case bytes.HasPrefix(head, []byte("KDMV")) || bytes.HasPrefix(head, []byte("# Disk DescriptorFile")):
		return "vmdk", "7z"
	case bytes.HasPrefix(head, []byte("QFI\xfb")):
		return "qcow2", "7z"
	case bytes.HasPrefix(head, []byte("vhdxfile")):
		return "vhdx", "7z"
	case bytes.HasPrefix(head, []byte("conectix")):
		return "vhd", "7z"
	case bytes.HasPrefix(head, []byte("UBI#")) || bytes.HasPrefix(head, []byte("UBI!")):
		return "ubi", "unblob"
	case bytes.HasPrefix(head, []byte{0x85, 0x19}) || bytes.HasPrefix(head, []byte{0x19, 0x85}):
		return "jffs2", "unblob"
	case bytes.HasPrefix(head, []byte{0x45, 0x3d, 0xcd, 0x28}) || bytes.HasPrefix(head, []byte{0x28, 0xcd, 0x3d, 0x45}):
		return "cramfs", "unblob"
	case bytes.HasPrefix(head, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		if strings.HasSuffix(base, ".msi") || strings.HasSuffix(base, ".msp") || strings.HasSuffix(base, ".msm") {
			return "msi", "7z"
		}
		return "", ""
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		if len(head) > 11 && head[8] == 'A' && head[9] == 'I' && (head[10] == 1 || head[10] == 2) {
			return "appimage", ""
		}
		return "", ""
	case bytes.HasPrefix(head, []byte("MZ")):
		if strings.HasSuffix(base, ".exe") {
			if k, d := sniffInstaller(f, size); k != "" {
				return k, d
			}
		}
		return "", ""
	}
	if len(head) > 262 && (string(head[257:262]) == "ustar" || tarChecksumOK(head)) {
		return "tar", ""
	}
	// A zip with data in front of it: Spring Boot "fully executable" jars start with a
	// shell script, self-extracting archives with a stub. The end-of-central-directory
	// record sits in the last 64 KiB.
	if bytes.HasPrefix(head, []byte("#!")) || hasZipExt(base) {
		if zipAtEnd(f, size) {
			return "zip", ""
		}
	}
	if len(head) > 0x43a && binary.LittleEndian.Uint16(head[0x438:]) == 0xEF53 {
		return "ext4", ""
	}
	if len(head) > 520 && (string(head[512:520]) == "EFI PART" || (head[510] == 0x55 && head[511] == 0xaa && mbrHasPartition(head))) {
		return "disk", ""
	}
	if strings.HasSuffix(base, ".asar") && len(head) > 16 && binary.LittleEndian.Uint32(head) == 4 {
		return "asar", ""
	}
	if strings.HasSuffix(base, ".dmg") && size > 512 {
		trailer := make([]byte, 512)
		if _, err := f.ReadAt(trailer, size-512); err == nil && bytes.HasPrefix(trailer, []byte("koly")) {
			return "dmg", "7z"
		}
	}
	if strings.HasSuffix(base, ".vhd") && size > 512 {
		trailer := make([]byte, 512)
		if _, err := f.ReadAt(trailer, size-512); err == nil && bytes.HasPrefix(trailer, []byte("conectix")) {
			return "vhd", "7z"
		}
	}
	if strings.HasSuffix(base, ".lzma") {
		return "lzma", ""
	}
	// Firmware blobs with no recognised header: let unblob carve them when present.
	for _, ext := range []string{".bin", ".img", ".fw", ".trx", ".chk", ".rom", ".pkg", ".firmware", ".upd", ".swu"} {
		if strings.HasSuffix(base, ext) && size > 256<<10 {
			return "firmware", "unblob"
		}
	}
	return "", ""
}

// sniffInstaller looks for NSIS and Inno Setup markers in an .exe: the first and
// last 4 MiB, where both formats keep their headers.
func sniffInstaller(f *os.File, size int64) (string, string) {
	window := int64(4 << 20)
	buf := make([]byte, window)
	n, _ := f.ReadAt(buf, 0)
	data := buf[:n]
	if size > window {
		tail := make([]byte, window)
		m, _ := f.ReadAt(tail, size-window)
		data = append(data, tail[:m]...)
	}
	switch {
	case bytes.Contains(data, []byte("Inno Setup Setup Data")) || bytes.Contains(data, []byte("Inno Setup Messages")):
		return "inno", "innoextract"
	case bytes.Contains(data, []byte("NullsoftInst")) || bytes.Contains(data, []byte("Nullsoft.NSIS.exehead")):
		return "nsis", "7z"
	case bytes.Contains(data, []byte("InstallShield")) && bytes.Contains(data, []byte("MSCF")):
		return "installshield", "7z"
	}
	return "", ""
}

func tarChecksumOK(head []byte) bool {
	if len(head) < 512 {
		return false
	}
	field := strings.Trim(string(head[148:156]), " \x00")
	if field == "" {
		return false
	}
	var want int64
	for _, c := range field {
		if c < '0' || c > '7' {
			return false
		}
		want = want*8 + int64(c-'0')
	}
	var sum int64
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int64(head[i])
		}
	}
	return sum == want && head[0] != 0
}

func mbrHasPartition(head []byte) bool {
	for i := 0; i < 4; i++ {
		e := head[446+16*i : 446+16*i+16]
		typ := e[4]
		sectors := binary.LittleEndian.Uint32(e[12:])
		if typ != 0 && sectors > 0 {
			return true
		}
	}
	return false
}

func io_readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

var zipExts = []string{".jar", ".war", ".ear", ".zip", ".apk", ".aar", ".whl", ".nupkg", ".hpi", ".jpi", ".sar", ".par", ".xpi", ".vsix", ".crx"}

func hasZipExt(base string) bool {
	for _, e := range zipExts {
		if strings.HasSuffix(base, e) {
			return true
		}
	}
	return false
}

// zipAtEnd looks for an end-of-central-directory record near the end of the file.
func zipAtEnd(f *os.File, size int64) bool {
	n := int64(66 << 10)
	if n > size {
		n = size
	}
	tail := make([]byte, n)
	if _, err := f.ReadAt(tail, size-n); err != nil {
		return false
	}
	return bytes.LastIndex(tail, []byte("PK\x05\x06")) >= 0
}
