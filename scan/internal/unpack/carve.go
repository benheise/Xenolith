package unpack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
)

// Firmware images (router .chk/.trx, vendor .bin) are usually a header, a compressed
// kernel and a squashfs root filesystem laid end to end. Without unblob the built-in
// carver finds squashfs superblocks anywhere in the blob and opens them in place, which
// covers the root filesystem of most Linux-based devices.

const maxCarved = 16

// squashfsAt validates a little-endian squashfs 4.0 superblock at the start of sb.
func squashfsAt(sb []byte, off, size int64) (bytesUsed int64, ok bool) {
	if len(sb) < 96 || !bytes.Equal(sb[:4], []byte("hsqs")) {
		return 0, false
	}
	blockSize := binary.LittleEndian.Uint32(sb[12:])
	comp := binary.LittleEndian.Uint16(sb[20:])
	blockLog := binary.LittleEndian.Uint16(sb[22:])
	major, minor := binary.LittleEndian.Uint16(sb[28:]), binary.LittleEndian.Uint16(sb[30:])
	used := int64(binary.LittleEndian.Uint64(sb[40:]))
	if major != 4 || minor != 0 || comp < 1 || comp > 6 {
		return 0, false
	}
	if blockSize < 4096 || blockSize > 1<<20 || blockSize&(blockSize-1) != 0 || int(blockLog) != bits.TrailingZeros32(blockSize) {
		return 0, false
	}
	if used < 96 || off+used > size+4096 {
		return 0, false
	}
	return used, true
}

// findSquashfs returns the offsets of valid squashfs superblocks in f, skipping over
// each filesystem it finds (a squashfs never contains another one at a lower level).
func findSquashfs(f io.ReaderAt, size int64) []int64 {
	const chunk = 4 << 20
	buf := make([]byte, chunk+96)
	var out []int64
	for pos := int64(0); pos < size && len(out) < maxCarved; {
		n, err := f.ReadAt(buf, pos)
		if n <= 0 {
			break
		}
		data := buf[:n]
		next := pos + chunk
		for i := 0; i < n && len(out) < maxCarved; {
			j := bytes.Index(data[i:], []byte("hsqs"))
			if j < 0 {
				break
			}
			at := pos + int64(i+j)
			if at >= next {
				break
			}
			sb := make([]byte, 96)
			if m, _ := f.ReadAt(sb, at); m == 96 {
				if used, ok := squashfsAt(sb, at, size); ok {
					out = append(out, at)
					if at+used > next {
						next = at + used
					}
					i = int(min(at+used-pos, int64(n)))
					continue
				}
			}
			i += j + 1
		}
		if err != nil {
			break
		}
		pos = next
	}
	return out
}

// extractFirmware opens an unrecognised firmware blob: with unblob when it is
// installed, otherwise (or when unblob finds nothing) by carving squashfs.
func (r *Result) extractFirmware(p, dir, location string, depth int) (int, error) {
	var helperErr error = errHelperMissing
	if r.Helpers["unblob"] != "" {
		n, err := r.extractWithHelper("unblob", "firmware", p, dir, location, depth)
		if n > 0 {
			return n, err
		}
		helperErr = err
	}
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return 0, err
	}
	offsets := findSquashfs(f, st.Size())
	f.Close()
	total := 0
	for _, off := range offsets {
		sub := filepath.Join(dir, fmt.Sprintf("squashfs-0x%x", off))
		loc := fmt.Sprintf("%s!/squashfs@0x%x", location, off)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return total, err
		}
		r.locations[sub] = loc
		n, err := r.extractSquashfs(p, off, sub, loc, depth)
		total += n
		if err != nil {
			r.skip(loc, "squashfs: "+err.Error())
		}
		if n > 0 {
			r.opts.Log(fmt.Sprintf("  %s: squashfs carved from firmware, %d files", loc, n))
		}
	}
	if total == 0 {
		return 0, helperErr
	}
	if r.Helpers["unblob"] == "" {
		r.skip(location, "firmware: only the squashfs filesystems were carved; unblob would also open kernels and other blobs")
	}
	return total, nil
}

// firmwareMagic: headers of common firmware containers (Broadcom TRX, Netgear CHK,
// U-Boot uImage, Android boot images, flattened device trees).
func firmwareMagic(head []byte) bool {
	for _, m := range [][]byte{[]byte("HDR0"), []byte("*#$^"), {0x27, 0x05, 0x19, 0x56}, []byte("ANDROID!"), {0xd0, 0x0d, 0xfe, 0xed}} {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}
