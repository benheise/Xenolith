package unpack

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/blakesmith/ar"
	"github.com/bodgit/sevenzip"
	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	diskfs "github.com/diskfs/go-diskfs"
	backendfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// extract writes the members of one container into dir. It returns how many files
// it wrote; an error with n == 0 means the container could not be opened at all.
func (r *Result) extract(kind, detail, p, dir, location string, depth int) (int, error) {
	switch kind {
	case "zip":
		return r.extractZip(p, dir, location, depth)
	case "tar":
		return r.extractTarFile(p, dir, location, depth)
	case "gzip", "bzip2", "xz", "zstd", "lzma":
		return r.extractCompressed(kind, p, dir, location, depth)
	case "7z":
		return r.extract7z(p, dir, location, depth)
	case "ar":
		return r.extractAr(p, dir, location, depth)
	case "rpm":
		return r.extractRPM(p, dir, location, depth)
	case "cpio":
		f, err := os.Open(p)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return r.extractCpio(f, dir, location, depth)
	case "squashfs", "iso9660", "ext4":
		return r.extractFilesystem(kind, p, 0, dir, location, depth)
	case "disk":
		return r.extractDisk(p, dir, location, depth)
	case "appimage":
		return r.extractAppImage(p, dir, location, depth)
	case "asar":
		return r.extractAsar(p, dir, location, depth)
	case "cab", "msi", "xar", "vmdk", "qcow2", "vhd", "vhdx", "dmg", "nsis", "installshield", "inno",
		"ubi", "jffs2", "cramfs", "firmware":
		return r.extractWithHelper(detail, kind, p, dir, location, depth)
	}
	return 0, fmt.Errorf("no extractor for %s", kind)
}

func (r *Result) extractZip(p, dir, location string, depth int) (int, error) {
	z, err := zip.OpenReader(p)
	if err != nil {
		return 0, err
	}
	defer z.Close()
	n, encrypted := 0, 0
	for _, f := range z.File {
		if f.FileInfo().IsDir() || f.Mode()&os.ModeSymlink != 0 || strings.HasSuffix(f.Name, "/") {
			continue
		}
		if f.Flags&0x1 != 0 {
			encrypted++
			r.skip(location+"!/"+f.Name, "encrypted zip member")
			continue
		}
		rc, err := f.Open()
		if err != nil {
			r.skip(location+"!/"+f.Name, err.Error())
			continue
		}
		ok, err := r.writeMember(dir, location, f.Name, int64(f.UncompressedSize64), depth, rc)
		rc.Close()
		if ok {
			n++
		}
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
	if n == 0 && encrypted > 0 {
		return 0, errEncrypted
	}
	return n, nil
}

func (r *Result) extractTarFile(p, dir, location string, depth int) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return r.extractTar(f, dir, location, depth)
}

func (r *Result) extractTar(src io.Reader, dir, location string, depth int) (int, error) {
	tr := tar.NewReader(src)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			if n > 0 {
				return n, err
			}
			return 0, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		ok, err := r.writeMember(dir, location, h.Name, h.Size, depth, tr)
		if ok {
			n++
		}
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
}

// extractCompressed decompresses a single stream into one member named after the file.
func (r *Result) extractCompressed(kind, p, dir, location string, depth int) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var src io.Reader
	switch kind {
	case "gzip":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		src = gz
	case "bzip2":
		src = bzip2.NewReader(f)
	case "xz":
		xr, err := xz.NewReader(f)
		if err != nil {
			return 0, err
		}
		src = xr
	case "lzma":
		lr, err := lzma.NewReader(f)
		if err != nil {
			return 0, err
		}
		src = lr
	case "zstd":
		zr, err := zstd.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		src = zr
	}
	name := innerName(location, kind)
	ok, err := r.writeMember(dir, location, name, -1, depth, src)
	if ok {
		return 1, err
	}
	if err == nil {
		err = errors.New("nothing written")
	}
	return 0, err
}

// innerName strips the compression suffix: fw.tar.gz -> fw.tar, foo.tgz -> foo.tar.
func innerName(location, kind string) string {
	base := location[strings.LastIndex(location, "/")+1:]
	lower := strings.ToLower(base)
	for _, s := range [][2]string{{".tgz", ".tar"}, {".txz", ".tar"}, {".tbz2", ".tar"}, {".tbz", ".tar"}, {".tzst", ".tar"},
		{".tar.gz", ".tar"}, {".tar.xz", ".tar"}, {".tar.bz2", ".tar"}, {".tar.zst", ".tar"}, {".tar.lzma", ".tar"},
		{".gz", ""}, {".xz", ""}, {".bz2", ""}, {".zst", ""}, {".lzma", ""}, {".z", ""}} {
		if strings.HasSuffix(lower, s[0]) {
			return base[:len(base)-len(s[0])] + s[1]
		}
	}
	return base + ".decompressed"
}

func (r *Result) extract7z(p, dir, location string, depth int) (int, error) {
	z, err := sevenzip.OpenReader(p)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "password") || strings.Contains(strings.ToLower(err.Error()), "encrypt") {
			return 0, errEncrypted
		}
		return 0, err
	}
	defer z.Close()
	n := 0
	for _, f := range z.File {
		if f.FileInfo().IsDir() || f.FileInfo().Mode()&os.ModeSymlink != 0 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			r.skip(location+"!/"+f.Name, err.Error())
			continue
		}
		ok, err := r.writeMember(dir, location, f.Name, int64(f.UncompressedSize), depth, rc)
		rc.Close()
		if ok {
			n++
		}
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
	return n, nil
}

func (r *Result) extractAr(p, dir, location string, depth int) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	rd := ar.NewReader(f)
	n := 0
	for {
		h, err := rd.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		name := strings.TrimSuffix(strings.TrimSpace(h.Name), "/")
		ok, err := r.writeMember(dir, location, name, h.Size, depth, io.LimitReader(rd, h.Size))
		if ok {
			n++
		}
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
}

func (r *Result) extractRPM(p, dir, location string, depth int) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	pkg, err := rpm.Read(f)
	if err != nil {
		return 0, err
	}
	var payload io.Reader
	switch pkg.PayloadCompression() {
	case "gzip", "":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		payload = gz
	case "bzip2":
		payload = bzip2.NewReader(f)
	case "xz", "lzma":
		xr, err := xz.NewReader(f)
		if err != nil {
			lr, lerr := lzma.NewReader(f)
			if lerr != nil {
				return 0, err
			}
			payload = lr
		} else {
			payload = xr
		}
	case "zstd":
		zr, err := zstd.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		payload = zr
	default:
		return 0, fmt.Errorf("unsupported rpm payload compression %q", pkg.PayloadCompression())
	}
	if format := pkg.PayloadFormat(); format != "cpio" && format != "" {
		return 0, fmt.Errorf("unsupported rpm payload format %q", format)
	}
	return r.extractCpio(payload, dir, location, depth)
}

func (r *Result) extractCpio(src io.Reader, dir, location string, depth int) (int, error) {
	cr := cpio.NewReader(src)
	n := 0
	for {
		h, err := cr.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if !h.Mode.IsRegular() {
			continue
		}
		ok, err := r.writeMember(dir, location, h.Name, h.Size, depth, cr)
		if ok {
			n++
		}
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
}

// extractFilesystem reads a squashfs, ISO 9660 or ext4 image starting at offset.
func (r *Result) extractFilesystem(kind, p string, offset int64, dir, location string, depth int) (int, error) {
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	b, err := backendfile.OpenFromPath(p, true)
	if err != nil {
		return 0, err
	}
	defer b.Close()
	size := st.Size() - offset
	var fsys filesystem.FileSystem
	switch kind {
	case "squashfs":
		fsys, err = squashfs.Read(b, size, offset, 4096)
	case "iso9660":
		fsys, err = iso9660.Read(b, size, offset, 2048)
	case "ext4":
		fsys, err = ext4.Read(b, size, offset, 512)
	default:
		return 0, fmt.Errorf("unknown filesystem %s", kind)
	}
	if err != nil {
		return 0, err
	}
	return r.walkFS(fsys, dir, location, depth)
}

// walkFS copies every regular file of a go-diskfs filesystem.
func (r *Result) walkFS(fsys filesystem.FileSystem, dir, location string, depth int) (int, error) {
	n := 0
	var walk func(string) error
	walk = func(dirName string) error {
		entries, err := fsys.ReadDir(dirName)
		if err != nil {
			r.skip(location+"!"+dirName, err.Error())
			return nil
		}
		for _, e := range entries {
			name := path.Join(dirName, e.Name())
			if e.IsDir() {
				if e.Name() == "." || e.Name() == ".." {
					continue
				}
				if err := walk(name); err != nil {
					return err
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			fh, err := fsys.OpenFile(name, os.O_RDONLY)
			if err != nil {
				r.skip(location+"!"+name, err.Error())
				continue
			}
			ok, err := r.writeMember(dir, location, name, info.Size(), depth, fh)
			fh.Close()
			if ok {
				n++
			}
			if errors.Is(err, errLimit) {
				return err
			}
		}
		return nil
	}
	err := walk("/")
	return n, err
}

// extractDisk opens a partitioned raw disk image and extracts each filesystem it can read.
func (r *Result) extractDisk(p, dir, location string, depth int) (int, error) {
	d, err := diskfs.Open(p, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		return 0, err
	}
	defer d.Close()
	table, err := d.GetPartitionTable()
	if err != nil {
		return 0, err
	}
	n := 0
	for i, part := range table.GetPartitions() {
		if part.GetSize() <= 0 {
			continue
		}
		fsys, err := d.GetFilesystem(i + 1)
		if err != nil {
			// go-diskfs knows FAT, ISO, squashfs and ext4; anything else (NTFS, XFS,
			// LVM, swap, encrypted) is reported rather than guessed at.
			r.skip(fmt.Sprintf("%s!/partition%d", location, i+1), fmt.Sprintf("%s (%s)", err.Error(), humanBytes(part.GetSize())))
			continue
		}
		m, err := r.walkFS(fsys, dir, fmt.Sprintf("%s!/partition%d", location, i+1), depth)
		n += m
		if errors.Is(err, errLimit) {
			return n, err
		}
	}
	if n == 0 {
		return 0, errors.New("no readable filesystem in any partition")
	}
	return n, nil
}

// extractAppImage reads the squashfs image appended to an AppImage's ELF runtime.
func (r *Result) extractAppImage(p, dir, location string, depth int) (int, error) {
	f, err := elf.Open(p)
	if err != nil {
		return 0, err
	}
	// The runtime ends where its section headers end; the image follows.
	var end int64
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOBITS && int64(s.Offset+s.Size) > end {
			end = int64(s.Offset + s.Size)
		}
	}
	f.Close()
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	// Search forward from the end of the ELF for the squashfs magic (it is
	// 4096-aligned in type-2 AppImages built with appimagetool).
	fh, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	buf := make([]byte, 4)
	for off := end &^ 0xFFF; off < st.Size()-4 && off < end+(64<<20); off += 4096 {
		if _, err := fh.ReadAt(buf, off); err != nil {
			break
		}
		if string(buf) == "hsqs" {
			return r.extractFilesystem("squashfs", p, off, dir, location, depth)
		}
	}
	return 0, errors.New("no squashfs image found after the runtime")
}

// extractAsar unpacks an Electron app.asar (pickle header + JSON directory + blob).
func (r *Result) extractAsar(p, dir, location string, depth int) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	head := make([]byte, 16)
	if _, err := io.ReadFull(f, head); err != nil {
		return 0, err
	}
	pickleSize := binary.LittleEndian.Uint32(head[4:8])
	jsonLen := binary.LittleEndian.Uint32(head[12:16])
	if jsonLen > 64<<20 || pickleSize < jsonLen {
		return 0, errors.New("asar header too large")
	}
	hdr := make([]byte, jsonLen)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return 0, err
	}
	base := int64(8 + pickleSize)
	var root map[string]any
	if err := json.Unmarshal(hdr, &root); err != nil {
		return 0, err
	}
	n := 0
	var walk func(prefix string, node map[string]any) error
	walk = func(prefix string, node map[string]any) error {
		files, _ := node["files"].(map[string]any)
		for name, v := range files {
			entry, _ := v.(map[string]any)
			if entry == nil {
				continue
			}
			full := path.Join(prefix, name)
			if _, isDir := entry["files"]; isDir {
				if err := walk(full, entry); err != nil {
					return err
				}
				continue
			}
			if unpacked, _ := entry["unpacked"].(bool); unpacked {
				continue // lives next to the archive in app.asar.unpacked, scanned as a plain file
			}
			size, _ := entry["size"].(float64)
			offStr, _ := entry["offset"].(string)
			off, err := strconv.ParseInt(offStr, 10, 64)
			if err != nil {
				continue
			}
			ok, err := r.writeMember(dir, location, full, int64(size), depth, io.NewSectionReader(f, base+off, int64(size)))
			if ok {
				n++
			}
			if errors.Is(err, errLimit) {
				return err
			}
		}
		return nil
	}
	err = walk("", root)
	return n, err
}
