// Package unpack extracts nested artifacts (archives, packages, filesystem and
// disk images, installers) into a private temporary tree without executing,
// mounting or emulating anything from the artifact. It records, for every
// extracted file, the logical location shown in reports (outer!/inner!/path) and
// everything it could not open.
package unpack

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options bound the extraction.
type Options struct {
	MaxDepth    int    // archives inside archives (default 10)
	MaxBytes    int64  // total bytes written (default 50x the input, at least 4 GiB)
	MaxFiles    int    // total files written (default 500000)
	MaxFileSize int64  // one extracted member (default 8 GiB)
	Helpers     string // auto, none
	Keep        bool   // keep the temporary tree
	Root        string // where to extract (default: a new temp dir)
	Log         func(string)
}

func (o *Options) defaults(inputSize int64) {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 10
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = inputSize * 50
		if o.MaxBytes < 4<<30 {
			o.MaxBytes = 4 << 30
		}
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = 500000
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 8 << 30
	}
	if o.Helpers == "" {
		o.Helpers = "auto"
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
}

// Entry is one extracted regular file.
type Entry struct {
	Path     string // on disk
	Location string // logical: outer!/inner!/member
	Size     int64
	Depth    int
}

// Result is what a run produced.
type Result struct {
	Root         string            // temporary extraction root (contains one dir per container)
	Trees        []string          // directories to scan: the input dir (if any) and Root
	Entries      []Entry           // every extracted file
	Containers   []Container       // every container that was opened
	NotInspected []string          // what could not be opened, with the reason
	Formats      map[string]int    // format -> count of containers opened
	Helpers      map[string]string // helper name -> path or "" when missing
	locations    map[string]string // extraction dir -> logical container location
	written      int64
	files        int
	opts         Options
	inputDir     string
	next         int
}

// Container is an archive, package or image that was opened.
type Container struct {
	Location string
	Format   string
	Depth    int
	Files    int
}

// Locate maps an on-disk path (inside Root or the input directory) to its logical location.
func (r *Result) Locate(p string) string {
	p = filepath.Clean(p)
	if r.inputDir != "" {
		if rel, err := filepath.Rel(r.inputDir, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	best, bestLoc := "", ""
	for dir, loc := range r.locations {
		if (p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))) && len(dir) > len(best) {
			best, bestLoc = dir, loc
		}
	}
	if best == "" {
		return filepath.ToSlash(p)
	}
	rel, _ := filepath.Rel(best, p)
	if rel == "." {
		return bestLoc
	}
	if bestLoc == "" { // the copy of the input file itself
		return filepath.ToSlash(rel)
	}
	return bestLoc + "!/" + filepath.ToSlash(rel)
}

// Run unpacks an artifact (file or directory).
func Run(artifact string, opts Options) (*Result, error) {
	info, err := os.Stat(artifact)
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if info.IsDir() {
		size = dirSize(artifact)
	}
	opts.defaults(size)
	root := opts.Root
	if root == "" {
		root, err = os.MkdirTemp("", "xenolith-scan-")
		if err != nil {
			return nil, err
		}
	}
	r := &Result{Root: root, Formats: map[string]int{}, Helpers: findHelpers(opts.Helpers), locations: map[string]string{}, opts: opts}
	r.Trees = []string{root}
	start := time.Now()
	if info.IsDir() {
		r.inputDir = filepath.Clean(artifact)
		r.Trees = append([]string{r.inputDir}, r.Trees...)
		_ = filepath.WalkDir(artifact, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return nil
			}
			r.consider(p, r.Locate(p), st.Size(), 0)
			return nil
		})
	} else {
		r.placeInput(artifact, size)
		r.consider(artifact, filepath.Base(artifact), size, 0)
	}
	opts.Log(fmt.Sprintf("unpacked %d containers, %d files, %s in %s", len(r.Containers), r.files,
		humanBytes(r.written), time.Since(start).Round(time.Millisecond)))
	sort.Strings(r.NotInspected)
	return r, nil
}

// maxInputCopy bounds copying the input file into the scanned tree when a hard link
// is not possible (different filesystems).
const maxInputCopy = 4 << 30

// placeInput puts the artifact itself into the scanned tree, so the detection layers
// see it as well as whatever was unpacked from it: a .deb or .ipk for Syft's archive
// cataloger, a .jar or wheel for its Java and Python catalogers, a bare executable
// for the fingerprints. A hard link costs nothing; otherwise it is copied.
func (r *Result) placeInput(artifact string, size int64) {
	dir := filepath.Join(r.Root, "input")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	dst := filepath.Join(dir, filepath.Base(artifact))
	r.locations[dir] = ""
	if err := os.Link(artifact, dst); err == nil {
		return
	}
	if size > maxInputCopy {
		r.skip(filepath.Base(artifact), "input file itself not passed to the package catalogers (too large to copy; unpacked contents were)")
		return
	}
	in, err := os.Open(artifact)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return
	}
	out.Close()
}

// Cleanup removes the temporary tree unless Keep was set.
func (r *Result) Cleanup() {
	if !r.opts.Keep && r.Root != "" {
		_ = os.RemoveAll(r.Root)
	}
}

// consider looks at one file and extracts it if it is a container we can open.
func (r *Result) consider(p, location string, size int64, depth int) {
	if size == 0 {
		return
	}
	kind, detail := sniff(p, location, size)
	if kind == "" {
		return
	}
	if depth >= r.opts.MaxDepth {
		r.skip(location, fmt.Sprintf("%s nested deeper than %d containers", kind, r.opts.MaxDepth))
		return
	}
	dir := r.newDir(location)
	n, err := r.safeExtract(kind, detail, p, dir, location, depth+1)
	if err != nil && n == 0 {
		_ = os.RemoveAll(dir)
		delete(r.locations, dir)
		if errors.Is(err, errHelperMissing) {
			r.skip(location, fmt.Sprintf("%s: needs %s (not installed)", kind, detail))
		} else if errors.Is(err, errEncrypted) {
			r.skip(location, fmt.Sprintf("%s: encrypted; not attempted", kind))
		} else {
			r.skip(location, fmt.Sprintf("%s: %v", kind, err))
		}
		return
	}
	if err != nil {
		r.skip(location, fmt.Sprintf("%s: partially extracted (%d files): %v", kind, n, err))
	}
	r.Formats[kind]++
	r.Containers = append(r.Containers, Container{Location: location, Format: kind, Depth: depth, Files: n})
	r.opts.Log(fmt.Sprintf("  %s: %s, %d files", location, kind, n))
}

// safeExtract runs one extractor and turns a panic in any parser into an error, so a
// malformed or unexpected container is reported as not inspected instead of ending
// the scan. Each one is a parser bug to fix; the message says where it happened.
func (r *Result) safeExtract(kind, detail, p, dir, location string, depth int) (n int, err error) {
	before := r.files
	defer func() {
		if rec := recover(); rec != nil {
			n, err = r.files-before, fmt.Errorf("parser crashed (please report): %v", rec)
		}
	}()
	return r.extract(kind, detail, p, dir, location, depth)
}

func (r *Result) newDir(location string) string {
	r.next++
	dir := filepath.Join(r.Root, fmt.Sprintf("c%04d", r.next))
	_ = os.MkdirAll(dir, 0o755)
	r.locations[dir] = location
	return dir
}

func (r *Result) skip(location, why string) {
	r.NotInspected = append(r.NotInspected, location+": "+why)
}

var (
	errHelperMissing = errors.New("helper missing")
	errEncrypted     = errors.New("encrypted")
	errLimit         = errors.New("extraction limit reached")
)

// writeMember writes one extracted file under dir, enforcing the limits and
// refusing unsafe names, then recurses into it.
func (r *Result) writeMember(dir, container, name string, size int64, depth int, src io.Reader) (bool, error) {
	clean, ok := safeName(name)
	if !ok {
		r.skip(container+"!/"+name, "unsafe member path")
		return false, nil
	}
	if size > r.opts.MaxFileSize {
		r.skip(container+"!/"+clean, fmt.Sprintf("member larger than %s", humanBytes(r.opts.MaxFileSize)))
		return false, nil
	}
	if r.files >= r.opts.MaxFiles {
		return false, fmt.Errorf("%w: more than %d files", errLimit, r.opts.MaxFiles)
	}
	dst := filepath.Join(dir, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	budget := r.opts.MaxBytes - r.written
	if budget <= 0 {
		f.Close()
		return false, fmt.Errorf("%w: more than %s extracted", errLimit, humanBytes(r.opts.MaxBytes))
	}
	n, err := io.Copy(f, io.LimitReader(src, budget+1))
	f.Close()
	r.written += n
	if n > budget {
		_ = os.Remove(dst)
		return false, fmt.Errorf("%w: more than %s extracted", errLimit, humanBytes(r.opts.MaxBytes))
	}
	if err != nil {
		_ = os.Remove(dst)
		return false, err
	}
	r.files++
	loc := container + "!/" + clean
	r.Entries = append(r.Entries, Entry{Path: dst, Location: loc, Size: n, Depth: depth})
	r.consider(dst, loc, n, depth)
	return true, nil
}

// safeName normalises an archive member name and rejects traversal.
func safeName(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	for strings.HasPrefix(name, "/") {
		name = name[1:]
	}
	if name == "" || name == "." {
		return "", false
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "\x00") {
		return "", false
	}
	return clean, true
}

func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if st, err := d.Info(); err == nil {
				total += st.Size()
			}
		}
		return nil
	})
	return total
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
