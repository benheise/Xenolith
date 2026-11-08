package unpack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Helpers are optional external unpackers. The binary works without them and
// lists what it skipped because one was missing.
var helperNames = map[string][]string{
	"7z":          {"7zz", "7z", "7za"},
	"innoextract": {"innoextract"},
	"unblob":      {"unblob"},
}

func findHelpers(mode string) map[string]string {
	found := map[string]string{}
	for name, candidates := range helperNames {
		found[name] = ""
		if mode == "none" {
			continue
		}
		for _, c := range candidates {
			if p, err := exec.LookPath(c); err == nil {
				found[name] = p
				break
			}
		}
	}
	return found
}

const helperTimeout = 20 * time.Minute

// extractWithHelper runs an external unpacker into dir, then registers what it
// produced. Helpers run with a timeout, an empty environment apart from PATH, and
// the extraction directory as their working directory.
func (r *Result) extractWithHelper(helper, kind, p, dir, location string, depth int) (int, error) {
	bin := r.Helpers[helper]
	if bin == "" {
		return 0, errHelperMissing
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return 0, err
	}
	var args []string
	switch helper {
	case "7z":
		args = []string{"x", "-y", "-p", "-bd", "-bso0", "-bsp0", "-o" + dir, abs}
	case "innoextract":
		args = []string{"--silent", "--extract", "--output-dir", dir, abs}
	case "unblob":
		args = []string{"--extract-dir", dir, "--depth", fmt.Sprint(r.opts.MaxDepth), abs}
	default:
		return 0, fmt.Errorf("unknown helper %s", helper)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LC_ALL=C"}
	out, runErr := cmd.CombinedOutput()
	if kind == "msi" && runErr == nil {
		r.renameMSI(bin, dir, location)
	}
	n, regErr := r.registerTree(dir, location, depth)
	if n == 0 {
		msg := string(out)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if runErr != nil {
			if isEncryptedMessage(msg) {
				return 0, errEncrypted
			}
			return 0, fmt.Errorf("%s failed: %v %s", helper, runErr, trim(msg))
		}
		return 0, fmt.Errorf("%s produced no files", helper)
	}
	if runErr != nil && !errors.Is(regErr, errLimit) {
		return n, fmt.Errorf("%s exited with %v", helper, runErr)
	}
	return n, regErr
}

// registerTree records files a helper wrote and recurses into them, enforcing the
// byte and file limits after the fact (over-limit files are removed).
func (r *Result) registerTree(dir, location string, depth int) (int, error) {
	n := 0
	var limitErr error
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || limitErr != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			_ = os.Remove(p) // never keep links a helper created
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		st, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if r.files >= r.opts.MaxFiles || r.written+st.Size() > r.opts.MaxBytes {
			_ = os.Remove(p)
			limitErr = fmt.Errorf("%w: helper output exceeded the extraction limits", errLimit)
			return nil
		}
		r.files++
		r.written += st.Size()
		loc := location + "!/" + filepath.ToSlash(rel)
		r.Entries = append(r.Entries, Entry{Path: p, Location: loc, Size: st.Size(), Depth: depth})
		n++
		r.consider(p, loc, st.Size(), depth)
		return nil
	})
	return n, limitErr
}

func isEncryptedMessage(msg string) bool {
	for _, w := range []string{"Wrong password", "encrypted", "Can not open encrypted", "password"} {
		if containsFold(msg, w) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			out = append(out, ' ')
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// renameMSI replaces what 7-Zip gives for an MSI (table streams and cabinets whose
// members are named by File-table keys) with the installed tree: each cabinet is
// unpacked and its members moved to the paths the Directory/Component/File tables
// give them. Without readable tables the cabinets are left for the normal recursion.
func (r *Result) renameMSI(bin, dir, location string) {
	names, ok, err := msiNames(dir)
	if err != nil {
		r.skip(location, "MSI tables unreadable, files keep their cabinet names: "+err.Error())
	}
	if !ok || len(names) == 0 {
		return
	}
	cabs, _ := filepath.Glob(filepath.Join(dir, "*.cab"))
	for _, cab := range cabs {
		tmp, err := os.MkdirTemp(dir, ".cab-")
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
		cmd := exec.CommandContext(ctx, bin, "x", "-y", "-p", "-bd", "-bso0", "-bsp0", "-o"+tmp, cab)
		cmd.Dir = tmp
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + tmp, "LC_ALL=C"}
		runErr := cmd.Run()
		cancel()
		if runErr != nil {
			_ = os.RemoveAll(tmp)
			continue // leave the cabinet for the normal recursion
		}
		_ = filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			rel, _ := filepath.Rel(tmp, p)
			key := filepath.ToSlash(rel)
			target, ok := names[key]
			if !ok {
				target = filepath.Base(cab) + "/" + key
			}
			clean, safe := safeName(target)
			if !safe {
				clean = filepath.Base(cab) + "/" + key
			}
			dst := filepath.Join(dir, filepath.FromSlash(clean))
			for i := 2; ; i++ { // two files may install to the same name (per-architecture copies)
				if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
					break
				}
				dst = filepath.Join(dir, filepath.FromSlash(clean)) + fmt.Sprintf(".%d", i)
			}
			if os.MkdirAll(filepath.Dir(dst), 0o755) == nil {
				_ = os.Rename(p, dst)
			}
			return nil
		})
		_ = os.RemoveAll(tmp)
		_ = os.Remove(cab)
	}
	// the table streams are database internals, not installed files
	streams, _ := filepath.Glob(filepath.Join(dir, "!*"))
	for _, s := range streams {
		_ = os.Remove(s)
	}
}
