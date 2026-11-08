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
