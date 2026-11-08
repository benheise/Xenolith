// Package submit turns a scan into a pull request against benheise/Xenolith with
// the GitHub CLI, or prints the manual upload path when gh is not available.
package submit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/benheise/Xenolith/scan/internal/registry"
)

const (
	Upstream = "benheise/Xenolith"
	WebRoot  = "https://github.com/benheise/Xenolith"
)

// Target is where the file goes inside the repository.
func Target(supplier, product, version string) string {
	return fmt.Sprintf("community/sboms/%s/%s--%s.cdx.json", registry.Slug(supplier), registry.Slug(product), registry.Slug(version))
}

// Options for a submission.
type Options struct {
	Supplier, Product, Version string
	Submission                 string // path to submission.cdx.json
	Components                 int
	Watchlist                  []string
	Artifact                   string
	DryRun                     bool
	Log                        func(string)
}

// ManualInstructions explains how to submit without gh.
func ManualInstructions(o Options) string {
	target := Target(o.Supplier, o.Product, o.Version)
	return fmt.Sprintf(`The GitHub CLI (gh) is not available, so open the pull request by hand:

  1. Fork %s and create a branch.
  2. Upload %s as
       %s
     (the web uploader: %s/upload/main/%s)
  3. Open a pull request; CI runs `+"`python -m xenolith community --check`"+` on it.

Pull request text you can paste:

%s`, WebRoot, filepath.Base(o.Submission), target, WebRoot, filepath.Dir(target), Body(o))
}

// Body is the pull request description.
func Body(o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Component list: %s %s %s\n\n", o.Supplier, o.Product, o.Version)
	fmt.Fprintf(&b, "- **What was analyzed:** `%s`\n", o.Artifact)
	fmt.Fprintf(&b, "- **How:** xenolith-scan (static analysis; see the tool's report for evidence)\n")
	fmt.Fprintf(&b, "- **Components:** %d at or above the 0.7 confidence line\n", o.Components)
	if len(o.Watchlist) > 0 {
		fmt.Fprintf(&b, "- **Watchlist components found:** %s\n", strings.Join(o.Watchlist, ", "))
	}
	b.WriteString("- **Attestation:** I am permitted to share this component list (xenolith:attestation = yes)\n\n")
	b.WriteString("Checklist (from CONTRIBUTING.md §3):\n- [x] The file is the scanner's `submission.cdx.json`, not the local report\n- [x] No file paths, user names or build directories\n- [x] Product identity confirmed\n")
	return b.String()
}

// Run forks, branches, commits and opens the pull request with gh.
func Run(o Options) (string, error) {
	if o.Log == nil {
		o.Log = func(string) {}
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		return "", errors.New("gh not found")
	}
	if out, err := run(gh, "auth", "status"); err != nil {
		return "", fmt.Errorf("gh is not logged in: %s", strings.TrimSpace(out))
	}
	user, err := run(gh, "api", "user", "--jq", ".login")
	if err != nil {
		return "", fmt.Errorf("gh api user: %w", err)
	}
	user = strings.TrimSpace(user)
	target := Target(o.Supplier, o.Product, o.Version)
	branch := "scan/" + strings.TrimSuffix(filepath.Base(target), ".cdx.json")
	if o.DryRun {
		return fmt.Sprintf("dry run: would fork %s as %s, add %s on branch %s and open a pull request", Upstream, user, target, branch), nil
	}
	o.Log("forking " + Upstream + " (no-op if the fork exists)")
	if out, err := run(gh, "repo", "fork", Upstream, "--clone=false"); err != nil && !strings.Contains(out, "already exists") {
		return "", fmt.Errorf("gh repo fork: %s", strings.TrimSpace(out))
	}
	work, err := os.MkdirTemp("", "xenolith-submit-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	o.Log("cloning the fork")
	if out, err := run(gh, "repo", "clone", user+"/Xenolith", work, "--", "--depth", "1", "--branch", "main"); err != nil {
		return "", fmt.Errorf("gh repo clone: %s", strings.TrimSpace(out))
	}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		return buf.String(), err
	}
	if out, err := git("checkout", "-b", branch); err != nil {
		return "", fmt.Errorf("git checkout: %s", out)
	}
	dst := filepath.Join(work, filepath.FromSlash(target))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	data, err := os.ReadFile(o.Submission)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", err
	}
	git("add", target)
	msg := fmt.Sprintf("community: %s %s %s component list (xenolith-scan)", o.Supplier, o.Product, o.Version)
	if out, err := git("-c", "user.name=xenolith-scan", "-c", "user.email=xenolith-scan@users.noreply.github.com", "commit", "-q", "-m", msg); err != nil {
		return "", fmt.Errorf("git commit: %s", out)
	}
	o.Log("pushing " + branch)
	if out, err := git("push", "-q", "-u", "origin", branch); err != nil {
		return "", fmt.Errorf("git push: %s", out)
	}
	o.Log("opening the pull request")
	bodyFile := filepath.Join(work, "pr-body.md")
	_ = os.WriteFile(bodyFile, []byte(Body(o)), 0o644)
	cmd := exec.Command(gh, "pr", "create", "--repo", Upstream, "--head", user+":"+branch, "--title", msg, "--body-file", bodyFile)
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh pr create: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func run(bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}
