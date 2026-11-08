package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/benheise/Xenolith/scan/internal/fingerprint"
	"github.com/benheise/Xenolith/scan/internal/registry"
)

// corpusEntry is one artifact with a known inventory (the vendor's own notices or
// dependency report, as stored by Xenolith) to measure the scanner against.
type corpusEntry struct {
	Artifact  string `yaml:"artifact" json:"artifact"` // local path or https URL
	SHA256    string `yaml:"sha256" json:"sha256"`
	Supplier  string `yaml:"supplier" json:"supplier"`
	Product   string `yaml:"product" json:"product"`
	Version   string `yaml:"version" json:"version"`
	Inventory string `yaml:"inventory" json:"inventory"` // Xenolith inventory JSON: {"components":[{"name","version"}]}
	Note      string `yaml:"note" json:"note"`
}

type corpus struct {
	Artifacts []corpusEntry `yaml:"artifacts" json:"artifacts"`
}

type evalResult struct {
	Artifact       string   `json:"artifact"`
	Inventory      int      `json:"inventory_components"`
	Found          int      `json:"found"`
	FoundVersion   int      `json:"found_with_same_version"`
	Recall         float64  `json:"recall"`
	WatchInventory int      `json:"watchlist_in_inventory"`
	WatchFound     int      `json:"watchlist_found"`
	WatchRecall    float64  `json:"watchlist_recall"`
	Extra          int      `json:"found_but_not_listed"`
	Missed         []string `json:"missed"`
	ExtraHighConf  []string `json:"extra_high_confidence"`
	Error          string   `json:"error,omitempty"`
}

func runEval(manifest, out string) error {
	b, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var c corpus
	if strings.HasSuffix(manifest, ".json") {
		err = json.Unmarshal(b, &c)
	} else {
		err = yaml.Unmarshal(b, &c)
	}
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	pack, err := fingerprint.LoadEmbedded()
	if err != nil {
		return err
	}
	watchNames := map[string]bool{}
	for _, fp := range pack.Components {
		watchNames[norm(fp.Name)] = true
		watchNames[norm(fp.ID)] = true
	}
	for _, alias := range []string{"libcurl", "libssl", "libcrypto", "liblzma", "xz utils", "glibc", "libc6", "openssh-server", "openssh-client", "libwebp", "brotli", "libbrotli", "log4j", "log4j-core", "commons-text", "spring-beans", "spring-core", "spring-framework", "php", "openssl", "openssh", "curl"} {
		watchNames[norm(alias)] = true
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	var results []evalResult
	fmt.Printf("%-40s %8s %8s %8s %10s %6s\n", "artifact", "listed", "found", "recall", "watchlist", "extra")
	for _, e := range c.Artifacts {
		r := evalOne(e, out, pack, watchNames)
		results = append(results, r)
		if r.Error != "" {
			fmt.Printf("%-40s error: %s\n", trunc(r.Artifact, 40), r.Error)
			continue
		}
		fmt.Printf("%-40s %8d %8d %7.0f%% %6d/%-3d %6d\n", trunc(r.Artifact, 40), r.Inventory, r.Found, r.Recall*100, r.WatchFound, r.WatchInventory, r.Extra)
	}
	summaryPath := filepath.Join(out, "eval.json")
	jb, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(summaryPath, append(jb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("\nwrote %s (per-artifact missed and extra lists)\n", summaryPath)
	return nil
}

func evalOne(e corpusEntry, out string, pack *fingerprint.Pack, watch map[string]bool) evalResult {
	r := evalResult{Artifact: filepath.Base(e.Artifact)}
	local := e.Artifact
	if strings.HasPrefix(e.Artifact, "https://") {
		dl := filepath.Join(out, "downloads", filepath.Base(e.Artifact))
		if _, err := os.Stat(dl); err != nil {
			if err := download(e.Artifact, dl); err != nil {
				r.Error = "download: " + err.Error()
				return r
			}
		}
		local = dl
	}
	if e.SHA256 != "" {
		sum, err := sha256File(local)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		if !strings.EqualFold(sum, e.SHA256) {
			r.Error = "sha256 mismatch: " + sum
			return r
		}
	}
	dir := filepath.Join(out, registry.Slug(filepath.Base(e.Artifact)))
	flags := scanFlags{supplier: e.Supplier, product: e.Product, version: e.Version, helpers: "auto", maxDepth: 10, yes: true, quiet: true, noSummary: true}
	if err := scanOne(local, dir, flags, pack); err != nil {
		r.Error = "scan: " + err.Error()
		return r
	}
	_, found, err := loadComponents(filepath.Join(dir, "submission.cdx.json"))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	invB, err := os.ReadFile(e.Inventory)
	if err != nil {
		r.Error = "inventory: " + err.Error()
		return r
	}
	var inv struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(invB, &inv); err != nil {
		r.Error = "inventory: " + err.Error()
		return r
	}
	foundNorm := map[string]string{}
	for k, v := range found {
		foundNorm[norm(k)] = v
		if i := strings.LastIndex(k, ":"); i >= 0 { // group:name -> name
			foundNorm[norm(k[i+1:])] = v
		}
	}
	matched := map[string]bool{}
	for _, c := range inv.Components {
		r.Inventory++
		key := norm(c.Name)
		isWatch := watch[key]
		if isWatch {
			r.WatchInventory++
		}
		v, ok := foundNorm[key]
		if !ok {
			// try the last path-ish token (org.apache.commons:commons-text, libfoo-dev)
			for _, alt := range altNames(c.Name) {
				if v, ok = foundNorm[alt]; ok {
					break
				}
			}
		}
		if ok {
			r.Found++
			matched[key] = true
			if isWatch {
				r.WatchFound++
			}
			if c.Version != "" && strings.Contains(v, c.Version) {
				r.FoundVersion++
			}
		} else {
			r.Missed = append(r.Missed, c.Name+" "+c.Version)
		}
	}
	for k := range foundNorm {
		if !matched[k] {
			r.Extra++
		}
	}
	if r.Inventory > 0 {
		r.Recall = float64(r.Found) / float64(r.Inventory)
	}
	if r.WatchInventory > 0 {
		r.WatchRecall = float64(r.WatchFound) / float64(r.WatchInventory)
	}
	return r
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func norm(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func altNames(name string) []string {
	var out []string
	if i := strings.LastIndex(name, ":"); i >= 0 {
		out = append(out, norm(name[i+1:]))
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		out = append(out, norm(name[i+1:]))
	}
	n := norm(name)
	out = append(out, strings.TrimPrefix(n, "lib"), strings.TrimSuffix(n, "-dev"), strings.TrimPrefix(strings.TrimSuffix(n, "-dev"), "lib"))
	return out
}

func download(url, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
