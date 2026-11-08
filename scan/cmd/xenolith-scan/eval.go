package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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
	Artifact        string   `json:"artifact"`
	Inventory       int      `json:"inventory_components"`
	Found           int      `json:"found"`
	Versioned       int      `json:"found_with_listed_version"`
	FoundVersion    int      `json:"found_with_same_version"`
	VersionAccuracy float64  `json:"version_accuracy"`
	WrongVersion    []string `json:"wrong_version,omitempty"`
	Recall          float64  `json:"recall"`
	WatchInventory  int      `json:"watchlist_in_inventory"`
	WatchFound      int      `json:"watchlist_found"`
	WatchRecall     float64  `json:"watchlist_recall"`
	Extra           int      `json:"found_but_not_listed"`
	Missed          []string `json:"missed"`
	ExtraHighConf   []string `json:"found_but_not_listed_components"`
	Error           string   `json:"error,omitempty"`
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
		if fp.Watchlist {
			watchNames[norm(fp.Name)] = true
			watchNames[norm(fp.ID)] = true
		}
	}
	for _, alias := range []string{"libcurl", "libssl", "libcrypto", "liblzma", "xz utils", "glibc", "libc6", "openssh-server", "openssh-client", "libwebp", "brotli", "libbrotli", "log4j", "log4j-core", "commons-text", "spring-beans", "spring-core", "spring-framework", "php", "openssl", "openssh", "curl", "react-server-dom-turbopack"} {
		watchNames[norm(alias)] = true
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	var results []evalResult
	fmt.Printf("%-40s %7s %6s %7s %8s %10s %6s\n", "artifact", "listed", "found", "recall", "version", "watchlist", "extra")
	for _, e := range c.Artifacts {
		r := evalOne(e, out, pack, watchNames)
		results = append(results, r)
		if r.Error != "" {
			fmt.Printf("%-40s error: %s\n", trunc(r.Artifact, 40), r.Error)
			continue
		}
		ver := "-"
		if r.Versioned > 0 {
			ver = fmt.Sprintf("%d/%d", r.FoundVersion, r.Versioned)
		}
		fmt.Printf("%-40s %7d %6d %6.0f%% %8s %6d/%-3d %6d\n", trunc(r.Artifact, 40), r.Inventory, r.Found, r.Recall*100, ver, r.WatchFound, r.WatchInventory, r.Extra)
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
	// index every submitted component under its full and short (group-less) name; extras
	// are counted per submitted component, not per index key
	// every submitted component is indexed under its full name, its short (group-less)
	// name and a punctuation-free form; a listed component matches all of them, so the
	// same name from a notices file and from the jar itself both count
	index := map[string][]string{}
	put := func(key, orig string) {
		for _, k := range []string{key, strings.ReplaceAll(key, "-", "")} { // node.js = nodejs
			if !slices.Contains(index[k], orig) {
				index[k] = append(index[k], orig)
			}
		}
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		put(norm(k), k)
		if a, ok := evalAliases[norm(k)]; ok {
			put(a, k)
		}
		if i := strings.LastIndex(k, ":"); i >= 0 { // group:name -> name
			put(norm(k[i+1:]), k)
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
		cands := index[key]
		if len(cands) == 0 {
			// try the last path-ish token (org.apache.commons:commons-text, libfoo-dev)
			for _, alt := range append(altNames(c.Name), strings.ReplaceAll(key, "-", "")) {
				if cands = index[alt]; len(cands) > 0 {
					break
				}
			}
		}
		if len(cands) == 0 {
			r.Missed = append(r.Missed, c.Name+" "+c.Version)
			continue
		}
		r.Found++
		var seen []string
		ok := false
		for _, o := range cands {
			matched[o] = true
			seen = append(seen, found[o])
			ok = ok || hasVersion(found[o], c.Version)
		}
		if isWatch {
			r.WatchFound++
		}
		if c.Version != "" {
			r.Versioned++
			if ok {
				r.FoundVersion++
			} else {
				r.WrongVersion = append(r.WrongVersion, fmt.Sprintf("%s %s (scanner: %s)", c.Name, c.Version, orDash(strings.Join(seen, "; "))))
			}
		}
	}
	for k, v := range found {
		if !matched[k] {
			r.Extra++
			r.ExtraHighConf = append(r.ExtraHighConf, strings.TrimSpace(k+" "+v))
		}
	}
	sort.Strings(r.ExtraHighConf)
	if r.Inventory > 0 {
		r.Recall = float64(r.Found) / float64(r.Inventory)
	}
	if r.WatchInventory > 0 {
		r.WatchRecall = float64(r.WatchFound) / float64(r.WatchInventory)
	}
	if r.Versioned > 0 {
		r.VersionAccuracy = float64(r.FoundVersion) / float64(r.Versioned)
	}
	return r
}

// hasVersion: the scanner's value is one version or a sorted ", "-joined list of them.
func hasVersion(found, want string) bool {
	for _, v := range strings.Split(found, ", ") {
		if v == want {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// evalAliases: product names a binary's own metadata uses for a component that ground
// truth lists under its short name. Matching only; submissions keep what was found.
var evalAliases = map[string]string{
	"zstandard": "zstd",
	"xz-utils":  "xz",
	"qt6":       "qt",
	"qt5":       "qt",
}

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
