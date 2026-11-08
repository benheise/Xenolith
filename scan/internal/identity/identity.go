// Package identity prefills the product's supplier, name and version from what the
// artifact itself says (PE VERSIONINFO, Info.plist, os-release, image labels,
// installer names) and matches the result against Xenolith's product registry.
package identity

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/benheise/Xenolith/scan/internal/registry"
)

// Guess is a prefilled product identity with the evidence behind it.
type Guess struct {
	Supplier string           `json:"supplier"`
	Product  string           `json:"product"`
	Version  string           `json:"version"`
	Type     string           `json:"type"` // application, firmware, operating-system, container
	Source   string           `json:"source"`
	Matches  []registry.Match `json:"matches,omitempty"`
}

// FromTrees looks through the unpacked trees for product metadata, strongest first.
func FromTrees(trees []string, artifactName string, labels map[string]string) Guess {
	var g Guess
	if len(labels) > 0 {
		g = fromLabels(labels)
	}
	if g.Product == "" {
		g = fromPE(trees)
	}
	if g.Product == "" {
		g = fromPlist(trees)
	}
	if g.Product == "" {
		g = fromOSRelease(trees)
	}
	if g.Product == "" {
		g = fromName(artifactName)
	}
	if g.Type == "" {
		g.Type = "application"
	}
	g.Matches = registry.Find(g.Supplier, g.Product, 5)
	return g
}

func fromLabels(labels map[string]string) Guess {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(labels[k]); v != "" {
				return v
			}
		}
		return ""
	}
	g := Guess{
		Supplier: get("org.opencontainers.image.vendor", "vendor", "maintainer"),
		Product:  get("org.opencontainers.image.title", "name", "org.label-schema.name"),
		Version:  get("org.opencontainers.image.version", "version", "org.label-schema.version"),
		Type:     "container", Source: "container image labels",
	}
	if g.Product == "" {
		return Guess{}
	}
	return g
}

// --- Windows: VS_VERSIONINFO strings in the largest executable ---------------

var versionKeys = []string{"CompanyName", "ProductName", "ProductVersion", "FileDescription", "FileVersion"}

func fromPE(trees []string) Guess {
	best, bestSize := "", int64(0)
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			lower := strings.ToLower(d.Name())
			if !strings.HasSuffix(lower, ".exe") && !strings.HasSuffix(lower, ".msi") {
				return nil
			}
			if st, err := d.Info(); err == nil && st.Size() > bestSize && st.Size() < 512<<20 {
				best, bestSize = p, st.Size()
			}
			return nil
		})
	}
	if best == "" {
		return Guess{}
	}
	data, err := os.ReadFile(best)
	if err != nil {
		return Guess{}
	}
	info := VersionInfo(data)
	g := Guess{Supplier: info["CompanyName"], Product: info["ProductName"], Version: info["ProductVersion"],
		Type: "application", Source: "VERSIONINFO in " + filepath.Base(best)}
	if g.Version == "" {
		g.Version = info["FileVersion"]
	}
	if g.Product == "" {
		g.Product = info["FileDescription"]
	}
	if g.Product == "" {
		return Guess{}
	}
	return g
}

// VersionInfo reads StringFileInfo values from a PE file's VS_VERSIONINFO resource
// without parsing the resource tree: keys and values are UTF-16LE strings laid out
// as key, padding, value.
func VersionInfo(data []byte) map[string]string {
	out := map[string]string{}
	marker := utf16le("VS_VERSION_INFO")
	start := bytes.Index(data, marker)
	if start < 0 {
		return out
	}
	region := data[start:]
	if len(region) > 64<<10 {
		region = region[:64<<10]
	}
	for _, key := range versionKeys {
		k := append(utf16le(key), 0, 0)
		i := bytes.Index(region, k)
		if i < 0 {
			continue
		}
		j := i + len(k)
		for j%4 != 0 || (j+1 < len(region) && region[j] == 0 && region[j+1] == 0) {
			j++
			if j+1 >= len(region) {
				break
			}
		}
		out[key] = strings.TrimSpace(readUTF16(region[j:]))
	}
	return out
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func readUTF16(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b) && len(u) < 256; i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// --- macOS: Info.plist ------------------------------------------------------

func fromPlist(trees []string) Guess {
	var best string
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || best != "" || !d.Type().IsRegular() || d.Name() != "Info.plist" {
				return nil
			}
			if strings.Contains(p, ".app"+string(filepath.Separator)+"Contents") || strings.Contains(p, "Contents") {
				best = p
			}
			return nil
		})
	}
	if best == "" {
		return Guess{}
	}
	data, err := os.ReadFile(best)
	if err != nil {
		return Guess{}
	}
	d := Plist(data)
	g := Guess{Product: firstNonEmpty(d["CFBundleDisplayName"], d["CFBundleName"]), Version: firstNonEmpty(d["CFBundleShortVersionString"], d["CFBundleVersion"]),
		Type: "application", Source: "Info.plist"}
	if id := d["CFBundleIdentifier"]; id != "" {
		parts := strings.Split(id, ".")
		if len(parts) >= 2 {
			g.Supplier = strings.Title(parts[1]) //nolint:staticcheck
		}
	}
	if g.Product == "" {
		return Guess{}
	}
	return g
}

// Plist reads the top-level string values of an XML property list.
func Plist(data []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth, key := 0, ""
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "dict":
				depth++
			case "key":
				if depth == 1 {
					var k string
					dec.DecodeElement(&k, &t)
					key = k
				}
			case "string":
				if depth == 1 && key != "" {
					var v string
					dec.DecodeElement(&v, &t)
					out[key] = v
					key = ""
				}
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				depth--
			}
		}
	}
	return out
}

// --- Linux: /etc/os-release --------------------------------------------------

func fromOSRelease(trees []string) Guess {
	var best string
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || best != "" || !d.Type().IsRegular() || d.Name() != "os-release" {
				return nil
			}
			if strings.HasSuffix(filepath.ToSlash(p), "/etc/os-release") || strings.HasSuffix(filepath.ToSlash(p), "/usr/lib/os-release") {
				best = p
			}
			return nil
		})
	}
	if best == "" {
		return Guess{}
	}
	data, err := os.ReadFile(best)
	if err != nil {
		return Guess{}
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	name := firstNonEmpty(kv["NAME"], kv["PRETTY_NAME"])
	if name == "" {
		return Guess{}
	}
	// A plain distribution says what the appliance runs on, not what the product is;
	// vendors' own os-release files name the product.
	note := "os-release"
	for _, generic := range []string{"ubuntu", "debian", "alpine", "centos", "red hat", "rocky", "fedora", "suse", "opensuse", "almalinux", "amazon linux", "oracle linux", "arch"} {
		if strings.Contains(strings.ToLower(name), generic) {
			note = "os-release (a generic distribution: the product name probably differs)"
		}
	}
	return Guess{Product: name, Version: firstNonEmpty(kv["VERSION_ID"], kv["VERSION"]), Type: "firmware", Source: note}
}

// --- file name --------------------------------------------------------------

// "acme-fw-7.2.9.tar.gz", "Setup_1.4.0_x64.exe", "Brotli-1.1.0-cp312-...whl": the version is
// the first dotted number after the name; platform and build tags after it are dropped.
var nameVersion = regexp.MustCompile(`(?i)^([a-z][\w.+ -]*?)[-_ ]v?(\d+(?:\.\d+)+(?:[a-z]\d*|[-_.](?:rc|beta|alpha|p|sp|r)\d+)?)(?:[-_.+].*)?\.[a-z0-9]+$`)

func fromName(artifact string) Guess {
	base := filepath.Base(artifact)
	if m := nameVersion.FindStringSubmatch(base); m != nil {
		product := strings.NewReplacer("_", " ", "-", " ").Replace(m[1])
		return Guess{Product: strings.TrimSpace(product), Version: m[2], Type: "application", Source: "file name"}
	}
	return Guess{Product: strings.TrimSuffix(base, filepath.Ext(base)), Source: "file name"}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
