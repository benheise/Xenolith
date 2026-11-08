package identity

import (
	"testing"
	"unicode/utf16"
)

func u16(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = append(out, byte(c), byte(c>>8))
	}
	return append(out, 0, 0)
}

func TestVersionInfo(t *testing.T) {
	data := append([]byte("MZ...junk..."), u16("VS_VERSION_INFO")...)
	data = append(data, 0, 0, 0, 0)
	for _, kv := range [][2]string{{"CompanyName", "Acme Networks, Inc."}, {"ProductName", "Acme Firewall Manager"}, {"ProductVersion", "7.2.9.1234"}} {
		data = append(data, u16(kv[0])...)
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		data = append(data, u16(kv[1])...)
	}
	info := VersionInfo(data)
	if info["CompanyName"] != "Acme Networks, Inc." || info["ProductName"] != "Acme Firewall Manager" || info["ProductVersion"] != "7.2.9.1234" {
		t.Fatalf("VersionInfo = %v", info)
	}
}

func TestPlistAndFileName(t *testing.T) {
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleName</key><string>Acme Agent</string>
<key>CFBundleShortVersionString</key><string>4.1.0</string><key>CFBundleIdentifier</key><string>com.acme.agent</string>
<key>Nested</key><dict><key>CFBundleName</key><string>ignored</string></dict></dict></plist>`
	d := Plist([]byte(plist))
	if d["CFBundleName"] != "Acme Agent" || d["CFBundleShortVersionString"] != "4.1.0" {
		t.Fatalf("plist = %v", d)
	}
	for name, want := range map[string][2]string{
		"acme-fw-7.2.9.tar.gz":                               {"acme fw", "7.2.9"},
		"Brotli-1.1.0-cp312-cp312-manylinux_2_17_x86_64.whl": {"Brotli", "1.1.0"},
		"Setup_1.4.0_x64.exe":                                {"Setup", "1.4.0"},
		"gh_2.63.2_linux_amd64.deb":                          {"gh", "2.63.2"},
		"image-v12.0.1-rc1.bin":                              {"image", "12.0.1-rc1"},
	} {
		g := fromName(name)
		if g.Product != want[0] || g.Version != want[1] {
			t.Errorf("%s -> %q %q, want %q %q", name, g.Product, g.Version, want[0], want[1])
		}
	}
}
