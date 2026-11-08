package unpack

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// msiFixture writes the streams 7-Zip extracts from an MSI: a string pool, _Columns
// and column-major tables, with 2-byte string references.
type msiFixture struct {
	strs []string
	ids  map[string]int
}

func (f *msiFixture) id(s string) int {
	if s == "" {
		return 0
	}
	if f.ids == nil {
		f.ids = map[string]int{}
	}
	if id, ok := f.ids[s]; ok {
		return id
	}
	f.strs = append(f.strs, s)
	f.ids[s] = len(f.strs)
	return len(f.strs)
}

type fixtureCol struct {
	name string
	typ  int // MSI column type: 0x0d48 string(72) key, 0x1d48 nullable string, 0x0502 int16, 0x0104 int32
}

func (f *msiFixture) table(dir, name string, cols []fixtureCol, rows [][]any, columns *[][4]any) {
	for i, c := range cols {
		*columns = append(*columns, [4]any{name, i + 1, c.name, c.typ})
	}
	var out []byte
	for ci, c := range cols {
		for _, row := range rows {
			switch v := row[ci].(type) {
			case string:
				out = binary.LittleEndian.AppendUint16(out, uint16(f.id(v)))
			case int:
				if c.typ&0xff == 4 {
					out = binary.LittleEndian.AppendUint32(out, uint32(int64(v)+0x80000000))
				} else {
					out = binary.LittleEndian.AppendUint16(out, uint16(v+0x8000))
				}
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "!"+name), out, 0o644); err != nil {
		panic(err)
	}
}

func (f *msiFixture) finish(dir string, columns [][4]any) {
	var cols []byte
	for c := 0; c < 4; c++ {
		for _, row := range columns {
			switch c {
			case 0, 2:
				cols = binary.LittleEndian.AppendUint16(cols, uint16(f.id(row[c].(string))))
			default:
				cols = binary.LittleEndian.AppendUint16(cols, uint16(row[c].(int)+0x8000))
			}
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "!_Columns"), cols, 0o644)
	pool := binary.LittleEndian.AppendUint16(nil, 1252)
	pool = binary.LittleEndian.AppendUint16(pool, 0)
	var data []byte
	for _, s := range f.strs {
		pool = binary.LittleEndian.AppendUint16(pool, uint16(len(s)))
		pool = binary.LittleEndian.AppendUint16(pool, 1)
		data = append(data, s...)
	}
	_ = os.WriteFile(filepath.Join(dir, "!_StringPool"), pool, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "!_StringData"), data, 0o644)
}

func TestMSINames(t *testing.T) {
	dir := t.TempDir()
	f := &msiFixture{}
	var columns [][4]any
	key, nullable, i2, i4 := 0x2d48, 0x1d48, 0x0502, 0x0104
	f.table(dir, "Directory", []fixtureCol{{"Directory", key}, {"Directory_Parent", nullable}, {"DefaultDir", 0x0dff}}, [][]any{
		{"TARGETDIR", "", "SourceDir"},
		{"ProgramFiles64Folder", "TARGETDIR", "."},
		{"INSTALLFOLDER", "ProgramFiles64Folder", "p_nc8oqe|Wireshark"},
		{"dirplugins", "INSTALLFOLDER", "plugins"},
		{"direvil", "INSTALLFOLDER", ".."},
	}, &columns)
	f.table(dir, "Component", []fixtureCol{{"Component", key}, {"ComponentId", nullable}, {"Directory_", 0x0d48}, {"Attributes", i2}}, [][]any{
		{"cmpMain", "{GUID-1}", "INSTALLFOLDER", 0},
		{"cmpPlugin", "{GUID-2}", "dirplugins", 0},
		{"cmpEvil", "{GUID-3}", "direvil", 0},
	}, &columns)
	f.table(dir, "File", []fixtureCol{{"File", key}, {"Component_", 0x0d48}, {"FileName", 0x0dff}, {"FileSize", i4}, {"Attributes", 0x1502}, {"Sequence", i4}}, [][]any{
		{"filWireshark_exe", "cmpMain", "tx588dkj.exe|Wireshark.exe", 12199592, 512, 1},
		{"filBrotli", "cmpMain", "brotlidec.dll", 50000, 512, 2},
		{"filPlugin", "cmpPlugin", "PLUGIN~1.DLL|plugin one.dll", 1000, 512, 3},
		{"filEvil", "cmpEvil", "..\\..\\etc\\passwd", 1, 512, 4},
	}, &columns)
	f.finish(dir, columns)

	names, ok, err := msiNames(dir)
	if err != nil || !ok {
		t.Fatalf("msiNames: ok=%v err=%v", ok, err)
	}
	want := map[string]string{
		"filWireshark_exe": "Wireshark/Wireshark.exe",
		"filBrotli":        "Wireshark/brotlidec.dll",
		"filPlugin":        "Wireshark/plugins/plugin one.dll",
	}
	for k, v := range want {
		if names[k] != v {
			t.Errorf("%s: got %q, want %q", k, names[k], v)
		}
	}
	// a hostile name or directory must not leave the tree
	if p, ok := safeName(names["filEvil"]); !ok || filepath.IsAbs(p) || p == ".." || len(p) > 2 && p[:3] == "../" {
		t.Errorf("hostile entry escaped: %q", names["filEvil"])
	}
}

func TestMSINamesWithoutTables(t *testing.T) {
	if _, ok, err := msiNames(t.TempDir()); ok || err != nil {
		t.Fatalf("no streams: ok=%v err=%v", ok, err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "!_StringPool"), []byte{0xe4, 0x04, 0, 0, 5, 0, 1, 0}, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "!_StringData"), []byte("ab"), 0o644) // shorter than the pool says
	if _, _, err := msiNames(dir); err == nil {
		t.Error("a corrupt string pool should be an error")
	}
}

func FuzzMSITables(f *testing.F) {
	f.Add([]byte{0xe4, 0x04, 0, 0, 3, 0, 1, 0}, []byte("Foo"), []byte{1, 0, 0x01, 0x80, 1, 0, 0x48, 0x8d}, []byte{1, 0})
	f.Fuzz(func(t *testing.T, pool, data, cols, file []byte) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "!_StringPool"), pool, 0o644)
		_ = os.WriteFile(filepath.Join(dir, "!_StringData"), data, 0o644)
		_ = os.WriteFile(filepath.Join(dir, "!_Columns"), cols, 0o644)
		_ = os.WriteFile(filepath.Join(dir, "!File"), file, 0o644)
		_, _, _ = msiNames(dir) // must not panic
	})
}
