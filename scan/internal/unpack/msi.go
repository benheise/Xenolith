package unpack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// Windows Installer databases keep the real file names in tables; the cabinets inside
// an MSI name their members by the File table's key ("filWireshark_exe"). 7-Zip
// extracts the raw streams (`!File`, `!_StringPool`, ...), and msiNames reads them to
// map each key to its installed path, so files keep names that Syft and people can use.
//
// Format notes follow Wine's msi/string.c and msi/table.c: strings live in one pool
// (`_StringPool` lengths, `_StringData` bytes), tables are stored column by column,
// integers carry a 0x8000 / 0x80000000 bias (0 is NULL) and string columns hold
// 2- or 3-byte references into the pool.

const (
	msiTypeValid    = 0x0100
	msiTypeString   = 0x0800
	msiTypeNullable = 0x1000
	msiMaxStream    = 64 << 20
)

type msiColumn struct {
	number int
	name   string
	typ    int
}

type msiDB struct {
	dir     string
	strs    []string // index = string id; 0 is the empty/NULL string
	refSize int
	columns map[string][]msiColumn
}

// msiNames returns File key -> slash-separated install path for an MSI whose streams
// 7-Zip extracted into dir. ok is false when the streams are not there.
func msiNames(dir string) (map[string]string, bool, error) {
	db, err := openMSI(dir)
	if err != nil || db == nil {
		return nil, false, err
	}
	files, err := db.table("File")
	if err != nil {
		return nil, true, err
	}
	comps, _ := db.table("Component")
	dirs, _ := db.table("Directory")
	compDir := map[string]string{}
	for _, row := range comps {
		compDir[row["Component"]] = row["Directory_"]
	}
	dirRows := map[string]map[string]string{}
	for _, row := range dirs {
		dirRows[row["Directory"]] = row
	}
	cache := map[string]string{}
	var dirPath func(id string, depth int) string
	dirPath = func(id string, depth int) string {
		if p, ok := cache[id]; ok {
			return p
		}
		row, ok := dirRows[id]
		if !ok || depth > 64 {
			return ""
		}
		name := msiLongName(strings.SplitN(row["DefaultDir"], ":", 2)[0])
		parent := row["Directory_Parent"]
		p := ""
		if parent != "" && parent != id {
			p = dirPath(parent, depth+1)
		}
		if name != "" && name != "." && name != "SourceDir" {
			p = path.Join(p, name)
		}
		cache[id] = p
		return p
	}
	out := map[string]string{}
	for _, row := range files {
		key, name := row["File"], msiLongName(row["FileName"])
		if key == "" || name == "" {
			continue
		}
		out[key] = path.Join(dirPath(compDir[row["Component_"]], 0), name)
	}
	return out, true, nil
}

// msiLongName takes "SHORT~1.DLL|LongName.dll" (or just one name) and returns a single
// safe path element.
func msiLongName(s string) string {
	if i := strings.LastIndexByte(s, '|'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.NewReplacer("/", "_", "\\", "_", "\x00", "").Replace(s)
	if s == ".." {
		return "_"
	}
	return s
}

func openMSI(dir string) (*msiDB, error) {
	pool, err := readStream(dir, "!_StringPool")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := readStream(dir, "!_StringData")
	if err != nil {
		return nil, err
	}
	if len(pool) < 4 {
		return nil, fmt.Errorf("msi: string pool too short")
	}
	db := &msiDB{dir: dir, refSize: 2, columns: map[string][]msiColumn{}}
	codepage := uint32(binary.LittleEndian.Uint16(pool)) | uint32(binary.LittleEndian.Uint16(pool[2:])&0x7fff)<<16
	if binary.LittleEndian.Uint16(pool[2:])&0x8000 != 0 {
		db.refSize = 3
	}
	decode := func(b []byte) string {
		if codepage == 65001 || utf8.Valid(b) {
			return string(b)
		}
		s, err := charmap.Windows1252.NewDecoder().Bytes(b)
		if err != nil {
			return string(b)
		}
		return string(s)
	}
	db.strs = []string{""}
	words := func(i int) int { return int(binary.LittleEndian.Uint16(pool[i*2:])) }
	count := len(pool) / 4
	offset := 0
	for i := 1; i < count; {
		length, refs := words(i*2), words(i*2+1)
		if length == 0 && refs == 0 { // unused id
			db.strs = append(db.strs, "")
			i++
			continue
		}
		if length == 0 { // a string over 64 KiB: the next entry carries the length
			if (i+1)*2+1 >= len(pool)/2 {
				break
			}
			length = words((i+1)*2+1)<<16 | words((i+1)*2)
			i += 2
		} else {
			i++
		}
		if offset+length > len(data) {
			return nil, fmt.Errorf("msi: string pool runs past the string data")
		}
		db.strs = append(db.strs, decode(data[offset:offset+length]))
		offset += length
	}
	cols, err := readStream(dir, "!_Columns")
	if err != nil {
		return nil, err
	}
	// _Columns: Table (string), Number (i2), Name (string), Type (i2), column-major
	rowSize := 2*db.refSize + 4
	rows := len(cols) / rowSize
	at := func(col, row, width int) []byte {
		base := 0
		widths := []int{db.refSize, 2, db.refSize, 2}
		for c := 0; c < col; c++ {
			base += widths[c] * rows
		}
		return cols[base+row*width : base+row*width+width]
	}
	for r := 0; r < rows; r++ {
		table := db.str(at(0, r, db.refSize))
		num := int(binary.LittleEndian.Uint16(at(1, r, 2))) - 0x8000
		name := db.str(at(2, r, db.refSize))
		typ := int(binary.LittleEndian.Uint16(at(3, r, 2))) - 0x8000
		if table == "" || name == "" {
			continue
		}
		db.columns[table] = append(db.columns[table], msiColumn{number: num, name: name, typ: typ})
	}
	for t := range db.columns {
		sort.Slice(db.columns[t], func(i, j int) bool { return db.columns[t][i].number < db.columns[t][j].number })
	}
	return db, nil
}

func (db *msiDB) str(b []byte) string {
	id := int(b[0]) | int(b[1])<<8
	if len(b) == 3 {
		id |= int(b[2]) << 16
	}
	if id <= 0 || id >= len(db.strs) {
		return ""
	}
	return db.strs[id]
}

func (db *msiDB) width(typ int) int {
	switch {
	case typ&^msiTypeNullable == msiTypeString|msiTypeValid: // binary stream column
		return 2
	case typ&msiTypeString != 0:
		return db.refSize
	case typ&0xff <= 2:
		return 2
	}
	return 4
}

// table reads a whole table; integers come back as decimal strings.
func (db *msiDB) table(name string) ([]map[string]string, error) {
	cols := db.columns[name]
	if len(cols) == 0 {
		return nil, fmt.Errorf("msi: no %s table", name)
	}
	raw, err := readStream(db.dir, "!"+name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // an empty table has no stream
	}
	if err != nil {
		return nil, err
	}
	rowSize := 0
	for _, c := range cols {
		rowSize += db.width(c.typ)
	}
	if rowSize == 0 || len(raw)%rowSize != 0 {
		return nil, fmt.Errorf("msi: %s table is %d bytes, not a multiple of its %d-byte rows", name, len(raw), rowSize)
	}
	rows := len(raw) / rowSize
	out := make([]map[string]string, rows)
	for r := range out {
		out[r] = map[string]string{}
	}
	base := 0
	for _, c := range cols {
		w := db.width(c.typ)
		for r := 0; r < rows; r++ {
			b := raw[base+r*w : base+r*w+w]
			switch {
			case c.typ&msiTypeString != 0 && w == db.refSize && !(c.typ&^msiTypeNullable == msiTypeString|msiTypeValid):
				out[r][c.name] = db.str(b)
			case w == 2:
				if v := int(binary.LittleEndian.Uint16(b)); v != 0 {
					out[r][c.name] = fmt.Sprint(v - 0x8000)
				}
			case w == 4:
				if v := int64(binary.LittleEndian.Uint32(b)); v != 0 {
					out[r][c.name] = fmt.Sprint(v - 0x80000000)
				}
			}
		}
		base += w * rows
	}
	return out, nil
}

func readStream(dir, name string) ([]byte, error) {
	p := filepath.Join(dir, name)
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > msiMaxStream {
		return nil, fmt.Errorf("msi: %s stream is too large", name)
	}
	return os.ReadFile(p)
}
