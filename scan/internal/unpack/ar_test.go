package unpack

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func arMember(name string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", name, "0", "0", "0", "644", len(data))
	b.Write(data)
	if len(data)%2 == 1 {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// A GNU static library like numpy's libnpymath.a: symbol table, long-name table,
// a short name and a long one.
func gnuStaticLib() []byte {
	long := "npy_math_complex_long_name.o/\n"
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	b.Write(arMember("/", []byte("\x00\x00\x00\x01\x00\x00\x00\x00sym\x00")))
	b.Write(arMember("//", []byte(long)))
	b.Write(arMember("halffloat.o/", []byte("\x7fELF short")))
	b.Write(arMember("/0", []byte("\x7fELF long name member!")))
	return b.Bytes()
}

func TestArGNU(t *testing.T) {
	rd, err := newArReader(bytes.NewReader(gnuStaticLib()))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		h, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rd)
		got = append(got, fmt.Sprintf("%s=%d:%s", h.Name, h.Size, data[:4]))
	}
	want := "[halffloat.o=10:\x7fELF npy_math_complex_long_name.o=22:\x7fELF]"
	if fmt.Sprint(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestArBSDAndMalformed(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	b.Write(arMember("#1/20", append([]byte("a_long_bsd_name.o\x00\x00\x00"), []byte("DATA")...)))
	rd, _ := newArReader(bytes.NewReader(b.Bytes()))
	h, err := rd.Next()
	if err != nil || h.Name != "a_long_bsd_name.o" || h.Size != 4 {
		t.Fatalf("BSD name: %+v %v", h, err)
	}
	for _, bad := range []string{"!<arch>\n" + "x", "!<arch>\n" + string(arMember("/9999", []byte("x"))), "!<arch>\n" + "short header"} {
		rd, err := newArReader(bytes.NewReader([]byte(bad)))
		if err != nil {
			continue
		}
		if _, err := rd.Next(); err == nil {
			t.Errorf("malformed archive %q should be an error", bad[:12])
		}
	}
}

func FuzzArReader(f *testing.F) {
	f.Add(gnuStaticLib())
	f.Add([]byte("!<arch>\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rd, err := newArReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		for i := 0; i < 1000; i++ {
			if _, err := rd.Next(); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, rd)
		}
	})
}
