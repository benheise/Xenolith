package unpack

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// arReader reads Unix ar archives: Debian packages, and static libraries (.a) in
// both GNU form ("/" symbol table, "//" long-name table, "name/" and "/123" names)
// and BSD form ("#1/len" names stored in front of the data). Every field is
// validated; a malformed header is an error, never a panic.
type arReader struct {
	r         *bufio.Reader
	remaining int64  // bytes left in the current member
	pad       bool   // a padding byte follows the current member
	longNames []byte // GNU "//" table
}

type arHeader struct {
	Name string
	Size int64
}

var errArFormat = errors.New("not an ar archive")

func newArReader(r io.Reader) (*arReader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, errArFormat
	}
	if string(magic) != "!<arch>\n" {
		return nil, errArFormat
	}
	return &arReader{r: br}, nil
}

const maxArMember = 1 << 40

// Next advances to the next member, skipping the symbol and long-name tables.
func (a *arReader) Next() (*arHeader, error) {
	for {
		if err := a.skipRest(); err != nil {
			return nil, err
		}
		raw := make([]byte, 60)
		n, err := io.ReadFull(a.r, raw)
		if err == io.EOF || (err == io.ErrUnexpectedEOF && n == 0) {
			return nil, io.EOF
		}
		if err != nil {
			return nil, fmt.Errorf("ar: truncated header")
		}
		if raw[58] != '`' || raw[59] != '\n' {
			return nil, fmt.Errorf("ar: bad header terminator")
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(raw[48:58])), 10, 64)
		if err != nil || size < 0 || size > maxArMember {
			return nil, fmt.Errorf("ar: bad member size %q", strings.TrimSpace(string(raw[48:58])))
		}
		a.remaining, a.pad = size, size%2 == 1
		name := strings.TrimRight(string(raw[0:16]), " ")
		switch {
		case name == "/" || name == "/SYM64/" || name == "__.SYMDEF" || name == "__.SYMDEF SORTED":
			continue // symbol table
		case name == "//":
			if size > 64<<20 {
				return nil, fmt.Errorf("ar: long-name table too large")
			}
			a.longNames = make([]byte, size)
			if _, err := io.ReadFull(a.r, a.longNames); err != nil {
				return nil, fmt.Errorf("ar: truncated long-name table")
			}
			a.remaining = 0
			continue
		case strings.HasPrefix(name, "#1/"): // BSD: the name is the first n bytes of the data
			n, err := strconv.Atoi(strings.TrimSpace(name[3:]))
			if err != nil || n < 0 || int64(n) > size || n > 4096 {
				return nil, fmt.Errorf("ar: bad BSD name length")
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(a.r, buf); err != nil {
				return nil, fmt.Errorf("ar: truncated BSD name")
			}
			a.remaining -= int64(n)
			name = string(bytes.TrimRight(buf, "\x00"))
		case strings.HasPrefix(name, "/") && len(name) > 1: // GNU: offset into the long-name table
			off, err := strconv.Atoi(name[1:])
			if err != nil || off < 0 || off >= len(a.longNames) {
				return nil, fmt.Errorf("ar: bad long-name offset %q", name)
			}
			end := bytes.IndexByte(a.longNames[off:], '\n')
			if end < 0 {
				end = len(a.longNames) - off
			}
			name = strings.TrimSuffix(string(a.longNames[off:off+end]), "/")
		default:
			name = strings.TrimSuffix(name, "/") // GNU short name terminator
		}
		if name == "" {
			name = "member"
		}
		return &arHeader{Name: name, Size: a.remaining}, nil
	}
}

// Read reads from the current member.
func (a *arReader) Read(p []byte) (int, error) {
	if a.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > a.remaining {
		p = p[:a.remaining]
	}
	n, err := a.r.Read(p)
	a.remaining -= int64(n)
	if err == io.EOF && a.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (a *arReader) skipRest() error {
	if a.remaining > 0 {
		if _, err := io.CopyN(io.Discard, a.r, a.remaining); err != nil {
			return fmt.Errorf("ar: truncated member")
		}
		a.remaining = 0
	}
	if a.pad {
		a.pad = false
		if _, err := a.r.ReadByte(); err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}
