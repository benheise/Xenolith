package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestValidSourceURL(t *testing.T) {
	for _, ok := range []string{"https://download.example.com/fw-7.2.9.bin", "https://github.com/acme/fw/releases/tag/v7.2.9"} {
		if err := validSourceURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/a.bin", "ftp://example.com/a.bin", "example.com/a.bin", "https://", "file:///tmp/a.bin"} {
		if validSourceURL(bad) == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestAskSourceURL(t *testing.T) {
	cases := []struct{ input, want string }{
		{"https://example.com/fw.bin\n", "https://example.com/fw.bin"},
		{"\n", ""}, // Enter skips
		{"", ""},   // end of input skips
		{"example.com/fw.bin\nhttps://example.com/r/\n", "https://example.com/r/"}, // re-asked after a bad answer
		{"no\nnope\nnever\nhttps://late.example/\n", ""},                           // gives up after three tries
		{"  https://example.com/x.msi  \n", "https://example.com/x.msi"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		got := askSourceURL(bufio.NewReader(strings.NewReader(c.input)), &out, "fw.bin")
		if got != c.want {
			t.Errorf("input %q: got %q, want %q", c.input, got, c.want)
		}
		if !strings.Contains(out.String(), "Where can others download fw.bin?") {
			t.Errorf("prompt missing: %q", out.String())
		}
	}
}
