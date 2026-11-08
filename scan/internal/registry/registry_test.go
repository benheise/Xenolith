package registry

import "testing"

func TestFind(t *testing.T) {
	if len(Load()) < 1000 {
		t.Fatalf("registry snapshot too small: %d", len(Load()))
	}
	m := Find("Citrix", "NetScaler ADC", 3)
	if len(m) == 0 || m[0].Key != "citrix/netscaler-adc" || m[0].Score < 0.95 {
		t.Fatalf("exact match should win: %+v", m)
	}
	m = Find("", "AcmeOS", 3)
	for _, x := range m {
		if x.Score >= 0.6 {
			t.Errorf("'AcmeOS' must not strongly match %s (%s): %.2f", x.Key, x.Name, x.Score)
		}
	}
	m = Find("Fortinet", "FortiOS", 1)
	if len(m) == 0 || m[0].Key != "fortinet/fortios" {
		t.Fatalf("FortiOS: %+v", m)
	}
	if Slug("Acme Networks, Inc.") != "acme-networks-inc" {
		t.Fatal(Slug("Acme Networks, Inc."))
	}
}
