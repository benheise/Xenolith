package watchlist

import "testing"

func TestMatch(t *testing.T) {
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ group, name, version, want string }{
		{"org.jenkins-ci.main", "jenkins-core", "2.580.2", "jenkins"},
		{"org.apache.shiro", "shiro-core", "1.13.0", "shiro"},
		{"", "struts", "1.3.10", "struts1"},
		{"", "struts", "6.4.0", "struts2"},
		{"com.thoughtworks.xstream", "xstream", "1.4.21", "xstream"},
		{"", "Grafana", "13.4.0", "grafana"},
		{"org.tukaani", "xz", "1.9", ""},   // XZ for Java is not XZ Utils
		{"", "curl", "0.4.44", ""},         // the Rust crate, ruled out by its version
		{"", "curl", "8.5.0", "curl"},
		{"", "left-pad", "1.3.0", ""},
	}
	for _, c := range cases {
		if got := Match(c.group, c.name, c.version); got != c.want {
			t.Errorf("Match(%q, %q, %q) = %q, want %q", c.group, c.name, c.version, got, c.want)
		}
	}
}
