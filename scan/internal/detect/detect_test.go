package detect

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestSyftUnresolvedVersions(t *testing.T) {
	declared := pkg.Package{Name: "activemq-broker", Version: "UNKNOWN", PURL: "pkg:maven/org.apache.activemq/activemq-broker@UNKNOWN", FoundBy: "java-pom-cataloger"}
	c := fromSyft(declared, "", nil)
	if c.Version != "" || c.PURL != "pkg:maven/org.apache.activemq/activemq-broker" || c.Confidence >= 0.7 {
		t.Errorf("declared, unresolved: %+v", c)
	}
	prop := pkg.Package{Name: "netty-codec", Version: "${netty.version}", FoundBy: "java-pom-cataloger"}
	if c := fromSyft(prop, "", nil); c.Version != "" || c.Confidence >= 0.7 {
		t.Errorf("property placeholder: %+v", c)
	}
	// a PE binary without version resources is presence only: a lead below the line
	pe := pkg.Package{Name: "snappyjava", Version: "UNKNOWN", FoundBy: "pe-binary-package-cataloger"}
	if c := fromSyft(pe, "", nil); c.Version != "" || c.Confidence >= 0.7 || len(c.Notes) != 1 {
		t.Errorf("pe binary: %+v", c)
	}
	versioned := pkg.Package{Name: "GLib", Version: "2.80.0", FoundBy: "pe-binary-package-cataloger"}
	if c := fromSyft(versioned, "", nil); c.Confidence != 0.9 {
		t.Errorf("versioned pe binary: %+v", c)
	}
	// a declared dependency with a concrete version keeps the manifest confidence
	pinned := pkg.Package{Name: "log4j-core", Version: "2.13.3", FoundBy: "java-pom-cataloger"}
	if c := fromSyft(pinned, "", nil); c.Version != "2.13.3" || c.Confidence != 0.7 {
		t.Errorf("pinned: %+v", c)
	}
}

func TestDeclaredByLibrary(t *testing.T) {
	inJar := file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/BOOT-INF/lib/log4j-core-2.17.1.jar"})
	inJar.AccessPath = "/BOOT-INF/lib/log4j-core-2.17.1.jar:META-INF/maven/org.apache.logging.log4j/log4j-core/pom.xml"
	dep := pkg.Package{Name: "jmdns", Version: "3.5.7", FoundBy: "java-pom-cataloger", Locations: file.NewLocationSet(inJar)}
	if !declaredByLibrary(dep) {
		t.Error("a dependency declared in a bundled library's pom.xml should be ignored")
	}
	top := pkg.Package{Name: "log4j-core", Version: "2.17.1", FoundBy: "java-pom-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/src/pom.xml"))}
	if declaredByLibrary(top) {
		t.Error("a project pom.xml is a declaration worth keeping (at manifest confidence)")
	}
	jarItself := pkg.Package{Name: "log4j-core", Version: "2.17.1", FoundBy: "java-archive-cataloger", Locations: file.NewLocationSet(inJar)}
	if declaredByLibrary(jarItself) {
		t.Error("the archive cataloger's own finding must stay")
	}
}

func TestKernelModulesWithoutVersion(t *testing.T) {
	ko := pkg.Package{Name: "e1000e", Type: pkg.LinuxKernelModulePkg, FoundBy: "linux-kernel-cataloger",
		Metadata: pkg.LinuxKernelModule{Name: "e1000e", KernelVersion: "5.15.167"}}
	c := fromSyft(ko, "", nil)
	if c.Confidence >= 0.7 || len(c.Notes) != 1 {
		t.Errorf("unversioned in-tree module should be a lead: %+v", c)
	}
	ko.Version = "3.2.6-k"
	if c := fromSyft(ko, "", nil); c.Confidence < 0.7 {
		t.Errorf("a module with its own version stays: %+v", c)
	}
}

func TestJarNamedFromFile(t *testing.T) {
	jar := pkg.Package{Name: "context-slf4j", Version: "5.13.2", PURL: "pkg:maven/io.zipkin.brave/context-slf4j@5.13.2",
		FoundBy: "java-archive-cataloger", Metadata: pkg.JavaArchive{},
		Locations: file.NewLocationSet(file.NewLocation("/BOOT-INF/lib/brave-context-slf4j-5.13.2.jar"))}
	if c := fromSyft(jar, "", nil); c.Name != "brave-context-slf4j" || c.PURL != "pkg:maven/io.zipkin.brave/brave-context-slf4j@5.13.2" {
		t.Errorf("name from the Maven file name: %+v", c)
	}
	nested := file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/input/zipkin-server-2.23.16-exec.jar"})
	nested.AccessPath = "/input/zipkin-server-2.23.16-exec.jar:BOOT-INF/lib/brave-context-slf4j-5.13.2.jar"
	jar.Locations = file.NewLocationSet(nested)
	if c := fromSyft(jar, "", nil); c.Name != "brave-context-slf4j" {
		t.Errorf("name from a nested jar's file name: %+v", c)
	}
	other := pkg.Package{Name: "netty-common", Version: "4.1.70.Final", FoundBy: "java-archive-cataloger", Metadata: pkg.JavaArchive{},
		Locations: file.NewLocationSet(file.NewLocation("/lib/netty-common-4.1.70.Final.jar"))}
	if c := fromSyft(other, "", nil); c.Name != "netty-common" {
		t.Errorf("unchanged when the file name agrees: %+v", c)
	}
}

func TestPENamesAndVersions(t *testing.T) {
	for in, want := range map[string]string{
		"The c-ares library":                          "c-ares",
		"XZ Utils <https://tukaani.org/xz/>":          "XZ Utils",
		"NGHTTP2.":                                    "NGHTTP2",
		"GNU libintl: accessing NLS message catalogs": "GNU libintl",
		"Qt6":                          "Qt6",
		"Microsoft® C Runtime Library": "Microsoft® C Runtime",
	} {
		if got := peName(in); got != want {
			t.Errorf("peName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"1, 0, 0, 0": "1.0.0", "6.7.3.0": "6.7.3", "4.4.19": "4.4.19", "10.0.28000.1839": "10.0.28000.1839"} {
		if got := peVersion(in); got != want {
			t.Errorf("peVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFoldBinaryIntoFingerprint(t *testing.T) {
	loc := "Wireshark.msi!/Wireshark/zlib-ng2.dll"
	merged := merge([]Component{
		{Name: "zlib", Version: "2.1.5", Confidence: 0.9, FoundBy: []string{"syft:pe-binary-package-cataloger"}, Locations: []string{loc}},
		{Name: "zlib-ng", Version: "2.1.5", Confidence: 0.9, FoundBy: []string{"xenolith-fingerprint"}, Locations: []string{loc}},
		{Name: "zlib", Version: "1.3.1", Confidence: 0.9, FoundBy: []string{"xenolith-fingerprint"}, Locations: []string{"Wireshark.msi!/Wireshark/zlib1.dll"}},
	})
	if len(merged) != 2 {
		t.Fatalf("want zlib-ng 2.1.5 and zlib 1.3.1, got %+v", merged)
	}
	for _, c := range merged {
		if c.Name == "zlib" && c.Version == "2.1.5" {
			t.Errorf("the version resource's name survived: %+v", c)
		}
		if c.Name == "zlib-ng" && len(c.FoundBy) != 2 {
			t.Errorf("found_by not merged: %+v", c)
		}
	}
}
