"""Java runtime watchlist entry (Java4Shell, CVE-2026-114938): name matching,
Java version strings and versions written into component names."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xenolith import catalog  # noqa: E402
from xenolith.sources.notices import version_in_name  # noqa: E402
from xenolith.versions import check, java_version  # noqa: E402

CAT = catalog.load()
JDK = CAT.components["openjdk"]


def status(version: str) -> str:
    return check([version], JDK.affected, JDK.version_style)["status"]


class JavaRuntimeNamesTest(unittest.TestCase):
    def test_runtimes_match(self):
        for name in ["OpenJDK", "openjdk-17", "openjdk17", "openjdk-15-jre-headless", "java-17-openjdk-headless",
                     "openjdk-zulu", "OpenJDK/Java", "Eclipse Temurin JRE", "adoptium/temurin17-binariesjdk",
                     "corretto/corretto-8", "bell-sw/liberica", "SapMachine sapmachine-17.0.17",
                     "Bundled Oracle Java JRE", "Oracle Java SE Development Kit", "Java Runtime", "JRE", "jdk8u",
                     "Java Platform Standard Edition (JRE) (J2RE)", "Zulu builds of OpenJDK for Windows",
                     "Microsoft Build of OpenJDK", "GraalVM for JDK 21"]:
            self.assertEqual(CAT.match_component(name, ""), "openjdk", name)

    def test_libraries_and_parts_do_not(self):
        for name in ["OpenJDK ORB", "OpenJDK Nashorn", "openjdk-14-source", "openjdk-cacerts", "java-13-openjdk-jmods",
                     "kotlin-stdlib-jdk8", "bcprov-jdk18on", "jackson-datatype-jdk8", "WildFly: IIOP Openjdk Subsystem",
                     "nb-javac jdk-17.0.1-ga", "Java Servlet API", "openjdk17-loongarch", "jdk-wf", "IBM Semeru Runtime"]:
            self.assertIsNone(CAT.match_component(name, ""), name)


class JavaVersionTest(unittest.TestCase):
    def test_suffixes_dropped(self):
        self.assertEqual(java_version("17.0.15+6"), "17.0.15")
        self.assertEqual(java_version("17.0.15_p6"), "17.0.15")
        self.assertEqual(java_version("21.0.7+6~us1"), "21.0.7")
        self.assertEqual(java_version("17.0.18+1-ea-beta"), "17.0.18")
        self.assertEqual(java_version("jdk-17.0.2"), "17.0.2")
        self.assertEqual(java_version("1.8.0_402"), "1.8.0_402")

    def test_java4shell_ranges(self):
        for v in ["17.0.6", "17.0.15+6", "17.0.21+9", "17.0.21.0.3", "18.0.2", "21.0.7+6~us1", "25.0.5+8",
                  "26.0.1", "27.0.1.0.3", "17.0.15_p6"]:
            self.assertEqual(status(v), "in_range", v)
        for v in ["17.0.5", "17.0.2", "17.0.21.1", "17.0.21.1.2", "21.0.13.1", "25.0.5.1", "27.0.1.1",
                  "11.0.16.1+1", "1.8.0_402", "8u452+11", "13~24"]:
            self.assertEqual(status(v), "outside", v)


class VersionInNameTest(unittest.TestCase):
    def test_takes_last_dotted_version(self):
        self.assertEqual(version_in_name("SapMachine sapmachine-17.0.17"), "17.0.17")
        self.assertEqual(version_in_name("Apache Log4j 2"), "")
        self.assertEqual(version_in_name(""), "")


if __name__ == "__main__":
    unittest.main()
