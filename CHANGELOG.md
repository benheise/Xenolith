# Changelog

Notable changes to the census: new watchlist components, incident passes, new sources and
site features. Daily data refreshes aren't listed; `git log` has the full history.

## 2026-11-18: Java4Shell pass (CVE-2026-114938)

Java4Shell is a heap overflow in the HotSpot JVM's AVX-512 Base64 decoder, fixed on
2026-11-17 by the [OpenJDK Vulnerability Group](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
and [Oracle's November 2026 Critical Security Patch Update](https://www.oracle.com/security-alerts/cspunov2026.html).
It affects Java 17.0.6 and later 17 updates, 21, 25 and 27 (and the end-of-life 18–20, 22–24 and 26)
on x86-64 CPUs with AVX-512 VBMI. Java 8 and 11 aren't affected. Many products bundle their own
Java runtime, so customers can't fix them by updating the host's Java.

- **Watchlist.** Added `openjdk` (OpenJDK / HotSpot Java runtime) with the affected ranges
  17.0.6 to 17.0.21.1, 18 to 21.0.13.1, 22 to 25.0.5.1 and 26 to 27.0.1.1 (fixed versions
  excluded). It matches OpenJDK, Temurin, Corretto, Zulu, Liberica, SapMachine, Microsoft,
  Red Hat, GraalVM and Oracle/Sun JRE and JDK names in notices and SBOMs, and leaves out Java
  libraries that only have "jdk" in their names. IBM Semeru (OpenJ9, a different JVM) isn't matched.
- **Java version strings.** Build and packaging suffixes (`17.0.15+6`, `17.0.15_p6`,
  `21.0.7+6~us1`) are dropped before the range check, and a version written into the component
  name (`SapMachine sapmachine-17.0.17`) is used when the version column is empty.
- **Stored notices, re-matched.** All 302 inventories: 26 products from 11 vendors list a Java
  runtime. Eleven product versions list one in the Java4Shell range:
  Commvault Backup & Recovery 11.42, 2024E and 2023E; Elastic Stack 8.19.24, 8.19.25, 9.4.9
  and 9.5.6; NetApp Active IQ Unified Manager 9.18, 9.18P1 and 9.18P2; NetApp ONTAP tools for
  VMware vSphere 9.13P2. F5 BIG-IP, Ivanti Connect Secure, NetApp SnapCenter and WatchGuard
  Fireware OS list Java without a version. The rest list Java 8 or 11.
- **Vendor statements** (`community/assertions.csv`): Barracuda Networks lists 35 products as
  under investigation (2026-11-17); Keycloak says its 26.8.2 server images (OpenJDK 21.0.13)
  and Operator image (OpenJDK 25) are affected, with a JVM flag as the only workaround so far
  (2026-11-18).
- **SAP.** No SAP statement yet. SAP's own knowledge base shows SapMachine 17 bundled in HANA
  XS Advanced (17.0.15 in its example, which is in range; HANA Cockpit runs on XSA) and
  SapMachine 21 as the runtime of SAP Commerce Cloud 2211-jdk21.x (hosted by SAP). Both are
  recorded as "present".
- **CSAF.** With the CVE on the watchlist, the next refresh picks up Red Hat's VEX data and
  other CSAF providers' advisories as they publish.
- **Still open.** As of 2026-11-18 there is no community vendor-status tracker for Java4Shell,
  and Atlassian, Jenkins/CloudBees, JFrog, Ping Identity, Confluent, Elastic, Gerrit and
  Spinnaker hadn't published product guidance. Products that run on the host's Java (Jenkins
  packages, Kafka, Solr, Gerrit) depend on the host being updated.
