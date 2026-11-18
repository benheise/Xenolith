# Changelog

Notable changes to the census: new watchlist components, incident passes, new sources and
site features. Daily data refreshes aren't listed; `git log` has the full history.

## 2026-11-18: JetBrains and Oracle notices, and a browser fetch for client-side pages

- **JetBrains.** The third-party software page on jetbrains.com is drawn in the browser
  from JetBrains' product release API, where each release links a
  `third-party-libraries.json` (name, version and license for every library). A new
  discovery rule (`type: jetbrains`) reads it directly: TeamCity (2026.2.2, 2026.1.6,
  2025.11.8), YouTrack, Hub, IDE Services and Datalore Enterprise (two release lines each),
  IntelliJ IDEA (two) and PyCharm, WebStorm, GoLand, PhpStorm, Rider, CLion, RubyMine,
  DataGrip, RustRover, Toolbox App and Gateway (the latest each): 24 lists of 118 to 2,022
  libraries. JetBrains Runtime, the OpenJDK build inside the IDEs (listed as version 21),
  now counts as `openjdk` for Java4Shell.
- **Oracle.** Each Fusion Middleware 14.1.2 product has its own Licensing Information User
  Manual with a component and version table; a discovery rule on the 14.1.2 chapter of the
  FMW licensing manual picks up all 23 of them (WebLogic Server, HTTP Server with curl
  8.10.0 and OpenSSL 3.0.15, SOA Suite, WebCenter, Data Integrator and the rest). The
  WebLogic 15.1.1 and 26.1 manuals name components without versions and are left out.
- **BMC Helix Operations Management 25.1** added: its third-party page is plain HTML (2,357
  components), not client-side as noted before.
- **Browser fetch (`render: true`).** Documents and discovery rules can ask to be loaded
  in headless Chromium when their HTML is an empty shell. The plain fetch always comes
  first and decides; HTTP errors, login forms and bot challenges are never rendered. No
  catalog entry needs it yet: every page tried turned out to have a data source or to be
  gone, so the refresh workflow installs no browser.
- **Checked and not crawlable.** SolarWinds Kiwi Syslog Server and Kiwi CatTools: the
  pages were withdrawn ("request an SBOM"), also in a browser. ManageEngine OpManager:
  the third-party library page answers HTTP 404 (as do the OpUtils, NetFlow Analyzer and
  NCM copies). Microsoft's third-party archive moved to opensource.microsoft.com/3pc,
  backed by a JSON search API, but has nothing for Exchange or SharePoint.
- **Corrections for vendor lists.** A new `corrections:` section in `catalog/notices.yaml`
  sets aside entries in a vendor's list that are known to be wrong, with a reason and
  evidence. They stay in the stored inventory as published, and the statement says what
  wasn't counted and links the evidence. First use: YouTrack's and Hub's lists carry an old
  block that includes Log4j 2.10.0 (the pre-Log4Shell version, attributed to slf4j.org),
  although JetBrains has shipped Log4j 2.17 or later in both since December 2021; the
  products no longer show Log4j in the Log4Shell range.
- **Fixes.** "Log4j 1.7.36" (SLF4J's log4j-over-slf4j bridge, as JetBrains lists it) and
  "log4j 1.2-api" (Log4j 2's bridge) no longer count as Log4j 1. License names are no
  longer read as components from license texts. Re-matching offline
  (`notices --match-only`) keeps the discovery paths an online run recorded instead of
  re-inferring them.

## 2026-11-18: xenolith-scan recognises bundled Java runtimes

- **Fingerprint.** The shared fingerprint pack (`catalog/fingerprints.yaml`, used by
  `xenolith-scan` and `python -m xenolith fingerprint`) now finds the HotSpot Java runtime
  a product bundles by the build string in `libjvm.so` / `jvm.dll` and reports it as
  `openjdk` with the full Java version, linked to the Java4Shell watchlist entry. Syft's
  reading of the runtime's `release` file merges into the same component.
- **Checked on real builds:** Temurin 17.0.15+6 (Linux) and 21.0.7+6 (Windows), SapMachine
  21.0.7, Liberica 17.0.15+10 and Ubuntu's openjdk-21. IBM Semeru (OpenJ9, not HotSpot) is
  reported separately as `eclipse openj9` instead of being counted as affected.
- **Evaluation corpus:** added the Temurin 17.0.15+6 JRE, and Elasticsearch 8.15.0's
  bundled JDK (22.0.1+8-16) is now part of its ground truth; both are found at the right
  version.

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
- **Products from Calif's disclosure** ([calif.io/java4shell](https://calif.io/java4shell), 2026-11-17):
  Calif demonstrated code execution without logging in on Keycloak, Jira, Confluence, Artifactory,
  Jenkins and PingFederate, and by a logged-in user on Apache Kafka, Solr, Elasticsearch, Gerrit
  and Spinnaker, all on affected Java builds. Products that bundle their own Java (Jira and
  Confluence Data Center, Artifactory, Elasticsearch, Keycloak images, Spinnaker images) are
  recorded as affected; those that run on the Java the customer installs (Jenkins, PingFederate,
  Kafka, Solr, Gerrit) as runtime-dependent: patch the host's Java.
- **SAP.** No SAP statement yet. SAP's own knowledge base shows SapMachine 17 bundled in HANA
  XS Advanced (17.0.15 in its example, which is in range; HANA Cockpit runs on XSA) and
  SapMachine 21 as the runtime of SAP Commerce Cloud 2211-jdk21.x (hosted by SAP). Both are
  recorded as "present".
- **CSAF.** With the CVE on the watchlist, the refresh run straight after this pass picked up
  Red Hat's VEX data: 30 Red Hat products, 21 affected with only a workaround so far (RHEL 8–10,
  Red Hat build of OpenJDK 17/21/25, JBoss EAP 7 and 8, JBoss Web Server, Data Grid, AMQ Broker,
  streams for Apache Kafka, Red Hat build of Keycloak and others) and 9 not affected (OpenJDK 8
  and 11 builds, RHEL 6 and 7, Fuse 7, Single Sign-On 7 and others). Other CSAF providers'
  advisories arrive on daily refreshes as they publish. With Calif's list, the census
  holds 152 Java4Shell statements about 105 products.
- **Still open.** As of 2026-11-18 there is no community vendor-status tracker for Java4Shell,
  and Atlassian, Jenkins/CloudBees, JFrog, Ping Identity, Confluent, Elastic, Gerrit and
  Spinnaker hadn't published product guidance. Products that run on the host's Java (Jenkins
  packages, Kafka, Solr, Gerrit) depend on the host being updated.
