# Changelog

Notable changes to the census: new watchlist components, incident passes, new sources and
site features. Daily data refreshes aren't listed; `git log` has the full history.

## 2026-11-20: Java4Shell recheck

Evening recheck of vendors still pending on Java4Shell (CVE-2026-114938). 9 new statements and
6 updated rows (320 Java4Shell statements in all), each read on the vendor's own page.

- **Status changes:**
  - Cisco (advisory v1.3, 20 November): Catalyst Center moved from affected to not affected.
    NextFusion Platform, listed as affected in v1.2, is gone from v1.3 with no note in the revision
    history; its row is now `unknown`. Secure Network Analytics now has patches planned for 7.6.1,
    7.6.0 and 7.5.3 (date not set). Every other fixed release is still TBD.
  - Splunk (SVD-2026-1102, 20 November): AppDynamics On-Premises Events Service, EUM Server and
    Enterprise Console moved from affected to workaround (-XX:-UseBASE64Intrinsics).
- **New products from vendors already tracked:**
  - Cisco v1.3 adds Crosswork Hierarchical Controller, Optical Networking Controller, HyperFlex HX
    Data Platform and Unified Contact Center Enterprise Cloud Connect (fix planned in 15.0(1)SU3).
  - Splunk adds Splunk Attack Analyzer as affected, no fix named.
- **New vendor:** JetBrains (two posts of 20 November). YouTrack Server fixed in 2026.2.19884,
  2026.1.14193 and 2025.3.178461 with a patched bundled Java; TeamCity's 2026.1.6 and 2026.2.2
  Docker images republished with a patched Java, other installs need their Java updated;
  TeamCity Cloud and YouTrack Cloud not affected.
- **No change:** PaperCut (26.0.7 still planned for the week of 23 November; no 25.x fix date),
  Keycloak (Operator image still on the workaround), Barracuda (last updated 18 November),
  Atlassian (patches still wait on Temurin), Elastic (8.19.26, 9.4.10, 9.5.7 and 9.6.0 not
  released yet), Jenkins, Tenable, Fortinet, Eclipse Temurin.
- Exploitation unchanged: probing and exploit attempts, no confirmed compromise, not in CISA KEV.
- **Not added:** ManageEngine's community post gives Java patch IDs for Endpoint Central users,
  not a status for any ManageEngine product. Esri's ArcGIS post still refuses automated access
  (HTTP 403). Sophos' advisory timed out; the copy read through another fetcher was v3, older than
  the v5 already in the census, so its rows are unchanged.
- Still silent: Ping Identity, JFrog (product statement), CloudBees, Broadcom (VMware Tanzu,
  Symantec), IBM (no Semeru or WebSphere bulletin), Oracle's own products, SAP, SapMachine,
  JetBrains Runtime and the IDEs.

## 2026-11-21: EPSS scores and a card for every watchlist CVE

- **EPSS:** `python -m xenolith epss` fetches FIRST.org's EPSS score and percentile for every
  watchlist CVE on each refresh, and caches the CVSS score, publication date and description from
  the CVE record (`data/spine/epss.json`, `data/spine/cve_details.json`).
- **CVE card:** every CVE on the site now opens a score card (`#v=CVE-...`): EPSS probability
  and percentile, CVSS, CISA KEV status and date, ransomware use, whether a product has been named
  in attacks, the component, and how many products have a vendor statement. Searching a CVE ID
  offers its card.
- **When EPSS and KEV disagree** the card says so: 98 of the 392 KEV-listed watchlist CVEs score
  under 10% on EPSS, six of them under 1%. EPSS is a forecast; KEV is evidence.
- Threat cards show the highest EPSS score among their CVEs.

## 2026-11-20: Threats tab

The site now opens on a **Threats** tab: the five watchlist flaws with the newest sign of
exploitation, newest first, with ten more behind a button. The census moved to `#census`.

- A sign is a CISA KEV listing, a statement marked exploited or attempted, or a demonstrated
  exploit. An item is dated by its newest sign, so an old flaw newly added to KEV rises again.
- Each card shows the level, CVEs, KEV date and ransomware flag, the incident note, the products
  named in attacks, and how many products have a vendor statement or no stated fix.
- Incidents that only list KEV entries appear as one item per CVE, titled with KEV's name.
- Below the list: this year's watchlist flaws with no exploitation report yet.
- The feed is built into `docs/data/meta.json` (`threats`, `watching`) on every refresh.

## 2026-11-20: KEV gap list closed

Every KEV entry that fits the watchlist rules is now tracked: 392 of 1,790 KEV CVEs (21.9%),
up from 168. The watchlist has 91 components and 446 CVEs. What is left untracked is outside
the rules, listed at the end.

- **Tracked components brought up to date** with ranges from the CVE records: Struts (4 more),
  Tomcat (2), httpd (2), ActiveMQ, PHP (2), ImageMagick (2), Ghostscript, FreeType. New
  components `struts1`, `spring-cloud-function`, `spring-cloud-config`, `spring-data-commons`.
- **The 108 engine CVEs added earlier now have statements.** 97 vendor advisories opened and
  named their CVE; 129 statements and the exploitation flags come from them. 11 could not be
  read (old Fortinet and Cisco pages that returned errors or moved) and keep only their KEV row.
- **Chromium** (71 CVEs, ranges from the Chrome CVE records) for products that list Chromium or
  Chrome in their notices. Electron and CEF are not matched: their version numbers are their own.
- **Third-party components found in at least two stored inventories:** Elasticsearch, Kibana,
  BIND, InetUtils, Shiro, JBoss Seam, UnRAR, Starlette, Rails, Git, Jenkins core, ExifTool,
  Telerik UI, Spark, Flink, PHPUnit, PHPMailer, MinIO, Grafana, and 13 old Java SE flaws under
  `openjdk`. Where a CVE record has no usable version data the incident is marked `unranged`
  (new flag) instead of guessing.
- **More vendor engines:** `webkit` (24), `gecko` (13), `ivanti-connect-secure` (16), `junos` (7),
  `cisco-ios-xr` (6), `zyxel-zld` (6), `manageengine` (6), `check-point-gaia` (5),
  `vmware-workspace-one` (4), `cleo-file-transfer` (2), `wso2-carbon` (2). 73 of their 91
  advisories were read, giving 125 statements; 18 could not be read (Cleo and WSO2 refused
  automated access; several Pulse Secure and ManageEngine pages have moved).
- **Statements generated from advisories** carry a short factual note (the KEV name of the flaw,
  its KEV date, whether the vendor reports exploitation) and the versions from the vendor's CVE
  record. They were machine-read, with the exploitation sentences checked by hand.
- **Criteria:** "commonly bundled" is now measured as presence in at least two stored inventories.

**Still untracked, by rule (1,398 entries):** single-vendor products and applications (Windows,
Office, Exchange, routers, CMSs); Apple OS components other than WebKit, which KEV does not
name; the Linux kernel, Bash, polkit and chipset code, where a version check means nothing;
open-source servers no stored inventory lists (Roundcube, Exim, Drupal, OFBiz and others);
OpenSSH CVE-2026-123158 (musl-only). SonicWall SonicOS and SMA are single product lines.

## 2026-11-20: More engines, embedded products and a KEV coverage report

**New engines (52 to 56 components), 29 statements read on the vendors' advisories:**

- `cisco-ios-xe` (IOS and IOS XE): the 2023 web UI takeover (CVE-2023-20198, CVE-2023-20273) and
  the SNMP overflow CVE-2025-20352.
- `cisco-sdwan` (Controller, Manager, Validator): peering authentication bypasses CVE-2026-20127
  and CVE-2026-20182.
- `cisco-asyncos` (Secure Email Gateway, Secure Email and Web Manager): CVE-2025-20393.
- `vcenter` (vCenter, Cloud Foundation, vSphere Foundation, Telco Cloud): CVE-2026-123890,
  CVE-2026-59310, CVE-2024-37079.
- Left out: SonicWall SonicOS and SMA1000 (one product each, no shared engine).

**Products exploited through an embedded component**, each from a source that names the product:

- PAN-OS through PHP (PHP2Shell): Palo Alto Networks reports active exploitation of exposed
  management interfaces.
- VMware Cloud Foundation (NSX-V) through XStream: VMware reports exploitation in the wild.
- VMware Horizon through Log4j (Sophos).
- Google Chrome through libvpx (Google) and libwebp (CERT-EU relaying Google).
- Not marked: Next.js for React2Shell and any product for the Brotli flaw. No source opened
  names a product that was compromised.

**KEV depth for the engines:** each first-party engine gains an "Earlier exploited flaws (CISA
KEV)" incident with the 108 other KEV entries CISA files under that product family. They are
findable by CVE and carry the KEV badge; no vendor statements have been read for them yet.

**KEV coverage report:** `python -m xenolith kev --coverage` prints how much of the catalog the
census covers. On 20 November (1,790 entries): 168 CVEs on the watchlist (9.4%), 748 of 751
KEV products in the registry (99.6%), 85 with composition data (11.3%).

## 2026-11-20: First-party engines and an exploitation review

**Criteria.** The watchlist now also takes a vendor's own engine that it ships across several
product lines and reports on product by product (CONTRIBUTING.md, "What belongs on the
watchlist"). These entries have no notices patterns and need no version ranges.

**New components (48 to 52), 60 statements, each read on the vendor's advisory:**

- `netscaler` (NetScaler ADC and Gateway): CVE-2026-3055, CVE-2026-8452, CVE-2026-19490,
  CVE-2026-88771, CVE-2026-88772, CVE-2026-88779. Citrix reports exploits of 88771 and 88772.
- `fortios` (FortiOS code in FortiProxy, FortiSwitchManager, FortiWeb, FortiManager,
  FortiAnalyzer, FortiNAC-F): the FortiCloud SSO login bypasses CVE-2025-59718 and
  CVE-2026-24858, and the CAPWAP daemon overflow CVE-2025-25249.
- `pan-os` (firewalls, Panorama, Prisma Access, Cloud NGFW): CVE-2026-0300, CVE-2026-0257,
  CVE-2026-0322.
- `cisco-asa` (ASA Software and the ASA code in FTD): CVE-2025-20333, CVE-2025-20362,
  CVE-2026-20349, CVE-2026-76418.
- `f5-tmm` gains CVE-2026-94127 (BIG-IP APM OAuth), which F5 says has been exploited.

**Exploitation review of the whole census:**

- New `python -m xenolith kev` step checks every watchlist CVE against CISA KEV on each refresh.
  51 of 105 tracked CVEs are listed, across 26 of 52 components. Each incident now shows it on
  the component page and card. KEV names the component, not the products embedding it, so this
  is separate from the product-level signal.
- Products marked `exploited`, each from a source that names the product: NetScaler ADC and
  Gateway, PAN-OS, Cisco ASA and FTD, BIG-IP APM, and for Apache Axis 1.x Confluence Data Center
  and N-able N-central (Rapid7). PAN-OS also carries an `attempted` report for CVE-2026-0257.
- Not marked: Fortinet products (Fortinet and CISA report exploitation without naming the
  product) and every product embedding a third-party component whose KEV entry names only the
  component (Log4j, Struts, Tomcat and the rest).
- Looked at and left out: Ivanti Connect Secure (exploited, but one product, no shared engine),
  Check Point Gaia (the exploited flaws are in different products), F5 CVE-2025-53521 (apmd, not
  TMM), Fortinet CVE-2025-61624 (needs a privileged user).

## 2026-11-20: F5 TMM (BIG-IP data plane)

New component `f5-tmm` (48 on the watchlist) for the six critical TMM stack overflows in F5's
out-of-band notification of 18 November: CVE-2026-116953, CVE-2026-120285, CVE-2026-120292,
CVE-2026-120722, CVE-2026-121805 and CVE-2026-123637. 15 statements, each read on F5's advisory.

- **Affected, hotfix only:** BIG-IP (all modules), BIG-IP APM, BIG-IP DNS, BIG-IP PEM on 21.1.0,
  17.5.0 to 17.5.1 and 17.1.0 to 17.1.3; BIG-IP Next for Kubernetes and BIG-IP CNF 2.2.0 to 2.4.2.
- **Not affected:** BIG-IQ, F5 Insight, F5OS, F5OS-A, F5OS-C, F5 AI Gateway, F5 Distributed Cloud,
  NGINX One Console and the NGINX products.
- Each flaw needs a specific iRule command or APM policy on a virtual server; the incident note
  lists them. No exploitation reported; not in CISA KEV.
- TMM is F5's own engine, not a library other vendors bundle, so it sits outside the written
  watchlist criteria and has no notices patterns; its ranges are BIG-IP release numbers. It is here because F5 ships
  it across several product lines and states a status for each.

## 2026-11-20: Exploitation signal

Statements can now say whether a product is being exploited, apart from its status.

- **New `exploitation` column** in `community/assertions.csv`: `exploited`, `attempted`,
  `demonstrated_preauth`, `demonstrated_postauth`. The bar for each level is in CONTRIBUTING.md.
  Files with the old ten-column header still load.
- **Site:** a product with a report shows a badge on every statement and on its product card,
  sorts first on the component page, and each level has its own filter and count.
- **Java4Shell (CVE-2026-114938) as of 20 November:** no product is confirmed exploited and no
  observed attempt is tied to a product (the GreyNoise, watchTowr, Cloudflare and Previdian
  reports are sensor hits). Marked from Calif's write-up: exploit shown with no login needed for
  Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate; login needed for Kafka,
  Solr, Elasticsearch, Gerrit and Spinnaker.

## 2026-11-20: Java4Shell research pass

Fresh read of every Java4Shell (CVE-2026-114938) source, plus new vendor pages. 34 new statements
and 8 updated rows (311 Java4Shell statements in all). Still not in CISA KEV; no confirmed
compromise.

- **Status changes:**
  - Citrix (CTX697367, modified 20 November): Linux VDA, Analytics, XenMobile Server, App Layering
    and UniconOS Management moved from under investigation to impacted, fixed builds to be named.
    Cloudpaging Server is now listed as not impacted, where the 19 November reading had 9.9 and
    later needing a JRE update. Secure Access is still under investigation.
  - Ubuntu: the CRaC builds on 26.04 and 26.10 are fixed.
- **New products from vendors already tracked:**
  - Sophos (advisory v5): Mobile EAS Proxy 9.8.3 and earlier bundle an affected runtime, fixed in
    9.8.4; Phish Threat fixed; Endpoint Protection and Home for Windows have no Java.
  - Splunk (SVD-2026-1102): ten AppDynamics on-premises products and agents confirmed affected,
    fixes in development; DB Connect, ITSI and the AppDynamics Java Agent depend on the Java you
    install; Apps & Add-ons, On-Call and AppDynamics SaaS unaffected.
- **New vendors:**
  - Palo Alto Networks: four Idira (privileged access) products fixed in named releases; PAN-OS,
    Panorama, WF-500-B and the PAN-DB private cloud appliance not impacted.
  - Tenable: Enclave Security and Tenable OT affected, patches pending; Security Center and
    Nessus do not include Java.
  - Mimecast: assessment continues, no customer action.
  - TuxCare: OpenJDK 17 builds fixed.
- **No change:** Cisco (still v1.2), Barracuda, PaperCut, Keycloak, Atlassian, Elastic, Jenkins,
  Debian, Fortinet (47 under investigation, 28 not impacted), Google, Okta.
- **Not added:** Gurucul's advisory and CISA's alert page both refused automated access, so
  neither was read; CISA's test results are known here only through press reports.
- The openjdk incident note now says what exploitation takes: a crash is easy, code execution
  needs a separate exploit for each application.

## 2026-11-19: Java4Shell recheck

Daily recheck of vendors still pending on Java4Shell (CVE-2026-114938). 121 new statements,
each read on the vendor's own page.

- **No status changes** on existing rows. Cisco is still at v1.2 (fixed releases TBD), PaperCut's
  fixed release is still planned for the week of 23 November, the Keycloak Operator image is
  unchanged, Barracuda still has Data Inspector and WAF-as-a-Service / Active DDoS Protection
  under investigation, Atlassian's patches still wait on Temurin builds, Elastic's fixed releases
  (8.19.26, 9.4.10, 9.5.7, 9.6.0) are not out yet, and Splunk names no new products.
- **New vendors:**
  - BellSoft: Liberica JDK fixed in 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1.
  - Okta: Access Gateway (2026.45.1), LDAP Agent (5.26.3), On-Premises Provisioning Agent (3.3.4)
    and RADIUS Agent (2.30.0) fixed; Auth0 not affected.
  - Citrix (CTX697367, a script-drawn page read in the browser): Cloudpaging Server 9.9 and later
    runs on JRE 17 and needs the Azul Zulu JRE update; Linux VDA, Analytics, XenMobile Server,
    Secure Access, App Layering and UniconOS Management under investigation; 15 products,
    including NetScaler ADC and Gateway, not affected.
  - Fortinet (FG-IR-26-278): 47 products under investigation, 28 confirmed not impacted.
  - Google: GCP-2026-082 (Distroless Java, Cloud Buildpacks, Dataproc, Dataflow, App Engine
    standard and Cloud Run on interim mitigations; Container-Optimized OS has no Java; GKE control
    plane not affected) and the Apigee bulletin (Apigee X fixed in 1-18-0-apigee-10, hybrid in
    1.17.4; OPDK 4.54 depends on the JDK installed; Edge Public Cloud, Microgateway, Integrated
    Portals and API Gateway not affected).
  - Quarkus: the framework runs on the JDK you provide; its Mandrel and GraalVM CE builder images
    ship with the -XX:-UseBASE64Intrinsics workaround.
- Siemens SSA-272816 (Industrial Edge Management) is already in through Siemens' CSAF feed.
- Exploitation unchanged: probing and exploit attempts, no confirmed compromise, not in CISA KEV.
- Left out: Esri's ArcGIS post (HTTP 403 to automated clients); SapMachine, whose release data
  lists 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 builds, but no SapMachine page naming the CVE
  was found; and claims seen only in news or social media (Epic Systems not affected, GraalVM
  Native Image 25.1 and later affected with a fix due in 25.6, Omnissa Horizon, UniFi).
- Still silent: Ping Identity, JFrog (product statement), Broadcom, IBM, Oracle's own products,
  SAP and JetBrains. Sophos' page refused the connection, so its rows stay at advisory v3.

## 2026-11-19: second criteria pass; 41 → 47 components, 12 more incidents on existing ones

The rest of the backlog was checked against the criteria, 17 months of oss-security (July 2025
to November 2026, 3,042 threads) were matched to the components named in stored product lists,
and CISA KEV was checked for bugs in components already tracked.

- **New components:** Net-SNMP (CVE-2025-68615), Commons BeanUtils (CVE-2014-0114,
  CVE-2019-10086, CVE-2025-48734), Groovy (CVE-2015-3253), Spring Security (CVE-2022-22978),
  Ghostscript (CVE-2023-36664, CVE-2024-29510) and ImageMagick (ImageTragick, KEV).
- **More incidents on tracked components**, which until now carried one or two each:
  - OpenSSL: Heartbleed (KEV) and the January 2026 CMS stack overflow, CVE-2025-15467.
    Entries in an affected range went from 1 to 77.
  - Apache HTTP Server: CVE-2024-38475 (KEV); 0 to 43.
  - Tomcat: CVE-2017-12617 (KEV), CVE-2026-34486 (KEV) and the May 2026 fixes
    (CVE-2026-41293, -43512, -43515); 25 to 37.
  - ActiveMQ: CVE-2026-34197 (KEV); 14 to 17.
  - Struts 2: CVE-2017-9805, CVE-2018-11776 and CVE-2020-17530 (all KEV).
  - PHP: CVE-2024-4577 (KEV; PHP-CGI on Windows only).
- **Checked and left out:**
  - Apache MINA (CVE-2024-52046): rated 10.0, but no public exploit and only for
    applications that use ObjectSerializationDecoder.
  - Velocity, Xalan: need attacker-supplied templates or stylesheets.
  - BusyBox: applet bugs that need local or crafted-file input, not a network path.
  - Jetty, Netty: denial of service and desync bugs; MadeYouReset spans many implementations.
  - Telerik UI for ASP.NET AJAX, Exim, Roundcube: in KEV, but no stored product list names them.
  - Samba CVE-2025-10230: only AD domain controllers with a WINS hook script.
  - libssh2 CVE-2026-55200: critical but one release (1.11.1) and no public exploit yet.
  - FreeType CVE-2020-15999 (KEV): the CVE record gives Chrome versions only and the
    FreeType change log was unreachable, so the range is unverified.
- Still open: Spring Cloud Gateway and Function, Spring Data Commons, older Java SE KEV
  entries, MySQL Group Replication (CVE-2026-60163), rsync's 2026 fixes, dnsmasq's May 2026 fixes.

## 2026-11-19: watchlist criteria written down; 24 → 41 components

The watchlist was never meant to be limited to CISA KEV entries, but recent passes looked for
new components only there. [CONTRIBUTING.md](CONTRIBUTING.md#other-changes) now states the
criteria: commonly bundled, a critical or high remote bug, and exploited, named or with a public
exploit, or the cause of a vendor advisory wave. Four limits stay (a version check has to mean
something, one CVE per component, a clean name match, and a bug that matters to whoever runs
the product).

A first pass against those criteria ranked candidates by how many stored product lists name
them and swept the 840 most-listed packages against OSV. Seventeen components were added, with
ranges from each CVE record, the project's advisory or the reviewed GitHub advisory:

| Component | Incident | Products listing it | Statements in range |
|---|---|---|---|
| zlib | CVE-2022-37434 | 57 | 105 |
| Expat | CVE-2022-25235, -25236, -25315; CVE-2022-40674 | 36 | 71 |
| jackson-databind | CVE-2017-7525, CVE-2020-8840 | 57 | 36 |
| SnakeYAML | CVE-2022-1471 | 43 | 34 |
| FreeType | CVE-2025-27363 (KEV) | 9 | 34 |
| Commons Collections | CVE-2015-7501 | 40 | 24 |
| Apache Tika | CVE-2025-66516 | 11 | 18 |
| H2 | CVE-2021-42392 | 14 | 17 |
| pgjdbc | CVE-2024-1597 | 22 | 17 |
| XStream | CVE-2021-39144 (KEV) | 24 | 13 |
| Commons FileUpload | CVE-2016-1000031 | 20 | 13 |
| dnsmasq | DNSpooq, CVE-2020-25681 and -25682 | 14 | 12 |
| Samba | SambaCry, CVE-2017-7494 (KEV) | 7 | 6 |
| libssh | CVE-2018-10933 | 12 | 4 |
| rsync | CVE-2024-12084 | 24 | 3 |
| libvpx | CVE-2023-5217 (KEV) | 1 | 1 |
| Commons Configuration | CVE-2022-33980 | 15 | 0 |

"In range" means the listed version falls in the affected range. Most of these bugs need a
condition in the product (noted on each component's page), so it is a lead to check, not a
finding. The zlib, Expat and libssh fingerprints now link to the watchlist.

Considered and left out, with the limit that applied:

- Bash (Shellshock), libxml2: fixes ship as distribution backports, so listed versions mislead.
- Redis (RediShell), MongoDB (MongoBleed): the server shares its name with client libraries
  whose version numbers overlap.
- lodash, minimist, axios and other prototype-pollution findings: they depend on how the
  embedding application uses the library.
- SQLite (Magellan): needs attacker-controlled SQL, which few embedders allow.
- Chromium, Electron, Node.js: a steady stream of exploited bugs; any pinned range goes stale.
- Not yet checked against the criteria: net-snmp (CVE-2025-68615), Apache MINA, Commons
  BeanUtils, Velocity, Groovy, Xalan, BusyBox.

## 2026-11-19 (evening): second recheck

- **Java4Shell:**
  - Cisco advisory v1.2: IOS XE and UCS Central moved to not affected, and 10 more products
    were added as affected: Crosswork Assurance UX, Crosswork Workflow Manager, NextFusion,
    Ultra Cloud Core NRF, AppDynamics On-Prem Enterprise Console, Finesse, UCCE, Unified CVP,
    Unified Intelligence Center and Virtualized Voice Browser. Planned fixed releases for Smart
    Software Manager On-Prem, cnBNG and CAF are now in the rows.
  - Sophos advisory v3: Taegis fixed (hosted); Taegis Log Collector and NDR don't contain Java.
  - Distribution packages: Debian 12 and 13 fixed; Ubuntu fixed, except its CRaC builds.
  - Incident note: a proof of concept that triggers the bug is public.
- **NGINX2Root:** Debian 13 fixed (DSA-6642-1); Debian 12 still vulnerable. Incident note: public
  proof of concept (Rapid7), not in KEV.
- **Apache Axis 1.x:** Confluence Data Center (fixed in 9.2.28; 10.x removed the SOAP API).
  Incident note: Rapid7 saw exploitation against Confluence and N-able N-central from 13
  November. N-able's own page refused automated access, so N-central has no row.
- PHP shipped 8.5.13, 8.4.28, 8.3.37 and 8.2.36 today, fixing CVE-2026-115560 and two more
  session-handling bugs. These are left out of the PHP2Shell incident because they need unusual
  configurations.
- No new watchlist components: the only component-level KEV entries since 18 November are Axis
  and the musl-only OpenSSH bug.

## 2026-11-19: Java4Shell and NGINX2Root recheck; Apache Axis 1.x added

Every statement below was checked on the vendor's own page.

- **Java4Shell (CVE-2026-114938):**
  - Barracuda: 30 of its 35 products moved from under investigation to not affected; Email
    Gateway Defense and MSP / Maestro are remediated (hosted). Data Inspector and WAF-as-a-Service
    / Active DDoS Protection are still under investigation.
  - Keycloak: fixed container image 26.8.2-3 (tags latest, 26.8, 26.8.2), on Red Hat OpenJDK
    21.0.13.1. The Operator image is unchanged (workaround).
  - New vendor statements: Atlassian (six Data Center products, workaround
    `-XX:UseAVX=2 -XX:+IgnoreUnrecognizedVMOptions` until patches), Elastic (Elasticsearch,
    Logstash and ECE on a workaround with fixes planned; Kibana, Beats, Elastic Agent, APM Server,
    ECK and Maps Server don't use Java), the Jenkins project (patch the Java you run) and Splunk
    (Enterprise, Universal Forwarder, SOAR and its cloud services unaffected).
  - Incident note: probing and exploit attempts seen since 18 November; no confirmed compromise,
    not in KEV.
- **NGINX2Root (CVE-2026-123007 and four more):** F5's per-product table (NGINX Plus, Instance
  Manager, F5 WAF and DoS for NGINX, App Protect WAF and DoS, Gateway Fabric, Ingress Controller;
  BIG-IP, BIG-IQ and F5OS not vulnerable), Synology (DSM, DSM Enterprise, BeeStation OS, APM on a
  workaround with DSM fixes due 20 November; SRM not affected), and fixed packages from Ubuntu,
  Amazon Linux 2023, Amazon Linux 2 and AlmaLinux.
- **Watchlist: 23 → 24 components.** Apache Axis 1.x: unauthenticated class instantiation through
  SOAP faults (CVE-2026-90436), added to CISA KEV on 18 November. Axis 1 is end of life with no
  upstream fix. Matching uses only unambiguous Axis 1 names, because Axis2's version numbers
  overlap. Stored inventories show it in BMC Helix Innovation Suite, Extreme Networks' Site Engine,
  IQ Controller and Universal Compute Platform, and four JetBrains IDEs.
- Considered and left out: OpenSSH CVE-2026-123158 (KEV, but only musl-based builds without PAM,
  so a version range would flag nearly every product), PHP CVE-2026-115560 (non-default
  configuration; fixed in PHP's 19 November releases) and NGINX Rift CVE-2026-42945 (not in KEV).
- Still silent on Java4Shell: Ping Identity, JFrog (product statement), Broadcom, Esri, IBM,
  Oracle's own products, SAP, JetBrains, BellSoft Liberica and SapMachine.

## 2026-11-19: Java4Shell sources from Censys' advisory

Followed every source linked from [Censys' CVE-2026-114938 advisory](https://censys.com/advisory/cve-2026-114938/).

- **Apache Tomcat** (new statement, runtime_dependent): Wiz reports it proved remote
  exploitation feasible against Tomcat ([Wiz](https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk),
  2026-11-17). Wiz also names Jenkins and Confluence; their existing rows now say so.
- **Amazon Corretto**: exact fixed builds from the Corretto changelogs (17.0.21.1.2,
  21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4).
- **Java4Shell incident note**: adds the second mitigation, `-XX:UseAVX=2` (x86-64 only; JVMs
  on ARM64 fail to start with it), named by Calif, Red Hat and Wiz and tested by VulnCheck,
  and that the CVE isn't in CISA KEV.
- Already covered: the OpenJDK advisory, Oracle's November CSPU, RHSA-2026:100573 (via Red
  Hat's CSAF), Calif's product list and the CVE record. CISA's alert page refused automated
  access and wasn't read.

## 2026-11-18: nine more watchlist components, Java4Shell vendor statements, Red Hat, GitLab and JFrog sources

From a research pass on components worth tracking, Java4Shell developments and new public
component lists. Every range below was checked against the CVE record (or the project's own
advisory where the record has none) and every vendor statement against the vendor's page.

- **Watchlist: 14 → 23 components.** Each is commonly bundled as a private copy inside
  appliances and enterprise servers, so OS patching doesn't reach it:
  - nginx: **NGINX2Root** (CVE-2026-123007 and four more, disclosed 18 November 2026; fixed in
    1.30.7 and 1.31.9). GitLab's own manifests show nginx 1.31.7 in every current release.
  - Apache Tomcat: partial PUT RCE (CVE-2025-24813, KEV) and Ghostcat (CVE-2020-1938, KEV).
  - sudo: Baron Samedit (CVE-2021-3156, KEV) and the chroot escalation (CVE-2025-32463, KEV).
  - jQuery: `<option>` HTML injection (CVE-2020-11023, KEV).
  - Erlang/OTP: SSH pre-authentication RCE (CVE-2025-32433, KEV).
  - Apache ActiveMQ Classic: OpenWire RCE (CVE-2023-46604, KEV); Artemis is excluded.
  - Apache Struts 2: S2-045 (CVE-2017-5638, KEV) and the S2-066/S2-067 upload flaws; Struts 1
    is excluded.
  - Apache HTTP Server: path traversal and RCE in 2.4.49 and 2.4.50 (CVE-2021-41773/42013, KEV).
  - Squid: **Squidbleed** (CVE-2026-47729, fixed in 7.6).

  Re-matching the stored inventories gave 362 new statements straight away (jQuery in 61
  products, Tomcat in 20, sudo in 19, nginx in 13). Left out on purpose: the Linux kernel and
  polkit (fixes ship as backports, so version ranges would mislead), HTTP/2 Rapid Reset (one
  CVE across many implementations), Jenkins core and GeoServer (no listings found yet), and
  libexpat, SnakeYAML and Jackson (no exploited incident).
- **Java4Shell: 67 new vendor statements.**
  - Cisco (advisory v1.1): 13 products affected, among them Catalyst Center, Secure Network
    Analytics, Secure Workload, Smart Software Manager On-Prem and Intersight Virtual
    Appliance; 11 not affected (ISE, ASA, FMC, FTD, NX-OS, IOS XR, SD-WAN); IOS XE and UCS
    Central still under investigation. Cisco's CSAF file has no product tree yet, so these
    come from the advisory page.
  - PaperCut NG/MF Application and Site Server 25.0.0–25.0.13 and 26.0.0–26.0.6 (workaround;
    fixed release planned for the week of 23 November).
  - Sophos (Java not present in UTM, the macOS agents, the mobile apps and the AV engine),
    Graylog (fixed package revisions), Openfire (uses the host's Java), Ory (no JVM), and Red
    Hat Single Sign-On 7.6 (affected only on OpenJDK 17).
  - Fixed Java builds: Oracle Java SE (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf),
    GraalVM for JDK and GraalVM Enterprise, Eclipse Temurin (17.0.21.1+2, 21.0.13.1+2, 25.0.5.1+2, 27.0.1.1+4), Azul Zulu and Azul
    Prime (26.08.110.0, 26.02.510.0), the Microsoft Build of OpenJDK, Amazon Corretto, and
    Amazon Linux 2 and 2023.
  - The incident now shows a note on the component page. It covers the AVX-512 VBMI
    condition, the extra Oracle builds the ranges can't express (Java 8 Enterprise
    Performance Pack 8u511b33-perf and GraalVM Enterprise 21.3.20.0.3) and the
    `-XX:-UseBASE64Intrinsics` mitigation.
  - Not yet published as of 18 November: statements from Atlassian, Jenkins, Ping Identity
    and Elastic. Splunk is investigating (SVD-2026-1102). Red Hat, Ubuntu and Debian stable
    fixes are pending. The CVE is not in CISA's KEV catalog; CISA's SSVC entry says no
    exploitation has been seen.
- **New sources.**
  - Red Hat's public SPDX SBOMs for 15 customer-run products (`type: file_index`;
    bzip2-compressed documents are unpacked): Keycloak, Single Sign-On, JBoss EAP and Web
    Server, AMQ, streams for Kafka, Data Grid, Satellite, Ansible Automation Platform, Quay,
    Directory Server, Certificate System, 3scale, Advanced Cluster Security and OpenJDK.
  - GitLab's Omnibus license manifest for each self-managed release (`versions_json` now
    takes a tag list; the new extractor reads Omnibus manifests).
  - JFrog's table of the OpenJDK and Tomcat versions bundled in each Artifactory release
    (`type: version_table`). Artifactory 7.173 ships OpenJDK 25.0.4.1, which is in the
    Java4Shell range.
- **Corrections.** The rest of JetBrains' stale YouTrack/Hub block (log4j 1.2, Spring
  4.0.1.RELEASE) is set aside too, by maintainer decision. The statement for each product
  names what wasn't counted.
- **Fixes.** The Rust `curl` crate (0.4.x) no longer counts as curl. Barracuda (lists only
  inside the appliance) and Ping Identity (no versioned list) were added to the vendors
  checked and found not crawlable.

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
