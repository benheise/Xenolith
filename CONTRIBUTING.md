# Contributing to Xenolith

Xenolith answers one question: **which commercial products embed which third-party components?** Its value depends entirely on evidence, so every contribution must point to something others can check.

There are three ways to contribute data, from quickest to most thorough. All three go through a pull request, and every pull request is validated automatically.

- [1. Add a vendor notices document](#1-add-a-vendor-notices-document) (`catalog/notices.yaml`)
- [2. Add a sourced statement](#2-add-a-sourced-statement) (`community/assertions.csv`)
- [3. Submit an SBOM](#3-submit-an-sbom) (`community/sboms/*.cdx.json`)
- [Other changes](#other-changes): watchlist components, product aliases, CSAF providers, corrections, code
- [Before you open the pull request](#before-you-open-the-pull-request)

## Ground rules

- **Link to evidence.** Every row, document and SBOM needs a public source or a reproducible artifact. "I know this" isn't enough.
- **Only share what you may share.** Don't submit confidential documents, internal SBOMs, customer data, or scans of software whose license or your employer's policy forbids it. If in doubt, ask your legal or open source office first.
- **Products, not packages.** Open source libraries and their dependents are covered by deps.dev, OSV and ecosyste.ms.
- **Your words for notes.** Don't paste advisory text; summarize it.
- Contributions under `community/` are licensed **CC-BY-4.0**.

---

## 1. Add a vendor notices document

**Use this when** a vendor publishes a list of the open source components in a product: an "Open Source Used In …" document, an OSS listing, third-party notices, attributions, acknowledgments, or a published SBOM.

**File:** [`catalog/notices.yaml`](catalog/notices.yaml), under `documents:`.

```yaml
  - supplier: Example Networks          # the vendor, as it names itself
    product: Example Gateway OS         # the product, without the vendor's name
    version: "7.2"                      # product version the document covers (quote it)
    url: https://example.com/legal/gateway-os-7.2-open-source.pdf
    found_at: https://example.com/support/gateway-os-7.2   # the page that links the document
```

| Field | Required | Notes |
|---|---|---|
| `supplier` | yes | Vendor name |
| `product` | yes | Product name |
| `version` | yes | Product version or release line; use `"all"` if the document isn't versioned |
| `url` | yes | Direct, public, stable link. PDF, HTML, plain text, CycloneDX or SPDX |
| `found_at` | strongly recommended | The vendor page that links the document (release notes, a documentation index, a legal page). It is the record's discovery path: it lets anyone retrace where the file came from, and find the next version when this one moves. When the link sits two clicks deep, give a list, outermost page first |

Every record in the census says how its source reached it (`found_via`): **hand-listed** (added to a catalog file like this one), **auto-discovered** (found by a `discover:` rule, a CSAF aggregator or a feed) or **community** (contributed under `community/`). Its `discovery_path` lists the pages that led to the document, and `sha256` is the hash of the bytes it was read from. Product pages on the site show all three. `python -m xenolith provenance` lists the hand-listed documents and scanner corpus artifacts still missing `found_at`.

If the vendor has an **index page** linking a document per product or version, add a `discover:` rule instead (see the Palo Alto Networks rule in the same file) so new versions are picked up automatically.

Check it locally:

```bash
python -m xenolith notices --only "Example Networks"
```

The output says how many components were extracted and by which parser. If it says `0 components`, open an issue with the URL; the parser may need a new format.

## 2. Add a sourced statement

**Use this when** you have a public vendor statement about one product and one component: a security advisory, KB article, release note, support forum answer from the vendor, or a VEX document.

**File:** [`community/assertions.csv`](community/assertions.csv). One row per product and component. The header must stay exactly:

```
component,supplier,product,versions,status,cves,evidence,source_url,date,notes,exploitation
```

| Column | Required | Allowed values / format |
|---|---|---|
| `component` | yes | An `id` from [`catalog/components.yaml`](catalog/components.yaml), e.g. `brotli`, `php`, `log4j-core` |
| `supplier` | yes | Vendor name |
| `product` | yes | Product name |
| `versions` | no | Product versions the statement covers, free text: `7.2.0 to 7.2.9; fixed in 7.2.10` |
| `status` | yes | `affected`, `workaround`, `fixed`, `under_investigation`, `runtime_dependent`, `not_affected`, `present`, `absent`, `unknown` |
| `cves` | no | Space-separated CVE IDs from that component's watchlist entry. Leave empty for composition-only facts |
| `evidence` | no | `vendor-advisory`, `vendor-sbom`, `notices-file`, `binary-scan` or `community` (default) |
| `source_url` | yes | `https://` link to the evidence |
| `date` | yes | `YYYY-MM-DD`, the date the source made the statement |
| `notes` | no | Short context in your own words |
| `exploitation` | no | Empty, or `exploited`, `attempted`, `demonstrated_preauth`, `demonstrated_postauth`. See below |

What the statuses mean:

| Status | Use when the source says |
|---|---|
| `affected` | The product is vulnerable and no fix is available yet |
| `workaround` | Vulnerable; only a mitigation is available |
| `fixed` | The product contained the component and a fixed version is available |
| `under_investigation` | The vendor is still checking |
| `runtime_dependent` | The product runs on a copy the customer installs (patch the host) |
| `not_affected` | Not affected (component may or may not be present) |
| `present` | The component is in the product; no CVE is assessed |
| `absent` | The component is not in the product |

**Exploitation** is a separate signal from the status, because a product can have a fix out and still be the one attackers are breaking into. It is the strongest reason to patch a product now, so the bar is a named source that says it about this product, not about the vulnerability in general.

| Level | Use when a named source says | Not enough |
|---|---|---|
| `exploited` | This product was compromised in the wild through this CVE (the vendor, a national CERT, CISA KEV naming the product, or an incident responder) | The CVE is in KEV but the report names another product |
| `attempted` | Exploit attempts aimed at this product were observed, with no confirmed compromise | Internet-wide scanning or honeypot hits that are not tied to a product |
| `demonstrated_preauth` | A researcher has a working exploit for this product that needs no login, even if it is private | A crash-only proof of concept |
| `demonstrated_postauth` | The same, but the exploit needs a login | |

Put the level on a row whose `source_url` is the report itself (usually a `community` evidence row beside the vendor's own row), with the CVE in `cves`. The site shows the strongest level on every statement for that product and lists those products first. Raise a level when a better source appears; never lower `exploited`.

Examples:

```csv
brotli,Example Networks,Example Gateway OS,7.2.0 to 7.2.9,fixed,CVE-2026-111497,vendor-advisory,https://example.com/psirt/EX-2026-014,2026-10-29,Fixed in 7.2.10
php,Example Networks,Example Console,,absent,,vendor-advisory,https://example.com/kb/123,2026-10-24,Console is Java; no PHP runtime
openssl,Example Networks,Example Gateway OS,7.2,present,,notices-file,https://example.com/legal/oss-7.2.pdf,2026-06-01,Bundles OpenSSL 3.0.13
```

## 3. Submit an SBOM

**Use this when** you have a **CycloneDX** SBOM of a product: one the vendor published, or one you produced by scanning software you're permitted to analyze **and** to share the results of (a public download, a container image, your own company's product with approval).

**File:** `community/sboms/<supplier>/<product>--<version>.cdx.json` (the `prepare` command below picks this path for you). A complete, valid example: [`community/examples/example-binary-scan.cdx.json`](community/examples/example-binary-scan.cdx.json).

Required content:

| Where | Field | Rule |
|---|---|---|
| top level | `bomFormat`, `specVersion` | `"CycloneDX"`, 1.4 to 1.7 |
| `metadata` | `timestamp` | When the SBOM was produced (ISO 8601) |
| `metadata` | `tools` | The tool(s) that produced it, e.g. `syft`, `cdxgen`, `xenolith-scan` |
| `metadata.component` | `name`, `version` | The **product** and its version |
| `metadata.supplier` (or `metadata.component.supplier`) | `name` | The **vendor** |
| `components[]` | `name`, `version` | The embedded components. Versions strongly recommended |
| `metadata.properties` | `xenolith:evidence` | `binary-scan` (you scanned it) or `vendor-sbom` (the vendor published it) |
| `metadata.properties` | `xenolith:artifact` | What was analyzed: file name, download URL or image digest |
| `metadata.properties` | `xenolith:artifact_sha256` | Required for `binary-scan`: SHA-256 of the analyzed file, so others can reproduce it |
| `metadata.properties` | `xenolith:source_url` | Public `https://` link: the vendor's SBOM (required for `vendor-sbom`) or the download page (recommended for `binary-scan`) |
| `metadata.properties` | `xenolith:attestation` | Must be `"yes"`: you confirm you're permitted to share this component list |

Limits: 8 MB per file, 25,000 components. Submissions are CycloneDX; `prepare` below converts SPDX JSON for you.

What happens next: the SBOM becomes an inventory just like a notices document. Its full component list becomes searchable on the site, and watchlist components in it appear on the product's page as statements with evidence type `binary-scan` or `vendor-sbom`, flagged when a listed version falls in a CVE's affected range.

**Producing one.** The quickest way is [`xenolith-scan`](scan/README.md): `xenolith-scan scan <artifact>` unpacks the installer, firmware image, archive or disk image, detects components (Syft, the fingerprint pack, notices files inside the product), asks you to confirm the product identity and writes `xenolith-out/submission.cdx.json` ready for this section, plus a local `report.html` and `not-inspected.txt`. `xenolith-scan review xenolith-out` lets you keep or drop findings below the 0.7 confidence line (Xenolith makes statements only from findings at or above it; the rest stay searchable in the inventory), and `xenolith-scan submit xenolith-out --attest` opens the pull request with `gh` or prints the upload path. Builds for Linux, macOS and Windows are on the releases page (`scan/v*` tags), signed with cosign; or `make -C scan build` with Go 1.26.

The Python pieces still work and take other scanners' output. Two commands, both offline. `fingerprint` looks through a firmware image's extracted files, an installation folder or an archive (zip, jar, war, tar, tgz, nested to any depth) for the watchlist components, including statically linked and shaded copies, and writes CycloneDX. `prepare` turns that, or the output of any other scanner, into a submission: it fills in the product and the `xenolith:` properties, computes the artifact's SHA-256, keeps only component name, version, purl and CPE (so paths, user names and build directories from your machine never reach the pull request), validates the file and lists the watchlist components it found.

```bash
# 1. Unpack if needed, then scan
unblob -e ./extracted acme-fw-7.2.9.bin                       # firmware image (optional helper)
python -m xenolith fingerprint ./extracted -o scan.cdx.json    # watchlist components, with evidence
# or a broad inventory from another scanner:
# syft scan dir:./extracted -o cyclonedx-json=scan.cdx.json
# cve-bin-tool ./extracted --sbom-type cyclonedx --sbom-output scan.cdx.json
# blint sbom -i ./extracted -o scan.cdx.json

# 2. Turn it into a submission
python -m xenolith prepare scan.cdx.json \
  --supplier "Acme Networks" --product "Acme Gateway OS" --version 7.2.9 \
  --artifact acme-fw-7.2.9.bin --product-type firmware --attest
# -> community/sboms/acme-networks/acme-gateway-os--7-2-9.cdx.json
```

`fingerprint` prints each finding with its confidence and where it was found, so you can check it before submitting. Findings without a version (a shaded class, Brotli's built-in dictionary in a stripped binary) are reported as present with the version unknown. Leave out `--attest` until you've confirmed you may share the list; the file is written but marked not ready. For a vendor-published SBOM, pass `--evidence vendor-sbom --source-url https://...` instead. [design/xenolith-scan.md](design/xenolith-scan.md) describes the design behind `xenolith-scan`, which does both steps in one.

---

## The wanted list

[`catalog/wanted.yaml`](catalog/wanted.yaml) lists widely deployed products whose component lists we tried to collect and couldn't, shown on the site's [Wanted page](https://benheise.github.io/Xenolith/#w=all). Each entry says what's blocking it (login, in-product only, blocked downloads, no public list), where the list usually lives for someone with access, and our best guesses at what it contains.

**Helping with an entry.** If you can see inside one of these products, the entry's "where" line says where to look. Contribute what you find the usual way: a notices URL (section 1), a sourced statement (section 2) or an SBOM (section 3). When a component list arrives for the product, the build moves the entry to "Now verified" automatically; a sourced statement about one component shows on the entry as already verified and replaces the guess about it.

**Guesses are not data.** They appear only on the Wanted page, never on product or component pages, and never count as evidence. Each guess needs a `confidence` and a `basis`:

| `confidence` | Use when |
|---|---|
| `named` | The vendor named the component publicly (an advisory, KB article, old notices, a support page), but there's no complete, current list. Give the `source` link |
| `likely` | Strong inference: the platform or runtime makes it near-certain (a Photon OS appliance has glibc and OpenSSL; an Electron app has Chromium's libwebp) |
| `possible` | Weaker inference worth checking |

**The research queue.** [`catalog/research_queue.yaml`](catalog/research_queue.yaml) lists widely deployed, customer-run products nobody has researched yet, picked from analyst and review-site rankings (Gartner Magic Quadrants and Peer Insights, G2) and from products with CISA KEV entries but no component data. If you know where one of them publishes its notices, add the notices to `catalog/notices.yaml` and remove the queue entry; if it turns out to be blocked, move it to `wanted.yaml` with guesses. Quote any value that contains a comma.

**Adding an entry.** Add the product under its vendor with `product`, `key` (the product key from the site's URL, `#p=<key>`, so the entry links to the existing page), and at least one guess. Use `component:` for watchlist ids and `name:` for anything else. If a vendor statement already settles a component, add it to `community/assertions.csv` instead of guessing. `python -m xenolith community --check` validates the file.

---

## Other changes

**What belongs on the watchlist.** The census stores every component a vendor lists; the watchlist is the subset that gets version-range checks and vendor statements. A component belongs on it when it is shared (see below) and it has a critical or high-severity bug reachable over the network that meets at least one of these:

- it is exploited in the wild (CISA KEV or another credible report);
- it has a name or a public exploit or proof of concept;
- it has set off a wave of vendor advisories, with several unrelated vendors publishing statements about it.

"Shared" means either of two things:

- **A third-party component** that products from different vendors commonly bundle (Log4j, OpenSSL, nginx).
- **A vendor's own engine** that the vendor ships across several of its product lines and reports on product by product: the F5 Traffic Management Microkernel in BIG-IP modules and BIG-IP Next, FortiOS code in FortiProxy and FortiSwitchManager, the VPN engine behind Ivanti Connect Secure, Policy Secure and ZTA gateways. One bug there puts several products on the list at once, and the vendor's advisory is the only place that says which. A flaw in a single product with no shared engine doesn't qualify; that is what the vendor's own advisory feed is for.

A first-party engine never shows up in a notices file, so its entry has no `notices_names` and needs no `affected:` ranges (there is nothing to range-check; the versions go in each statement), and its statements all come from the vendor's advisories. Name the entry after the engine or the product family (`f5-tmm`, `fortios`), and say in a comment which product lines share it.

CISA KEV is one signal among these, never the filter: Java4Shell, NGINX2Root and Squidbleed were added before any KEV listing. Look for candidates in oss-security, critical GitHub advisories, vendor advisory waves and KEV, and rank them by how many products in the stored inventories list the component.

Four limits apply however serious the bug is:

- **A version check has to mean something.** If fixes mostly ship as backports or depend on how the product was built (the Linux kernel, polkit, the musl-only OpenSSH bug), a version range would flag nearly every product, so leave it out.
- **One CVE, one component.** A protocol bug shared by many implementations (HTTP/2 Rapid Reset) doesn't fit.
- **The name has to match cleanly.** If another package shares the name and its version numbers overlap (Axis 1 and Axis2, the MongoDB server and its drivers), match only unambiguous names or leave it out.
- **The bug has to matter to someone who runs the product.** Bugs that need the embedding application to misuse the library in an unusual way (most prototype-pollution findings) are low priority; say so in the incident `note` when a condition applies.

The census doesn't check every stored component against every CVE. That would bury vendor statements under scanner noise; use a scanner for that.

**Add a component to the watchlist.** Add an entry to [`catalog/components.yaml`](catalog/components.yaml) with `id`, `name`, the incident's CVEs, the `affected:` ranges copied from the CVE record (`last_affected` for a line with no fix), and `notices_names` patterns for how the component appears in notices. Maven and Go coordinates need their own patterns, and an ambiguous name can be tied to a version pattern (`{pattern, version}`), as for Struts 2 versus Struts 1. A short `note` on an incident is shown on the component's page. A CVE can belong to one component only, so a protocol bug shared by many implementations (HTTP/2 Rapid Reset) doesn't fit. Every stored notices document and SBOM is re-matched on the next build, and the CSAF crawl picks up the new CVEs from advisories it has already read.

**Add or improve a fingerprint.** [`catalog/fingerprints.yaml`](catalog/fingerprints.yaml) tells `python -m xenolith fingerprint` and `xenolith-scan` (which embeds a copy; `make -C scan sync` refreshes it and a Go test checks it) how to recognise each watchlist component: version strings in executables, functions a library defines, the constant its version function returns, static data only it contains, and package metadata paths inside archives. Check a new rule against a real build of the component and add a synthetic sample to `FingerprintTest` in `tests/test_pipeline.py`; the test suite also checks that every fingerprint reports a name the watchlist matches.

**Merge a product that shows up twice.** Add an alias to [`catalog/identity.yaml`](catalog/identity.yaml). Many duplicates are already linked automatically through shared CPE identifiers; `docs/data/crosswalk.json` lists those links.

**Add a vendor's notices.** Single documents go under `documents:` in [`catalog/notices.yaml`](catalog/notices.yaml). For vendors with many products or releases, a `discover:` rule finds them: an index page of links, a table of product | version | link (`type: table`), a directory listing laid out as product/version/notice (`type: autoindex`), a JSON list of versions (`type: versions_json`), a product picker whose options are embedded in the page (`type: embedded_json`), JetBrains' release API (`type: jetbrains`), a plain-text index of document paths (`type: file_index`, Red Hat's SBOM index), or a table of the component versions each release bundles (`type: version_table`, JFrog); `versions_json` also takes a list of tags (`field` plus `version_regex`) and a `{minor}` placeholder; link rules can take the product and version from the document URL (`product_from_url`, `version_from_url`) and fix a product name as the vendor spells it (`rename`). Apple's release list has its own source (`type: apple_releases`, `xenolith/sources/apple.py`) because it must map Apple project tags to upstream versions. Examples of each are in the file. Documents are parsed by whichever extractors apply (bzip2-compressed ones are unpacked first): HTML and pipe tables, SBOMs (CycloneDX, SPDX, Omnibus license manifests), tables of contents, NetApp and Black Duck notice reports (`Components:` sections), Black Duck URL lines, license groups and `Embedded Software Components` tables, `Name Version License` tables flattened from PDFs, DLL lists in Common Criteria Security Targets, versioned jar names, and, when nothing structured is found, plain `name version` lines in a document that talks about third-party software. If a vendor's format isn't recognised, `python tools/probe.py <url>` shows what each extractor finds; add an extractor in `xenolith/sources/notices.py` with a test. A site that blocks automated clients may have a mirror (BMC's docs.helixops.ai) or an incomplete TLS chain (`catalog/intermediates.pem`).

**A vendor's list is wrong.** If an entry is demonstrably wrong (a stale version the vendor has since replaced, a component credited under the wrong name), add it under `corrections:` at the end of `catalog/notices.yaml` with a reason and evidence links. The entry stays in the inventory as published but makes no statement, and the statement for the rest of the list says what wasn't counted. Don't use it to hide entries that are merely inconvenient.

**Pages drawn in the browser.** When a page's HTML is an empty shell that a script fills, look first for the data the script loads (the browser's network panel usually shows a JSON request; JetBrains and Microsoft both turned out to have one) and point a rule at it. If there is none, `render: true` on a document or `discover:` rule loads it in headless Chromium (`pip install playwright && python -m playwright install chromium`; `XENOLITH_CHROMIUM` can point at an installed Chrome). The plain fetch always comes first: a page it can already read is used as is, and an HTTP error, a login form or a bot challenge stays an error. Rendering is for pages that are empty without a browser, never for getting past a site that refuses automated clients. A rendered document's `sha256` is the hash of its visible text, and its inventory says `rendered: true`. If you add the first such entry, also add the Playwright install to `.github/workflows/refresh.yml`.

**Add a CSAF provider.** Add its `provider-metadata.json` URL to [`catalog/csaf_providers.yaml`](catalog/csaf_providers.yaml). Providers on BSI's aggregator are picked up automatically.

**Report a wrong statement.** Open an issue with the product, the statement, and a link to the vendor's current advisory.

**Code.** The pipeline is Python with three dependencies (PyYAML, pypdf, standard library otherwise). Add a test for any parser or rule you change.

## Before you open the pull request

```bash
pip install -r requirements.txt
python -m xenolith community --check     # validates assertions.csv and every file in community/sboms/
python -m unittest discover -s tests
```

The same checks run on the pull request. The pull request template has a short checklist.
