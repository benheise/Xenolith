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
```

| Field | Required | Notes |
|---|---|---|
| `supplier` | yes | Vendor name |
| `product` | yes | Product name |
| `version` | yes | Product version or release line; use `"all"` if the document isn't versioned |
| `url` | yes | Direct, public, stable link. PDF, HTML, plain text, CycloneDX or SPDX |

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
component,supplier,product,versions,status,cves,evidence,source_url,date,notes
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

**Producing one.** Two commands, both offline. `fingerprint` looks through a firmware image's extracted files, an installation folder or an archive (zip, jar, war, tar, tgz, nested to any depth) for the watchlist components, including statically linked and shaded copies, and writes CycloneDX. `prepare` turns that, or the output of any other scanner, into a submission: it fills in the product and the `xenolith:` properties, computes the artifact's SHA-256, keeps only component name, version, purl and CPE (so paths, user names and build directories from your machine never reach the pull request), validates the file and lists the watchlist components it found.

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

`fingerprint` prints each finding with its confidence and where it was found, so you can check it before submitting. Findings without a version (a shaded class, Brotli's built-in dictionary in a stripped binary) are reported as present with the version unknown. Leave out `--attest` until you've confirmed you may share the list; the file is written but marked not ready. For a vendor-published SBOM, pass `--evidence vendor-sbom --source-url https://...` instead. [design/xenolith-scan.md](design/xenolith-scan.md) describes the single cross-platform scanner planned to replace step 1.

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

**Add a component to the watchlist.** Add an entry to [`catalog/components.yaml`](catalog/components.yaml) with `id`, `name`, the incident's CVEs, the `affected:` ranges copied from the CVE record, and `notices_names` patterns for how the component appears in notices. Every stored notices document and SBOM is re-matched on the next build.

**Add or improve a fingerprint.** [`catalog/fingerprints.yaml`](catalog/fingerprints.yaml) tells `fingerprint` how to recognise each watchlist component: version strings in executables, functions a library defines, the constant its version function returns, static data only it contains, and package metadata paths inside archives. Check a new rule against a real build of the component and add a synthetic sample to `FingerprintTest` in `tests/test_pipeline.py`; the test suite also checks that every fingerprint reports a name the watchlist matches.

**Merge a product that shows up twice.** Add an alias to [`catalog/identity.yaml`](catalog/identity.yaml). Many duplicates are already linked automatically through shared CPE identifiers; `docs/data/crosswalk.json` lists those links.

**Add a vendor's notices.** Single documents go under `documents:` in [`catalog/notices.yaml`](catalog/notices.yaml). For vendors with many products or releases, a `discover:` rule finds them: an index page of links, a table of product | version | link (`type: table`), a directory listing laid out as product/version/notice (`type: autoindex`), a JSON list of versions (`type: versions_json`), or a product picker whose options are embedded in the page (`type: embedded_json`). Examples of each are in the file.

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
