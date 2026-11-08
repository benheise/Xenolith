# Xenolith

**An open census of which commercial products embed which third-party components.**

Search it: **https://benheise.github.io/Xenolith/**

In geology, a xenolith is a piece of foreign rock sealed inside a host rock. In software, it's the copy of PHP inside a firewall's management console, the Brotli decoder bundled into an IDE, or the Log4j jar buried in an appliance.

## The problem

When a vulnerability lands in a widely embedded component (Log4Shell in 2021, PHP2Shell and the Brotli decoder bug in October 2026), every security team asks the same question: *which of the products we run ship it inside?* Asset scanners can't see into appliances, firmware or SaaS, and vendor SBOMs are rarely public. Each time, the community rebuilds the same vendor × product × status table by hand in a GitHub repository, then archives it when the incident ends.

Xenolith makes that table permanent and indexes it by component, so the next incident starts from what is already known.

## Scope

Xenolith covers **products**: appliances, firmware, enterprise and hosted software, management consoles. It doesn't index open source **packages**. These services already do that well, and Xenolith links to them instead:

| Need | Use |
|---|---|
| Which open source packages depend on a library | [deps.dev](https://deps.dev/), [ecosyste.ms](https://ecosyste.ms/) |
| Vulnerable versions of open source packages | [OSV.dev](https://osv.dev/), [GitHub Advisory Database](https://github.com/advisories) |
| Which distributions package a project | [Repology](https://repology.org/) |
| The most widely used open source libraries | [Census III of Free and Open Source Software](https://www.linuxfoundation.org/press/open-source-usage-trends-and-security-challenges-revealed-in-new-study) |

## How it works

```
catalog/components.yaml       watchlist: components + the CVEs that identify them
        │
        ├─ Vendor CSAF/VEX feeds ──────────┐  "Product P is fixed / known_affected /
        ├─ Vendor open source notices ─────┤   not affected by CVE-X", or "P lists
        ├─ NCSC-NL and CISA trackers ──────┤   component C 1.0.6 in its notices"
        ├─ community/assertions.csv ───────┤
        │                                  ▼
        │                     data/assertions/**/*.ndjson   (open data, one sourced claim per line)
        │                                  │
CVE records + CISA KEV ──► data/spine/products.ndjson       (product registry, ranked by KEV and CVE counts)
                                           │
                                           ▼
                             docs/  (static search site on GitHub Pages)
```

1. **Component watchlist.** [`catalog/components.yaml`](catalog/components.yaml) lists widely embedded components and the CVEs that identify them (for example CVE-2026-111497 means Brotli).
2. **Vendor advisories (automated).** A crawler reads CSAF 2.x feeds from Cisco, Microsoft, Red Hat, Siemens, Schneider Electric, ABB, SICK, CISA and every provider on BSI's CSAF aggregator. When a vendor's advisory states a product's status for a watchlist CVE, that's a statement about whether the product embeds the component. The crawl is incremental: unchanged advisories are never fetched twice.
3. **Vendor open source notices (automated).** Vendors publish "Open Source Used In" documents, OSS listings and third-party notices for their products: the closest public stand-in for an SBOM of a closed product. `python -m xenolith notices` fetches the documents listed or discovered by [`catalog/notices.yaml`](catalog/notices.yaml) (PDF, HTML, text, CycloneDX or SPDX), extracts the **full** component list with versions, stores it under `data/notices/`, and matches it against the watchlist. Every Palo Alto Networks OSS listing (PAN-OS, Panorama, WildFire, GlobalProtect, CN-Series and more) is discovered automatically. Because the full lists are kept, you can search *any* library name on the site, not just watchlist components, and adding a component to the watchlist re-matches every stored document instantly.
4. **Incident trackers (seed data).** The NCSC-NL php2shell and log4shell repositories and CISA's log4j-affected-db are imported with full provenance.
5. **Community submissions.** Anyone can add a sourced statement (vendor advisory, SBOM, third-party notices file, binary scan) by pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).
6. **Product registry.** Vendor/product names from CNA-published CVE records and the CISA KEV catalog, ranked by exploitation. Products with no composition data yet are listed too, which makes the gaps visible.
7. **Static site.** `python -m xenolith build` writes JSON for the single-page search UI in `docs/`. A daily GitHub Actions run refreshes everything and republishes.

### Reading a statement

Each record is one claim from one source, with a link back to it and the date of the claim.

| Status | Meaning |
|---|---|
| Affected | Product contains a vulnerable version; no fix stated |
| Workaround only | Affected; vendor published a mitigation but no fix |
| Fix released | Product contained the component; vendor has shipped a fixed version |
| Investigating | Vendor or tracker hasn't concluded |
| Uses host runtime | Product runs on a copy you install and patch yourself (e.g. a PHP app) |
| Contains (not assessed) | Component is listed in the vendor's notices or SBOM; no CVE assessed. Check the component version against the CVE's affected range, and remember vendors backport fixes |
| Not affected | Vendor says the product isn't affected |
| Not present | Vendor says the component isn't in the product at all |

Tracker rows are only as current as the tracker (the Log4j trackers were archived in 2022–2023). Always confirm against the vendor's own advisory before acting.

## Running it locally

Requires Python 3.11+ and PyYAML.

```bash
pip install -r requirements.txt

# Incident trackers (clone into src/ first; directory names are Owner_repo)
git clone --depth 1 https://github.com/NCSC-NL/php2shell src/NCSC-NL_php2shell
git clone --depth 1 https://github.com/NCSC-NL/log4shell src/NCSC-NL_log4shell
git clone --depth 1 https://github.com/cisagov/log4j-affected-db src/cisagov_log4j-affected-db
python -m xenolith trackers --src src

python -m xenolith csaf --only Cisco --max-fetch 200   # vendor CSAF feeds (incremental)
python -m xenolith notices                             # vendor open source notices (incremental)
python -m xenolith community                           # validate + ingest community/assertions.csv
python -m xenolith spine                               # KEV-only registry; add --cves <cvelistV5/cves> for the full one
python -m xenolith build                               # write docs/data/

python -m http.server -d docs 8000                     # open http://localhost:8000
python -m unittest discover -s tests
```

## Repository layout

| Path | What |
|---|---|
| `catalog/` | Component watchlist, data source registry, CSAF provider list, notices document list |
| `community/assertions.csv` | Community-contributed statements (edit by pull request) |
| `data/assertions/` | Normalized statements per source (NDJSON). The open data dump |
| `data/notices/` | Full component inventories extracted from vendor notices (one JSON file per document) |
| `data/spine/products.ndjson` | Product registry |
| `data/state/csaf/` | Crawl state so CSAF documents are only re-fetched when they change |
| `docs/` | The GitHub Pages site (`index.html` + generated `data/`) |
| `schema/assertion.schema.json` | JSON Schema for one statement |
| `xenolith/` | Pipeline code (standard library + PyYAML) |

## Roadmap

- [x] Seed from NCSC-NL and CISA incident trackers
- [x] Incremental CSAF/VEX crawler with aggregator discovery
- [x] Product registry from CVE records + KEV
- [x] Static search site and daily refresh
- [ ] Transparency Exchange API (TEA) client to collect vendor SBOMs as vendors publish them
- [x] Parse vendor third-party notices / "open source used in" documents into component lists
- [ ] More notices sources: per-vendor discovery rules for vendors that publish index pages (add yours to `catalog/notices.yaml`)
- [ ] Binary composition scans (Syft, cdxgen) of freely downloadable appliance images, with vendored-copy fingerprints like the Brotli fix check
- [ ] Product identity crosswalk (CVE vendor/product strings ↔ CPE ↔ CSAF product IDs ↔ purl) so the same product from different sources merges into one entry
- [ ] Export as CycloneDX/SPDX so tools like GUAC or Dependency-Track can ingest it

## Licensing

Code is [Apache-2.0](LICENSE). Each data record keeps the terms of its source; see [DATA_LICENSE.md](DATA_LICENSE.md).
