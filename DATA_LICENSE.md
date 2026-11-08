# Data licensing

Xenolith's code is licensed under Apache-2.0 (see `LICENSE`). The data is not one work under one license. Every record under `data/` and `docs/data/` names its source (`source` field), and each source's terms continue to apply to the records taken from it.

| Source id | Origin | Terms |
|---|---|---|
| `ncsc-nl-php2shell` | [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) | EUPL-1.2 |
| `ncsc-nl-log4shell` | [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) | MIT |
| `cisa-log4j` | [cisagov/log4j-affected-db](https://github.com/cisagov/log4j-affected-db) | CC0-1.0 |
| `csaf` | Vendors' public (TLP:CLEAR) CSAF advisories | Each vendor's terms of use. Only factual statements (product, version, status, date, link) are extracted; advisory documents are not redistributed |
| `notices` | Vendors' public open source notices / OSS listings (see `catalog/notices.yaml`) | Each vendor's terms of use. Only component names and versions are extracted, as facts; license texts and documents are not redistributed |
| `community` | `community/assertions.csv` in this repository | CC-BY-4.0 |
| `cvelist` (product registry) | [CVE Program cvelistV5](https://github.com/CVEProject/cvelistV5) and [CISA KEV](https://github.com/cisagov/kev-data) | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse); KEV is CC0-1.0 |

If you republish a subset of the data, filter by `source` and follow that source's terms. By contributing to `community/assertions.csv` you agree to license your contribution under CC-BY-4.0.

This summary is not legal advice.
