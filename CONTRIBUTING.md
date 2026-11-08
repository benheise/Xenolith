# Contributing to Xenolith

The census is only as good as its evidence. The most useful contribution is a **sourced statement** about what a commercial product embeds.

## Add a vendor's open source notices document (easiest)

If a vendor publishes an "Open Source Used In", OSS listing, third-party notices or SBOM document for a product, add it to [`catalog/notices.yaml`](catalog/notices.yaml):

```yaml
  - supplier: Example Networks
    product: Example Gateway OS
    version: "7.2"
    url: https://example.com/docs/gateway-os-7.2-open-source.pdf
```

PDF, HTML, plain text, CycloneDX and SPDX all work. The next scheduled run extracts every component in it. If the vendor has an index page linking all its documents, add a `discover` rule instead so new product versions are picked up automatically. Run `python -m xenolith notices --only "Example Networks"` locally to check what gets extracted.

Some vendors block automated downloads or put notices behind a login; those can't be crawled. Don't add copies hosted by third parties.

## Add a statement

Edit [`community/assertions.csv`](community/assertions.csv) and open a pull request. One row per product and component:

| Column | Required | Example |
|---|---|---|
| `component` | yes | `brotli` (an `id` from [`catalog/components.yaml`](catalog/components.yaml)) |
| `supplier` | yes | `Example Networks` |
| `product` | yes | `Example Gateway OS` |
| `versions` | no | `7.2.0 to 7.2.9; fixed in 7.2.10` |
| `status` | yes | `fixed` (see below) |
| `cves` | no | `CVE-2026-111497` (space-separated; leave empty for composition-only evidence) |
| `evidence` | no | `vendor-advisory`, `vendor-sbom`, `notices-file`, `binary-scan` or `community` (default) |
| `source_url` | yes | `https://…` link to the evidence |
| `date` | yes | `2026-10-29` (the date the source made the statement) |
| `notes` | no | Short context, in your own words |

`status` is one of: `affected`, `workaround`, `fixed`, `under_investigation`, `runtime_dependent`, `not_affected`, `present` (component is embedded, no CVE assessed), `absent` (component is not in the product), `unknown`.

Good evidence, in order of strength: a vendor advisory or VEX statement, a vendor-published SBOM, the vendor's third-party notices / "open source used in" document, a reproducible binary scan of a publicly downloadable artifact (say which tool and which artifact hash). Don't submit statements you can't link to.

Pull request checks run `python -m xenolith community --check` and the test suite. Errors name the line and the problem.

## Add a component to the watchlist

Add an entry to `catalog/components.yaml` with the CVEs that identify the component. Good candidates are small, permissively licensed libraries that vendors copy into their products (compression, parsing, TLS, image codecs, logging, runtimes). The crawler will start matching vendor advisories for those CVEs on its next run, including advisories it has already seen.

## Merge a product that shows up twice

If the same product appears as two entries (different spellings across sources), add an alias to [`catalog/identity.yaml`](catalog/identity.yaml). Supplier aliases go under `suppliers`, product aliases under `products` for that supplier. Names are written lowercase without punctuation, after the automatic rules described at the top of that file.

## Add a CSAF provider

Add the provider's `provider-metadata.json` URL to `catalog/csaf_providers.yaml`. Providers listed on BSI's CSAF aggregator are picked up automatically.

## Report a wrong statement

Open an issue with the product, the statement you believe is wrong, and a link to the vendor's current advisory. Statements imported from a tracker or vendor feed are corrected at the source when possible.

## Code

```bash
pip install -r requirements.txt
python -m unittest discover -s tests
```

The pipeline uses only the standard library plus PyYAML so it runs anywhere GitHub Actions does.
