# xenolith-scan GitHub Action

For vendors who want every release's component list in Xenolith: scan the release
artifact in CI and open the pull request automatically.

```yaml
name: Publish component list
on:
  release:
    types: [published]

jobs:
  xenolith:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: gh release download ${{ github.event.release.tag_name }} --pattern 'acme-fw-*.bin' --dir dist
        env:
          GH_TOKEN: ${{ github.token }}
      - uses: benheise/Xenolith/scan/action@main
        with:
          artifact: dist/acme-fw-${{ github.event.release.tag_name }}.bin
          supplier: Acme Networks
          product: Acme Firewall
          version: ${{ github.event.release.tag_name }}
          type: firmware
          source-url: ${{ github.event.release.html_url }}
          submit: "true"
        env:
          GH_TOKEN: ${{ secrets.XENOLITH_SUBMIT_TOKEN }}   # a fine-grained token that can fork and open PRs
```

Without `submit: "true"` the action only scans and uploads `report.html`,
`not-inspected.txt` and `submission.cdx.json` as a workflow artifact for your review.
The report never leaves your repository; only the submission goes to Xenolith, and only
when you ask. Setting `submit` is the attestation that your organization permits
publishing the list.

Pin `ref` to a release tag (`scan/v0.1.0`) once one exists; `main` builds the current
scanner from source with `go install`.
