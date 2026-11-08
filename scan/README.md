# xenolith-scan

What third-party components are inside a commercial product? Point this at the artifact
customers receive (an installer, a firmware image, an appliance disk image, an archive, a
container image) and get two things back:

- `submission.cdx.json`: a minimal CycloneDX 1.6 SBOM that passes Xenolith's
  `python -m xenolith community --check`: product identity, artifact hash, the component
  list with how each one was found and how sure the tool is. No file paths, no evidence
  strings. Safe for a public pull request.
- `report.html`: everything, for your eyes: where each component was found, the string
  or symbol that identified it, and `not-inspected.txt`, the list of what the tool could
  not open (encrypted partitions, formats without a helper). A scan shows what is
  present; it never claims something is absent.

```
xenolith-scan scan acme-fw-7.2.9.bin               # unpack, detect, write ./xenolith-out/
xenolith-scan review xenolith-out                  # keep or drop low-confidence findings
xenolith-scan submit xenolith-out --attest         # open the pull request (gh) or print the upload path
xenolith-scan diff old-scan/ new-scan/             # what changed between two versions
xenolith-scan eval scan/corpus/manifest.yaml       # recall and version accuracy on the evaluation corpus
xenolith-scan helpers                              # which optional unpackers are installed
```

Design and rationale: [`design/xenolith-scan.md`](../design/xenolith-scan.md).
Contributor workflow: [CONTRIBUTING.md §3](../CONTRIBUTING.md#3-submit-an-sbom).

## How it works

1. **Unpack**, recursively and statically, into a private temporary tree: zip/jar, tar,
   gzip, bzip2, xz, zstd, lzma, 7z, ar/deb, rpm, cpio, squashfs, ISO 9660, ext4, raw disk
   images (MBR/GPT), AppImage, Electron asar, and squashfs carved out of firmware blobs
   (router `.chk`/`.trx` images); with optional helpers found on `PATH`: 7-Zip (MSI,
   CAB, NSIS, InstallShield, xar/pkg, DMG, VMDK, qcow2, VHD; MSI files get their
   installed paths back from the MSI tables), innoextract (Inno Setup), unblob
   (firmware blobs, UBI, JFFS2, cramfs). Nothing from the artifact
   is executed, mounted or emulated. Depth, byte and file limits bound the extraction;
   traversal names, links and device files are refused.
2. **Detect** with three layers and merge the evidence per component:
   - [Syft](https://github.com/anchore/syft) (embedded as a library): package databases
     (dpkg, rpm, apk...), language manifests, Go/Rust/.NET/Java binaries, version-string
     classifiers for common native binaries.
   - the Xenolith **fingerprint pack** (`catalog/fingerprints.yaml`, pinned into the
     binary, `--fingerprints` for a newer one): version strings, static data markers,
     defined ELF symbols and PE exports, and what version functions return (a constant
     or a literal; x86, x86-64, AArch64), for the watchlist components and for common
     libraries the census does not track (zlib, SQLite, libpng, Electron, Chromium,
     Node.js and others, marked `watchlist: false`). This is what finds a statically
     linked Brotli or OpenSSL with no package metadata.
   - **notices files inside the product** (THIRD-PARTY-NOTICES, LICENSES.chromium.html,
     embedded CycloneDX/SPDX files).
3. **Identify the product** from what the artifact says (PE VERSIONINFO, Info.plist,
   os-release, image labels, the file name), match it against Xenolith's product registry
   (embedded snapshot, so the result lands on the existing page with its CPE), and confirm
   with you. Nothing is submitted under a guessed name: `--supplier/--product/--version`
   for CI, prompts otherwise.
4. **Emit** the submission and the local report. Findings below 0.7 confidence stay in
   the report unless `review` keeps them. Xenolith reads the confidence and makes
   statements only from findings at or above that line.

| Evidence | Confidence |
|---|---|
| Installed-package database, embedded build info, exact version string | 0.9 |
| Version probe (constant returned by a version function), Syft binary classifier | 0.8 |
| Notices file shipped in the product | 0.75 |
| Declared manifest (lock file) not confirmed by an installed copy | 0.7 |
| Defined symbols (presence, no version) | 0.7 |
| Static data marker, class file present | 0.6 |
| File name only | 0.5 |

Some things Syft reports are not evidence of what ships and are handled accordingly: the
dependencies declared in the `pom.xml` of a bundled library are ignored (counted in
`not-inspected.txt`), a declared dependency without a resolved version drops to 0.5, and
an in-tree kernel module with no version of its own drops to 0.6.

## Evaluation

`scan/corpus/manifest.yaml` lists 24 public artifacts (Debian packages, Python wheels,
npm and Maven packages, an OpenWrt image, Splunk's Universal Forwarder, Visual Studio
Code, Wireshark's Windows installers, Elasticsearch) with ground truth the maker published.
The Windows installers need 7-Zip on `PATH`.
`xenolith-scan eval` downloads them, checks the hashes, scans and prints recall, version
accuracy and watchlist recall per artifact; `eval.json` has the missed, wrong-version and
unlisted lists. Current results and the defects the corpus found are in the
[design doc](../design/xenolith-scan.md#real-artifact-proofs-november-2026).

## Building

Go 1.26 or newer. From this directory:

```
make build        # copies the fingerprint pack and registry snapshot in, builds ./xenolith-scan
make test
```

Releases are built by `.github/workflows/release-scan.yml` on tags `scan/vX.Y.Z`:
linux, macOS and Windows on amd64 and arm64 plus linux arm/riscv64/ppc64le/s390x, signed
with Sigstore cosign (keyless), with checksums, SLSA build provenance and the tool's own SBOM.
Vendors can run the same binary in CI with the composite action in [`action/`](action/).

## Privacy and safety

- No network during a scan (the one exception: a `registry:` image reference is pulled
  by Syft). `submit` talks to GitHub only when you run it; nothing else phones home.
- The submission carries the artifact's SHA-256 and file name, never its path, and never
  host paths, user names or build directories from the machine that ran the scan.
- Helpers run with a timeout, an empty environment and the extraction directory as
  their working directory. Encrypted content is listed as not inspected; the tool holds
  no keys and attempts no decryption.
- Get permission before scanning and before submitting: see the contributor workflow.
