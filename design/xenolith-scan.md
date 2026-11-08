# xenolith-scan: design recommendation

**Status:** implemented through phase 4 in [`scan/`](../scan/README.md) (November 2026); see the delivery plan at the end for what each phase delivered and what is still open. The Python pieces that came first remain ([CONTRIBUTING.md §3](../CONTRIBUTING.md#3-submit-an-sbom)): `python -m xenolith fingerprint`, the reference implementation of the watchlist detection (fingerprints in [`catalog/fingerprints.yaml`](../catalog/fingerprints.yaml), shared with the Go scanner and checked identical by its tests), and `python -m xenolith prepare`, which turns any scanner's output into a submission.

## The problem it solves

Someone has a copy of a commercial product (a firmware image, an installer, an appliance VM, a container image) and wants to know what third-party components are inside. Often that person works for the vendor and still doesn't know: the product was assembled over years by teams that are gone, components came in through SDKs and toolchains, and nobody kept a list. Today they would need to know which unpacker handles the format, which scanner finds statically linked libraries, how to read a CycloneDX file, and what Xenolith needs on top of it.

`xenolith-scan` should make that one command, on whatever laptop they have:

```
xenolith-scan acme-fw-7.2.9.bin
```

and produce two things:

1. **A submission file**: a minimal CycloneDX 1.6 SBOM that passes `python -m xenolith community --check`, holding only the product's identity, the artifact's hash and the component list. It is safe to put in a public pull request.
2. **A local report** that never leaves the machine: every component with where it was found, the evidence string or symbol that identified it, the confidence, and a list of everything the tool couldn't open.

## Principles

- **Assemble, don't reinvent.** Mature open source engines already do most of the detection. Xenolith's value is the glue: unpacking chained formats, a fingerprint pack tuned to embedded components, product identity, privacy stripping, and the submission format.
- **Static analysis only.** The tool never executes, mounts or emulates anything from the artifact. That is what makes it safe on hostile input and lets an x86 laptop analyze ARM, MIPS or PowerPC firmware.
- **Offline by default.** No network access during a scan, no telemetry. The network is used only by an explicit `submit` and an optional fingerprint update.
- **Say what was not inspected.** A scan can show that a component is present. It can never show that one is absent (encrypted partitions, unknown formats, stripped binaries), so the tool never emits "absent" and always lists what it couldn't open.
- **Presence, not exposure.** Results become `present` statements with the version as detected. Vendors backport fixes without changing version strings, so "affected" stays the vendor's call (Xenolith already flags versions inside a CVE's range as a reason to ask).

## Recommended architecture

```
                 artifact (file, folder, image ref)
                               │
 1. Intake ── identify type, hash original, read product metadata (MSI, PE, Info.plist, os-release, firmware header)
                               │
 2. Unpack ── built-in Go extractors ──► optional helpers (unblob, 7-Zip, innoextract) ──► sandboxed temp tree
                               │                                   ▲
                               │          recurse into anything new (depth, size and count limits)
                               ▼
 3. Detect ── a. package databases & manifests  (Syft catalogers: dpkg, rpm, apk, opkg, jar, npm, pip, …)
              b. embedded build info             (Go buildinfo, cargo-auditable, .NET deps/PE, jar pom.properties)
              c. version-string classifiers      (Syft binary classifiers + Xenolith fingerprint pack)
              d. symbol / data fingerprints      (exported symbols, static tables, version probes)
              e. notices files inside the product (THIRD-PARTY-NOTICES, licenses/, LICENSES.chromium.html)
                               │
 4. Resolve ── canonical name + purl + CPE, merge evidence per component, confidence score
                               │
 5. Identify product ── prefill from metadata, match against Xenolith's product registry, confirm with user
                               │
 6. Emit ── submission.cdx.json (minimal, validated)  +  report.html (full, local only)
                               │
 7. Submit (optional) ── gh fork → branch → PR, or print the web upload link
```

### Language and distribution: Go, one static binary

Go is the right base because the two strongest engines are Go libraries under Apache-2.0, the same license as Xenolith: [Syft](https://github.com/anchore/syft) (Anchore) and [OSV-SCALIBR](https://github.com/google/osv-scalibr) (Google). Both can be embedded as libraries rather than driven as subprocesses. Go's standard library parses ELF, PE and Mach-O for every architecture (`debug/elf`, `debug/pe`, `debug/macho`), and `CGO_ENABLED=0` builds give one self-contained executable per target with no runtime to install.

Two notions of "architecture" need keeping apart:

| | What it means | How it's covered |
|---|---|---|
| **Host** | The machine the tool runs on | Release builds for linux, macOS and Windows on amd64 and arm64 (six binaries), plus linux on armv7, riscv64, ppc64le and s390x for running on servers and appliances |
| **Target** | The architecture of the binaries being analyzed | Irrelevant to the host: analysis is static, so any build reads x86, ARM, MIPS, PowerPC and RISC-V binaries |

Build and release with GoReleaser on GitHub Actions: sign every binary with Sigstore cosign (keyless), publish SLSA build provenance, publish the tool's own SBOM, and distribute through GitHub Releases, Homebrew, winget/Scoop and a container image. An organization that has to approve tools before employees run them can then verify exactly what it is approving.

### Engines and helpers

| Tool | Role | Language, license | How to use it |
|---|---|---|---|
| [Syft](https://github.com/anchore/syft) | Core cataloging: package databases, language manifests, Go/Rust/.NET/Java binaries, version-string classifiers for common native binaries | Go, Apache-2.0 | Embed as a library |
| [OSV-SCALIBR](https://github.com/google/osv-scalibr) | Second extractor set, strongest on Linux hosts and images | Go, Apache-2.0 | Embed selectively where it adds coverage; Windows/macOS support is still experimental |
| [unblob](https://github.com/onekey-sec/unblob) | Recursive firmware unpacking (30+ archive, compression and filesystem formats), carving of unknown chunks | Python + Rust, MIT | Optional helper: auto-detected on `PATH`, or run from its container image |
| 7-Zip, [innoextract](https://constexpr.org/innoextract/) | MSI, NSIS, Inno Setup, DMG, VMDK and other formats Go libraries don't cover well | C/C++ | Optional helpers |
| [cve-bin-tool](https://github.com/ossf/cve-bin-tool) | Several hundred version checkers for common native libraries | Python, **GPL-3.0** | Optional external cross-check only; don't copy its checkers into the Apache-licensed tool |
| [blint](https://github.com/owasp-dep-scan/blint) | ELF/PE/Mach-O/Android SBOMs; symbol database for statically linked native libraries | Python | Optional deep mode for vendored native code |

A "full" container image bundles every helper for people who can run Docker; the plain binary degrades gracefully and lists anything it skipped because a helper was missing.

### Unpacking

Most real artifacts are nested: an OVA holds a VMDK holding partitions holding a squashfs holding a JAR holding shaded JARs. The unpacker recurses until nothing new opens, with hard limits on depth (default 10), total extracted bytes (default 50× the input, capped) and file count. It refuses path traversal and symlinks pointing outside the extraction root, skips device files, never follows links on the host, and works in a private temp directory it deletes afterwards (`--keep` to retain it).

| Artifact | Handled by |
|---|---|
| zip, tar, gzip, bzip2, xz, zstd, cpio, ar/deb, rpm, ISO 9660, squashfs | Built in (Go libraries) |
| Container images (registry, OCI or docker archive) | Built in (Syft's image source) |
| JAR/WAR/EAR, nested and shaded jars, Electron `app.asar`, AppImage, snap | Built in |
| MSI, NSIS, Inno Setup, DMG, macOS PKG (xar/pbzx) | 7-Zip, innoextract (helpers) |
| Firmware blobs, UBI/UBIFS, JFFS2, YAFFS, cramfs, vendor containers | unblob (helper) |
| OVA, VMDK, qcow2, VHD(X), raw disk images with ext4/XFS/NTFS | go-diskfs where it can; 7-Zip or unblob otherwise |
| Encrypted or signed-and-encrypted images | **Not attempted.** Listed as not inspected; the tool contains no keys and does no decryption |

### Detection layers and confidence

Each finding records how it was made, and the strongest evidence wins when several layers find the same component:

| Layer | Example | Confidence |
|---|---|---|
| Package database | `/var/lib/dpkg/status` lists `libbrotli1 1.0.9-2+b6` | High |
| Embedded build info | Go buildinfo, cargo-auditable data, `META-INF/maven/.../pom.properties` | High |
| Notices file shipped in the product | `THIRD-PARTY-NOTICES.txt` lists `zlib 1.2.13` | High for presence, medium for version |
| Version-string classifier | `OpenSSL 3.0.13 30 Jan 2024`, `deflate 1.2.13 Copyright`, `libcurl/8.5.0`, `expat_2.5.0` | Medium to high |
| Symbol or data fingerprint | Exported `BrotliDecoderDecompressStream` plus Brotli's built-in dictionary | Medium for presence, version unknown |
| Version probe | The constant returned by `BrotliDecoderVersion`, read from its disassembly | Medium |
| File name only | `libfoo.so.1.2` with nothing else | Low, excluded from the submission by default |

Brotli shows why the fingerprint layer matters: the library carries no human-readable version string, so string classifiers miss it, yet its exported symbols and its large static dictionary are distinctive. That is the layer that would have found the vendored decoders in the October 2026 hunt.

**The fingerprint pack lives in this repository**, as [`catalog/fingerprints.yaml`](../catalog/fingerprints.yaml) next to `components.yaml` (it exists now, with the Python reference scanner): per watchlist component, the version-string regexes, distinctive symbols, data signatures and version probes. The scanner embeds a pinned copy at build time and can load a newer one with `--fingerprints`. Adding detection for the next incident's component is then a pull request here, reviewed with the same test fixtures, rather than a scanner release.

Notices files found inside the product are parsed with the same extractors Xenolith uses for vendor notices documents (`xenolith/sources/notices.py`); port the text extractors to Go and share the existing test fixtures so both behave identically.

### Product identity

The submission needs the vendor, product and version as Xenolith knows them. The tool prefills them from the artifact (MSI `Manufacturer`/`ProductName`/`ProductVersion`, PE `VERSIONINFO`, macOS `Info.plist`, `/etc/os-release`, firmware headers, image labels), then fuzzy-matches against a bundled snapshot of Xenolith's product registry (`docs/data/products.json`, which carries CPEs) so the result lands on the existing product page. The user confirms or corrects; nothing is submitted under a guessed name.

### Output

The submission file follows [CONTRIBUTING.md §3](../CONTRIBUTING.md#3-submit-an-sbom), with CycloneDX 1.6 fields carrying the extra detail:

| Content | CycloneDX field |
|---|---|
| Product, vendor, version, CPE | `metadata.component`, `metadata.supplier` |
| Scanner and engine versions, fingerprint pack version | `metadata.tools.components[]` |
| Artifact name, SHA-256, evidence type, attestation | `metadata.properties` (`xenolith:*`) |
| Component identity | `name`, `version`, `purl`, `cpe` |
| How it was found and how sure | `evidence.identity[]` with `methods[].technique` (`manifest-analysis`, `binary-analysis`, `hash-comparison`, `filename`) and `confidence` |

It deliberately omits file paths, evidence strings and anything from the vendor's own code; those stay in the local report. Low-confidence findings are excluded unless the user reviews and keeps them.

Matching change on the Xenolith side: read `evidence.identity[].confidence` during intake and turn only findings at 0.7 or above into statements, keeping the rest searchable in the inventory.

### Command-line shape

```
xenolith-scan scan <artifact>...      unpack, detect, write ./xenolith-out/
      --supplier --product --version  skip the prompts (CI use)
      --helpers auto|none|container   which optional helpers to use
      --max-depth 10 --max-bytes 50G  unpacking limits
      --fingerprints FILE             newer fingerprint pack
xenolith-scan review ./xenolith-out   table of findings: keep or drop each low-confidence item
xenolith-scan submit ./xenolith-out   --attest; fork, branch and open the PR with gh, or print the upload link
```

`./xenolith-out/` holds `submission.cdx.json`, `report.html`, `not-inspected.txt` and `scan.log`.

## The contributor's workflow

For an employee who doesn't know what's in their own company's product:

1. **Get permission first.** Ask whoever owns open source compliance or product security (an OSPO, PSIRT or legal). Frame it as the company publishing its own component list, which customers increasingly ask for anyway.
2. **Scan what ships, not the source tree.** Run the tool on the artifact customers receive. What's in the build system and what's in the shipped image differ, and customers are exposed to the second. If the source is available, a build-time SBOM (Syft or cdxgen on the build output, Yocto's `create-spdx`) is a useful cross-check.
3. **Review the local report.** Confirm the product identity, look at low-confidence findings, and read `not-inspected.txt` to see what the tool couldn't open.
4. **Best outcome: the company publishes it.** Put the SBOM or notices file at a stable public URL and contribute that URL (`catalog/notices.yaml`, or a `vendor-sbom` submission). It then carries the vendor's authority and stays current with each release.
5. **Otherwise submit the scan** with `xenolith-scan submit --attest`, which opens a pull request with the file and a filled-in template. CI validates it and a maintainer merges it.

A customer or researcher follows the same steps, except step 1 becomes reading the product's license terms. Some EULAs restrict reverse engineering, and the rules differ by country. A static inventory is far less intrusive than disassembly, but this is not legal advice: when in doubt, don't submit, and never circumvent encryption or copy protection.

For vendors who want to do this every release, ship a GitHub Action wrapping the same binary: it scans release artifacts and opens a pull request here automatically.

## Delivery plan

| Phase | Scope | Status |
|---|---|---|
| **0** | `python -m xenolith prepare`: converts Syft, cdxgen, cve-bin-tool, blint or Trivy output (CycloneDX or SPDX) into a validated submission. `python -m xenolith fingerprint` and `catalog/fingerprints.yaml`: version strings, defined ELF symbols, version-function constants (x86-64, AArch64), static data markers and archive metadata for all 13 watchlist components | **Done.** Tests on synthetic samples; the pack was checked against real builds (OpenSSL in the cryptography wheel, Brotli's version probe in the Brotli wheel) |
| **1: MVP** | Go CLI with Syft embedded; directories, common archives, deb/rpm and container images; the fingerprint pack pinned into the binary; product prompts with registry matching; submission and local report; signed releases for six host targets (plus linux arm, riscv64, ppc64le, s390x) | **Done** (`scan/`). `.github/workflows/release-scan.yml` builds, signs (cosign keyless), attests (GitHub build provenance + SLSA generic generator) and attaches a Syft SBOM per archive. The 90 % recall bar is measured by `xenolith-scan eval` on `scan/corpus/manifest.yaml`: 100 % on the two watchlist artifacts in the corpus so far; the corpus needs vendor artifacts with published notices to be a real test |
| **2: Installers and firmware** | MSI, NSIS, Inno, DMG/PKG, AppImage/snap, OVA/VMDK/qcow2; unblob helper and the "full" container image; notices files inside products; Electron and nested jars | **Done except the container image.** Built in: squashfs, ISO 9660, ext4, raw disk images with MBR/GPT, AppImage, Electron asar, nested jars, 7z. Through helpers found on `PATH`: 7-Zip (MSI, CAB, NSIS, InstallShield, xar/pkg, DMG, VMDK, qcow2, VHD/VHDX), innoextract (Inno Setup), unblob (UBI, JFFS2, cramfs, unknown firmware blobs). Notices files inside the product are parsed with a Go port of the text extractors. Running helpers from a bundled container image is not implemented; a missing helper is listed in `not-inspected.txt` |
| **3: Vendored code** | Symbol and data fingerprints, version probes, confidence scoring, optional blint deep mode, `review` and `submit` commands | **Done except blint.** Confidence scoring merges Syft catalogers, fingerprints and notices files per component (0.9 package metadata or exact string, 0.8 probe or classifier, 0.75 notices file, 0.7 declared manifest or defined symbols, 0.6 marker, 0.5 file name); findings below 0.7 stay local unless `review` keeps them, and Xenolith's intake reads the confidence and makes statements only at or above 0.7 |
| **4: At scale** | GitHub Action for vendors, diffing two versions of a product, read-only collection from a running appliance (with the owner's approval) | **Action and diff done** (`scan/action/`, `xenolith-scan diff`). Collection from a running appliance is deliberately not started: it needs a design of its own for consent, scope and what leaves the device |

### Evaluation corpus

Xenolith already holds the best ground truth available: vendors' own notices documents and dependency reports for specific product versions. Where the matching artifact is freely downloadable (Elastic publishes both per release, for example), scan it and compare. `scan/corpus/manifest.yaml` is that corpus: URLs, hashes and a ground-truth inventory per artifact (the maker's own statement of what it bundles); `xenolith-scan eval scan/corpus/manifest.yaml` downloads, scans and reports recall per artifact and for the watchlist specifically, writing the missed and extra lists to `eval.json`. Measure recall against the vendor's list and treat anything the scanner finds that the vendor didn't list as something to investigate: it is either a false positive or a gap in the vendor's notices, and both are worth knowing. Keep the corpus as a manifest of download URLs and hashes, never the binaries themselves.

## Security of the tool itself

The tool reads attacker-controlled input by design. Run every parser under the unpacking limits, fuzz the extractors (Go's native fuzzing), run optional helpers in their container image when Docker is available, never execute or mount artifact content, and keep the dependency set small and pinned with automated update PRs. Treat a parser crash on a malformed artifact as a bug to fix, not a scan result.
