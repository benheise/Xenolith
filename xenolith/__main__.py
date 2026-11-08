"""Command line entry point: python -m xenolith <command>."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import build as build_mod
from . import catalog as catalog_mod
from . import fingerprint as fingerprint_mod
from . import prepare as prepare_mod
from . import wanted as wanted_mod
from .catalog import ROOT
from .model import dedupe, write_ndjson
from .sources import cisa_log4j, community, community_sbom, csaf, cvelist, ncsc_markdown, notices

DATA = ROOT / "data"
DOCS_DATA = ROOT / "docs" / "data"

TRACKERS = [
    # (source id, repo, directory name under --src, default component)
    ("ncsc-nl-php2shell", "NCSC-NL/php2shell", "php"),
    ("ncsc-nl-log4shell", "NCSC-NL/log4shell", "log4j-core"),
    ("cisa-log4j", "cisagov/log4j-affected-db", "log4j-core"),
]


def _git(repo: Path, fmt: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(repo), "log", "-1", f"--format={fmt}"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def cmd_trackers(args) -> int:
    cat = catalog_mod.load()
    src = Path(args.src)
    for source_id, repo, default_comp in TRACKERS:
        path = src / repo.replace("/", "_")
        if not path.exists():
            print(f"- {source_id}: {path} not found, skipped")
            continue
        commit = _git(path, "%H") or "main"
        as_of = _git(path, "%cs") or ""
        if source_id == "cisa-log4j":
            rows, stats = cisa_log4j.ingest(path, catalog=cat, commit=commit)
        else:
            rows, stats = ncsc_markdown.ingest(
                path, source_id=source_id, repo_url=f"https://github.com/{repo}",
                default_component=default_comp, catalog=cat, as_of=as_of, commit=commit)
        n = write_ndjson(DATA / "assertions" / "trackers" / f"{source_id}.ndjson", dedupe(rows))
        print(f"- {source_id} @ {commit[:10]} ({as_of}): {n} assertions  {json.dumps(stats)}")
    return 0


def cmd_csaf(args) -> int:
    cat = catalog_mod.load()
    results = csaf.crawl(ROOT / "catalog" / "csaf_providers.yaml", catalog=cat, data_dir=DATA,
                         only=args.only, max_fetch=args.max_fetch, discover=not args.no_discover)
    failed = [r for r in results if "error" in r]
    print(f"{len(results) - len(failed)} providers crawled, {len(failed)} unreachable")
    return 0


def cmd_notices(args) -> int:
    cat = catalog_mod.load()
    if not args.match_only:
        stats = notices.crawl(ROOT / "catalog" / "notices.yaml", data_dir=DATA, max_fetch=args.max_fetch,
                              refresh_days=args.refresh_days, only=args.only, discover_docs=not args.no_discover)
        print(f"notices crawl: {json.dumps(stats)}")
    rows, stats = notices.assertions(cat, DATA)
    n = write_ndjson(DATA / "assertions" / "notices.ndjson", dedupe(rows))
    print(f"notices: {n} assertions from {stats['inventories']} inventories ({stats['components']} components)")
    return 0


def cmd_community(args) -> int:
    """Validate (and unless --check, ingest) community/assertions.csv and community/sboms/; validate catalog/wanted.yaml."""
    cat = catalog_mod.load()
    rows, errors = community.load(ROOT / "community" / "assertions.csv", cat)
    sboms, sbom_errors = community_sbom.load_all(ROOT)
    errors += sbom_errors
    errors += wanted_mod.validate(wanted_mod.load(ROOT / "catalog" / "wanted.yaml"), set(cat.components))
    for e in errors:
        print(f"::error::{e}")
    if errors:
        print(f"{len(errors)} problem(s) found; see CONTRIBUTING.md for the required formats")
        return 1
    if not args.check:
        write_ndjson(DATA / "assertions" / "community.ndjson", dedupe(rows))
        community_sbom.write_inventories(sboms, DATA)
        nrows, _ = notices.assertions(cat, DATA)
        write_ndjson(DATA / "assertions" / "notices.ndjson", dedupe(nrows))
    print(f"community: {len(rows)} valid rows, {len(sboms)} valid SBOM file(s)")
    return 0


def cmd_spine(args) -> int:
    kev = cvelist.load_kev(Path(args.kev) if args.kev else None)
    out, stats = cvelist.build(Path(args.cves) if args.cves else None, kev, min_cves=args.min_cves)
    n = write_ndjson(DATA / "spine" / "products.ndjson", out)
    print(f"spine: {n} products  {json.dumps(stats)}")
    return 0


def cmd_build(args) -> int:
    cat = catalog_mod.load()
    counts = build_mod.build(cat, DATA, DOCS_DATA, spine_min_cves=args.spine_min_cves)
    print(f"built docs/data: {json.dumps(counts)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="xenolith", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("trackers", help="ingest NCSC-NL and CISA incident trackers from local clones")
    t.add_argument("--src", default="src", help="directory holding clones named Owner_repo")
    t.set_defaults(fn=cmd_trackers)

    c = sub.add_parser("csaf", help="crawl CSAF providers for watchlist CVEs (incremental)")
    c.add_argument("--only", nargs="*", help="only providers whose name contains one of these strings")
    c.add_argument("--max-fetch", type=int, help="override per-provider fetch cap for this run")
    c.add_argument("--no-discover", action="store_true", help="skip aggregator discovery")
    c.set_defaults(fn=cmd_csaf)

    n = sub.add_parser("notices", help="parse vendor third-party notices into component inventories")
    n.add_argument("--only", nargs="*", help="only documents whose supplier/product contains one of these strings")
    n.add_argument("--max-fetch", type=int, default=80, help="documents fetched per run")
    n.add_argument("--refresh-days", type=int, default=14, help="re-fetch documents older than this")
    n.add_argument("--no-discover", action="store_true", help="skip index-page discovery")
    n.add_argument("--match-only", action="store_true", help="re-match stored inventories without fetching")
    n.set_defaults(fn=cmd_notices)

    m = sub.add_parser("community", help="validate and ingest community/assertions.csv")
    m.add_argument("--check", action="store_true", help="validate only, write nothing")
    m.set_defaults(fn=cmd_community)

    f = sub.add_parser("fingerprint", help="find watchlist components in a file, folder or archive (offline)")
    f.add_argument("target", help="extracted firmware or install folder, or an archive (zip, jar, war, tar, tgz)")
    f.add_argument("-o", "--output", help="write the findings as CycloneDX JSON (input for `prepare`)")
    f.add_argument("--min-confidence", type=float, default=0.0, help="drop findings below this confidence (0-1)")
    f.add_argument("--fingerprints", help="alternative fingerprints file (default catalog/fingerprints.yaml)")
    f.add_argument("-v", "--verbose", action="store_true", help="list items that could not be inspected")
    f.set_defaults(fn=fingerprint_mod.run)

    r = sub.add_parser("prepare", help="turn a Syft/cdxgen/cve-bin-tool SBOM into a community/sboms submission")
    r.add_argument("scan", help="CycloneDX or SPDX JSON written by the scanner")
    r.add_argument("--supplier", required=True, help="vendor of the product, e.g. \"Example Networks\"")
    r.add_argument("--product", required=True, help="product name as the vendor writes it")
    r.add_argument("--version", required=True, help="product version that was scanned")
    r.add_argument("--artifact", required=True,
                   help="the original file you scanned (its sha256 is computed), or a download URL / image digest")
    r.add_argument("--artifact-sha256", help="sha256 of the artifact, if --artifact is not a local file")
    r.add_argument("--evidence", choices=sorted(community_sbom.EVIDENCE), default="binary-scan")
    r.add_argument("--source-url", help="public https link to the vendor's SBOM (required for vendor-sbom)")
    r.add_argument("--product-type", choices=prepare_mod.PRODUCT_TYPES, default="application")
    r.add_argument("--attest", action="store_true",
                   help="confirm you are permitted to share this component list (sets xenolith:attestation=yes)")
    r.add_argument("-o", "--output", help="output path (default community/sboms/<supplier>/<product>--<version>.cdx.json)")
    r.set_defaults(fn=lambda a: prepare_mod.run(a, ROOT, catalog_mod.load()))

    s = sub.add_parser("spine", help="build the product spine from cvelistV5 and CISA KEV")
    s.add_argument("--cves", help="path to an extracted cvelistV5 'cves' directory (omit for KEV-only)")
    s.add_argument("--kev", help="local KEV CSV (default: download from cisagov/kev-data)")
    s.add_argument("--min-cves", type=int, default=3, help="keep non-KEV products with at least this many CVEs")
    s.set_defaults(fn=cmd_spine)

    b = sub.add_parser("build", help="build docs/data for the GitHub Pages site")
    b.add_argument("--spine-min-cves", type=int, default=10,
                   help="list products with no composition data yet only if they have KEV entries or this many CVEs")
    b.set_defaults(fn=cmd_build)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
