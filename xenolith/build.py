"""Merge stored assertions and the product spine into the static site's data files.

Inputs (committed, the open data dump):
  data/assertions/**/*.ndjson
  data/spine/products.ndjson

Outputs (served by GitHub Pages):
  docs/data/meta.json                build info, sources, components and counts
  docs/data/products.json            every product: name, per-component verdict, spine stats
  docs/data/components/<id>.json     every assertion about one component
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .catalog import Catalog
from .model import dedupe, read_ndjson

EVIDENCE_RANK = {
    "vendor-advisory": 0,
    "vendor-sbom": 1,
    "binary-scan": 2,
    "notices-file": 3,
    "community": 4,
    "tracker": 5,
}

COMPARABLES = [
    {"name": "deps.dev (Open Source Insights)", "url": "https://deps.dev/",
     "covers": "Resolved dependency graphs and dependents for open source packages (npm, Maven, PyPI, Go, Cargo, NuGet, RubyGems)."},
    {"name": "ecosyste.ms", "url": "https://ecosyste.ms/",
     "covers": "Packages, dependent repositories and Docker image SBOMs across 100+ open source registries."},
    {"name": "OSV.dev", "url": "https://osv.dev/",
     "covers": "Open source vulnerabilities mapped to package versions."},
    {"name": "GitHub Advisory Database", "url": "https://github.com/advisories",
     "covers": "Reviewed advisories for open source packages, with Dependabot dependents."},
    {"name": "Repology", "url": "https://repology.org/",
     "covers": "Which Linux and BSD distributions package which open source project, and at what version."},
    {"name": "Census III of Free and Open Source Software", "url": "https://www.linuxfoundation.org/press/open-source-usage-trends-and-security-challenges-revealed-in-new-study",
     "covers": "Linux Foundation / Harvard ranking of the most widely used open source libraries."},
]

FRONTEND_NOTES_LIMIT = 320
FRONTEND_REFS_LIMIT = 4


def _collapse_csaf_duplicates(assertions: list[dict]) -> list[dict]:
    """One vendor often publishes the same statement in two documents (advisory + VEX).
    Keep the newest and list the other document as a reference."""
    keep: dict[tuple, dict] = {}
    rest: list[dict] = []
    for a in assertions:
        if a["source"] != "csaf":
            rest.append(a)
            continue
        key = (a["publisher"], a["component"], a["product_key"], a["version"], json.dumps(a["cves"], sort_keys=True))
        prev = keep.get(key)
        if prev is None:
            keep[key] = a
            continue
        newer, older = (a, prev) if a["updated"] > prev["updated"] else (prev, a)
        if older["source_url"] not in newer["references"]:
            newer["references"] = [older["source_url"]] + newer["references"]
        keep[key] = newer
    return rest + list(keep.values())


def load_assertions(data_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted((data_dir / "assertions").rglob("*.ndjson")):
        rows.extend(read_ndjson(path))
    return dedupe(_collapse_csaf_duplicates(rows))


def _best(assertions: list[dict]) -> dict:
    """The assertion shown as a product's headline status for one component:
    the most authoritative evidence type, newest first within that type."""
    newest_first = sorted(assertions, key=lambda a: a["updated"], reverse=True)
    return min(newest_first, key=lambda a: EVIDENCE_RANK.get(a["evidence"], 9))


def build(catalog: Catalog, data_dir: Path, out_dir: Path, *, spine_min_cves: int = 10) -> dict:
    assertions = load_assertions(data_dir)
    spine = list(read_ndjson(data_dir / "spine" / "products.ndjson"))
    spine_by_key = {p["key"]: p for p in spine}

    by_component: dict[str, list[dict]] = defaultdict(list)
    by_product: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    names: dict[str, tuple[str, str]] = {}
    for a in assertions:
        by_component[a["component"]].append(a)
        by_product[a["product_key"]][a["component"]].append(a)
        names.setdefault(a["product_key"], (a["supplier"], a["product"]))

    comp_dir = out_dir / "components"
    comp_dir.mkdir(parents=True, exist_ok=True)
    for old in comp_dir.glob("*.json"):
        if old.stem not in by_component:
            old.unlink()

    components_meta = []
    for comp in catalog.components.values():
        rows = sorted(by_component.get(comp.id, []),
                      key=lambda a: (a["supplier"].lower(), a["product"].lower(), a["version"]))
        slim = []
        for a in rows:
            slim.append({
                "k": a["product_key"], "s": a["supplier"], "p": a["product"], "v": a["version"],
                "c": a["cves"], "st": a["verdict"], "e": a["evidence"], "src": a["source"],
                "pub": a.get("publisher", ""), "u": a["source_url"],
                "r": a["references"][:FRONTEND_REFS_LIMIT],
                "n": a["notes"][:FRONTEND_NOTES_LIMIT], "cat": a.get("category"), "d": a["updated"],
            })
        (comp_dir / f"{comp.id}.json").write_text(json.dumps(slim, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        verdicts = Counter(a["verdict"] for a in rows)
        components_meta.append({
            "id": comp.id, "name": comp.name, "upstream": comp.upstream, "purl": comp.purl,
            "cpe": comp.cpe, "aliases": comp.aliases, "incidents": comp.incidents,
            "assertions": len(rows), "products": len({a["product_key"] for a in rows}),
            "contains": sum(1 for a in rows if a["contains"] is True),
            "verdicts": dict(verdicts),
        })

    products = []
    for key, comps in by_product.items():
        supplier, product = names[key]
        sp = spine_by_key.get(key)
        products.append({
            "k": key, "s": supplier, "p": product,
            "c": {cid: _best(rows)["verdict"] for cid, rows in sorted(comps.items())},
            "n": sum(len(r) for r in comps.values()),
            **({"cv": sp["cve_count"], "kev": sp["kev_count"]} if sp else {}),
        })
    spine_only = 0
    for sp in spine:
        if sp["key"] in by_product:
            continue
        if sp["kev_count"] == 0 and sp["cve_count"] < spine_min_cves:
            continue
        products.append({"k": sp["key"], "s": sp["supplier"], "p": sp["product"], "c": {}, "n": 0,
                         "cv": sp["cve_count"], "kev": sp["kev_count"]})
        spine_only += 1
    products.sort(key=lambda p: (p["s"].lower(), p["p"].lower()))
    (out_dir / "products.json").write_text(json.dumps(products, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    source_counts = Counter(a["source"] for a in assertions)
    source_dates: dict[str, str] = {}
    for a in assertions:
        if a["updated"] > source_dates.get(a["source"], ""):
            source_dates[a["source"]] = a["updated"]
    publishers = Counter(a.get("publisher") or a.get("category") for a in assertions if a["source"] == "csaf")
    sources_meta = []
    for sid, s in catalog.sources.items():
        entry = {**s, "assertions": source_counts.get(sid, 0), "latest": source_dates.get(sid, "")}
        if sid == "cvelist":
            entry["products"] = len(spine)
        if sid == "csaf":
            entry["publishers"] = dict(publishers.most_common())
        sources_meta.append(entry)

    meta = {
        "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "assertions": len(assertions),
            "products_with_data": len(by_product),
            "spine_products": len(spine),
            "spine_only_shown": spine_only,
            "components": len(catalog.components),
        },
        "components": components_meta,
        "sources": sources_meta,
        "comparables": COMPARABLES,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return meta["counts"]
