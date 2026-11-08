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
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .catalog import Catalog, normalize_name
from .model import dedupe, product_key, read_ndjson
from .sources.notices import iter_inventories
from .versions import check as range_check
from . import crosswalk
from . import wanted as wanted_mod
from .catalog import CATALOG

EVIDENCE_RANK = {
    "vendor-advisory": 0,
    "vendor-sbom": 1,
    "binary-scan": 2,
    "community": 3,
    "tracker": 4,
    "notices-file": 5,   # proves presence, says nothing about CVE status; never the headline if anything else exists
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
    # Re-key with the current identity rules so alias changes apply without re-ingesting.
    for a in rows:
        a["product_key"] = product_key(a["supplier"], a["product"])
    return dedupe(_collapse_csaf_duplicates(rows))


def load_spine(data_dir: Path) -> list[dict]:
    """Registry entries re-keyed and merged when several names map to one product."""
    merged: dict[str, dict] = {}
    for sp in read_ndjson(data_dir / "spine" / "products.ndjson"):
        key = product_key(sp["supplier"], sp["product"])
        prev = merged.get(key)
        if prev is None or sp["cve_count"] > prev["cve_count"]:
            entry = {**sp, "key": key}
            if prev is not None:
                entry["kev_count"] = max(entry["kev_count"], prev["kev_count"])
            merged[key] = entry
        else:
            prev["kev_count"] = max(prev["kev_count"], sp["kev_count"])
    return list(merged.values())


def _best(assertions: list[dict]) -> dict:
    """The assertion shown as a product's headline status for one component:
    the most authoritative evidence type, newest first within that type."""
    newest_first = sorted(assertions, key=lambda a: a["updated"], reverse=True)
    return min(newest_first, key=lambda a: EVIDENCE_RANK.get(a["evidence"], 9))


def build(catalog: Catalog, data_dir: Path, out_dir: Path, *, spine_min_cves: int = 10) -> dict:
    assertions = load_assertions(data_dir)
    spine = load_spine(data_dir)

    # Link entries that share a CPE vendor:product (registry CPEs from CVE records,
    # CPEs from vendor CSAF product trees), then fold them onto one key.
    links: dict[str, set[str]] = defaultdict(set)
    weight: dict[str, float] = defaultdict(float)
    for sp in spine:
        weight[sp["key"]] += sp["cve_count"] + 10 * sp["kev_count"]
        for c in sp.get("cpe") or []:
            if (vp := crosswalk.normalize_cpe(c)):
                links[vp].add(sp["key"])
    for a in assertions:
        weight[a["product_key"]] += 1
        for c in a.get("cpes") or []:
            if (vp := crosswalk.normalize_cpe(c)):
                links[vp].add(a["product_key"])
    remap, clusters = crosswalk.build(links, weight)
    for a in assertions:
        a["product_key"] = remap.get(a["product_key"], a["product_key"])
    spine = _merge_spine(spine, remap)
    product_cpes: dict[str, set[str]] = defaultdict(set)
    for vp, keys in links.items():
        for k in keys:
            product_cpes[remap.get(k, k)].add(vp)
    (out_dir / "crosswalk.json").parent.mkdir(parents=True, exist_ok=True)
    (out_dir / "crosswalk.json").write_text(json.dumps(clusters, ensure_ascii=False, indent=0), encoding="utf-8")
    spine_by_key = {p["key"]: p for p in spine}

    by_component: dict[str, list[dict]] = defaultdict(list)
    by_product: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    name_votes: dict[str, Counter] = defaultdict(Counter)
    for a in assertions:
        by_component[a["component"]].append(a)
        by_product[a["product_key"]][a["component"]].append(a)
        name_votes[a["product_key"]][(a["supplier"], a["product"])] += 1
    # Display name: the most common spelling across sources, preferring the registry's.
    for sp in spine:
        if sp["key"] in name_votes:
            name_votes[sp["key"]][(sp["supplier"], sp["product"])] += 3
    names: dict[str, tuple[str, str]] = {k: v.most_common(1)[0][0] for k, v in name_votes.items()}

    comp_dir = out_dir / "components"
    comp_dir.mkdir(parents=True, exist_ok=True)
    for old in comp_dir.glob("*.json"):
        if old.stem not in by_component:
            old.unlink()

    # Provenance shared by most of a source's rows (a tracker's repository, say) is sent once in
    # meta.sources; a row carries found_via / discovery_path only when it differs from that.
    prov_votes: dict[str, Counter] = defaultdict(Counter)
    for a in assertions:
        prov_votes[a["source"]][(a.get("found_via", ""), tuple(a.get("discovery_path", [])))] += 1
    source_prov = {sid: c.most_common(1)[0][0] for sid, c in prov_votes.items()}

    def prov_fields(a: dict) -> dict:
        fv, dp = a.get("found_via", ""), a.get("discovery_path", [])
        out = {} if (fv, tuple(dp)) == source_prov.get(a["source"]) else {"fv": fv, "dp": dp}
        if a.get("sha256"):
            out["h"] = a["sha256"]
        return out

    components_meta = []
    vulnerable_versions: dict[tuple[str, str], bool] = {}
    for comp in catalog.components.values():
        rows = sorted(by_component.get(comp.id, []), key=lambda a: _version_key(a["version"]), reverse=True)
        rows.sort(key=lambda a: (a["supplier"].lower(), a["product"].lower()))   # stable: newest version first per product
        slim = []
        in_range = 0
        for a in rows:
            rc = range_check(a["component_version"].split(", "), comp.affected) if a.get("component_version") else None
            if rc and rc["status"] == "in_range":
                in_range += 1
                vulnerable_versions[(a["product_key"], comp.id)] = True
            slim.append({
                "k": a["product_key"], "s": a["supplier"], "p": a["product"], "v": a["version"],
                "c": a["cves"], "st": a["verdict"], "e": a["evidence"], "src": a["source"],
                "pub": a.get("publisher", ""), "u": a["source_url"],
                "r": a["references"][:FRONTEND_REFS_LIMIT],
                "n": a["notes"][:FRONTEND_NOTES_LIMIT], "cat": a.get("category"), "d": a["updated"],
                **({"cv": a["component_version"]} if a.get("component_version") else {}),
                **({"rc": rc["status"], "rcc": rc["cves"], "rcv": rc["versions"]} if rc and rc["status"] != "unknown" else {}),
                **prov_fields(a),
            })
        (comp_dir / f"{comp.id}.json").write_text(json.dumps(slim, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        verdicts = Counter(a["verdict"] for a in rows)
        components_meta.append({
            "id": comp.id, "name": comp.name, "upstream": comp.upstream, "purl": comp.purl,
            "cpe": comp.cpe, "aliases": comp.aliases, "incidents": comp.incidents,
            "assertions": len(rows), "products": len({a["product_key"] for a in rows}),
            "contains": sum(1 for a in rows if a["contains"] is True),
            "in_range": in_range,
            "verdicts": dict(verdicts),
        })

    inventories = build_inventories(data_dir, out_dir, remap)
    for key, inv in inventories.items():
        names.setdefault(key, (inv["s"], inv["p"]))

    products = []
    for key in sorted(set(by_product) | set(inventories)):
        comps = by_product.get(key, {})
        supplier, product = names[key]
        sp = spine_by_key.get(key)
        products.append({
            "k": key, "s": supplier, "p": product,
            "c": {cid: _best(rows)["verdict"] for cid, rows in sorted(comps.items())},
            "n": sum(len(r) for r in comps.values()),
            **({"cv": sp["cve_count"], "kev": sp["kev_count"]} if sp else {}),
            **({"inv": inventories[key]["count"]} if key in inventories else {}),
            **({"vr": sorted(cid for (k, cid) in vulnerable_versions if k == key)}
               if any(k == key for (k, _) in vulnerable_versions) else {}),
            **({"cpe": sorted(product_cpes[key])[:4]} if product_cpes.get(key) else {}),
        })
    spine_only = 0
    for sp in spine:
        if sp["key"] in by_product or sp["key"] in inventories:
            continue
        if sp["kev_count"] == 0 and sp["cve_count"] < spine_min_cves:
            continue
        products.append({"k": sp["key"], "s": sp["supplier"], "p": sp["product"], "c": {}, "n": 0,
                         "cv": sp["cve_count"], "kev": sp["kev_count"],
                         **({"cpe": sorted(product_cpes[sp["key"]])[:4]} if product_cpes.get(sp["key"]) else {})})
        spine_only += 1
    products.sort(key=lambda p: (p["s"].lower(), p["p"].lower()))

    # Wanted list: guesses live only in wanted.json; product pages just get a flag.
    wanted = wanted_mod.build(
        wanted_mod.load(CATALOG / "wanted.yaml"),
        component_names={cid: c.name for cid, c in catalog.components.items()},
        remap=remap,
        statements={k: {cid: _best(rows)["verdict"] for cid, rows in comps.items()} for k, comps in by_product.items()},
        inventories=set(inventories),
        known_keys={p["k"] for p in products},
    )
    open_keys = {e["k"] for e in wanted["entries"] if e["status"] == "wanted"}
    for prod in products:
        if prod["k"] in open_keys:
            prod["w"] = 1
    wanted["queue"] = wanted_mod.build_queue(wanted_mod.load(CATALOG / "research_queue.yaml"),
                                             products={p["k"]: p for p in products}, remap=remap)
    (out_dir / "wanted.json").write_text(json.dumps(wanted, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
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
        if sid in source_prov:
            entry["fv"], entry["dp"] = source_prov[sid][0], list(source_prov[sid][1])
        sources_meta.append(entry)

    meta = {
        "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "assertions": len(assertions),
            "products_with_data": len(set(by_product) | set(inventories)),
            "inventories": sum(i["docs"] for i in inventories.values()),
            "inventory_components": sum(i["rows"] for i in inventories.values()),
            "cpe_linked_clusters": len(clusters),
            "cpe_linked_entries": len(remap),
            "spine_products": len(spine),
            "spine_only_shown": spine_only,
            "components": len(catalog.components),
            "wanted": wanted["counts"]["wanted"],
            "wanted_fulfilled": wanted["counts"]["fulfilled"],
        },
        "components": components_meta,
        "sources": sources_meta,
        "comparables": COMPARABLES,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return meta["counts"]


def _version_key(v: str):
    return [(0, int(t)) if t.isdigit() else (1, t) for t in re.findall(r"\d+|[a-z]+", (v or "").lower())]


def _merge_spine(spine: list[dict], remap: dict[str, str]) -> list[dict]:
    merged: dict[str, dict] = {}
    for sp in spine:
        key = remap.get(sp["key"], sp["key"])
        prev = merged.get(key)
        if prev is None:
            merged[key] = {**sp, "key": key}
        else:
            keep = sp if sp["cve_count"] > prev["cve_count"] else prev
            merged[key] = {**keep, "key": key,
                           "cve_count": max(sp["cve_count"], prev["cve_count"]),
                           "kev_count": max(sp["kev_count"], prev["kev_count"]),
                           "cpe": sorted(set(sp.get("cpe") or []) | set(prev.get("cpe") or []))}
    return list(merged.values())


def build_inventories(data_dir: Path, out_dir: Path, remap: dict[str, str] | None = None) -> dict[str, dict]:
    """Write per-product component lists from notices files, plus a name index for search.

    docs/data/inventory/<product_key>.json   [{v, u, d, x, c: [[name, version], ...], e, fv, dp, h, a?}], newest version first
                                             (e evidence, fv found_via, dp discovery_path, h sha256, a scanned artifact)
    docs/data/inventory_index.json           {p: [product_key, ...], n: {name: [[product idx, product version, component version], ...]}}
    """
    inv_dir = out_dir / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, dict] = {}
    for _, inv in iter_inventories(data_dir):
        key = product_key(inv["supplier"], inv["product"])
        key = (remap or {}).get(key, key)
        g = grouped.setdefault(key, {"s": inv["supplier"], "p": inv["product"], "docs": []})
        g["docs"].append(inv)
    written = set()
    keys = sorted(grouped)
    index: dict[str, list] = defaultdict(list)
    out: dict[str, dict] = {}
    for pi, key in enumerate(keys):
        g = grouped[key]
        g["docs"].sort(key=lambda d: _version_key(d.get("version", "")), reverse=True)
        payload = [{"v": d.get("version", ""), "u": d["url"], "d": d.get("retrieved", ""),
                    "x": d.get("extractors", []), "c": [[c["name"], c.get("version", "")] for c in d["components"]],
                    "e": d.get("evidence", "notices-file"), "fv": d.get("found_via", ""),
                    "dp": d.get("discovery_path", []), "h": d.get("sha256", ""),
                    **({"a": d["artifact"]} if d.get("artifact") else {})}
                   for d in g["docs"]]
        fname = key.replace("/", "__") + ".json"
        (inv_dir / fname).write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        written.add(fname)
        unique = {normalize_name(c["name"]) for d in g["docs"] for c in d["components"]}
        rows = 0
        for d in g["docs"]:
            for c in d["components"]:
                index[normalize_name(c["name"])].append([pi, d.get("version", ""), c.get("version", "")])
                rows += 1
        out[key] = {"s": g["s"], "p": g["p"], "count": len(unique), "docs": len(g["docs"]), "rows": rows}
    for old in inv_dir.glob("*.json"):
        if old.name not in written:
            old.unlink()
    (out_dir / "inventory_index.json").write_text(
        json.dumps({"p": keys, "n": dict(sorted(index.items()))}, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8")
    return out
