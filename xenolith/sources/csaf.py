"""Crawl CSAF 2.x providers and turn statements about watchlist CVEs into assertions.

A vendor advisory that says "product P is known_affected / fixed /
known_not_affected by CVE-X", where CVE-X belongs to a watchlist component,
is evidence about whether P embeds that component. This is the main automated
source of composition facts for closed-source products.

Crawling is incremental. Per provider, data/state/csaf/<provider>.json records
each document's release date and the CVEs it mentions, so unchanged documents
are not fetched again. Extracted assertions live in
data/assertions/csaf/<provider>.ndjson and are replaced per document when
that document changes.
"""

from __future__ import annotations

import csv
import io
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import yaml

from .. import fetch
from ..catalog import Catalog
from ..model import VERDICT_PRIORITY, make_assertion, read_ndjson, slug, write_ndjson

SOURCE_ID = "csaf"
# Bump when parse_advisory extracts more: documents that matched the watchlist
# are re-fetched once so their stored statements pick up the new fields.
PARSER_VERSION = 3   # 2: CPEs from product_identification_helper; 3: CPE 2.2 URIs

CSAF_STATUS = {
    "known_affected": "affected",
    "first_affected": "affected",
    "last_affected": "affected",
    "fixed": "fixed",
    "first_fixed": "fixed",
    "recommended": "fixed",
    "known_not_affected": "not_affected",
    "under_investigation": "under_investigation",
}
VERSION_CATEGORIES = {"product_version", "product_version_range", "service_pack", "patch_level"}
PUBLIC_TLP = {"WHITE", "CLEAR"}
RESTRICTED_TLP_DIRS = ("amber", "amber+strict", "green", "red")
FILENAME_CVE = re.compile(r"cve-(\d{4})-(\d{4,})", re.IGNORECASE)


# ---------------------------------------------------------------- product tree

def _cpe_vp(cpe: str | None) -> str | None:
    from .cvelist import cpe_vendor_product
    return cpe_vendor_product(cpe) if cpe else None


def _from_path(path: list[tuple[str, str]], full_name: str, helper: dict | None = None) -> dict:
    vendor = next((n for c, n in reversed(path) if c == "vendor"), None)
    product = next((n for c, n in reversed(path) if c == "product_name"), None) \
        or next((n for c, n in reversed(path) if c == "product_family"), None) \
        or full_name
    version = " ".join(n for c, n in path if c in VERSION_CATEGORIES and n)
    return {"vendor": vendor, "product": product or full_name, "version": version,
            "cpe": _cpe_vp((helper or {}).get("cpe"))}


def index_product_tree(pt: dict) -> tuple[dict[str, dict], dict[str, list[str]]]:
    """Return (product_id -> {vendor, product, version}, group_id -> [product_id])."""
    names: dict[str, dict] = {}

    def walk(branches, path):
        for b in branches or []:
            p = path + [(b.get("category", ""), str(b.get("name", "")))]
            prod = b.get("product") or {}
            if prod.get("product_id"):
                names[prod["product_id"]] = _from_path(p, prod.get("name", ""), prod.get("product_identification_helper"))
            walk(b.get("branches"), p)

    walk(pt.get("branches"), [])
    for fp in pt.get("full_product_names") or []:
        if fp.get("product_id"):
            names.setdefault(fp["product_id"], {"vendor": None, "product": fp.get("name", ""), "version": "",
                                                "cpe": _cpe_vp((fp.get("product_identification_helper") or {}).get("cpe"))})
    for rel in pt.get("relationships") or []:
        fp = rel.get("full_product_name") or {}
        pid = fp.get("product_id")
        if not pid:
            continue
        comp = names.get(rel.get("product_reference"))
        plat = names.get(rel.get("relates_to_product_reference"))
        if plat:
            comp_label = ""
            if comp:
                comp_label = " ".join(x for x in (comp["product"], comp["version"]) if x)
            names[pid] = {"vendor": plat["vendor"] or (comp or {}).get("vendor"),
                          "product": plat["product"],
                          "version": " ".join(x for x in (plat["version"], comp_label) if x),
                          "cpe": plat.get("cpe")}
        else:
            names.setdefault(pid, {"vendor": None, "product": fp.get("name", ""), "version": "", "cpe": None})
    groups = {g["group_id"]: list(g.get("product_ids") or []) for g in pt.get("product_groups") or [] if g.get("group_id")}
    return names, groups


def _expand(ids: list[str] | None, group_ids: list[str] | None, groups: dict[str, list[str]]) -> set[str]:
    out = set(ids or [])
    for g in group_ids or []:
        out.update(groups.get(g, []))
    return out


def _rollup(statuses: list[str]) -> str:
    """Product-level status across versions: a published fix wins, then workaround."""
    s = set(statuses)
    if "fixed" in s:
        return "fixed"
    if "workaround" in s:
        return "workaround"
    for st in VERDICT_PRIORITY:
        if st in s:
            return st
    return "unknown"


def parse_advisory(doc: dict, url: str, cve_map: dict[str, str], provider: str) -> tuple[list[dict], list[str]]:
    """Return (assertions, all CVE IDs mentioned in the document)."""
    document = doc.get("document") or {}
    publisher = (document.get("publisher") or {}).get("name") or provider
    tracking = document.get("tracking") or {}
    updated = str(tracking.get("current_release_date") or tracking.get("initial_release_date") or "")[:10]
    title = document.get("title") or tracking.get("id") or ""
    names, groups = index_product_tree(doc.get("product_tree") or {})

    all_cves: list[str] = []
    # (component, supplier, product) -> {cve: {version: status}}
    rows: dict[tuple[str, str, str], dict[str, dict[str, str]]] = {}
    row_cpes: dict[tuple[str, str, str], set[str]] = {}
    for vuln in doc.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").upper()
        if cve:
            all_cves.append(cve)
        comp = cve_map.get(cve)
        if not comp:
            continue
        remed: dict[str, set[str]] = {}
        for r in vuln.get("remediations") or []:
            for pid in _expand(r.get("product_ids"), r.get("group_ids"), groups):
                remed.setdefault(pid, set()).add(r.get("category", ""))
        absent: set[str] = set()
        for f in vuln.get("flags") or []:
            if f.get("label") == "component_not_present":
                absent |= _expand(f.get("product_ids"), f.get("group_ids"), groups)
        for category, pids in (vuln.get("product_status") or {}).items():
            base = CSAF_STATUS.get(category)
            if base is None:
                continue
            for pid in pids or []:
                st = base
                if base == "affected":
                    cats = remed.get(pid, set())
                    if "vendor_fix" in cats:
                        st = "fixed"
                    elif cats & {"workaround", "mitigation"}:
                        st = "workaround"
                elif base == "not_affected" and pid in absent:
                    st = "absent"
                info = names.get(pid) or {"vendor": None, "product": pid, "version": ""}
                key = (comp, info["vendor"] or publisher, info["product"] or pid)
                if info.get("cpe"):
                    row_cpes.setdefault(key, set()).add(info["cpe"])
                versions = rows.setdefault(key, {}).setdefault(cve, {})
                v = info["version"] or ""
                prev = versions.get(v)
                versions[v] = st if prev is None else min(prev, st, key=VERDICT_PRIORITY.index)

    out = []
    for (comp, supplier, product), per_cve in rows.items():
        cves = {cve: _rollup(list(vmap.values())) for cve, vmap in per_cve.items()}
        by_status: dict[str, set[str]] = {}
        for vmap in per_cve.values():
            for ver, st in vmap.items():
                if ver:
                    by_status.setdefault(st, set()).add(ver)
        version = "; ".join(
            f"{st.replace('_', ' ')}: {', '.join(sorted(vs)[:8])}{' …' if len(vs) > 8 else ''}"
            for st, vs in sorted(by_status.items(), key=lambda kv: VERDICT_PRIORITY.index(kv[0]))
        )
        out.append(make_assertion(
            component=comp,
            supplier=supplier,
            product=product,
            version=version,
            cves=cves,
            evidence="vendor-advisory",
            source=SOURCE_ID,
            publisher=publisher,
            source_url=url,
            notes=title,
            category=provider,
            updated=updated,
            cpes=row_cpes.get((comp, supplier, product), ()),
        ))
    return out, sorted(set(all_cves))


# ---------------------------------------------------------------- discovery

def list_documents(meta: dict, log=print) -> list[tuple[str, str]]:
    """Enumerate (document URL, release date) from a provider-metadata.json.

    A distribution that fails (for example an access-restricted feed) is
    skipped; the provider's other distributions are still read.
    """
    docs: dict[str, str] = {}
    failed: list[str] = []
    for dist in meta.get("distributions") or []:
        directory = str(dist.get("directory_url") or "").lower()
        if any(f"/{tlp}/" in directory + "/" for tlp in RESTRICTED_TLP_DIRS):
            continue  # TLP-restricted directory; needs credentials by design
        try:
            _read_distribution(dist, docs)
        except fetch.FetchError as e:
            failed.append(str(e))
    if failed:
        log(f"  ! {len(failed)} distribution(s) unreadable, e.g. {failed[0]}")
    return sorted(docs.items())


def _read_distribution(dist: dict, docs: dict[str, str]) -> None:
    directory = dist.get("directory_url")
    if directory:
        base = directory if directory.endswith("/") else directory + "/"
        text = fetch.get_text(urljoin(base, "changes.csv"), timeout=120)
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 2 and row[0].strip().endswith(".json"):
                docs[urljoin(base, row[0].strip())] = row[1].strip()
    rolie = dist.get("rolie") or {}
    for feed in rolie.get("feeds") or []:
        if str(feed.get("tlp_label", "")).upper() not in PUBLIC_TLP:
            continue
        data = fetch.get_json(feed["url"], timeout=120)
        for entry in (data.get("feed") or {}).get("entry") or []:
            href = (entry.get("content") or {}).get("src")
            if not href:
                href = next((l.get("href") for l in entry.get("link") or [] if l.get("rel") == "self"), None)
            if href and href.endswith(".json"):
                docs[href] = str(entry.get("updated") or "")


def discover_providers(aggregator_url: str) -> list[dict]:
    data = fetch.get_json(aggregator_url)
    out = []
    for entry in (data.get("csaf_providers") or []) + (data.get("csaf_publishers") or []):
        m = entry.get("metadata") or {}
        if m.get("url"):
            out.append({"name": (m.get("publisher") or {}).get("name") or m["url"], "metadata": m["url"]})
    return out


def load_providers(config_path: Path, *, discover: bool = True) -> list[dict]:
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    defaults = cfg.get("defaults") or {}
    exclude = set(cfg.get("exclude") or [])
    providers = []
    seen = set()
    for p in cfg.get("providers") or []:
        providers.append({**defaults, **p})
        seen.add(p["metadata"])
    if discover:
        for agg in cfg.get("discover_from_aggregators") or []:
            try:
                for p in discover_providers(agg):
                    if p["metadata"] not in seen and p["metadata"] not in exclude:
                        providers.append({**defaults, **p})
                        seen.add(p["metadata"])
            except fetch.FetchError as e:
                print(f"  ! aggregator {agg}: {e}")
    return providers


# ---------------------------------------------------------------- crawl

def _filename_cve(url: str) -> str | None:
    m = FILENAME_CVE.search(url.rsplit("/", 1)[-1])
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def crawl_provider(provider: dict, *, catalog: Catalog, data_dir: Path,
                   max_fetch: int | None = None, workers: int = 8, log=print) -> dict:
    cve_map = catalog.cve_to_component
    watch = set(cve_map)
    pslug = slug(provider["name"])
    state_path = data_dir / "state" / "csaf" / f"{pslug}.json"
    store_path = data_dir / "assertions" / "csaf" / f"{pslug}.ndjson"
    state: dict[str, dict] = json.loads(state_path.read_text()) if state_path.exists() else {}
    stats = {"provider": provider["name"], "documents": 0, "candidates": 0, "fetched": 0,
             "errors": 0, "assertions": 0, "remaining": 0}

    meta = fetch.get_json(provider["metadata"])
    docs = list_documents(meta, log=log)
    stats["documents"] = len(docs)
    if provider.get("mode", "full") == "cve-filename":
        docs = [(u, r) for u, r in docs if _filename_cve(u) in watch]

    def needs(url: str, release: str) -> bool:
        st = state.get(url)
        if st is None or st.get("r") != release:
            return True
        if st.get("x") and st.get("pv", 1) < PARSER_VERSION:
            return True
        return set(st.get("c", [])) & watch != set(st.get("x", []))

    todo = sorted(((u, r) for u, r in docs if needs(u, r)), key=lambda ur: ur[1], reverse=True)
    stats["candidates"] = len(todo)
    cap = max_fetch if max_fetch is not None else int(provider.get("max_fetch", 1500))
    batch, rest = todo[:cap], todo[cap:]
    stats["remaining"] = len(rest)

    existing = list(read_ndjson(store_path))
    refreshed: set[str] = set()
    new_assertions: list[dict] = []

    def work(item):
        url, release = item
        return url, release, fetch.get_json(url, timeout=60)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, item) for item in batch]
        for fut in as_completed(futures):
            try:
                url, release, doc = fut.result()
            except fetch.FetchError as e:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    log(f"  ! {e}")
                continue
            stats["fetched"] += 1
            assertions, cves = parse_advisory(doc, url, cve_map, provider["name"])
            state[url] = {"r": release, "c": cves, "x": sorted(set(cves) & watch), "pv": PARSER_VERSION}
            refreshed.add(url)
            new_assertions.extend(assertions)

    kept = [a for a in existing if a["source_url"] not in refreshed]
    merged = kept + new_assertions
    stats["assertions"] = len(merged)
    write_ndjson(store_path, sorted(merged, key=lambda a: (a["component"], a["product_key"], a["source_url"])))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
    return stats


def crawl(config_path: Path, *, catalog: Catalog, data_dir: Path, only: list[str] | None = None,
          max_fetch: int | None = None, discover: bool = True, log=print) -> list[dict]:
    results = []
    for p in load_providers(config_path, discover=discover):
        if only and not any(o.lower() in p["name"].lower() for o in only):
            continue
        log(f"- {p['name']} ({p.get('mode', 'full')})")
        try:
            st = crawl_provider(p, catalog=catalog, data_dir=data_dir, max_fetch=max_fetch, log=log)
        except fetch.FetchError as e:
            log(f"  ! skipped: {e}")
            results.append({"provider": p["name"], "error": str(e)})
            continue
        log(f"  {st['fetched']} fetched, {st['remaining']} queued for later runs, "
            f"{st['assertions']} assertions stored, {st['errors']} errors")
        results.append(st)
    return results


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
