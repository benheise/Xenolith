"""Ingest CISA's archived log4j-affected-db (YAML under data/)."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..catalog import Catalog, normalize_cve
from ..model import make_assertion

SOURCE_ID = "cisa-log4j"
REPO_URL = "https://github.com/cisagov/log4j-affected-db"


def cve_status(entry: dict) -> str | None:
    affected = [v for v in entry.get("affected_versions") or [] if str(v).strip()]
    fixed = [v for v in entry.get("fixed_versions") or [] if str(v).strip()]
    unaffected = [v for v in entry.get("unaffected_versions") or [] if str(v).strip()]
    if fixed:
        return "fixed"
    if affected:
        return "affected"
    if unaffected:
        return "not_affected"
    # "investigated: false" with empty version lists means nobody recorded a
    # vendor statement before the database was archived. That is no claim at
    # all, so it is not reported as "under investigation".
    return None


def _versions(cves: dict) -> str:
    parts = []
    for label, key in (("affected", "affected_versions"), ("fixed", "fixed_versions"), ("unaffected", "unaffected_versions")):
        vals = sorted({str(v).strip() for e in cves.values() for v in (e or {}).get(key) or [] if str(v).strip()})
        if vals:
            parts.append(f"{label}: {', '.join(vals[:6])}")
    return "; ".join(parts)


def ingest(repo: Path, *, catalog: Catalog, commit: str = "develop") -> tuple[list[dict], dict]:
    cve_map = catalog.cve_to_component
    # cisagov.yml is the merged copy of the per-letter files; read only the merged one.
    files = [repo / "data" / "cisagov.yml"]
    stats = {"rows": 0, "skipped_no_statement": 0, "assertions": 0}
    out: list[dict] = []
    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for sw in doc.get("software") or []:
            stats["rows"] += 1
            vendor = str(sw.get("vendor") or "").strip()
            product = str(sw.get("product") or "").strip()
            if not vendor and not product:
                continue
            raw_cves = sw.get("cves") or {}
            by_component: dict[str, dict[str, str]] = {}
            for raw_id, entry in raw_cves.items():
                cve = normalize_cve(str(raw_id))
                if not cve:
                    continue
                st = cve_status(entry or {})
                if st is None:
                    continue
                comp = cve_map.get(cve, "log4j-core")
                by_component.setdefault(comp, {})[cve] = st
            if not by_component:
                stats["skipped_no_statement"] += 1
                continue
            refs = [str(u) for u in (sw.get("vendor_links") or []) + (sw.get("references") or []) if str(u).startswith("http")]
            updated = str(sw.get("last_updated") or "")[:10] or "2023-02-02"
            for comp, cves in by_component.items():
                out.append(make_assertion(
                    component=comp,
                    supplier=vendor,
                    product=product,
                    version=_versions(raw_cves),
                    cves=cves,
                    status=None if cves else "unknown",
                    evidence="tracker",
                    source=SOURCE_ID,
                    source_url=f"{REPO_URL}/blob/{commit}/data/{f.name}",
                    references=refs,
                    notes=str(sw.get("notes") or ""),
                    updated=updated,
                    found_via="hand-listed",
                    discovery_path=[REPO_URL],
                ))
    stats["assertions"] = len(out)
    return out, stats
