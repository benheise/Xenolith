"""Build the product spine: the registry of vendor products Xenolith tracks.

Sources:
  * CVE Program cvelistV5: every vendor/product pair a CNA has named in the
    `affected` block of a published CVE record.
  * CISA KEV: vendor/product pairs with known exploited vulnerabilities.

Package-ecosystem entries (records with packageName/collectionURL, and the
GitHub_M CNA, which assigns CVEs to open source repositories) are excluded.
Those are covered by deps.dev, OSV and similar services.

Products are ranked by KEV count, then CVE count, which approximates "widely
deployed and actually attacked".
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import Iterator

from .. import fetch
from ..model import product_key

KEV_CSV = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv"
EXCLUDED_CNAS = {"GitHub_M"}
PLACEHOLDERS = {"", "n/a", "na", "none", "unknown", "-", "?", "unspecified", "not applicable"}


def load_kev(path: Path | None = None) -> list[dict]:
    text = path.read_text(encoding="utf-8") if path else fetch.get_text(KEV_CSV, timeout=120)
    return list(csv.DictReader(io.StringIO(text)))


def iter_records(cve_dir: Path) -> Iterator[dict]:
    for path in cve_dir.rglob("CVE-*.json"):
        try:
            yield json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue


def build(cve_dir: Path | None, kev_rows: list[dict], *, min_cves: int = 3) -> tuple[list[dict], dict]:
    kev_ids = {r["cveID"].upper() for r in kev_rows}
    agg: dict[str, dict] = {}
    stats = Counter()

    def entry(vendor: str, product: str) -> dict:
        key = product_key(vendor, product)
        e = agg.get(key)
        if e is None:
            e = agg[key] = {"key": key, "names": Counter(), "cves": set(), "kev": set(),
                            "cpes": set(), "cnas": Counter(), "last": ""}
        e["names"][(vendor.strip(), product.strip())] += 1
        return e

    if cve_dir is not None:
        for rec in iter_records(cve_dir):
            meta = rec.get("cveMetadata") or {}
            if meta.get("state") != "PUBLISHED":
                stats["not_published"] += 1
                continue
            cve = str(meta.get("cveId", "")).upper()
            cna = (rec.get("containers") or {}).get("cna") or {}
            short = (cna.get("providerMetadata") or {}).get("shortName") or meta.get("assignerShortName") or ""
            if short in EXCLUDED_CNAS:
                stats["excluded_cna"] += 1
                continue
            stats["records"] += 1
            published = str(meta.get("datePublished") or "")[:10]
            for aff in cna.get("affected") or []:
                if aff.get("packageName") or aff.get("collectionURL"):
                    stats["excluded_package_entries"] += 1
                    continue
                vendor = str(aff.get("vendor") or "").strip()
                product = str(aff.get("product") or "").strip()
                if vendor.lower() in PLACEHOLDERS or product.lower() in PLACEHOLDERS:
                    stats["placeholder_entries"] += 1
                    continue
                e = entry(vendor, product)
                e["cves"].add(cve)
                if cve in kev_ids:
                    e["kev"].add(cve)
                e["cnas"][short] += 1
                for cpe in aff.get("cpes") or []:
                    if isinstance(cpe, str) and cpe.startswith("cpe:"):
                        e["cpes"].add(cpe)
                if published > e["last"]:
                    e["last"] = published

    for r in kev_rows:
        e = entry(r.get("vendorProject", ""), r.get("product", ""))
        e["cves"].add(r["cveID"].upper())
        e["kev"].add(r["cveID"].upper())
        if r.get("dateAdded", "") > e["last"]:
            e["last"] = r.get("dateAdded", "")

    out = []
    for e in agg.values():
        if not e["kev"] and len(e["cves"]) < min_cves:
            stats["below_threshold"] += 1
            continue
        (vendor, product), _ = e["names"].most_common(1)[0]
        # Keep CPE vendor:product prefixes only; full CPEs repeat per version.
        cpe_prefixes = sorted({":".join(c.split(":")[:5]) for c in e["cpes"]})[:5]
        out.append({
            "key": e["key"],
            "supplier": vendor,
            "product": product,
            "cve_count": len(e["cves"]),
            "kev_count": len(e["kev"]),
            "last_cve": e["last"],
            "cpe": cpe_prefixes,
            "cnas": [c for c, _ in e["cnas"].most_common(3)],
        })
    out.sort(key=lambda p: (-p["kev_count"], -p["cve_count"], p["key"]))
    stats["products"] = len(out)
    return out, dict(stats)
