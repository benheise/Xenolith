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
import re
from collections import Counter
from pathlib import Path
from typing import Iterator

from .. import fetch
from ..model import product_key

KEV_CSV = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv"
EXCLUDED_CNAS = {"GitHub_M"}
PLACEHOLDERS = {"", "n/a", "na", "none", "unknown", "-", "?", "unspecified", "not applicable"}
GENERIC_TOKENS = {"the", "for", "and", "software", "server", "firmware", "client", "edition", "enterprise",
                  "system", "systems", "suite", "app", "application", "plugin", "module", "version", "series"}


def cpe_vendor_product(cpe: str) -> str | None:
    """'cpe:2.3:o:paloaltonetworks:pan-os:10.1:*...' or CPE 2.2 'cpe:/o:paloaltonetworks:pan-os:10.1'
    -> 'paloaltonetworks:pan-os'."""
    s = (cpe or "").strip().lower().replace("\\:", "\x00").replace("\\", "")
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")[3:5]
    elif s.startswith("cpe:/"):
        parts = s[5:].split(":")[1:3]
    else:
        return None
    if len(parts) < 2 or parts[0] in ("", "*", "-") or parts[1] in ("", "*", "-"):
        return None
    return f"{parts[0]}:{parts[1]}".replace("\x00", ":")


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 2 and t not in GENERIC_TOKENS}


def name_similarity(product: str, cpe_product: str) -> float:
    a, b = _tokens(product), _tokens(cpe_product.replace("_", " "))
    if not a or not b:
        return 0.0
    if "".join(sorted(a)) == "".join(sorted(b)):
        return 1.0
    return len(a & b) / len(a | b)


def assign_adp_cpes(products: list[str], adp_cpes: list[str]) -> dict[int, list[str]]:
    """CISA's ADP container adds CPEs to many CVE records, but not per CNA entry.
    Give each ADP CPE to the one CNA product it matches best (similarity >= 0.5,
    no ties), so 'fedoraproject:fedora' never lands on a Chrome entry and
    'mozilla:firefox_esr' goes to Firefox ESR, not Firefox."""
    out: dict[int, list[str]] = {}
    for c in dict.fromkeys(adp_cpes):
        vp = cpe_vendor_product(c)
        if not vp:
            continue
        scores = [name_similarity(p, vp.split(":", 1)[1]) for p in products]
        if not scores:
            continue
        best = max(scores)
        if best >= 0.5 and scores.count(best) == 1:
            out.setdefault(scores.index(best), []).append(vp)
    return out


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
            adp_cpes = [c for adp in (rec.get("containers") or {}).get("adp") or []
                        for a in adp.get("affected") or [] for c in a.get("cpes") or [] if isinstance(c, str)]
            usable = []
            for aff in cna.get("affected") or []:
                if aff.get("packageName") or aff.get("collectionURL"):
                    stats["excluded_package_entries"] += 1
                    continue
                vendor = str(aff.get("vendor") or "").strip()
                product = str(aff.get("product") or "").strip()
                if vendor.lower() in PLACEHOLDERS or product.lower() in PLACEHOLDERS:
                    stats["placeholder_entries"] += 1
                    continue
                usable.append((aff, vendor, product))
            adp_assigned = assign_adp_cpes([p for _, _, p in usable], adp_cpes)
            for i, (aff, vendor, product) in enumerate(usable):
                e = entry(vendor, product)
                e["cves"].add(cve)
                if cve in kev_ids:
                    e["kev"].add(cve)
                e["cnas"][short] += 1
                for cpe in aff.get("cpes") or []:
                    if isinstance(cpe, str) and (vp := cpe_vendor_product(cpe)):
                        e["cpes"].add(vp)
                for vp in adp_assigned.get(i, []):
                    e["cpes"].add(vp)
                    stats["adp_cpes_attached"] += 1
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
        cpe_prefixes = sorted(e["cpes"])[:8]   # CPE vendor:product pairs (version parts dropped)
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
