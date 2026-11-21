"""EPSS scores and CVE record details for the watchlist CVEs.

EPSS (FIRST.org) is a daily forecast of the chance a CVE is exploited in the next 30 days.
It is fetched fresh on every run. CVE record details (CVSS, publication date, description)
change rarely, so they are cached and only missing ones are fetched.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import fetch

EPSS_API = "https://api.first.org/data/v1/epss"
CVE_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
BATCH = 80   # CVE IDs per request (the API caps the query string)


def fetch_epss(cves: list[str]) -> dict:
    """{"date": "YYYY-MM-DD", "scores": {cve: [probability, percentile]}}; CVEs FIRST has not scored are left out."""
    scores: dict[str, list[float]] = {}
    date = ""
    for i in range(0, len(cves), BATCH):
        data = fetch.get_json(f"{EPSS_API}?cve={','.join(cves[i:i + BATCH])}&limit={BATCH}", timeout=60)
        for row in data.get("data", []):
            scores[row["cve"].upper()] = [round(float(row["epss"]), 5), round(float(row["percentile"]), 5)]
            date = max(date, row.get("date", ""))
    return {"date": date, "scores": dict(sorted(scores.items()))}


def _cvss(record: dict) -> dict:
    """The newest CVSS score in the record: the CNA's own if present, otherwise an ADP's (CISA Vulnrichment)."""
    containers = [record["containers"].get("cna", {})] + list(record["containers"].get("adp", []))
    for want in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for c in containers:
            for m in c.get("metrics", []):
                v = m.get(want)
                if isinstance(v, dict) and v.get("baseScore") is not None:
                    return {"score": float(v["baseScore"]), "severity": (v.get("baseSeverity") or "").title(),
                            "version": want[5:].replace("_", "."), "vector": v.get("vectorString", "")}
    return {}


def details(record: dict) -> dict:
    cna = record["containers"].get("cna", {})
    desc = next((d.get("value", "") for d in cna.get("descriptions", []) if (d.get("lang") or "en").lower().startswith("en")), "")
    desc = " ".join(desc.split())
    return {
        "published": (record.get("cveMetadata", {}).get("datePublished") or "")[:10],
        "description": desc if len(desc) <= 600 else desc[:599].rstrip() + "…",
        **({"cvss": c} if (c := _cvss(record)) else {}),
    }


def fetch_details(cves: list[str], cache: dict[str, dict]) -> dict[str, dict]:
    """Add record details for CVEs not in `cache`; a CVE whose record cannot be fetched is skipped and retried next run."""
    def one(cve: str):
        year, num = cve.split("-")[1:]
        try:
            return cve, details(json.loads(fetch.get_text(CVE_RAW.format(year=year, bucket=num[:-3] + "xxx", cve=cve), timeout=40)))
        except Exception:
            return cve, None
    missing = [c for c in cves if c not in cache]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for cve, d in pool.map(one, missing):
            if d:
                cache[cve] = d
    return {c: cache[c] for c in sorted(cache) if c in set(cves)}
