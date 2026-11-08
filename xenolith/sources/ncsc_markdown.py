"""Ingest NCSC-NL style incident trackers (php2shell, log4shell).

These repositories keep one Markdown table per letter under software/, with
columns: Supplier | Product | Version | Status CVE-... (one per CVE) | Notes | Links.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..catalog import Catalog, normalize_cve
from ..model import make_assertion

CELL_SPLIT = re.compile(r"(?<!\\)\|")
LINK_RE = re.compile(r"\]\(<?(https?://[^)>\s]+)>?\)")
BARE_URL_RE = re.compile(r"(?<![(<])(https?://[^\s)|<>]+)")

STATUS_MAP = {
    "vulnerable": "affected",
    "fix": "fixed",
    "fix/workaround": "fixed",
    "workaround": "workaround",
    "not vuln": "not_affected",
    "investigation": "under_investigation",
    "runtime-dependent": "runtime_dependent",
    "unknown": "unknown",
    "": None,   # blank cell: no claim for this CVE
    "x": None,
}

# php2shell SPDX segments that hold open source packages rather than products.
# deps.dev, OSV and distro trackers already index these.
PHP2SHELL_EXCLUDED_SEGMENTS = {
    "runtime-core",
    "frameworks-libraries",
    "os-distributions",
    "containers-images",
    "developer-tooling",
}


def _cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    return [c.strip().replace("\\|", "|") for c in CELL_SPLIT.split(line)]


def map_status(raw: str) -> str | None:
    key = raw.strip().lower()
    if key in STATUS_MAP:
        return STATUS_MAP[key]
    return "unknown"


def parse_tables(software_dir: Path) -> list[dict]:
    """Return raw rows: supplier, product, version, statuses{CVE: raw}, notes, links, file."""
    rows: list[dict] = []
    for path in sorted(software_dir.glob("software_list_*.md")):
        header: list[str] | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s.startswith("|"):
                header = None if not s else header
                continue
            cells = _cells(s)
            if cells and cells[0].lower() == "supplier":
                header = cells
                continue
            if header is None or set(s) <= set("|:- "):
                continue
            row = dict(zip(header, cells + [""] * (len(header) - len(cells))))
            statuses = {}
            for col, val in row.items():
                if col.lower().startswith("status"):
                    cve = normalize_cve(col)
                    if cve:
                        statuses[cve] = val
            links = LINK_RE.findall(row.get("Links", "")) + BARE_URL_RE.findall(row.get("Links", ""))
            rows.append({
                "supplier": row.get("Supplier", ""),
                "product": row.get("Product", ""),
                "version": next((v for k, v in row.items() if k.lower().startswith("version")), ""),
                "statuses": statuses,
                "notes": row.get("Notes", ""),
                "links": links,
                "file": path.name,
            })
    return rows


def php2shell_segments(repo: Path) -> dict[tuple[str, str], str]:
    """Map (supplier name, package name) -> segment from the php2shell SPDX sources."""
    seg_dir = repo / "software" / "spdx" / "segments"
    shared = repo / "software" / "spdx" / "shared" / "organizations.json"
    orgs: dict[str, str] = {}
    if shared.exists():
        for e in json.loads(shared.read_text(encoding="utf-8")).get("@graph", []):
            if e.get("type") == "Organization":
                orgs[e["spdxId"]] = e.get("name", "")
    out: dict[tuple[str, str], str] = {}
    for f in sorted(seg_dir.glob("*.json")):
        for e in json.loads(f.read_text(encoding="utf-8")).get("@graph", []):
            if e.get("type") == "software_Package":
                supplier = orgs.get(e.get("suppliedBy", ""), "")
                out[(supplier.strip().lower(), e.get("name", "").strip().lower())] = f.stem
                out.setdefault(("", e.get("name", "").strip().lower()), f.stem)
    return out


def ingest(
    repo: Path,
    *,
    source_id: str,
    repo_url: str,
    default_component: str,
    catalog: Catalog,
    as_of: str,
    commit: str = "main",
) -> tuple[list[dict], dict]:
    cve_map = catalog.cve_to_component
    segments = php2shell_segments(repo) if source_id == "ncsc-nl-php2shell" else {}
    stats = {"rows": 0, "excluded_out_of_scope": 0, "assertions": 0, "unmapped_cves": set()}
    out: list[dict] = []
    for row in parse_tables(repo / "software"):
        stats["rows"] += 1
        category = None
        if segments:
            category = segments.get((row["supplier"].strip().lower(), row["product"].strip().lower())) \
                or segments.get(("", row["product"].strip().lower()))
            if category in PHP2SHELL_EXCLUDED_SEGMENTS:
                stats["excluded_out_of_scope"] += 1
                continue
        by_component: dict[str, dict[str, str]] = {}
        for cve, raw in row["statuses"].items():
            st = map_status(raw)
            if st is None:
                continue
            comp = cve_map.get(cve)
            if comp is None:
                stats["unmapped_cves"].add(cve)
                comp = default_component
            by_component.setdefault(comp, {})[cve] = st
        if not by_component:
            by_component[default_component] = {}
        file_url = f"{repo_url}/blob/{commit}/software/{row['file']}"
        for comp, cves in by_component.items():
            out.append(make_assertion(
                component=comp,
                supplier=row["supplier"],
                product=row["product"],
                version=row["version"],
                cves=cves,
                status=None if cves else "unknown",
                evidence="tracker",
                source=source_id,
                source_url=file_url,
                references=row["links"],
                notes=row["notes"],
                category=category,
                updated=as_of,
                found_via="hand-listed",          # the tracker repository is listed in catalog/sources.yaml
                discovery_path=[repo_url],
            ))
    stats["assertions"] = len(out)
    stats["unmapped_cves"] = sorted(stats["unmapped_cves"])
    return out, stats
