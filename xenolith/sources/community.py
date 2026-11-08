"""Validate and ingest community/assertions.csv (contributed by pull request)."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from ..catalog import Catalog, CVE_RE
from ..model import EVIDENCE, STATUSES, make_assertion

SOURCE_ID = "community"
COLUMNS = ["component", "supplier", "product", "versions", "status", "cves",
           "evidence", "source_url", "date", "notes"]
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REPO_FILE_URL = "https://github.com/benheise/Xenolith/blob/main/community/assertions.csv"


def load(path: Path, catalog: Catalog) -> tuple[list[dict], list[str]]:
    """Return (assertions, errors). Any error should fail CI for the pull request."""
    errors: list[str] = []
    out: list[dict] = []
    if not path.exists():
        return out, errors
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            return out, [f"{path.name}: header must be exactly: {','.join(COLUMNS)}"]
        for n, row in enumerate(reader, start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            if not any(row.values()):
                continue
            where = f"{path.name} line {n}"
            comp = row["component"]
            if comp not in catalog.components:
                errors.append(f"{where}: unknown component {comp!r} (add it to catalog/components.yaml first)")
                continue
            if not row["supplier"] or not row["product"]:
                errors.append(f"{where}: supplier and product are required")
                continue
            status = row["status"]
            if status not in STATUSES:
                errors.append(f"{where}: status must be one of {', '.join(STATUSES)}")
                continue
            evidence = row["evidence"] or "community"
            if evidence not in EVIDENCE:
                errors.append(f"{where}: evidence must be one of {', '.join(EVIDENCE)}")
                continue
            if not row["source_url"].startswith("https://"):
                errors.append(f"{where}: source_url must be an https:// link to the evidence")
                continue
            if not DATE_RE.match(row["date"]):
                errors.append(f"{where}: date must be YYYY-MM-DD (when the source made the statement)")
                continue
            cves = [c.upper() for c in CVE_RE.findall(row["cves"])]
            wrong = [c for c in cves if c not in catalog.components[comp].cves]
            if wrong:
                errors.append(f"{where}: {', '.join(wrong)} not listed for {comp} in catalog/components.yaml")
                continue
            out.append(make_assertion(
                component=comp,
                supplier=row["supplier"],
                product=row["product"],
                version=row["versions"],
                cves={c: status for c in cves},
                status=status,
                evidence=evidence,
                source=SOURCE_ID,
                source_url=row["source_url"],
                references=[REPO_FILE_URL],
                notes=row["notes"],
                updated=row["date"],
                found_via="community",
                discovery_path=[f"{REPO_FILE_URL}#L{n}"],
            ))
    return out, errors
