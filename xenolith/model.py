"""The assertion record and the vocabularies every ingester maps into.

An assertion is one sourced claim about one product and one component:
"Supplier S's product P (versions V) contains component C, with this status
for these CVEs, according to source X as of date D."
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Iterable, Iterator

# Per-CVE status vocabulary, plus "present"/"absent" for composition-only claims
# (for example a notices file shows the component is bundled, but nobody has
# assessed a CVE against it).
STATUSES = (
    "affected",             # product contains a vulnerable version, no fix published
    "workaround",           # affected; vendor published a workaround or mitigation only
    "fixed",                # product contained the component; vendor published a fixed version
    "under_investigation",  # vendor or tracker has not concluded
    "runtime_dependent",    # product runs on a host-supplied copy (patch the host runtime)
    "not_affected",         # vendor states the product is not affected
    "present",              # component is embedded; vulnerability status not assessed
    "absent",               # component is not present in the product
    "unknown",
)

# Order used to roll several per-CVE statuses up into one verdict.
VERDICT_PRIORITY = (
    "affected",
    "workaround",
    "fixed",
    "under_investigation",
    "present",
    "runtime_dependent",
    "not_affected",
    "absent",
    "unknown",
)

CONTAINS_TRUE = {"affected", "workaround", "fixed", "present"}
CONTAINS_FALSE = {"absent"}

EVIDENCE = (
    "tracker",          # community incident tracker (NCSC-NL, CISA)
    "vendor-advisory",  # vendor CSAF advisory / VEX
    "vendor-sbom",      # SBOM published by the vendor
    "notices-file",     # third-party notices / OSS attribution document
    "binary-scan",      # composition derived from scanning a downloadable artifact
    "community",        # contributed to this repository with a source link
)

ASSERTION_FIELDS = (
    "id", "component", "supplier", "product", "product_key", "version",
    "cves", "verdict", "contains", "evidence", "source", "publisher",
    "source_url", "references", "notes", "category", "updated", "component_version",
)


def slug(text: str) -> str:
    """Lowercase ASCII slug used for product identity keys."""
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", "-", text.lower())
    return text.strip("-") or "unknown"


def product_key(supplier: str, product: str) -> str:
    """Canonical key for a product; see xenolith/identity.py and catalog/identity.yaml."""
    from .identity import product_key as canonical_key
    return canonical_key(supplier, product)


def verdict(statuses: Iterable[str]) -> str:
    present = set(statuses)
    for status in VERDICT_PRIORITY:
        if status in present:
            return status
    return "unknown"


def contains(v: str) -> bool | None:
    if v in CONTAINS_TRUE:
        return True
    if v in CONTAINS_FALSE:
        return False
    return None


def clean_text(text: str, limit: int = 600) -> str:
    text = re.sub(r"\s+", " ", (text or "").replace("<br>", " / ")).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def make_assertion(
    *,
    component: str,
    supplier: str,
    product: str,
    cves: dict[str, str],
    evidence: str,
    source: str,
    source_url: str,
    updated: str,
    version: str = "",
    references: Iterable[str] = (),
    notes: str = "",
    category: str | None = None,
    status: str | None = None,
    publisher: str = "",
    component_version: str = "",
) -> dict:
    """Build a normalized assertion.

    `cves` maps CVE ID -> status. `status` is used when the claim has no CVE
    (composition-only evidence such as a notices file).
    """
    supplier = clean_text(supplier, 200) or "Unknown supplier"
    product = clean_text(product, 300) or "All products"
    for cve, st in cves.items():
        if st not in STATUSES:
            raise ValueError(f"unknown status {st!r} for {cve}")
    if status is not None and status not in STATUSES:
        raise ValueError(f"unknown status {status!r}")
    if evidence not in EVIDENCE:
        raise ValueError(f"unknown evidence type {evidence!r}")
    statuses = list(cves.values()) or [status or "unknown"]
    v = verdict(statuses)
    version = clean_text(version, 300)
    key = product_key(supplier, product)
    ident = hashlib.sha1(
        "\x1f".join([source, source_url, key, version, component]).encode()
    ).hexdigest()[:16]
    refs: list[str] = []
    for ref in references:
        if ref and ref not in refs:
            refs.append(ref)
    out = {
        "id": ident,
        "component": component,
        "supplier": supplier,
        "product": product,
        "product_key": key,
        "version": version,
        "cves": dict(sorted(cves.items())),
        "verdict": v,
        "contains": contains(v),
        "evidence": evidence,
        "source": source,
        "publisher": clean_text(publisher, 200),
        "source_url": source_url,
        "references": refs[:12],
        "notes": clean_text(notes),
        "category": category,
        "updated": updated,
    }
    if component_version:
        out["component_version"] = clean_text(component_version, 200)
    return out


def dedupe(assertions: Iterable[dict]) -> list[dict]:
    """Merge assertions that share an id (same source, product, version, component)."""
    merged: dict[str, dict] = {}
    for a in assertions:
        prev = merged.get(a["id"])
        if prev is None:
            merged[a["id"]] = a
            continue
        prev["cves"].update(a["cves"])
        prev["cves"] = dict(sorted(prev["cves"].items()))
        prev["verdict"] = verdict(prev["cves"].values() or [prev["verdict"]])
        prev["contains"] = contains(prev["verdict"])
        for ref in a["references"]:
            if ref not in prev["references"]:
                prev["references"].append(ref)
        if a["updated"] > prev["updated"]:
            prev["updated"] = a["updated"]
    return sorted(merged.values(), key=lambda a: (a["component"], a["product_key"], a["version"], a["id"]))


def write_ndjson(path: Path, records: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def read_ndjson(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
