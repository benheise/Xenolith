"""Tolerant version comparison and affected-range checks.

Vendor notices write versions many ways: 1.1.1g, 8.0p1, 2.0-beta9,
0:2.28-225.el8, v1.2.3, 7.4.33. This module turns them into comparable keys
and checks them against the [introduced, fixed) ranges recorded in
catalog/components.yaml.

A result of "in_range" means the listed version falls in a range the CVE
record marks affected. It does NOT mean the product is vulnerable: vendors
routinely backport fixes without changing the upstream version string, and
the vulnerable code may not be built or reachable. It is a prioritization
signal for asking the vendor, nothing more.
"""

from __future__ import annotations

import re
from typing import Iterable

PRERELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "m", "snapshot"}
_END = (0.5, "")


def version_key(v: str) -> list[tuple] | None:
    """Comparable key, or None when the string has no version in it."""
    if not v:
        return None
    s = v.strip().lower()
    s = re.sub(r"^\d+:", "", s)          # rpm/deb epoch
    s = re.sub(r"^v(?=\d)", "", s)
    if not re.match(r"^\d", s):
        return None
    key: list[tuple] = []
    for tok in re.findall(r"\d+|[a-z]+", s):
        if tok.isdigit():
            key.append((1, int(tok)))
        elif tok in PRERELEASE:
            key.append((0, tok))
        else:
            key.append((2, tok))         # post-release letters: 1.1.1g, 8.0p1
    key.append(_END)
    return key


def in_range(version: str, rng: dict) -> bool | None:
    vk = version_key(version)
    if vk is None:
        return None
    lo = version_key(str(rng.get("introduced", "0")))
    if lo is not None and vk < lo:
        return False
    if rng.get("fixed") is not None:
        hi = version_key(str(rng["fixed"]))
        return hi is None or vk < hi
    if rng.get("last_affected") is not None:
        hi = version_key(str(rng["last_affected"]))
        return hi is None or vk <= hi
    return True


def check(versions: Iterable[str], affected: list[dict]) -> dict:
    """Check component versions against a component's affected entries.

    Returns {"status": "in_range" | "outside" | "unknown", "cves": [...], "versions": [...]}
    where versions are the listed versions that fell in range.
    """
    versions = [v.strip() for v in versions if v and v.strip()]
    if not versions or not affected:
        return {"status": "unknown", "cves": [], "versions": []}
    parsed = [v for v in versions if version_key(v) is not None]
    if not parsed:
        return {"status": "unknown", "cves": [], "versions": []}
    hit_cves: list[str] = []
    hit_versions: list[str] = []
    for entry in affected:
        for v in parsed:
            if any(in_range(v, r) for r in entry.get("ranges", [])):
                for c in entry.get("cves", []):
                    if c not in hit_cves:
                        hit_cves.append(c)
                if v not in hit_versions:
                    hit_versions.append(v)
    return {"status": "in_range" if hit_cves else "outside", "cves": hit_cves, "versions": hit_versions}
