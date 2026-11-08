"""Link product entries that name the same CPE vendor:product.

Hand-written aliases (catalog/identity.yaml) catch spelling variants. This
module catches the rest automatically: when a CVE record or a vendor CSAF
document ties two differently-named entries to the same CPE (for example
"Ivanti / Connect Secure" and "Pulse Secure / Pulse Connect Secure" both
mapped to ivanti:connect_secure), they are the same product.

Guards against bad merges (see build()):
  * a CPE shared by more than MAX_KEYS_PER_CPE entries is treated as generic;
  * supplier and product names must both resemble the CPE's vendor and product;
  * entries with different release numbers in their names stay separate.
"""

from __future__ import annotations

import re
from collections import defaultdict

MAX_KEYS_PER_CPE = 6


def normalize_cpe(value: str) -> str | None:
    """Accept 'vendor:product', a CPE 2.3 string or a CPE 2.2 URI; return 'vendor:product'."""
    from .sources.cvelist import cpe_vendor_product
    value = (value or "").strip().lower()
    if value.startswith("cpe:"):
        return cpe_vendor_product(value)
    if value.count(":") != 1 or "*" in value:
        return None
    return value


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def supplier_matches(supplier_key: str, cpe_vendor: str) -> bool:
    a, b = _compact(supplier_key), _compact(cpe_vendor)
    if not a or not b:
        return False
    if a == b or a.startswith(b) or b.startswith(a):
        return True
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n >= 4


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


# Words that distinguish packaging or platform, not the product ("Windows Server 2016
# Server Core installation" is Windows Server 2016).
QUALIFIERS = {"core", "installation", "systems", "based", "bit", "x64", "x86", "arm64", "32", "64",
              "docker", "container", "containers", "edition", "standard", "service", "pack", "sp",
              "for", "on", "premises", "the", "version"}
MIN_SIMILARITY = 0.7


def similarity(name: str, cpe_product: str) -> float:
    from .sources.cvelist import _tokens
    a = _tokens(name) - QUALIFIERS
    b = _tokens(cpe_product.replace("_", " ")) - QUALIFIERS
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _numbers(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"(?<![a-z0-9])\d+(?![a-z0-9])", text.lower()))


def build(links: dict[str, set[str]], weight: dict[str, float]) -> tuple[dict[str, str], list[dict]]:
    """links: cpe vendor:product -> product keys that name it.
    weight: product key -> evidence weight (breaks ties when picking the surviving key).

    An entry joins through a CPE only if (1) its supplier resembles the CPE
    vendor, (2) its product name resembles the CPE product, and (3) it carries
    the same release numbers as the entries it joins: "Excel 2010" and
    "Excel 2016" share microsoft:excel but stay separate products.

    Returns (remap {old key: surviving key}, clusters [{key, keys, cpes}]).
    """
    uf = _UnionFind()
    used: list[tuple[str, list[str]]] = []
    for cpe, keys in links.items():
        if len(keys) < 2 or len(keys) > MAX_KEYS_PER_CPE:
            continue
        vendor, product = cpe.split(":", 1)
        ok = [k for k in keys
              if supplier_matches(k.split("/", 1)[0], vendor)
              and similarity(k.split("/", 1)[1].replace("-", " "), product) >= MIN_SIMILARITY]
        by_release: dict[frozenset, list[str]] = defaultdict(list)
        for k in sorted(ok):
            by_release[_numbers(k.split("/", 1)[1].replace("-", " "))].append(k)
        for group in by_release.values():
            if len(group) < 2:
                continue
            for k in group[1:]:
                uf.union(group[0], k)
            used.append((cpe, group))
    groups: dict[str, list[str]] = defaultdict(list)
    for k in list(uf.parent):
        groups[uf.find(k)].append(k)
    cluster_cpes: dict[str, set[str]] = defaultdict(set)
    for cpe, group in used:
        cluster_cpes[uf.find(group[0])].add(cpe)
    remap: dict[str, str] = {}
    clusters: list[dict] = []
    for root, keys in groups.items():
        if len(keys) < 2:
            continue
        cpes = cluster_cpes[root]
        def score(k: str) -> tuple:
            sim = max((similarity(k.split("/", 1)[1].replace("-", " "), c.split(":", 1)[1]) for c in cpes), default=0)
            return (round(sim, 2), weight.get(k, 0), -len(k), k)
        keep = max(keys, key=score)
        for k in keys:
            if k != keep:
                remap[k] = keep
        clusters.append({"key": keep, "keys": sorted(keys), "cpes": sorted(cpes)})
    clusters.sort(key=lambda c: (-len(c["keys"]), c["key"]))
    return remap, clusters
