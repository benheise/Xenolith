"""Canonical supplier and product names, so one product gets one key.

See catalog/identity.yaml for the alias tables and the rules applied here.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path

import yaml

IDENTITY_FILE = Path(__file__).resolve().parent.parent / "catalog" / "identity.yaml"

LEGAL_SUFFIX = re.compile(
    r"(?:[\s,]+(?:inc|incorporated|llc|l l c|ltd|limited|corp|corporation|co|company|gmbh|ag|se|sa|s a|nv|n v|"
    r"bv|b v|plc|pty|oy|ab|a s|kk|k k|srl|spa|s p a|lp|l p))+$")
ACRONYM_PAREN = re.compile(r"\s*\(([A-Z0-9][A-Za-z0-9\-]{0,7})\)")


def _plain(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


@lru_cache(maxsize=1)
def _tables() -> tuple[dict[str, str], dict[str, dict[str, str]], dict[str, list[str]]]:
    cfg = yaml.safe_load(IDENTITY_FILE.read_text(encoding="utf-8")) if IDENTITY_FILE.exists() else {}
    supplier_alias: dict[str, str] = {}
    supplier_names: dict[str, list[str]] = {}
    for canon, aliases in (cfg.get("suppliers") or {}).items():
        c = _plain(canon)
        supplier_alias[c] = c
        supplier_names[c] = [c] + [_plain(a) for a in aliases or []]
        for a in aliases or []:
            supplier_alias[_plain(a)] = c
    product_alias: dict[str, dict[str, str]] = {}
    for sup, prods in (cfg.get("products") or {}).items():
        table = product_alias.setdefault(_plain(sup), {})
        for canon, aliases in (prods or {}).items():
            c = _plain(canon)
            table[c] = c
            for a in aliases or []:
                table[_plain(a)] = c
    return supplier_alias, product_alias, supplier_names


def canonical_supplier(name: str) -> str:
    n = _plain(name)
    prev = None
    while prev != n:                       # "Foo Holdings Co., Ltd." -> "foo holdings"
        prev = n
        n = LEGAL_SUFFIX.sub("", n).strip()
    alias, _, _ = _tables()
    return alias.get(n, n) or _plain(name) or "unknown"


def canonical_product(supplier: str, product: str) -> str:
    sup = canonical_supplier(supplier)
    _, product_alias, supplier_names = _tables()
    raw = ACRONYM_PAREN.sub("", product or "")
    p = _plain(raw)
    for prefix in sorted(set(supplier_names.get(sup, [sup]) + [sup, _plain(supplier)]), key=len, reverse=True):
        if prefix and p.startswith(prefix + " ") and len(p) > len(prefix) + 1:
            p = p[len(prefix) + 1:]
            break
    p = re.sub(r"\s+software$", "", p).strip() or p
    return product_alias.get(sup, {}).get(p, p) or _plain(product) or "all products"


def product_key(supplier: str, product: str) -> str:
    return f"{canonical_supplier(supplier).replace(' ', '-')}/{canonical_product(supplier, product).replace(' ', '-')}"
