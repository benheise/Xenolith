"""The wanted list: products whose component lists couldn't be collected (catalog/wanted.yaml).

Guesses in the wanted list are never statements. The build writes them to
docs/data/wanted.json for the site's Wanted page only; product and component
pages never show them. An entry counts as fulfilled once Xenolith holds a
component list for the product (a vendor notices document or a community SBOM).
Sourced statements about single components appear on the entry as already
verified, and a guess about a component that has one is dropped.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .identity import product_key

REASONS = {
    "blocked": "Vendor site refuses automated downloads",
    "login": "Behind a customer login",
    "in-product": "Only shipped inside the product",
    "signed-urls": "Served through short-lived signed links",
    "client-side": "List only renders in a browser",
    "withdrawn": "Vendor withdrew the public list",
    "not-published": "No public component list found",
    "no-versions": "Public list has names but no versions",
    "needs-parser": "Public list needs a custom parser",
    "not-found": "No list for current releases",
}
CONFIDENCE = ("named", "likely", "possible")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$")


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {} if path.exists() else {}


def validate(cfg: dict, component_ids: set[str]) -> list[str]:
    errors = []
    for vi, vendor in enumerate(cfg.get("vendors") or []):
        where = f"wanted.yaml vendor {vi + 1} ({vendor.get('supplier', '?')})"
        if not vendor.get("supplier"):
            errors.append(f"{where}: supplier is required")
        if not vendor.get("products"):
            errors.append(f"{where}: products is empty")
        for product in vendor.get("products") or []:
            pw = f"{where} / {product.get('product', '?')}"
            if not product.get("product"):
                errors.append(f"{pw}: product is required")
            reason = product.get("blocked") or vendor.get("blocked")
            if reason not in REASONS:
                errors.append(f"{pw}: blocked must be one of {', '.join(REASONS)}")
            if product.get("key") and not KEY_RE.match(product["key"]):
                errors.append(f"{pw}: key must look like supplier-slug/product-slug")
            if not product.get("guesses"):
                errors.append(f"{pw}: at least one guess is required")
            for gi, g in enumerate(product.get("guesses") or []):
                gw = f"{pw} guess {gi + 1}"
                if bool(g.get("component")) == bool(g.get("name")):
                    errors.append(f"{gw}: give exactly one of component (watchlist id) or name")
                if g.get("component") and g["component"] not in component_ids:
                    errors.append(f"{gw}: unknown component '{g['component']}' (use name for components not on the watchlist)")
                if g.get("confidence") not in CONFIDENCE:
                    errors.append(f"{gw}: confidence must be one of {', '.join(CONFIDENCE)}")
                if not str(g.get("basis") or "").strip():
                    errors.append(f"{gw}: basis (why you think so) is required")
                if g.get("source") and not str(g["source"]).startswith("https://"):
                    errors.append(f"{gw}: source must be an https:// link")
                if g.get("confidence") == "named" and not (g.get("source") or g.get("name")):
                    errors.append(f"{gw}: a 'named' guess about a watchlist component needs a source link")
    return errors


def build(cfg: dict, *, component_names: dict[str, str], remap: dict[str, str],
          statements: dict[str, dict[str, str]], inventories: set[str], known_keys: set[str]) -> dict:
    """statements: product key -> {component id: best verdict}; inventories: keys with component lists."""
    entries = []
    for vendor in cfg.get("vendors") or []:
        for product in vendor.get("products") or []:
            key = product.get("key") or product_key(vendor["supplier"], product["product"])
            key = remap.get(key, key)
            verified = statements.get(key, {})
            guesses = []
            for g in product.get("guesses") or []:
                if g.get("component") and g["component"] in verified:
                    continue                     # a sourced statement already covers it
                guesses.append({k: v for k, v in {
                    "c": g.get("component"),
                    "n": g.get("name") or component_names.get(g.get("component"), g.get("component")),
                    "conf": g["confidence"],
                    "v": str(g.get("version") or ""),
                    "b": g["basis"],
                    "src": g.get("source"),
                }.items() if v})
            reason = product.get("blocked") or vendor.get("blocked")
            entries.append({
                "s": vendor["supplier"], "p": product["product"], "k": key,
                "linked": key in known_keys,
                "status": "fulfilled" if key in inventories else "wanted",
                "reason": reason,
                "detail": product.get("detail") or vendor.get("detail", ""),
                "where": product.get("where") or vendor.get("where", ""),
                "verified": [{"c": cid, "n": component_names.get(cid, cid), "v": verdict}
                             for cid, verdict in sorted(verified.items())],
                "guesses": guesses,
            })
    entries.sort(key=lambda e: (e["status"] != "fulfilled", e["s"].lower(), e["p"].lower()))
    return {
        "reasons": REASONS,
        "entries": entries,
        "counts": {
            "wanted": sum(e["status"] == "wanted" for e in entries),
            "fulfilled": sum(e["status"] == "fulfilled" for e in entries),
            "guesses": sum(len(e["guesses"]) for e in entries if e["status"] == "wanted"),
        },
    }
