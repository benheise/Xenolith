"""Validate and ingest CycloneDX SBOMs contributed under community/sboms/.

A contributed SBOM becomes an inventory, exactly like a parsed vendor notices
document: its full component list is searchable, and watchlist components in it
become statements with evidence type `binary-scan` or `vendor-sbom`.

Required (see CONTRIBUTING.md for an example):
  bomFormat "CycloneDX", specVersion 1.4-1.7
  metadata.timestamp
  metadata.component.name and .version            the product and its version
  metadata.supplier.name or metadata.component.supplier.name
  metadata.tools                                   what produced the SBOM
  components[] with name (version strongly recommended)
  metadata.properties:
    xenolith:evidence     binary-scan | vendor-sbom
    xenolith:artifact     what was analyzed (file name, download URL or image digest)
    xenolith:artifact_sha256   required for binary-scan
    xenolith:source_url   public https link where others can check (required for vendor-sbom)
    xenolith:attestation  must be "yes": the submitter may share this component list
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT_URL = "https://github.com/benheise/Xenolith/blob/main/"
MAX_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 25000
EVIDENCE = {"binary-scan", "vendor-sbom"}
SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}


def _props(meta: dict) -> dict[str, str]:
    out = {}
    for p in meta.get("properties") or []:
        if isinstance(p, dict) and p.get("name"):
            out[str(p["name"])] = str(p.get("value", ""))
    return out


STATEMENT_CONFIDENCE = 0.7   # scanner findings below this stay in the inventory but make no statement


def _confidence(c: dict) -> float | None:
    """Scanner confidence from CycloneDX evidence.identity[].confidence or the xenolith:confidence property."""
    best = None
    for ident in ((c.get("evidence") or {}).get("identity") or []):
        try:
            v = float(ident.get("confidence"))
        except (TypeError, ValueError, AttributeError):
            continue
        best = v if best is None else max(best, v)
    if best is None:
        for p in c.get("properties") or []:
            if isinstance(p, dict) and p.get("name") == "xenolith:confidence":
                try:
                    best = float(p.get("value"))
                except (TypeError, ValueError):
                    pass
    return best


def _walk(components: list) -> list[dict]:
    out, stack = [], list(components or [])
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            if c.get("name"):
                name = f"{c['group']}:{c['name']}" if c.get("group") else str(c["name"])
                entry = {"name": name, "version": str(c.get("version") or "")}
                conf = _confidence(c)
                if conf is not None:
                    entry["confidence"] = round(conf, 2)
                found_by = next((p.get("value") for p in c.get("properties") or []
                                 if isinstance(p, dict) and p.get("name") == "xenolith:found_by"), None)
                if found_by:
                    entry["found_by"] = str(found_by)[:200]
            else:
                entry = None
            if entry:
                out.append(entry)
            stack.extend(c.get("components") or [])
    seen, uniq = set(), []
    for c in out:
        key = (c["name"].lower(), c["version"])
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return sorted(uniq, key=lambda c: (c["name"].lower(), c["version"]))


def validate(path: Path, repo_root: Path) -> tuple[dict | None, list[str]]:
    """Return (inventory, errors) for one contributed SBOM file."""
    rel = path.relative_to(repo_root).as_posix()
    if path.stat().st_size > MAX_BYTES:
        return None, [f"{rel}: larger than {MAX_BYTES // (1024 * 1024)} MB"]
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, [f"{rel}: not valid JSON ({e})"]
    return check(bom, rel)


def check(bom: dict, rel: str) -> tuple[dict | None, list[str]]:
    """Validate an already-parsed CycloneDX document; `rel` is its path under the repository."""
    errs: list[str] = []
    if not isinstance(bom, dict):
        return None, [f"{rel}: top level must be a JSON object"]
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be \"CycloneDX\"")
    if str(bom.get("specVersion")) not in SPEC_VERSIONS:
        errs.append(f"specVersion must be one of {', '.join(sorted(SPEC_VERSIONS))}")
    meta = bom.get("metadata") or {}
    comp = meta.get("component") or {}
    props = _props(meta)
    supplier = (meta.get("supplier") or {}).get("name") or (comp.get("supplier") or {}).get("name") \
        or (meta.get("manufacturer") or {}).get("name") or (comp.get("manufacturer") or {}).get("name")
    if not comp.get("name"):
        errs.append("metadata.component.name (the product) is required")
    if not comp.get("version"):
        errs.append("metadata.component.version (the product version) is required")
    if not supplier:
        errs.append("metadata.supplier.name (the vendor) is required")
    if not re.match(r"^\d{4}-\d{2}-\d{2}", str(meta.get("timestamp") or "")):
        errs.append("metadata.timestamp is required (ISO 8601)")
    if not meta.get("tools"):
        errs.append("metadata.tools must name the tool that produced the SBOM")
    evidence = props.get("xenolith:evidence", "")
    if evidence not in EVIDENCE:
        errs.append("metadata.properties xenolith:evidence must be binary-scan or vendor-sbom")
    if not props.get("xenolith:artifact"):
        errs.append("metadata.properties xenolith:artifact (what was analyzed) is required")
    if evidence == "binary-scan" and not re.fullmatch(r"[0-9a-fA-F]{64}", props.get("xenolith:artifact_sha256", "")):
        errs.append("binary-scan submissions need xenolith:artifact_sha256 (64 hex characters)")
    src = props.get("xenolith:source_url", "")
    if evidence == "vendor-sbom" and not src.startswith("https://"):
        errs.append("vendor-sbom submissions need xenolith:source_url (https link to the vendor's SBOM)")
    if src and not src.startswith("https://"):
        errs.append("xenolith:source_url must be an https:// link")
    if props.get("xenolith:attestation", "").strip().lower() != "yes":
        errs.append("xenolith:attestation must be \"yes\" (you are permitted to share this component list)")
    components = _walk(bom.get("components") or [])
    if not components:
        errs.append("components[] is empty")
    if len(components) > MAX_COMPONENTS:
        errs.append(f"more than {MAX_COMPONENTS} components")
    if errs:
        return None, [f"{rel}: {e}" for e in errs]
    return {
        "supplier": str(supplier).strip(),
        "product": str(comp["name"]).strip(),
        "version": str(comp["version"]).strip(),
        "url": src or ROOT_URL + rel,
        "submission": ROOT_URL + rel,
        "retrieved": str(meta["timestamp"])[:10],
        "kind": "sbom",
        "extractors": ["sbom"],
        "evidence": evidence,
        "source": "community",
        "artifact": props.get("xenolith:artifact", "")[:300],
        "artifact_sha256": props.get("xenolith:artifact_sha256", "").lower(),
        "tool": ", ".join(t.get("name", "") for t in _tools(meta.get("tools")) if t.get("name"))[:200],
        "components": components,
    }, []


def _tools(tools) -> list[dict]:
    if isinstance(tools, list):            # CycloneDX 1.4 style
        return [t for t in tools if isinstance(t, dict)]
    if isinstance(tools, dict):            # 1.5+: {components: [...], services: [...]}
        return [t for t in (tools.get("components") or []) + (tools.get("services") or []) if isinstance(t, dict)]
    return []


def load_all(repo_root: Path) -> tuple[list[dict], list[str]]:
    base = repo_root / "community" / "sboms"
    invs, errors = [], []
    for path in sorted(base.rglob("*.json")) if base.exists() else []:
        inv, errs = validate(path, repo_root)
        errors.extend(errs)
        if inv:
            invs.append(inv)
    return invs, errors


def write_inventories(invs: list[dict], data_dir: Path) -> int:
    from ..model import slug
    out_dir = data_dir / "community_sboms"
    for old in out_dir.rglob("*.json") if out_dir.exists() else []:
        old.unlink()
    for inv in invs:
        p = out_dir / slug(inv["supplier"]) / f"{slug(inv['product'])}--{slug(inv['version'])}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(inv, ensure_ascii=False, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    return len(invs)
