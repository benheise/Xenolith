"""Turn a scanner's SBOM into a Xenolith submission: python -m xenolith prepare.

Takes the CycloneDX or SPDX JSON written by `python -m xenolith fingerprint`,
Syft, cdxgen, cve-bin-tool, blint, Trivy or similar, and writes a CycloneDX 1.6 file under community/sboms/ that
passes `python -m xenolith community --check`:

  * the product (supplier, name, version) goes in metadata.component
  * the xenolith: properties are filled in, including the sha256 of the
    analyzed artifact, computed here from the local file
  * components keep only type, group, name, version, purl and cpe; scanner
    properties, file entries and evidence paths are dropped, so host paths,
    user names and build directories from the scanning machine never reach
    the pull request
  * the scanner(s) that produced the input stay listed in metadata.tools

Nothing is uploaded; the command only reads and writes local files.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .model import slug
from .sources.community_sbom import check

PREPARE_VERSION = "1"
PRODUCT_TYPES = ("application", "firmware", "operating-system", "container", "device", "platform")
KEEP_TYPES = {"library", "application", "framework", "operating-system", "firmware", "container",
              "platform", "device", "device-driver"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _tools_from_cyclonedx(meta: dict) -> list[dict]:
    tools = meta.get("tools")
    items = tools if isinstance(tools, list) else (tools or {}).get("components", []) if isinstance(tools, dict) else []
    out = []
    for t in items:
        if isinstance(t, dict) and t.get("name"):
            out.append({k: str(t[k]) for k in ("name", "version") if t.get(k)})
    return out


def _tools_from_spdx(doc: dict) -> list[dict]:
    out = []
    for c in (doc.get("creationInfo") or {}).get("creators") or []:
        m = re.match(r"Tool:\s*(.+?)(?:[-\s]v?(\d[\w.+-]*))?$", str(c))
        if m:
            out.append({"name": m.group(1).strip(), **({"version": m.group(2)} if m.group(2) else {})})
    return out


def _clean_component(c: dict) -> dict | None:
    name = str(c.get("name") or "").strip()
    ctype = str(c.get("type") or "library")
    if not name or ctype not in KEEP_TYPES:
        return None
    out = {"type": ctype, "name": name[:200]}
    for key in ("group", "version", "purl", "cpe"):
        if c.get(key):
            out[key] = str(c[key])[:300]
    props = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
    found_by = props.get("xenolith:found_by") or props.get("syft:package:foundBy") or props.get("cdx:found_by")
    keep = [("xenolith:found_by", found_by)] + [(k, props.get(k)) for k in ("xenolith:confidence", "xenolith:note")]
    keep = [{"name": k, "value": str(v)[:200]} for k, v in keep if v]
    if keep:
        out["properties"] = keep
    return out


def components_from_cyclonedx(bom: dict) -> list[dict]:
    out, stack = [], list(bom.get("components") or [])
    while stack:
        c = stack.pop(0)
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        cleaned = _clean_component(c)
        if cleaned:
            out.append(cleaned)
    return out


def components_from_spdx(doc: dict) -> list[dict]:
    described = set(doc.get("documentDescribes") or [])
    for r in doc.get("relationships") or []:
        if r.get("relationshipType") == "DESCRIBES":
            described.add(r.get("relatedSpdxElement"))
    out = []
    for p in doc.get("packages") or []:
        if not isinstance(p, dict) or p.get("SPDXID") in described:
            continue
        c = {"type": "library", "name": p.get("name"), "version": p.get("versionInfo")}
        for ref in p.get("externalRefs") or []:
            kind = ref.get("referenceType")
            if kind == "purl" and "purl" not in c:
                c["purl"] = ref.get("referenceLocator")
            elif kind in ("cpe23Type", "cpe22Type") and "cpe" not in c:
                c["cpe"] = ref.get("referenceLocator")
        cleaned = _clean_component(c)
        if cleaned:
            out.append(cleaned)
    return out


def _dedupe(components: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in components:
        key = (c.get("group", "").lower(), c["name"].lower(), c.get("version", ""), c.get("purl", ""))
        if key not in seen:
            seen.add(key)
            out.append(c)
    out.sort(key=lambda c: (c["name"].lower(), c.get("version", "")))
    for i, c in enumerate(out):
        c["bom-ref"] = f"c{i + 1}"
    return out


def prepare(scan: dict, *, supplier: str, product: str, version: str, artifact: str,
            artifact_sha256: str = "", evidence: str = "binary-scan", source_url: str = "",
            product_type: str = "application", attest: bool = False) -> dict:
    """Build the submission document from a parsed scanner output."""
    if scan.get("bomFormat") == "CycloneDX":
        components = components_from_cyclonedx(scan)
        tools = _tools_from_cyclonedx(scan.get("metadata") or {})
    elif str(scan.get("spdxVersion", "")).startswith("SPDX-"):
        components = components_from_spdx(scan)
        tools = _tools_from_spdx(scan)
    else:
        raise ValueError("input is neither CycloneDX JSON nor SPDX JSON "
                         "(for Syft use -o cyclonedx-json; for cve-bin-tool use --sbom-type cyclonedx)")
    tools = [t for t in tools if not t["name"].startswith("xenolith")]
    tools.append({"name": "xenolith prepare", "version": PREPARE_VERSION})
    props = [{"name": "xenolith:evidence", "value": evidence},
             {"name": "xenolith:artifact", "value": artifact}]
    if artifact_sha256:
        props.append({"name": "xenolith:artifact_sha256", "value": artifact_sha256.lower()})
    if source_url:
        props.append({"name": "xenolith:source_url", "value": source_url})
    props.append({"name": "xenolith:attestation", "value": "yes" if attest else "no"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", **t} for t in tools]},
            "supplier": {"name": supplier},
            "component": {"type": product_type, "bom-ref": "product", "name": product,
                          "version": version, "supplier": {"name": supplier}},
            "properties": props,
        },
        "components": _dedupe(components),
    }


def default_path(root: Path, supplier: str, product: str, version: str) -> Path:
    return root / "community" / "sboms" / slug(supplier) / f"{slug(product)}--{slug(version)}.cdx.json"


def run(args, root: Path, catalog=None) -> int:
    scan_path = Path(args.scan)
    try:
        scan = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"error: cannot read {scan_path}: {e}")
        return 2

    artifact, digest = args.artifact, (args.artifact_sha256 or "").strip()
    local = Path(artifact)
    if local.is_file():
        digest = digest or sha256_file(local)
        artifact = local.name                      # never the full local path
    elif local.is_dir():
        print("error: --artifact must be the original file you scanned (installer, firmware image, archive), "
              "not the folder you extracted it to")
        return 2

    try:
        doc = prepare(scan, supplier=args.supplier, product=args.product, version=args.version,
                      artifact=artifact, artifact_sha256=digest, evidence=args.evidence,
                      source_url=args.source_url or "", product_type=args.product_type, attest=args.attest)
    except ValueError as e:
        print(f"error: {e}")
        return 2

    out = Path(args.output) if args.output else default_path(root, args.supplier, args.product, args.version)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        rel = out.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = out.name
    inv, errors = check(doc, rel)

    print(f"wrote {rel}: {len(doc['components'])} components from {', '.join(t['name'] for t in doc['metadata']['tools']['components'])}")
    if catalog is not None and inv:
        hits = {}
        for c in inv["components"]:
            cid = catalog.match_component(c["name"], c.get("version", ""))
            if cid:
                hits.setdefault(cid, []).append(f"{c['name']} {c['version']}".strip())
        if hits:
            print("watchlist components found: " + "; ".join(f"{k} ({', '.join(v[:3])})" for k, v in sorted(hits.items())))
    if errors:
        for e in errors:
            print(f"not ready: {e.split(': ', 1)[-1]}")
        if not args.attest:
            print("Re-run with --attest once you have confirmed you are permitted to share this component list.")
        return 1
    print("ready: review the file, then open a pull request that adds it (see CONTRIBUTING.md section 3)")
    return 0
