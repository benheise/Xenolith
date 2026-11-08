"""Write the product-registry snapshot xenolith-scan embeds for product identity.

    python tools/export_registry.py            # after `python -m xenolith build`

Reads docs/data/products.json (every product Xenolith knows, with CPE vendor:product
pairs where the registry has them) and writes a compact JSON array to
scan/internal/registry/products.min.json: [key, supplier, product, [cpes], kev]. Only
products with some signal are kept (an inventory, a statement, a KEV entry or a CPE), so
the file stays small enough to ship inside the scanner.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "data" / "products.json"
DST = ROOT / "scan" / "internal" / "registry" / "products.min.json"


def main() -> int:
    if not SRC.exists():
        print(f"error: {SRC} missing; run `python -m xenolith build` first")
        return 2
    items = json.loads(SRC.read_text(encoding="utf-8"))
    rows = []
    for p in items:
        if not (p.get("n") or p.get("inv") or p.get("kev") or p.get("cpe") or p.get("w")):
            continue
        rows.append([p["k"], p["s"], p["p"], sorted(p.get("cpe") or [])[:4], int(p.get("kev") or 0)])
    rows.sort(key=lambda r: r[0])
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {DST.relative_to(ROOT)}: {len(rows)} products ({DST.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
