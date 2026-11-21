"""Write the watchlist name matcher xenolith-scan embeds.

    python tools/export_watchlist.py

Reads catalog/components.yaml and writes scan/internal/watchlist/watchlist.min.json:
[[id, name, [[pattern, version, not_version], ...]], ...]. The scanner uses it to link a
finding to its census component by name, the way the census does when it ingests an
SBOM, so every component on the watchlist is recognised without a fingerprint of its own.
Go's regexp has no lookahead, so a version rule of the form ^(?!X) is exported as the
negated pattern ^X.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "catalog" / "components.yaml"
DST = ROOT / "scan" / "internal" / "watchlist" / "watchlist.min.json"
LOOK = re.compile(r"\(\?<?[!=]|\\[1-9]|\(\?P=")


def rows(src: Path = SRC) -> list:
    """The snapshot as data; raises ValueError for a pattern Go cannot compile."""
    rows = []
    for c in yaml.safe_load(src.read_text(encoding="utf-8"))["components"]:
        pats = []
        for e in c.get("notices_names") or []:
            pattern, version = (e["pattern"], e.get("version", "")) if isinstance(e, dict) else (e, "")
            negated = ""
            if m := re.fullmatch(r"\^\(\?!(.+)\)", version):
                version, negated = "", "^" + m.group(1)
            if LOOK.search(pattern) or LOOK.search(version) or LOOK.search(negated):
                raise ValueError(f"{c['id']}: pattern needs a construct Go's regexp lacks: {pattern!r} {version!r}")
            pats.append([pattern, version, negated])
        rows.append([c["id"], c["name"], pats])
    return rows


def main() -> int:
    try:
        data = rows()
    except ValueError as e:
        print(f"error: {e}")
        return 2
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {DST.relative_to(ROOT)}: {len(data)} components, {sum(len(r[2]) for r in data)} name patterns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
