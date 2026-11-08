"""Load the component watchlist and source registry from catalog/."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class Component:
    id: str
    name: str
    upstream: str = ""
    purl: str = ""
    cpe: str = ""
    aliases: list[str] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return [c.upper() for inc in self.incidents for c in inc.get("cves", [])]


@dataclass
class Catalog:
    components: dict[str, Component]
    sources: dict[str, dict]

    @property
    def cve_to_component(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for comp in self.components.values():
            for cve in comp.cves:
                if cve in out and out[cve] != comp.id:
                    raise ValueError(f"{cve} is listed under both {out[cve]} and {comp.id}")
                out[cve] = comp.id
        return out

    @property
    def watchlist(self) -> set[str]:
        return set(self.cve_to_component)


def load(catalog_dir: Path = CATALOG) -> Catalog:
    comps_raw = yaml.safe_load((catalog_dir / "components.yaml").read_text(encoding="utf-8"))
    comps: dict[str, Component] = {}
    for c in comps_raw["components"]:
        if c["id"] in comps:
            raise ValueError(f"duplicate component id {c['id']}")
        comps[c["id"]] = Component(
            id=c["id"],
            name=c["name"],
            upstream=c.get("upstream", ""),
            purl=c.get("purl", ""),
            cpe=c.get("cpe", ""),
            aliases=list(c.get("aliases", [])),
            incidents=list(c.get("incidents", [])),
        )
    src_raw = yaml.safe_load((catalog_dir / "sources.yaml").read_text(encoding="utf-8"))
    sources = {s["id"]: s for s in src_raw["sources"]}
    cat = Catalog(components=comps, sources=sources)
    _ = cat.cve_to_component  # validate: each CVE maps to one component
    return cat


def normalize_cve(text: str) -> str | None:
    m = CVE_RE.search(text or "")
    return m.group(0).upper() if m else None
