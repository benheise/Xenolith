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
    notices_names: list = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return [c.upper() for inc in self.incidents for c in inc.get("cves", [])]

    def matchers(self) -> list[tuple[re.Pattern, re.Pattern | None]]:
        out = []
        for entry in self.notices_names:
            if isinstance(entry, dict):
                out.append((re.compile(entry["pattern"], re.I),
                            re.compile(entry["version"], re.I) if entry.get("version") else None))
            else:
                out.append((re.compile(entry, re.I), None))
        return out


def normalize_name(name: str) -> str:
    """Lowercase, trim and collapse whitespace in a third-party component name."""
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def name_variants(name: str) -> list[str]:
    """The name itself plus its last coordinate segment
    (org.apache.logging.log4j:log4j-core -> log4j-core, github.com/google/brotli -> brotli)."""
    n = normalize_name(name)
    out = [n]
    tail = re.split(r"[:/]", n)[-1]
    if tail and tail != n:
        out.append(tail)
    return out


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

    def match_component(self, name: str, version: str = "") -> str | None:
        """Return the watchlist component id a third-party component name refers to, if any."""
        if not hasattr(self, "_matchers"):
            self._matchers = [(c.id, m) for c in self.components.values() for m in c.matchers()]
        for variant in name_variants(name):
            for cid, (pattern, vpattern) in self._matchers:
                if pattern.fullmatch(variant) and (vpattern is None or vpattern.match(version or "")):
                    return cid
        return None


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
            notices_names=list(c.get("notices_names", [])),
        )
        comps[c["id"]].matchers()  # validate regexes at load time
    src_raw = yaml.safe_load((catalog_dir / "sources.yaml").read_text(encoding="utf-8"))
    sources = {s["id"]: s for s in src_raw["sources"]}
    cat = Catalog(components=comps, sources=sources)
    _ = cat.cve_to_component  # validate: each CVE maps to one component
    return cat


def normalize_cve(text: str) -> str | None:
    m = CVE_RE.search(text or "")
    return m.group(0).upper() if m else None
