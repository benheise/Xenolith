"""Turn vendors' third-party notices documents into component inventories.

Vendors publish "Open Source Used In ..." documents, OSS listings, third-party
notices and acknowledgments for their products. They are the closest public
stand-in for an SBOM of a closed product: a list of the open source
components (often with versions) inside it.

Pipeline per document:
  fetch (PDF, HTML, text or SBOM JSON) -> text -> extractors -> inventory
  inventory -> watchlist matching -> "present" assertions (evidence: notices-file)

Inventories are stored in full under data/notices/, so adding a component to
the watchlist re-matches every stored document without fetching it again.

Extractors (all run; results are merged and de-duplicated):
  html_table      tables with name and version columns (Palo Alto OSS listings)
  pipe_table      the same tables rendered as text
  dotted_toc      "Name 1.2.3 ........ 12" tables of contents (Citrix/NetScaler)
  numbered_toc    "1.12 name 1.2.3" + "1.12.1 Available under license" (Cisco)
  gt_list         ">>> name-1.2.3" (VMware/Broadcom open_source_licenses.txt)
  tpn_list        "%% name version 1.2.3 NOTICES AND INFORMATION" (Microsoft ThirdPartyNotices)
  includes_prose  "This product includes X software" (F5 acknowledgments)
  sbom            CycloneDX JSON, SPDX 2 JSON / tag-value, SPDX 3 JSON-LD
"""

from __future__ import annotations

import hashlib
import html as htmllib
import io
import json
import re
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import yaml

from .. import fetch
from ..catalog import Catalog, normalize_name
from ..model import make_assertion, slug

SOURCE_ID = "notices"
MAX_BYTES = 60 * 1024 * 1024
MAX_PDF_PAGES = 800

VERSION_TOKEN = re.compile(r"^[vV]?\d[\w.\-+~:]*$")
STOP_WORDS = re.compile(
    r"\b(licen[cs]e[sd]?|copyright|notices?|appendix|section|table of contents|terms and conditions|"
    r"general public|all rights reserved|disclaimer|warrant(y|ies)|page \d+)\b", re.I)


# ----------------------------------------------------------------- helpers

def split_name_version(body: str) -> tuple[str, str]:
    """'Apache Xerces-C++ XML Parser 2.7.0' -> ('Apache Xerces-C++ XML Parser', '2.7.0')."""
    body = re.sub(r"\s+:\s*.*$", "", body.strip())        # Cisco ' :30', ' :June 13, 2012'
    body = re.sub(r"\s*\((?:https?://|www\.)[^)]*\)", "", body).strip()
    tokens = body.split()
    for i in range(1, len(tokens)):
        if VERSION_TOKEN.match(tokens[i]):
            return " ".join(tokens[:i]), " ".join(tokens[i:])
    m = re.match(r"^(.+?)[-_]v?(\d[\w.\-+~]*)$", body)
    if m and len(tokens) == 1:
        return m.group(1), m.group(2)
    return body, ""


def plausible(name: str) -> bool:
    name = name.strip()
    if not name or len(name) > 120 or not re.search(r"[A-Za-z]", name):
        return False
    return not STOP_WORDS.search(name)


class _Tables(HTMLParser):
    """Collect table rows (lists of cell text) from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.tables.append([])
        elif tag == "tr" and self.tables:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._row is not None and self._cell is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None and self.tables:
            if self._row:
                self.tables[-1].append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


NAME_HEADERS = {"name", "component", "component(s)", "components", "component name", "package", "package name", "software", "library",
                "open source component", "open source software", "project", "module", "third party software",
                "third-party software", "oss component", "software name"}
VERSION_HEADERS = {"version", "component version", "package version", "version number", "release"}


def _header_index(row: list[str]) -> tuple[int, int | None] | None:
    low = [c.strip().lower().rstrip(":") for c in row]
    ni = next((i for i, c in enumerate(low) if c in NAME_HEADERS), None)
    vi = next((i for i, c in enumerate(low) if c in VERSION_HEADERS), None)
    if ni is not None and vi is not None and ni != vi:
        return ni, vi
    # Name-only tables still count when a license column shows it's a component table.
    if ni is not None and any("licen" in c for i, c in enumerate(low) if i != ni):
        return ni, None
    return None


def _cells_at(row: list[str], idx: tuple[int, int | None]) -> tuple[str, str] | None:
    ni, vi = idx
    if len(row) <= ni or (vi is not None and len(row) <= vi):
        return None
    return row[ni], (row[vi] if vi is not None else "")


def html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|noscript)\b.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h[1-6]|pre|table|section|article|dd|dt)>", "\n", html)
    html = re.sub(r"(?i)</t[dh]>", " | ", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    return "\n".join(re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in text.splitlines())


def pdf_to_text(body: bytes) -> str:
    from pypdf import PdfReader  # imported lazily so the rest of the pipeline doesn't need it
    reader = PdfReader(io.BytesIO(body))
    parts = []
    for i, page in enumerate(reader.pages):
        if i >= MAX_PDF_PAGES:
            break
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001 - a broken page shouldn't sink the whole document
            continue
    return "\n".join(parts)


# ----------------------------------------------------------------- extractors

def ex_html_table(html: str | None) -> list[tuple[str, str]]:
    if not html:
        return []
    p = _Tables()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for table in p.tables:
        idx = None
        for row in table:
            h = _header_index(row)
            if h:
                idx = h
                continue
            got = _cells_at(row, idx) if idx else None
            if got and plausible(got[0]):
                for name in _split_multi(got[0]):
                    out.append((name, got[1]))
    return out


def _split_multi(cell: str) -> list[str]:
    """'zlib, libpng' in a name cell lists several components (Oracle-style tables)."""
    parts = [p.strip() for p in re.split(r"\s*[,;]\s*|\n", cell) if p.strip()]
    return parts if len(parts) > 1 and all(len(p) < 60 for p in parts) else [cell]


def ex_pipe_table(text: str) -> list[tuple[str, str]]:
    out, idx = [], None
    for line in text.splitlines():
        if "|" not in line:
            idx = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        h = _header_index(cells)
        if h:
            idx = h
            continue
        got = _cells_at(cells, idx) if idx else None
        if got and not set("".join(cells)) <= set("-: ") and plausible(got[0]):
            out.append(got)
    return out


DOTTED = re.compile(r"^\s*(?P<body>\S.*?\S)\s*(?:\.\s?){4,}\s*\d+\s*$")


LICENSE_ONLY = re.compile(
    r"^(?:the )?(?:bsd|mit|isc|apache|mozilla public|mpl|gnu|gpl|lgpl|agpl|eclipse public|epl|cddl|"
    r"common development and distribution|artistic|boost software|public domain|creative commons|cc[- ]?by|"
    r"python software foundation|psf|unicode|w3c|x11|wtfpl|unlicense|ms-pl|microsoft public)"
    r"(?:[\s\-]+(?:\d[\w.\-]*|clause|v\d[\w.]*|version|public|general|lesser|library|software|license|licence|"
    r"only|or later|revised|new|simplified|\+|\(\w+\)))*$", re.I)
TOC_WORDS = {"contents", "content", "table of contents", "index", "revision history", "introduction", "preface"}


def ex_dotted_toc(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = DOTTED.match(line)
        if not m:
            continue
        # Ivanti and others write "component License ...... 12"; the label isn't part of the name.
        raw = m.group("body")
        body = re.sub(r"\s+(?:licen[cs]es?|notices?|attributions?)$", "", raw, flags=re.I).strip()
        if body != raw.strip() and LICENSE_ONLY.match(body):
            continue   # a license section ("BSD 3-Clause License"), not a component
        if body.lower() in TOC_WORDS or re.match(r"^\d+ lines\b", body) or not plausible(body):
            continue
        name, ver = split_name_version(body)
        if plausible(name):
            out.append((name, ver))
    return out


NUMBERED = re.compile(r"^\s*(\d+)\.(\d+)\s+(?P<body>\S.*?)\s*$")
NUMBERED_SUB = re.compile(r"^\s*(\d+)\.(\d+)\.1\s+(?:Available under license|Notifications|Notices)", re.I)


def ex_numbered_toc(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    confirmed = {(m.group(1), m.group(2)) for line in lines if (m := NUMBERED_SUB.match(line))}
    if not confirmed:
        return []
    out, seen = [], set()
    for line in lines:
        m = NUMBERED.match(line)
        if not m or (m.group(1), m.group(2)) not in confirmed or (m.group(1), m.group(2)) in seen:
            continue
        seen.add((m.group(1), m.group(2)))
        name, ver = split_name_version(m.group("body"))
        if plausible(name):
            out.append((name, ver))
    return out


def ex_gt_list(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*>>>\s*(?P<body>\S.*?)\s*$", line)
        if not m:
            continue
        body = m.group("body")
        mm = re.match(r"^(?P<name>.+?)-(?P<ver>v?\d[\w.\-+~:]*)$", body)
        name, ver = (mm.group("name"), mm.group("ver")) if mm else split_name_version(body)
        if plausible(name):
            out.append((name, ver))
    return out


def ex_tpn_list(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*%%\s+(?P<body>.+?)\s+NOTICES(?:\s|,|$)", line, re.I)
        if not m:
            continue
        body = re.sub(r"\s*\([^)]*\)", "", m.group("body")).strip()
        mm = re.match(r"^(?P<name>.+?)\s+(?:version\s+)?(?P<ver>v?\d[\w.\-+~:]*)$", body, re.I)
        name, ver = (mm.group("name"), mm.group("ver")) if mm else (body, "")
        if plausible(name):
            out.append((name, ver))
    return out


INCLUDES = re.compile(
    r"This product (?:includes|contains|uses|incorporates) (?:the |a |an )?"
    r"(?P<name>[A-Za-z0-9][\w.+\-/]*(?: [A-Za-z0-9][\w.+\-/]*){0,4}?)"
    r"(?:,? (?:version|v\.?) ?(?P<ver>\d[\w.\-+]*))?"
    r"(?= software| softwares| librar| package| code| module| component| toolkit| project| patch|,|;|\.(?:\s|$)| \(| developed| which| from| distributed| copyright| by )",
    re.I)


# Boilerplate from standard license texts ("This product includes cryptographic software written by ...").
PROSE_STOP_FIRST = {"cryptographic", "software", "either", "portions", "code", "material", "materials",
                    "technology", "copyrighted", "certain", "some", "other", "additional", "third-party"}


def ex_includes_prose(text: str) -> list[tuple[str, str]]:
    flat = re.sub(r"\s+", " ", text)
    out = []
    for m in INCLUDES.finditer(flat):
        name = m.group("name").strip()
        first = name.lower().split()[0]
        if name.lower() in {"software", "the following", "following", "open source", "third party"} \
                or first in PROSE_STOP_FIRST or "written" in name.lower():
            continue
        if plausible(name):
            out.append((name, m.group("ver") or ""))
    return out


DROPDOWN_HEAD = re.compile(
    r'class="[^"]*MCDropDownHead[^"]*h2closed[^"]*"[^>]*>\s*<a[^>]*>(?:\s*<img[^>]*>)?\s*(?P<name>[^<]+?)\s*</a>', re.I)
DROPDOWN_SKIP = {"copyright", "copyrights", "license", "licenses", "notice", "notices", "source", "source code"}


def ex_dropdown_heads(html: str | None) -> list[tuple[str, str]]:
    """Component names from MadCap Flare collapsible sections (one per component)."""
    if not html:
        return []
    out = []
    for m in DROPDOWN_HEAD.finditer(html):
        name = htmllib.unescape(m.group("name")).strip()
        if name.lower() not in DROPDOWN_SKIP and plausible(name):
            out.append(split_name_version(name))
    return out


def ex_sbom(obj) -> list[tuple[str, str]]:
    out = []
    if not isinstance(obj, dict):
        return out
    if obj.get("bomFormat") == "CycloneDX":
        stack = list(obj.get("components") or [])
        while stack:
            c = stack.pop()
            if isinstance(c, dict):
                if c.get("name"):
                    full = f"{c['group']}:{c['name']}" if c.get("group") else c["name"]
                    out.append((full, str(c.get("version") or "")))
                stack.extend(c.get("components") or [])
    elif obj.get("spdxVersion"):
        for p in obj.get("packages") or []:
            if p.get("name"):
                out.append((p["name"], str(p.get("versionInfo") or "")))
    elif "@graph" in obj:
        for e in obj["@graph"]:
            if isinstance(e, dict) and e.get("type") == "software_Package" and e.get("name"):
                out.append((e["name"], str(e.get("software_packageVersion") or "")))
    return out


def ex_spdx_tag(text: str) -> list[tuple[str, str]]:
    if "SPDXVersion:" not in text:
        return []
    out, name = [], None
    for line in text.splitlines():
        if line.startswith("PackageName:"):
            if name:
                out.append((name, ""))
            name = line.split(":", 1)[1].strip()
        elif line.startswith("PackageVersion:") and name:
            out.append((name, line.split(":", 1)[1].strip()))
            name = None
    if name:
        out.append((name, ""))
    return out


def extract(body: bytes, content_type: str, url: str) -> tuple[list[dict], list[str], str]:
    """Return (components [{name, version}], extractors that produced results, document kind)."""
    ct = (content_type or "").lower()
    lower_url = url.lower().split("?")[0]
    kind, text, html, obj = "text", "", None, None
    if body[:5] == b"%PDF-" or "pdf" in ct or lower_url.endswith(".pdf"):
        kind, text = "pdf", pdf_to_text(body)
    else:
        raw = body.decode("utf-8-sig", errors="replace")
        stripped = raw.lstrip()
        if stripped.startswith("{") and ("json" in ct or lower_url.endswith(".json") or '"bomFormat"' in raw[:2000] or '"spdxVersion"' in raw[:2000] or '"@graph"' in raw[:4000]):
            try:
                obj = json.loads(raw)
                kind = "sbom"
            except json.JSONDecodeError:
                obj = None
        if obj is None and ("html" in ct or re.search(r"(?i)<html|<table|<body", raw[:20000])):
            kind, html, text = "html", raw, html_to_text(raw)
        elif obj is None:
            text = raw

    results: dict[str, list[tuple[str, str]]] = {}
    if obj is not None:
        results["sbom"] = ex_sbom(obj)
    else:
        results["html_table"] = ex_html_table(html)
        if not results["html_table"]:
            results["pipe_table"] = ex_pipe_table(text)
        results["spdx_tag"] = ex_spdx_tag(text)
        results["numbered_toc"] = ex_numbered_toc(text)
        results["dotted_toc"] = ex_dotted_toc(text)
        results["gt_list"] = ex_gt_list(text)
        results["tpn_list"] = ex_tpn_list(text)
        if not any(results.values()):
            results["dropdown_heads"] = ex_dropdown_heads(html)
        # Prose is the weakest signal; only use it when nothing structured was found.
        if not any(results.values()):
            results["includes_prose"] = ex_includes_prose(text)

    seen: dict[tuple[str, str], dict] = {}
    for rows in results.values():
        for name, ver in rows:
            name = re.sub(r"\s+", " ", name).strip(" -–:;,")
            ver = re.sub(r"\s+", " ", ver or "").strip(" ,;")
            key = (normalize_name(name), ver.lower())
            if name and key not in seen:
                seen[key] = {"name": name, "version": ver}
    used = [k for k, v in results.items() if v]
    comps = sorted(seen.values(), key=lambda c: (normalize_name(c["name"]), c["version"]))
    return comps, used, kind


# ----------------------------------------------------------------- registry and discovery

def _anchor_links(html: str, base: str) -> list[tuple[str, str]]:
    out = []
    for href, inner in re.findall(r'(?is)<a\b[^>]*\bhref="([^"]+)"[^>]*>(.*?)</a>', html):
        text = re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", inner))).strip()
        out.append((urljoin(base, htmllib.unescape(href)), text))
    return out


def discover(rule: dict, log=print) -> list[dict]:
    """Find notices documents linked from an index page.

    rule: {supplier, index, link (regex on absolute URL), title (regex with
    named groups product and version, applied to the link text)}.
    """
    page = fetch.get_text(rule["index"], timeout=90)
    link_re = re.compile(rule["link"], re.I)
    title_re = re.compile(rule["title"], re.I)
    docs: dict[str, dict] = {}
    for url, text in _anchor_links(page, rule["index"]):
        if not link_re.search(url):
            continue
        m = title_re.search(text)
        if not m:
            continue
        product = (rule.get("product_prefix", "") + m.group("product")).strip()
        docs.setdefault(url, {"supplier": rule["supplier"], "product": product,
                              "version": m.groupdict().get("version") or "", "url": url,
                              "discovered_by": rule["index"]})
    log(f"  {rule['supplier']}: {len(docs)} documents linked from {rule['index']}")
    return list(docs.values())


def discover_versions(rule: dict, log=print) -> list[dict]:
    """Build document URLs from a JSON list of released versions (Elastic's artifacts API).

    rule: {type: versions_json, supplier, product, versions_url, field, url_template,
           exclude (regex), keep_latest_per_minor (bool), limit (int)}
    """
    data = fetch.get_json(rule["versions_url"])
    versions = [v for v in data.get(rule.get("field", "versions"), []) if isinstance(v, str)]
    if rule.get("exclude"):
        versions = [v for v in versions if not re.search(rule["exclude"], v)]
    versions = [v for v in versions if re.match(r"^\d+(\.\d+)*$", v)]
    key = lambda v: [int(x) for x in v.split(".")]
    versions.sort(key=key, reverse=True)
    if rule.get("keep_latest_per_minor", True):
        # Reports often lag the newest patch release, so take the newest patch
        # per minor whose document actually exists (checked with HEAD requests).
        by_minor: dict[tuple, list[str]] = {}
        for v in versions:
            by_minor.setdefault(tuple(key(v)[:2]), []).append(v)
        latest = []
        for minor in sorted(by_minor, reverse=True):
            for v in by_minor[minor][:4]:
                if _exists(rule["url_template"].format(version=v)):
                    latest.append(v)
                    break
            if len(latest) >= int(rule.get("limit", 4)):
                break
        versions = latest
    versions = versions[: int(rule.get("limit", 4))]
    docs = [{"supplier": rule["supplier"], "product": rule["product"], "version": v,
             "url": rule["url_template"].format(version=v), "discovered_by": rule["versions_url"]} for v in versions]
    log(f"  {rule['supplier']} {rule['product']}: versions {', '.join(versions)}")
    return docs


def load_registry(path: Path, *, discover_docs: bool = True, log=print) -> list[dict]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    docs: dict[str, dict] = {}
    for d in cfg.get("documents") or []:
        docs[d["url"]] = {**d, "version": str(d.get("version") or "")}
    if discover_docs:
        for rule in cfg.get("discover") or []:
            try:
                found = discover_versions(rule, log=log) if rule.get("type") == "versions_json" else discover(rule, log=log)
                for d in found:
                    docs.setdefault(d["url"], d)
            except fetch.FetchError as e:
                log(f"  ! discovery failed for {rule.get('index')}: {e}")
    return list(docs.values())


def inventory_path(data_dir: Path, doc: dict) -> Path:
    h = hashlib.sha1(doc["url"].encode()).hexdigest()[:8]
    name = f"{slug(doc['product'])}--{slug(doc.get('version') or 'all')}--{h}.json"
    return data_dir / "notices" / slug(doc["supplier"]) / name


# ----------------------------------------------------------------- crawl

def crawl(registry_path: Path, *, data_dir: Path, max_fetch: int = 80, refresh_days: int = 14,
          only: list[str] | None = None, discover_docs: bool = True, log=print) -> dict:
    docs = load_registry(registry_path, discover_docs=discover_docs, log=log)
    if only:
        docs = [d for d in docs if any(o.lower() in f"{d['supplier']} {d['product']}".lower() for o in only)]
    state_path = data_dir / "state" / "notices.json"
    state: dict[str, dict] = json.loads(state_path.read_text()) if state_path.exists() else {}
    today = date.today()
    cutoff = (today - timedelta(days=refresh_days)).isoformat()

    def due(d):
        st = state.get(d["url"])
        return st is None or st.get("fetched", "") < cutoff or not inventory_path(data_dir, d).exists() and st.get("status") == "ok"

    todo = [d for d in docs if due(d)]
    todo.sort(key=lambda d: state.get(d["url"], {}).get("fetched", ""))   # never-fetched first
    stats = {"documents": len(docs), "due": len(todo), "fetched": 0, "parsed": 0, "unchanged": 0,
             "empty": 0, "errors": 0}
    for d in todo[:max_fetch]:
        url = d["url"]
        try:
            body, ctype = _get(url)
        except fetch.FetchError as e:
            stats["errors"] += 1
            state[url] = {**state.get(url, {}), "fetched": today.isoformat(), "status": "error", "error": str(e)[:200]}
            log(f"  ! {e}")
            continue
        stats["fetched"] += 1
        sha = hashlib.sha256(body).hexdigest()
        inv = inventory_path(data_dir, d)
        if state.get(url, {}).get("sha") == sha and inv.exists():
            state[url].update(fetched=today.isoformat())
            stats["unchanged"] += 1
            continue
        try:
            comps, used, kind = extract(body, ctype, url)
        except Exception as e:  # noqa: BLE001 - one bad document must not stop the crawl
            stats["errors"] += 1
            state[url] = {"fetched": today.isoformat(), "status": "error", "error": f"parse: {e}"[:200], "sha": sha}
            log(f"  ! parse failed {url}: {e}")
            continue
        status = "ok" if comps else "empty"
        stats["parsed" if comps else "empty"] += 1
        state[url] = {"fetched": today.isoformat(), "status": status, "sha": sha, "n": len(comps),
                      "via": used, "kind": kind}
        if comps:
            inv.parent.mkdir(parents=True, exist_ok=True)
            inv.write_text(json.dumps({
                "supplier": d["supplier"], "product": d["product"], "version": d.get("version", ""),
                "url": url, "retrieved": today.isoformat(), "sha256": sha, "kind": kind,
                "extractors": used, "components": comps,
            }, ensure_ascii=False, indent=0, sort_keys=True) + "\n", encoding="utf-8")
        log(f"  {d['supplier']} {d['product']} {d.get('version', '')}: {len(comps)} components via {', '.join(used) or 'nothing'}")
    stats["remaining"] = max(0, len(todo) - max_fetch)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True, indent=0) + "\n")
    return stats


def _exists(url: str) -> bool:
    import urllib.request
    from .. import USER_AGENT
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001
        return False


def _get(url: str) -> tuple[bytes, str]:
    """Fetch with a size cap; returns (body, content type)."""
    import urllib.request
    from .. import USER_AGENT
    last = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                length = int(resp.headers.get("Content-Length") or 0)
                if length > MAX_BYTES:
                    raise fetch.FetchError(f"{url}: {length // (1024 * 1024)} MB exceeds the {MAX_BYTES // (1024 * 1024)} MB cap")
                body = resp.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise fetch.FetchError(f"{url}: larger than the {MAX_BYTES // (1024 * 1024)} MB cap")
                return body, resp.headers.get("Content-Type", "")
        except fetch.FetchError:
            raise
        except Exception as e:  # noqa: BLE001
            last = e
            if getattr(e, "code", None) in (401, 403, 404, 410):
                break
    raise fetch.FetchError(f"{url}: {last}")


# ----------------------------------------------------------------- assertions

def iter_inventories(data_dir: Path):
    for p in sorted((data_dir / "notices").rglob("*.json")):
        try:
            yield p, json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue


def assertions(catalog: Catalog, data_dir: Path) -> tuple[list[dict], dict]:
    """Match every stored inventory against the watchlist."""
    out = []
    stats = {"inventories": 0, "components": 0, "matches": 0}
    for _, inv in iter_inventories(data_dir):
        stats["inventories"] += 1
        stats["components"] += len(inv.get("components", []))
        hits: dict[str, list[dict]] = {}
        for c in inv.get("components", []):
            cid = catalog.match_component(c["name"], c.get("version", ""))
            if cid:
                hits.setdefault(cid, []).append(c)
        for cid, comps in hits.items():
            stats["matches"] += 1
            listed = "; ".join(f"{c['name']} {c['version']}".strip() for c in comps[:6])
            versions = ", ".join(dict.fromkeys(c["version"] for c in comps if c.get("version")))
            pv = inv.get("version", "")
            out.append(make_assertion(
                component=cid,
                supplier=inv["supplier"],
                product=inv["product"],
                version=pv,
                cves={},
                status="present",
                evidence="notices-file",
                source=SOURCE_ID,
                publisher=inv["supplier"],
                source_url=inv["url"],
                notes=f"Listed in {inv['supplier']}'s open source notices for {inv['product']}"
                      f"{' ' + pv if pv else ''} as: {listed}.",
                category="Third-party notices",
                updated=inv.get("retrieved", ""),
                component_version=versions,
            ))
    return out, stats


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
