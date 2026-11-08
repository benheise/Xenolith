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
  component_license  "Components:" list of name+version then license (NetApp NOTICE.pdf)
  source_archives    directory listing of a source offer: "h2-1.4.198-sources.jar" (NetApp)
  url_lines          "jedis 2.9.0: https://github.com/... MIT" (Extreme Networks)
  license_groups     "Packages that use this license: (D-Bus 1.14.8, ...)" (Extreme Networks)
  jar_names          versioned jar file names in running text: "commons-text-1.10.0.jar" (ManageEngine)
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


LICENSE_LINE = re.compile(
    r"(\bLicen[cs]e\b|\bPublic Domain\b|\bCreative Commons\b|\bUnlicense\b|^\(|\bexception\b|"
    r"^(?:Unicode|W3C|SSLeay|Sleepycat|Beerware|WTFPL|0BSD|Zlib)\b)")
CL_START = re.compile(r"(?im)^\s*Components:\s*$")
CL_END = re.compile(r"(?im)^\s*Licenses:\s*$")


def _cl_split(body: str) -> tuple[str, str]:
    """Name/version for one notice-report entry: the version is the last one or two tokens."""
    tokens = body.split()
    for i in range(1, len(tokens)):
        tok = tokens[i]
        if VERSION_TOKEN.match(tok) and not re.match(r"^\d+(st|nd|rd|th)$", tok) and len(tokens) - i <= 2:
            return " ".join(tokens[:i]), " ".join(tokens[i:])
    if len(tokens) == 1:
        m = re.match(r"^(.+?)[-_]v?(\d[\w.\-+~]*)$", body)
        if m:
            return m.group(1), m.group(2)
    return body, ""


def ex_component_license(text: str) -> list[tuple[str, str]]:
    """NetApp-style notice reports: after a "Components:" heading, each entry is the
    component name and version (often wrapped over two or three lines) followed by
    its license expression (one line, or several lines inside parentheses).
    """
    m = CL_START.search(text or "")
    if not m:
        return []
    body = text[m.end():]
    end = CL_END.search(body)
    lines, prev_blank = [], True
    for raw in (body[:end.start()] if end else body).splitlines():      # drop blanks, headers, page numbers
        line = raw.strip()
        if not line or (line.isdigit() and len(line) <= 4 and prev_blank) or line in ("Component", "License", "Component License"):
            prev_blank = prev_blank or not line
            continue
        prev_blank = False
        lines.append(line)

    out: list[tuple[str, str]] = []

    def emit(name: str, version: str):
        name = re.sub(r"\s+", " ", name).strip()
        if plausible(name) and name.lower() not in ("component", "components"):
            out.append((name, "" if version.lower() == "unspecified" else version))

    def is_version_line(line: str) -> bool:
        return " " not in line and bool(VERSION_TOKEN.match(line))

    buf: list[str] = []
    i, depth, in_license = 0, 0, False
    while i < len(lines):
        line = lines[i]
        i += 1
        if depth > 0:                                   # inside a multi-line "( ... AND ... )"
            depth += line.count("(") - line.count(")")
            continue
        if in_license:
            in_license = False
            if line.startswith("("):
                depth = line.count("(") - line.count(")")
                continue
            if LICENSE_LINE.search(line):
                continue
        if buf and LICENSE_LINE.search(line):           # entry without a version
            emit(" ".join(buf), "")
            buf = []
            depth = line.count("(") - line.count(")") if line.startswith("(") else 0
            continue
        # A package name wrapped mid-word ("@babel/plugin-transform-log" + "ical-...")
        if buf and " " not in buf[-1] and re.search(r"[-/@]", buf[-1]) and re.match(r"[a-z]", line) \
                and not _cl_split(buf[-1])[1]:
            buf[-1] += line
        else:
            buf.append(line)
        joined = " ".join(buf)
        if line == "Unspecified" or joined.endswith(" Unspecified"):
            name, version = re.sub(r"\s*Unspecified$", "", joined), ""
        else:
            name, version = _cl_split(joined)
            if version and " " not in joined and i < len(lines) and is_version_line(lines[i]):
                continue                                # "xen-utils-3.2-1" then "4.17.5+23-g…"
            if not version and len(buf) < 4:
                continue
        emit(name, version)
        buf = []
        in_license = True
    return out


ARCHIVE_EXT = re.compile(r"(?i)(\.src)?\.(tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tgz|tbz2|txz|tar|zip|jar|rpm|deb|gem|whl|js)$")
ARCHIVE_SUFFIX = re.compile(r"(?i)[-_.](sources?|src|orig|dfsg)$")
ARCHIVE_NAME_VERSION = re.compile(r"^(?P<n>[A-Za-z][\w.+-]*?)[-_]v?(?P<v>\d[\w.+~]*(?:-(?:[A-Za-z]{1,3}\d*|\d[\w.+~]*))*)$")


def archive_name_version(filename: str) -> tuple[str, str] | None:
    """'h2-1.4.198-sources.jar' -> ('h2', '1.4.198'); None for files that aren't versioned archives."""
    stem = filename.rsplit("/", 1)[-1]
    if not ARCHIVE_EXT.search(stem):
        return None
    stem = ARCHIVE_EXT.sub("", stem)
    for _ in range(2):
        stem = ARCHIVE_SUFFIX.sub("", stem)
    if re.search(r"_\d{12,}$", stem):          # vendor bundle stamped with a build timestamp
        return None
    m = ARCHIVE_NAME_VERSION.match(stem)
    if not m:
        return None
    return m.group("n"), m.group("v")


def ex_source_archives(html: str | None) -> list[tuple[str, str]]:
    """Directory listings of a product's source offer: each archive name is a component."""
    if not html:
        return []
    out = []
    for href in re.findall(r'(?i)<a\s[^>]*href="([^"?#/][^"]*)"', html):
        nv = archive_name_version(htmllib.unescape(href))
        if nv and plausible(nv[0]):
            out.append(nv)
    return out


URL_LINE = re.compile(r"(?m)^\s*(?P<n>\S.{0,150}?)\s+(?P<v>v?\d[\w.\-+~]*):\s+https?://")
LICENSE_GROUP = re.compile(r"Packages that use this license:\s*\(")


def ex_url_lines(text: str) -> list[tuple[str, str]]:
    """Black Duck style reports: "jedis 2.9.0: https://github.com/xetorthio/jedis MIT" (Extreme Networks)."""
    out = []
    for m in URL_LINE.finditer(text or ""):
        name = m.group("n").strip()
        if plausible(name):
            out.append((name, m.group("v")))
    return out


def ex_license_groups(text: str) -> list[tuple[str, str]]:
    """Reports grouped by license: "Packages that use this license: (D-Bus 1.14.8, dbus-glib 0.112)"."""
    out = []
    for m in LICENSE_GROUP.finditer(text or ""):
        depth, i, start = 1, m.end(), m.end()
        while i < len(text) and depth and i - start < 200_000:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        body = re.sub(r"\s+", " ", text[start:i - 1])
        for item in re.split(r",\s+(?![^()]*\))", body):
            name, version = split_name_version(item.strip())
            if version and plausible(name):
                out.append((name, version))
    return out


JAR_NAME = re.compile(r"(?<![\w.-])([A-Za-z][\w.+-]*?-\d[\w.+~-]*\.jar)\b")


def ex_jar_names(text: str) -> list[tuple[str, str]]:
    """Versioned jar file names anywhere in the text: "commons-text-1.10.0.jar" (ManageEngine)."""
    out = []
    text = re.sub(r"(?<=\d\.) (?=\d)", "", text or "")          # "commons-lang3-3. 18.0.jar" (PDF spacing)
    text = re.sub(r"(?<=[\w.])-\n(?=[\w])", "-", text)        # names wrapped after a hyphen
    for name in JAR_NAME.findall(text):
        nv = archive_name_version(name)
        if nv and plausible(nv[0]):
            out.append(nv)
    return out


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
    elif isinstance(obj.get("components"), list):
        # Plain component lists: {"components": [{"name", "version", "licenses"}]} (Veeam)
        for c in obj["components"]:
            if isinstance(c, dict) and c.get("name"):
                out.append((str(c["name"]), str(c.get("version") or "")))
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
    elif html and re.search(r"(?i)<title>\s*Index of /", html[:3000]):
        kind = "listing"
        results["source_archives"] = ex_source_archives(html)
    else:
        results["html_table"] = ex_html_table(html)
        if not results["html_table"]:
            results["pipe_table"] = ex_pipe_table(text)
        results["spdx_tag"] = ex_spdx_tag(text)
        results["numbered_toc"] = ex_numbered_toc(text)
        results["dotted_toc"] = ex_dotted_toc(text)
        results["gt_list"] = ex_gt_list(text)
        results["tpn_list"] = ex_tpn_list(text)
        results["component_license"] = ex_component_license(text)
        results["url_lines"] = ex_url_lines(text)
        results["license_groups"] = ex_license_groups(text)
        results["jar_names"] = ex_jar_names(text)
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


def _listing(url: str) -> list[str]:
    """Entries of an Apache/nginx-style directory listing (names relative to url)."""
    page = fetch.get_text(url, timeout=60)
    out = []
    for href in re.findall(r'(?i)<a\s[^>]*href="([^"?#][^"]*)"', page):
        href = htmllib.unescape(href)
        if href.startswith(("/", "http:", "https:", "../", "./")):
            continue
        out.append(href)
    return out


def discover_autoindex(rule: dict, log=print) -> list[dict]:
    """Walk a directory listing laid out as <product>/<version>/<notice file>.

    rule: {type: autoindex, supplier, index, file (regex for the notice file name),
           products: {directory: product name, or {name, version, latest}},
           version (regex with group v, searched in each version directory name),
           exclude (regex on version directory names), latest (newest versions kept per
           product, default 3)}
    """
    from ..versions import version_key
    file_re = re.compile(rule.get("file", r"(?i)notice.*\.pdf$"))
    exclude = re.compile(rule["exclude"]) if rule.get("exclude") else None
    base = rule["index"].rstrip("/") + "/"
    docs: list[dict] = []
    for directory, spec in (rule.get("products") or {}).items():
        spec = spec if isinstance(spec, dict) else {"name": spec}
        product = spec["name"]
        ver_re = re.compile(spec.get("version") or rule.get("version") or r"^(?P<v>.+)$")
        keep = int(spec.get("latest") or rule.get("latest", 3))
        try:
            entries = _listing(base + directory.strip("/") + "/")
        except fetch.FetchError as e:
            log(f"  ! {rule['supplier']} {product}: {e}")
            continue
        versions: dict[str, str] = {}
        for entry in entries:
            name = entry.rstrip("/")
            if not entry.endswith("/") or (exclude and exclude.search(name)):
                continue
            m = ver_re.search(name)
            if m and m.group("v") and version_key(m.group("v")) is not None:
                versions.setdefault(m.group("v"), entry)
        found = []
        for v in sorted(versions, key=version_key, reverse=True)[: int(rule.get("max_folders", 12))]:
            folder = base + directory.strip("/") + "/" + versions[v]
            try:
                files = _listing(folder)
            except fetch.FetchError:
                continue
            notice = next((f for f in files if file_re.search(f)), None)
            if notice:
                url = folder + notice
            elif rule.get("archives") and sum(1 for f in files if archive_name_version(f)) >= 3:
                url = folder            # no notice report: the source archives are the component list
            else:
                continue
            found.append(v)
            docs.append({"supplier": rule["supplier"], "product": product, "version": v,
                         "url": url, "discovered_by": base + directory})
            if len(found) >= keep:
                break
        log(f"  {rule['supplier']} {product}: {', '.join(found) or 'no notices found'}")
    return docs


def discover_table(rule: dict, log=print) -> list[dict]:
    """Index pages that are a table of product | version | link (Extreme Networks).

    rule: {type: table, supplier, index, product_column, version_column (0-based td
           index), link (regex for the document URL), exclude (regex on versions),
           latest (newest versions kept per product, default 2)}
    """
    from ..versions import version_key
    page = fetch.get_text(rule["index"], timeout=90)
    link_re = re.compile(rule.get("link", "."))
    exclude = re.compile(rule["exclude"]) if rule.get("exclude") else None
    pc, vc = int(rule.get("product_column", 0)), int(rule.get("version_column", 1))
    by_product: dict[str, dict[str, str]] = {}
    for row in re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", page):
        row = re.sub(r'(?is)<(span|div)[^>]*display:\s*none[^>]*>.*?</\1>', "", row)   # hidden sort keys
        cells = [re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"(?is)<td[^>]*>(.*?)</td>", row)]
        links = [urljoin(rule["index"], htmllib.unescape(h)) for h in re.findall(r'(?i)href="([^"]+)"', row)]
        link = next((u for u in links if link_re.search(u)), None)
        if not link or len(cells) <= max(pc, vc):
            continue
        product, version = cells[pc], cells[vc]
        if not re.match(r"[A-Za-z]", product) or not version or (exclude and exclude.search(version)) \
                or version_key(version) is None:
            continue
        by_product.setdefault(product, {}).setdefault(version, link)
    docs = []
    keep = int(rule.get("latest", 2))
    for product, versions in sorted(by_product.items()):
        for v in sorted(versions, key=version_key, reverse=True)[:keep]:
            docs.append({"supplier": rule["supplier"], "product": product, "version": v,
                         "url": versions[v], "discovered_by": rule["index"]})
    log(f"  {rule['supplier']}: {len(docs)} documents for {len(by_product)} products from {rule['index']}")
    return docs


def discover_embedded_json(rule: dict, log=print) -> list[dict]:
    """Product/version pickers whose options are a JSON config embedded in the page (Veeam).

    rule: {type: embedded_json, supplier, index, config (regex; group 1 is the
           HTML-escaped JSON), list_key, product_key, versions_key, version_key, url_key,
           exclude_products (regex), latest (versions per product, default 2)}
    """
    page = fetch.get_text(rule["index"], timeout=90)
    m = re.search(rule["config"], page, re.S)
    if not m:
        raise fetch.FetchError(f"{rule['index']}: embedded configuration not found")
    cfg = json.loads(htmllib.unescape(m.group(1)))
    items = cfg.get(rule.get("list_key", "items"), []) if isinstance(cfg, dict) else cfg
    skip = re.compile(rule["exclude_products"]) if rule.get("exclude_products") else None
    keep = int(rule.get("latest", 2))
    docs = []
    for item in items:
        product = str(item.get(rule.get("product_key", "product")) or "").strip()
        if not product or (skip and skip.search(product)):
            continue
        for v in (item.get(rule.get("versions_key", "versions")) or [])[:keep]:     # listed newest first
            version = str(v.get(rule.get("version_key", "version")) or "")
            version = re.sub(r"^\D*?(?=\d)", "", version) if not version[:1].isdigit() else version
            path = v.get(rule.get("url_key", "path"))
            if path:
                docs.append({"supplier": rule["supplier"], "product": product, "version": version,
                             "url": urljoin(rule["index"], path), "discovered_by": rule["index"]})
    log(f"  {rule['supplier']}: {len(docs)} documents for {len({d['product'] for d in docs})} products")
    return docs


def load_registry(path: Path, *, discover_docs: bool = True, log=print) -> list[dict]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    docs: dict[str, dict] = {}
    for d in cfg.get("documents") or []:
        docs[d["url"]] = {**d, "version": str(d.get("version") or "")}
    if discover_docs:
        for rule in cfg.get("discover") or []:
            try:
                kind = rule.get("type")
                found = (discover_versions(rule, log=log) if kind == "versions_json"
                         else discover_autoindex(rule, log=log) if kind == "autoindex"
                         else discover_table(rule, log=log) if kind == "table"
                         else discover_embedded_json(rule, log=log) if kind == "embedded_json"
                         else discover(rule, log=log))
                for d in found:
                    docs.setdefault(d["url"], d)
            except fetch.FetchError as e:
                log(f"  ! discovery failed for {rule.get('index') or rule.get('versions_url')}: {e}")
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
        with fetch.urlopen(req, 30) as resp:
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
            with fetch.urlopen(req, 120) as resp:
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
    """Vendor notices inventories plus contributed SBOMs (data/community_sboms/)."""
    paths = sorted((data_dir / "notices").rglob("*.json")) + sorted((data_dir / "community_sboms").rglob("*.json"))
    for p in paths:
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
            evidence = inv.get("evidence", "notices-file")
            where = {"notices-file": f"Listed in {inv['supplier']}'s open source notices",
                     "vendor-sbom": f"Listed in {inv['supplier']}'s published SBOM",
                     "binary-scan": f"Found by a contributed binary scan ({inv.get('tool') or 'tool not stated'})"}[evidence]
            out.append(make_assertion(
                component=cid,
                supplier=inv["supplier"],
                product=inv["product"],
                version=pv,
                cves={},
                status="present",
                evidence=evidence,
                source=inv.get("source", SOURCE_ID),
                publisher=inv["supplier"] if evidence != "binary-scan" else "Community submission",
                source_url=inv["url"],
                references=[r for r in (inv.get("submission"),) if r],
                notes=f"{where} for {inv['product']}{' ' + pv if pv else ''} as: {listed}."
                      + (f" Artifact: {inv['artifact']} (sha256 {inv['artifact_sha256'][:16]}…)." if inv.get("artifact_sha256") else ""),
                category={"notices-file": "Third-party notices", "vendor-sbom": "Vendor SBOM",
                          "binary-scan": "Binary scan"}[evidence],
                updated=inv.get("retrieved", ""),
                component_version=versions,
            ))
    return out, stats


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
