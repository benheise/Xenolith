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
  sbom            CycloneDX JSON, SPDX 2 JSON / tag-value, SPDX 3 JSON-LD, plain JSON arrays of
                  {name, version} (JetBrains third-party-libraries.json)

Documents and discovery rules marked `render: true` are loaded in headless Chromium when
the plain page is an empty client-side shell (see _get_rendered); never around a refusal.
"""

from __future__ import annotations

import bz2
import hashlib
import html as htmllib
import io
import json
import re
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import yaml

from .. import fetch
from ..catalog import Catalog, normalize_name
from ..model import make_assertion, slug
from .community_sbom import STATEMENT_CONFIDENCE

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
    if len(tokens) == 1:
        m = re.match(r"^(.+?)@[\^~>=<]*v?(\d[\w.\-+~]*)$", body)     # npm style: name@1.2.3, @scope/name@^1.2.3
        if m:
            return m.group(1), m.group(2)
        m = re.match(r"^(.+?)[-_]v?(\d[\w.\-+~]*)$", body)
        if m:
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
                "third-party software", "oss component", "software name", "product/library", "product / library",
                "library/dependency", "library name", "third-party component", "third party component", "tps name"}
# "release version" is the component's version in Oracle's 14.1.2 licensing manuals. (The older
# Fusion Middleware chapter's plural "Release Versions" column names Oracle releases, not
# component versions, so it is deliberately not listed.)
VERSION_HEADERS = {"version", "component version", "package version", "version number", "release", "release version"}


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
    """'zlib, libpng' in a name cell lists several components (Oracle-style tables).

    Commas inside parentheses belong to one name: 'BSAFE Software (CCME, MES, Crypto J)'."""
    if re.search(r"\([^)]*,[^)]*\)", cell):
        return [cell]
    parts = [p.strip() for p in re.split(r"\s*[,;]\s*|\n", cell) if p.strip()]
    return parts if len(parts) > 1 and all(len(p) < 60 for p in parts) else [cell]


def ex_pipe_table(text: str) -> list[tuple[str, str]]:
    out, idx = [], None
    for line in text.splitlines():
        if not line.strip():
            continue                    # HTML tables flatten to rows separated by blank lines
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
        # Siemens: "1.12 libHaru – Version 2.3.0" -> "libHaru 2.3.0"; a bare section heading
        # ("1. Third Party Software Components") carries no component.
        numbered = re.match(r"^\d+(?:\.\d+)+\s+(?P<rest>\S.*)$", body)
        if numbered:
            body = re.sub(r"\s+[–\-]?\s*version\s+(?=v?\d)", " ", numbered.group("rest"), flags=re.I)
        elif re.match(r"^\d+\.\s", body):
            continue
        name, ver = split_name_version(body)
        if not ver and re.match(r"^\d{1,2}\s+[A-Za-z][A-Za-z ]{2,40}$", body):
            continue   # "6 TOE Summary Specification": a numbered section heading
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
        ver = re.sub(r"\s+\(.*$", "", ver)          # "9.1 (org.ow2.asm:asm:9.1," -> "9.1"
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
        if plausible(name) and not LICENSE_ONLY.match(name.lstrip("*•- ")):     # "LGPL v2.1: https://..."
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


BD_LINE = re.compile(r"(?m)^\s*(?P<n>[A-Za-z@][^:\n]{0,120}?)\s+(?P<v>v?\d[\w.\-+~]*)\s*:\s+(?P<rest>\S.*)$")
BD_REST = re.compile(r"(?i)licen|gpl|\bmit\b|bsd|apache|public domain|https?://|commercial|proprietary|unspecified|unknown|"
                     r"artistic|cddl|\bepl\b|\bmpl\b|internal|\bfree\b|zlib|\bisc\b|openssl|boost|unicode|w3c|eula|agreement|"
                     r"permissive|ms-pl|bouncy|creative|python|eclipse|mozilla|oracle|microsoft|sun\b")


def ex_bd_components(text: str) -> list[tuple[str, str]]:
    """Black Duck notices reports (Ivanti): after "Components:", one entry per line as
    "name version : license" or "name version: https://home : license"."""
    if not text or not CL_START.search(text):
        return []
    out = []
    for m in BD_LINE.finditer(text):
        name, rest = m.group("n").strip(), m.group("rest")
        if BD_REST.search(rest) and plausible(name) and not name.lower().startswith(("http", "see ", "note")):
            out.append((name, m.group("v")))
    return out


TABLE_HEAD = re.compile(r"(?im)^\s*(?:component\s+)?(?:name|library(?:/dependency)?)\s+(?:version\s+)?licen[cs]e\s*$")
JUNK_NAMES = {"inc", "inc.", "ltd", "ltd.", "llc", "corp", "corp.", "gmbh", "co.", "version", "release", "page", "copyright"}


def ex_table_lines(text: str) -> list[tuple[str, str]]:
    """PDF tables flattened to lines under a "Name Version License" header (Axway):
    "log4j-core-2.10.0.jar 2.10.0 Apache 2.0 License" or
    "Gateway Server libcrypto 1.0.2r OpenSSL License" (a leading component column)."""
    out = []
    for m in TABLE_HEAD.finditer(text or ""):
        misses = 0
        for raw in text[m.end():].splitlines():
            line = raw.strip()
            if not line:
                continue
            if TABLE_HEAD.match(line):
                break
            tokens = line.split()
            vi = next((i for i in range(1, min(len(tokens), 5))
                       if VERSION_TOKEN.match(tokens[i].replace(",", ".")) and re.search(r"\d", tokens[i])), None)
            if vi is None or not re.search(r"[A-Za-z]", tokens[vi - 1]) \
                    or (len(tokens) == 2 and not re.search(r"[._-]", tokens[0])):     # "Gateway 6.17.3" page headers
                misses += 1
                if misses > 8:
                    break
                continue
            misses = 0
            name, version = tokens[vi - 1], tokens[vi].replace(",", ".")
            if name.lower().endswith((".jar", ".dll", ".so")):
                nv = archive_name_version(name) if name.lower().endswith(".jar") else None
                name = nv[0] if nv else re.sub(r"\.(jar|dll|so)$", "", name, flags=re.I)
            if plausible(name) and name.lower() not in JUNK_NAMES and not re.fullmatch(r"(?:19|20)\d\d", version):
                out.append((name, version))
    return out


HOMEPAGE_HEAD = re.compile(r"(?im)^\s*component name\s+component version name\s+home page\s+licen[cs]e names?\s*$")


def ex_homepage_table(text: str) -> list[tuple[str, str]]:
    """Black Duck "Embedded Software Components" tables (NVIDIA networking):
    "DPDK 22.11 https://www.dpdk.org BSD 3-clause" / "iproute2 6.1.0, 6.4.0 http://..."."""
    out = []
    for m in HOMEPAGE_HEAD.finditer(text or ""):
        for raw in text[m.end():].splitlines():
            tokens = raw.split()
            hi = next((i for i, t in enumerate(tokens) if t.lower().startswith(("http://", "https://"))), None)
            if hi is None or hi < 2:
                if HOMEPAGE_HEAD.match(raw):
                    break
                continue
            versions, vi = [], hi
            while vi >= 1 and VERSION_TOKEN.match(tokens[vi - 1].rstrip(",")):
                versions.insert(0, tokens[vi - 1].rstrip(","))
                vi -= 1
            name = " ".join(tokens[:vi])
            if versions and plausible(name):
                out.extend((name, v) for v in versions)
    return out


DLL_HEAD = re.compile(r"(?i)list of third[- ]party (?:libraries|components|software)")
DLL_LINE = re.compile(r"^\s*([A-Za-z][\w.\-]*)\.(?:dll|so|dylib)\s*$", re.I)


def ex_dll_names(text: str) -> list[tuple[str, str]]:
    """Common Criteria Security Targets list an application's third-party libraries as bare
    DLL names, one per line, under "Appendix X: List of Third-Party Libraries" (CyberArk)."""
    m = DLL_HEAD.search(text or "")
    if not m:
        return []
    out = []
    for raw in text[m.end():].splitlines():
        lm = DLL_LINE.match(raw)
        if lm and plausible(lm.group(1)):
            out.append((lm.group(1), ""))
    return out if len(out) >= 3 else []


NV_LINE = re.compile(r"^(?P<n>[A-Za-z.@][\w.+/:@()\-]*(?: [A-Za-z][\w.+/:@()\-]*){0,5})\s+v?(?P<v>\d+(?:\.\d+)+(?:[\w.\-+~]*)?)$")
NV_GATE = re.compile(r"(?i)third[- ]party (?:software|applications?|components?|products?|librar(?:y|ies)|programs?)|"
                     r"open[- ]source (?:software|components?|librar(?:y|ies))|list of components")
NV_STOP_LAST = {"version", "release", "revision", "chapter", "section", "page", "step", "figure", "table", "part", "build",
                "document", "copyright", "edition", "volume", "issue", "rev", "draft", "update", "patch", "hotfix", "pack",
                "v", "ver", "guide", "manual", "notes", "since", "than", "to", "of", "for", "and", "or", "in", "on", "at", "by"}


def ex_name_version_lines(text: str) -> list[tuple[str, str]]:
    """Plain "name version" lines in a document that talks about third-party software:
    Commvault's installed-applications list, BMC's per-license component lists.
    Used only when no structured extractor found anything."""
    if not text or not NV_GATE.search(text):
        return []
    out = []
    for raw in text.splitlines():
        m = NV_LINE.match(raw.strip())
        if not m:
            continue
        name = m.group("n").strip()
        if name.split()[-1].lower() in NV_STOP_LAST or not plausible(name):
            continue
        out.append((name, m.group("v")))
    return out if len(out) >= 3 else []


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


TAG_PREFIX = re.compile(r"^(?:release|rel|version|ver|v)(?=[-_.]?\d)[-_.]?", re.I)


def tag_version(name: str, version: str) -> str:
    """A release tag as a version: "curl-8_23_0" -> "8.23.0", "OpenSSL_1_1_1n" -> "1.1.1n",
    "release-1.31.7" -> "1.31.7", "v1.2.12" -> "1.2.12". Anything else is returned as is."""
    v = (version or "").strip()
    base = re.escape(re.sub(r"[-_ ]?(?:lib|libs)$", "", name.strip()))
    v = re.sub(rf"^(?:lib)?{base}[-_]?(?=v?\d)", "", v, flags=re.I)
    v = TAG_PREFIX.sub("", v)
    if re.fullmatch(r"\d+(?:_\d+)+[a-z]?\d*", v):
        v = v.replace("_", ".")
    return v


def ex_license_manifest(obj) -> list[tuple[str, str]]:
    """Omnibus (Chef) license manifests, as GitLab publishes per release:
    {software: {"license": ..., "version": <tag>, "dependencies": {software: {...}}}}."""
    if not isinstance(obj, dict):
        return []
    entries = [v for v in obj.values() if isinstance(v, dict)]
    if len(entries) < 5 or sum(1 for v in entries if "license" in v and "version" in v) < 0.8 * len(entries):
        return []
    out: dict[str, str] = {}

    def walk(tree: dict) -> None:
        for name, info in tree.items():
            if not isinstance(info, dict) or "version" not in info:
                continue
            if name not in out and not re.fullmatch(r"[0-9a-f]{40}", str(info.get("version") or "")):
                out[name] = tag_version(name, str(info.get("version") or ""))
            walk(info.get("dependencies") or {})
    walk(obj)
    return [(n, v) for n, v in out.items() if n not in ("version-manifest", "package-scripts", "config_guess")]


def ex_sbom(obj) -> list[tuple[str, str]]:
    out = []
    if (manifest := ex_license_manifest(obj)):
        return manifest
    if isinstance(obj, list):
        # Plain JSON arrays of {"name", "version", ...} (JetBrains third-party-libraries.json)
        for c in obj:
            if isinstance(c, dict) and isinstance(c.get("name"), str) and c["name"].strip():
                out.append((c["name"].strip(), str(c.get("version") or "")))
        return out
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


MAX_DECOMPRESSED = 300 * 1024 * 1024


def decompress(body: bytes) -> bytes:
    """bzip2-compressed documents (Red Hat's SBOMs are .json.bz2), capped at MAX_DECOMPRESSED."""
    if body[:3] != b"BZh":
        return body
    d = bz2.BZ2Decompressor()
    out = d.decompress(body, max_length=MAX_DECOMPRESSED)
    if not d.eof:
        raise ValueError(f"document is larger than {MAX_DECOMPRESSED // 2**20} MB uncompressed")
    return out


def extract(body: bytes, content_type: str, url: str) -> tuple[list[dict], list[str], str]:
    """Return (components [{name, version}], extractors that produced results, document kind)."""
    ct = (content_type or "").lower()
    lower_url = url.lower().split("?")[0]
    if body[:3] == b"BZh":
        try:
            body = decompress(body)
        except (OSError, ValueError, EOFError):
            return [], [], "bzip2"
        lower_url = re.sub(r"\.bz2$", "", lower_url)
        ct = "application/json" if lower_url.endswith(".json") else ct
    kind, text, html, obj = "text", "", None, None
    if body[:5] == b"%PDF-" or "pdf" in ct or lower_url.endswith(".pdf"):
        kind, text = "pdf", pdf_to_text(body)
    else:
        raw = body.decode("utf-8-sig", errors="replace")
        stripped = raw.lstrip()
        is_json = "json" in ct or lower_url.endswith(".json")
        if (stripped.startswith("{") and (is_json or '"bomFormat"' in raw[:2000] or '"spdxVersion"' in raw[:2000] or '"@graph"' in raw[:4000])) \
                or (stripped.startswith("[") and is_json):
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
        results["bd_components"] = ex_bd_components(text)
        # Black Duck reports share the "Components:" heading with NetApp's format but
        # the NetApp parser only produces noise on them.
        results["component_license"] = [] if len(results["bd_components"]) >= 3 else ex_component_license(text)
        results["url_lines"] = ex_url_lines(text)
        results["license_groups"] = ex_license_groups(text)
        results["table_lines"] = ex_table_lines(text)
        results["homepage_table"] = ex_homepage_table(text)
        results["dll_names"] = ex_dll_names(text)
        if results["dll_names"]:
            # A Security Target's table of contents is section headings, not components.
            results["dotted_toc"] = [r for r in results["dotted_toc"] if r[1]]
            results["numbered_toc"] = [r for r in results["numbered_toc"] if r[1]]
        results["jar_names"] = ex_jar_names(text)
        structured = [k for k in ("html_table", "pipe_table", "spdx_tag", "numbered_toc", "dotted_toc", "gt_list", "tpn_list",
                                  "bd_components", "component_license", "url_lines", "license_groups", "table_lines",
                                  "homepage_table", "dll_names") if results.get(k)]
        if not structured:
            results["name_version_lines"] = ex_name_version_lines(text)
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
    named groups product and version, applied to the link text), optional
    product_prefix, product (fixed name), version_from_url (regex with group
    version applied to the URL when the link text has none), product_from_url
    (regex with group product applied to the URL; underscores become spaces),
    rename (product name as found -> name to use), render (load the index in a
    browser when its plain HTML has no matching links)}.
    """
    page = fetch.get_text(rule["index"], timeout=90)
    link_re = re.compile(rule["link"], re.I)
    title_re = re.compile(rule["title"], re.I)
    if rule.get("render") and not any(link_re.search(u) for u, _ in _anchor_links(page, rule["index"])):
        page = _render_checked(rule["index"], page)        # links are added by a script
    url_ver = re.compile(rule["version_from_url"], re.I) if rule.get("version_from_url") else None
    url_prod = re.compile(rule["product_from_url"], re.I) if rule.get("product_from_url") else None
    docs: dict[str, dict] = {}
    seen_index = False
    for url, text in _anchor_links(page, rule["index"]):
        if not link_re.search(url):
            continue
        m = title_re.search(text)
        if not m:
            continue
        product = rule.get("product") or (rule.get("product_prefix", "") + (m.groupdict().get("product") or "")).strip()
        if url_prod and (pm := url_prod.search(url)):
            product = (rule.get("product_prefix", "") + pm.group("product").replace("_", " ")).strip()
        product = (rule.get("rename") or {}).get(product, product)
        version = m.groupdict().get("version") or ""
        if not version and url_ver and (vm := url_ver.search(url)):
            version = vm.group("version")
        if (url_prod and not product.strip(rule.get("product_prefix", ""))) or (url_ver and not version):
            continue                       # the URL didn't carry what the rule expects
        docs.setdefault(url, {"supplier": rule["supplier"], "product": product, "version": version, "url": url,
                              "discovered_by": rule["index"]})
    log(f"  {rule['supplier']}: {len(docs)} documents linked from {rule['index']}")
    return list(docs.values())


def _doc_url(template: str, version: str) -> str:
    return template.format(version=version, minor=".".join(version.split(".")[:2]))


def discover_versions(rule: dict, log=print) -> list[dict]:
    """Build document URLs from a JSON list of released versions (Elastic's artifacts API).

    rule: {type: versions_json, supplier, product, versions_url, field, url_template,
           exclude (regex), version_regex (group `version`), keep_latest_per_minor (bool),
           limit (int)}. versions_url may answer {field: [versions]} or a list of objects
    whose `field` holds the version; url_template may use {version} and {minor} (19.5).
    """
    data = fetch.get_json(rule["versions_url"])
    field = rule.get("field", "versions")
    if isinstance(data, list):                  # a list of objects (GitLab's tags API): take `field` of each
        raw = [item.get(field) for item in data if isinstance(item, dict)]
    else:
        raw = data.get(field, [])
    versions = [v for v in raw if isinstance(v, str)]
    if rule.get("exclude"):
        versions = [v for v in versions if not re.search(rule["exclude"], v)]
    if rule.get("version_regex"):               # "19.5.6+ee.0" -> "19.5.6"
        vre = re.compile(rule["version_regex"])
        versions = list(dict.fromkeys(m.group("version") for v in versions if (m := vre.search(v))))
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
                if _exists(_doc_url(rule["url_template"], v)):
                    latest.append(v)
                    break
            if len(latest) >= int(rule.get("limit", 4)):
                break
        versions = latest
    versions = versions[: int(rule.get("limit", 4))]
    docs = [{"supplier": rule["supplier"], "product": rule["product"], "version": v,
             "url": _doc_url(rule["url_template"], v), "discovered_by": rule["versions_url"]} for v in versions]
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
                         "url": url, "discovered_by": base + directory.strip("/") + "/"})
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


def discover_file_index(rule: dict, log=print) -> list[dict]:
    """A plain-text index of document paths, one per line (Red Hat's SBOM index.txt).

    rule: {type: file_index, supplier, index, link (regex on each line, groups product
           and version), products: {key: product name, or {name, latest}}, latest
           (newest versions kept per product, default 2)}
    """
    from ..versions import version_key
    link_re = re.compile(rule["link"])
    found: dict[str, dict[str, str]] = {}
    for line in fetch.get_text(rule["index"], timeout=90).splitlines():
        m = link_re.search(line.strip())
        if m and m.group("product") in (rule.get("products") or {}) and version_key(m.group("version")) is not None:
            found.setdefault(m.group("product"), {})[m.group("version")] = urljoin(rule["index"], line.strip())
    docs = []
    for key, spec in (rule.get("products") or {}).items():
        spec = spec if isinstance(spec, dict) else {"name": spec}
        versions = found.get(key, {})
        keep = sorted(versions, key=version_key, reverse=True)[: int(spec.get("latest") or rule.get("latest", 2))]
        for v in keep:
            docs.append({"supplier": rule["supplier"], "product": spec["name"], "version": v,
                         "url": versions[v], "discovered_by": rule["index"]})
        if not keep:
            log(f"  ! {rule['supplier']} {spec['name']}: nothing in {rule['index']}")
    log(f"  {rule['supplier']}: {len(docs)} documents for {len(found)} products from {rule['index']}")
    return docs


def discover_version_table(rule: dict, log=print) -> list[dict]:
    """A vendor page with a table of the component versions each product release bundles
    (JFrog: Artifactory version | OpenJDK version). Each row becomes an inline document.

    rule: {type: version_table, supplier, product, index, latest (rows kept per table,
           default 6), tables: [{version_column (header text), value_column (header
           text), component (name to record), value_regex (optional; group v picks the
           version out of the cell)}]}
    """
    from ..versions import version_key
    page = fetch.get_text(rule["index"], timeout=90)
    tables = []
    for table in re.findall(r"(?is)<table\b.*?</table>", page):
        rows = [[re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"(?is)<t[hd][^>]*>(.*?)</t[hd]>", row)]
                for row in re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", table)]
        if rows:
            tables.append(rows)
    keep = int(rule.get("latest", 6))
    docs = []
    for spec in rule["tables"]:
        want_v, want_c = spec["version_column"].lower(), spec["value_column"].lower()
        rows = next((t for t in tables if [h.lower() for h in t[0]][:2] == [want_v, want_c]), None)
        if rows is None:
            log(f"  ! {rule['supplier']} {rule['product']}: no table headed {spec['version_column']!r} | {spec['value_column']!r}")
            continue
        value_re = re.compile(spec["value_regex"]) if spec.get("value_regex") else None
        kept = 0
        for cells in rows[1:]:
            if len(cells) < 2 or version_key(cells[0]) is None:
                continue
            value = cells[1]
            if value_re:
                m = value_re.search(value)
                if not m:
                    continue
                value = m.group("v")
            if version_key(value) is None:
                continue
            product_version = re.sub(r"\s*-\s*", " to ", cells[0])          # "7.59.9-7.68.20" -> "7.59.9 to 7.68.20"
            slug = re.sub(r"[^a-z0-9.]+", "-", f"{spec['component']}-{product_version}".lower()).strip("-")
            docs.append({"supplier": rule["supplier"], "product": rule["product"], "version": product_version,
                         "url": f"{rule['index']}#{slug}", "discovered_by": rule["index"],
                         "components": [{"name": spec["component"], "version": value}],
                         "kind": "version-table", "via": ["version_table"]})
            kept += 1
            if kept >= keep:
                break
    log(f"  {rule['supplier']} {rule['product']}: {len(docs)} release rows from {rule['index']}")
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


def discover_jetbrains(rule: dict, log=print) -> list[dict]:
    """JetBrains' product release API, the data behind jetbrains.com/legal/third-party-software.

    Each release in https://data.services.jetbrains.com/products carries a link to its
    third-party-libraries.json (name, version, license per library).

    rule: {type: jetbrains, supplier, versions_url (the products API, filtered by code),
           products: {code: product name, or {name, latest}}, release_types (default
           [release]), version_from_url (regex with group version, for releases whose API
           version repeats across builds: YouTrack "2026.2" -> youtrack-2026.2.19840.json),
           per_minor (keep only the newest release of each year.minor line, so `latest`
           spans release lines rather than patch releases),
           latest (newest versions kept per product, default 2)}
    """
    data = fetch.get_json(rule["versions_url"])
    types = set(rule.get("release_types") or ["release"])
    url_ver = re.compile(rule["version_from_url"]) if rule.get("version_from_url") else None
    wanted = rule.get("products") or {}
    docs = []
    for item in data if isinstance(data, list) else []:
        spec = wanted.get(item.get("code"))
        if spec is None:
            continue
        spec = spec if isinstance(spec, dict) else {"name": spec}
        keep = int(spec.get("latest") or rule.get("latest", 2))
        found: dict[str, str] = {}
        lines: set[str] = set()
        for rel in item.get("releases") or []:            # newest first
            link = (((rel.get("downloads") or {}).get("thirdPartyLibrariesJson") or {}).get("link") or "")
            if rel.get("type") not in types or not link.startswith("https://"):
                continue
            version = str(rel.get("version") or "")
            if url_ver and (m := url_ver.search(link)):
                version = m.group("version")
            line = ".".join(version.split(".")[:2]) if rule.get("per_minor") else version
            if version and line not in lines:
                lines.add(line)
                found[version] = link
            if len(found) >= keep:
                break
        for version, link in found.items():
            docs.append({"supplier": rule["supplier"], "product": spec["name"], "version": version, "url": link,
                         "discovered_by": rule["versions_url"]})
        log(f"  {rule['supplier']} {spec['name']}: {', '.join(found) or 'no third-party list'}")
    return docs


def rule_start(rule: dict) -> str:
    """Where a discovery rule's trail starts: its index page, versions API or release list."""
    if rule.get("type") == "apple_releases":
        from . import apple
        return rule.get("index") or apple.RELEASES_URL
    return rule.get("index") or rule.get("versions_url") or ""


def doc_provenance(doc: dict, rule: dict | None = None) -> dict:
    """found_via and discovery_path for a registry document.

    Hand-listed documents carry the page a person found the link on as `found_at` in
    catalog/notices.yaml; discovered ones carry the rule's start page plus the page the
    link was read from (`discovered_by`) when that is a different page.
    """
    if rule is None:
        found_at = doc.get("found_at") or []
        path = [found_at] if isinstance(found_at, str) else [str(p) for p in found_at]
        return {"found_via": "hand-listed", "discovery_path": [p for p in dict.fromkeys(path) if p]}
    path = [rule_start(rule)]
    if doc.get("discovered_by"):
        path.append(doc["discovered_by"])
    return {"found_via": "auto-discovered", "discovery_path": [p for p in dict.fromkeys(path) if p]}


def load_registry(path: Path, *, discover_docs: bool = True, log=print) -> list[dict]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    docs: dict[str, dict] = {}
    for d in cfg.get("documents") or []:
        docs[d["url"]] = {**d, "version": str(d.get("version") or ""), **doc_provenance(d)}
    if discover_docs:
        for rule in cfg.get("discover") or []:
            try:
                kind = rule.get("type")
                if kind == "apple_releases":
                    from . import apple
                    found = apple.discover(rule, log=log)
                else:
                    found = (discover_versions(rule, log=log) if kind == "versions_json"
                             else discover_autoindex(rule, log=log) if kind == "autoindex"
                             else discover_table(rule, log=log) if kind == "table"
                             else discover_embedded_json(rule, log=log) if kind == "embedded_json"
                             else discover_jetbrains(rule, log=log) if kind == "jetbrains"
                             else discover_version_table(rule, log=log) if kind == "version_table"
                             else discover_file_index(rule, log=log) if kind == "file_index"
                             else discover(rule, log=log))
                for d in found:
                    if rule.get("render"):
                        d = {**d, "render": True}
                    docs.setdefault(d["url"], {**d, **doc_provenance(d, rule)})
            except fetch.FetchError as e:
                log(f"  ! discovery failed for {rule.get('index') or rule.get('versions_url')}: {e}")
    return list(docs.values())


def infer_provenance(url: str, supplier: str, cfg: dict) -> dict:
    """Provenance for a stored inventory without network access, from the catalog alone.

    Used to stamp inventories whose document was not (re)discovered in this run, so a
    discovery outage never strips provenance. Hand-listed URLs come first; otherwise the
    discovery rule for the same supplier whose start page or link pattern matches.
    """
    for d in cfg.get("documents") or []:
        if d.get("url") == url:
            return doc_provenance(d)
    rules = [r for r in cfg.get("discover") or [] if r.get("supplier") == supplier]
    for rule in rules:
        kind = rule.get("type")
        if kind == "autoindex":
            base = rule["index"].rstrip("/") + "/"
            for directory in rule.get("products") or {}:
                folder = base + directory.strip("/") + "/"
                if url.startswith(folder):
                    return doc_provenance({"discovered_by": folder}, rule)
        elif kind == "versions_json":
            prefix = rule["url_template"].split("{", 1)[0]
            if url.startswith(prefix):
                return doc_provenance({}, rule)
        elif kind == "apple_releases":
            if url.startswith(rule_start(rule)):
                return doc_provenance({}, rule)
        elif kind == "file_index":
            if url.startswith(rule["index"].rsplit("/", 1)[0] + "/"):
                return doc_provenance({}, rule)
        elif kind == "version_table":
            if url.startswith(rule["index"] + "#"):
                return doc_provenance({}, rule)
        elif kind == "jetbrains":
            if re.match(r"https://(?:resources|download)\.jetbrains\.com/", url):
                return doc_provenance({"discovered_by": rule["versions_url"]}, rule)
        elif rule.get("link") and re.search(rule["link"], url, re.I):
            return doc_provenance({}, rule)
    if len(rules) == 1:
        return doc_provenance({}, rules[0])
    return {"found_via": "hand-listed", "discovery_path": []}


def write_inventory(path: Path, inv: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inv, ensure_ascii=False, indent=0, sort_keys=True) + "\n", encoding="utf-8")


def stamp_inventories(registry_path: Path, data_dir: Path, docs: list[dict] | None = None, log=print) -> int:
    """Write found_via and discovery_path into every stored notices inventory.

    `docs` (from load_registry) gives the exact discovery path seen in this run; documents
    not among them are stamped from the catalog alone (infer_provenance). No network.
    Returns the number of files changed.
    """
    cfg = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
    by_url = {d["url"]: d for d in docs or []}
    starts = {(r.get("supplier"), rule_start(r)) for r in cfg.get("discover") or []}
    changed = 0
    for p in sorted((data_dir / "notices").rglob("*.json")):
        try:
            inv = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        d = by_url.get(inv.get("url", ""))
        path = inv.get("discovery_path") or []
        if d and d.get("found_via"):
            prov = {"found_via": d["found_via"], "discovery_path": d.get("discovery_path", [])}
        elif inv.get("found_via") == "auto-discovered" and path and (inv.get("supplier"), path[0]) in starts:
            continue        # stamped by an online run from a rule that still exists: more exact than inference
        else:
            prov = infer_provenance(inv.get("url", ""), inv.get("supplier", ""), cfg)
        if inv.get("found_via") != prov["found_via"] or inv.get("discovery_path", []) != prov["discovery_path"]:
            inv["found_via"], inv["discovery_path"] = prov["found_via"], prov["discovery_path"]
            write_inventory(p, inv)
            changed += 1
    log(f"  provenance stamped on {changed} inventories")
    return changed


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
        inline = d.get("components")        # discovery that already produced the component list (Apple)
        rendered = False
        if inline is not None:
            body, ctype = json.dumps(inline, sort_keys=True).encode(), "application/json"
        else:
            try:
                if d.get("render"):
                    body, ctype, rendered = _get_rendered(url)
                else:
                    body, ctype = _get(url)
            except fetch.FetchError as e:
                stats["errors"] += 1
                state[url] = {**state.get(url, {}), "fetched": today.isoformat(), "status": "error", "error": str(e)[:200]}
                log(f"  ! {e}")
                continue
        stats["fetched"] += 1
        # A rendered page's markup carries per-load tokens; its text is what stays put.
        sha = hashlib.sha256(html_to_text(body.decode("utf-8")).encode("utf-8") if rendered else body).hexdigest()
        inv = inventory_path(data_dir, d)
        if state.get(url, {}).get("sha") == sha and inv.exists():
            state[url].update(fetched=today.isoformat())
            stats["unchanged"] += 1
            continue
        try:
            if inline is not None:
                comps, used, kind = inline, list(d.get("via") or ["inline"]), d.get("kind", "inline")
            else:
                comps, used, kind = extract(body, ctype, url)
        except Exception as e:  # noqa: BLE001 - one bad document must not stop the crawl
            stats["errors"] += 1
            state[url] = {"fetched": today.isoformat(), "status": "error", "error": f"parse: {e}"[:200], "sha": sha}
            log(f"  ! parse failed {url}: {e}")
            continue
        status = "ok" if comps else "empty"
        stats["parsed" if comps else "empty"] += 1
        state[url] = {"fetched": today.isoformat(), "status": status, "sha": sha, "n": len(comps),
                      "via": used, "kind": kind, **({"rendered": True} if rendered else {})}
        if comps:
            write_inventory(inv, {
                "supplier": d["supplier"], "product": d["product"], "version": d.get("version", ""),
                "url": url, "retrieved": today.isoformat(), "sha256": sha, "kind": kind,
                "extractors": used, "components": comps,
                "found_via": d.get("found_via", "hand-listed"), "discovery_path": d.get("discovery_path", []),
                **({"rendered": True} if rendered else {}),
            })
        log(f"  {d['supplier']} {d['product']} {d.get('version', '')}: {len(comps)} components via {', '.join(used) or 'nothing'}")
    stats["remaining"] = max(0, len(todo) - max_fetch)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True, indent=0) + "\n")
    stats["stamped"] = stamp_inventories(registry_path, data_dir, docs, log=log)
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


# ----------------------------------------------------------------- rendered fetch (opt-in)
#
# `render: true` on a document or discovery rule loads a page in headless Chromium, for
# pages a script builds in the browser (the plain HTML is an empty shell). It is only used
# after a plain fetch succeeded and found nothing, and it is never a way around a refusal:
# an HTTP error, a login form or a bot challenge on either fetch stays an error. The browser
# announces itself: Chromium's own headless user agent plus Xenolith's.

BLOCK_STATUS = {401, 403, 407, 429}
WALL = re.compile(r"(?i)\b(?:captcha|just a moment|attention required|access denied|checking your browser|"
                  r"verify (?:that )?you are (?:a )?human|are you a robot|pardon our interruption|request unsuccessful|"
                  r"enable javascript and cookies to continue|please (?:sign|log) ?in|(?:sign|log) ?in to (?:continue|view))\b")
LOGIN_URL = re.compile(r"(?i)/(?:login|log-in|signin|sign-in|sso|saml2?|oauth2?|authorize)(?:[/?.#]|$)")


def _wall(html: str) -> str | None:
    """The login or bot-challenge marker a page shows instead of content, if any.

    Looks at the title, and at the visible text only when there is little of it, so a
    notices page that merely mentions "access denied" in a license text is not a wall."""
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    title = htmllib.unescape(m.group(1)) if m else ""
    text = html_to_text(html)
    short = len(re.sub(r"\s+", "", text)) < 1500
    for hay in (title, text if short else ""):
        if hay and (w := WALL.search(hay)):
            return w.group(0)
    if short and re.search(r"(?i)<input[^>]+type=[\"']?password", html):
        return "password form"
    return None


def _render_html(url: str, timeout: float = 90) -> tuple[int, str, str]:
    """Load url in headless Chromium; returns (HTTP status, rendered HTML, final URL).

    Tests replace this function; it is the only code that starts a browser."""
    import os
    from .. import USER_AGENT
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeout, sync_playwright
    except ImportError as e:
        raise fetch.FetchError(f"{url}: render: true needs Playwright "
                               "(pip install playwright && python -m playwright install chromium)") from e
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, executable_path=os.environ.get("XENOLITH_CHROMIUM") or None,
                                        proxy={"server": proxy} if proxy else None)
            try:
                probe = browser.new_page()
                ua = probe.evaluate("navigator.userAgent")
                probe.close()
                page = browser.new_context(user_agent=f"{ua} {USER_AGENT}").new_page()
                resp = page.goto(url, wait_until="load", timeout=timeout * 1000)
                try:
                    page.wait_for_load_state("networkidle", timeout=20000)
                except PlaywrightTimeout:
                    pass                      # analytics that never go quiet; the content is there by now
                return (resp.status if resp else 0), page.content(), page.url
            finally:
                browser.close()
    except fetch.FetchError:
        raise
    except Exception as e:  # noqa: BLE001 - browser failures become ordinary fetch errors
        raise fetch.FetchError(f"{url}: render failed: {e}") from e


def _render_checked(url: str, plain_html: str) -> str:
    """Render a page whose plain fetch succeeded; refuse login and bot walls on either fetch."""
    if w := _wall(plain_html):
        raise fetch.FetchError(f"{url}: the plain fetch got a login or bot page ({w}); not rendered")
    status, html, final = _render_html(url)
    if status in BLOCK_STATUS or not (200 <= status < 300):
        raise fetch.FetchError(f"{url}: HTTP {status} in the browser; not retried")
    if final != url and LOGIN_URL.search(urlsplit(final).path or "/"):
        raise fetch.FetchError(f"{url}: the browser was sent to a login page ({final})")
    if w := _wall(html):
        raise fetch.FetchError(f"{url}: the browser got a login or bot page ({w})")
    return html


def _get_rendered(url: str) -> tuple[bytes, str, bool]:
    """Fetch a `render: true` document: (body, content type, whether it was rendered).

    The plain fetch comes first and decides: an error stays an error, a non-HTML body or a
    page the extractors can already read is used as is, and only an HTML page with no
    components is loaded in the browser."""
    body, ctype = _get(url)
    raw = body.decode("utf-8-sig", errors="replace")
    if body[:5] == b"%PDF-" or not ("html" in ctype.lower() or re.search(r"(?i)<html|<body", raw[:20000])):
        return body, ctype, False
    comps, _, _ = extract(body, ctype, url)
    if comps:
        return body, ctype, False
    return _render_checked(url, raw).encode("utf-8"), "text/html; charset=utf-8", True


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


NAME_VERSION = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+){1,3})(?![\w.])")


def version_in_name(name: str) -> str:
    """The version some notices put in the component name instead of the version
    column ("SapMachine sapmachine-17.0.17"); empty when there isn't one."""
    found = NAME_VERSION.findall(name or "")
    return found[-1] if found else ""


CORRECTION_FIELDS = {"supplier", "products", "names", "versions", "reason", "evidence"}


def validate_corrections(cfg: dict) -> list[str]:
    """Problems with the `corrections:` section of catalog/notices.yaml."""
    errors = []
    for i, c in enumerate(cfg.get("corrections") or []):
        where = f"corrections[{i}]"
        if not isinstance(c, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        if extra := set(c) - CORRECTION_FIELDS:
            errors.append(f"{where}: unexpected field(s) {', '.join(sorted(extra))}")
        for field in ("supplier", "names", "reason", "evidence"):
            if not str(c.get(field) or "").strip():
                errors.append(f"{where}: {field} is required")
        for e in [c.get("evidence")] if isinstance(c.get("evidence"), str) else (c.get("evidence") or []):
            if not str(e).startswith("https://"):
                errors.append(f"{where}: evidence must be https URLs")
        for field in ("products", "names", "versions"):
            try:
                re.compile(str(c.get(field) or ".*"))
            except re.error as e:
                errors.append(f"{where}: {field} is not a valid regex ({e})")
    return errors


def load_corrections(registry_path: Path) -> list[dict]:
    """Vendor list entries known to be wrong (catalog/notices.yaml `corrections:`).

    Each names a supplier, products, component names and versions (full-match regexes),
    a reason and evidence. Matching entries stay in the stored inventory exactly as the
    vendor published them but make no statement."""
    cfg = (yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}) if registry_path.exists() else {}
    if errors := validate_corrections(cfg):
        raise ValueError("; ".join(errors))
    out = []
    for c in cfg.get("corrections") or []:
        evidence = [c["evidence"]] if isinstance(c["evidence"], str) else list(c["evidence"])
        out.append({**c, "evidence": evidence, "_product": re.compile(str(c.get("products") or ".*")),
                    "_name": re.compile(str(c["names"]), re.I), "_version": re.compile(str(c.get("versions") or ".*"))})
    return out


def assertions(catalog: Catalog, data_dir: Path, corrections: list[dict] | None = None) -> tuple[list[dict], dict]:
    """Match every stored inventory against the watchlist.

    `corrections` defaults to the shipped catalog's (load_corrections); pass [] for none."""
    if corrections is None:
        from ..catalog import CATALOG
        corrections = load_corrections(CATALOG / "notices.yaml")
    out = []
    stats = {"inventories": 0, "components": 0, "matches": 0, "set_aside": 0}
    used = [0] * len(corrections)
    for _, inv in iter_inventories(data_dir):
        stats["inventories"] += 1
        stats["components"] += len(inv.get("components", []))
        rules = [(i, r) for i, r in enumerate(corrections)
                 if r["supplier"] == inv.get("supplier") and r["_product"].fullmatch(inv.get("product", ""))]
        hits: dict[str, list[dict]] = {}
        aside: dict[str, list[tuple[dict, dict]]] = {}
        for c in inv.get("components", []):
            # Scanner findings carry a confidence; below the line they stay searchable
            # in the inventory but don't become statements (design/xenolith-scan.md).
            if c.get("confidence") is not None and float(c["confidence"]) < STATEMENT_CONFIDENCE:
                continue
            cid = catalog.match_component(c["name"], c.get("version", ""))
            if not cid:
                continue
            rule = next(((i, r) for i, r in rules if r["_name"].fullmatch(c["name"])
                         and r["_version"].fullmatch(c.get("version") or "")), None)
            if rule:
                used[rule[0]] += 1
                stats["set_aside"] += 1
                aside.setdefault(cid, []).append((c, rule[1]))
                continue
            hits.setdefault(cid, []).append(c)
        for cid, comps in hits.items():
            stats["matches"] += 1
            listed = "; ".join(f"{c['name']} {c['version']}".strip() for c in comps[:6])
            dropped = aside.get(cid, [])
            set_aside = ""
            if dropped:
                listed_aside = list(dict.fromkeys(f"{c['name']} {c['version']}".strip() for c, _ in dropped))
                names = ", ".join(listed_aside[:3]) + (f" and {len(listed_aside) - 3} more" if len(listed_aside) > 3 else "")
                reasons = "; ".join(dict.fromkeys(r["reason"].strip().rstrip(".") for _, r in dropped))
                set_aside = f" Not counted: {names} ({reasons})."
            versions = ", ".join(dict.fromkeys(v for c in comps if (v := c.get("version") or version_in_name(c["name"]))))
            pv = inv.get("version", "")
            evidence = inv.get("evidence", "notices-file")
            # An image built from a distribution's packages (a dpkg, rpm or apk database inside)
            # gets its fixes backported without a version change, so its versions say nothing
            # about a CVE range. The statement is still made; the range check is skipped.
            packaged = evidence_is_distro(inv)
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
                references=[r for r in (inv.get("submission"),) if r]
                           + list(dict.fromkeys(e for _, r in dropped for e in r["evidence"])),
                notes=f"{where} for {inv['product']}{' ' + pv if pv else ''} as: {listed}."
                      + (f" Artifact: {inv['artifact']} (sha256 {inv['artifact_sha256'][:16]}…)." if inv.get("artifact_sha256") else "")
                      + set_aside,
                category=DISTRO_SCAN if packaged else {"notices-file": "Third-party notices", "vendor-sbom": "Vendor SBOM",
                                                       "binary-scan": "Binary scan"}[evidence],
                updated=inv.get("retrieved", ""),
                component_version=versions,
                found_via=inv.get("found_via", ""),
                discovery_path=inv.get("discovery_path", []),
                sha256=inv.get("sha256", ""),
            ))
    stats["corrections_unused"] = sum(1 for n in used if not n)
    return out, stats


DISTRO_SCAN = "Binary scan (distribution packages)"
_PACKAGE_DB = re.compile(r"(?:dpkg|rpm|apk)-db-cataloger")


def evidence_is_distro(inv: dict, minimum: int = 20) -> bool:
    """True for a scanned image whose components mostly come from a Linux package database."""
    if inv.get("evidence") != "binary-scan":
        return False
    return sum(1 for c in inv.get("components", []) if _PACKAGE_DB.search(str(c.get("found_by", "")))) >= minimum


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
