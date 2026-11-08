"""Apple: the open source projects in each macOS and iOS release.

opensource.apple.com/releases lists, for every release, the Apple open source
projects it shipped (as Apple project tags such as OpenSSH-354.120.2). The list is
embedded in the site's JavaScript bundle rather than served as a page. Apple's tags
are not upstream versions, so for projects that wrap a well-known component the
upstream version is read from the project's own source on
github.com/apple-oss-distributions (openssh/version.h, curl's curlver.h, ...).
Projects without a resolver are recorded by name only (with the Apple tag kept
in an `apple` field), never with the Apple tag as a version.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .. import fetch

RELEASES_URL = "https://opensource.apple.com/releases/"
RAW = "https://raw.githubusercontent.com/apple-oss-distributions/{project}/{project}-{tag}/{path}"
CACHE = Path(__file__).resolve().parents[2] / "data" / "state" / "apple_resolve.json"


def _define(name: str):
    rx = re.compile(r'#define\s+' + name + r'\s+"([^"]+)"')
    return lambda text: (m.group(1) if (m := rx.search(text)) else None)


def _ssh(text: str):
    m = re.search(r'#define\s+SSH_VERSION\s+"OpenSSH_([\w.]+)"', text)
    p = re.search(r'#define\s+SSH_PORTABLE\s+"([\w]+)"', text)
    return (m.group(1) + (p.group(1) if p else "")) if m else None


def _m4_version(text: str):
    parts = re.findall(r"m4_define\(\[(MAJOR|MINOR|MICRO)_VERSION\],\s*(\d+)\)", text)
    d = dict(parts)
    return ".".join(d[k] for k in ("MAJOR", "MINOR", "MICRO")) if len(d) == 3 else None


def _ac_init(text: str):
    m = re.search(r"AC_INIT\(\[?[\w.-]+\]?,\s*\[?([\w.\-]+)\]?", text)
    return m.group(1) if m else None


def _httpd(text: str):
    nums = {k: v for k, v in re.findall(r"#define\s+AP_SERVER_(MAJORVERSION|MINORVERSION|PATCHLEVEL)_NUMBER\s+(\d+)", text)}
    return ".".join(nums[k] for k in ("MAJORVERSION", "MINORVERSION", "PATCHLEVEL")) if len(nums) == 3 else None


# Apple project -> (upstream component name, file inside the project, version reader)
RESOLVERS = {
    "OpenSSH": ("OpenSSH", "openssh/version.h", _ssh),
    "curl": ("curl", "curl/include/curl/curlver.h", _define("LIBCURL_VERSION")),
    "zlib": ("zlib", "zlib/zlib.h", _define("ZLIB_VERSION")),
    "libxml2": ("libxml2", "libxml2/configure.ac", _m4_version),
    "apache_mod_php": ("PHP", "php/main/php_version.h", _define("PHP_VERSION")),
    "apache": ("Apache HTTP Server", "httpd/include/ap_release.h", _httpd),
    "sudo": ("sudo", "sudo/configure.ac", _ac_init),
    "expat": ("expat", "expat/lib/expat.h", lambda t: (".".join(re.findall(r"#define\s+XML_(?:MAJOR|MINOR|MICRO)_VERSION\s+(\d+)", t)) or None)),
    "libpcap": ("libpcap", "libpcap/VERSION", lambda t: t.strip().splitlines()[0].strip() if t.strip() else None),
    "tcpdump": ("tcpdump", "tcpdump/VERSION", lambda t: t.strip().splitlines()[0].strip() if t.strip() else None),
    "bzip2": ("bzip2", "bzip2/bzlib.h", lambda t: (m.group(1) if (m := re.search(r"bzip2/libbzip2 version ([\d.]+)", t)) else None)),
    "pcre": ("PCRE", "pcre/configure.ac", lambda t: (".".join(re.findall(r"m4_define\(pcre_(?:major|minor), \[(\d+)\]\)", t)) or None)),
    "libressl": ("LibreSSL", "libressl/VERSION", lambda t: t.strip().splitlines()[0].strip() if t.strip() else None),
}


def _load_cache() -> dict:
    try:
        return json.loads(CACHE.read_text())
    except Exception:  # noqa: BLE001
        return {}


def resolve(project: str, tag: str, cache: dict) -> str | None:
    """Upstream version of an Apple project at a tag, or None when unknown."""
    key = f"{project}-{tag}"
    if key in cache:
        return cache[key] or None
    name, path, reader = RESOLVERS[project]
    version = None
    try:
        text = fetch.get_text(RAW.format(project=project, tag=tag, path=path), timeout=60)
        version = reader(text)
    except fetch.FetchError:
        version = None
    cache[key] = version or ""
    return version


def releases_data(index: str = RELEASES_URL) -> dict:
    """{platform: {family: {release: {project: tag}}}} from the site's JS bundle."""
    page = fetch.get_text(index, timeout=60)
    scripts = re.findall(r'<script[^>]+src="([^"]+main\.built[^"]+\.js)"', page)
    if not scripts:
        raise fetch.FetchError(f"{index}: no main.built script found")
    src = scripts[0] if scripts[0].startswith("http") else "https://opensource.apple.com" + scripts[0]
    js = fetch.get_text(src, timeout=120)
    start = js.find("{macOS:")
    if start < 0:
        raise fetch.FetchError(f"{src}: releases object not found")
    depth, i = 0, start
    while i < len(js):
        depth += {"{": 1, "}": -1}.get(js[i], 0)
        i += 1
        if depth == 0:
            break
    literal = re.sub(r'([{,])\s*([A-Za-z_$][\w$]*)\s*:', r'\1"\2":', js[start:i])
    return json.loads(literal)


def _vkey(label: str):
    nums = re.findall(r"\d+", label)
    return [int(n) for n in nums]


def discover(rule: dict, log=print) -> list[dict]:
    """rule: {type: apple_releases, supplier, index, products: {platform: {name, latest}}, min_projects}."""
    data = releases_data(rule.get("index") or RELEASES_URL)
    cache = _load_cache()
    docs = []
    for platform, spec in (rule.get("products") or {}).items():
        spec = spec or {}
        product = spec.get("name") or platform
        families = data.get(platform) or {}
        releases = []
        for family, rels in families.items():
            for label, projects in rels.items():
                if len(projects) >= int(rule.get("min_projects", 1)):
                    releases.append((label, projects))
        releases.sort(key=lambda r: _vkey(r[0]), reverse=True)
        for label, projects in releases[: int(spec.get("latest", 3))]:
            version = re.sub(r"^\D+", "", label).strip()
            comps, resolved = [], 0
            for project, tag in sorted(projects.items(), key=lambda kv: kv[0].lower()):
                tag = str(tag)
                if project in RESOLVERS:
                    upstream = resolve(project, tag, cache)
                    resolved += bool(upstream)
                    comps.append({"name": RESOLVERS[project][0], "version": upstream or "", "apple": f"{project}-{tag}"})
                else:
                    comps.append({"name": project, "version": "", "apple": f"{project}-{tag}"})
            docs.append({"supplier": rule["supplier"], "product": product, "version": version,
                         "url": f"{RELEASES_URL}#{re.sub(r'[^a-z0-9.]+', '-', label.lower())}",
                         "discovered_by": rule.get("index") or RELEASES_URL,
                         "components": comps, "kind": "apple-release", "via": ["apple_releases", "upstream_headers"]})
            log(f"  Apple {product} {version}: {len(comps)} projects, {resolved} upstream versions resolved")
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(cache, sort_keys=True, indent=0) + "\n")
    return docs
