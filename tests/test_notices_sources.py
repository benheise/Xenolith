"""JetBrains release API, Oracle 14.1.2 manuals and the opt-in rendered fetch. No network:
every fetch and the browser are replaced with fakes."""

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xenolith import catalog, fetch as fetch_mod  # noqa: E402
from xenolith.sources import notices  # noqa: E402


class Patch:
    """Replace attributes for the duration of a with-block."""

    def __init__(self, *triples):
        self.triples, self.saved = triples, []

    def __enter__(self):
        for obj, name, value in self.triples:
            self.saved.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)
        return self

    def __exit__(self, *exc):
        for obj, name, value in reversed(self.saved):
            setattr(obj, name, value)


def no_browser(url, timeout=90):
    raise AssertionError(f"the browser must not be started for {url}")


SHELL = ('<html><head><title>Third-party software</title><script src="/app.js"></script></head>'
         '<body><div id="root"></div><noscript>Enable JavaScript</noscript></body></html>')
RENDERED = ('<html><head><title>Third-party software</title></head><body><table>'
            '<tr><th>Library</th><th>Version</th><th>License</th></tr>'
            '<tr><td>OpenSSL</td><td>3.0.15</td><td>Apache-2.0</td></tr>'
            '<tr><td>zlib</td><td>1.3.1</td><td>Zlib</td></tr></table></body></html>')


class JetBrainsTest(unittest.TestCase):
    API = [
        {"code": "TC", "name": "TeamCity", "releases": [
            {"version": "2026.2.2", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/tc-2026.2.2.json"}}},
            {"version": "2026.2.1", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/tc-2026.2.1.json"}}},
            {"version": "2026.2.3", "type": "eap", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/tc-eap.json"}}},
            {"version": "2026.1.6", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/tc-2026.1.6.json"}}},
            {"version": "2026.1.5", "type": "release", "downloads": {}},
            {"version": "2025.11.8", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/tc-2025.11.8.json"}}}]},
        {"code": "YTD", "name": "YouTrack", "releases": [
            {"version": "2026.2", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/youtrack-2026.2.19840.json"}}},
            {"version": "2026.2", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/youtrack-2026.2.19656.json"}}},
            {"version": "2026.1", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/youtrack-2026.1.14165.json"}}}]},
        {"code": "RSCLT", "name": "ReSharper Command Line Tools", "releases": [
            {"version": "2026.3", "type": "release", "downloads": {"thirdPartyLibrariesJson": {"link": "https://r.example/rs.json"}}}]},
    ]
    RULE = {"type": "jetbrains", "supplier": "JetBrains", "index": "https://www.jetbrains.com/legal/third-party-software/",
            "versions_url": "https://api.example/products?code=TC,YTD", "per_minor": True, "latest": 1,
            "version_from_url": r"youtrack-(?P<version>\d{4}\.\d+\.\d+)\.json$",
            "products": {"TC": {"name": "TeamCity", "latest": 3}, "YTD": {"name": "YouTrack", "latest": 2}}}

    def discover(self, rule):
        with Patch((fetch_mod, "get_json", lambda url, **kw: self.API)):
            return notices.discover_jetbrains(rule, log=lambda *a: None)

    def test_release_lines_types_and_build_versions(self):
        docs = self.discover(self.RULE)
        self.assertEqual([(d["product"], d["version"]) for d in docs],
                         [("TeamCity", "2026.2.2"), ("TeamCity", "2026.1.6"), ("TeamCity", "2025.11.8"),
                          ("YouTrack", "2026.2.19840"), ("YouTrack", "2026.1.14165")])
        self.assertNotIn("https://r.example/tc-eap.json", [d["url"] for d in docs])      # EAP builds are skipped
        self.assertNotIn("ReSharper Command Line Tools", {d["product"] for d in docs})  # only listed products

    def test_without_per_minor_keeps_newest_releases(self):
        docs = self.discover({**self.RULE, "per_minor": False})
        self.assertEqual([d["version"] for d in docs if d["product"] == "TeamCity"], ["2026.2.2", "2026.2.1", "2026.1.6"])

    def test_provenance_starts_at_the_public_page(self):
        doc = self.discover(self.RULE)[0]
        prov = notices.doc_provenance(doc, self.RULE)
        self.assertEqual(prov, {"found_via": "auto-discovered",
                                "discovery_path": [self.RULE["index"], self.RULE["versions_url"]]})
        cfg = {"discover": [self.RULE]}
        self.assertEqual(notices.infer_provenance("https://resources.jetbrains.com/storage/x.json", "JetBrains", cfg), prov)

    def test_json_array_is_a_component_list(self):
        body = json.dumps([{"name": "org.apache.commons:commons-text", "version": "1.10.0", "license": "Apache 2.0"},
                           {"name": "JetBrains Runtime", "url": "https://github.com/JetBrains/JetBrainsRuntime", "version": "21"},
                           {"name": "  ", "version": "1"}, "not a dict"]).encode()
        comps, used, kind = notices.extract(body, "application/json", "https://r.example/idea-2026.3-third-party-libraries.json")
        self.assertEqual((used, kind), (["sbom"], "sbom"))
        self.assertEqual({(c["name"], c["version"]) for c in comps},
                         {("org.apache.commons:commons-text", "1.10.0"), ("JetBrains Runtime", "21")})
        # An array is only read as JSON when the response says it is JSON.
        _, used, kind = notices.extract(b'["a", "b"]', "text/plain", "https://r.example/list.txt")
        self.assertNotEqual(kind, "sbom")

    def test_matching_of_jetbrains_names(self):
        cat = catalog.load()
        self.assertEqual(cat.match_component("JetBrains Runtime", "21"), "openjdk")
        self.assertIsNone(cat.match_component("JetBrains Runtime API", "1.9.0"))
        self.assertIsNone(cat.match_component("Log4j", "1.7.36"))          # SLF4J's log4j-over-slf4j bridge
        self.assertIsNone(cat.match_component("log4j", "1.2-api-2.14.0"))  # Log4j 2's 1.2 bridge
        self.assertEqual(cat.match_component("log4j", "1.2.17"), "log4j-1")
        self.assertEqual(cat.match_component("log4j", "1.2"), "log4j-1")

    def test_shipped_rule(self):
        cfg = yaml.safe_load((ROOT / "catalog" / "notices.yaml").read_text(encoding="utf-8"))
        rule = next(r for r in cfg["discover"] if r.get("type") == "jetbrains")
        codes = re.search(r"code=([A-Z,]+)", rule["versions_url"]).group(1).split(",")
        self.assertEqual(sorted(codes), sorted(rule["products"]))                 # the API filter matches the list
        self.assertTrue(rule["index"].startswith("https://www.jetbrains.com/"))
        self.assertEqual(re.search(rule["version_from_url"], "youtrack-2026.2.19840.json").group("version"), "2026.2.19840")
        self.assertIsNone(re.search(rule["version_from_url"], "tc-2026.2.2-third-party-libraries.json"))


class OracleTest(unittest.TestCase):
    PAGE = ('<table><tr><th>Provider</th><th>Component</th><th>Release Version</th><th>Licensing Information</th></tr>'
            '<tr><td>OpenSSL</td><td>OpenSSL</td><td>3.0.15</td><td>Apache License 2.0 ...</td></tr>'
            '<tr><td>RSA</td><td>BSAFE Software (CCME, MES, Crypto J, Cert J, and SSL J)</td><td>6.3</td><td>...</td></tr>'
            '<tr><td>Daniel Stenberg</td><td>curl</td><td>8.10.0</td><td>MIT ...</td></tr></table>')

    def test_release_version_column(self):
        rows = notices.ex_html_table(self.PAGE)
        self.assertEqual(rows, [("OpenSSL", "3.0.15"), ("BSAFE Software (CCME, MES, Crypto J, Cert J, and SSL J)", "6.3"),
                                ("curl", "8.10.0")])

    def test_plural_release_versions_is_not_a_component_version(self):
        old = ('<table><tr><th>Provider</th><th>Component(s)</th><th>Release Versions</th><th>Licensing Information</th></tr>'
               '<tr><td>Infozip</td><td>zip 3</td><td>11.1.1.9.0</td><td>...</td></tr></table>')
        self.assertEqual(notices.ex_html_table(old), [("zip 3", "")])           # named, but not given Oracle's release

    def test_discover_rename_and_shipped_rule(self):
        cfg = yaml.safe_load((ROOT / "catalog" / "notices.yaml").read_text(encoding="utf-8"))
        rule = next(r for r in cfg["discover"] if r["supplier"] == "Oracle")
        base = "https://docs.oracle.com/en/middleware/fusion-middleware/14.1.2"
        page = (f'<a href="{base}/wlslc/index.html">Oracle WebLogic Server</a>'
                f'<a href="{base}/ohslc/index.html">Oracle HTTP Server</a>'
                f'<a href="{base}/grllc/index.html">Oracle GraalVM for JDK 23 (24.1)</a>'
                f'<a href="{base}/wsmlc/index.html">Oracle Webservices Manage</a>r'
                f'<a href="{base}/umslc/index.html">User Messaging Service</a>'
                '<a href="https://opensource.oracle.com/#graalpy">Open Source Projects at Oracle</a>')
        with Patch((fetch_mod, "get_text", lambda url, **kw: page)):
            docs = notices.discover(rule, log=lambda *a: None)
        self.assertEqual([(d["product"], d["version"]) for d in docs],
                         [("Oracle WebLogic Server", "14.1.2"), ("Oracle HTTP Server", "14.1.2"),
                          ("Oracle Web Services Manager", "14.1.2"), ("User Messaging Service", "14.1.2")])

    def test_noise_from_license_texts(self):
        self.assertEqual(notices.ex_url_lines("* LGPL v2.1: https://www.gnu.org/licenses/\nEPL v1.0: https://www.eclipse.org/legal\n"
                                              "jedis 2.9.0: https://github.com/xetorthio/jedis MIT\n"), [("jedis", "2.9.0")])
        self.assertEqual(notices.ex_gt_list(">>> ASM 9.1 (org.ow2.asm:asm:9.1, org.ow2.asm:asm-tree:9.1)\n>>> zlib-1.2.13\n"),
                         [("ASM", "9.1"), ("zlib", "1.2.13")])
        self.assertEqual(notices._split_multi("zlib, libpng"), ["zlib", "libpng"])


class RenderTest(unittest.TestCase):
    URL = "https://vendor.example/legal/third-party.html"

    def test_wall_detection(self):
        self.assertEqual(notices._wall("<title>Just a moment...</title><body>Checking</body>"), "Just a moment")
        self.assertEqual(notices._wall("<title>Docs</title><body>Please sign in to continue</body>"), "Please sign in")
        self.assertEqual(notices._wall('<title>Docs</title><form><input type="password" name="p"></form>'), "password form")
        long_license = "<title>Notices</title><body>" + ("Permission is hereby granted, free of charge. " * 60) + \
                       "ACCESS DENIED is not a license term. <input type=password></body>"
        self.assertIsNone(notices._wall(long_license))      # a long page that only mentions it is not a wall
        self.assertIsNone(notices._wall(SHELL))

    def test_http_error_is_never_rendered(self):
        def refused(url):
            raise fetch_mod.FetchError(f"{url}: HTTP Error 403: Forbidden")
        with Patch((notices, "_get", refused), (notices, "_render_html", no_browser)):
            with self.assertRaisesRegex(fetch_mod.FetchError, "403"):
                notices._get_rendered(self.URL)

    def test_bot_or_login_page_is_never_rendered(self):
        for page in ("<html><title>Attention Required! | Cloudflare</title><body>captcha</body></html>",
                     '<html><title>Log in</title><body><form><input type="password"></form></body></html>'):
            with Patch((notices, "_get", lambda url: (page.encode(), "text/html")), (notices, "_render_html", no_browser)):
                with self.assertRaisesRegex(fetch_mod.FetchError, "not rendered"):
                    notices._get_rendered(self.URL)

    def test_readable_or_non_html_pages_are_used_as_is(self):
        for body, ctype in ((RENDERED.encode(), "text/html"), (b"%PDF-1.7 ...", "application/pdf"),
                            (b'{"bomFormat": "CycloneDX", "components": []}', "application/json")):
            with Patch((notices, "_get", lambda url: (body, ctype)), (notices, "_render_html", no_browser)):
                self.assertEqual(notices._get_rendered(self.URL), (body, ctype, False))

    def test_empty_shell_is_rendered(self):
        calls = []

        def browser(url, timeout=90):
            calls.append(url)
            return 200, RENDERED, url
        with Patch((notices, "_get", lambda url: (SHELL.encode(), "text/html")), (notices, "_render_html", browser)):
            body, ctype, rendered = notices._get_rendered(self.URL)
        self.assertEqual((calls, rendered, ctype), ([self.URL], True, "text/html; charset=utf-8"))
        comps, _, _ = notices.extract(body, ctype, self.URL)
        self.assertEqual({(c["name"], c["version"]) for c in comps}, {("OpenSSL", "3.0.15"), ("zlib", "1.3.1")})

    def test_refusals_in_the_browser(self):
        cases = [(lambda url, timeout=90: (403, RENDERED, url), "HTTP 403"),
                 (lambda url, timeout=90: (429, RENDERED, url), "HTTP 429"),
                 (lambda url, timeout=90: (200, RENDERED, "https://vendor.example/sso/login?next=x"), "login page"),
                 (lambda url, timeout=90: (200, "<title>Are you a robot?</title><body>verify</body>", url), "bot page")]
        for browser, message in cases:
            with Patch((notices, "_get", lambda url: (SHELL.encode(), "text/html")), (notices, "_render_html", browser)):
                with self.assertRaisesRegex(fetch_mod.FetchError, message):
                    notices._get_rendered(self.URL)

    def test_missing_playwright_is_a_fetch_error(self):
        saved = {k: sys.modules.get(k) for k in ("playwright", "playwright.sync_api")}
        sys.modules["playwright"] = None
        sys.modules["playwright.sync_api"] = None
        try:
            with self.assertRaisesRegex(fetch_mod.FetchError, "needs Playwright"):
                notices._render_html(self.URL)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_crawl_records_rendering_and_text_hash(self):
        registry = {"documents": [{"supplier": "Acme", "product": "Console", "version": "5.1", "url": self.URL,
                                   "found_at": "https://vendor.example/legal/", "render": True}]}
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "notices.yaml"
            reg.write_text(yaml.safe_dump(registry))
            data = Path(d) / "data"
            with Patch((notices, "_get", lambda url: (SHELL.encode(), "text/html")),
                       (notices, "_render_html", lambda url, timeout=90: (200, RENDERED, url))):
                stats = notices.crawl(reg, data_dir=data, discover_docs=False, log=lambda *a: None)
            self.assertEqual((stats["fetched"], stats["parsed"]), (1, 1))
            inv = json.loads(next((data / "notices").rglob("*.json")).read_text())
            self.assertTrue(inv["rendered"])
            self.assertEqual(inv["sha256"], hashlib.sha256(notices.html_to_text(RENDERED).encode()).hexdigest())
            self.assertEqual((inv["found_via"], inv["discovery_path"]), ("hand-listed", ["https://vendor.example/legal/"]))
            state = json.loads((data / "state" / "notices.json").read_text())
            self.assertTrue(state[self.URL]["rendered"])

    def test_plain_documents_never_start_a_browser(self):
        registry = {"documents": [{"supplier": "Acme", "product": "Console", "version": "5.1", "url": self.URL}]}
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "notices.yaml"
            reg.write_text(yaml.safe_dump(registry))
            with Patch((notices, "_get", lambda url: (SHELL.encode(), "text/html")), (notices, "_render_html", no_browser)):
                stats = notices.crawl(reg, data_dir=Path(d) / "data", discover_docs=False, log=lambda *a: None)
        self.assertEqual(stats["empty"], 1)

    def test_rendered_index_only_when_links_are_missing(self):
        rule = {"supplier": "Acme", "index": "https://vendor.example/legal/", "render": True,
                "link": r"/notices/[^/]+\.pdf$", "title": r"^(?P<product>.+?) (?P<version>\d[\d.]*)$"}
        links = '<a href="/notices/console-5.1.pdf">Console 5.1</a>'
        with Patch((fetch_mod, "get_text", lambda url, **kw: f"<html><body>{links}</body></html>"),
                   (notices, "_render_html", no_browser)):
            self.assertEqual(len(notices.discover(rule, log=lambda *a: None)), 1)
        with Patch((fetch_mod, "get_text", lambda url, **kw: SHELL),
                   (notices, "_render_html", lambda url, timeout=90: (200, f"<html><body>{links}</body></html>", url))):
            docs = notices.discover(rule, log=lambda *a: None)
        self.assertEqual([(d["product"], d["version"]) for d in docs], [("Console", "5.1")])
        with tempfile.TemporaryDirectory() as d:          # documents found by a render rule inherit render: true
            reg = Path(d) / "notices.yaml"
            reg.write_text(yaml.safe_dump({"discover": [rule]}))
            with Patch((fetch_mod, "get_text", lambda url, **kw: SHELL),
                       (notices, "_render_html", lambda url, timeout=90: (200, f"<html><body>{links}</body></html>", url))):
                found = notices.load_registry(reg, log=lambda *a: None)
        self.assertTrue(found[0]["render"])

    def test_no_shipped_entry_renders_without_need(self):
        # render: true is opt-in; nothing in the catalog needs it today, and refresh.yml installs no browser.
        cfg = yaml.safe_load((ROOT / "catalog" / "notices.yaml").read_text(encoding="utf-8"))
        rendered = [e for e in (cfg.get("documents") or []) + (cfg.get("discover") or []) if e.get("render")]
        workflow = (ROOT / ".github" / "workflows" / "refresh.yml").read_text(encoding="utf-8")
        self.assertEqual(bool(rendered), "playwright" in workflow.lower())


class OfflineStampTest(unittest.TestCase):
    def test_offline_stamp_keeps_paths_from_online_runs(self):
        # Two rules for one supplier whose link patterns both match: inference alone would pick the
        # first rule, so an exact path written by an online run must survive --match-only.
        rules = [{"supplier": "NVIDIA", "index": "https://docs.example/a", "link": r"/Legal/.+\.pdf$", "title": "."},
                 {"supplier": "NVIDIA", "index": "https://docs.example/b", "link": r"/Legal/.+\.pdf$", "title": "."}]
        exact = ["https://docs.example/b", "https://docs.example/b/page-7"]
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "notices.yaml"
            reg.write_text(yaml.safe_dump({"discover": rules}))
            data = Path(d)
            (data / "notices" / "nvidia").mkdir(parents=True)
            kept = data / "notices" / "nvidia" / "kept.json"
            stale = data / "notices" / "nvidia" / "stale.json"
            notices.write_inventory(kept, {"supplier": "NVIDIA", "url": "https://c.example/Legal/x.pdf",
                                           "found_via": "auto-discovered", "discovery_path": exact})
            notices.write_inventory(stale, {"supplier": "NVIDIA", "url": "https://c.example/Legal/y.pdf",
                                            "found_via": "auto-discovered", "discovery_path": ["https://docs.example/removed"]})
            self.assertEqual(notices.stamp_inventories(reg, data, log=lambda *a: None), 1)
            self.assertEqual(json.loads(kept.read_text())["discovery_path"], exact)
            self.assertEqual(json.loads(stale.read_text())["discovery_path"], ["https://docs.example/a"])


class CorrectionsTest(unittest.TestCase):
    RULE = {"supplier": "JetBrains", "products": "YouTrack|Hub", "names": "log4j-(?:api|core|slf4j-impl)",
            "versions": r"2\.10\.0", "reason": "a stale entry", "evidence": "https://blog.example/log4j"}

    def write(self, data: Path, product: str, comps: list[dict]) -> None:
        notices.write_inventory(data / "notices" / "jetbrains" / f"{product}.json", {
            "supplier": "JetBrains", "product": product, "version": "2026.2", "url": f"https://r.example/{product}.json",
            "retrieved": "2026-11-18", "sha256": "0" * 64, "components": comps})

    def run_with(self, corrections, setup):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d)
            setup(data)
            reg = data / "notices.yaml"
            reg.write_text(yaml.safe_dump({"corrections": corrections}))
            return notices.assertions(catalog.load(), data, notices.load_corrections(reg))

    def test_set_aside_entry_is_named_and_sourced(self):
        def setup(data):
            self.write(data, "YouTrack", [{"name": "log4j-core", "version": "2.10.0"},
                                          {"name": "org.apache.logging.log4j:log4j-core", "version": "2.24.3"}])
            self.write(data, "Hub", [{"name": "log4j-core", "version": "2.10.0"}])           # nothing else listed
            self.write(data, "TeamCity", [{"name": "log4j-core", "version": "2.10.0"}])      # not covered
        rows, stats = self.run_with([self.RULE], setup)
        by = {r["product"]: r for r in rows if r["component"] == "log4j-core"}
        self.assertEqual(by["YouTrack"]["component_version"], "2.24.3")
        self.assertIn("Not counted: log4j-core 2.10.0 (a stale entry).", by["YouTrack"]["notes"])
        self.assertIn("https://blog.example/log4j", by["YouTrack"]["references"])
        self.assertNotIn("Hub", by)                                     # only the stale entry: no statement
        self.assertEqual(by["TeamCity"]["component_version"], "2.10.0")
        self.assertEqual((stats["set_aside"], stats["corrections_unused"]), (2, 0))

    def test_unused_corrections_are_reported(self):
        _, stats = self.run_with([self.RULE], lambda data: self.write(
            data, "YouTrack", [{"name": "org.apache.logging.log4j:log4j-core", "version": "2.24.3"}]))
        self.assertEqual((stats["set_aside"], stats["corrections_unused"]), (0, 1))

    def test_validation(self):
        bad = {"corrections": [{"supplier": "X", "names": "(", "reason": "", "evidence": "http://x", "note": "?"}]}
        errors = " | ".join(notices.validate_corrections(bad))
        for needle in ("unexpected field", "reason is required", "evidence must be https", "names is not a valid regex"):
            self.assertIn(needle, errors)
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "notices.yaml"
            reg.write_text(yaml.safe_dump(bad))
            with self.assertRaises(ValueError):
                notices.load_corrections(reg)

    def test_shipped_corrections(self):
        reg = ROOT / "catalog" / "notices.yaml"
        self.assertEqual(notices.validate_corrections(yaml.safe_load(reg.read_text(encoding="utf-8"))), [])
        rule = next(r for r in notices.load_corrections(reg) if r["supplier"] == "JetBrains")
        self.assertTrue(rule["_product"].fullmatch("YouTrack") and rule["_product"].fullmatch("Hub"))
        self.assertIsNone(rule["_product"].fullmatch("TeamCity"))
        self.assertTrue(rule["_name"].fullmatch("log4j-core") and rule["_version"].fullmatch("2.10.0"))
        self.assertIsNone(rule["_name"].fullmatch("org.apache.logging.log4j:log4j-core"))   # the current entries stay
        self.assertIsNone(rule["_version"].fullmatch("2.20.0"))


class NewSourcesTest(unittest.TestCase):
    """GitLab license manifests, JFrog's bundled-version tables, Red Hat's SBOM index."""

    def test_tag_versions(self):
        for name, tag, want in [("curl", "curl-8_23_0", "8.23.0"), ("openssl", "OpenSSL_1_1_1n", "1.1.1n"),
                                ("openssl", "openssl-3.6.3", "3.6.3"), ("nginx", "release-1.31.7", "1.31.7"),
                                ("zlib", "v1.2.12", "1.2.12"), ("libgcrypt", "libgcrypt-1.10.2", "1.10.2"),
                                ("libxml2", "2.15.4", "2.15.4"), ("libedit", "20120601-3.0", "20120601-3.0")]:
            self.assertEqual(notices.tag_version(name, tag), want, tag)

    def test_license_manifest(self):
        manifest = {
            "openssl": {"license": "Apache-2.0", "version": "openssl-3.6.3", "status": "acceptable"},
            "nginx": {"license": "BSD-2-Clause", "version": "release-1.31.7",
                      "dependencies": {"pcre2": {"license": "BSD", "version": "10.44"},
                                       "openssl": {"license": "Apache-2.0", "version": "openssl-3.6.3"}}},
            "curl": {"license": "MIT", "version": "curl-8_23_0"},
            "config_guess": {"license": "GPL-3.0", "version": "c9092d05347c925a26f6887980e185206e13f9d6"},
            "postgresql": {"license": "PostgreSQL", "version": "17.11"},
            "redis": {"license": "BSD-3-Clause", "version": "7.2.16"},
        }
        body = json.dumps(manifest).encode()
        comps, used, kind = notices.extract(body, "application/json", "https://g.example/gitlab-ee/19.5/19.5.6-ee.0.json")
        self.assertEqual(kind, "sbom")
        self.assertEqual({(c["name"], c["version"]) for c in comps},
                         {("openssl", "3.6.3"), ("nginx", "1.31.7"), ("pcre2", "10.44"), ("curl", "8.23.0"),
                          ("postgresql", "17.11"), ("redis", "7.2.16")})
        self.assertEqual(notices.ex_license_manifest({"name": "x", "version": "1"}), [])   # not a manifest

    def test_versions_json_from_a_tag_list(self):
        tags = [{"name": n} for n in ("19.6.0+rc43.ee.0", "19.6.0+ee.0", "19.6.0+ce.0", "19.5.6+ee.0", "19.5.5+ee.0",
                                      "19.4.8+ee.0", "19.3.9+ee.0")]
        rule = {"type": "versions_json", "supplier": "GitLab", "product": "GitLab EE", "versions_url": "https://api.example/tags",
                "field": "name", "version_regex": r"^(?P<version>\d+\.\d+\.\d+)\+ee\.0$", "keep_latest_per_minor": True,
                "limit": 3, "url_template": "https://g.example/gitlab-ee/{minor}/{version}-ee.0.json"}
        published = {"https://g.example/gitlab-ee/19.5/19.5.6-ee.0.json", "https://g.example/gitlab-ee/19.4/19.4.8-ee.0.json",
                     "https://g.example/gitlab-ee/19.3/19.3.9-ee.0.json"}       # 19.6.0's manifest isn't out yet
        with Patch((fetch_mod, "get_json", lambda url, **kw: tags), (notices, "_exists", lambda url: url in published)):
            docs = notices.discover_versions(rule, log=lambda *a: None)
        self.assertEqual([(d["version"], d["url"]) for d in docs],
                         [("19.5.6", "https://g.example/gitlab-ee/19.5/19.5.6-ee.0.json"),
                          ("19.4.8", "https://g.example/gitlab-ee/19.4/19.4.8-ee.0.json"),
                          ("19.3.9", "https://g.example/gitlab-ee/19.3/19.3.9-ee.0.json")])

    def test_version_table(self):
        page = ("<table><tr><th>Artifactory Version</th><th>OpenJDK Version</th></tr>"
                "<tr><td>7.173</td><td>25.0.4.1</td></tr><tr><td>7.146</td><td>21.0.11</td></tr>"
                "<tr><td>7.59.9-7.68.20</td><td>17.0.6</td></tr></table>"
                "<table><tr><th>Artifactory Product Version</th><th>Tomcat Version</th></tr>"
                "<tr><td>7.173.8</td><td>Artifactory Service: 11.0.26 Access Service: 11.0.25</td></tr></table>")
        rule = {"type": "version_table", "supplier": "JFrog", "product": "Artifactory", "index": "https://docs.example/releases",
                "latest": 2, "tables": [
                    {"version_column": "Artifactory Version", "value_column": "OpenJDK Version", "component": "OpenJDK"},
                    {"version_column": "Artifactory Product Version", "value_column": "Tomcat Version",
                     "component": "Apache Tomcat", "value_regex": r"Artifactory Service:\s*(?P<v>\d+\.\d+\.\d+)"}]}
        with Patch((fetch_mod, "get_text", lambda url, **kw: page)):
            docs = notices.discover_version_table(rule, log=lambda *a: None)
        self.assertEqual([(d["version"], d["components"]) for d in docs],
                         [("7.173", [{"name": "OpenJDK", "version": "25.0.4.1"}]),
                          ("7.146", [{"name": "OpenJDK", "version": "21.0.11"}]),
                          ("7.173.8", [{"name": "Apache Tomcat", "version": "11.0.26"}])])
        self.assertEqual(len({d["url"] for d in docs}), 3)                  # one inventory per row
        cat = catalog.load()
        self.assertEqual(cat.match_component("OpenJDK", "25.0.4.1"), "openjdk")
        self.assertEqual(cat.match_component("Apache Tomcat", "11.0.26"), "tomcat")

    def test_file_index_and_bzip2(self):
        import bz2
        index = "spdx/rhbk-26.4.json.bz2\nspdx/rhbk-26.6.json.bz2\nspdx/eap-7.4.z.json.bz2\nspdx/eap-8.1.z.json.bz2\nspdx/rhel-9.9.z.json.bz2\n"
        rule = {"type": "file_index", "supplier": "Red Hat", "index": "https://s.example/sbom/v1/index.txt", "latest": 1,
                "link": r"^spdx/(?P<product>[a-z0-9_]+(?:-[a-z]+)*?)[-_](?P<version>\d[\w.]*?)\.json\.bz2$",
                "products": {"rhbk": {"name": "Red Hat build of Keycloak", "latest": 2}, "eap": "Red Hat JBoss EAP"}}
        with Patch((fetch_mod, "get_text", lambda url, **kw: index)):
            docs = notices.discover_file_index(rule, log=lambda *a: None)
        self.assertEqual([(d["product"], d["version"], d["url"]) for d in docs],
                         [("Red Hat build of Keycloak", "26.6", "https://s.example/sbom/v1/spdx/rhbk-26.6.json.bz2"),
                          ("Red Hat build of Keycloak", "26.4", "https://s.example/sbom/v1/spdx/rhbk-26.4.json.bz2"),
                          ("Red Hat JBoss EAP", "8.1.z", "https://s.example/sbom/v1/spdx/eap-8.1.z.json.bz2")])
        spdx = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "log4j-core", "versionInfo": "2.25.5.redhat-00001"},
                                                        {"name": "jquery", "versionInfo": "3.4.1"}]}
        comps, used, kind = notices.extract(bz2.compress(json.dumps(spdx).encode()), "application/octet-stream",
                                            "https://s.example/sbom/v1/spdx/eap-8.1.z.json.bz2")
        self.assertEqual((kind, {(c["name"], c["version"]) for c in comps}),
                         ("sbom", {("log4j-core", "2.25.5.redhat-00001"), ("jquery", "3.4.1")}))
        self.assertEqual(notices.extract(b"BZh9 not really bzip2", "application/octet-stream", "https://x/a.json.bz2")[0], [])


class WatchlistAdditionsTest(unittest.TestCase):
    def test_new_components_match_and_range(self):
        from xenolith import versions
        cat = catalog.load()
        cases = [("nginx", "1.24.0", "nginx"), ("nginx-bin", "1.20.1", "nginx"), ("nginx-filesystem", "1.20.1", None),
                 ("ingress-nginx", "1.9.0", None), ("Apache Tomcat", "9.0.98", "tomcat"),
                 ("org.apache.tomcat.embed:tomcat-embed-core", "10.1.19", "tomcat"), ("tomcat-jdbc", "9.0.1", None),
                 ("Apache Tomcat Native Library", "1.2.3", None), ("tomcat-embed-el", "9.0.1", None),
                 ("sudo", "1.8.27", "sudo"), ("jQuery", "3.4.1", "jquery"), ("jQuery UI", "1.12.1", None),
                 ("@types/jquery", "3.5", None), ("erlang-otp", "26.0.2", "erlang-otp"), ("OTP", "23.3", "erlang-otp"),
                 ("WildFly Elytron - SASL OTP", "1.0", None), ("Apache ActiveMQ", "5.14.5", "activemq"),
                 ("Apache ActiveMQ", "2.6.3", None), ("ActiveMQ Artemis", "2.30.0", None),
                 ("Apache Struts", "2.3.37", "struts2"), ("Apache Struts", "1.3.10", None), ("struts-core", "1.3.10", None),
                 ("Apache HTTP Server", "2.4.49", "apache-httpd"), ("httpd-tools", "2.4.37", None),
                 ("Apache HttpClient", "4.5", None), ("Squid Cache", "3.5.28", "squid"), ("SquidClamav", "6.0", None),
                 ("curl", "0.4.44", None), ("curl", "8.23.0", "curl")]
        for name, version, want in cases:
            self.assertEqual(cat.match_component(name, version), want, f"{name} {version}")

        def status(cid, version):
            comp = cat.components[cid]
            return versions.check([version], comp.affected, comp.version_style)["status"]
        expected = {("nginx", "1.30.6"): "in_range", ("nginx", "1.30.7"): "outside", ("nginx", "1.31.8"): "in_range",
                    ("nginx", "1.31.9"): "outside", ("tomcat", "8.5.100"): "in_range", ("tomcat", "9.0.99"): "in_range", ("tomcat", "9.0.118"): "outside",
                    ("tomcat", "10.1.34"): "in_range", ("tomcat", "9.0.30"): "in_range",         # Ghostcat
                    ("sudo", "1.9.5p1"): "in_range", ("sudo", "1.9.5p2"): "outside", ("sudo", "1.9.17_p1"): "outside",
                    ("erlang-otp", "OTP-26.2.5"): "in_range", ("erlang-otp", "26.2.5.11"): "outside",
                    ("erlang-otp", "27.3.4.1"): "outside", ("activemq", "5.17.7"): "in_range", ("activemq", "5.19.4"): "outside", ("activemq", "5.14.5"): "in_range",
                    ("jquery", "3.4.1"): "in_range", ("jquery", "3.5.0"): "outside", ("squid", "7.5"): "in_range",
                    ("squid", "7.6"): "outside", ("struts2", "2.3.37"): "in_range", ("struts2", "6.4.0"): "outside"}
        for (cid, version), want in expected.items():
            self.assertEqual(status(cid, version), want, f"{cid} {version}")

    def test_axis1_is_kept_apart_from_axis2(self):
        from xenolith import versions
        cat = catalog.load()
        cases = [("org.apache.axis:axis", "1.4", "axis1"), ("axis:axis", "1.2.1", "axis1"),
                 ("com.springsource.org.apache.axis", "1.4.0", "axis1"), ("Apache Axis", "1.4", "axis1"),
                 ("axis", "1.2-RC3", "axis1"), ("axis-saaj", "1.4", "axis1"),
                 ("Apache Axis", "1.4.1", None), ("Apache Axis", "1.7.8", None),          # Axis2 releases
                 ("Apache Axis", "2.0 - SAAJ 1.3", None), ("Axis (Java)", "1.5.1", None),
                 ("org.apache.axis2:axis2-kernel", "1.8.2", None), ("d3-axis", "3.0.0", None)]
        for name, version, want in cases:
            self.assertEqual(cat.match_component(name, version), want, f"{name} {version}")
        comp = cat.components["axis1"]
        self.assertEqual(versions.check(["1.4"], comp.affected, comp.version_style)["status"], "in_range")

    def test_criteria_pass_components_match_only_their_own_names(self):
        from xenolith import versions
        cat = catalog.load()
        cases = [("zlib", "1.2.11", "zlib"), ("libexpat", "2.2.5", "expat"), ("freetype2", "2.9.1", "freetype"),
                 ("libssh", "0.7.3", "libssh"), ("libssh2", "1.9.0", None), ("rsync", "3.2.7", "rsync"),
                 ("Samba", "3.5.1", "samba"), ("samba", "0.1.0", None), ("Dnsmasq", "2.80", "dnsmasq"),
                 ("libvpx", "1.6.0", "libvpx"), ("org.yaml:snakeyaml", "1.33", "snakeyaml"), ("SnakeYAML", "2.2", "snakeyaml"),
                 ("com.fasterxml.jackson.core:jackson-databind", "2.9.6", "jackson-databind"),
                 ("Jackson Databind", "2.8.9", "jackson-databind"), ("jackson-databind-nullable", "0.2.6", None),
                 ("tools.jackson.core:jackson-databind", "3.0.0", None), ("jackson-core", "2.9.6", None),
                 ("Apache Commons Collections", "3.2.1", "commons-collections"),
                 ("org.apache.commons:commons-collections4", "4.0", "commons-collections"),
                 ("XStream", "1.4.7", "xstream"), ("com.thoughtworks.xstream:xstream", "1.4.19", "xstream"),
                 ("h2", "1.4.197", "h2"), ("h2", "0.4.13", None), ("H2 Database Engine", "2.1.214", "h2"),
                 ("Apache Commons Configuration", "2.7", "commons-configuration"),
                 ("PostgreSQL JDBC Driver (pgjdbc)", "42.2.10", "pgjdbc"), ("postgresql", "42.7.2", "pgjdbc"),
                 ("postgresql", "17.11", None), ("PostgreSQL", "9.6.10", None),
                 ("org.apache.tika:tika-core", "2.9.1", "tika"), ("Apache Tika", "1.16", "tika"),
                 ("org.apache.tika:tika-langdetect-tika", "3.2.3", None),
                 ("Apache Commons FileUpload", "1.3.2", "commons-fileupload"), ("jQuery FileUpload", "9.0", None),
                 ("angular-material-fileupload", "3.0.2", None), ("redis", "6.2.6", None), ("bash", "4.2.46", None)]
        for name, version, want in cases:
            self.assertEqual(cat.match_component(name, version), want, f"{name} {version}")

        def status(cid, version):
            comp = cat.components[cid]
            return versions.check([version], comp.affected, comp.version_style)["status"]
        expected = {("zlib", "1.2.12"): "in_range", ("zlib", "1.2.13"): "outside", ("expat", "2.4.4"): "in_range",
                    ("expat", "2.4.8"): "in_range", ("expat", "2.4.9"): "outside", ("freetype", "2.13.0"): "in_range",
                    ("freetype", "2.13.1"): "outside", ("libssh", "0.5.4"): "outside", ("libssh", "0.7.3"): "in_range",
                    ("libssh", "0.8.4"): "outside", ("rsync", "3.1.3"): "outside", ("rsync", "3.3.0"): "in_range",
                    ("rsync", "3.4.0"): "outside", ("samba", "3.0.33"): "outside", ("samba", "4.2.14"): "in_range",
                    ("samba", "4.19.8"): "outside", ("dnsmasq", "2.81"): "in_range", ("dnsmasq", "2.85"): "outside",
                    ("snakeyaml", "1.33"): "in_range", ("snakeyaml", "2.0"): "outside",
                    ("jackson-databind", "2.8.9"): "in_range",        # past CVE-2017-7525, still in CVE-2020-8840
                    ("jackson-databind", "2.9.10.3"): "outside", ("jackson-databind", "2.13.4.2"): "outside",
                    ("commons-collections", "3.2.1"): "in_range", ("commons-collections", "3.2.2"): "outside",
                    ("commons-collections", "4.0"): "in_range", ("commons-collections", "4.4"): "outside",
                    ("xstream", "1.4.7"): "in_range", ("xstream", "1.4.20"): "outside", ("h2", "1.4.197"): "in_range",
                    ("h2", "2.1.214"): "outside", ("commons-configuration", "1.10"): "outside",
                    ("commons-configuration", "2.7"): "in_range", ("commons-configuration", "2.10.1"): "outside",
                    ("pgjdbc", "42.2.10"): "in_range", ("pgjdbc", "42.7.2"): "outside", ("pgjdbc", "42.4.3"): "in_range",
                    ("tika", "2.9.1"): "in_range", ("tika", "3.2.3"): "outside", ("tika", "1.12"): "outside",
                    ("commons-fileupload", "1.3.2"): "in_range", ("commons-fileupload", "1.5"): "outside"}
        for (cid, version), want in expected.items():
            self.assertEqual(status(cid, version), want, f"{cid} {version}")

    def test_second_criteria_pass(self):
        from xenolith import versions
        cat = catalog.load()
        cases = [("net-snmp", "5.8", "net-snmp"), ("net-snmp-agent-libs", "5.9.1", "net-snmp"), ("Net-SNMP Distributed MIBs", "5.8", None),
                 ("Apache Commons BeanUtils", "1.9.2", "commons-beanutils"), ("Commons BeanUtils Bean Collections", "1.8.3", None),
                 ("Groovy", "2.4.3", "groovy"), ("org.codehaus.groovy:groovy-all", "2.4.12", "groovy"), ("Groovy JSR-223", "2.4.3", None),
                 ("org.codehaus.groovy:groovy-json", "2.4.3", None), ("Spring Security", "5.6.3", "spring-security"),
                 ("spring-security-crypto", "5.6.3", None), ("spring-security-oauth2-core", "5.6.3", None),
                 ("Ghostscript", "9.26", "ghostscript"), ("ImageMagick", "6.5.5-10", "imagemagick"), ("imagemagick-dev", "1.0", None)]
        for name, version, want in cases:
            self.assertEqual(cat.match_component(name, version), want, f"{name} {version}")

        def cves(cid, version):
            comp = cat.components[cid]
            return set(versions.check([version], comp.affected, comp.version_style).get("cves") or [])
        def status(cid, version):
            comp = cat.components[cid]
            return versions.check([version], comp.affected, comp.version_style)["status"]
        expected = {("openssl", "1.0.1f"): "in_range", ("openssl", "1.0.1g"): "outside", ("openssl", "1.0.2k"): "outside",
                    ("openssl", "3.0.18"): "in_range", ("openssl", "3.0.19"): "outside", ("openssl", "3.5.5"): "outside",
                    ("tomcat", "9.0.116"): "in_range", ("tomcat", "8.0.46"): "in_range", ("tomcat", "11.0.22"): "outside",
                    ("struts2", "2.5.25"): "in_range", ("struts2", "2.5.26"): "in_range",      # 2.5.26 is still before S2-066's fix
                    ("struts2", "6.4.0"): "outside", ("apache-httpd", "2.4.59"): "in_range", ("apache-httpd", "2.4.60"): "outside",
                    ("php", "8.2.19"): "in_range", ("activemq", "6.2.2"): "in_range", ("activemq", "6.2.3"): "outside",
                    ("net-snmp", "5.9.4"): "in_range", ("net-snmp", "5.9.5"): "outside",
                    ("commons-beanutils", "1.7.0"): "in_range", ("commons-beanutils", "1.9.4"): "in_range",
                    ("commons-beanutils", "1.11.0"): "outside", ("groovy", "2.4.3"): "in_range", ("groovy", "2.4.4"): "outside",
                    ("groovy", "1.6.0"): "outside", ("spring-security", "5.6.3"): "in_range", ("spring-security", "5.6.4"): "outside",
                    ("spring-security", "6.2.8"): "outside", ("ghostscript", "9.26"): "in_range", ("ghostscript", "10.03.1"): "outside",
                    ("imagemagick", "6.5.5-10"): "in_range", ("imagemagick", "6.9.10-23"): "outside", ("imagemagick", "7.0.5.4"): "outside"}
        for (cid, version), want in expected.items():
            self.assertEqual(status(cid, version), want, f"{cid} {version}")

    def test_every_incident_is_sourced_and_ranged(self):
        cat = catalog.load()
        for comp in cat.components.values():
            for inc in comp.incidents:
                self.assertTrue(inc.get("cves"), comp.id)
                ranged = {c for a in inc.get("affected") or [] for c in a["cves"]}
                self.assertEqual(ranged, set(inc["cves"]), f"{comp.id}: {inc['name']} needs ranges for every CVE")
        self.assertIn("8u513-perf", next(i for i in cat.components["openjdk"].incidents)["note"])

    def test_second_jetbrains_correction(self):
        rules = [r for r in notices.load_corrections(ROOT / "catalog" / "notices.yaml") if r["supplier"] == "JetBrains"]
        stale = rules[1]
        for name, version in [("log4j", "1.2"), ("spring-aop", "4.0.1.RELEASE"), ("spring-context", "4.0.1.RELEASE")]:
            self.assertTrue(stale["_name"].fullmatch(name) and stale["_version"].fullmatch(version), name)
        self.assertIsNone(stale["_version"].fullmatch("6.2.11"))
        self.assertIsNone(stale["_name"].fullmatch("org.springframework:spring-core"))


if __name__ == "__main__":
    unittest.main()
