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


if __name__ == "__main__":
    unittest.main()
