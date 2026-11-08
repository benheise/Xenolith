import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xenolith import build, catalog  # noqa: E402
from xenolith.model import make_assertion, product_key, verdict, write_ndjson  # noqa: E402
from xenolith.sources import community, csaf, ncsc_markdown  # noqa: E402

SCHEMA = json.loads((ROOT / "schema" / "assertion.schema.json").read_text())
STATUS_ENUM = set(SCHEMA["$defs"]["status"]["enum"])


def check_schema(t: unittest.TestCase, a: dict) -> None:
    for field in SCHEMA["required"]:
        t.assertIn(field, a)
    t.assertTrue(set(a) <= set(SCHEMA["properties"]), set(a) - set(SCHEMA["properties"]))
    t.assertIn(a["verdict"], STATUS_ENUM)
    for st in a["cves"].values():
        t.assertIn(st, STATUS_ENUM)
    t.assertIn(a["evidence"], SCHEMA["properties"]["evidence"]["enum"])
    t.assertRegex(a["product_key"], SCHEMA["properties"]["product_key"]["pattern"])


class CatalogTest(unittest.TestCase):
    def test_catalog_loads_and_cves_are_unique(self):
        cat = catalog.load()
        self.assertIn("php", cat.components)
        self.assertEqual(cat.cve_to_component["CVE-2026-111497"], "brotli")
        self.assertEqual(cat.cve_to_component["CVE-2021-4104"], "log4j-1")
        self.assertTrue(set(cat.sources) >= {"csaf", "community", "ncsc-nl-php2shell"})


class ModelTest(unittest.TestCase):
    def test_verdict_priority(self):
        self.assertEqual(verdict(["fixed", "affected"]), "affected")
        self.assertEqual(verdict(["not_affected", "fixed"]), "fixed")
        self.assertEqual(verdict([]), "unknown")

    def test_product_key(self):
        self.assertEqual(product_key("Café Systems GmbH", "Gateway OS 7.x"), "cafe-systems/gateway-os-7-x")

    def test_identity_merges_variants(self):
        same = [("Palo Alto Networks, Inc.", "PAN-OS"), ("Palo Alto", "PAN-OS Software"), ("palo alto networks", "Palo Alto Networks PAN-OS")]
        self.assertEqual({product_key(s, p) for s, p in same}, {"palo-alto-networks/pan-os"})
        self.assertEqual(product_key("Ivanti", "Pulse Connect Secure"), product_key("Ivanti", "Ivanti Connect Secure"))
        self.assertEqual(product_key("Cisco Systems, Inc.", "Cisco Adaptive Security Appliance (ASA) Software"),
                         "cisco/adaptive-security-appliance")
        self.assertEqual(product_key("Zoom", "Zoom"), "zoom/zoom")   # never strip a product down to nothing

    def test_make_assertion_rejects_bad_status(self):
        with self.assertRaises(ValueError):
            make_assertion(component="php", supplier="A", product="B", cves={"CVE-2026-109618": "broken"},
                           evidence="tracker", source="x", source_url="https://x", updated="2026-01-01")


class NcscMarkdownTest(unittest.TestCase):
    TABLE = """# List
| Supplier | Product | Version (see Status) | Status CVE-2021-4104 | Status CVE-2021-44228 | Notes | Links |
|:---------|:--------|:--------------------:|:----:|:----:|:------|------:|
|Acme|Widget Server|2.1|Not vuln|Fix|Upgrade to 2.2<br>see advisory|[source](<https://acme.example/sa-1>)|
|Acme|Widget \\| Pro||||Contact vendor||
"""

    def test_parse_and_split_by_component(self):
        cat = catalog.load()
        with tempfile.TemporaryDirectory() as d:
            sw = Path(d) / "software"
            sw.mkdir()
            (sw / "software_list_a.md").write_text(self.TABLE, encoding="utf-8")
            rows, stats = ncsc_markdown.ingest(Path(d), source_id="ncsc-nl-log4shell", repo_url="https://github.com/x/y",
                                               default_component="log4j-core", catalog=cat, as_of="2022-06-15")
        self.assertEqual(stats["rows"], 2)
        by = {(a["product"], a["component"]): a for a in rows}
        self.assertEqual(by[("Widget Server", "log4j-core")]["verdict"], "fixed")
        self.assertTrue(by[("Widget Server", "log4j-core")]["contains"])
        self.assertEqual(by[("Widget Server", "log4j-1")]["verdict"], "not_affected")
        self.assertEqual(by[("Widget Server", "log4j-core")]["references"], ["https://acme.example/sa-1"])
        self.assertEqual(by[("Widget | Pro", "log4j-core")]["verdict"], "unknown")
        for a in rows:
            check_schema(self, a)


class CsafTest(unittest.TestCase):
    DOC = {
        "document": {"publisher": {"name": "Acme PSIRT"}, "title": "Brotli in Acme products",
                     "tracking": {"current_release_date": "2026-10-30T10:00:00Z"}},
        "product_tree": {
            "branches": [{"category": "vendor", "name": "Acme", "branches": [
                {"category": "product_name", "name": "Gateway OS", "branches": [
                    {"category": "product_version", "name": "7.2.9", "product": {"product_id": "GW-729", "name": "Acme Gateway OS 7.2.9"}},
                    {"category": "product_version", "name": "7.2.10", "product": {"product_id": "GW-7210", "name": "Acme Gateway OS 7.2.10"}},
                ]},
                {"category": "product_name", "name": "Badge Reader", "product": {"product_id": "BR", "name": "Acme Badge Reader"}},
                {"category": "product_name", "name": "Console", "product": {"product_id": "CON", "name": "Acme Console"}},
            ]}],
        },
        "vulnerabilities": [
            {"cve": "CVE-2026-111497",
             "product_status": {"known_affected": ["GW-729", "CON"], "fixed": ["GW-7210"], "known_not_affected": ["BR"]},
             "remediations": [{"category": "workaround", "product_ids": ["CON"]}],
             "flags": [{"label": "component_not_present", "product_ids": ["BR"]}]},
            {"cve": "CVE-2099-0001", "product_status": {"known_affected": ["GW-729"]}},
        ],
    }

    def test_parse_advisory(self):
        cat = catalog.load()
        rows, cves = csaf.parse_advisory(self.DOC, "https://acme.example/csaf/a.json", cat.cve_to_component, "Acme")
        self.assertEqual(cves, ["CVE-2026-111497", "CVE-2099-0001"])
        by = {a["product"]: a for a in rows}
        self.assertEqual(set(by), {"Gateway OS", "Badge Reader", "Console"})
        self.assertEqual(by["Gateway OS"]["verdict"], "fixed")          # a fixed version exists
        self.assertIn("7.2.10", by["Gateway OS"]["version"])
        self.assertEqual(by["Console"]["verdict"], "workaround")
        self.assertEqual(by["Badge Reader"]["verdict"], "absent")
        self.assertIs(by["Badge Reader"]["contains"], False)
        self.assertEqual(by["Gateway OS"]["updated"], "2026-10-30")
        for a in rows:
            check_schema(self, a)

    def test_relationship_names_use_platform(self):
        doc = {"document": {"publisher": {"name": "Vendor"}, "tracking": {}},
               "product_tree": {
                   "branches": [{"category": "vendor", "name": "Vendor", "branches": [
                       {"category": "product_name", "name": "Suite 9", "product": {"product_id": "S9", "name": "Suite 9"}},
                       {"category": "product_version", "name": "brotli-1.1.0", "product": {"product_id": "B", "name": "brotli-1.1.0"}}]}],
                   "relationships": [{"category": "default_component_of", "product_reference": "B",
                                      "relates_to_product_reference": "S9",
                                      "full_product_name": {"product_id": "S9:B", "name": "Suite 9 / brotli"}}]},
               "vulnerabilities": [{"cve": "CVE-2026-111497", "product_status": {"fixed": ["S9:B"]}}]}
        cat = catalog.load()
        rows, _ = csaf.parse_advisory(doc, "https://v.example/x.json", cat.cve_to_component, "Vendor")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["product"], "Suite 9")
        self.assertIn("brotli-1.1.0", rows[0]["version"])

    def test_filename_cve(self):
        self.assertEqual(csaf._filename_cve("https://x/2026/msrc_cve-2026-111497.json"), "CVE-2026-111497")
        self.assertIsNone(csaf._filename_cve("https://x/2026/cisco-sa-php.json"))


class CommunityTest(unittest.TestCase):
    def write(self, d, body):
        p = Path(d) / "assertions.csv"
        p.write_text(",".join(community.COLUMNS) + "\n" + body, encoding="utf-8")
        return p

    def test_valid_and_invalid_rows(self):
        cat = catalog.load()
        with tempfile.TemporaryDirectory() as d:
            p = self.write(d, "brotli,Acme,Gateway OS,7.2.x,fixed,CVE-2026-111497,vendor-advisory,https://acme.example/sa,2026-10-30,\n"
                              "brotli,Acme,Badge,,present,,notices-file,https://acme.example/notices.pdf,2026-10-01,bundles 1.0.9\n"
                              "nosuch,Acme,X,,fixed,,,https://x,2026-01-01,\n"
                              "php,Acme,Y,,fixed,CVE-2026-111497,,https://x,2026-01-01,\n"
                              "php,Acme,Z,,fixed,,,http://insecure,2026-01-01,\n")
            rows, errors = community.load(p, cat)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(errors), 3)
        self.assertEqual(rows[1]["verdict"], "present")
        self.assertTrue(rows[1]["contains"])
        for a in rows:
            check_schema(self, a)

    def test_repo_csv_is_valid(self):
        rows, errors = community.load(ROOT / "community" / "assertions.csv", catalog.load())
        self.assertEqual(errors, [])


class BuildTest(unittest.TestCase):
    def test_build_outputs(self):
        cat = catalog.load()
        a1 = make_assertion(component="brotli", supplier="Acme", product="Gateway OS", cves={"CVE-2026-111497": "fixed"},
                            evidence="vendor-advisory", source="csaf", source_url="https://acme.example/a.json",
                            updated="2026-10-30", publisher="Acme PSIRT")
        a2 = dict(a1, id="0" * 16, source_url="https://acme.example/vex.json", updated="2026-10-31")
        a3 = make_assertion(component="brotli", supplier="Acme", product="Gateway OS", cves={"CVE-2026-111497": "affected"},
                            evidence="tracker", source="ncsc-nl-php2shell", source_url="https://t", updated="2026-11-01")
        with tempfile.TemporaryDirectory() as d:
            data, out = Path(d) / "data", Path(d) / "out"
            write_ndjson(data / "assertions" / "x.ndjson", [a1, a2, a3])
            write_ndjson(data / "spine" / "products.ndjson", [
                {"key": "acme/gateway-os", "supplier": "Acme", "product": "Gateway OS", "cve_count": 12, "kev_count": 1},
                {"key": "other/thing", "supplier": "Other", "product": "Thing", "cve_count": 50, "kev_count": 0},
                {"key": "small/thing", "supplier": "Small", "product": "Thing", "cve_count": 2, "kev_count": 0}])
            counts = build.build(cat, data, out, spine_min_cves=10)
            products = json.loads((out / "products.json").read_text())
            comp = json.loads((out / "components" / "brotli.json").read_text())
            meta = json.loads((out / "meta.json").read_text())
        self.assertEqual(counts["assertions"], 2)  # advisory + VEX duplicate collapsed
        by = {p["k"]: p for p in products}
        self.assertEqual(by["acme/gateway-os"]["c"]["brotli"], "fixed")  # vendor advisory outranks tracker
        self.assertEqual(by["acme/gateway-os"]["kev"], 1)
        self.assertIn("other/thing", by)
        self.assertNotIn("small/thing", by)
        csaf_row = next(r for r in comp if r["src"] == "csaf")
        self.assertEqual(csaf_row["d"], "2026-10-31")
        self.assertIn("https://acme.example/a.json", csaf_row["r"])
        self.assertTrue(any(c["id"] == "brotli" and c["contains"] == 2 for c in meta["components"]))


if __name__ == "__main__":
    unittest.main()


from xenolith.sources import notices  # noqa: E402


class NoticesExtractTest(unittest.TestCase):
    def comps(self, body, ctype="text/plain", url="https://v.example/notices.txt"):
        comps, used, kind = notices.extract(body.encode() if isinstance(body, str) else body, ctype, url)
        return {(c["name"], c["version"]) for c in comps}, used

    def test_html_table(self):
        html = """<html><body><table><tr><th>NAME</th><th>VERSION</th><th>LICENSE TYPE</th></tr>
        <tr><td>brotli</td><td>1.0.6</td><td>MIT</td></tr><tr><td>php</td><td>7.4.33</td><td>PHP</td></tr></table></body></html>"""
        got, used = self.comps(html, "text/html", "https://v.example/x.html")
        self.assertEqual(got, {("brotli", "1.0.6"), ("php", "7.4.33")})
        self.assertEqual(used, ["html_table"])

    def test_dotted_toc_skips_license_entries(self):
        text = ("Table of Contents\n7-Zip (win32) 9.20 ........................ 12\n"
                "Apache Xerces-C++ XML Parser 2.7.0 ............ 12\ncURL 7.13.1 ............ 13\n"
                "BSD 3-Clause License ............ 40\n")
        got, _ = self.comps(text)
        self.assertEqual(got, {("7-Zip (win32)", "9.20"), ("Apache Xerces-C++ XML Parser", "2.7.0"), ("cURL", "7.13.1")})

    def test_numbered_toc_needs_license_subentry(self):
        text = ("1.12 e2fsprogs 1.41.14 :30\n     1.12.1 Available under license\n"
                "1.13 HK2 Implementation Utilities 2.4.0-b31\n 1.13.1 Available under license\n"
                "1.14 openssl 1.0.2k\n 1.14.1 Notifications\n"
                "1. Redistributions of source code must retain\n")
        got, used = self.comps(text)
        self.assertEqual(got, {("e2fsprogs", "1.41.14"), ("HK2 Implementation Utilities", "2.4.0-b31"), ("openssl", "1.0.2k")})
        self.assertIn("numbered_toc", used)

    def test_gt_list_and_tpn(self):
        got, _ = self.comps("   >>> libcurl-7.56.1\n   >>> expat-2.2.0\n   >>> GNU General Public License, V2.0\n")
        self.assertEqual(got, {("libcurl", "7.56.1"), ("expat", "2.2.0")})
        got, _ = self.comps("%% brotli version 1.0.9 (https://github.com/google/brotli) NOTICES AND INFORMATION BEGIN HERE\n"
                            "%% zlib 1.2.13 NOTICES, INFORMATION, AND LICENSE BEGIN HERE\n")
        self.assertEqual(got, {("brotli", "1.0.9"), ("zlib", "1.2.13")})

    def test_prose_only_when_nothing_structured(self):
        html = "<html><body><p>This product includes OpenSSL, developed by the OpenSSL Project.</p><p>This product includes curl software, copyright Daniel.</p></body></html>"
        got, used = self.comps(html, "text/html", "https://v.example/ack.html")
        self.assertEqual(got, {("OpenSSL", ""), ("curl", "")})
        self.assertEqual(used, ["includes_prose"])

    def test_sboms(self):
        cdx = json.dumps({"bomFormat": "CycloneDX", "components": [
            {"name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1"},
            {"name": "outer", "version": "1", "components": [{"name": "brotli", "version": "1.1.0"}]}]})
        got, used = self.comps(cdx, "application/json", "https://v.example/bom.json")
        self.assertIn(("org.apache.logging.log4j:log4j-core", "2.14.1"), got)
        self.assertIn(("brotli", "1.1.0"), got)
        self.assertEqual(used, ["sbom"])
        spdx = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "php", "versionInfo": "8.3.1"}]})
        got, _ = self.comps(spdx, "application/json", "https://v.example/sbom.spdx.json")
        self.assertEqual(got, {("php", "8.3.1")})

    def test_split_name_version(self):
        self.assertEqual(notices.split_name_version("Datejs 1.0 Alpha-1"), ("Datejs", "1.0 Alpha-1"))
        self.assertEqual(notices.split_name_version("stblinux-3.3-1.3 3.3-x.x"), ("stblinux-3.3-1.3", "3.3-x.x"))
        self.assertEqual(notices.split_name_version("ethtool 3.4.1 :June 13, 2012"), ("ethtool", "3.4.1"))


class NoticesMatchTest(unittest.TestCase):
    def test_matching(self):
        cat = catalog.load()
        self.assertEqual(cat.match_component("curl-minimal", "7.61.1"), "curl")
        self.assertEqual(cat.match_component("log4j", "1.2.17"), "log4j-1")
        self.assertEqual(cat.match_component("Apache Log4j", "2.17.1"), "log4j-core")
        self.assertEqual(cat.match_component("org.apache.logging.log4j:log4j-core", "2.14.1"), "log4j-core")
        self.assertEqual(cat.match_component("libbrotlidec", ""), "brotli")
        self.assertIsNone(cat.match_component("phpseclib", ""))
        self.assertIsNone(cat.match_component("zlib", "1.2.13"))

    def test_assertions_and_inventory_build(self):
        cat = catalog.load()
        with tempfile.TemporaryDirectory() as d:
            data, out = Path(d) / "data", Path(d) / "out"
            inv = {"supplier": "Acme", "product": "Gateway OS", "version": "7.2", "url": "https://acme.example/oss.html",
                   "retrieved": "2026-11-08", "extractors": ["html_table"],
                   "components": [{"name": "php", "version": "7.4.33"}, {"name": "php-cli", "version": "7.4.33"},
                                  {"name": "zlib", "version": "1.2.11"}]}
            path = notices.inventory_path(data, inv)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(inv))
            rows, stats = notices.assertions(cat, data)
            self.assertEqual(stats["components"], 3)
            self.assertEqual(len(rows), 1)
            a = rows[0]
            self.assertEqual((a["component"], a["verdict"], a["contains"], a["evidence"]), ("php", "present", True, "notices-file"))
            self.assertEqual(a["component_version"], "7.4.33")
            check_schema(self, a)
            write_ndjson(data / "assertions" / "notices.ndjson", rows)
            build.build(cat, data, out)
            products = {p["k"]: p for p in json.loads((out / "products.json").read_text())}
            self.assertEqual(products["acme/gateway-os"]["inv"], 3)
            index = json.loads((out / "inventory_index.json").read_text())
            self.assertIn("zlib", index["n"])
            self.assertTrue((out / "inventory" / "acme__gateway-os.json").exists())



from xenolith.versions import check as range_check, version_key  # noqa: E402


class VersionRangeTest(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(version_key("2.0-beta9"), version_key("2.0"))
        self.assertLess(version_key("1.1.1"), version_key("1.1.1g"))
        self.assertLess(version_key("8.0p1"), version_key("8.5p1"))
        self.assertLess(version_key("1.0.9"), version_key("1.0.10"))
        self.assertLess(version_key("0:2.28-225.el8"), version_key("2.34"))
        self.assertIsNone(version_key("Display Manager dependent"))

    def test_catalog_ranges(self):
        cat = catalog.load()
        brotli = cat.components["brotli"].affected
        self.assertEqual(range_check(["1.0.6"], brotli)["status"], "in_range")
        self.assertEqual(range_check(["1.0.10"], brotli)["status"], "outside")
        self.assertEqual(range_check(["1.2.1"], brotli)["status"], "outside")
        self.assertEqual(range_check([""], brotli)["status"], "unknown")
        log4j = cat.components["log4j-core"].affected
        hit = range_check(["2.14.1"], log4j)
        self.assertEqual(hit["status"], "in_range")
        self.assertIn("CVE-2021-44228", hit["cves"])
        self.assertNotIn("CVE-2021-44228", range_check(["2.16.0"], log4j)["cves"])
        self.assertIn("CVE-2021-44832", range_check(["2.16.0"], log4j)["cves"])
        ssh = cat.components["openssh"].affected
        self.assertEqual(range_check(["9.7p1"], ssh)["status"], "in_range")
        self.assertEqual(range_check(["8.0p1"], ssh)["status"], "outside")
        php = cat.components["php"].affected
        self.assertEqual(range_check(["8.3.35"], php)["status"], "in_range")
        self.assertEqual(range_check(["8.3.36"], php)["status"], "outside")


from xenolith import crosswalk  # noqa: E402
from xenolith.sources import cvelist  # noqa: E402


class CrosswalkTest(unittest.TestCase):
    def test_cpe_parsing(self):
        self.assertEqual(cvelist.cpe_vendor_product("cpe:2.3:o:paloaltonetworks:pan-os:10.1.0:*:*:*:*:*:*:*"), "paloaltonetworks:pan-os")
        self.assertEqual(cvelist.cpe_vendor_product("cpe:/a:redhat:ansible_automation_platform:2.4::el8"), "redhat:ansible_automation_platform")
        self.assertIsNone(cvelist.cpe_vendor_product("cpe:2.3:a:*:*:*"))
        self.assertEqual(crosswalk.normalize_cpe("Microsoft:Windows_10"), "microsoft:windows_10")

    def test_adp_assignment(self):
        got = cvelist.assign_adp_cpes(["Firefox", "Firefox ESR"], ["cpe:2.3:a:mozilla:firefox:*", "cpe:2.3:a:mozilla:firefox_esr:*"])
        self.assertEqual(got, {0: ["mozilla:firefox"], 1: ["mozilla:firefox_esr"]})
        self.assertEqual(cvelist.assign_adp_cpes(["Chrome"], ["cpe:2.3:o:fedoraproject:fedora:38"]), {})

    def test_links_and_guards(self):
        links = {
            "microsoft:windows_server_2016": {"microsoft/windows-server-2016", "microsoft/windows-server-2016-server-core-installation"},
            "microsoft:excel": {"microsoft/excel-2010", "microsoft/excel-2016"},
            "acme:gateway_os": {"acme/gateway-os", "other-vendor/gateway-os"},
            "acme:everything": {f"acme/product-{i}" for i in range(8)},
            "ibm:mq_appliance": {"ibm/mq", "ibm/mq-appliance"},
        }
        remap, clusters = crosswalk.build(links, {"microsoft/windows-server-2016": 10})
        self.assertEqual(remap, {"microsoft/windows-server-2016-server-core-installation": "microsoft/windows-server-2016"})
        self.assertEqual(len(clusters), 1)

    def test_csaf_cpe_capture(self):
        doc = {"document": {"publisher": {"name": "Acme"}, "tracking": {}},
               "product_tree": {"branches": [{"category": "vendor", "name": "Acme", "branches": [
                   {"category": "product_name", "name": "Gateway OS", "product": {
                       "product_id": "GW", "name": "Gateway OS",
                       "product_identification_helper": {"cpe": "cpe:2.3:o:acme:gateway_os:7.2:*:*:*:*:*:*:*"}}}]}]},
               "vulnerabilities": [{"cve": "CVE-2026-111497", "product_status": {"known_affected": ["GW"]}}]}
        rows, _ = csaf.parse_advisory(doc, "https://acme.example/a.json", catalog.load().cve_to_component, "Acme")
        self.assertEqual(rows[0]["cpes"], ["acme:gateway_os"])
        check_schema(self, rows[0])


from xenolith.sources import community_sbom  # noqa: E402


class CommunitySbomTest(unittest.TestCase):
    EXAMPLE = ROOT / "community" / "examples" / "example-binary-scan.cdx.json"

    def test_example_is_valid_and_becomes_statements(self):
        cat = catalog.load()
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            target = repo / "community" / "sboms" / "example-networks" / "gateway.cdx.json"
            target.parent.mkdir(parents=True)
            target.write_text(self.EXAMPLE.read_text())
            invs, errors = community_sbom.load_all(repo)
            self.assertEqual(errors, [])
            self.assertEqual(invs[0]["evidence"], "binary-scan")
            community_sbom.write_inventories(invs, repo / "data")
            rows, _ = notices.assertions(cat, repo / "data")
        by = {a["component"]: a for a in rows}
        self.assertEqual(set(by), {"brotli", "openssl", "php"})
        self.assertEqual(by["brotli"]["evidence"], "binary-scan")
        self.assertEqual(by["brotli"]["component_version"], "1.0.9")
        for a in rows:
            check_schema(self, a)

    def test_missing_fields_are_reported(self):
        bom = json.loads(self.EXAMPLE.read_text())
        bom["metadata"]["properties"] = [p for p in bom["metadata"]["properties"] if p["name"] != "xenolith:attestation"]
        del bom["metadata"]["component"]["version"]
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            target = repo / "community" / "sboms" / "x.cdx.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(bom))
            invs, errors = community_sbom.load_all(repo)
        self.assertEqual(invs, [])
        self.assertTrue(any("attestation" in e for e in errors))
        self.assertTrue(any("metadata.component.version" in e for e in errors))


from xenolith import prepare  # noqa: E402


class PrepareTest(unittest.TestCase):
    SYFT = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"timestamp": "2026-11-01T00:00:00Z",
                     "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.33.0"}]},
                     "component": {"type": "file", "name": "/home/alice/work/acme-fw_extract"}},
        "components": [
            {"type": "library", "name": "brotli", "version": "1.0.9", "purl": "pkg:generic/brotli@1.0.9",
             "properties": [{"name": "syft:package:foundBy", "value": "binary-classifier-cataloger"},
                            {"name": "syft:location:0:path", "value": "/home/alice/work/acme-fw_extract/usr/lib/libbrotlidec.so.1"}]},
            {"type": "library", "name": "openssl", "version": "3.0.13",
             "cpe": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
             "components": [{"type": "library", "name": "zlib", "version": "1.2.13"}]},
            {"type": "library", "name": "brotli", "version": "1.0.9", "purl": "pkg:generic/brotli@1.0.9"},
            {"type": "file", "name": "/home/alice/work/acme-fw_extract/etc/passwd"},
        ],
    }
    SPDX = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": ["Organization: Anchore, Inc", "Tool: syft-1.33.0"]},
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "/scan/root"},
            {"SPDXID": "SPDXRef-php", "name": "php", "versionInfo": "8.2.20",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/php@8.2.20"}]},
        ],
    }

    def _run(self, scan, attest=True, **kw):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "scan.json").write_text(json.dumps(scan))
            fw = root / "acme-fw-7.2.9.bin"
            fw.write_bytes(b"firmware")
            args = type("A", (), dict(scan=str(root / "scan.json"), supplier="Acme Networks", product="Acme Gateway OS",
                                      version="7.2.9", artifact=str(fw), artifact_sha256=None, evidence="binary-scan",
                                      source_url=None, product_type="firmware", attest=attest, output=None, **kw))
            code = prepare.run(args, root, catalog.load())
            out = root / "community" / "sboms" / "acme-networks" / "acme-gateway-os--7-2-9.cdx.json"
            doc = json.loads(out.read_text())
            invs, errors = community_sbom.load_all(root)
        return code, doc, invs, errors

    def test_syft_output_becomes_valid_submission(self):
        code, doc, invs, errors = self._run(self.SYFT)
        self.assertEqual((code, errors), (0, []))
        text = json.dumps(doc)
        self.assertNotIn("/home/alice", text)                 # no host paths survive
        self.assertNotIn("passwd", text)                      # file entries dropped
        names = [(c["name"], c.get("version")) for c in doc["components"]]
        self.assertEqual(names, [("brotli", "1.0.9"), ("openssl", "3.0.13"), ("zlib", "1.2.13")])
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        self.assertEqual(props["xenolith:artifact"], "acme-fw-7.2.9.bin")
        self.assertEqual(props["xenolith:artifact_sha256"], prepare.hashlib.sha256(b"firmware").hexdigest())
        self.assertEqual([t["name"] for t in doc["metadata"]["tools"]["components"]], ["syft", "xenolith prepare"])
        self.assertEqual(invs[0]["product"], "Acme Gateway OS")

    def test_without_attest_is_not_ready(self):
        code, doc, invs, errors = self._run(self.SYFT, attest=False)
        self.assertEqual(code, 1)
        self.assertTrue(any("attestation" in e for e in errors))

    def test_spdx_input(self):
        code, doc, _, errors = self._run(self.SPDX)
        self.assertEqual((code, errors), (0, []))
        self.assertEqual([c["name"] for c in doc["components"]], ["php"])
        self.assertEqual(doc["metadata"]["tools"]["components"][0], {"type": "application", "name": "syft", "version": "1.33.0"})
