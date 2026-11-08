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


class CrosswalkReleaseTest(unittest.TestCase):
    def test_service_packs_stay_apart(self):
        links = {"redhat:jboss_data_virtualization": {"red-hat/jboss-data-virtualization-6-4-8-sp1",
                                                      "red-hat/jboss-data-virtualization-6-4-8-sp2"}}
        remap, clusters = crosswalk.build(links, {})
        self.assertEqual((remap, clusters), ({}, []))


import io as _io  # noqa: E402
import struct as _struct  # noqa: E402
import tarfile as _tarfile  # noqa: E402
import zipfile as _zipfile  # noqa: E402

from xenolith import fingerprint as fpm  # noqa: E402


def make_elf(functions: dict[str, bytes], imports=(), machine=0x3E) -> bytes:
    """Minimal little-endian ELF64 shared object that defines `functions` and imports `imports`."""
    text = b"".join(code.ljust(16, b"\x90") for code in functions.values())
    names = list(functions) + list(imports)
    dynstr, offsets = b"\x00", []
    for n in names:
        offsets.append(len(dynstr))
        dynstr += n.encode() + b"\x00"
    text_off, str_off = 0x100, 0x100 + len(text)
    sym_off = (str_off + len(dynstr) + 7) & ~7
    syms = b"\x00" * 24
    for i, n in enumerate(names):
        defined = n in functions
        syms += _struct.pack("<IBBHQQ", offsets[i], 0x12, 0, 1 if defined else 0,
                             text_off + 16 * i if defined else 0, 16 if defined else 0)
    sh_off = (sym_off + len(syms) + 7) & ~7
    total = sh_off + 64 * 4
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + _struct.pack(
        "<HHIQQQIHHHHHH", 3, machine, 1, 0, 0x40, sh_off, 0, 64, 56, 1, 64, 4, 0)
    phdr = _struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    shdrs = b"\x00" * 64
    shdrs += _struct.pack("<IIQQQQIIQQ", 0, 1, 6, text_off, text_off, len(text), 0, 0, 16, 0)
    shdrs += _struct.pack("<IIQQQQIIQQ", 0, 3, 2, str_off, str_off, len(dynstr), 0, 0, 1, 0)
    shdrs += _struct.pack("<IIQQQQIIQQ", 0, 11, 2, sym_off, sym_off, len(syms), 2, 1, 8, 24)
    out = bytearray(total)
    out[0:64] = header
    out[64:64 + 56] = phdr
    out[text_off:text_off + len(text)] = text
    out[str_off:str_off + len(dynstr)] = dynstr
    out[sym_off:sym_off + len(syms)] = syms
    out[sh_off:sh_off + len(shdrs)] = shdrs
    return bytes(out)


def jar(entries: dict[str, bytes]) -> bytes:
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        self.fps = fpm.load()

    def scan(self, files: dict[str, bytes]) -> dict[tuple[str, str], dict]:
        with tempfile.TemporaryDirectory() as d:
            for rel, data in files.items():
                p = Path(d) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            s = fpm.Scanner(self.fps)
            s.scan(Path(d))
        return {(g["component"], g["version"]): g for g in fpm.summarize(s.findings)}

    def test_version_strings(self):
        elf = b"\x7fELF" + b"\x00" * 60
        found = self.scan({
            "lib/libcrypto.so.1.1": elf + b"OpenSSL 1.1.1k  25 Mar 2021\x00OPENSSLDIR: \"/usr/lib/ssl\"\x00",
            "lib/libcurl.so.4": elf + b"libcurl/7.88.1\x00",
            "lib/libc.so.6": elf + b"GNU C Library (GNU libc) stable release version 2.36.\x00",
            "bin/php-fpm": elf + b"X-Powered-By: PHP/8.1.2\x00OpenSSL 3.0.2 15 Mar 2022\x00",   # header copy only
            "bin/sshd": elf + b"OpenSSH_9.3p1\x00/etc/ssh/sshd_config\x00",
            "bin/putty": elf + b"OpenSSH_2.3\x00",                                          # bug table, not OpenSSH
            "bin/xz": elf + b"xz (XZ Utils) 5.6.1\x00",
        })
        self.assertEqual(set(found), {("openssl", "1.1.1k"), ("curl", "7.88.1"), ("glibc", "2.36"),
                                      ("php", "8.1.2"), ("openssh", "9.3p1"), ("xz", "5.6.1")})

    def test_version_probes_and_symbols(self):
        x86 = b"\xf3\x0f\x1e\xfa\xb8" + _struct.pack("<I", 0x1000009) + b"\xc3"
        arm = b"".join(_struct.pack("<I", i) for i in (0x52800120, 0x72A02000, 0xD65F03C0))   # movz/movk/ret
        found = self.scan({
            "a/libbrotlidec.so.1": make_elf({"BrotliDecoderVersion": x86, "BrotliDecoderDecompressStream": b"\xc3"}),
            "b/libbrotlidec.so.1": make_elf({"BrotliDecoderVersion": arm}, machine=0xB7),
            "c/libwebp.so.7": make_elf({"WebPGetDecoderVersion": b"\xb8\x02\x03\x01\x00\xc3"}),
            "d/liblzma.so.5": make_elf({"lzma_version_number": b"\xb8" + _struct.pack("<I", 50060012) + b"\xc3"}),
            # a program that only imports Brotli is not a copy of it
            "e/app": make_elf({"main": b"\xc3"}, imports=["BrotliDecoderDecompressStream", "BrotliDecoderVersion"]),
            # stripped static copy: only the built-in dictionary remains
            "f/firmware.bin": b"\x7fELF" + b"\x00" * 60 + b"timedownlifeleftbackcodedatashowonlysitecityopenjustlikefreeworktextyear",
        })
        self.assertIn(("brotli", "1.0.9"), found)
        self.assertEqual(len(found[("brotli", "1.0.9")]["locations"]), 2)       # x86-64 and AArch64
        self.assertIn(("libwebp", "1.3.2"), found)
        self.assertIn(("xz", "5.6.1"), found)
        self.assertEqual(found[("brotli", "")]["locations"], ["f/firmware.bin"])
        self.assertTrue(found[("brotli", "")]["notes"])

    def test_archives(self):
        log4j = jar({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": b"groupId=org.apache.logging.log4j\nversion=2.14.1\n",
                     "org/apache/logging/log4j/core/lookup/JndiLookup.class": b"\xca\xfe\xba\xbe"})
        spring = jar({"META-INF/MANIFEST.MF": b"Implementation-Title: spring-beans\nImplementation-Version: 5.3.17\n",
                      "org/springframework/beans/BeanWrapperImpl.class": b"\xca\xfe\xba\xbe"})
        other = jar({"META-INF/MANIFEST.MF": b"Implementation-Title: other\nImplementation-Version: 9.9\n"})
        shaded = jar({"com/acme/shaded/org/apache/log4j/net/SocketNode.class": b"\xca\xfe\xba\xbe"})
        war = jar({"WEB-INF/lib/log4j-core-2.14.1.jar": log4j, "WEB-INF/lib/spring-beans-5.3.17.jar": spring,
                   "WEB-INF/lib/other.jar": other, "WEB-INF/lib/agent-all.jar": shaded})
        tgz = _io.BytesIO()
        with _tarfile.open(fileobj=tgz, mode="w:gz") as t:
            for name, data in {"opt/app/app.war": war,
                               "web/node_modules/react-server-dom-webpack/package.json": b'{"version": "19.0.0"}'}.items():
                info = _tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, _io.BytesIO(data))
        found = self.scan({"product.tgz": tgz.getvalue()})
        self.assertIn(("log4j-core", "2.14.1"), found)
        self.assertIn(("spring-framework", "5.3.17"), found)
        self.assertIn(("react-server-components", "19.0.0"), found)
        self.assertIn(("log4j-1", ""), found)                                  # shaded copy, version unknown
        self.assertNotIn(("log4j-core", ""), found)                            # same jar already gave the version
        self.assertNotIn(("spring-framework", "9.9"), found)                   # other jar's manifest

    def test_names_match_watchlist(self):
        cat = catalog.load()
        samples = {"brotli": "1.1.0", "xz": "5.4.5", "log4j-1": "1.2.17", "log4j-core": "2.14.1"}
        for fp in self.fps:
            names = {fp.name} | {s["name"] for s in fp.strings if s.get("name")}
            if fp.id == "react-server-components":
                names |= {"react-server-dom-turbopack"}
            for n in names:
                full = f"{fp.group}:{n}" if fp.group else n
                self.assertEqual(cat.match_component(full, samples.get(fp.id, "1.0.0")), fp.id, full)

    def test_findings_become_a_valid_submission(self):
        elf = b"\x7fELF" + b"\x00" * 60 + b"OpenSSL 3.0.13 30 Jan 2024\x00OPENSSLDIR: \"/x\"\x00"
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "fw").mkdir()
            (root / "fw" / "libcrypto.so.3").write_bytes(elf)
            s = fpm.Scanner(self.fps)
            s.scan(root / "fw")
            doc = fpm.to_cyclonedx(fpm.summarize(s.findings), self.fps, "fw")
            self.assertEqual(doc["components"][0]["evidence"]["occurrences"][0]["location"], "libcrypto.so.3")
            out = prepare.prepare(doc, supplier="Acme", product="Gateway", version="1.0", artifact="fw.bin",
                                  artifact_sha256="a" * 64, attest=True)
            inv, errors = community_sbom.check(out, "community/sboms/acme/gateway--1-0.cdx.json")
        self.assertEqual(errors, [])
        self.assertEqual(inv["components"], [{"name": "openssl", "version": "3.0.13"}])
        self.assertNotIn("occurrences", json.dumps(out))                       # paths stay local


class NewNoticesFormatsTest(unittest.TestCase):
    def test_netapp_component_license(self):
        text = ("Components:\nComponent\nLicense\nabab 2.0.6\nBSD 3-clause \"New\" or \"Revised\" License\n"
                "acl (access control list)\n2.2.51\nGNU Lesser General Public License v2.1 only\n"
                "ACPICA\n(BSD 3-clause \"New\" or \"Revised\" License AND Intel License)\n"
                "@babel/plugin-transform-log\nical-assignment-operators 7.25.9\nMIT License\n"
                "xen-utils-3.2-1\n4.17.5+23-ga4e5191dc0\nGNU General Public License v2.0 only\n"
                "AGPGART Driver Routines\nUnspecified\nMIT License\n\n3\nbrotli 1.0.9\nMIT License\n"
                "Licenses:\nApache License 2.0 ...\nbogus 9.9\n")
        rows = notices.ex_component_license(text)
        self.assertEqual(rows, [("abab", "2.0.6"), ("acl (access control list)", "2.2.51"), ("ACPICA", ""),
                                ("@babel/plugin-transform-logical-assignment-operators", "7.25.9"),
                                ("xen-utils-3.2-1", "4.17.5+23-ga4e5191dc0"), ("AGPGART Driver Routines", ""),
                                ("brotli", "1.0.9")])

    def test_source_archive_listing(self):
        html = ('<html><head><title>Index of /ESeries/v11.70</title></head><body><a href="?C=N;O=D">Name</a>'
                '<a href="glibc-2.19-18+deb8u10.tar.gz">x</a><a href="h2-1.4.198-sources.jar">x</a>'
                '<a href="ESeries_v11.70_1607925826596.tgz">x</a><a href="PacHelper.js">x</a>'
                '<a href="linux_distro/">x</a></body></html>').encode()
        comps, used, kind = notices.extract(html, "text/html", "https://opensource.netapp.com/x/v11.70/")
        self.assertEqual((kind, used), ("listing", ["source_archives"]))
        self.assertEqual({(c["name"], c["version"]) for c in comps}, {("glibc", "2.19-18+deb8u10"), ("h2", "1.4.198")})

    def test_extreme_formats(self):
        text = ("jedis 2.9.0: https://github.com/xetorthio/jedis MIT License\n"
                "Apache Karaf :: Shell SSH 3.0.7: http://www.apache.org/karaf/ Apache License 2.0\n"
                "Packages that use this license: (acl (access control list) 2.3.1, D-Bus\n1.14.8, OpenSSL 3.0.10)\n")
        self.assertEqual(notices.ex_url_lines(text), [("jedis", "2.9.0"), ("Apache Karaf :: Shell SSH", "3.0.7")])
        self.assertEqual(notices.ex_license_groups(text), [("acl (access control list)", "2.3.1"), ("D-Bus", "1.14.8"),
                                                           ("OpenSSL", "3.0.10")])

    def test_jar_names_and_component_json(self):
        self.assertEqual(notices.ex_jar_names("commons-lang3-3. 18.0.jar 3.18.0 strings\ncommons-text-\n1.10.0.jar"),
                         [("commons-lang3", "3.18.0"), ("commons-text", "1.10.0")])
        body = json.dumps({"components": [{"name": "log4j-core", "version": "2.17.1"}], "licenses": []}).encode()
        comps, used, kind = notices.extract(body, "application/json", "https://www.veeam.com/services/license/content?file=x")
        self.assertEqual(comps, [{"name": "log4j-core", "version": "2.17.1"}])

    def test_java_xz_is_not_xz_utils(self):
        cat = catalog.load()
        self.assertIsNone(cat.match_component("xz", "1.10"))           # org.tukaani:xz (Java)
        self.assertEqual(cat.match_component("xz", "5.2.4"), "xz")


from xenolith import wanted as wanted_mod  # noqa: E402


class WantedTest(unittest.TestCase):
    CFG = {"vendors": [{"supplier": "Acme", "blocked": "login", "detail": "Behind a login.", "where": "Admin UI > Legal",
                        "products": [
                            {"product": "Gateway", "key": "acme/gateway", "guesses": [
                                {"component": "openssl", "confidence": "likely", "basis": "TLS VPN"},
                                {"component": "openssh", "confidence": "likely", "basis": "SSH admin"},
                                {"name": "Apache Tomcat", "confidence": "named", "basis": "Install guide", "version": "9.0"}]},
                            {"product": "Console", "guesses": [{"component": "curl", "confidence": "possible", "basis": "Agent"}]}]}]}

    def test_shipped_list_is_valid(self):
        cat = catalog.load()
        cfg = wanted_mod.load(ROOT / "catalog" / "wanted.yaml")
        self.assertEqual(wanted_mod.validate(cfg, set(cat.components)), [])
        self.assertGreater(sum(len(v["products"]) for v in cfg["vendors"]), 20)

    def test_validation_errors(self):
        bad = {"vendors": [{"supplier": "X", "blocked": "nope", "products": [{"product": "Y", "guesses": [
            {"component": "not-a-component", "confidence": "sure", "basis": ""},
            {"component": "openssl", "name": "also", "confidence": "likely", "basis": "b"},
            {"component": "curl", "confidence": "named", "basis": "b"}]}]}]}
        errors = " | ".join(wanted_mod.validate(bad, {"openssl", "curl"}))
        for needle in ("blocked must be", "unknown component", "confidence must be", "basis", "exactly one of", "needs a source"):
            self.assertIn(needle, errors)

    def test_build_drops_verified_guesses_and_fulfils(self):
        names = {"openssl": "OpenSSL", "openssh": "OpenSSH", "curl": "curl"}
        out = wanted_mod.build(self.CFG, component_names=names, remap={},
                               statements={"acme/gateway": {"openssh": "fixed"}},
                               inventories={"acme/console"}, known_keys={"acme/gateway"})
        by = {e["p"]: e for e in out["entries"]}
        gw = by["Gateway"]
        self.assertEqual(gw["status"], "wanted")
        self.assertTrue(gw["linked"])
        self.assertEqual([v["c"] for v in gw["verified"]], ["openssh"])
        self.assertEqual([g["n"] for g in gw["guesses"]], ["OpenSSL", "Apache Tomcat"])   # openssh guess dropped
        self.assertEqual(by["Console"]["status"], "fulfilled")                             # a component list arrived
        self.assertEqual(by["Console"]["k"], "acme/console")
        self.assertEqual(out["counts"], {"wanted": 1, "fulfilled": 1, "guesses": 2})
        self.assertEqual(out["entries"][0]["p"], "Console")                               # fulfilled listed first

    def test_guesses_never_reach_statements(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            build.build(catalog.load(), ROOT / "data", out)
            wanted = json.loads((out / "wanted.json").read_text())
            products = json.loads((out / "products.json").read_text())
            self.assertTrue(any(p.get("w") for p in products))
            guessed = {(e["k"], g["c"]) for e in wanted["entries"] for g in e["guesses"] if g.get("c")}
            for cid in {c for _, c in guessed}:
                rows = json.loads((out / "components" / f"{cid}.json").read_text())
                keys = {r["k"] for r in (rows if isinstance(rows, list) else rows.get("rows", []))}
                self.assertFalse({k for k, c in guessed if c == cid} & keys, cid)
