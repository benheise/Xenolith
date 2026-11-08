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
        self.assertEqual(product_key("Café Systems GmbH", "Gateway OS 7.x"), "cafe-systems-gmbh/gateway-os-7-x")

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
