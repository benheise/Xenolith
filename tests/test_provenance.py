"""Provenance: how each record reached the census (found_via), the pages that led to its
source (discovery_path) and the hash of the bytes it was read from (sha256)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xenolith import build, catalog  # noqa: E402
from xenolith.model import FOUND_VIA, make_assertion, provenance, stamp, write_ndjson  # noqa: E402
from xenolith.sources import notices  # noqa: E402

SCHEMA = json.loads((ROOT / "schema" / "assertion.schema.json").read_text())
SHA = "ab" * 32


def is_https(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "https" and bool(u.netloc)


class ProvenanceModelTest(unittest.TestCase):
    def test_validates_and_normalises(self):
        p = provenance("hand-listed", ["https://a/", "https://a/", "", "https://b/"], SHA.upper())
        self.assertEqual(p, {"found_via": "hand-listed", "discovery_path": ["https://a/", "https://b/"], "sha256": SHA})
        self.assertEqual(provenance(), {})
        self.assertEqual(len(provenance("auto-discovered", [f"https://x/{i}" for i in range(10)])["discovery_path"]), 6)

    def test_rejects_unknown_tag_and_bad_hash(self):
        with self.assertRaises(ValueError):
            provenance("scraped")
        with self.assertRaises(ValueError):
            provenance("community", sha256="abc")

    def test_stamp_replaces_path_but_keeps_hash_unless_given(self):
        rec = {"found_via": "hand-listed", "discovery_path": ["https://old/"], "sha256": SHA}
        stamp(rec, "auto-discovered", ["https://new/"])
        self.assertEqual(rec, {"found_via": "auto-discovered", "discovery_path": ["https://new/"], "sha256": SHA})
        stamp(rec, "auto-discovered", [], "cd" * 32)
        self.assertEqual(rec["sha256"], "cd" * 32)
        self.assertNotIn("discovery_path", rec)

    def test_assertion_carries_provenance_in_schema(self):
        a = make_assertion(component="brotli", supplier="Acme", product="Gateway OS", cves={"CVE-2026-111497": "affected"},
                           evidence="notices-file", source="notices", source_url="https://acme.example/notices.pdf",
                           updated="2026-11-08", found_via="hand-listed",
                           discovery_path=["https://acme.example/support"], sha256=SHA)
        self.assertTrue(set(a) <= set(SCHEMA["properties"]))
        self.assertIn(a["found_via"], SCHEMA["properties"]["found_via"]["enum"])
        self.assertEqual(set(SCHEMA["properties"]["found_via"]["enum"]), set(FOUND_VIA))
        self.assertRegex(a["sha256"], SCHEMA["properties"]["sha256"]["pattern"])
        self.assertEqual(a["discovery_path"], ["https://acme.example/support"])


class NoticesProvenanceTest(unittest.TestCase):
    CFG = {
        "documents": [
            {"supplier": "Acme", "product": "Gateway", "url": "https://acme.example/n.pdf",
             "found_at": "https://acme.example/docs"},
            {"supplier": "Acme", "product": "Router", "url": "https://acme.example/r.pdf",
             "found_at": ["https://acme.example/", "https://acme.example/legal"]},
            {"supplier": "Acme", "product": "Old", "url": "https://acme.example/o.pdf"},
        ],
        "discover": [
            {"type": "autoindex", "supplier": "Acme", "index": "https://dl.acme.example/notices",
             "products": {"gw/": "Gateway"}},
        ],
    }

    def test_hand_listed_single_page_trail_and_missing(self):
        docs = self.CFG["documents"]
        self.assertEqual(notices.doc_provenance(docs[0]),
                         {"found_via": "hand-listed", "discovery_path": ["https://acme.example/docs"]})
        self.assertEqual(notices.doc_provenance(docs[1])["discovery_path"],
                         ["https://acme.example/", "https://acme.example/legal"])
        self.assertEqual(notices.doc_provenance(docs[2]), {"found_via": "hand-listed", "discovery_path": []})

    def test_discovered_path_starts_at_rule(self):
        rule = self.CFG["discover"][0]
        p = notices.doc_provenance({"discovered_by": "https://dl.acme.example/notices/gw/"}, rule)
        self.assertEqual(p, {"found_via": "auto-discovered",
                             "discovery_path": ["https://dl.acme.example/notices", "https://dl.acme.example/notices/gw/"]})

    def test_infer_offline(self):
        self.assertEqual(notices.infer_provenance("https://acme.example/n.pdf", "Acme", self.CFG)["discovery_path"],
                         ["https://acme.example/docs"])
        p = notices.infer_provenance("https://dl.acme.example/notices/gw/7.2.txt", "Acme", self.CFG)
        self.assertEqual(p["found_via"], "auto-discovered")
        self.assertEqual(p["discovery_path"][-1], "https://dl.acme.example/notices/gw/")

    def test_stamp_inventories_writes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            reg, data = Path(d) / "notices.yaml", Path(d) / "data"
            reg.write_text(yaml.safe_dump(self.CFG))
            inv = data / "notices" / "acme" / "gateway.json"
            inv.parent.mkdir(parents=True)
            inv.write_text(json.dumps({"supplier": "Acme", "product": "Gateway", "url": "https://acme.example/n.pdf",
                                       "sha256": SHA, "components": []}))
            self.assertEqual(notices.stamp_inventories(reg, data, log=lambda *_: None), 1)
            stored = json.loads(inv.read_text())
            self.assertEqual(stored["found_via"], "hand-listed")
            self.assertEqual(stored["discovery_path"], ["https://acme.example/docs"])
            self.assertEqual(stored["sha256"], SHA)
            self.assertEqual(notices.stamp_inventories(reg, data, log=lambda *_: None), 0)


class BuildProvenanceTest(unittest.TestCase):
    def test_rows_omit_source_default_and_keep_hash(self):
        cat = catalog.load()
        common = dict(component="brotli", supplier="Acme", cves={"CVE-2026-111497": "affected"},
                      evidence="tracker", source="ncsc-nl-php2shell", updated="2026-11-01",
                      found_via="hand-listed", discovery_path=["https://github.com/NCSC-NL/x"])
        rows = [make_assertion(product=f"P{i}", source_url=f"https://t/{i}", **common) for i in range(3)]
        odd = make_assertion(product="Odd", source_url="https://t/odd", sha256=SHA,
                             **dict(common, discovery_path=["https://elsewhere.example/"]))
        with tempfile.TemporaryDirectory() as d:
            data, out = Path(d) / "data", Path(d) / "out"
            write_ndjson(data / "assertions" / "x.ndjson", rows + [odd])
            build.build(cat, data, out)
            comp = json.loads((out / "components" / "brotli.json").read_text())
            meta = json.loads((out / "meta.json").read_text())
        src = next(s for s in meta["sources"] if s["id"] == "ncsc-nl-php2shell")
        self.assertEqual((src["fv"], src["dp"]), ("hand-listed", ["https://github.com/NCSC-NL/x"]))
        by = {r["p"]: r for r in comp}
        self.assertNotIn("fv", by["P0"])
        self.assertEqual(by["Odd"]["dp"], ["https://elsewhere.example/"])
        self.assertEqual(by["Odd"]["h"], SHA)


class CatalogDiscoveryUrlsTest(unittest.TestCase):
    """Every recorded discovery page is an https URL, in the notices catalog and the scanner corpus."""

    def test_notices_found_at(self):
        cfg = yaml.safe_load((ROOT / "catalog" / "notices.yaml").read_text(encoding="utf-8"))
        for d in cfg.get("documents") or []:
            fa = d.get("found_at")
            for page in ([fa] if isinstance(fa, str) else fa or []):
                self.assertTrue(is_https(page), f"{d['product']}: found_at {page!r}")
                self.assertNotEqual(page, d["url"], f"{d['product']}: found_at is the document itself")

    def test_corpus_found_at(self):
        corpus = yaml.safe_load((ROOT / "scan" / "corpus" / "manifest.yaml").read_text(encoding="utf-8"))
        for c in corpus["artifacts"]:
            self.assertTrue(is_https(c.get("found_at", "")), f"{c['product']} {c['version']}: found_at missing")
            self.assertNotEqual(c["found_at"], c["artifact"])


if __name__ == "__main__":
    unittest.main()
