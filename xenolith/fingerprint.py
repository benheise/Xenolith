"""Find watchlist components in a product: python -m xenolith fingerprint <file or folder>.

A small reference scanner for catalog/fingerprints.yaml. It looks through an
extracted firmware tree, an installation folder, or an archive (zip, jar, war,
ear, apk, tar, tgz) and reports the watchlist components it finds, with
versions where the evidence carries one:

  * version strings in ELF, PE and Mach-O files ("OpenSSL 3.0.13 30 Jan 2024")
  * ELF symbols the file defines (not just imports), and the constant returned by
    version functions such as BrotliDecoderVersion (x86-64 and AArch64)
  * static data only the component contains (Brotli's built-in dictionary)
  * package metadata and class files inside archives, nested to any depth

The output is CycloneDX JSON that `python -m xenolith prepare` turns into a
submission. Nothing is executed, mounted or sent anywhere. It complements a
general scanner such as Syft, which covers package databases and language
ecosystems far more broadly; this one is tuned to the watchlist, including
copies that are statically linked or vendored without metadata.
"""

from __future__ import annotations

import io
import json
import mmap
import os
import re
import struct
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

FINGERPRINTS = Path(__file__).resolve().parent.parent / "catalog" / "fingerprints.yaml"
TOOL_VERSION = "1"
MAX_MEMBER_BYTES = 256 * 1024 * 1024        # archive members read into memory
MAX_DEPTH = 6                               # archives inside archives
ZIP_EXT = (".jar", ".war", ".ear", ".zip", ".apk", ".aar", ".hpi", ".jpi", ".nupkg", ".whl", ".sar", ".par")
TAR_EXT = (".tar", ".tgz", ".tar.gz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".ova")
EXEC_MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
              b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
NOT_BINARY = (".class", ".properties", ".xml", ".html", ".htm", ".js", ".mjs", ".css", ".txt", ".md", ".json",
              ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".mf", ".sf", ".rsa", ".dsa", ".yml", ".yaml")


# ----------------------------------------------------------------- fingerprints

@dataclass
class Fingerprint:
    id: str
    name: str
    group: str = ""
    purl: str = ""
    strings: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    markers: list = field(default_factory=list)
    paths: list = field(default_factory=list)


def load(path: Path = FINGERPRINTS) -> list[Fingerprint]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for cid, spec in (cfg.get("components") or {}).items():
        fp = Fingerprint(id=cid, name=spec["name"], group=spec.get("group", ""), purl=spec.get("purl", ""))
        for s in spec.get("strings") or []:
            fp.strings.append({**s, "contains": s["contains"].encode(), "regex": re.compile(s["regex"].encode()),
                               "requires_any": [r.encode() for r in s.get("requires_any") or []]})
        fp.symbols = [s.encode() for s in spec.get("symbols") or []]
        fp.probes = list(spec.get("probes") or [])
        fp.markers = [{**m, "bytes": m["bytes"].encode()} for m in spec.get("markers") or []]
        fp.paths = [{**p, "regex": re.compile(p["regex"])} for p in spec.get("paths") or []]
        out.append(fp)
    return out


@dataclass
class Finding:
    component: str
    name: str
    group: str
    version: str
    technique: str          # CycloneDX evidence technique
    confidence: float
    location: str
    evidence: str = ""
    note: str = ""


# ----------------------------------------------------------------- ELF symbols and version probes

class Elf:
    """Just enough ELF to list defined symbols and read code at a symbol's address."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        self.bits = 64 if data[4] == 2 else 32
        self.end = "<" if data[5] == 1 else ">"
        e = self.end
        if self.bits == 64:
            self.machine = struct.unpack_from(e + "H", data, 18)[0]
            phoff, shoff = struct.unpack_from(e + "QQ", data, 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 54)
        else:
            self.machine = struct.unpack_from(e + "H", data, 18)[0]
            phoff, shoff = struct.unpack_from(e + "II", data, 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 42)
        self.segments = []
        for i in range(min(phnum, 256)):
            off = phoff + i * phentsize
            if self.bits == 64:
                ptype, _, poff, vaddr, _, filesz = struct.unpack_from(e + "IIQQQQ", data, off)
            else:
                ptype, poff, vaddr, _, filesz = struct.unpack_from(e + "IIIII", data, off)
            if ptype == 1:                          # PT_LOAD
                self.segments.append((vaddr, filesz, poff))
        self.sections = []
        for i in range(min(shnum, 4096)):
            off = shoff + i * shentsize
            if off + shentsize > len(data):
                break
            if self.bits == 64:
                _, stype, _, _, soff, size, link, _, _, entsize = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
            else:
                _, stype, _, _, soff, size, link, _, _, entsize = struct.unpack_from(e + "IIIIIIIIII", data, off)
            self.sections.append((stype, soff, size, link, entsize))

    def defined_symbols(self, wanted: set[bytes]) -> dict[bytes, int]:
        """{name: address} for wanted names that this file defines (dynsym and symtab)."""
        found: dict[bytes, int] = {}
        e = self.end
        for stype, soff, size, link, entsize in self.sections:
            if stype not in (2, 11) or not entsize or link >= len(self.sections):   # SYMTAB, DYNSYM
                continue
            str_off = self.sections[link][1]
            for j in range(min(size // entsize, 2_000_000)):
                off = soff + j * entsize
                if self.bits == 64:
                    name, info, _, shndx, value = struct.unpack_from(e + "IBBHQ", self.data, off)
                else:
                    name, value, _, info, _, shndx = struct.unpack_from(e + "IIIBBH", self.data, off)
                if shndx == 0 or (info & 0xF) != 2:   # undefined, or not a function
                    continue
                start = str_off + name
                end = self.data.find(b"\x00", start, start + 256)
                sym = self.data[start:end]
                if sym in wanted:
                    found[sym] = value
            if len(found) == len(wanted):
                break
        return found

    def read_at(self, vaddr: int, n: int = 32) -> bytes:
        for seg_vaddr, filesz, poff in self.segments:
            if seg_vaddr <= vaddr < seg_vaddr + filesz:
                off = poff + (vaddr - seg_vaddr)
                return bytes(self.data[off:off + n])
        return b""


def returned_constant(elf: Elf, vaddr: int) -> int | None:
    """The immediate a tiny 'return CONSTANT;' function returns (x86/x86-64, AArch64)."""
    code = elf.read_at(vaddr & ~1)
    if not code:
        return None
    if elf.machine in (0x3E, 0x03):                 # x86-64, i386
        if code[:4] in (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb"):   # endbr64/endbr32
            code = code[4:]
        if code[:1] == b"\xb8" and code[5:6] == b"\xc3":             # mov eax, imm32; ret
            return struct.unpack_from("<I", code, 1)[0]
        return None
    if elf.machine == 0xB7:                         # AArch64
        value, seen = 0, False
        for i in range(0, len(code) - 3, 4):
            ins = struct.unpack_from("<I", code, i)[0]
            if ins in (0xD503201F, 0xD503233F, 0xD503245F, 0xD503241F):   # nop, paciasp, bti
                continue
            if ins == 0xD65F03C0:                   # ret
                return value if seen else None
            hw, imm, rd = (ins >> 21) & 3, (ins >> 5) & 0xFFFF, ins & 0x1F
            if rd != 0:
                return None
            if ins & 0x7F800000 == 0x52800000:      # movz w0/x0
                value, seen = imm << (16 * hw), True
            elif ins & 0x7F800000 == 0x72800000 and seen:   # movk
                value = (value & ~(0xFFFF << (16 * hw))) | (imm << (16 * hw))
            else:
                return None
    return None


DECODERS = {
    "brotli_hex": lambda v: f"{v >> 24}.{(v >> 12) & 0xFFF}.{v & 0xFFF}",
    "webp_hex": lambda v: f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}",
    "lzma_number": lambda v: f"{v // 10000000}.{(v // 10000) % 1000}.{(v // 10) % 1000}",
}


# ----------------------------------------------------------------- scanner

class Scanner:
    def __init__(self, fingerprints: list[Fingerprint], log=None):
        self.fps = fingerprints
        self.findings: list[Finding] = []
        self.skipped: list[str] = []
        self.log = log or (lambda *_: None)
        self.wanted_symbols = {s for fp in self.fps for s in fp.symbols} | \
                              {p["symbol"].encode() for fp in self.fps for p in fp.probes}

    # -- entry points
    def scan(self, root: Path) -> list[Finding]:
        root = Path(root)
        if root.is_file():
            self._file(root, root.name)
        else:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames.sort()
                for fn in sorted(filenames):
                    p = Path(dirpath) / fn
                    if p.is_symlink() or not p.is_file():
                        continue
                    self._file(p, p.relative_to(root).as_posix())
        return self.findings

    def _file(self, path: Path, rel: str):
        try:
            size = path.stat().st_size
            if size == 0:
                return
            with path.open("rb") as f:
                head = f.read(8)
                self._paths(rel, lambda: path.read_bytes() if size < 4 * 1024 * 1024 else b"")
                if head[:4] == b"PK\x03\x04" or rel.lower().endswith(ZIP_EXT):
                    if zipfile.is_zipfile(path):
                        with zipfile.ZipFile(path) as z:
                            self._zip(z, rel, 1)
                        return
                if rel.lower().endswith(TAR_EXT) and tarfile.is_tarfile(path):
                    with tarfile.open(path, "r:*") as t:
                        self._tar(t, rel, 1)
                    return
                if head.startswith(EXEC_MAGIC) and not rel.lower().endswith(NOT_BINARY):
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        self._binary(mm, rel)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, EOFError) as e:
            self.skipped.append(f"{rel}: {e}")

    # -- archives
    def _member(self, rel: str, data: bytes, depth: int):
        if data[:4] == b"PK\x03\x04":
            if depth > MAX_DEPTH:
                self.skipped.append(f"{rel}: nested deeper than {MAX_DEPTH} archives")
                return
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    self._zip(z, rel, depth + 1)
            except zipfile.BadZipFile as e:
                self.skipped.append(f"{rel}: {e}")
        elif data.startswith(EXEC_MAGIC) and not rel.lower().endswith(NOT_BINARY):
            self._binary(data, rel)

    def _zip(self, z: zipfile.ZipFile, base: str, depth: int):
        for info in z.infolist():
            if info.is_dir():
                continue
            rel = f"{base}!/{info.filename}"
            self._paths(rel, lambda info=info: z.read(info) if info.file_size < 4 * 1024 * 1024 else b"")
            if info.filename.lower().endswith(NOT_BINARY):
                continue
            with z.open(info) as fh:
                head = fh.read(4)
            if head == b"PK\x03\x04" or head.startswith(EXEC_MAGIC):
                if info.file_size > MAX_MEMBER_BYTES:
                    self.skipped.append(f"{rel}: larger than {MAX_MEMBER_BYTES >> 20} MB")
                    continue
                self._member(rel, z.read(info), depth)

    def _tar(self, t: tarfile.TarFile, base: str, depth: int):
        for m in t:
            if not m.isfile() or m.size == 0:
                continue
            rel = f"{base}!/{m.name.lstrip('./')}"
            name = m.name.rsplit("/", 1)[-1]
            small = m.size < 4 * 1024 * 1024
            data = None
            if self._wants_path(rel) and small:
                data = t.extractfile(m).read()
                self._paths(rel, lambda d=data: d)
            if m.size > MAX_MEMBER_BYTES:
                self.skipped.append(f"{rel}: larger than {MAX_MEMBER_BYTES >> 20} MB")
                continue
            f = t.extractfile(m)
            head = f.read(4) if data is None else data[:4]
            if head == b"PK\x03\x04" or head.startswith(EXEC_MAGIC) or name.lower().endswith(ZIP_EXT):
                data = data if data is not None else head + f.read()
                self._member(rel, data, depth)

    # -- path rules (package metadata, class files, file names)
    def _wants_path(self, rel: str) -> bool:
        return any(p["regex"].search(rel) for fp in self.fps for p in fp.paths)

    def _paths(self, rel: str, read):
        content = None
        for fp in self.fps:
            for rule in fp.paths:
                m = rule["regex"].search(rel)
                if not m:
                    continue
                version, how = m.groupdict().get("v") or "", rule.get("version")
                if how in ("pom", "manifest", "package_json"):
                    if content is None:
                        content = read() or b""
                    version = _metadata_version(how, content, rule)
                    if version is None:         # manifest of some other jar
                        continue
                name = m.groupdict().get("name") or fp.name
                technique = "manifest-analysis" if how else ("filename" if m.groupdict().get("v") else "binary-analysis")
                self._add(fp, version, technique, float(rule.get("confidence", 0.6)), rel,
                          evidence=rel.rsplit("/", 1)[-1], note=rule.get("note", ""), name=name)

    # -- executables and libraries
    def _binary(self, data, rel: str):
        for fp in self.fps:
            for s in fp.strings:
                if data.find(s["contains"]) < 0:
                    continue
                if s["requires_any"] and not any(data.find(r) >= 0 for r in s["requires_any"]):
                    continue
                for m in s["regex"].finditer(data):
                    v = m.group("v").decode("ascii", "replace")
                    self._add(fp, v, "binary-analysis", 0.9, rel, evidence=m.group(0).decode("ascii", "replace"),
                              name=s.get("name") or fp.name)
                    break
            for mk in fp.markers:
                if data.find(mk["bytes"]) >= 0:
                    self._add(fp, "", "binary-analysis", 0.6, rel, evidence="static data marker", note=mk.get("note", ""))
        if data[:4] == b"\x7fELF" and self.wanted_symbols and any(data.find(s) >= 0 for s in self.wanted_symbols):
            try:
                elf = Elf(data)
                defined = elf.defined_symbols(self.wanted_symbols)
            except (ValueError, struct.error) as e:
                self.skipped.append(f"{rel}: ELF parse: {e}")
                return
            for fp in self.fps:
                version = ""
                for probe in fp.probes:
                    addr = defined.get(probe["symbol"].encode())
                    value = returned_constant(elf, addr) if addr else None
                    if value:
                        v = DECODERS[probe["decode"]](value)
                        if re.fullmatch(r"\d{1,2}\.\d{1,4}\.\d{1,4}", v):
                            version = v
                            self._add(fp, v, "binary-analysis", 0.8, rel, evidence=f"{probe['symbol']}() returns {value:#x}")
                            break
                if fp.symbols and not version and all(s in defined for s in fp.symbols):
                    self._add(fp, "", "binary-analysis", 0.7, rel, evidence="defines " + ", ".join(s.decode() for s in fp.symbols))

    def _add(self, fp: Fingerprint, version: str, technique: str, confidence: float, rel: str,
             evidence: str = "", note: str = "", name: str = ""):
        self.findings.append(Finding(fp.id, name or fp.name, fp.group, version.strip(), technique,
                                     confidence, rel, evidence[:200], note))


def _metadata_version(how: str, content: bytes, rule: dict) -> str | None:
    text = content.decode("utf-8", "replace")
    if how == "pom":
        m = re.search(r"(?m)^version\s*[=:]\s*(\S+)", text)
        return m.group(1) if m else ""
    if how == "manifest":
        fields = dict(re.findall(r"(?m)^([\w-]+):\s*(.+?)\s*$", text))
        if rule.get("manifest_title") and not re.search(rule["manifest_title"], fields.get("Implementation-Title", "")):
            return None
        return fields.get("Implementation-Version") or fields.get("Bundle-Version") or ""
    if how == "package_json":
        try:
            return str(json.loads(text).get("version") or "")
        except (json.JSONDecodeError, AttributeError):
            return ""
    return ""


# ----------------------------------------------------------------- results

def summarize(findings: list[Finding]) -> list[dict]:
    """One entry per (component, name, version); unversioned presence is dropped when the
    same container already gave a version for that component."""
    def container(loc: str) -> str:
        # the archive a finding came from, or the folder of a file on disk
        return loc.rsplit("!/", 1)[0] if "!/" in loc else loc.rsplit("/", 1)[0] if "/" in loc else ""

    versioned = {(f.component, container(f.location)) for f in findings if f.version}
    groups: dict[tuple, dict] = {}
    for f in findings:
        if not f.version and (f.component, container(f.location)) in versioned:
            continue
        key = (f.component, f.group, f.name, f.version)
        g = groups.setdefault(key, {"component": f.component, "group": f.group, "name": f.name,
                                    "version": f.version, "confidence": 0.0, "techniques": set(),
                                    "locations": [], "evidence": [], "notes": set()})
        g["confidence"] = max(g["confidence"], f.confidence)
        g["techniques"].add(f.technique)
        if f.location not in g["locations"]:
            g["locations"].append(f.location)
        if f.evidence and f.evidence not in g["evidence"]:
            g["evidence"].append(f.evidence)
        if f.note:
            g["notes"].add(f.note)
    return sorted(groups.values(), key=lambda g: (g["component"], g["version"]))


def to_cyclonedx(summary: list[dict], fingerprints: list[Fingerprint], target: str) -> dict:
    purls = {fp.id: fp.purl for fp in fingerprints}
    comps = []
    for i, g in enumerate(summary):
        c = {"type": "library", "bom-ref": f"f{i + 1}", "name": g["name"]}
        if g["group"]:
            c["group"] = g["group"]
        if g["version"]:
            c["version"] = g["version"]
            if purls.get(g["component"]):
                purl = purls[g["component"]].replace("{version}", g["version"])
                c["purl"] = purl.replace("react-server-dom-webpack", g["name"]) if g["component"] == "react-server-components" else purl
        c["evidence"] = {
            "identity": [{"field": "name", "confidence": round(g["confidence"], 2),
                          "methods": [{"technique": t, "confidence": round(g["confidence"], 2)} for t in sorted(g["techniques"])]}],
            "occurrences": [{"location": loc} for loc in g["locations"][:50]],
        }
        c["properties"] = [{"name": "xenolith:component", "value": g["component"]},
                           {"name": "xenolith:found_by", "value": "xenolith-fingerprint"},
                           {"name": "xenolith:confidence", "value": f"{g['confidence']:.2f}"}]
        if g["notes"]:
            c["properties"].append({"name": "xenolith:note", "value": "; ".join(sorted(g["notes"]))})
        comps.append(c)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "xenolith-fingerprint", "version": TOOL_VERSION}]},
            "component": {"type": "file", "name": target},
        },
        "components": comps,
    }


def run(args) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: {target} not found")
        return 2
    fps = load(Path(args.fingerprints) if args.fingerprints else FINGERPRINTS)
    scanner = Scanner(fps)
    scanner.scan(target)
    summary = summarize(scanner.findings)
    if args.min_confidence:
        summary = [g for g in summary if g["confidence"] >= args.min_confidence]
    for g in summary:
        name = f"{g['group']}:{g['name']}" if g["group"] else g["name"]
        where = g["locations"][0] + (f" (+{len(g['locations']) - 1} more)" if len(g["locations"]) > 1 else "")
        print(f"{g['component']:<24} {name:<40} {g['version'] or '(version unknown)':<18} "
              f"{g['confidence']:.1f}  {where}")
        for note in sorted(g["notes"]):
            print(f"{'':24} note: {note}")
    if not summary:
        print("no watchlist components found")
    if scanner.skipped:
        print(f"{len(scanner.skipped)} item(s) not inspected" + ("" if args.verbose else " (use --verbose to list)"))
        if args.verbose:
            for s in scanner.skipped:
                print(f"  - {s}")
    if args.output:
        doc = to_cyclonedx(summary, fps, target.name)
        Path(args.output).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.output}; next: python -m xenolith prepare {args.output} --supplier ... --product ... "
              f"--version ... --artifact <original file>")
    return 0
