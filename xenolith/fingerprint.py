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
import posixpath
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
    watchlist: bool = True              # false: detect-only (reported, not a census watchlist component)
    strings: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    markers: list = field(default_factory=list)
    paths: list = field(default_factory=list)


def load(path: Path = FINGERPRINTS) -> list[Fingerprint]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for cid, spec in (cfg.get("components") or {}).items():
        fp = Fingerprint(id=cid, name=spec["name"], group=spec.get("group", ""), purl=spec.get("purl", ""),
                         watchlist=spec.get("watchlist", True) is not False)
        for s in spec.get("strings") or []:
            fp.strings.append({**s, "contains": s["contains"].encode(), "regex": re.compile(s["regex"].encode()),
                               "requires_any": [r.encode() for r in s.get("requires_any") or []],
                               "unless_any": [r.encode() for r in s.get("unless_any") or []]})
        fp.symbols = [s.encode() for s in spec.get("symbols") or []]
        fp.probes = list(spec.get("probes") or [])
        fp.markers = [{**m, "bytes": m["bytes"].encode()} for m in spec.get("markers") or []]
        fp.paths = []
        for p in spec.get("paths") or []:
            rule = {**p, "regex": re.compile(p["regex"])}
            if p.get("sibling"):
                sb = p["sibling"]
                rule["sibling"] = {**sb, "regex": re.compile(sb["regex"].encode())}
                if sb.get("rewrite"):
                    rule["sibling"]["rewrite"] = (re.compile(sb["rewrite"]["regex"]), sb["rewrite"].get("to", ""))
                if "v" not in rule["sibling"]["regex"].groupindex or not sb.get("path"):
                    raise ValueError(f"fingerprints: {cid}: sibling needs a path and a (?P<v>...) group")
            fp.paths.append(rule)
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


class Pe:
    """Just enough PE/COFF to find exported functions and read their code (Windows DLLs
    export their version functions the way ELF libraries define them)."""

    MAX_EXPORTS = 1 << 16

    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        machine, nsec = struct.unpack_from("<HH", data, pe + 4)
        optsz = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        self.arch = {0x8664: "x86", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, "")
        dd = opt + (112 if magic == 0x20B else 96)
        nrva = struct.unpack_from("<I", data, dd - 4)[0]
        self.export_dir = struct.unpack_from("<II", data, dd) if nrva > 0 else (0, 0)
        self.sections = []
        for i in range(min(nsec, 96)):
            _, vsize, va, rawsz, rawptr = struct.unpack_from("<8sIIII", data, opt + optsz + 40 * i)
            self.sections.append((va, max(vsize, rawsz), rawsz, rawptr))

    def read_rva(self, rva: int, n: int = 32) -> bytes:
        for va, size, rawsz, rawptr in self.sections:
            if va <= rva < va + size:
                off = rva - va
                if off >= rawsz:
                    return b""
                return bytes(self.data[rawptr + off:rawptr + min(rawsz, off + n)])
        return b""

    def exports(self, wanted: set[bytes]) -> dict[bytes, int]:
        erva, esize = self.export_dir
        hdr = self.read_rva(erva, 40) if erva and esize >= 40 else b""
        if len(hdr) < 40:
            return {}
        nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIII", hdr, 20)
        if nfun > self.MAX_EXPORTS or nnames > self.MAX_EXPORTS:
            return {}
        longest = max((len(w) for w in wanted), default=0)
        names, ords, funcs = self.read_rva(anames, nnames * 4), self.read_rva(aords, nnames * 2), self.read_rva(afun, nfun * 4)
        out = {}
        for i in range(min(len(names) // 4, len(ords) // 2)):
            raw = self.read_rva(struct.unpack_from("<I", names, i * 4)[0], longest + 1)
            if b"\0" not in raw or raw[:raw.index(b"\0")] not in wanted:
                continue
            o = struct.unpack_from("<H", ords, i * 2)[0]
            if o * 4 + 4 > len(funcs):
                continue
            rva = struct.unpack_from("<I", funcs, o * 4)[0]
            if not erva <= rva < erva + esize:     # forwarded exports point into the export directory
                out[raw[:raw.index(b"\0")]] = rva
        return out


def returned_constant(elf: Elf, vaddr: int) -> int | None:
    """The immediate a tiny 'return CONSTANT;' function returns (x86/x86-64, AArch64)."""
    arch = {0x3E: "x86", 0x03: "x86", 0xB7: "arm64"}.get(elf.machine, "")
    # x86 functions may start at odd addresses (Pillow's liblcms2 has one at 0xed7f); only
    # 32-bit ARM uses the low bit, for Thumb, and it is not decoded here.
    return decode_return(elf.read_at(vaddr), arch)


def decode_return(code: bytes, arch: str) -> int | None:
    if not code:
        return None
    if arch == "x86":                               # x86-64, i386
        if code[:4] in (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb"):   # endbr64/endbr32
            code = code[4:]
        framed = False
        if code[:4] == b"\x55\x48\x89\xe5":            # push rbp; mov rbp, rsp (frame pointers kept)
            code, framed = code[4:], True
        elif code[:3] == b"\x55\x89\xe5":               # i386: push ebp; mov ebp, esp
            code, framed = code[3:], True
        if code[:1] != b"\xb8" or len(code) < 6:        # mov eax, imm32
            return None
        value, rest = struct.unpack_from("<I", code, 1)[0], code[5:]
        if framed and rest[:1] in (b"\x5d", b"\xc9"):   # pop rbp / leave
            rest = rest[1:]
        return value if rest[:1] == b"\xc3" else None
    if arch == "arm64":
        value, seen = 0, False
        for i in range(0, len(code) - 3, 4):
            ins = struct.unpack_from("<I", code, i)[0]
            if ins in (0xD503201F, 0xD503233F, 0xD503245F, 0xD503241F, 0xD50323BF,   # nop, paciasp, bti, autiasp
                       0xA9BF7BFD, 0x910003FD, 0xA8C17BFD):   # stp x29,x30,[sp,#-16]! / mov x29,sp / ldp x29,x30,[sp],#16
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


def decode_address(code: bytes, arch: str, addr: int) -> int | None:
    """Address of the literal a tiny 'return "literal";' function returns: x86-64
    lea rax,[rip+disp32]; ret (optionally framed), or AArch64 adrp x0 / add x0,x0,#lo12 / ret."""
    if arch == "x86":
        at = 4 if code[:4] == b"\xf3\x0f\x1e\xfa" else 0
        framed = code[at:at + 4] == b"\x55\x48\x89\xe5"
        if framed:
            at += 4
        if code[at:at + 3] != b"\x48\x8d\x05" or len(code) < at + 8:
            return None
        disp = struct.unpack_from("<i", code, at + 3)[0]
        rest = code[at + 7:]
        if framed and rest[:1] in (b"\x5d", b"\xc9"):
            rest = rest[1:]
        return addr + at + 7 + disp if rest[:1] == b"\xc3" else None
    if arch == "arm64":
        target = None
        for i in range(0, len(code) - 3, 4):
            ins = struct.unpack_from("<I", code, i)[0]
            if ins in (0xD503201F, 0xD503233F, 0xD503245F, 0xD503241F, 0xD50323BF, 0xA9BF7BFD, 0x910003FD, 0xA8C17BFD):
                continue
            if ins & 0x9F00001F == 0x90000000:                      # adrp x0, page
                imm = ((ins >> 29) & 3) | (((ins >> 5) & 0x7FFFF) << 2)
                if imm & (1 << 20):
                    imm -= 1 << 21
                target = ((addr + i) & ~0xFFF) + (imm << 12)
            elif target is not None and ins & 0xFFC003FF == 0x91000000:   # add x0, x0, #imm12
                target += (ins >> 10) & 0xFFF
            elif ins == 0xD65F03C0:
                return target
            else:
                return None
    return None


def version_in(literal: bytes) -> str:
    literal = literal.split(b"\0", 1)[0]
    m = re.search(rb"\d+\.\d+(?:\.\d+){0,2}", literal) if 0 < len(literal) <= 64 else None
    return m.group(0).decode() if m else ""


DECODERS = {
    "brotli_hex": lambda v: f"{v >> 24}.{(v >> 12) & 0xFFF}.{v & 0xFFF}",
    "webp_hex": lambda v: f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}",
    "lzma_number": lambda v: f"{v // 10000000}.{(v // 10000) % 1000}.{(v // 10) % 1000}",
    "sqlite_number": lambda v: f"{v // 1000000}.{(v // 1000) % 1000}.{v % 1000}",
    "lcms_number": lambda v: f"{v // 1000}.{(v // 10) % 100}" + (f".{v % 10}" if v % 10 else ""),
    "decimal_mmp": lambda v: f"{v // 10000}.{(v // 100) % 100}.{v % 100}",
    "pg_number": lambda v: f"{v // 10000}.{v % 10000}" if v >= 100000 else f"{v // 10000}.{(v // 100) % 100}.{v % 100}",
}
VERSION_SHAPE = re.compile(r"\d{1,2}\.\d{1,4}(?:\.\d{1,4})?")


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
                self._paths(rel, lambda: path.read_bytes() if size < 4 * 1024 * 1024 else b"",
                            lambda r: _read_small(path.parent / r))
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
            self._paths(rel, lambda info=info: z.read(info) if info.file_size < 4 * 1024 * 1024 else b"",
                        lambda r, info=info: _zip_sibling(z, info.filename, r))
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
                self._paths(rel, lambda d=data: d, lambda r, name=m.name: _tar_sibling(t, name, r))
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

    def _paths(self, rel: str, read, sibling=None):
        """sibling(relpath) reads a file relative to the matched one's directory (or None)."""
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
                confidence, note = float(rule.get("confidence", 0.6)), rule.get("note", "")
                sb = rule.get("sibling")
                if not version and sb and sibling is not None:
                    groups = {k: v or "" for k, v in m.groupdict().items()}
                    target = re.sub(r"\{(\w+)\}", lambda g: groups.get(g.group(1), ""), sb["path"])
                    data = sibling(target)
                    sm = sb["regex"].search(data) if data else None
                    if sm:
                        version = sm.group("v").decode("utf-8", "replace")
                        if sb.get("rewrite"):
                            rx, to = sb["rewrite"]
                            version = rx.sub(lambda _m: to, version)
                        confidence = min(confidence, float(sb.get("confidence", confidence)))
                        note = "; ".join(x for x in (note, sb.get("note", "")) if x)
                name = m.groupdict().get("name") or fp.name
                technique = "manifest-analysis" if how else ("filename" if m.groupdict().get("v") else "binary-analysis")
                self._add(fp, version, technique, confidence, rel,
                          evidence=rel.rsplit("/", 1)[-1], note=note, name=name)

    # -- executables and libraries
    def _binary(self, data, rel: str):
        for fp in self.fps:
            for s in fp.strings:
                if data.find(s["contains"]) < 0:
                    continue
                if s["requires_any"] and not any(data.find(r) >= 0 for r in s["requires_any"]):
                    continue
                if any(data.find(r) >= 0 for r in s["unless_any"]):
                    continue
                # Prefer the most specific version and skip glob patterns: OpenSSH keeps the bare
                # "OpenSSH_9.2" next to "OpenSSH_9.2p1 Debian-..." and a table of "OpenSSH_7.0*".
                best = None
                for i, m in enumerate(s["regex"].finditer(data)):
                    if i >= 10000:
                        break
                    if data[m.end():m.end() + 1] == b"*":
                        continue
                    if best is None or len(m.group("v")) > len(best.group("v")):
                        best = m
                if best is not None:
                    v = best.group("v").decode("ascii", "replace")
                    self._add(fp, v, "binary-analysis", float(s.get("confidence", 0.9)), rel,
                              evidence=best.group(0).decode("ascii", "replace"), name=s.get("name") or fp.name)
            for mk in fp.markers:
                if data.find(mk["bytes"]) >= 0:
                    self._add(fp, "", "binary-analysis", 0.6, rel, evidence="static data marker", note=mk.get("note", ""))
        if not self.wanted_symbols or not any(data.find(s) >= 0 for s in self.wanted_symbols):
            return
        verb = "defines"
        if data[:4] == b"\x7fELF":
            try:
                elf = Elf(data)
                defined = elf.defined_symbols(self.wanted_symbols)
            except (ValueError, struct.error) as e:
                self.skipped.append(f"{rel}: ELF parse: {e}")
                return
            read = elf.read_at                                    # (vaddr, n=32)
            arch = {0x3E: "x86", 0x03: "x86", 0xB7: "arm64"}.get(elf.machine, "")
        elif data[:2] == b"MZ":
            try:
                pe = Pe(data)
                defined = pe.exports(self.wanted_symbols)
            except (ValueError, struct.error):
                return                                  # a DOS stub or other MZ file
            read, arch, verb = pe.read_rva, pe.arch, "exports"
        else:
            return
        for fp in self.fps:
            version = ""
            for probe in fp.probes:
                addr = defined.get(probe["symbol"].encode())
                if not addr:
                    continue
                if probe["decode"] == "string":
                    target = decode_address(read(addr, 32), arch, addr)
                    v = version_in(read(target, 65)) if target is not None else ""
                    if VERSION_SHAPE.fullmatch(v):
                        version = v
                        self._add(fp, v, "binary-analysis", 0.8, rel, evidence=f'{probe["symbol"]}() returns "{v}"')
                        break
                    continue
                value = decode_return(read(addr, 32), arch)
                if value:
                    v = DECODERS[probe["decode"]](value)
                    if VERSION_SHAPE.fullmatch(v):
                        version = v
                        self._add(fp, v, "binary-analysis", 0.8, rel, evidence=f"{probe['symbol']}() returns {value:#x}")
                        break
            if fp.symbols and not version and all(s in defined for s in fp.symbols):
                self._add(fp, "", "binary-analysis", 0.7, rel, evidence=f"{verb} " + ", ".join(s.decode() for s in fp.symbols))

    def _add(self, fp: Fingerprint, version: str, technique: str, confidence: float, rel: str,
             evidence: str = "", note: str = "", name: str = ""):
        self.findings.append(Finding(fp.id, name or fp.name, fp.group, version.strip(), technique,
                                     confidence, rel, evidence[:200], note))


SIBLING_LIMIT = 8 * 1024 * 1024


def _read_small(p: Path):
    try:
        if p.is_file() and not p.is_symlink() and p.stat().st_size <= SIBLING_LIMIT:
            return p.read_bytes()
    except OSError:
        pass
    return None


def _tar_sibling(t: tarfile.TarFile, member: str, rel: str):
    target = posixpath.normpath(posixpath.join(posixpath.dirname(member), rel))
    try:
        m = t.getmember(target)
    except KeyError:
        return None
    if not m.isfile() or m.size > SIBLING_LIMIT:
        return None
    f = t.extractfile(m)
    return f.read() if f else None


def _zip_sibling(z: zipfile.ZipFile, member: str, rel: str):
    target = posixpath.normpath(posixpath.join(posixpath.dirname(member), rel))
    try:
        info = z.getinfo(target)
    except KeyError:
        return None
    return z.read(info) if info.file_size <= SIBLING_LIMIT else None


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
    tracked = {fp.id for fp in fingerprints if fp.watchlist}
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
        c["properties"] = ([{"name": "xenolith:component", "value": g["component"]}] if g["component"] in tracked else []) + [
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
        print("no components found")
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
