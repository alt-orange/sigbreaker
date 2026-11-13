#!/usr/bin/env python3
"""Signature-detection test for SigBreaker.

Builds wildcard byte patterns from original x64 PE runtime-function records,
then checks their survival in the processed binary's executable sections.

What is wildcarded (per instruction, via capstone):
  - rel8/rel16/rel32 branch and call displacements (retargeted by relocation)
  - rip-relative memory displacements (data does not move, but encodings may)
  - absolute immediates whose value lands inside the image (code/data VAs)
Everything else - opcodes, modrm, sib, registers, small immediates - stays
concrete. Junk insertion, block reordering and re-encoding are NOT
wildcarded: a signature only survives if the byte stream itself survived.

Entry and instruction-aligned body signatures are tested separately. An E9
entry targeting .sbrk is reported as redirected; other entries can still be
modified by in-place passes. Short, padding-only, or undecodable records are
excluded from the tested denominator and counted explicitly.

The report counts each detected signature once overall and once per location
where it matches: its original function span, the appended section, or elsewhere.
By default LZMA-compressed .sbrk code is restored before scanning. --view both
also scans the physical executable sections. No input binary is executed.
The optional baseline identifies patterns shared with other original functions.

Usage:
  python scripts/signature_test.py ORIGINAL PROCESSED [--prefix 256]
       [--baseline] [--view both] [--json results.json] [--sample N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import struct
import sys
from dataclasses import dataclass, field
import tempfile

try:
    import capstone as cs
except ImportError:
    raise SystemExit("Install dependencies: python -m pip install -r scripts/requirements-signatures.txt")

try:
    import ahocorasick
except ImportError:
    ahocorasick = None

WILD = 1  # mask marker: 1 = wildcard byte, 0 = concrete


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_size: int
    raw_ptr: int
    chars: int


@dataclass
class Image:
    data: bytes
    image_base: int
    sections: list[Section]
    image_size: int = 0
    headers_size: int = 0
    restored_sections: tuple[str, ...] = ()

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + s.raw_size:
                off = s.raw_ptr + rva - s.va
                if off < len(self.data):
                    return off
        return None

    def section_of_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def image_range(self) -> tuple[int, int]:
        return 0, self.image_size or max(s.va + max(s.vsize, s.raw_size) for s in self.sections)

    def regions(self) -> list[tuple[int, int]]:
        return [(s.raw_ptr, s.raw_size) for s in self.sections
                if s.chars & 0x20000000 and s.raw_size]

    def offset_to_rva(self, offset: int) -> int | None:
        for s in self.sections:
            if s.raw_ptr <= offset < s.raw_ptr + s.raw_size:
                return s.va + offset - s.raw_ptr
        return None


def parse_image(path: str) -> Image:
    return parse_data(Path(path).read_bytes())


def checked(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated PE data at {offset:#x} (size {size:#x})")
    return data[offset:offset + size]


def parse_data(data: bytes) -> Image:
    if checked(data, 0, 2) != b"MZ":
        raise ValueError("not a PE file: missing MZ header")
    checked(data, 0x3c, 4)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    checked(data, pe, 24)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file: missing PE signature")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    if machine != 0x8664:
        raise ValueError("only x86-64 PE images are supported")
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    checked(data, pe + 24, opt)
    if opt < 112 or struct.unpack_from("<H", data, pe + 24)[0] != 0x20b:
        raise ValueError("expected PE32+ optional header")
    directories = struct.unpack_from("<I", data, pe + 24 + 108)[0]
    if 112 + directories * 8 > opt:
        raise ValueError("data directories exceed optional header")
    image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    if not 1 <= count <= 96:
        raise ValueError("invalid PE section count")
    s0 = pe + 24 + opt
    checked(data, s0, count * 40)
    image_size, headers_size = struct.unpack_from("<II", data, pe + 24 + 56)
    if not image_size or headers_size < s0 + count * 40:
        raise ValueError("invalid PE image/header size")
    checked(data, 0, headers_size)
    sections = []
    for i in range(count):
        s = s0 + 40 * i
        name = data[s:s + 8].rstrip(b"\0").decode(errors="replace")
        sections.append(Section(
            name=name,
            va=struct.unpack_from("<I", data, s + 12)[0],
            vsize=struct.unpack_from("<I", data, s + 8)[0],
            raw_size=struct.unpack_from("<I", data, s + 16)[0],
            raw_ptr=struct.unpack_from("<I", data, s + 20)[0],
            chars=struct.unpack_from("<I", data, s + 36)[0],
        ))
    spans = []
    for section in sections:
        if section.va + max(section.vsize, section.raw_size) > image_size:
            raise ValueError(f"section {section.name} exceeds image size")
        if section.raw_size:
            checked(data, section.raw_ptr, section.raw_size)
            if section.raw_ptr < headers_size:
                raise ValueError(f"section {section.name} overlaps PE headers")
            spans.append((section.raw_ptr, section.raw_ptr + section.raw_size))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError("overlapping PE raw sections")
    return Image(data, image_base, sections, image_size, headers_size)


def restore_code(img: Image) -> Image:
    """Restore compressed code for scanning; keep the decoder and packed section.

    These bytes model code after decompression, not a complete live process.
    Raw offsets in this view refer to the reconstructed scan image.
    """
    for pack in img.sections:
        if not pack.name.startswith(".sbpack"):
            continue
        record = checked(img.data, pack.raw_ptr, pack.raw_size)
        if not record.startswith(b"SBRKCMP1"):
            continue
        checked(record, 0, 124)
        version, rva, size, packed_at, packed_size = struct.unpack_from("<5I", record, 8)
        removed_at = struct.unpack_from("<Q", record, 44)[0]
        target = next((s for s in img.sections if s.va == rva), None)
        if (version != 1 or target is None or target.raw_size != 0 or
                not 0 < size <= target.vsize or
                not img.headers_size <= removed_at <= len(img.data) or packed_at < 124):
            raise ValueError("invalid .sbrk compression recovery record")
        packed = checked(record, packed_at, packed_size)
        checked(packed, 0, 13)
        if struct.unpack_from("<Q", packed, 5)[0] not in (size, 0xffffffffffffffff):
            raise ValueError("LZMA size disagrees with .sbrk recovery record")
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64 * 1024 * 1024)
        code = decoder.decompress(packed, max_length=size + 1)
        if len(code) != size or not decoder.eof:
            raise ValueError("incomplete or oversized .sbrk LZMA stream")
        data = bytearray(img.data[:removed_at] + code + img.data[removed_at:])
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        s0 = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
        for i, section in enumerate(img.sections):
            raw_ptr = section.raw_ptr + (size if section.raw_ptr >= removed_at else 0)
            raw_size = section.raw_size
            if section is target:
                raw_ptr, raw_size = removed_at, size
            struct.pack_into("<II", data, s0 + i * 40 + 16, raw_size, raw_ptr)
        restored = parse_data(bytes(data))
        restored.restored_sections = (target.name,)
        return restored
    return img


def pdata_functions(img: Image) -> list[tuple[int, int]]:
    """(start_rva, end_rva) of every runtime-function record."""
    pe = struct.unpack_from("<I", img.data, 0x3C)[0]
    dd = pe + 24 + 112  # DataDirectory offset within a PE32+ optional header
    if struct.unpack_from("<I", img.data, pe + 24 + 108)[0] <= 3:
        return []
    exc_rva, exc_size = struct.unpack_from("<II", img.data, dd + 8 * 3)
    if not exc_size:
        return []
    off = img.rva_to_off(exc_rva)
    if off is None or exc_size % 12 or img.rva_to_off(exc_rva + exc_size - 1) != off + exc_size - 1:
        raise ValueError("invalid runtime-function table")
    funcs = []
    for i in range(exc_size // 12):
        start, end, _ = struct.unpack_from("<III", img.data, off + 12 * i)
        if end > start:
            section = img.section_of_rva(start)
            start_off = img.rva_to_off(start)
            if (section is None or not section.chars & 0x20000000 or start_off is None
                    or img.rva_to_off(end - 1) != start_off + end - start - 1):
                raise ValueError(f"runtime function {start:#x}..{end:#x} is not file-backed executable code")
            funcs.append((start, end))
    return sorted(set(funcs))


# --------------------------------------------------------------------------
# signature construction
# --------------------------------------------------------------------------

_md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
_md.detail = True

BRANCH_GROUPS = {cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_BRANCH_RELATIVE}
PADDING = {cs.x86.X86_INS_NOP, cs.x86.X86_INS_INT3, cs.x86.X86_INS_UD2}


@dataclass
class Signature:
    fn_start: int     # original function entry rva
    fn_end: int
    sig_start: int    # rva the signature was cut from
    pattern: bytes    # raw bytes as they appear in the original
    mask: bytes       # 1 = wildcard, 0 = concrete
    insns: int
    wild: int         # number of wildcarded bytes


def _mask_bits(mask: bytearray, offset: int, size: int) -> None:
    for i in range(max(0, offset), min(len(mask), offset + size)):
        mask[i] = WILD


def body_start(img: Image, start: int, end: int, offset: int) -> int | None:
    """Find an instruction boundary at or after the requested body offset."""
    if offset == 0:
        return start
    off = img.rva_to_off(start)
    if off is None or start + offset >= end:
        return None
    for insn in _md.disasm(img.data[off:off + min(offset + 15, end - start)], start):
        if insn.address >= start + offset:
            return insn.address
    return None


def build_signature(img: Image, start: int, end: int, prefix: int) -> Signature | None:
    """Linear-decode up to `prefix` bytes of a function and mask every
    position-dependent field."""
    off = img.rva_to_off(start)
    if off is None:
        return None
    size = min(prefix or end - start, end - start)
    blob = img.data[off:off + size]
    # Decode through the last instruction that starts in the signature so a
    # prefix ending inside a displacement still masks the bytes it contains.
    decode_blob = img.data[off:off + min(size + 14, end - start)]
    lo, hi = (img.image_base + rva for rva in img.image_range())
    mask = bytearray(len(blob))
    count = 0
    covered = 0
    useful = False
    for insn in _md.disasm(decode_blob, start):
        enc = insn.encoding  # capstone >= 5 byte offsets of disp/imm
        is_branch = bool(BRANCH_GROUPS & set(insn.groups))
        def mask_at(offset: int, size: int) -> None:
            if size > 0:
                _mask_bits(mask, insn.address - start + offset, size)

        # branch/call displacements
        if is_branch and enc.imm_size:
            mask_at(enc.imm_offset, enc.imm_size)

        for op in insn.operands:
            if op.type == cs.x86.X86_OP_IMM:
                # absolute immediate pointing into the image
                if not is_branch and lo <= (op.imm & 0xffffffffffffffff) < hi and enc.imm_size:
                    mask_at(enc.imm_offset, enc.imm_size)
            elif op.type == cs.x86.X86_OP_MEM:
                if op.mem.base == cs.x86.X86_REG_RIP and enc.disp_size:
                    mask_at(enc.disp_offset, enc.disp_size)
                elif op.mem.base == cs.x86.X86_REG_INVALID and lo <= op.mem.disp < hi:
                    mask_at(enc.disp_offset, enc.disp_size)
        count += 1
        useful |= insn.id not in PADDING
        covered = min(size, insn.address + insn.size - start)
        if covered >= size:
            break
    if count == 0 or not useful:
        return None
    return Signature(start, end, start, blob[:covered], bytes(mask[:covered]), count, sum(mask[:covered]))


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

def compile_regex(sig: Signature):
    parts = []
    run = bytearray()
    for b, m in zip(sig.pattern, sig.mask):
        if m == WILD:
            if run:
                parts.append(re.escape(bytes(run)))
                run.clear()
            parts.append(b"(?:.)")
        else:
            run.append(b)
    if run:
        parts.append(re.escape(bytes(run)))
    return re.compile(b"(?s:" + b"".join(parts) + b")")


def first_concrete_run(sig: Signature) -> tuple[int, int] | None:
    """(offset, length) of the longest concrete run."""
    start = None
    best = (None, 0)
    for i, m in enumerate(sig.mask):
        if m != WILD:
            if start is None:
                start = i
            length = i - start + 1
            if length > best[1]:
                best = (start, length)
        else:
            start = None
    return best if best[0] is not None else None


@dataclass
class Match:
    offset: int  # offset within the scanned image (reconstructed when decoded)
    rva: int
    location: str


LOCATIONS = ("original-site", "appended", "elsewhere")


@dataclass
class SignatureHits:
    count: int = 0
    locations: dict[str, int] = field(default_factory=lambda: dict.fromkeys(LOCATIONS, 0))
    examples: list[Match] = field(default_factory=list)

    def record(self, offset: int, sig: Signature, img: Image) -> None:
        rva = img.offset_to_rva(offset)
        section = img.section_of_rva(rva)
        if sig.fn_start <= rva and rva + len(sig.pattern) <= sig.fn_end:
            location = "original-site"
        elif section.name.startswith(".sbrk"):
            location = "appended"
        else:
            location = "elsewhere"
        # Bound report memory, while retaining exact counts for every location.
        if len(self.examples) < 3 or not self.locations[location]:
            self.examples.append(Match(offset, rva, location))
        self.count += 1
        self.locations[location] += 1


def search_all(sigs: list[Signature], img: Image,
               regions: list[tuple[int, int]]) -> list[SignatureHits]:
    """Find every signature within `regions` of (raw_ptr, size) form.

    Native multi-pattern anchors when available; verify full wildcard patterns.
    Each match must fit in one executable section; overlapping hits are kept."""
    anchors: dict[int, dict[bytes, list[tuple[int, int]]]] = {}
    wildcard_only = []
    for idx, sig in enumerate(sigs):
        run = first_concrete_run(sig)
        if run:
            offset, length = run
            length = min(length, 64 if ahocorasick else 4)
            offset += (run[1] - length) // 2
            by_length = anchors.setdefault(length, {})
            by_length.setdefault(sig.pattern[offset:offset + length], []).append((idx, offset))
        else:
            wildcard_only.append(idx)

    regexes: list = [None] * len(sigs)
    hits = [SignatureHits() for _ in sigs]

    def verify(idx: int, candidate: int, raw_ptr: int, end: int) -> None:
        if candidate < raw_ptr or candidate + len(sigs[idx].pattern) > end:
            return
        if regexes[idx] is None:
            regexes[idx] = compile_regex(sigs[idx])
        if regexes[idx].match(img.data, candidate):
            hits[idx].record(candidate, sigs[idx], img)

    automaton = None
    if ahocorasick and anchors:
        automaton = ahocorasick.Automaton()
        for length, by_length in anchors.items():
            for key, candidates in by_length.items():
                automaton.add_word(key.decode("latin1") if ahocorasick.unicode else key,
                                   (length, candidates))
        automaton.make_automaton()

    for raw_ptr, size in regions:
        blob_end = min(raw_ptr + size, len(img.data))
        if automaton is not None:
            blob = img.data[raw_ptr:blob_end]
            keys = blob.decode("latin1") if ahocorasick.unicode else blob
            for pos, (length, candidates) in automaton.iter(keys):
                for idx, anchor_off in candidates:
                    verify(idx, raw_ptr + pos - length + 1 - anchor_off, raw_ptr, blob_end)
        else:
            for length, by_length in anchors.items():
                for pos in range(raw_ptr, blob_end - length + 1):
                    for idx, anchor_off in by_length.get(img.data[pos:pos + length], ()):
                        verify(idx, pos - anchor_off, raw_ptr, blob_end)
        for idx in wildcard_only:
            for pos in range(raw_ptr, blob_end - len(sigs[idx].pattern) + 1):
                hits[idx].record(pos, sigs[idx], img)
    return hits



def entry_redirected(img: Image, rva: int) -> bool:
    off = img.rva_to_off(rva)
    if off is None or img.rva_to_off(rva + 4) != off + 4 or img.data[off] != 0xe9:
        return False
    target = rva + 5 + struct.unpack_from("<i", img.data, off + 1)[0]
    section = img.section_of_rva(target)
    return section is not None and section.name.startswith(".sbrk")


def ratio(count: int, total: int) -> str:
    return f"{count:,} / {total:,} ({100 * count / total:.2f}%)" if total else "0 / 0 (n/a)"


def write_json(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         suffix=".tmp", delete=False) as stream:
            name = stream.name
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(name, path)
    finally:
        if name is not None and os.path.exists(name):
            os.unlink(name)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare original function signatures against a processed PE")
    ap.add_argument("original")
    ap.add_argument("processed")
    ap.add_argument("--prefix", type=int, default=256, help="maximum signature bytes (0 = full body)")
    ap.add_argument("--min-insns", type=int, default=4, help="minimum decoded instructions per signature")
    ap.add_argument("--sample", type=int, default=0, help="first N runtime-function records (0 = all)")
    ap.add_argument("--body-offset", type=int, default=16,
                    help="body signature starts at the first instruction boundary at/after this offset")
    ap.add_argument("--baseline", action="store_true",
                    help="also measure signatures matching outside their source function in the original")
    ap.add_argument("--view", choices=("decoded", "file", "both"), default="decoded",
                    help="scan restored executable code, physical file sections, or both (default decoded)")
    ap.add_argument("--json", type=Path, help="save summary and per-signature match results")
    args = ap.parse_args(argv)
    if min(args.prefix, args.sample, args.body_offset) < 0 or args.min_insns < 1:
        ap.error("prefix, sample and body-offset must be nonnegative; min-insns must be positive")
    if args.json and args.json.resolve() in {Path(args.original).resolve(), Path(args.processed).resolve()}:
        ap.error("JSON output must differ from both input binaries")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    def progress(message: str) -> None:
        print(f"[signature-test] {message}", file=sys.stderr, flush=True)

    def line(label: str, value) -> None:
        print(f"  {label:<28} {value}")

    try:
        progress("Reading binaries and building original function signatures")
        original_file = parse_image(args.original)
        orig = restore_code(original_file)
        physical = parse_image(args.processed)
        decoded = restore_code(physical) if args.view != "file" else physical
        all_funcs = pdata_functions(orig)
        if not all_funcs:
            raise ValueError("original binary has no runtime-function records; no functions to test")
        funcs = all_funcs[:args.sample] if args.sample else all_funcs
        variants = [("entry", 0), ("body", args.body_offset)]
        sigs, variant_of, skipped = [], [], [0, 0]
        for vi, (_, offset) in enumerate(variants):
            for start, end in funcs:
                cut = body_start(orig, start, end, offset)
                sig = build_signature(orig, cut, end, args.prefix) if cut is not None else None
                if sig is None or sig.insns < args.min_insns:
                    skipped[vi] += 1
                    continue
                sig.fn_start, sig.fn_end = start, end
                sigs.append(sig)
                variant_of.append(vi)
        if not sigs:
            raise ValueError("no usable signatures; functions are too short, undecodable, or padding-only")
        own_hits = sum(bool(compile_regex(sig).match(orig.data, orig.rva_to_off(sig.sig_start)))
                       for sig in sigs)
        if own_hits != len(sigs):
            raise ValueError("signature self-control failed against original bytes")
        baseline = None
        if args.baseline:
            progress(f"Scanning original control ({len(sigs):,} signatures)")
            baseline = search_all(sigs, orig, orig.regions())
            if any(not hits.locations["original-site"] for hits in baseline):
                raise ValueError("scanner self-control failed: an original signature was not found at its source")
        print("Function signature comparison")
        line("Original", args.original)
        line("Processed", args.processed)
        line("Function coverage", "PE x64 runtime-function records (.pdata)")
        line("Records selected / total", f"{len(funcs):,} / {len(all_funcs):,}")
        line("Signature limit", f"{args.prefix:,} bytes" if args.prefix else "full remaining function")
        line("Body offset", f"first instruction boundary at/after +{args.body_offset}")
        line("Original-byte control", ratio(own_hits, len(sigs)))
        line("Search engine", "native multi-pattern" if ahocorasick else "Python anchors (install pyahocorasick for speed)")
        result = {
            "schema_version": 1,
            "original": {"path": str(Path(args.original).resolve()),
                         "sha256": hashlib.sha256(original_file.data).hexdigest()},
            "processed": {"path": str(Path(args.processed).resolve()),
                          "sha256": hashlib.sha256(physical.data).hexdigest()},
            "settings": {"prefix": args.prefix, "min_insns": args.min_insns,
                         "body_offset": args.body_offset, "sample": args.sample,
                         "baseline": args.baseline, "view": args.view},
            "function_records": len(all_funcs), "selected_records": len(funcs),
            "original_control": {"tested": len(sigs), "detected": own_hits,
                                 "scanner_checked": args.baseline}, "views": {}}
        views = []
        if args.view in ("file", "both"):
            views.append(("file", physical))
        if args.view == "decoded" or (args.view == "both" and decoded.restored_sections):
            views.append(("decoded", decoded))
        for name, img in views:
            progress(f"Scanning {name} view ({len(sigs):,} signatures)")
            hits = search_all(sigs, img, img.regions())
            redirected = {start: entry_redirected(img, start) for start, _ in funcs}
            print(f"\n{name.capitalize()} executable code" +
                  (f" (LZMA restored: {', '.join(img.restored_sections)})" if img.restored_sections else ""))
            view = {"restored_sections": list(img.restored_sections), "summary": {}, "signatures": []}
            for vi, (variant, _) in enumerate(variants):
                indices = [i for i, v in enumerate(variant_of) if v == vi]
                moved = [i for i in indices if redirected[sigs[i].fn_start]]
                moved_set = set(moved)
                retained = [i for i in indices if i not in moved_set]
                count = sum(bool(hits[i].count) for i in indices)
                locations = {loc: sum(bool(hits[i].locations[loc]) for i in indices) for loc in LOCATIONS}
                non_unique = (sum(bool(baseline[i].locations["appended"] or baseline[i].locations["elsewhere"])
                                  for i in indices) if baseline is not None else None)
                unique = ([i for i in indices if not (baseline[i].locations["appended"] or
                                                      baseline[i].locations["elsewhere"])]
                          if baseline is not None else None)
                summary = {"tested": len(indices), "detected": count, "skipped": skipped[vi],
                           "redirected": {"tested": len(moved), "detected": sum(bool(hits[i].count) for i in moved)},
                           "retained": {"tested": len(retained), "detected": sum(bool(hits[i].count) for i in retained)},
                           "locations": locations, "non_unique_original": non_unique,
                           "unique_original": ({"tested": len(unique),
                                                "detected": sum(bool(hits[i].count) for i in unique)}
                                               if unique is not None else None)}
                view["summary"][variant] = summary
                print(f"\n  {variant.upper()} signatures")
                line("Detected", ratio(count, len(indices)))
                line("Not detected", f"{len(indices) - count:,}")
                line("Skipped records", f"{skipped[vi]:,} (short / padding / undecodable)")
                for key, label in (("redirected", "Redirected entry: detected"), ("retained", "Other entry: detected")):
                    line(label, ratio(summary[key]["detected"], summary[key]["tested"]))
                line("Match locations", " / ".join(f"{loc} {locations[loc]:,}" for loc in LOCATIONS))
                if non_unique is not None:
                    line("Non-unique in original", ratio(non_unique, len(indices)))
                    line("Unique source: detected", ratio(summary["unique_original"]["detected"], len(unique)))
            if args.json:
                for i, sig in enumerate(sigs):
                    view["signatures"].append({
                        "function_rva": sig.fn_start, "function_end_rva": sig.fn_end,
                        "signature_rva": sig.sig_start, "variant": variants[variant_of[i]][0],
                        "length": len(sig.pattern), "instructions": sig.insns, "wildcard_bytes": sig.wild,
                        "entry_redirected": redirected[sig.fn_start], "detected": bool(hits[i].count),
                        "match_count": hits[i].count, "locations": hits[i].locations,
                        "non_unique_original": (bool(baseline[i].locations["appended"] or
                                                     baseline[i].locations["elsewhere"]) if baseline is not None else None),
                        "examples": [{"rva": h.rva, "scan_offset": h.offset, "location": h.location}
                                     for h in hits[i].examples]})
            result["views"][name] = view
        print("\nDetection means an original wildcard byte pattern survives in executable code.")
        print("Locations may overlap; shared original patterns can match a different function.")
        if args.json:
            write_json(args.json, result)
            print(f"Results: {args.json.resolve()}")
        return 0
    except (OSError, ValueError, struct.error, lzma.LZMAError, MemoryError) as error:
        print(f"[signature-test] error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
