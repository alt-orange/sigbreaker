#!/usr/bin/env python3
"""Signature-detection test for SigBreaker.

Builds byte-pattern signatures (with wildcards for every position-dependent
field) from the functions of an ORIGINAL PE, then checks how many of them
still match the PROCESSED binary.

What is wildcarded (per instruction, via capstone):
  - rel8/rel16/rel32 branch and call displacements (retargeted by relocation)
  - rip-relative memory displacements (data does not move, but encodings may)
  - absolute immediates whose value lands inside the image (code/data VAs)
Everything else - opcodes, modrm, sib, registers, small immediates - stays
concrete. Junk insertion, block reordering and re-encoding are NOT
wildcarded: a signature only survives if the byte stream itself survived.

Classification of every original function in the processed binary:
  relocated - the original entry now starts with an E9 trampoline into the
              appended section (its body was rebuilt elsewhere)
  retained  - the original bytes are still the live entry point

The report counts each detected signature once overall and once per location
where it matches: its original function span, the appended section, or elsewhere.
Retained functions can also change through in-place passes.

Usage:
  python scripts/signature_test.py ORIGINAL PROCESSED [--prefix 256]
       [--min-insns 4] [--sample N]
"""

from __future__ import annotations

import argparse
import bisect
import re
import struct
import sys
from dataclasses import dataclass

import capstone as cs

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

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                off = s.raw_ptr + rva - s.va
                if off < len(self.data):
                    return off
        return None

    def section_of_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.va <= rva < s.va + s.vsize:
                return s
        return None

    def image_range(self) -> tuple[int, int]:
        lo = min(s.va for s in self.sections)
        hi = max(s.va + s.vsize for s in self.sections)
        return lo, hi


def parse_image(path: str) -> Image:
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "not a PE file"
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    assert machine == 0x8664, "x86-64 only"
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    s0 = pe + 24 + opt
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
    return Image(data=data, image_base=image_base, sections=sections)


def pdata_functions(img: Image) -> list[tuple[int, int]]:
    """(start_rva, end_rva) of every runtime-function record."""
    pe = struct.unpack_from("<I", img.data, 0x3C)[0]
    dd = pe + 24 + 112  # DataDirectory offset within a PE32+ optional header
    exc_rva, exc_size = struct.unpack_from("<II", img.data, dd + 8 * 3)
    if not exc_size:
        return []
    off = img.rva_to_off(exc_rva)
    funcs = []
    for i in range(exc_size // 12):
        start, end, _ = struct.unpack_from("<III", img.data, off + 12 * i)
        if end > start:
            funcs.append((start, end))
    return funcs


# --------------------------------------------------------------------------
# signature construction
# --------------------------------------------------------------------------

_md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
_md.detail = True

BRANCH_GROUPS = {cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_BRANCH_RELATIVE}


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


def build_signature(img: Image, start: int, end: int, prefix: int) -> Signature | None:
    """Linear-decode up to `prefix` bytes of a function and mask every
    position-dependent field."""
    off = img.rva_to_off(start)
    if off is None:
        return None
    size = min(prefix, end - start)
    blob = img.data[off:off + size]
    # Decode through the last instruction that starts in the signature so a
    # prefix ending inside a displacement still masks the bytes it contains.
    decode_blob = img.data[off:off + min(size + 14, end - start)]
    lo, hi = (img.image_base + rva for rva in img.image_range())
    mask = bytearray(len(blob))
    wild = 0
    count = 0
    for insn in _md.disasm(decode_blob, start):
        enc = insn.encoding  # capstone >= 5 byte offsets of disp/imm
        is_branch = bool(BRANCH_GROUPS & set(insn.groups))
        wild_here = False

        def mask_at(offset: int, size: int) -> None:
            nonlocal wild_here
            if size > 0:
                _mask_bits(mask, insn.address - start + offset, size)
                wild_here = True

        # branch/call displacements
        if is_branch and enc.imm_size:
            mask_at(enc.imm_offset, enc.imm_size)

        for op in insn.operands:
            if op.type == cs.x86.X86_OP_IMM:
                # absolute immediate pointing into the image
                if not is_branch and lo <= op.imm < hi and enc.imm_size:
                    mask_at(enc.imm_offset, enc.imm_size)
            elif op.type == cs.x86.X86_OP_MEM:
                if op.mem.base == cs.x86.X86_REG_RIP and enc.disp_size:
                    mask_at(enc.disp_offset, enc.disp_size)
        wild += wild_here
        count += 1
        if insn.address + insn.size - start >= size:
            break
    if count == 0:
        return None
    return Signature(start, end, start, blob, bytes(mask), count, wild)


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


def first_concrete_run(sig: Signature, min_len: int = 4) -> tuple[int, int] | None:
    """(offset, length) of the first concrete run worth anchoring on."""
    start = None
    best = (None, 0)
    for i, m in enumerate(sig.mask):
        if m != WILD:
            if start is None:
                start = i
            length = i - start + 1
            if length >= min_len:
                return (start, length)
            if length > best[1]:
                best = (start, length)
        else:
            start = None
    return best if best[0] is not None else None


@dataclass
class Match:
    offset: int  # file offset of the match


def search_all(sigs: list[Signature], img: Image,
               regions: list[tuple[int, int]]) -> list[list[Match]]:
    """Find every signature within `regions` of (raw_ptr, size) form.

    Search using concrete anchors of up to four bytes. Verify each candidate
    against the full pattern, including patterns with no concrete bytes."""
    anchors: dict[int, dict[bytes, list[tuple[int, int]]]] = {}
    wildcard_only = []
    for idx, sig in enumerate(sigs):
        run = first_concrete_run(sig)
        if run:
            offset, length = run
            by_length = anchors.setdefault(length, {})
            by_length.setdefault(sig.pattern[offset:offset + length], []).append((idx, offset))
        else:
            wildcard_only.append(idx)

    regexes: list = [None] * len(sigs)
    hits: list[list[Match]] = [[] for _ in sigs]

    for raw_ptr, size in regions:
        blob_end = min(raw_ptr + size, len(img.data))
        for length, by_length in anchors.items():
            for pos in range(raw_ptr, blob_end - length + 1):
                for idx, anchor_off in by_length.get(img.data[pos:pos + length], ()):
                    cand = pos - anchor_off
                    if cand < raw_ptr or cand + len(sigs[idx].pattern) > blob_end:
                        continue
                    if regexes[idx] is None:
                        regexes[idx] = compile_regex(sigs[idx])
                    if regexes[idx].match(img.data, cand):
                        hits[idx].append(Match(cand))
        for idx in wildcard_only:
            hits[idx].extend(Match(pos) for pos in range(raw_ptr, blob_end - len(sigs[idx].pattern) + 1))
    return hits


def classify_offset(offset: int, sbrk: list[Section], orig_site_off: int | None) -> str:
    for s in sbrk:
        if s.raw_ptr <= offset < s.raw_ptr + s.raw_size:
            return "appended"
    if orig_site_off is not None and offset == orig_site_off:
        return "original-site"
    return "elsewhere"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("original")
    ap.add_argument("processed")
    ap.add_argument("--prefix", type=int, default=256,
                    help="bytes per signature (default 256, 0 = full body)")
    ap.add_argument("--min-insns", type=int, default=4,
                    help="skip functions with fewer decoded instructions")
    ap.add_argument("--sample", type=int, default=0,
                    help="only test the first N functions (0 = all)")
    ap.add_argument("--body-offset", type=int, default=16,
                    help="second variant anchors here, past the entry trampoline")
    ap.add_argument("--baseline", action="store_true",
                    help="also count how often signatures match outside their own "
                         "function in the ORIGINAL binary (false-positive rate)")
    args = ap.parse_args()

    orig = parse_image(args.original)
    proc = parse_image(args.processed)
    funcs = pdata_functions(orig)
    prefix = args.prefix or 0x7FFFFFFF
    if args.sample:
        funcs = funcs[:args.sample]

    sbrk = [s for s in proc.sections if s.name.startswith(".sbrk")]

    # --- build signatures: entry-anchored and body-anchored ---------------
    variants = [("entry (offset 0)", 0), (f"body (offset {args.body_offset})",
                                          args.body_offset)]
    sigs: list[Signature] = []
    variant_of: list[int] = []
    skipped = [0, 0]
    for vi, (_, boff) in enumerate(variants):
        for start, end in funcs:
            cut = start + min(boff, max(0, (end - start) // 2))
            sig = build_signature(orig, cut, end, prefix)
            if sig is None or sig.insns < args.min_insns:
                skipped[vi] += 1
                continue
            sig.fn_start, sig.fn_end = start, end
            sigs.append(sig)
            variant_of.append(vi)

    # --- sanity: every signature must match at its own original offset ----
    own_hits = 0
    for sig in sigs:
        off = orig.rva_to_off(sig.sig_start)
        if off is not None and compile_regex(sig).match(orig.data, off):
            own_hits += 1
    sanity = 100.0 * own_hits / max(1, len(sigs))

    # --- optional false-positive baseline against the original binary -----
    baseline = ""
    if args.baseline:
        orig_regions = [(s.raw_ptr, s.raw_size)
                        for s in orig.sections if s.chars & 0x20000000]
        orig_hits = search_all(sigs, orig, orig_regions)
        foreign = 0
        foreign_total = 0
        for idx, sig in enumerate(sigs):
            own = orig.rva_to_off(sig.fn_start)
            extra = [h for h in orig_hits[idx]
                     if not (own <= h.offset < own + sig.fn_end - sig.fn_start)]
            if extra:
                foreign += 1
                foreign_total += len(extra)
        baseline = (f"; false positives in ORIGINAL: {foreign} sigs "
                    f"({100 * foreign / max(1, len(sigs)):.1f}%) match "
                    f"elsewhere, {foreign_total} hits total")

    # --- classify functions in the processed binary -----------------------
    relocated = []
    for start, end in funcs:
        off = proc.rva_to_off(start)
        if off is None or proc.data[off] != 0xE9:
            continue
        disp = struct.unpack_from("<i", proc.data, off + 1)[0]
        target = start + 5 + disp
        if any(s.va <= target < s.va + s.vsize for s in sbrk):
            relocated.append((start, end))

    relocated_starts = sorted(r[0] for r in relocated)
    relocated_ends = [r[1] for r in relocated]

    def is_relocated(rva: int) -> bool:
        i = bisect.bisect_right(relocated_starts, rva) - 1
        return i >= 0 and rva < relocated_ends[i]

    # --- search the processed binary (both variants, one pass) ------------
    proc_regions = [(s.raw_ptr, s.raw_size)
                    for s in proc.sections if s.chars & 0x20000000]
    hits = search_all(sigs, proc, proc_regions)

    def classify(sig: Signature, hit: Match) -> str:
        for s in sbrk:
            if s.raw_ptr <= hit.offset < s.raw_ptr + s.raw_size:
                return "appended"
        off = proc.rva_to_off(sig.fn_start)
        if off is not None and off <= hit.offset < off + (sig.fn_end - sig.fn_start):
            return "original-site"
        return "elsewhere"

    width = 78
    print("=" * width)
    print(f"original : {args.original}")
    print(f"processed: {args.processed}")
    print(f"relocated to .sbrk: {len(relocated)} of {len(funcs)} functions; "
          f"sanity: {own_hits}/{len(sigs)} sigs match own original bytes"
          f"{baseline}")
    for vi, (name, _) in enumerate(variants):
        reloc_hit = {loc: 0 for loc in ("appended", "original-site", "elsewhere")}
        reloc_examples: list[str] = []
        vi_sigs = vi_retain = relocated_hits = 0
        retain_hits = 0
        for idx, sig in enumerate(sigs):
            if variant_of[idx] != vi:
                continue
            if is_relocated(sig.fn_start):
                vi_sigs += 1
                got = hits[idx]
                if got:
                    relocated_hits += 1
                    for location in {classify(sig, hit) for hit in got}:
                        reloc_hit[location] += 1
                    loc = classify(sig, got[0])
                    if len(reloc_examples) < 5:
                        reloc_examples.append(
                            f"    fn {sig.fn_start:#x}..{sig.fn_end:#x} matched at "
                            f"file offset {got[0].offset:#x} ({loc})")
            else:
                vi_retain += 1
                if hits[idx]:
                    retain_hits += 1
        print("-" * width)
        print(f"variant: {name}   ({vi_sigs + vi_retain} signatures, "
              f"{skipped[vi]} skipped as too short)")
        print(f"  relocated functions : {vi_sigs}")
        print(f"    still detected    : {relocated_hits} "
              f"({100 * relocated_hits / max(1, vi_sigs):.2f}%)  "
              f"[original-site {reloc_hit['original-site']} / "
              f"appended {reloc_hit['appended']} / "
              f"elsewhere {reloc_hit['elsewhere']}]")
        for line in reloc_examples:
            print(line)
        print(f"  retained functions  : {vi_retain}")
        print(f"    still detected    : {retain_hits} "
              f"({100 * retain_hits / max(1, vi_retain):.2f}%)")
        total = relocated_hits + retain_hits
        print(f"  OVERALL detection   : {total}/{vi_sigs + vi_retain} "
              f"({100 * total / max(1, vi_sigs + vi_retain):.2f}%)")
    print("=" * width)
    return 0


if __name__ == "__main__":
    sys.exit(main())
