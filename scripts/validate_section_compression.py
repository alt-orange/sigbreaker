"""Execute LZMA-compressed EXE/DLL fixtures, including ASLR and repeat processing."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--tool", type=Path, default=Path("target/release/sigbraker.exe"))
parser.add_argument("--seeds", type=int, nargs="+", default=[0, 7, 42])
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
tool = args.tool.resolve()
folder = root / "target/section-compression" / time.strftime("run-%Y%m%d-%H%M%S")
folder.mkdir(parents=True)
ctypes.windll.kernel32.SetErrorMode(0x8003)


def run(command):
    process = subprocess.run([str(value) for value in command], capture_output=True,
                             timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
    return process.returncode, process.stdout, process.stderr


def add_relocation_probe(data):
    """Add compressible space and a live absolute-pointer check to a fixture's .sbrk."""
    data = bytearray(data)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    table = opt + struct.unpack_from("<H", data, pe + 20)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    sections = [struct.unpack_from("<IIII", data, table + 40 * i + 8)
                for i in range(count)]

    def offset(rva):
        return next(raw + rva - start for _, start, size, raw in sections
                    if start <= rva < start + size)

    exports = offset(struct.unpack_from("<I", data, opt + 112)[0])
    names_count = struct.unpack_from("<I", data, exports + 24)[0]
    functions, names, ordinals = struct.unpack_from("<III", data, exports + 28)
    entry = None
    for index in range(names_count):
        name_rva = struct.unpack_from("<I", data, offset(names) + index * 4)[0]
        name_at = offset(name_rva)
        if data[name_at:data.index(0, name_at)] == b"compute":
            ordinal = struct.unpack_from("<H", data, offset(ordinals) + index * 2)[0]
            entry = struct.unpack_from("<I", data, offset(functions) + ordinal * 4)[0]
            break
    assert entry is not None, "fixture lacks its compute export"

    _, target, size, raw = sections[-1]
    assert data[table + 40 * (count - 1):][:5] == b".sbrk"
    assert raw + size == len(data), "controlled fixture must have no overlay"
    relocs, relocs_size = struct.unpack_from("<II", data, opt + 112 + 5 * 8)
    reloc_data = bytes(data[offset(relocs):offset(relocs) + relocs_size])
    padding = (max(0x10000, len(reloc_data) + 0x1000) + 0xFFF) & ~0xFFF
    data.extend(bytes(padding))
    section = table + 40 * (count - 1)
    struct.pack_into("<I", data, section + 8, size + padding)
    struct.pack_into("<I", data, section + 16, size + padding)
    struct.pack_into("<I", data, opt + 4, struct.unpack_from("<I", data, opt + 4)[0] + padding)
    alignment = struct.unpack_from("<I", data, opt + 32)[0]
    struct.pack_into("<I", data, opt + 56, (target + size + padding + alignment - 1) & -alignment)

    leaf = target + size
    field = leaf + 0x80
    code = (b"\x48\x8D\x05" + struct.pack("<i", entry - (leaf + 7))
            + b"\x48\x3B\x05" + struct.pack("<i", field - (leaf + 14))
            + b"\x0F\x94\xC0\x0F\xB6\xC0\xC3")
    data[raw + size:raw + size + len(code)] = code
    base = struct.unpack_from("<Q", data, opt + 24)[0]
    struct.pack_into("<Q", data, raw + size + 0x80, base + entry)
    entry_offset = offset(entry)
    data[entry_offset:entry_offset + 5] = b"\xE9" + struct.pack("<i", leaf - entry - 5)
    reloc_data += struct.pack("<IIHH", field & ~0xFFF, 12, 0xA000 | (field & 0xFFF), 0)
    reloc_offset = raw + size + 0x100
    data[reloc_offset:reloc_offset + len(reloc_data)] = reloc_data
    struct.pack_into("<II", data, opt + 112 + 5 * 8, leaf + 0x100, len(reloc_data))
    return data


cases = ["compute", "callback", "exceptions", "switch", "sort", "threads", "stackwalk", "unknown"]
rows = []
for variant in ["cpp", "cpp_fh3", "cpp_fh4", "cpp_guarded", "cpp_clang", "dll"]:
    source = root / "target/native-fixtures" / ("native_cpp.dll" if variant == "dll"
                                                else f"native_{variant}.exe")
    identity = ["--handler-map", str(source) + ".map"] if variant in ("cpp", "dll") else []
    suffix = source.suffix

    def execute(path, case):
        command = [path, case]
        if variant == "dll":
            command = [sys.executable, root / "scripts/dll_probe.py", *command]
        return run(command)

    for seed in args.seeds:
        prepared = folder / f"{variant}.{seed}.prepared{suffix}"
        transformed = run([tool, source, "-o", prepared, "--seed", seed, *identity])
        assert transformed[0] == 0, transformed[2].decode(errors="replace")
        prepared.write_bytes(add_relocation_probe(prepared.read_bytes()))
        baseline = {case: execute(prepared, case) for case in cases}
        assert baseline["compute"][:2] == (0, b"1\r\n"), "ASLR pointer probe failed"
        assert baseline["exceptions"][:2] == (0, b"4\r\n"), "original exception fixture failed"
        control = ["--no-seg-inject", "--no-alias", "--no-reorder", "--no-shuffle"]
        for keep in [False, True]:
            output = folder / f"{variant}.{seed}.keep-{keep}{suffix}"
            options = ["--keep-original"] if keep else []
            packed = run([tool, prepared, "-o", output, "--compress-section", *control, *identity, *options])
            (folder / f"{variant}.{seed}.keep-{keep}.log").write_bytes(packed[1] + packed[2])
            assert packed[0] == 0, packed[2].decode(errors="replace")
            assert b"compression: .sbrk LZMA" in packed[1], "compression was skipped"
            assert output.stat().st_size < prepared.stat().st_size
            for case in cases:
                assert execute(output, case) == baseline[case], (variant, seed, keep, case)
            original_packed = output.read_bytes()
            repeated = folder / f"{variant}.{seed}.repeat{suffix}"
            result = run([tool, output, "-o", repeated, "--compress-section", *control, *identity, *options])
            assert result[0] == 0, result[2].decode(errors="replace")
            assert repeated.read_bytes() == original_packed, "repeat compression changed the image"
            for case in cases:
                assert execute(repeated, case) == baseline[case], (variant, seed, keep, case, "repeated")
            rows.append({"variant": variant, "seed": seed, "keep_original": keep,
                         "before": prepared.stat().st_size, "after": output.stat().st_size,
                         "runtime_checks": 16, "passed": True})
            print(f"PASSED {variant}/{seed}/keep={keep}: LZMA, TLS, ASLR, 16 runtime checks", flush=True)
(folder / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
print(f"{sum(row['runtime_checks'] for row in rows)} runtime checks passed; results {folder / 'results.json'}")
