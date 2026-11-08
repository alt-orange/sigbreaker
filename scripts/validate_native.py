"""Compare actual execution of native PE files before/after SigBreaker."""
import ctypes
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from pe_fixture_checks import relocated_export, check_section_preservation

WORKSPACE = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--cpp', action='store_true', help='include MSVC EXE/DLL fixtures built by build_cpp_fixture.ps1')
settings = parser.parse_args()
ROOT = WORKSPACE / "target" / "runtime-validation"
ROOT.mkdir(parents=True, exist_ok=True)
TOOL = WORKSPACE / "target" / "release" / "sigbraker.exe"
RUN = ROOT / time.strftime("run-%Y%m%d-%H%M%S")
RUN.mkdir()
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
if os.name == "nt":
    # Suppress modal OS crash dialogs, including in child processes.
    ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)


def execute(argv, timeout=10):
    start = time.monotonic()
    try:
        p = subprocess.run(
            [str(x) for x in argv], cwd=RUN, capture_output=True,
            timeout=timeout, creationflags=FLAGS,
        )
        return {"exit": p.returncode, "stdout": p.stdout.hex(), "stderr": p.stderr.hex(),
                "seconds": round(time.monotonic() - start, 4), "error": None}
    except subprocess.TimeoutExpired:
        return {"exit": None, "stdout": "", "stderr": "", "seconds": timeout, "error": "timeout"}
    except OSError as e:
        return {"exit": None, "stdout": "", "stderr": "", "seconds": 0, "error": str(e)}


def signature(result):
    return tuple(result[k] for k in ("exit", "stdout", "stderr", "error"))


def target_command(name, path, args):
    if name == 'native_dll':
        return [sys.executable, WORKSPACE / 'scripts' / 'dll_probe.py', path, *args]
    return [path, *args]


def changed_executable_bytes(before, after):
    pe = struct.unpack_from("<I", before, 0x3C)[0]
    count = struct.unpack_from("<H", before, pe + 6)[0]
    optional_size = struct.unpack_from("<H", before, pe + 20)[0]
    table = pe + 24 + optional_size
    changed = 0
    for i in range(count):
        section = table + 40 * i
        size, offset = struct.unpack_from("<II", before, section + 16)
        flags = struct.unpack_from("<I", before, section + 36)[0]
        if flags & 0x20000000:
            changed += sum(a != b for a, b in zip(before[offset:offset + size], after[offset:offset + size]))
    return changed


probe = RUN / "native_probe.original.exe"
compile_result = execute([
    "rustc", WORKSPACE / "tests" / "fixtures" / "native_probe.rs", "--edition", "2021", "-C", "opt-level=2",
    "-C", "debuginfo=0", "-o", probe,
], timeout=45)
if compile_result["exit"] != 0:
    print(bytes.fromhex(compile_result["stderr"]).decode(errors="replace"), flush=True)
    raise SystemExit("native probe compilation failed")

rg_location = shutil.which("rg")
if not rg_location:
    raise SystemExit('ripgrep (rg) must be installed on PATH')
rg_source = Path(rg_location)
rg = RUN / "ripgrep.original.exe"
shutil.copy2(rg_source, rg)
corpus = RUN / "corpus"
corpus.mkdir()
text = corpus / "input.txt"
text.write_text("alpha\nbeta\nALPHA\nalpha beta\ncafé naïve\nnumber=42\n", encoding="utf-8", newline="\n")
(corpus / "second.txt").write_text("beta\ngamma\nalpha\n", encoding="utf-8", newline="\n")

probe_cases = [
    ("sum_empty", ["sum"], 0, "0\n", ""),
    ("sum_signed", ["sum", "-5", "9", "-3"], 0, "1\n", ""),
    ("sort_empty", ["sort"], 0, "\n", ""),
    ("sort_duplicates", ["sort", "3", "-1", "3", "0"], 0, "-1,0,3,3\n", ""),
    ("fib_zero", ["fib", "0"], 0, "0\n", ""),
    ("fib_30", ["fib", "30"], 0, "832040\n", ""),
    ("fib_50", ["fib", "50"], 0, "12586269025\n", ""),
    ("primes_zero", ["primes", "0"], 0, "0\n", ""),
    ("primes_1000", ["primes", "1000"], 0, "168\n", ""),
    ("caught_panic", ["unwind"], 0, "caught\n", ""),
    ("invalid_integer", ["sum", "oops"], 2, "", "error: invalid integer\n"),
    ("missing_integer", ["fib"], 2, "", "error: missing integer\n"),
    ("unknown_command", ["unknown"], 2, "", "error: unknown command\n"),
]
rg_cases = [
    ("version", ["--version"]),
    ("literal", ["--color", "never", "-n", "-F", "alpha", str(text)]),
    ("ignore_case", ["--color", "never", "-n", "-i", "alpha", str(text)]),
    ("count", ["--color", "never", "-c", "alpha", str(text)]),
    ("regex", ["--color", "never", "-o", r"number=([0-9]+)", str(text)]),
    ("unicode", ["--color", "never", "café|naïve", str(text)]),
    ("multiline", ["--color", "never", "-U", "alpha\nbeta", str(text)]),
    ("invert", ["--color", "never", "-v", "alpha", str(text)]),
    ("recursive", ["--color", "never", "--threads", "1", "--sort", "path", "alpha", str(corpus)]),
    ("no_matches", ["--color", "never", "no_such_token", str(text)]),
    ("invalid_regex", ["--color", "never", "[", str(text)]),
]
targets = [("native_probe", probe, [(c[0], c[1]) for c in probe_cases]), ("ripgrep", rg, rg_cases)]
cpp_expected = {}
seh_expected = {'0': '18 24 77 5\r\n', '1': '113 111 111 4\r\n', '2': '113 111 222 5\r\n', '3': '18 24 333 5\r\n'}
if settings.cpp:
    cpp_source = WORKSPACE / 'target' / 'native-fixtures' / 'native_cpp.exe'
    if not cpp_source.exists():
        raise SystemExit('Build the C++ fixture with scripts/build_cpp_fixture.ps1 first')
    cpp = RUN / 'native_cpp.original.exe'
    shutil.copy2(cpp_source, cpp)
    cpp_expected = {
        'compute': (0, str(sum(i if i % 3 == 0 else -i if i % 3 == 1 else 2*i for i in range(100))) + '\r\n', ''),
        'callback': (0, '3366\r\n', ''), 'exceptions': (0, '4\r\n', ''),
        'switch': (0, '130\r\n', ''), 'sort': (0, '-1 3 5 5 9 \r\n', ''),
        'threads': (0, '2000\r\n', ''), 'stackwalk': (0, 'ok\r\n', ''),
        'unknown': (2, '', 'unknown command\r\n'),
    }
    targets.append(('native_cpp', cpp, [(case, [case]) for case in cpp_expected]))
    dll_source = WORKSPACE / 'target' / 'native-fixtures' / 'native_cpp.dll'
    if not dll_source.exists():
        raise SystemExit('Build the DLL fixture with scripts/build_cpp_fixture.ps1 first')
    dll = RUN / 'native_dll.original.dll'
    shutil.copy2(dll_source, dll)
    targets.append(('native_dll', dll, [(case, [case]) for case in cpp_expected]))
    seh = RUN / 'native_seh.original.exe'
    shutil.copy2(WORKSPACE / 'target' / 'native-fixtures' / 'native_seh.exe', seh)
    targets.append(('native_seh', seh, [(mode, [mode]) for mode in seh_expected]))
result = {"run_directory": str(RUN), "targets": {}, "variants": []}
baseline = {}
for name, original, cases in targets:
    baseline[name] = {case: execute(target_command(name, original, args)) for case, args in cases}
    result["targets"][name] = {
        "original": str(original), "bytes": original.stat().st_size,
        "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "baseline": baseline[name],
    }
    for case, observation in baseline[name].items():
        if observation["error"]:
            raise SystemExit(f"baseline {name}/{case} failed: {observation['error']}")
    print(f"BASELINE {name}: {len(cases)} cases, {original.stat().st_size} bytes", flush=True)

for case, _, code, stdout, stderr in probe_cases:
    expected = (code, stdout.encode().hex(), stderr.encode().hex(), None)
    if signature(baseline["native_probe"][case]) != expected:
        raise SystemExit(f"native baseline does not match independent expected result for {case}")

for case, observation in baseline["ripgrep"].items():
    expected_exit = {"no_matches": 1, "invalid_regex": 2}.get(case, 0)
    if observation["exit"] != expected_exit:
        raise SystemExit(f"unexpected original ripgrep exit for {case}: {observation['exit']}")
for case, (code, stdout, stderr) in cpp_expected.items():
    for name in ('native_cpp', 'native_dll'):
        if signature(baseline[name][case]) != (code, stdout.encode().hex(), stderr.encode().hex(), None):
            raise SystemExit(f'{name} baseline failed independent expectation: {case}')
if settings.cpp:
    for mode, stdout in seh_expected.items():
        if signature(baseline['native_seh'][mode]) != (0, stdout.encode().hex(), '', None):
            raise SystemExit(f'SEH baseline failed independent expectation: {mode}')

modes = {
    "control": ["--no-seg-inject", "--no-reorder", "--no-shuffle"],
    "segment_only": ["--no-reorder", "--no-shuffle", "--no-grow-segments"],
    "reorder_only": ["--no-seg-inject", "--no-shuffle"],
    "shuffle_only": ["--no-seg-inject", "--no-reorder"],
    "default": [],
    "growing_segments": ["--grow-segments", "--seg-prob", "1", "--no-reorder", "--no-shuffle"],
}
for name, original, cases in targets:
    for mode, options in modes.items():
        # The SEH/assembly fixture targets layout and unwinding. Individual
        # prefix/scheduler coverage is supplied by the Rust/C++/ripgrep fixtures.
        if name == 'native_seh' and mode in ('segment_only', 'reorder_only'):
            continue
        seeds = [1397311314] if mode == "control" else [1397311314, 7, 42]
        for seed in seeds:
            tag = f"{name}.{mode}.{seed}"
            output = RUN / f"{tag}{original.suffix}"
            transformed = execute([TOOL, original, "-o", output, "--seed", seed, *options], timeout=30)
            row = {"target": name, "mode": mode, "seed": seed,
                   "output": str(output), "transform": transformed, "cases": {}}
            log = bytes.fromhex(transformed["stdout"]) + bytes.fromhex(transformed["stderr"])
            (RUN / f"{tag}.log").write_bytes(log)
            if transformed["exit"] != 0 or transformed["error"] or not output.exists():
                reason = bytes.fromhex(transformed['stderr']).decode(errors='replace')
                unsupported = any(marker in reason for marker in ('opaque exception metadata', 'unclassified image-relative data reference', 'unclassified absolute data reference', 'unclassified executable bytes', 'unresolved indirect branch', 'unsupported extended load-config metadata', 'nonempty volatile metadata', 'unsupported populated data directory', 'overlapping instruction roots'))
                row["status"] = 'unsupported_rebuild' if unsupported and not output.exists() else "transform_failed"
                print(f"{row['status'].upper()} {tag}: {reason.strip()}", flush=True)
            else:
                row["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
                before, after = original.read_bytes(), output.read_bytes()
                row['layout_strategy'] = check_section_preservation(before, after)
                row["changed_bytes"] = sum(a != b for a, b in zip(before, after))
                row["same_size"] = len(before) == len(after)
                row["input_bytes"] = len(before)
                row["output_bytes"] = len(after)
                row["code_changed_bytes"] = changed_executable_bytes(before, after)
                if name in ('native_cpp', 'native_dll'):
                    row['relocated_stackwalk'] = relocated_export(after, 'walk')
                if name == 'native_seh':
                    row['relocated_exception_functions'] = {export: relocated_export(after, export) for export in ('seh_probe', 'seh_nested', 'chained_body', 'tail_probe')}
                failed = []
                for case, args in cases:
                    observation = execute(target_command(name, output, args), timeout=5)
                    observation["matches_original"] = signature(observation) == signature(baseline[name][case])
                    row["cases"][case] = observation
                    if not observation["matches_original"]:
                        failed.append(case)
                    # A crash in every invocation makes repeated launches unhelpful.
                    if observation["error"] or (observation["exit"] is not None and observation["exit"] & 0xC0000000 == 0xC0000000):
                        row["stopped_after_crash"] = case
                        break
                row["status"] = "runtime_mismatch" if failed else "passed"
                if not failed and mode != "control" and row["code_changed_bytes"] == 0:
                    row["status"] = "no_code_change"
                if not failed and mode == 'growing_segments' and row['output_bytes'] <= row['input_bytes']:
                    row['status'] = 'no_code_change'
                row["failed_cases"] = failed
                print(f"{row['status'].upper()} {tag}: {len(row['cases'])}/{len(cases)} cases, "
                      f"{row['changed_bytes']} changed bytes" + (f", failures={failed}" if failed else ""), flush=True)
            result["variants"].append(row)
            (RUN / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

for name, original, _ in targets:
    assert hashlib.sha256(original.read_bytes()).hexdigest() == result["targets"][name]["sha256"]
summary = {status: sum(r["status"] == status for r in result["variants"])
           for status in ("passed", "unsupported_rebuild", "transform_failed", "runtime_mismatch", "no_code_change")}
result["summary"] = summary
result['relocated_stackwalk_coverage'] = {
    name: (any(row['target'] == name and row.get('relocated_stackwalk') and row['status'] == 'passed'
              for row in result['variants']) if any(row['target']==name and row['mode'] in ('default','shuffle_only','growing_segments') and row['status']=='passed' for row in result['variants']) else None)
    for name, _, _ in targets if name in ('native_cpp', 'native_dll')
}
result['relocated_exception_coverage'] = {
    export: any(row['target'] == 'native_seh' and row.get('relocated_exception_functions', {}).get(export) and row['status'] == 'passed' for row in result['variants'])
    for export in ('seh_probe', 'seh_nested', 'chained_body', 'tail_probe') if settings.cpp
}
(RUN / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(f"SUMMARY {summary}", flush=True)
print(f"RESULTS {RUN / 'results.json'}", flush=True)
print(f"RELOCATED STACK WALK {result['relocated_stackwalk_coverage']}", flush=True)
print(f"RELOCATED EXCEPTIONS {result['relocated_exception_coverage']}", flush=True)
raise SystemExit(0 if all(r["status"] == "passed" for r in result["variants"])
                 and all(value is not False for value in result['relocated_stackwalk_coverage'].values())
                 and all(result['relocated_exception_coverage'].values()) else 1)
