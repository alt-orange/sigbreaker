"""Require actual C++ handler relocation, then execute nested EH/destructors."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from pe_fixture_checks import relocated_export, check_section_preservation

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seeds', type=int, default=8)
args = parser.parse_args()
assert args.seeds > 0
root = Path(__file__).resolve().parent.parent
directory = root / 'target' / 'cpp-validation' / time.strftime('run-%Y%m%d-%H%M%S')
directory.mkdir(parents=True)
tool = root / 'target' / 'release' / 'sigbraker.exe'
flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
if os.name == 'nt':
    ctypes.windll.kernel32.SetErrorMode(0x8003)

def run(command):
    p = subprocess.run([str(x) for x in command], capture_output=True, timeout=45, creationflags=flags)
    return p.returncode, p.stdout, p.stderr

cases = ['compute', 'callback', 'exceptions', 'switch', 'sort', 'threads', 'stackwalk', 'unknown']
rows = []
for variant in ['cpp', 'cpp_fh3', 'cpp_fh4', 'cpp_guarded', 'cpp_clang']:
    source = root / 'target' / 'native-fixtures' / f'native_{variant}.exe'
    if not source.exists():
        if variant == 'cpp_clang':
            print('UNAVAILABLE optional Clang fixture', flush=True)
            continue
        raise AssertionError(f'Missing required fixture: {source}')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    baseline = {case: run([source, case]) for case in cases}
    assert baseline['exceptions'][:2] == (0, b'4\r\n')
    symbols = Path(str(source) + '.map')
    for seed in range(args.seeds):
        output = directory / f'{variant}.{seed}.exe'
        command = [tool, source, '-o', output, '--seed', seed, '--no-reorder']
        # Static CRT identity is explicit. Dynamic variants must resolve imports.
        if variant == 'cpp':
            command += ['--handler-map', symbols]
        transformed = run(command)
        (directory / f'{variant}.{seed}.log').write_bytes(transformed[1] + transformed[2])
        assert transformed[0] == 0, transformed[2].decode(errors='replace')
        data = output.read_bytes()
        strategy = check_section_preservation(source.read_bytes(), data)
        moved = relocated_export(data, 'exceptions')
        assert moved, f'Exception parent was not relocated: {variant}/{seed}'
        assert moved['unwind_flags'] & 3, 'relocated C++ function lost handler data'
        for case in cases:
            assert run([output, case]) == baseline[case], f'{variant}/{seed}/{case}: mismatch'
        rows.append({'variant': variant, 'seed': seed, 'passed': True, 'cases': len(cases),
                     'source_sha256': digest, 'layout_strategy': strategy, 'relocated_exceptions': moved})
        print(f'PASSED {variant}/{seed}: C++ handler relocated, {len(cases)} runtime cases', flush=True)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
(directory / 'results.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(f'RESULTS {directory / "results.json"}', flush=True)
