"""Stress known relocated SEH/chained/import-tail fixtures across layout seeds."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
from pe_fixture_checks import relocated_export

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', type=Path)
parser.add_argument('--seeds', type=int, default=24)
args = parser.parse_args()
if args.seeds < 1:
    parser.error('--seeds must be positive')
saved = json.loads(args.results.read_text(encoding='utf-8'))
source = Path(saved['targets']['native_seh']['original'])
directory = args.results.resolve().parent / 'exception-layouts'
directory.mkdir(exist_ok=True)
tool = Path(__file__).resolve().parent.parent / 'target' / 'release' / 'sigbraker.exe'
flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
ctypes.windll.kernel32.SetErrorMode(0x8003)
rows = []
for seed in range(args.seeds):
    for growing in (False, True):
        tag = f'{seed}.{"grow" if growing else "shuffle"}'
        output = directory / f'{tag}.exe'
        command = [str(tool), str(source), '-o', str(output), '--seed', str(seed), '--no-reorder', '--shuffle-prob', '1']
        command += ['--grow-segments', '--seg-prob', '1'] if growing else ['--no-seg-inject']
        proc = subprocess.run(command, capture_output=True, timeout=15, creationflags=flags)
        (directory / f'{tag}.log').write_bytes(proc.stdout + proc.stderr)
        assert proc.returncode == 0, f'transform failed: {tag}'
        data = output.read_bytes()
        moved = {name: relocated_export(data, name) for name in ('seh_probe', 'seh_nested', 'chained_body', 'tail_probe')}
        assert all(moved.values()), f'missing transformation coverage: {tag}: {moved}'
        assert relocated_export(data, 'chained_probe') is None, 'primary chain region moved'
        for name in ('seh_probe', 'seh_nested'):
            assert moved[name]['original_unwind_rva'] != moved[name]['relocated_unwind_rva'], 'handler record was not rewritten'
        assert moved['chained_body']['original_unwind_rva'] == moved['chained_body']['relocated_unwind_rva'], 'chain record must remain fixed'
        for case, baseline in saved['targets']['native_seh']['baseline'].items():
            run = subprocess.run([str(output), case], capture_output=True, timeout=5, creationflags=flags)
            assert (run.returncode, run.stdout.hex(), run.stderr.hex()) == (baseline['exit'], baseline['stdout'], baseline['stderr']), f'exception behavior mismatch: {tag}/{case}'
            rows.append({'seed': seed, 'growing': growing, 'case': case, 'passed': True})
(args.results.resolve().parent / 'exception-layouts.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(f'{len(rows)} exception layout/runtime cases passed across {2 * args.seeds} transformed variants')
