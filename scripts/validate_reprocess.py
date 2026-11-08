"""Reprocess saved native outputs repeatedly and compare to original behavior."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', type=Path)
args = parser.parse_args()
result = json.loads(args.results.read_text(encoding='utf-8'))
workspace = Path(__file__).resolve().parent.parent
tool = workspace / 'target' / 'release' / 'sigbraker.exe'
directory = args.results.resolve().parent
flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
checks = []
skipped = []
for name in result['targets']:
    selected = next(row for row in result['variants'] if row['target'] == name and row['mode'] == 'default' and row['seed'] == 42)
    if selected['status'] == 'unsupported_rebuild':
        skipped.append(name)
        print(f'UNSUPPORTED {name}: no successful default rebuild to reprocess', flush=True)
        continue
    assert selected['status'] == 'passed'
    source = Path(selected['output'])
    cases = [(case, [case]) for case in result['targets'][name]['baseline']] if name in ('native_cpp', 'native_dll', 'native_seh') else (
        [('version', ['--version'])] if name == 'ripgrep' else [('primes_1000', ['primes', '1000'])])
    for iteration in range(1, 4):
        output = directory / f'{name}.reprocess.{iteration}{source.suffix}'
        transform = subprocess.run([str(tool), str(source), '-o', str(output), '--seed', str(iteration), '--shuffle-prob', '1'], capture_output=True, timeout=45, creationflags=flags)
        (directory / f'{name}.reprocess.{iteration}.log').write_bytes(transform.stdout + transform.stderr)
        if transform.returncode:
            raise SystemExit(f'Reprocessing failed: {name}/{iteration}: {transform.stderr.decode(errors="replace")}')
        for case, commands in cases:
            command = [str(output), *commands]
            if name == 'native_dll':
                command = [sys.executable, str(workspace / 'scripts' / 'dll_probe.py'), *command]
            observed = subprocess.run(command, capture_output=True, timeout=10, creationflags=flags)
            baseline = result['targets'][name]['baseline'][case]
            assert (observed.returncode, observed.stdout.hex(), observed.stderr.hex()) == (baseline['exit'], baseline['stdout'], baseline['stderr']), f'{name}/{iteration}/{case} mismatch'
            checks.append({'target': name, 'iteration': iteration, 'case': case, 'passed': True})
        print(f'PASSED {name} reprocessing {iteration}: {len(cases)} cases', flush=True)
        source = output
(directory / 'reprocess.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
(directory / 'reprocess-unsupported.json').write_text(json.dumps(skipped), encoding='utf-8')
print(f'{len(checks)} reprocessed runtime cases passed')
