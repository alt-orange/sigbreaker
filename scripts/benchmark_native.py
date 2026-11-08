"""Repeat paired native workloads; record output equivalence and wall time.

Usage: python scripts/benchmark_native.py target/runtime-validation/run-.../results.json
Timings include process startup and are observations, not performance guarantees.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', type=Path)
parser.add_argument('--samples', type=int, default=9)
args = parser.parse_args()
if args.samples < 3:
    parser.error('--samples must be at least 3')
validation = json.loads(args.results.read_text(encoding='utf-8'))
if any(row['status'] != 'passed' for row in validation['variants']):
    raise SystemExit('Benchmark requires a successful validation matrix')
directory = args.results.resolve().parent
corpus = directory / 'benchmark-corpus.txt'
line = b'alpha beta number=123456 gamma delta zeta\n'
with corpus.open('wb') as out:
    for _ in range(64):
        out.write(line * 16384)
workloads = {
    'ripgrep': ['--color', 'never', '-c', r'number=[0-9]+', str(corpus)],
    'native_probe': ['primes', '500000'],
}
report = {'samples': args.samples, 'includes_process_startup': True, 'workloads': {}}
rng = random.Random(42)
for name, commands in workloads.items():
    row = next(v for v in validation['variants'] if v['target'] == name and v['mode'] == 'default' and v['seed'] == 42)
    binaries = {'original': validation['targets'][name]['original'], 'transformed': row['output']}
    for key, binary in binaries.items():
        expected_hash = validation['targets'][name]['sha256'] if key == 'original' else row['sha256']
        if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != expected_hash:
            raise SystemExit(f'Validation artifact changed: {binary}')
    samples = {key: [] for key in binaries}
    expected = None
    for iteration in range(args.samples + 2):
        order = list(binaries)
        rng.shuffle(order)
        for key in order:
            start = time.perf_counter()
            proc = subprocess.run([binaries[key], *commands], capture_output=True, timeout=30,
                                  creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            elapsed = time.perf_counter() - start
            observed = (proc.returncode, proc.stdout, proc.stderr)
            if expected is None:
                if proc.returncode != 0:
                    raise SystemExit(f'Benchmark baseline failed: {name}')
                expected = observed
            if observed != expected:
                raise SystemExit(f'Benchmark behavior mismatch: {name}/{key}')
            if iteration >= 2:
                samples[key].append(elapsed)
    medians = {key: statistics.median(values) for key, values in samples.items()}
    report['workloads'][name] = {'arguments': commands, 'seconds': samples, 'median_seconds': medians,
                                 'median_change_percent': 100 * (medians['transformed'] / medians['original'] - 1)}
    print(f"{name}: original {medians['original']:.6f}s, transformed {medians['transformed']:.6f}s, "
          f"change {report['workloads'][name]['median_change_percent']:+.2f}%")
output = directory / 'benchmark.json'
output.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(output)
