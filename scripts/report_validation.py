"""Summarize a saved native validation run without rerunning programs."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', type=Path)
args = parser.parse_args()
result = json.loads(args.results.read_text(encoding='utf-8'))
directory = args.results.resolve().parent
variants = result['variants']
checks = [case for row in variants for case in row['cases'].values()]
lines = [
    '# Native validation report', '',
    f"{sum(v['status'] == 'passed' for v in variants)}/{len(variants)} variants passed; "
    f"{sum(bool(c.get('matches_original')) for c in checks)}/{len(checks)} executed cases matched the original.", '',
    'Matching requires identical exit code, stdout, and stderr, with no timeout or launch error. '
    'Every active mode must change original executable bytes. Control runs may only update the PE checksum.', '',
    '| Target | Variants passed | Cases matched | Default output growth (bytes) |',
    '| --- | ---: | ---: | ---: |',
]
for name, original in result['targets'].items():
    rows = [row for row in variants if row['target'] == name]
    cases = [case for row in rows for case in row['cases'].values()]
    growth = [row['output_bytes'] - row['input_bytes'] for row in rows if row['mode'] == 'default' and 'output_bytes' in row]
    growth_label = f'{min(growth):,}–{max(growth):,}' if growth else 'unavailable'
    lines.append(f"| {name} | {sum(row['status'] == 'passed' for row in rows)}/{len(rows)} | "
                 f"{sum(bool(c.get('matches_original')) for c in cases)}/{len(cases)} | {growth_label} |")
lines += ['', '## Modes and coverage', '',
          'Modes: control, segment only, reorder only, shuffle only, and all passes. '
          'Active modes use seeds 1397311314, 7, and 42; the control uses one seed.', '',
          'Rust cases cover arithmetic, sorting, recursion/iteration, caught panic, and errors. '
          'ripgrep cases cover literal/regex, Unicode, multiline, recursive search, no matches, and invalid syntax. '
          'MSVC EXE/DLL cases cover callbacks, switch dispatch, nested exceptions/destructors, sorting, threads, '
          'stack walking, and errors. DLLs load in fresh Python processes through their exported entry.', '']
for name, covered in result.get('relocated_stackwalk_coverage', {}).items():
    rows = [row for row in variants if row['target'] == name and row.get('relocated_stackwalk')]
    lines.append(f'- {name}: relocated stack-walk coverage = {covered}; {len(rows)} variants have '
                 'an exported walk entry jumping into `.sbrk`, a corresponding runtime-function entry, '
                 'and runtime results in `results.json`.')
benchmark_file = directory / 'benchmark.json'
if benchmark_file.exists():
    benchmark = json.loads(benchmark_file.read_text(encoding='utf-8'))
    lines += ['', '## Repeated paired benchmark', '',
              f"{benchmark['samples']} measured samples per executable, after two warmup pairs; "
              'randomized original/transformed order. Process startup is included. Outputs are compared.', '',
              '| Workload | Original median (ms) | Transformed median (ms) | Change |',
              '| --- | ---: | ---: | ---: |']
    for name, measurement in benchmark['workloads'].items():
        med = measurement['median_seconds']
        lines.append(f"| {name} | {med['original'] * 1000:.3f} | {med['transformed'] * 1000:.3f} | "
                     f"{measurement['median_change_percent']:+.2f}% |")
    lines += ['', 'These measurements describe this host and these workloads. They do not establish zero overhead.']
lines += ['', '## Original inputs', '']
for name, original in result['targets'].items():
    lines.append(f"- {name}: {original['bytes']:,} bytes; SHA-256 `{original['sha256']}`.")
lines += ['', '## Evidence and limits', '',
          '`results.json` retains per-case output bytes, exit codes, timing, transform logs, and output hashes. '
          '`benchmark.json` retains every measured sample. Original hashes are checked after the runtime matrix.', '',
          'This finite test matrix does not prove arbitrary-binary equivalence. Handler-bearing/chained/newer '
          'unwind functions and unresolved control flow remain outside relocation support. Passing exception '
          'tests does not mean language-specific exception tables were rewritten.', '']
output = directory / 'REPORT.md'
output.write_text('\n'.join(lines), encoding='utf-8')
print(output)
