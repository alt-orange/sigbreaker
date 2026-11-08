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
    f"{sum(v['status'] == 'unsupported_rebuild' for v in variants)} variants were explicitly rejected by rebuild compatibility checks; these are not counted as passed transformations.", '',
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
          'Modes: control, segment only, reorder only, shuffle only, all passes, and expanding segment injection. '
          'Active modes use seeds 1397311314, 7, and 42; the control uses one seed.', '',
          'Rust cases cover arithmetic, sorting, recursion/iteration, caught panic, and errors. '
          'ripgrep cases cover literal/regex, Unicode, multiline, recursive search, no matches, and invalid syntax. '
          'MSVC EXE/DLL cases cover callbacks, switch dispatch, nested exceptions/destructors, sorting, threads, '
          'stack walking, and errors. DLLs load in fresh Python processes through their exported entry. '
          'The native SEH/assembly fixture focuses on control, shuffle, combined, and growing-prefix modes; '
          'it tests raised exceptions, access violations, nested finally/filter scopes, chained unwind, '
          'and import tail jumps. Individual prefix/scheduler modes are exercised on the other targets.', '']
for name, covered in result.get('relocated_stackwalk_coverage', {}).items():
    rows = [row for row in variants if row['target'] == name and row.get('relocated_stackwalk')]
    lines.append(f'- {name}: relocated stack-walk coverage = {covered}; {len(rows)} variants have '
                 'an exported walk entry reaching rewritten executable code, a corresponding runtime-function entry, '
                 'and runtime results in `results.json`.')
benchmark_file = directory / 'benchmark.json'
stress_file = directory / 'exception-layouts.json'
if stress_file.exists():
    stressed = json.loads(stress_file.read_text(encoding='utf-8'))
    lines += ['', '## Exception layout stress checks', '',
              f"{sum(bool(c['passed']) for c in stressed)}/{len(stressed)} cases passed with both shuffled "
              'and growing-prefix layouts over additional seeds. Each layout requires actual SEH/chained/'
              'import-tail relocation, rewritten SEH unwind records, and a fixed chained primary.']
for export, covered in result.get('relocated_exception_coverage', {}).items():
    lines.append(f'- {export}: verified relocation and matching native exception/stack/tail behavior = {covered}.')
reprocess_file = directory / 'reprocess.json'
if reprocess_file.exists():
    reprocessed = json.loads(reprocess_file.read_text(encoding='utf-8'))
    lines += ['', '## Reprocessing', '',
              f"{sum(bool(c['passed']) for c in reprocessed)}/{len(reprocessed)} repeated-processing runtime cases passed. "
              'Successful supported outputs were transformed three further times. `reprocess.json` retains the checks; '
              'per-pass logs retain transformation reports.']
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
          'This finite test matrix does not prove arbitrary-binary equivalence. Recognized C-specific SEH '
          'scope tables are rewritten. Supported secondary chains reuse their unchanged records and pinned '
          'primary. Named FH3/FH4, explicitly mapped static handlers, unwind V2, bounded jump tables, '
          'and guarded continuations have separate structural/runtime checks. Opaque handlers can be '
          'preserved through the append fallback. Unwind V3, arbitrary indirect dispatch, and general '
          'reference closure remain unsupported. These main-matrix results alone do not establish '
          'actual C++ handler relocation; use validate_cpp_layouts.py for that evidence.', '']
output = directory / 'REPORT.md'
output.write_text('\n'.join(lines), encoding='utf-8')
print(output)
