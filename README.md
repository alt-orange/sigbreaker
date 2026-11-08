# SigBreaker 1.0

SigBreaker is an experimental binary diversification tool for x86-64 PE images.
It implements configurable segment-prefix injection, dependency-based instruction
scheduling, and basic-block shuffling. Supported Windows runtime functions can be
relocated into an appended `.sbrk` section with explicit jumps and updated unwind
lookup entries. Files can grow when this pass runs.

## Build and use

```powershell
cargo build --locked --release
target/release/sigbraker.exe app.exe -o app.div.exe --seed 42
target/release/sigbraker.exe app.exe --info
target/release/sigbraker.exe --help
```

`--info` analyzes without writing. The default destination is
`<input-stem>.sigbrk.exe`; specify `-o` for a DLL destination. Output is written to
an adjacent temporary file and published by rename after validation. The same
input, options, seed, and tool build produce identical output.

The report prints `transformed: N/T functions (P%)`. This counts unique analyzed
functions whose final original code span changed, including entry jumps to
relocated code. Header/checksum changes and reverted edits do not count.
The denominator includes all lifted functions, including unsupported ones.
Default probabilities are `1.0`, and growing prefixes are enabled wherever the
input supports expanded layout. Every eligible transformation is attempted;
unsupported functions still retain their existing code layout.
Expanded-layout reports list separate reasons for exclusions, including metadata,
interior references, stack restoration, and insufficient blocks for shuffling.

The default command selects the full coverage settings:

```powershell
sigbraker app.exe
```

Growing prefixes support one- and two-block functions as well as larger ones;
actual block shuffling still requires at least three blocks with entry kept first.

| Option | Default | Purpose |
| --- | --- | --- |
| `--seed` | `1397311314` | Seed for all transformation randomness |
| `--seg-prob` | `1.0` | Probability per eligible memory instruction |
| `--grow-segments` | on | Grow prefixes in eligible relocated functions |
| `--no-grow-segments` | off | Restrict prefixes to existing instruction lengths |
| `--segments` | `es,cs,ss,ds` | Segment-prefix whitelist |
| `--reorder-prob` | `1.0` | Probability per eligible scheduling unit |
| `--shuffle-prob` | `1.0` | Probability per eligible function |
| `--no-seg-inject` | off | Disable prefix injection |
| `--no-reorder` | off | Disable scheduling |
| `--no-shuffle` | off | Disable block movement |
| `--no-verify` | off | Disable the in-place decode check |

## Implemented transformations

### Segment-prefix injection

The pass inserts an allowed segment override when the instruction can be encoded
at its original length. Removing a redundant zero displacement can make room for
the prefix. Instructions without room, existing explicit segment overrides,
unreachable instructions, and relocation-protected bytes are skipped.
With `--grow-segments`, eligible supported functions can instead be relocated with
longer prefixed encodings. Prologues keep their bytes and epilogues remain contiguous; this mode
uses explicit jumps even with `--no-shuffle`. Without runtime metadata, injection
automatically falls back to the existing instruction lengths. `--no-seg-inject`
disables both forms; `--no-grow-segments` keeps in-place prefix injection enabled.

FS and GS are excluded by default because their bases can affect memory addresses.
Enabling them requires an environment where the resulting addressing is equivalent;
merely having valid segment descriptors does not establish equivalence.

### Instruction scheduling

A dependency DAG tracks RAW, WAR, and WAW dependencies, overlapping register
families, flag reads and modifications, memory ordering, calls, and barriers.
Randomized Kahn topological sorting selects a valid dependency order.

For plain version-1 Windows unwind functions, scheduling is restricted to
equal-length runs of non-faulting scalar operations on volatile registers.
Prologues, stack changes, nonvolatile-register operations, memory operations, and
calls retain their positions. Scalar LEA, integer multiply, shifts, rotates, and
byte swaps are eligible when their operands and implicit state satisfy the same
volatile-register and dependency checks. Handler-bearing, chained, unknown-format, and
indirect-branch functions are excluded from this scheduler.

Images without runtime metadata use a broader experimental scheduler. Known
interior code references prevent movement; the dependency model is not a proof of
equivalence for arbitrary machine instructions or asynchronous exceptions.

### Basic-block shuffling

For supported metadata-backed functions, the entry block stays first and the
remaining blocks are permuted. Explicit jumps preserve fall-through edges.
The encoder relaxes short branches and recalculates RIP-relative displacements.
An old-to-new instruction map is checked against independently decoded output,
including branch destinations and memory targets.

The writer appends code in `.sbrk`, installs five-byte entry jumps, and publishes
a sorted table containing original and relocated runtime-function entries.
Unchanged prologue unwind descriptions are reused. Original function bodies,
section offsets, exports, and overlay bytes retain their original locations.
Existing direct callers and function pointers continue through the original entry.

Eligibility requires a fully decoded, reachable function with resolved local
control flow (plus recognized import tail exits), a complete unchanged prologue, contiguous supported epilogues,
and no known interior address references. Unsupported branch expansions, indirect
jumps, unknown handler formats, and relocation-pinned instructions prevent
relocation. RIP-relative indirect tail jumps through named import slots are
supported while retaining the same IAT slot and stack-restoring epilogue. New sections receive unique `.sbrk`, `.sbrk1`, etc. names when an image is
reprocessed. If no header slot is free, the final section can grow when it ends
at EOF, has no virtual-only tail, and meets alignment constraints. Existing raw
offsets are retained. Unsupported extension layouts fail before publication.

Without runtime metadata, the fallback shuffles in-place chains connected by
fall-through. If branch displacements cannot fit, the attempted move is reverted.

## Discovery and verification

Runtime-function extents come from the PE exception data directory. Without that
metadata, recursive decoding starts at the entry point, exports, and decoded
direct-call targets. Raw `E8` bytes in data do not create function roots.
Forwarded exports are excluded. Only instructions reachable through recognized
edges are eligible for rewriting; ambiguous interior branch targets pin a region.

The parser rejects truncated and overlapping sections and malformed relevant
directories. Base relocations are read by directory, independently of section
names. Absolute relocated code pointers, exported addresses, decoded calls,
cross-function branches, and RIP-relative code references constrain movement.
Read-only non-code sections are also scanned for aligned RVA and absolute-VA
code pointers. Candidates conservatively restrict movement; arbitrary relative
jump tables and register-derived targets remain unresolved.

Version-1 handler and chained records are explicitly represented. Handler RVAs
are checked; chain cycles, mismatched primary records, and unresolved chains are
rejected. Primary code referenced by a chain is pinned. Secondary version-1
chains ending at a plain primary can relocate while reusing the unchanged chain
record. The primary itself remains fixed.

Recognized AMD64 `__C_specific_handler` thunks imported from supported Microsoft
runtime DLLs enable SEH scope relocation. Scope boundaries and exception entry
points split blocks. New unwind records preserve the prologue slots and rewrite
scope intervals and exception continuation RVAs, including split/nested scopes.
Filters and finally funclets retain their original entry addresses. Unknown
handlers and in-function filter funclets remain unsupported. Images using guarded
EH continuation tables retain these functions in place until that table can be
rewritten. Static CRT wrappers and C++ FH3/FH4 are not inferred from byte patterns.

In-place verification checks decoding and instruction counts. Generated-layout
verification additionally checks instruction operands and destinations, and the
complete expanded PE is reparsed before publication. These structural checks do
not prove runtime equivalence. Test the output against the application's behavior.

## Validation

```powershell
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
./scripts/build_cpp_fixture.ps1
python scripts/validate_native.py --cpp
python scripts/benchmark_native.py target/runtime-validation/run-YYYYMMDD-HHMMSS/results.json
python scripts/validate_reprocess.py target/runtime-validation/run-YYYYMMDD-HHMMSS/results.json
python scripts/validate_exception_layouts.py target/runtime-validation/run-YYYYMMDD-HHMMSS/results.json
python scripts/report_validation.py target/runtime-validation/run-YYYYMMDD-HHMMSS/results.json
```

The Windows runtime runner requires Rust and ripgrep on PATH. The optional C++ EXE
and DLL fixtures require MSVC x64 build tools. It compares stdout, stderr, and exit
codes across control, individual-pass, and combined modes, using three seeds for
each active mode. Enabled modes must change original executable bytes; skipped
transformations do not count as successful transformation coverage.

Coverage includes branching, sorting, Unicode and multiline search, errors,
callbacks, switch tables, nested C++ exceptions and destructors, threads, stack
walking, DLL loading, and exports. Results, original hashes, generated files,
and per-transform logs are retained under `target/runtime-validation/`.
Two manual debugging harnesses are ignored by default and require explicit paths
through `SB_INPUT` / `SB_OUTPUT`; ordinary tests need no private local files.

## Boundaries

- AMD64 PE32+ only. Packed, self-modifying, overlapping-code, and deliberately
  obfuscated inputs are outside the supported scope.
- C++ FH3/FH4, unknown handler tables, unresolved jump tables, and newer unwind
  formats remain unsupported. The native SEH fixture explicitly checks exported
  handler functions and a chained secondary region moved before testing exceptions.
- Undeclared indirect targets and references from unlifted code are not fully
  discoverable. Metadata-free transformation remains experimental.
- Added jumps, code growth, and changed locality can affect performance. There
  is no zero-overhead guarantee; the benchmark records repeated paired samples.
- Rewriting changes signed image contents. Existing signatures and application
  integrity checks are not regenerated.

See [DEVELOPMENT.md](DEVELOPMENT.md) for the implementation map and remaining scope.

The CI workflow runs Rust checks on Windows and Linux and native validation on
Windows. A reproducible mutation smoke test exercises 2,048 malformed-input cases.
Reprocessing validation runs saved native outputs through three further passes.
