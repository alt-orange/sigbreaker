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

| Option | Default | Purpose |
| --- | --- | --- |
| `--seed` | `1397311314` | Seed for all transformation randomness |
| `--seg-prob` | `0.35` | Probability per eligible memory instruction |
| `--segments` | `es,cs,ss,ds` | Segment-prefix whitelist |
| `--reorder-prob` | `0.5` | Probability per eligible scheduling unit |
| `--shuffle-prob` | `0.5` | Probability per eligible function |
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
calls retain their positions. Handler-bearing, chained, unknown-format, and
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

Eligibility requires a fully decoded, reachable function with a closed direct
control-flow graph, a complete unchanged prologue, contiguous supported epilogues,
and no known interior address references. Unsupported branch expansions, indirect
jumps, handler/chained unwind records, and relocation-pinned instructions prevent
relocation. A free section-header slot is required; reprocessing an existing
`.sbrk` image with relocation enabled is rejected.

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
- Language-specific exception tables, chained unwind metadata, unresolved jump
  tables, and newer unwind formats are not rewritten. A passing exception test
  can include preserved handler functions; it does not imply those were relocated.
- Undeclared indirect targets and references from unlifted code are not fully
  discoverable. Metadata-free transformation remains experimental.
- Added jumps, code growth, and changed locality can affect performance. There
  is no zero-overhead guarantee; the benchmark records repeated paired samples.
- Rewriting changes signed image contents. Existing signatures and application
  integrity checks are not regenerated.

See [DEVELOPMENT.md](DEVELOPMENT.md) for the implementation map and remaining scope.
