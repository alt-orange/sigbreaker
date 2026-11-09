# SigBreaker 1.0

SigBreaker is an experimental diversification tool for AMD64 PE32+ images. It
injects segment prefixes, schedules eligible instructions, and relocates basic
blocks with updated control-flow and Windows exception metadata.

## Build and use

```powershell
cargo build --locked --release
target/release/sigbraker.exe app.exe -o app.div.exe --seed 42
target/release/sigbraker.exe app.exe --info
target/release/sigbraker.exe --help
target/release/sigbraker.exe --tui
```

In the TUI, enter or paste the input PE path. Use **Tab** or **↑/↓** to
select a field, **Space** to flip a switch, **F2** to inspect, and **F5** to
process. The report pane shows progress, results and errors. Use **PgUp/PgDn**
to scroll it and **Esc** to quit. Leave optional fields blank to use the CLI
defaults. Build with `--no-default-features` for a CLI-only binary.

Static CRT handler identities can be supplied from the matching linker `/MAP`
file. The map must describe the exact input image:

```powershell
target/release/sigbraker.exe app.exe --handler-map app.exe.map -o app.div.exe
```

The default probabilities are `1.0`, growing prefixes are enabled, and the same
input, options, seed, and build produce identical output. `--info` writes nothing.
Output is published by an adjacent temporary file and rename after validation.
The report counts unique functions whose original code spans actually changed;
header-only edits, rejected attempts, and reverted transformations are excluded.

## Supported transformations

| Area | Implemented support |
| --- | --- |
| Prefix injection | Equal-length encodings and expanded eligible functions; ES/CS/SS/DS by default |
| Opcode aliasing | Equal-length ALU/MOV direction aliases and unused REX/SIB bits in selected legacy instructions. Relocated version-1 epilogues can widen `add rsp` immediates |
| Scheduling | Register/flag dependencies, equal-length scalar runs, proven saved nonvolatile registers and private committed stack slots |
| Exceptions | Named-import C-specific SEH and C++ FH3/FH4; explicit static CRT/GS identities from linker maps |
| Unwind | Version 1, supported secondary chains with pinned primaries, version-2 explicit epilogue rewriting |
| Guarded EH | Sorted continuation-table rewriting; retained bodies keep their original targets alongside relocated targets |
| Indirect branches | Constant register targets and bounded read-only absolute-VA, RVA, and signed-relative jump tables |
| Interior references | Verified unchanged code-address values materialized by RIP-relative LEA; function-entry pointer identity stays stable |
| PE layout | Existing `.text` growth, or an appended section with header expansion and raw-offset movement |
| Global data | Explicitly mapped initialized objects move to appended data sections with patched references |

FH3 IP-to-state maps and FH4 compressed state maps follow emitted instruction
spans, including synthetic fall-through edges. FH4 handler continuations and
separated-map records are decoded and emitted explicitly. Static handlers are
identified through symbols rather than guessed from code prefixes or metadata
bytes. Supported GS wrappers preserve their frame-relative cookie descriptors.

Jump-table recognition requires a dominating unsigned bound, an unchanged index
and base, a file-backed read-only table, and decoded local case targets. Unknown
writes and control-flow joins discard register facts. Pointer arithmetic and
unresolved dispatches remain excluded from relocation.

The scheduler treats potentially faulting memory, division, calls, fences, and
unmodeled implicit machine state as barriers. Broader memory movement requires
stack slots already written in the prologue, no stack-address escape or calls,
no ambiguous writes, and no overlap with saved unwind state. Nonvolatile writes
require a matching prologue save. Prologues and stack-restoring epilogues retain
their positions; general stack-pointer changes are not rescheduled.

## Relocation and preservation

Original function entries keep five-byte trampolines. Function-entry pointers,
exports, and existing CFG entry identities retain their original addresses.
Block encoding preserves prologue bytes, relaxes branches, updates RIP-relative
operands, and independently decodes generated code to check destinations/effects.

For eligible layouts, the writer grows `.text`, rebases typed PE references,
retires replaced runtime records, and fills obsolete bodies with `INT3` after
the trampoline. The original section set is preserved on this path.

When opaque metadata, additional executable sections, or interior fixups prevent
that strategy, a uniquely named `.sbrk` section is appended. Existing RVAs remain
fixed. Occupied header padding can be preserved by expanding the headers and
moving raw sections. Certificate, debug, COFF, and section raw offsets are fixed.
Overlay bytes are preserved. This path retains original bodies and unwind
records because reference closure is incomplete. Guarded continuation tables
retain old targets and add mapped targets; moved VA fields reuse existing ASLR
relocations. The complete result is reparsed before publication.

This fallback removes the previous opaque-exception rebuild rejections while
leaving unrecognized handler functions in place. Compatibility of a whole image
is distinct from actually relocating its exception-handling functions.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--seed` | `1397311314` | Deterministic random seed |
| `--seg-prob` | `1.0` | Prefix probability |
| `--segments` | `es,cs,ss,ds` | Prefix whitelist |
| `--reorder-prob` | `1.0` | Scheduling probability |
| `--shuffle-prob` | `1.0` | Block movement probability |
| `--junk-prob` | `1.0` | Probability of padding each eligible gap or jump-protected split in relocated code |
| `--alias-prob` | `1.0` | Opcode alias probability |
| `--no-grow-segments` | off | Restrict prefixes to original lengths |
| `--no-seg-inject` | off | Disable prefix injection |
| `--no-reorder` | off | Disable scheduling |
| `--no-alias` | off | Disable opcode aliasing |
| `--no-shuffle` | off | Disable block shuffling |
| `--wipe-original` | off | Scrub original bodies behind entry jumps when relocation appends a section. With junk enabled, eligible calls in retained bodies can jump to their relocated copies |
| `--handler-map` | none | Matching linker map for static handlers |
| `--global-map` | none | Map of initialized globals to move and their RIP-relative reference sites |
| `--global-slot` | derived from seed | Layout slot from 0 to 255 for `--global-map` |
| `--no-verify` | off | Disable the in-place decode check |

FS/GS prefixes can change addresses; use them only in an environment where that
change is intended. Structural checks do not establish arbitrary-binary runtime
equivalence. Rewriting also invalidates existing image signatures.

### Moving selected global structs

Supply a map for the exact linked input image. All addresses in this map are
RVAs (virtual addresses minus the image base), with decimal or `0x` notation.

```text
# global RVA SIZE ALIGNMENT (sizes and alignment are in bytes)
global 0x5020 24 8
# Each RIP-relative instruction that accesses the object or one of its fields
rip 0x1130
rip 0x126a
```

```powershell
target/release/sigbraker.exe game.exe --global-map globals.txt --global-slot 5 -o game.build5.exe
target/release/sigbraker.exe game.exe --global-map globals.txt --global-slot 6 -o game.build6.exe
```

For a fixed input and map, distinct explicit slots give the selected objects
distinct module-relative addresses. Each run reports the old and new RVAs.
The pass preserves field offsets and read/write permissions, retargets listed
RIP-relative instructions and incoming `DIR64` pointers, and zeroes the old
storage. The data move works with code passes disabled and with appended code.

Use this with ordinary, file-backed initialized objects in `.data` and
`.rdata`. Supply every RIP-relative reference, including references from leaf
functions outside the unwind table. A linker symbol map can help identify an
object's RVA. Its size, alignment and reference sites must come from the matching
build's symbols, code and data. Exported globals, embedded base relocations,
unlisted RVA tables, references to one-past-end addresses, and addresses
computed from a different object or section base are outside this pass's
contract. The pass rejects invalid entries and missing references it detects.

## Validation

```powershell
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
./scripts/build_cpp_fixture.ps1
python scripts/validate_native.py --cpp
python scripts/validate_cpp_layouts.py --seeds 8
./scripts/run_fuzz.ps1 -Seconds 60
```

The native runner compares exit code, stdout, and stderr across control,
individual-pass, and combined modes. Every active variant must change executable
bytes. A rejected rebuild makes the runner fail; it is never counted as a pass.
The C++ runner additionally requires the exported exception parent to relocate
before running nested exceptions/destructors. Fixtures cover Rust, MSVC, optional
Clang, ripgrep, DLL loading, SEH, stack walking, callbacks, switches, and threads.
Logs, hashes, and generated artifacts remain under `target/`.

### Signature detection

```powershell
python scripts/signature_test.py ORIGINAL PROCESSED [--prefix 256] [--baseline]
```
Builds byte-pattern signatures from every original function (branch and
rip-relative displacements plus image-range immediates are wildcarded;
opcodes, registers, and small immediates stay concrete), then reports which
signatures still match the processed binary. Results are split into two
variants - entry-anchored (offset 0) and body-anchored (offset 16, past the
entry trampoline) - and by match location: at the original site, in the
appended section, or elsewhere (collision). `--baseline` adds the rate at
which the same signatures match outside their own function in the original
binary, which contextualizes collisions, especially for short prefixes.

Saved main results can be checked further with `validate_reprocess.py`,
`validate_exception_layouts.py`, and `report_validation.py`. The fuzz harness uses
LLVM SanitizerCoverage and libFuzzer, including comparison feedback, overflow
checks, parsing/lifting, scheduling, and transactional relocation assertions.
See [fuzz/README.md](fuzz/README.md) for setup and scope.

## Remaining boundaries

Unwind V3 relocation, arbitrary indirect targets, arbitrary code-pointer
arithmetic, unrestricted memory/stack scheduling, and general proof of reference
closure remain unfinished. Unknown handler identities stay pinned. Low-alignment
and malformed/unclassifiable layouts can still be rejected. Packed,
self-modifying, overlapping-code, and deliberately obfuscated inputs are outside
the supported contract. Metadata-free rewriting remains experimental.

GitHub Actions were not run or changed during this work. See
[DEVELOPMENT.md](DEVELOPMENT.md) for the implementation map and evidence.
