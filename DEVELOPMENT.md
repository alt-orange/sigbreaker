# Implementation status

All three core passes are implemented within the supported boundaries in README.
Expanded block layout supports eligible plain-v1 functions, recognized C-specific
SEH scope tables, and secondary unwind chains ending in a pinned plain primary. Unsupported functions remain in place; this is not general rewriting
of arbitrary PE binaries.

| Area | Implementation |
| --- | --- |
| PE parsing | `src/pe.rs`: sections, exports, runtime entries, unwind headers, base fixups, checksum |
| SEH scopes | `src/exception.rs`: named-import handler identity, scope parsing, interval splitting and continuation mapping |
| Discovery | `src/analysis.rs`: metadata extents; recursive entry/export/call roots otherwise; reachability pinning |
| Scheduling | `src/dependencies.rs`, `src/transforms/reorder.rs`: dependency DAG and randomized topological order |
| Prefixes | `src/transforms/segment_inject.rs`: whitelist and equal-length encoding |
| Expanded layout | `src/transforms/relayout.rs`: address map, fall-through jumps, branch relaxation, RIP relocation, decoded-output checks |
| PE writing | `src/writer.rs`: append-only section, combined runtime table, transactional in-memory commit and atomic output publication |
| Legacy layout | `src/transforms/shuffle.rs`: fixed-span chain permutations for metadata-free inputs |
| Integration | `src/pipeline.rs`: ordered passes, relifting, checks, reporting, publication |

## Preservation contract

Relocated functions keep their original entry address through a jump. Prologue
bytes must remain identical, so their version-1 unwind code offsets still apply
to the new begin address. Stack-restoring epilogues must remain contiguous in one
block. Old bodies and old runtime entries are retained. The new exception data
directory includes both old and new entries in address order.

Generated code must need no new absolute relocation fixups; layouts needing
absolute branch stubs are rejected. Existing fixups pin source instructions.
Known interior code-address references exclude a function from relocation.

Relevant format references are Microsoft's
[PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64),
and [prologue/epilogue rules](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog).

## Validation evidence

Portable Rust tests cover dependency aliases and flags, control-flow edges,
metadata pinning, recursive discovery and exports, malformed PE sections,
branch widening, RIP targets, address-taken code, deterministic expanded output,
overlay preservation, and failed output publication. A small control-flow
interpreter tests both paths of a relocated fixture through its entry trampoline.

`scripts/validate_native.py --cpp` validates a compiled Rust program, installed
ripgrep, an optimized MSVC executable, and a DLL loaded in fresh processes. Each
active pass must change executable bytes and match original behavior. Logs and
hashes identify exactly what was tested. `scripts/benchmark_native.py` records
paired timings with warmup, randomized order, and output checks.

## Deliberately unsupported scope

C++ exception metadata and unknown handler formats need dedicated parsers before
those functions can move. Chains terminating in handlers, newer unwind formats,
unresolved indirect jumps, arbitrary code/data mixtures, and
references from undiscovered code remain outside the relocation contract.
Absence of a known reference is not proof that an unknown indirect reference
does not exist. Additional program coverage and format support must be validated
separately; passing this test matrix is not a universal equivalence guarantee.

## Current follow-up implementation

- Explicit version-1 handler/chained unwind model, handler address validation,
  cycle/mismatch rejection, and protection for primary functions referenced by chains.
- Conservative read-only RVA/VA code-pointer table analysis.
- Broader non-faulting scalar scheduling, including address arithmetic.
- Expanding segment injection is enabled by default where metadata permits;
  `--no-grow-segments` opts out. All three pass probabilities default to 1.0.
- Unique relocation section names for reprocessing, plus final-section extension
  when no unused header slot exists and EOF/alignment/mapping checks permit it.
- Windows/Linux CI, Windows native validation, deterministic malformed-input
  mutation coverage, and repeated native reprocessing checks.

FH3/FH4 and newer unwind translation, general jump-table
rewriting, and deleting original bodies are still unfinished. Original bodies must
remain available while reference discovery and exception table relocation are
incomplete. Register-derived targets cannot be treated as resolved by scanning data.

## Exception and import-tail support

`src/exception.rs` resolves named imports through direct/indirect handler thunks
and handles AMD64 C-specific SEH scope tables. It preserves nested scope priority,
splits intervals using emitted instruction spans, and maps exception continuations.
Synthetic fall-through jumps inherit their original successor PC for scope membership.
The writer publishes copied unwind slots with rewritten scope data beside code.
Known scope-table references are owned metadata rather than opaque pointers.

Chained secondary regions can move when their chain ends at a plain primary;
primary ranges stay pinned. RIP-relative indirect tail jumps through known named
IAT slots retain their original memory target and contiguous restore sequence.
`native_seh.c` and `native_chain.asm` test actual moved handler functions, a chained
body, stack walking, exception propagation across that body, nested finally/filter
execution, and import tail dispatch. These checks are distinct from merely testing
preserved C++ handler functions.
