# Implementation status

This implementation expands compatibility and relocation coverage within explicit
bounds. It does not implement general rewriting of arbitrary PE programs.

| Area | Implementation |
| --- | --- |
| PE parsing | `src/pe.rs`: sections, directories, imports, runtime entries, unwind/guard metadata, base fixups |
| C-specific SEH/GS | `src/exception.rs`: handler identity, linker maps, scope splitting, GS descriptors |
| C++ EH | `src/cpp_eh.rs`: typed FH3 records, FH4 compressed maps, relocated state/continuation maps |
| Unwind V2 | `src/unwind.rs`: validated epilogue descriptors and rebuilt distances |
| Indirect targets | `src/indirect.rs`: conservative constant facts, direct address-use checks, bounded jump tables |
| Discovery | `src/analysis.rs`: metadata extents, recursive roots, reachability, reference provenance |
| Scheduling | `src/dependencies.rs`, `src/transforms/reorder.rs`: fault barriers, aliases, private-stack proof, saved registers |
| Expanded layout | `src/transforms/relayout.rs`: instruction/span maps, branch relaxation, typed code/table/guard fixups |
| PE writing | `src/writer.rs`, `src/rebuild.rs`: typed rebasing, append fallback, expanded headers, raw offsets, atomic publication |
| Fuzzing | `fuzz/`, `scripts/run_fuzz.ps1`: instrumented Rust static library and Windows libFuzzer driver |

## Preservation contract

Entry trampolines preserve original function-pointer identity and existing CFG
entries. Prologue bytes stay unchanged. Supported epilogues remain contiguous.
Typed interior pointers and table entries are rewritten only after complete
instruction maps exist. Arithmetic on code addresses does not establish a
rewritable pointer. Unknown register writes, joins, and missing table bounds
invalidate indirect-target facts.

The relocation pass always emits into an appended executable section. Input
executable sections may have any name. Original RVAs and runtime entries are
preserved. By default the writer scrubs original bodies that pass the reference
checks, and its guarded-continuation table keeps surviving and relocated
targets. New absolute load-config values require an
existing ASLR relocation when the image enables dynamic base relocation.

Static handler support requires a matching explicit linker map. Merely accepting
an image with an opaque handler is not evidence that this handler moved. The
native C++ runner separately asserts actual exported exception-parent relocation.

## Local validation evidence

The optional section-compression path embeds the public-domain LZMA SDK 25.01
decoder. Its source is in `src/compression/decoder.c`; regenerate the checked-in
Windows x64 code and unwind metadata with `python scripts/build_section_decoder.py`.
Normal Cargo builds use the embedded bytes. `scripts/validate_section_compression.py`
executes compressed EXE/DLL fixtures, including a live ASLR pointer probe,
guarded EH, nested C++ rethrows, threads, stack walking, and repeat processing.

Completed local runs before the final edge-case checks:

- Main matrix: 74/74 variants passed, 680/680 executed behavior checks matched;
  zero unsupported rebuilds, runtime mismatches, or unchanged active variants.
  This replaces the previous run with 36 opaque-metadata rejections.
- Additional C++ matrix: 40/40 layouts and 320/320 runtime checks passed across
  MSVC static CRT, imported FH3, imported FH4, guarded EH, and Clang. Each requires
  the exception parent to move and preserve handler metadata.
- Coverage-guided fuzzing: 19,938 executions over 31 seconds, no crash, coverage
  grew from 6,787 to 8,067 edges/features reported as `cov` by libFuzzer. The run
  registered matching arrays of 26,583 counters and PCs. This is finite smoke
  coverage, not an exhaustive campaign or an AddressSanitizer run.
- Rust regression tests cover malformed inputs, actual state-map remapping,
  explicit GS trailers, guarded-table growth, jump tables, register-derived
  jumps, interior address fixups, header/overlay preservation, version-2 epilogues,
  and complete register/stack-state comparison after private-stack scheduling.

Artifacts are retained locally under `target/runtime-validation/`,
`target/cpp-validation/`, and `target/coverage-fuzz/`. The main runner now exits
with failure on unsupported rebuilds rather than treating them as an acceptable
CI outcome. GitHub Actions were excluded at the user's request.

## Unfinished work

- Unwind V3/APX relocation and runtime validation.
- General indirect control flow and arithmetic-derived interior pointers beyond
  the recognized constant and bounded-table forms.
- Scheduling arbitrary memory operations or stack-pointer changes while fully
  preserving fault and unwind state.
- General proof of reference closure and retirement of all bodies retained by
  the append fallback.
- Remaining unusual PE layouts, including low-alignment inputs.
- Larger compiler/application corpora and longer fuzzing campaigns.

Relevant specifications: Microsoft's PE format and x64 exception-handling docs,
MSVC `ehdata.h` / `ehdata4_export.h`, and LLVM's SanitizerCoverage/libFuzzer docs.
