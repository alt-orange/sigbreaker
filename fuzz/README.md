# Coverage-guided fuzzing

Run from the repository root on Windows with Rust nightly, MSVC x64 tools, and
Visual Studio's Clang/libFuzzer component installed:

```powershell
./scripts/build_cpp_fixture.ps1
./scripts/run_fuzz.ps1 -Seconds 60
```

The first build uses cached Cargo dependencies (`--offline`). The checked-in
Cargo.lock fixes the harness dependencies. The driver instruments the Rust
library and dependencies with LLVM SanitizerCoverage, 8-bit counters, PC tables,
and comparison tracing. COFF section markers register the arrays with libFuzzer;
startup verifies matching counter/PC counts. Overflow checks are enabled.

The target parses and lifts inputs, applies prefix injection and scheduling,
attempts relocation, checks that rejected relocation leaves the image unchanged,
and reparses/relifts accepted output. No input PE is executed. This harness uses
coverage instrumentation, not AddressSanitizer. Runtime equivalence is tested by
the separate native validation scripts.

Synthetic seeds and optional compiled exception fixtures populate the corpus.
Logs, generated inputs, and crash artifacts stay under `target/coverage-fuzz/`.
The corpus persists between runs. A smoke run is not exhaustive coverage.
