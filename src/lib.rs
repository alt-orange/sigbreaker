//! SigBreaker 1.0 — a binary diversification engine for 64-bit x86 PE files.
//!
//! SigBreaker is built on top of BLARE, a lightweight binary transformation
//! layer that heuristically lifts executable sections into an instruction-level
//! representation (functions → basic blocks → instructions), applies
//! diversification passes, and emits a validated PE image:
//!
//! 1. **Segment selector injection** — random segment override prefixes are
//!    injected into instructions with memory operands, chosen from a
//!    user-configurable whitelist (FS/GS excluded by default).
//! 2. **Instruction reordering** — a dependency DAG is built per basic block
//!    (register RAW/WAR/WAW, memory ordering, calls, flags) and a randomized
//!    variant of Kahn's algorithm produces a valid topological order.
//! 3. **Basic block shuffling** — chains of basic blocks that pass movement
//!    checks are relayouted, with recognized direct branches patched explicitly.
//! 4. **Junk code injection** — unreachable gaps in relocated bodies (after
//!    unconditional terminators) are padded with random inert instructions
//!    (multi-byte nops, int3, segment prefixes) and inter-function padding is
//!    randomized, shattering byte-signature matches without touching any
//!    executed path.
//!
//! Supported version-1 functions can grow or move with updated runtime entries
//! and recognized C-specific SEH scopes. Unknown exception formats and unresolved
//! code references restrict movement. Structural checks and finite runtime tests
//! do not establish equivalence for arbitrary input binaries.

pub mod analysis;
pub mod cli;
pub mod cpp_eh;
pub mod dependencies;
pub mod exception;
pub mod indirect;
pub mod pe;
pub mod pipeline;
pub mod rebuild;
pub mod stats;
pub mod transforms;
pub mod unwind;
pub mod verify;
pub mod writer;
