//! SigBreaker 1.0 — a binary diversification engine for 64-bit x86 PE files.
//!
//! SigBreaker is built on top of BLARE, a lightweight binary transformation
//! layer that heuristically lifts executable sections into an instruction-level
//! representation (functions → basic blocks → instructions), applies
//! diversification passes, and writes the result back in place:
//!
//! 1. **Segment selector injection** — random segment override prefixes are
//!    injected into instructions with memory operands, chosen from a
//!    user-configurable whitelist (FS/GS excluded by default).
//! 2. **Instruction reordering** — a dependency DAG is built per basic block
//!    (register RAW/WAR/WAW, memory ordering, calls, flags) and a randomized
//!    variant of Kahn's algorithm produces a valid topological order.
//! 3. **Basic block shuffling** — chains of basic blocks that pass movement
//!    checks are relayouted, with recognized direct branches patched explicitly.
//!
//! Every transformation preserves file and section sizes. Internal instruction
//! addresses can change; unwind metadata, exception tables, and indirect code
//! references are not comprehensively validated or rewritten. Re-decoding checks
//! instruction validity and counts, not behavioral equivalence.

pub mod analysis;
pub mod cli;
pub mod dependencies;
pub mod pe;
pub mod pipeline;
pub mod stats;
pub mod transforms;
pub mod verify;
pub mod writer;
