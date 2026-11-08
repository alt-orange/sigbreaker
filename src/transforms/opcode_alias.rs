//! In-place opcode aliasing.
//!
//! Rewrites register-register ALU and MOV instructions into their equivalent
//! reversed-operand encoding (the MR↔RM forms differ only in opcode bit 1),
//! changing the opcode byte without changing instruction length, operand
//! order, flags or effects. This breaks byte signatures that cover opcode
//! bytes - including the short prologue-anchored signatures that survive
//! relocation unchanged - while every candidate is self-verified by decoding
//! the rewritten bytes and comparing them against the original decode.
//!
//! Because the rewrite is strictly in place and length-preserving, it applies
//! to every lifted function: relocated functions inherit the aliased bytes in
//! their relocated copies, and functions that stay behind are no longer
//! byte-identical to the original either.

use rand::Rng;

use crate::analysis::Analysis;
use crate::pe::PeLayout;
use crate::stats::Counters;
use crate::transforms::alias_in_place;

/// Configuration for opcode aliasing.
#[derive(Debug, Clone)]
pub struct Config {
    /// Probability [0, 1] that an eligible instruction is aliased.
    pub probability: f64,
}

pub fn run(
    analysis: &Analysis,
    pe: &PeLayout,
    data: &mut [u8],
    cfg: &Config,
    rng: &mut impl Rng,
) -> Counters {
    let mut c = Counters::default();
    for func in &analysis.functions {
        for block in &func.blocks {
            for ins in &block.instrs {
                if ins.pinned {
                    c.skipped_pinned += 1;
                    continue;
                }
                c.candidates += 1;
                if rng.gen::<f64>() >= cfg.probability {
                    continue;
                }
                let ip = pe.va(ins.rva);
                if alias_in_place(&mut data[ins.off..ins.off + ins.len], ip) {
                    c.applied += 1;
                    c.instructions_touched += 1;
                } else {
                    c.skipped_no_room += 1;
                }
            }
        }
    }
    c
}
