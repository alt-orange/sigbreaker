//! In-place opcode aliasing.
//!
//! Switches equivalent register-register ALU/MOV direction forms and changes
//! unused REX or SIB bits in selected legacy instructions.
//! Each replacement is checked against the original decode before publication.
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
    for (index, func) in analysis.functions.iter().enumerate() {
        for block in &func.blocks {
            for ins in &block.instrs {
                if ins.pinned && !analysis.pinned_only_by_unwind(ins) {
                    c.skipped_pinned += 1;
                    continue;
                }
                c.candidates += 1;
                if rng.gen::<f64>() >= cfg.probability {
                    continue;
                }
                let end = ins.rva + ins.len as u32;
                if analysis.range_externally_referenced(index, ins.rva + 1..end)
                    || (ins.pinned && analysis.references_code_as_data(ins.rva..end))
                {
                    *c.skipped_reasons.entry("interior code reference").or_default() += 1;
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
