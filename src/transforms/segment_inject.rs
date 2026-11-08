//! Pass 1 — Segment Selector Injection.
//!
//! Injects a random segment override prefix (from a user-configurable
//! whitelist) into instructions with memory operands, changing their
//! encoding — and therefore the byte pattern scanners match on — without
//! changing runtime behavior on the flat 64-bit memory model (all segment
//! bases except FS/GS are zero).
//!
//! SigBreaker rewrites strictly in place, so injection only happens when the
//! instruction re-encodes to **exactly** its original length. The encoder
//! gets one extra trick: when a memory operand carries a redundant zero
//! displacement (e.g. `[rax+00h]`), dropping it frees a byte for the prefix,
//! keeping the total length identical. Instructions without room are counted
//! and skipped.

use iced_x86::{OpKind, Register};
use rand::Rng;

use crate::analysis::Analysis;
use crate::pe::PeLayout;
use crate::stats::Counters;
use crate::transforms::encode_at;

/// Configuration for segment selector injection.
#[derive(Debug, Clone)]
pub struct Config {
    /// Probability [0, 1] that an eligible instruction is transformed.
    pub probability: f64,
    /// Whitelist of segment overrides. FS/GS must only be enabled for
    /// environments that define those segment descriptors.
    pub segments: Vec<Register>,
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
                if !has_memory_operand(&ins.iced) {
                    continue;
                }
                c.candidates += 1;
                if ins.pinned {
                    c.skipped_pinned += 1;
                    continue;
                }
                if ins.iced.segment_prefix() != Register::None {
                    continue; // already carries an explicit override
                }
                if rng.gen::<f64>() >= cfg.probability {
                    continue;
                }
                let seg = cfg.segments[rng.gen_range(0..cfg.segments.len())];
                let ip = pe.va(ins.rva);
                match reencode_with_prefix(&ins.iced, ip, seg, ins.len) {
                    Some(bytes) => {
                        data[ins.off..ins.off + ins.len].copy_from_slice(&bytes);
                        c.applied += 1;
                        c.instructions_touched += 1;
                    }
                    None => c.skipped_no_room += 1,
                }
            }
        }
    }
    c
}

fn has_memory_operand(ins: &iced_x86::Instruction) -> bool {
    (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory)
}

/// Tries to re-encode `orig` with a segment override prefix at exactly the
/// original length. Falls back to absorbing a redundant zero displacement.
fn reencode_with_prefix(
    orig: &iced_x86::Instruction,
    ip: u64,
    seg: Register,
    want_len: usize,
) -> Option<Vec<u8>> {
    for absorb_displacement in [false, true] {
        let mut cand = *orig;
        if absorb_displacement {
            // Only drop a zero displacement when a base or index register
            // keeps the ModRM form valid (never for [disp32]/[rip+disp32]).
            if cand.memory_displ_size() == 0 || cand.memory_displacement64() != 0 {
                continue;
            }
            if cand.memory_base() == Register::None && cand.memory_index() == Register::None {
                continue;
            }
            cand.set_memory_displ_size(0);
        }
        cand.set_segment_prefix(seg);
        match encode_at(cand, ip) {
            Some(bytes) if bytes.len() == want_len => return Some(bytes),
            _ => continue,
        }
    }
    None
}
