//! Pass 2 — Instruction Reordering.
//!
//! For each basic block, a dependency DAG is built from register usage
//! (RAW/WAR/WAW), memory ordering, calls and flags (see `dependencies`), and
//! a randomized variant of Kahn's algorithm produces a fresh, semantically
//! equivalent topological order. The chosen order is materialized by
//! permuting the instruction encodings inside the original block span.
//! Total size is preserved, but individual instruction addresses can change.
//!
//! Metadata-backed functions use a restricted register-only scheduler that
//! preserves instruction boundaries, prologues, and stack/nonvolatile state.
//! Other functions retain the experimental general scheduler below.

use iced_x86::{InstructionInfoFactory, Mnemonic, OpKind, Register};
use rand::Rng;

use crate::analysis::{Analysis, Function, Instr};
use crate::dependencies;
use crate::pe::PeLayout;
use crate::stats::Counters;
use crate::transforms::relocate_ip_relative;

/// Configuration for instruction reordering.
#[derive(Debug, Clone)]
pub struct Config {
    /// Probability [0, 1] that a non-entry basic block is reordered.
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
    for (f_idx, func) in analysis.functions.iter().enumerate() {
        if let Some(unwind) = pe.unwind_info(func.start_rva) {
            if !unwind.permits_register_reordering {
                c.skipped_metadata += 1;
            } else {
                reorder_register_runs(
                    analysis,
                    func,
                    f_idx,
                    unwind.prologue_end,
                    data,
                    cfg,
                    rng,
                    &mut c,
                );
            }
            continue;
        }
        if pe
            .runtime_functions
            .iter()
            .any(|r| r.start < func.end_rva && func.start_rva < r.end)
        {
            c.skipped_metadata += 1;
            continue;
        }
        for (block_idx, block) in func.blocks.iter().enumerate() {
            if block_idx == 0 {
                continue; // retain the discovered entry block's layout
            }
            if analysis.range_externally_referenced(f_idx, block.start_rva..block.end_rva) {
                continue; // an external edge may enter the block's interior
            }
            if rng.gen::<f64>() >= cfg.probability {
                continue;
            }

            let n = block.instrs.len();
            // Keep the terminator (if any) in place; permute only the body.
            let body_len = if block.instrs[n - 1].ends_block() {
                n - 1
            } else {
                n
            };
            if body_len < 2 {
                continue;
            }
            let body = &block.instrs[..body_len];
            if body.iter().any(|i| i.pinned) {
                c.skipped_pinned += 1;
                continue;
            }

            let dag = dependencies::build(body);
            let order = dependencies::random_topo_order(&dag.deps, rng);
            if order.len() != body_len {
                continue; // defensive: a DAG cycle must never reach here
            }
            if order.iter().enumerate().all(|(k, &v)| k == v) {
                continue; // frontier pick reproduced the original order
            }

            // Materialize the new order by moving whole instruction encodings.
            // An instruction with a RIP-relative memory operand that lands at
            // a different address is re-encoded so its displacement keeps
            // pointing at the same absolute target; if that cannot be done
            // at the original length, the block is left untouched.
            let base = body[0].off;
            let base_rva = body[0].rva;
            let total: usize = body.iter().map(|i| i.len).sum();
            debug_assert_eq!(
                body.last().unwrap().off + body.last().unwrap().len - base,
                total
            );
            let mut buf = Vec::with_capacity(total);
            let mut cursor_rva = base_rva;
            let mut failed = false;
            for &idx in &order {
                let src = &body[idx];
                let bytes = &data[src.off..src.off + src.len];
                if src.iced.is_ip_rel_memory_operand() && src.rva != cursor_rva {
                    match relocate_ip_relative(&src.iced, pe.va(cursor_rva), src.len) {
                        Some(fixed) => buf.extend_from_slice(&fixed),
                        None => {
                            failed = true;
                            break;
                        }
                    }
                } else {
                    buf.extend_from_slice(bytes);
                }
                cursor_rva += src.len as u32;
            }
            if failed {
                c.skipped_pinned += 1;
                continue;
            }
            data[base..base + total].copy_from_slice(&buf);

            c.applied += 1;
            c.instructions_touched += body_len as u64;
        }
    }
    c
}

/// Only non-faulting scalar operations on volatile registers participate.
/// Memory, calls, stack/frame changes, nonvolatile registers, and implicit
/// machine state delimit runs. Equal-sized slots keep every boundary fixed.
fn eligible_register_instruction(ins: &Instr, prologue_end: u32) -> bool {
    if ins.pinned
        || ins.rva <= prologue_end
        || !matches!(
            ins.iced.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movsx
                | Mnemonic::Movsxd
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Not
                | Mnemonic::Neg
                | Mnemonic::Inc
                | Mnemonic::Dec
                | Mnemonic::Cmp
                | Mnemonic::Test
        )
    {
        return false;
    }
    for op in 0..ins.iced.op_count() {
        if !matches!(
            ins.iced.op_kind(op),
            OpKind::Register
                | OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        ) {
            return false;
        }
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(&ins.iced);
    info.used_memory().is_empty()
        && info.used_registers().iter().all(|r| {
            matches!(
                r.register().full_register(),
                Register::RAX
                    | Register::RCX
                    | Register::RDX
                    | Register::R8
                    | Register::R9
                    | Register::R10
                    | Register::R11
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn reorder_register_runs(
    analysis: &Analysis,
    func: &Function,
    f_idx: usize,
    prologue_end: u32,
    data: &mut [u8],
    cfg: &Config,
    rng: &mut impl Rng,
    c: &mut Counters,
) {
    // Unresolved indirect entries may land inside a scheduled run.
    if func
        .blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .any(|i| i.iced.flow_control() == iced_x86::FlowControl::IndirectBranch)
    {
        c.skipped_metadata += 1;
        return;
    }
    for block in &func.blocks {
        // The entry instruction and prologue are already pinned. References
        // to the function entry do not prevent scheduling its later body.
        if analysis.range_externally_referenced(
            f_idx,
            block.start_rva.max(func.start_rva + 1)..block.end_rva,
        ) {
            continue;
        }
        let mut start = 0;
        while start < block.instrs.len() {
            if !eligible_register_instruction(&block.instrs[start], prologue_end) {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < block.instrs.len()
                && block.instrs[end].len == block.instrs[start].len
                && eligible_register_instruction(&block.instrs[end], prologue_end)
            {
                end += 1;
            }
            let run = &block.instrs[start..end];
            start = end;
            if run.len() < 2 {
                continue;
            }
            c.candidates += 1;
            if rng.gen::<f64>() >= cfg.probability {
                continue;
            }
            let dag = dependencies::build(run);
            let order = dependencies::random_topo_order(&dag.deps, rng);
            if order.len() != run.len() {
                continue;
            }
            let base = run[0].off;
            let size: usize = run.iter().map(|i| i.len).sum();
            let mut output = Vec::with_capacity(size);
            for &index in &order {
                let ins = &run[index];
                output.extend_from_slice(&data[ins.off..ins.off + ins.len]);
            }
            if output == data[base..base + size] {
                continue;
            }
            data[base..base + size].copy_from_slice(&output);
            c.applied += 1;
            c.instructions_touched += run.len() as u64;
        }
    }
}
