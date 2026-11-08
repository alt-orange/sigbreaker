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

use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rand::Rng;
use std::{collections::BTreeSet, ops::Range};

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
                    pe,
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
fn eligible_register_instruction(ins: &Instr, prologue_end: u32, proof: &FrameProof) -> bool {
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
                | Mnemonic::Lea
                | Mnemonic::Imul
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Bswap
        )
    {
        return false;
    }
    for op in 0..ins.iced.op_count() {
        if ins.iced.op_kind(op) == OpKind::Memory
            && matches!(
                ins.iced.mnemonic(),
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd
            )
            && proof.private_memory(&ins.iced)
        {
            continue;
        }
        if ins.iced.mnemonic() == Mnemonic::Lea
            && op == 1
            && ins.iced.op_kind(op) == OpKind::Memory
            && !ins.iced.is_ip_rel_memory_operand()
        {
            continue;
        }
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
    (info.used_memory().is_empty()
        || ins.iced.mnemonic() == Mnemonic::Lea
        || proof.private_memory(&ins.iced))
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
            ) || proof.saved.contains(&r.register().full_register())
                || (r.register() == Register::RSP && proof.private_memory(&ins.iced))
        })
}

#[derive(Default)]
struct FrameProof {
    saved: BTreeSet<Register>,
    slots: Vec<Range<i64>>,
    private: bool,
}
fn writes(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
fn gpr(number: usize) -> Register {
    [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ][number]
}
impl FrameProof {
    fn private_memory(&self, ins: &iced_x86::Instruction) -> bool {
        let at = ins.memory_displacement64() as i64;
        let size = ins.memory_size().size() as i64;
        self.private
            && ins.memory_base() == Register::RSP
            && ins.memory_index() == Register::None
            && !matches!(ins.segment_prefix(), Register::FS | Register::GS)
            && size > 0
            && at
                .checked_add(size)
                .is_some_and(|end| self.slots.iter().any(|s| s.start <= at && end <= s.end))
    }
    fn analyze(func: &Function, pe: &PeLayout, data: &[u8], end: u32) -> Self {
        let mut proof = Self {
            private: true,
            ..Self::default()
        };
        let unwind = pe.unwind_info(func.start_rva).unwrap();
        let at = pe.rva_to_offset(unwind.rva).unwrap();
        let count = data[at + 2] as usize;
        let frame = gpr((data[at + 3] & 15) as usize);
        let mut slot = 0;
        let mut described = BTreeSet::new();
        while slot < count {
            let offset = data[at + 4 + slot * 2];
            let op = data[at + 5 + slot * 2] & 15;
            let reg = (data[at + 5 + slot * 2] >> 4) as usize;
            let width = match op {
                0 | 2 | 3 | 10 => 1,
                1 if reg == 0 => 2,
                1 if reg == 1 => 3,
                4 | 8 => 2,
                5 | 9 => 3,
                _ => {
                    proof.private = false;
                    break;
                }
            };
            if matches!(op, 0 | 4 | 5)
                && gpr(reg) != frame
                && matches!(
                    gpr(reg),
                    Register::RBX
                        | Register::RBP
                        | Register::RSI
                        | Register::RDI
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15
                )
            {
                described.insert((func.start_rva + offset as u32, gpr(reg)));
            }
            slot += width;
        }
        let mut rsp = 0i64;
        let mut touched = Vec::new();
        let mut saved_slots = Vec::new();
        let mut factory = InstructionInfoFactory::new();
        for ins in func
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .filter(|i| i.rva < end)
        {
            let i = &ins.iced;
            if i.mnemonic() == Mnemonic::Push && i.op0_register().is_gpr64() {
                rsp -= 8;
                let range = rsp..rsp + 8;
                if described.contains(&(ins.rva + ins.len as u32, i.op0_register())) {
                    proof.saved.insert(i.op0_register());
                    saved_slots.push(range.clone());
                }
                touched.push(range);
            } else if i.mnemonic() == Mnemonic::Sub
                && i.op0_register() == Register::RSP
                && matches!(
                    i.op1_kind(),
                    OpKind::Immediate8to64 | OpKind::Immediate32to64
                )
            {
                let amount = i.immediate(1);
                if amount > 4096 {
                    proof.private = false;
                } else {
                    rsp -= amount as i64;
                }
            } else if i.mnemonic() == Mnemonic::Mov
                && i.op0_kind() == OpKind::Memory
                && i.memory_base() == Register::RSP
                && i.memory_index() == Register::None
            {
                let start = rsp + i.memory_displacement64() as i64;
                let range = start..start + i.memory_size().size() as i64;
                if i.op1_kind() == OpKind::Register
                    && described
                        .contains(&(ins.rva + ins.len as u32, i.op1_register().full_register()))
                {
                    proof.saved.insert(i.op1_register().full_register());
                    saved_slots.push(range.clone());
                }
                touched.push(range);
            } else if i.flow_control() != iced_x86::FlowControl::Next
                || factory
                    .info(i)
                    .used_registers()
                    .iter()
                    .any(|r| r.register() == Register::RSP && writes(r.access()))
            {
                proof.private = false;
            }
        }
        for block in &func.blocks {
            for (idx, item) in block
                .instrs
                .iter()
                .enumerate()
                .filter(|(_, i)| i.rva >= end)
            {
                let i = &item.iced;
                if matches!(
                    i.flow_control(),
                    iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
                ) {
                    proof.private = false;
                }
                if (0..i.op_count()).any(|op| {
                    i.op_kind(op) == OpKind::Register
                        && i.op_register(op) == Register::RSP
                        && (op != 0 || !matches!(i.mnemonic(), Mnemonic::Add | Mnemonic::Lea))
                }) {
                    proof.private = false;
                }
                if i.mnemonic() == Mnemonic::Lea
                    && i.memory_base() == Register::RSP
                    && i.op0_register() != Register::RSP
                {
                    proof.private = false;
                }
                let info = factory.info(i);
                for m in info.used_memory().iter().filter(|m| writes(m.access())) {
                    if m.base() != Register::RSP || m.index() != Register::None {
                        proof.private = false;
                        continue;
                    }
                    let offset = m.displacement() as i64 + rsp;
                    let size = m.memory_size().size() as i64;
                    if saved_slots
                        .iter()
                        .any(|s| s.start < offset + size && offset < s.end)
                    {
                        proof.private = false;
                    }
                }
                if info
                    .used_registers()
                    .iter()
                    .any(|r| r.register() == Register::RSP && writes(r.access()))
                    && i.flow_control() != iced_x86::FlowControl::Return
                {
                    let suffix = &block.instrs[idx..];
                    if suffix
                        .last()
                        .is_none_or(|last| last.iced.mnemonic() != Mnemonic::Ret)
                        || suffix[..suffix.len() - 1].iter().enumerate().any(|(j, s)| {
                            s.iced.mnemonic() != Mnemonic::Pop
                                && !(j == 0
                                    && matches!(s.iced.mnemonic(), Mnemonic::Add | Mnemonic::Lea)
                                    && s.iced.op0_register() == Register::RSP)
                        })
                    {
                        proof.private = false;
                    }
                }
            }
        }
        proof.slots = touched
            .into_iter()
            .filter(|s| {
                !saved_slots
                    .iter()
                    .any(|r| r.start < s.end && s.start < r.end)
            })
            .map(|s| s.start - rsp..s.end - rsp)
            .collect();
        if !proof.private {
            proof.saved.clear();
            proof.slots.clear();
        }
        proof
    }
}

#[allow(clippy::too_many_arguments)]
fn reorder_register_runs(
    analysis: &Analysis,
    func: &Function,
    f_idx: usize,
    prologue_end: u32,
    pe: &PeLayout,
    data: &mut [u8],
    cfg: &Config,
    rng: &mut impl Rng,
    c: &mut Counters,
) {
    let proof = FrameProof::analyze(func, pe, data, prologue_end);
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
            if !eligible_register_instruction(&block.instrs[start], prologue_end, &proof) {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < block.instrs.len()
                && block.instrs[end].len == block.instrs[start].len
                && eligible_register_instruction(&block.instrs[end], prologue_end, &proof)
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
            let dag = if proof.private {
                dependencies::build_private_stack(run)
            } else {
                dependencies::build(run)
            };
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
