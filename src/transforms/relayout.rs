//! Expanding block layout for closed-CFG, plain-v1 Windows runtime functions.
//! Old bodies remain available. Their entries jump to relocated copies, whose
//! runtime-function entries reuse unchanged prologue unwind descriptions.
use crate::{
    analysis::{Analysis, Function},
    pe::{PeFile, PeLayout},
    stats::Counters,
    writer::{align, SectionPlan},
};
use anyhow::{bail, Context, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock, InstructionInfoFactory, Mnemonic, OpAccess, Register,
};
use rand::{seq::SliceRandom, Rng};
use std::collections::{BTreeMap, BTreeSet};

pub struct EncodedFunction {
    pub code: Vec<u8>,
    pub address_map: BTreeMap<u64, u64>,
    pub inserted_jumps: usize,
}

/// Encode a requested block permutation with explicit fall-through edges.
/// All generated instruction semantics, branch destinations and memory targets
/// are checked by decoding the emitted bytes independently of the encoder.
pub fn encode_function(
    func: &Function,
    new_ip: u64,
    order: &[usize],
    data: &[u8],
) -> Result<EncodedFunction> {
    if order.first() != Some(&0)
        || order.len() != func.blocks.len()
        || order.iter().copied().collect::<BTreeSet<_>>() != (0..func.blocks.len()).collect()
    {
        bail!("invalid block permutation");
    }
    let mut instructions = Vec::new();
    let mut synthetic = BTreeSet::new();
    let mut next_synthetic = u64::MAX;
    let used_ips: BTreeSet<_> = func
        .blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .map(|i| i.iced.ip())
        .collect();
    for &bi in order {
        let block = &func.blocks[bi];
        instructions.extend(block.instrs.iter().map(|i| i.iced));
        let last = block.instrs.last().context("empty basic block")?;
        if last.falls_through() {
            let next = func
                .blocks
                .get(bi + 1)
                .context("fall-through escapes function")?;
            let mut jump = Instruction::with_branch(Code::Jmp_rel32_64, next.instrs[0].iced.ip())?;
            while used_ips.contains(&next_synthetic) {
                next_synthetic -= 1;
            }
            jump.set_ip(next_synthetic);
            synthetic.insert(next_synthetic);
            next_synthetic -= 1;
            instructions.push(jump);
        }
    }
    // Preserve encodings that do not depend on IP, including redundant REX
    // prefixes in MSVC prologues. Canonicalizing those changes unwind offsets.
    // Byte declarations occupy one encoder slot per original instruction;
    // independent verification below still decodes and checks real instructions.
    let originals: BTreeMap<_, _> = func
        .blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .map(|i| (i.iced.ip(), i))
        .collect();
    let encoding: Vec<_> = instructions
        .iter()
        .map(|instruction| {
            if !instruction.is_ip_rel_memory_operand()
                && !matches!(
                    instruction.flow_control(),
                    FlowControl::ConditionalBranch
                        | FlowControl::UnconditionalBranch
                        | FlowControl::Call
                )
            {
                if let Some(source) = originals.get(&instruction.ip()) {
                    let bytes = data
                        .get(source.off..source.off + source.len)
                        .context("missing source instruction bytes")?;
                    let mut fixed = Instruction::with_declare_byte(bytes)?;
                    fixed.set_ip(instruction.ip());
                    return Ok(fixed);
                }
            }
            Ok(*instruction)
        })
        .collect::<Result<_>>()?;
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(&encoding, new_ip),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
            | BlockEncoderOptions::RETURN_RELOC_INFOS,
    )?;
    if !encoded.reloc_infos.is_empty() || encoded.new_instruction_offsets.contains(&u32::MAX) {
        bail!("layout needs unsupported absolute branch stubs");
    }
    let map: BTreeMap<_, _> = instructions
        .iter()
        .zip(&encoded.new_instruction_offsets)
        .map(|(i, &off)| (i.ip(), new_ip + off as u64))
        .collect();
    let mut consumed = 0;
    for (original, &off) in instructions.iter().zip(&encoded.new_instruction_offsets) {
        if off as usize != consumed {
            bail!("unexpected gap in generated code");
        }
        let mut decoder = Decoder::with_ip(
            64,
            &encoded.code_buffer[off as usize..],
            new_ip + off as u64,
            DecoderOptions::NONE,
        );
        let mut decoded = decoder.decode();
        if decoded.is_invalid() {
            bail!("invalid generated instruction");
        }
        consumed += decoded.len();
        if matches!(
            original.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
        ) {
            let target = original.near_branch_target();
            let expected = map.get(&target).copied().unwrap_or(target);
            if decoded.near_branch_target() != expected || decoded.mnemonic() != original.mnemonic()
            {
                bail!("generated branch target mismatch");
            }
            decoded.set_code(original.code());
            decoded.set_near_branch64(target);
        }
        decoded.set_memory_displ_size(original.memory_displ_size());
        if decoded != *original {
            bail!("generated instruction changed operands or effects");
        }
    }
    if consumed != encoded.code_buffer.len() {
        bail!("trailing generated data");
    }
    Ok(EncodedFunction {
        code: encoded.code_buffer,
        address_map: map
            .into_iter()
            .filter(|(ip, _)| !synthetic.contains(ip))
            .collect(),
        inserted_jumps: synthetic.len(),
    })
}

fn eligible(analysis: &Analysis, pe: &PeLayout, f: &Function, index: usize) -> bool {
    let Some(info) = pe.unwind_info(f.start_rva) else {
        return false;
    };
    let Some(extent) = pe.runtime_functions.iter().find(|r| r.start == f.start_rva) else {
        return false;
    };
    if !info.permits_register_reordering
        || f.end_rva != extent.end
        || f.end_rva - f.start_rva < 5
        || f.blocks.len() < 3
        || f.blocks[0].end_rva < info.prologue_end
        || analysis.range_externally_referenced(index, f.start_rva + 1..f.end_rva)
    {
        return false;
    }
    let boundaries: BTreeSet<_> = f.blocks.iter().map(|b| b.start_rva).collect();
    let mut factory = InstructionInfoFactory::new();
    for b in &f.blocks {
        for (i, ins) in b.instrs.iter().enumerate() {
            if ins.pinned || matches!(ins.iced.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Endbr32) {
                return false;
            }
            if !matches!(
                ins.iced.flow_control(),
                FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
                    | FlowControl::UnconditionalBranch
                    | FlowControl::Return
            ) {
                return false;
            }
            if let Some(target) = ins.branch_target_rva(pe.image_base) {
                if !boundaries.contains(&target) {
                    return false;
                }
            }
            if ins.iced.is_call_near() {
                let target = ins.iced.near_branch_target();
                if target == ins.iced.next_ip()
                    || (target > pe.va(f.start_rva) && target < pe.va(f.end_rva))
                {
                    return false;
                }
            }
            if ins.iced.is_ip_rel_memory_operand() {
                let target = ins.iced.ip_rel_memory_address();
                if target >= pe.va(f.start_rva) && target < pe.va(f.end_rva) {
                    return false;
                }
            }
            // Keep every stack-restoring epilogue contiguous within one block.
            // Calls/returns have balanced implicit stack effects and are exempt.
            if ins.rva >= info.prologue_end && ins.iced.flow_control() == FlowControl::Next {
                let writes_rsp = factory.info(&ins.iced).used_registers().iter().any(|r| {
                    r.register().full_register() == Register::RSP
                        && matches!(
                            r.access(),
                            OpAccess::Write
                                | OpAccess::CondWrite
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        )
                });
                if writes_rsp {
                    let suffix = &b.instrs[i..];
                    if suffix
                        .last()
                        .is_none_or(|last| last.iced.mnemonic() != Mnemonic::Ret)
                    {
                        return false;
                    }
                    for (j, item) in suffix[..suffix.len() - 1].iter().enumerate() {
                        let pop = item.iced.mnemonic() == Mnemonic::Pop
                            && item.iced.op0_register().is_gpr64();
                        let restore = j == 0
                            && matches!(item.iced.mnemonic(), Mnemonic::Add | Mnemonic::Lea)
                            && item.iced.op0_register() == Register::RSP;
                        if !pop && !restore {
                            return false;
                        }
                    }
                }
            }
        }
    }
    !f.blocks
        .last()
        .unwrap()
        .instrs
        .last()
        .unwrap()
        .falls_through()
}

pub fn run(
    analysis: &Analysis,
    pe: &mut PeFile,
    probability: f64,
    rng: &mut impl Rng,
) -> Result<Counters> {
    let mut c = Counters::default();
    if probability == 0.0 || pe.layout().runtime_functions.is_empty() {
        return Ok(c);
    }
    let plan = SectionPlan::new(pe)?;
    let layout = pe.layout();
    let mut address_taken = layout.relocated_code_references(&pe.data);
    address_taken.extend(layout.code_roots.iter().copied());
    address_taken.extend(
        analysis
            .functions
            .iter()
            .flat_map(|f| &f.blocks)
            .flat_map(|b| &b.instrs)
            .filter(|i| i.iced.is_ip_rel_memory_operand())
            .filter_map(|i| {
                i.iced
                    .ip_rel_memory_address()
                    .checked_sub(layout.image_base)
            })
            .filter_map(|rva| u32::try_from(rva).ok()),
    );
    let mut payload = Vec::new();
    let mut entries = Vec::new();
    let mut patches = Vec::new();
    for (index, f) in analysis.functions.iter().enumerate() {
        if !eligible(analysis, layout, f, index)
            || address_taken
                .range(f.start_rva + 1..f.end_rva)
                .next()
                .is_some()
        {
            c.skipped_metadata += 1;
            continue;
        }
        c.candidates += 1;
        if rng.gen::<f64>() >= probability {
            continue;
        }
        let offset = align(u32::try_from(payload.len())?, 16)?;
        let rva = plan
            .rva
            .checked_add(offset)
            .context("relayout RVA overflow")?;
        let mut order: Vec<_> = (0..f.blocks.len()).collect();
        order[1..].shuffle(rng);
        if order.iter().enumerate().all(|(i, &b)| i == b) {
            order.swap(1, 2);
        }
        let Ok(encoded) = encode_function(f, layout.va(rva), &order, &pe.data) else {
            c.reverted += 1;
            continue;
        };
        let info = layout.unwind_info(f.start_rva).unwrap();
        let prologue_len = (info.prologue_end - f.start_rva) as usize;
        if encoded.code.get(..prologue_len) != Some(&pe.data[f.off..f.off + prologue_len]) {
            c.reverted += 1;
            continue;
        }
        let disp = layout.va(rva) as i128 - (layout.va(f.start_rva) as i128 + 5);
        let Ok(disp) = i32::try_from(disp) else {
            c.reverted += 1;
            continue;
        };
        let mut jump = vec![0xE9];
        jump.extend_from_slice(&disp.to_le_bytes());
        patches.push((f.off, jump));
        let end = rva
            .checked_add(u32::try_from(encoded.code.len())?)
            .context("function overflow")?;
        entries.push((rva, end, info.rva));
        payload.resize(offset as usize, 0xCC);
        payload.extend_from_slice(&encoded.code);
        c.applied += 1;
        c.instructions_touched += f.instr_count as u64;
    }
    if !entries.is_empty() {
        plan.commit(pe, payload, &entries, &patches)?;
    }
    Ok(c)
}
