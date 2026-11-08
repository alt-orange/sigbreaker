//! Expanding block layout for supported version-1 Windows runtime functions.
//! Old bodies remain available. Their entries jump to relocated copies, whose
//! runtime entries retain prologue unwind slots and rewrite recognized SEH scopes.
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
    pub spans: Vec<(u64, std::ops::Range<u64>)>,
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
    let mut synthetic_origins = BTreeMap::new();
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
            synthetic_origins.insert(next_synthetic, last.iced.next_ip());
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
                    let decoded =
                        Decoder::with_ip(64, bytes, instruction.ip(), DecoderOptions::NONE)
                            .decode();
                    if decoded == *instruction {
                        let mut fixed = Instruction::with_declare_byte(bytes)?;
                        fixed.set_ip(instruction.ip());
                        return Ok(fixed);
                    }
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
    let mut spans = Vec::new();
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
        spans.push((
            synthetic_origins
                .get(&original.ip())
                .copied()
                .unwrap_or(original.ip()),
            decoded.ip()..decoded.next_ip(),
        ));
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
        spans,
    })
}

fn import_tail(ins: &Instruction, pe: &PeLayout) -> bool {
    ins.is_jmp_near_indirect()
        && ins.segment_prefix() == Register::None
        && ins.is_ip_rel_memory_operand()
        && ins
            .ip_rel_memory_address()
            .checked_sub(pe.image_base)
            .and_then(|r| u32::try_from(r).ok())
            .is_some_and(|r| pe.import_slots.contains(&r))
}

fn eligible(
    analysis: &Analysis,
    pe: &PeLayout,
    f: &Function,
    index: usize,
    growing: bool,
) -> Result<(), &'static str> {
    let Some(info) = pe.unwind_info(f.start_rva) else {
        return Err("missing runtime metadata");
    };
    let Some(extent) = pe.runtime_functions.iter().find(|r| r.start == f.start_rva) else {
        return Err("missing runtime metadata");
    };
    let mut chain = info;
    while let crate::pe::UnwindKind::Chained { begin, .. } = chain.kind {
        let Some(primary) = pe.unwind_info(begin) else {
            return Err("unresolved chained unwind");
        };
        chain = primary;
    }
    let plain_chain = chain.rva % 4 == 0
        && matches!(info.kind, crate::pe::UnwindKind::Chained { .. })
        && matches!(chain.kind, crate::pe::UnwindKind::Plain);
    if info.rva % 4 != 0
        || (!info.permits_register_reordering
            && !pe.c_specific.contains_key(&f.start_rva)
            && !plain_chain)
    {
        return Err("unsupported unwind metadata");
    }
    if pe.c_specific.contains_key(&f.start_rva) && pe.guarded_eh_continuations {
        return Err("guarded exception continuations");
    }
    if f.end_rva != extent.end {
        return Err("incomplete decoding");
    }
    if f.end_rva - f.start_rva < 5 {
        return Err("entry smaller than jump");
    }
    if !growing && f.blocks.len() < 3 {
        return Err("too few blocks to shuffle");
    }
    if f.blocks[0].end_rva < info.prologue_end {
        return Err("split prologue");
    }
    if analysis.range_externally_referenced(index, f.start_rva + 1..f.end_rva) {
        return Err("interior code reference");
    }
    let boundaries: BTreeSet<_> = f.blocks.iter().map(|b| b.start_rva).collect();
    if let Some(scopes) = pe.c_specific.get(&f.start_rva) {
        let starts: BTreeSet<_> = f
            .blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .map(|i| i.rva)
            .chain(std::iter::once(f.end_rva))
            .collect();
        if scopes.scopes.iter().any(|s| {
            !starts.contains(&s.begin)
                || !starts.contains(&s.end)
                || (s.target != 0 && !starts.contains(&s.target))
        }) {
            return Err("scope boundary inside instruction");
        }
    }
    let mut factory = InstructionInfoFactory::new();
    for b in &f.blocks {
        for (i, ins) in b.instrs.iter().enumerate() {
            if ins.pinned || matches!(ins.iced.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Endbr32) {
                return Err("pinned or unreachable instructions");
            }
            if !import_tail(&ins.iced, pe)
                && !matches!(
                    ins.iced.flow_control(),
                    FlowControl::Next
                        | FlowControl::Call
                        | FlowControl::IndirectCall
                        | FlowControl::ConditionalBranch
                        | FlowControl::UnconditionalBranch
                        | FlowControl::Return
                )
            {
                return Err("unsupported control flow");
            }
            if let Some(target) = ins.branch_target_rva(pe.image_base) {
                if !boundaries.contains(&target) {
                    return Err("branch outside local blocks");
                }
            }
            if ins.iced.is_call_near() {
                let target = ins.iced.near_branch_target();
                if target == ins.iced.next_ip()
                    || (target > pe.va(f.start_rva) && target < pe.va(f.end_rva))
                {
                    return Err("interior call or PC materialization");
                }
            }
            if ins.iced.is_ip_rel_memory_operand() {
                let target = ins.iced.ip_rel_memory_address();
                if target >= pe.va(f.start_rva) && target < pe.va(f.end_rva) {
                    return Err("self-referencing code memory");
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
                    if suffix.last().is_none_or(|last| {
                        last.iced.mnemonic() != Mnemonic::Ret && !import_tail(&last.iced, pe)
                    }) {
                        return Err("unsupported stack restoration");
                    }
                    for (j, item) in suffix[..suffix.len() - 1].iter().enumerate() {
                        let pop = item.iced.mnemonic() == Mnemonic::Pop
                            && item.iced.op0_register().is_gpr64();
                        let restore = j == 0
                            && matches!(item.iced.mnemonic(), Mnemonic::Add | Mnemonic::Lea)
                            && item.iced.op0_register() == Register::RSP;
                        if !pop && !restore {
                            return Err("unsupported stack restoration");
                        }
                    }
                }
            }
        }
    }
    if f.blocks
        .last()
        .unwrap()
        .instrs
        .last()
        .unwrap()
        .falls_through()
    {
        return Err("fall-through outside function");
    }
    Ok(())
}

pub fn run(
    analysis: &Analysis,
    pe: &mut PeFile,
    probability: f64,
    rng: &mut impl Rng,
) -> Result<Counters> {
    run_with_segments(analysis, pe, probability, rng, None)
}

pub fn run_with_segments(
    analysis: &Analysis,
    pe: &mut PeFile,
    probability: f64,
    rng: &mut impl Rng,
    segments: Option<&super::segment_inject::Config>,
) -> Result<Counters> {
    let mut c = Counters::default();
    if (probability == 0.0 && segments.is_none()) || pe.layout().runtime_functions.is_empty() {
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
        let eligibility = eligible(analysis, layout, f, index, segments.is_some()).and_then(|()| {
            if address_taken
                .range(f.start_rva + 1..f.end_rva)
                .next()
                .is_some()
            {
                Err("interior address taken")
            } else {
                Ok(())
            }
        });
        if let Err(reason) = eligibility {
            *c.skipped_reasons.entry(reason).or_default() += 1;
            continue;
        }
        c.candidates += 1;
        let shuffle = rng.gen::<f64>() < probability && f.blocks.len() >= 3;
        let mut expanded = f.clone();
        let mut prefixed = 0;
        if let Some(cfg) = segments {
            let prologue_end = layout.unwind_info(f.start_rva).unwrap().prologue_end;
            for ins in expanded.blocks.iter_mut().flat_map(|b| &mut b.instrs) {
                if ins.rva >= prologue_end
                    && ins.iced.flow_control() == FlowControl::Next
                    && ins.iced.mnemonic() != Mnemonic::Lea
                    && ins.iced.segment_prefix() == Register::None
                    && (0..ins.iced.op_count())
                        .any(|i| ins.iced.op_kind(i) == iced_x86::OpKind::Memory)
                    && !cfg.segments.is_empty()
                    && rng.gen::<f64>() < cfg.probability
                {
                    ins.iced
                        .set_segment_prefix(cfg.segments[rng.gen_range(0..cfg.segments.len())]);
                    prefixed += 1;
                }
            }
        }
        if !shuffle && prefixed == 0 {
            *c.skipped_reasons
                .entry("probability or no prefix selected")
                .or_default() += 1;
            continue;
        }
        let offset = align(u32::try_from(payload.len())?, 16)?;
        let rva = plan
            .rva
            .checked_add(offset)
            .context("relayout RVA overflow")?;
        let mut order: Vec<_> = (0..f.blocks.len()).collect();
        if shuffle {
            order[1..].shuffle(rng);
            if order.iter().enumerate().all(|(i, &b)| i == b) {
                order.swap(1, 2);
            }
        }
        let Ok(encoded) = encode_function(&expanded, layout.va(rva), &order, &pe.data) else {
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
        let end = rva
            .checked_add(u32::try_from(encoded.code.len())?)
            .context("function overflow")?;
        // Exception data is emitted beside the copied code. Only its language
        // scope RVAs change; the prologue and original unwind slots stay exact.
        let mut unwind_rva = info.rva;
        let mut exception_bytes = Vec::new();
        let unwind_offset = align(
            offset
                .checked_add(u32::try_from(encoded.code.len())?)
                .context("unwind offset overflow")?,
            4,
        )?;
        if let Some(scopes) = layout.c_specific.get(&f.start_rva) {
            let Ok(relocated) = crate::exception::relocate(
                scopes,
                layout.image_base,
                &encoded.address_map,
                &encoded.spans,
            ) else {
                c.reverted += 1;
                continue;
            };
            let old_unwind = layout
                .rva_to_offset(info.rva)
                .context("unmapped original unwind")?;
            let codes_end = 4 + (pe.data[old_unwind + 2] as usize).div_ceil(2) * 4;
            exception_bytes.extend_from_slice(&pe.data[old_unwind..old_unwind + codes_end]);
            exception_bytes.extend_from_slice(&scopes.handler.to_le_bytes());
            exception_bytes.extend_from_slice(&u32::try_from(relocated.len())?.to_le_bytes());
            for scope in relocated {
                for value in [scope.begin, scope.end, scope.handler, scope.target] {
                    exception_bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
            unwind_rva = plan
                .rva
                .checked_add(unwind_offset)
                .context("new unwind RVA overflow")?;
        }
        patches.push((f.off, jump));
        entries.push((rva, end, unwind_rva));
        payload.resize(offset as usize, 0xCC);
        payload.extend_from_slice(&encoded.code);
        if !exception_bytes.is_empty() {
            payload.resize(unwind_offset as usize, 0);
            payload.extend_from_slice(&exception_bytes);
        }
        c.applied += 1;
        c.relocated_c_specific += u64::from(layout.c_specific.contains_key(&f.start_rva));
        c.relocated_chained +=
            u64::from(matches!(info.kind, crate::pe::UnwindKind::Chained { .. }));
        c.relocated_import_tails += u64::from(
            f.blocks
                .iter()
                .flat_map(|b| &b.instrs)
                .any(|i| import_tail(&i.iced, layout)),
        );
        c.instructions_touched += f.instr_count as u64;
    }
    if !entries.is_empty() {
        plan.commit(pe, payload, &entries, &patches)?;
    }
    Ok(c)
}
