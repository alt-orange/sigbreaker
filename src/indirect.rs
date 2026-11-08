//! Bounded constant propagation for register-derived branch targets. Facts are
//! discarded at every join, call, and control transfer; unknown writes kill them.
use crate::{analysis::Instr, pe::PeLayout};
use iced_x86::{FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

/// A code address may be remapped only when its value reaches a return or
/// register jump unchanged. Arithmetic on code pointers needs a richer model.
pub fn direct_address_use(function: &crate::analysis::Function, source: u32) -> bool {
    let mut instructions = function
        .blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .skip_while(|i| i.rva != source);
    let Some(first) = instructions.next() else {
        return false;
    };
    if !first.iced.op0_register().is_gpr64() {
        return false;
    }
    let mut pointers = BTreeSet::from([first.iced.op0_register()]);
    let mut factory = InstructionInfoFactory::new();
    for item in instructions {
        let i = &item.iced;
        if i.flow_control() == FlowControl::Return {
            return pointers.contains(&Register::RAX);
        }
        if i.flow_control() == FlowControl::IndirectBranch {
            return i.op0_kind() == OpKind::Register
                && pointers.contains(&i.op0_register().full_register());
        }
        if i.flow_control() != FlowControl::Next {
            return false;
        }
        let copy = i.mnemonic() == Mnemonic::Mov
            && i.op0_register().is_gpr64()
            && i.op1_kind() == OpKind::Register
            && pointers.contains(&i.op1_register());
        if pointers.contains(&i.memory_base().full_register())
            || pointers.contains(&i.memory_index().full_register())
        {
            return false;
        }
        let info = factory.info(i);
        if info.used_registers().iter().any(|r| {
            pointers.contains(&r.register().full_register())
                && matches!(
                    r.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        }) && !copy
        {
            return false;
        }
        for r in info.used_registers().iter().filter(|r| {
            matches!(
                r.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        }) {
            pointers.remove(&r.register().full_register());
        }
        if copy {
            pointers.insert(i.op0_register());
        }
        if pointers.is_empty() {
            return false;
        }
    }
    false
}

#[derive(Clone, Debug)]
pub enum TableKind {
    Absolute,
    Rva,
    Relative(u64),
}
#[derive(Clone, Debug)]
pub struct JumpTable {
    pub branch: u32,
    pub bytes: Range<usize>,
    pub targets: Vec<u32>,
    pub kind: TableKind,
}
impl JumpTable {
    pub fn rewrite(&self, base: u64, map: &BTreeMap<u64, u64>) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for &target in &self.targets {
            let va = map
                .get(&(base + target as u64))
                .copied()
                .unwrap_or(base + target as u64);
            match self.kind {
                TableKind::Absolute => bytes.extend_from_slice(&va.to_le_bytes()),
                TableKind::Rva => bytes.extend_from_slice(&u32::try_from(va - base)?.to_le_bytes()),
                TableKind::Relative(origin) => bytes
                    .extend_from_slice(&i32::try_from(va as i128 - origin as i128)?.to_le_bytes()),
            }
        }
        Ok(bytes)
    }
}

/// Recognize an unsigned range check dominating one straight-line dispatch.
/// Only constant read-only tables with every entry at a decoded local target
/// are accepted. A join, overwritten index/base, missing bound, or foreign
/// target leaves the indirect branch unresolved.
pub fn tables(
    pe: &PeLayout,
    data: &[u8],
    instrs: &[Instr],
    extra_entries: &BTreeSet<u32>,
) -> Vec<JumpTable> {
    let entries: BTreeSet<_> = instrs
        .iter()
        .filter_map(|i| i.branch_target_rva(pe.image_base))
        .chain(extra_entries.iter().copied())
        .collect();
    let starts: BTreeSet<_> = instrs.iter().map(|i| i.rva).collect();
    let mut result = Vec::new();
    for (jump_index, jump) in instrs
        .iter()
        .enumerate()
        .filter(|(_, i)| i.iced.flow_control() == FlowControl::IndirectBranch)
    {
        let Some(guard_index) = (1..jump_index)
            .rev()
            .take(16)
            .find(|&i| instrs[i].iced.flow_control() != FlowControl::Next)
        else {
            continue;
        };
        let guard = &instrs[guard_index].iced;
        if entries.contains(&instrs[guard_index].rva) {
            continue;
        }
        if !matches!(guard.mnemonic(), Mnemonic::Ja | Mnemonic::Jae) {
            continue;
        }
        let compare = &instrs[guard_index - 1].iced;
        if compare.mnemonic() != Mnemonic::Cmp
            || compare.op0_kind() != OpKind::Register
            || !matches!(
                compare.op1_kind(),
                OpKind::Immediate8to64
                    | OpKind::Immediate32to64
                    | OpKind::Immediate8to32
                    | OpKind::Immediate32
            )
        {
            continue;
        }
        let bound = compare.immediate(1);
        let count = if guard.mnemonic() == Mnemonic::Ja {
            bound.checked_add(1)
        } else {
            Some(bound)
        };
        let Some(count) = count.filter(|&n| n > 0 && n <= 4096) else {
            continue;
        };
        let dispatch = &instrs[guard_index + 1..=jump_index];
        if dispatch.iter().any(|i| entries.contains(&i.rva)) {
            continue;
        }
        let mut constants = BTreeMap::<Register, u64>::new();
        let mut bounded = BTreeSet::<Register>::new();
        if compare.op0_register().is_gpr64() {
            bounded.insert(compare.op0_register().full_register());
        }
        let mut guarded32 = compare
            .op0_register()
            .is_gpr32()
            .then_some(compare.op0_register());
        let mut found = None;
        let mut factory = InstructionInfoFactory::new();
        for (offset, item) in dispatch.iter().enumerate() {
            let ins = &item.iced;
            let absolute = offset == dispatch.len() - 1
                && ins.op0_kind() == OpKind::Memory
                && ins.memory_index_scale() == 8;
            let relative = offset + 2 == dispatch.len() - 1
                && matches!(ins.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
                && ins.op1_kind() == OpKind::Memory
                && ins.memory_index_scale() == 4;
            if absolute || relative {
                let base = ins.memory_base().full_register();
                let index = ins.memory_index().full_register();
                if let Some(&origin) = constants.get(&base).filter(|_| bounded.contains(&index)) {
                    let table_va = origin.wrapping_add(ins.memory_displacement64());
                    let kind = if absolute {
                        Some(TableKind::Absolute)
                    } else {
                        let add = &dispatch[offset + 1].iced;
                        let branch = &dispatch[offset + 2].iced;
                        let target = ins.op0_register().full_register();
                        if add.mnemonic() == Mnemonic::Add
                            && add.op0_register().full_register() == target
                            && add.op1_kind() == OpKind::Register
                            && add.op1_register().full_register() == base
                            && branch.op0_kind() == OpKind::Register
                            && branch.op0_register().full_register() == target
                        {
                            if ins.mnemonic() == Mnemonic::Movsxd && ins.op0_register().is_gpr64() {
                                Some(TableKind::Relative(origin))
                            } else if ins.mnemonic() == Mnemonic::Mov
                                && ins.op0_register().is_gpr32()
                                && origin == pe.image_base
                            {
                                Some(TableKind::Rva)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    if let Some(kind) = kind {
                        found = Some((table_va, kind));
                    }
                }
            }
            let value = (ins.mnemonic() == Mnemonic::Lea
                && ins.op0_register().is_gpr64()
                && ins.is_ip_rel_memory_operand())
            .then(|| ins.ip_rel_memory_address());
            let bounded_copy = matches!(ins.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
                && (ins.op0_register().is_gpr32() || ins.op0_register().is_gpr64())
                && (ins.op1_register().is_gpr32() || ins.op1_register().is_gpr64())
                && ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && (bounded.contains(&ins.op1_register().full_register())
                    || (guarded32 == Some(ins.op1_register()) && ins.op0_register().is_gpr32())
                    || (guarded32 == Some(ins.op1_register())
                        && ins.mnemonic() == Mnemonic::Movsxd));
            for used in factory.info(ins).used_registers() {
                if matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    constants.remove(&used.register().full_register());
                    bounded.remove(&used.register().full_register());
                    if guarded32
                        .is_some_and(|r| r.full_register() == used.register().full_register())
                    {
                        guarded32 = None;
                    }
                }
            }
            if let Some(value) = value {
                constants.insert(ins.op0_register().full_register(), value);
            }
            if bounded_copy {
                bounded.insert(ins.op0_register().full_register());
            }
        }
        let Some((table_va, kind)) = found else {
            continue;
        };
        let Some(rva) = table_va
            .checked_sub(pe.image_base)
            .and_then(|v| u32::try_from(v).ok())
        else {
            continue;
        };
        let stride = if matches!(kind, TableKind::Absolute) {
            8usize
        } else {
            4
        };
        let size = count as usize * stride;
        let Some(section) = pe.sections.iter().find(|s| {
            !s.is_executable() && s.characteristics & 0x80000000 == 0 && s.contains_rva(rva)
        }) else {
            continue;
        };
        let Some(at) = pe.rva_to_offset(rva) else {
            continue;
        };
        let Some(last) = rva.checked_add(size as u32 - 1) else {
            continue;
        };
        if !section.contains_rva(last) || pe.rva_to_offset(last) != Some(at + size - 1) {
            continue;
        }
        let Some(raw) = data.get(at..at + size) else {
            continue;
        };
        let targets: Option<Vec<_>> = raw
            .chunks_exact(stride)
            .map(|b| {
                let va = match kind {
                    TableKind::Absolute => u64::from_le_bytes(b.try_into().ok()?),
                    TableKind::Rva => pe.image_base + u32::from_le_bytes(b.try_into().ok()?) as u64,
                    TableKind::Relative(base) => {
                        base.wrapping_add(i32::from_le_bytes(b.try_into().ok()?) as i64 as u64)
                    }
                };
                let target = u32::try_from(va.checked_sub(pe.image_base)?).ok()?;
                starts.contains(&target).then_some(target)
            })
            .collect();
        if let Some(targets) = targets {
            result.push(JumpTable {
                branch: jump.rva,
                bytes: at..at + size,
                targets,
                kind,
            });
        }
    }
    result
}

pub fn resolve(
    pe: &PeLayout,
    instrs: &[Instr],
    extra_entries: impl IntoIterator<Item = u32>,
) -> BTreeMap<u32, u32> {
    let mut entries: BTreeSet<_> = instrs
        .iter()
        .filter_map(|i| i.branch_target_rva(pe.image_base))
        .collect();
    entries.extend(extra_entries);
    let mut constants = BTreeMap::<Register, u64>::new();
    let mut resolved = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    for item in instrs {
        if entries.contains(&item.rva) {
            constants.clear();
        }
        let ins = &item.iced;
        if ins.flow_control() == FlowControl::IndirectBranch && ins.op0_kind() == OpKind::Register {
            if let Some(rva) = constants
                .get(&ins.op0_register().full_register())
                .and_then(|v| v.checked_sub(pe.image_base))
                .and_then(|v| u32::try_from(v).ok())
            {
                if pe.executable_sections().any(|s| s.contains_rva(rva)) {
                    resolved.insert(item.rva, rva);
                }
            }
        }
        let value = if ins.op0_kind() == OpKind::Register && ins.op0_register().is_gpr64() {
            match ins.mnemonic() {
                Mnemonic::Lea if ins.is_ip_rel_memory_operand() => {
                    Some(ins.ip_rel_memory_address())
                }
                Mnemonic::Lea
                    if ins.memory_index() == Register::None && ins.memory_displacement64() == 0 =>
                {
                    constants.get(&ins.memory_base().full_register()).copied()
                }
                Mnemonic::Mov
                    if ins.op1_kind() == OpKind::Register && ins.op1_register().is_gpr64() =>
                {
                    constants.get(&ins.op1_register().full_register()).copied()
                }
                Mnemonic::Mov if ins.op1_kind() == OpKind::Immediate64 => Some(ins.immediate64()),
                _ => None,
            }
        } else {
            None
        };
        for used in factory.info(ins).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                constants.remove(&used.register().full_register());
            }
        }
        if let Some(value) = value {
            constants.insert(ins.op0_register(), value);
        }
        if ins.flow_control() != FlowControl::Next {
            constants.clear();
        }
    }
    resolved
}
