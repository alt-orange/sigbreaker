//! BLARE — binary lifting: functions → basic blocks → block chains.
//!
//! Function extents come from runtime metadata when present. Otherwise roots
//! are discovered by recursive decoding from entries, exports and direct calls.
//! Each function region is linearly decoded and split into basic
//! blocks at branch targets and terminators. Blocks are then grouped into
//! *chains*: maximal runs of blocks connected by fall-through edges. Chains
//! are the unit of movement for the block-shuffling pass — a chain is only
//! entered through a real branch, so relayouting it never breaks a
//! fall-through.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::pe::{PeLayout, SectionHeader};

/// One lifted instruction, at a fixed file offset.
#[derive(Debug, Clone)]
pub struct Instr {
    /// File offset of the instruction bytes.
    pub off: usize,
    /// RVA of the instruction.
    pub rva: u32,
    /// Original encoded length; the expanding layout pass may relax branches.
    pub len: usize,
    /// Overlaps a base-relocation fixup: bytes must not be rewritten.
    pub pinned: bool,
    /// Not reachable from the function entry through decoded edges. Dead
    /// instructions may only trail the live code (padding or data islands).
    pub dead: bool,
    /// The decoded instruction.
    pub iced: Instruction,
}

impl Instr {
    /// Terminators close a basic block.
    pub fn ends_block(&self) -> bool {
        matches!(
            self.iced.flow_control(),
            FlowControl::Return
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception
                | FlowControl::XbeginXabortXend
        )
    }

    /// Whether control can continue into the following byte.
    pub fn falls_through(&self) -> bool {
        // Ending a basic block does not imply ending fall-through: a jcc
        // has both a taken edge and an edge to the following instruction.
        // Keep uncertain cases (interrupts and transactional instructions)
        // together with their successors conservatively.
        !matches!(
            self.iced.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Exception
        )
    }

    /// Direct, statically-known relative branches (jcc/jmp/loop/jcxz).
    pub fn is_direct_branch(&self) -> bool {
        self.iced.is_jcc_short_or_near()
            || self.iced.is_jmp_short_or_near()
            || self.iced.is_loop()
            || self.iced.is_loopcc()
            || self.iced.is_jcx_short()
    }

    /// RVA of the branch target, if this is a direct relative branch.
    pub fn branch_target_rva(&self, image_base: u64) -> Option<u32> {
        if !self.is_direct_branch() {
            return None;
        }
        Some((self.iced.near_branch_target().wrapping_sub(image_base)) as u32)
    }
}

/// A basic block: a straight-line run of instructions with one entry.
#[derive(Debug, Clone)]
pub struct Block {
    pub start_rva: u32,
    /// Exclusive end RVA.
    pub end_rva: u32,
    pub instrs: Vec<Instr>,
}

/// A chain of basic blocks linked by fall-through edges.
///
/// The only way control enters a chain is a real branch (or a call), so
/// chains are the safely-movable units of a function.
#[derive(Debug, Clone)]
pub struct Chain {
    /// Indices into [`Function::blocks`], in layout order.
    pub blocks: Vec<usize>,
}

/// A lifted function region.
#[derive(Debug, Clone)]
pub struct Function {
    pub start_rva: u32,
    /// Exclusive end RVA.
    pub end_rva: u32,
    /// File offset of `start_rva`.
    pub off: usize,
    pub blocks: Vec<Block>,
    pub chains: Vec<Chain>,
    /// Number of instructions found by the initial linear decode.
    pub instr_count: usize,
    pub resolved_indirect: BTreeMap<u32, u32>,
    pub jump_tables: Vec<crate::indirect::JumpTable>,
}

impl Function {
    /// Drops trailing dead instructions (padding after the last live one).
    pub fn trim_dead_tail(&mut self) {
        while let Some(block) = self.blocks.last_mut() {
            while block.instrs.last().is_some_and(|i| i.dead) {
                block.instrs.pop();
            }
            if block.instrs.is_empty() {
                self.blocks.pop();
            } else {
                break;
            }
        }
    }
}

/// The result of lifting every executable section.
#[derive(Debug)]
pub struct Analysis {
    pub functions: Vec<Function>,
    /// Branch-target RVA → indices of regions containing a branch to it.
    /// Used to detect cross-function (tail-merged) references before moving code.
    branch_owners: BTreeMap<u32, Vec<usize>>,
    /// Direct call targets and known code-address references that must stay fixed.
    call_targets: BTreeSet<u32>,
    /// Targets referenced as data (non-`lea` RIP-relative reads, data-section
    /// pointers, relocation fixups). These can never be retargeted.
    data_refs: BTreeSet<u32>,
    /// Typed code-address materializations that can be rewritten after layout.
    pub address_references: BTreeMap<u32, Vec<Instr>>,
    /// Direct branch/call sources per target: `(owning region, instruction)`.
    /// Foreign edges into a relocated interior are rewritten to the new target.
    pub branch_sources: BTreeMap<u32, Vec<(usize, Instr)>>,
    /// Reachable instructions pinned solely by chained unwind metadata.
    metadata_only_pins: BTreeSet<u32>,
}

impl Analysis {
    /// Lifts all executable sections of the image.
    pub fn run(pe: &PeLayout, data: &[u8]) -> Result<Analysis> {
        let mut functions = Vec::new();
        let mut branch_owners: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut call_targets = BTreeSet::new();
        let mut data_refs = BTreeSet::new();
        let mut branch_sources = BTreeMap::<u32, Vec<(usize, Instr)>>::new();
        let mut address_references = BTreeMap::<u32, Vec<Instr>>::new();
        let mut metadata_only_pins = BTreeSet::new();
        call_targets.extend(pe.code_roots.iter().copied());
        let roots = if pe.runtime_functions.is_empty() {
            Self::discover_roots(pe, data)
        } else {
            BTreeSet::new()
        };

        for sec in pe.executable_sections() {
            for (start_rel, end_rel) in Self::region_bounds(pe, data, sec, &roots) {
                let f_idx = functions.len();
                let Some(func) =
                    Self::lift_region(
                        pe, data, sec, start_rel, end_rel, f_idx, &mut branch_owners,
                        &mut metadata_only_pins,
                    )
                else {
                    continue;
                };
                // Decoded calls and RIP-relative code pointers can target
                // interiors in other regions. Keep those addresses fixed.
                for ins in func.blocks.iter().flat_map(|b| &b.instrs) {
                    if ins.iced.is_ip_rel_memory_operand() {
                        if let Some(rva) = ins
                            .iced
                            .ip_rel_memory_address()
                            .checked_sub(pe.image_base)
                            .and_then(|v| u32::try_from(v).ok())
                        {
                            if pe.executable_sections().any(|s| s.contains_rva(rva)) {
                                if ins.iced.mnemonic() == iced_x86::Mnemonic::Lea {
                                    if pe.runtime_function_at(rva).is_some() {
                                        // A materialized function entry: the
                                        // entry keeps its trampoline, so the
                                        // value stays valid without rewriting.
                                        continue;
                                    }
                                    if crate::indirect::direct_address_use(&func, ins.rva) {
                                        address_references.entry(rva).or_default().push(ins.clone());
                                        continue;
                                    }
                                }
                                call_targets.insert(rva);
                                data_refs.insert(rva);
                                if pe.runtime_function_at(rva).is_some() {
                                    call_targets.insert(rva + 1);
                                    data_refs.insert(rva + 1);
                                }
                            }
                        }
                    }
                    if ins.iced.is_call_near() {
                        let target =
                            ins.iced.near_branch_target().wrapping_sub(pe.image_base) as u32;
                        call_targets.insert(target);
                        branch_sources.entry(target).or_default().push((f_idx, ins.clone()));
                    }
                    if ins.is_direct_branch() {
                        if let Some(target) = ins.branch_target_rva(pe.image_base) {
                            branch_sources.entry(target).or_default().push((f_idx, ins.clone()));
                        }
                    }
                }
                functions.push(func);
            }
        }

        let table_bytes: Vec<_> = functions
            .iter()
            .flat_map(|f| f.jump_tables.iter().map(|t| t.bytes.clone()))
            .collect();
        let relocated: BTreeSet<_> = pe.relocated_code_references_except(data, &table_bytes);
        call_targets.extend(relocated.iter().copied());
        data_refs.extend(relocated);
        let data_based: BTreeSet<_> = pe.data_code_references_except(data, &table_bytes);
        call_targets.extend(data_based.iter().copied());
        data_refs.extend(data_based);
        Ok(Analysis {
            functions,
            branch_owners,
            call_targets,
            data_refs,
            address_references,
            branch_sources,
            metadata_only_pins,
        })
    }

    pub(crate) fn pinned_only_by_unwind(&self, ins: &Instr) -> bool {
        self.metadata_only_pins.contains(&ins.rva)
    }

    pub(crate) fn references_code_as_data(&self, range: Range<u32>) -> bool {
        self.data_refs.range(range).next().is_some()
    }

    /// Whether `rva` might be referenced from outside function `f_idx`
    /// (a branch or call from another region). Such addresses must never move.
    pub fn externally_referenced(&self, f_idx: usize, rva: u32) -> bool {
        if self
            .branch_owners
            .get(&rva)
            .is_some_and(|owners| owners.iter().any(|&o| o != f_idx))
        {
            return true;
        }
        self.call_targets.contains(&rva)
    }

    /// Whether any known external branch or direct call targets this span.
    /// Targets can lie inside a block, including inside an instruction; in
    /// that case the entire containing span must retain its byte layout.
    pub fn range_externally_referenced(&self, f_idx: usize, range: Range<u32>) -> bool {
        self.address_references
            .range(range.clone())
            .next()
            .is_some()
            || self.range_unrewritable_reference(f_idx, range)
    }
    pub fn range_unrewritable_reference(&self, f_idx: usize, range: Range<u32>) -> bool {
        if range.start >= range.end {
            return false;
        }
        self.branch_owners
            .range(range.clone())
            .any(|(_, owners)| owners.iter().any(|&owner| owner != f_idx))
            || self.call_targets.range(range).next().is_some()
    }

    /// Whether every foreign code edge into `range` can be retargeted after
    /// the containing region moves. Data references and edges from another
    /// region that cannot be re-encoded (short forms, relocation-protected or
    /// dead source instructions) keep the range pinned.
    ///
    /// With `stale_ok` (layouts that retain original bodies) interior
    /// references stay valid pointing at the unchanged original bytes, so only
    /// the entry trampoline region must stay clean.
    pub fn interior_movable(
        &self,
        f_idx: usize,
        range: Range<u32>,
        stale_ok: bool,
    ) -> bool {
        if range.start >= range.end {
            return true;
        }
        if stale_ok {
            // The relocated entry becomes a 5-byte jump; any reference into
            // those bytes would execute garbage. References deeper into the
            // function stay valid pointing at the retained original bytes.
            // Foreign edges into the trampoline interior must be re-encodable
            // so the commit phase can rewrite them to the relocated copy;
            // shorter edges keep the function pinned. The entry itself stays
            // reachable through the trampoline, so it is not part of the
            // guarded span.
            let trampoline = range.start..range.start + 4;
            for &target in self.call_targets.range(trampoline.clone()) {
                if self.data_refs.contains(&target) {
                    return false;
                }
                match self.branch_sources.get(&target) {
                    Some(sources) => {
                        if sources
                            .iter()
                            .any(|(owner, s)| *owner != f_idx && !Self::retargetable(s))
                        {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            for (&target, owners) in self.branch_owners.range(trampoline) {
                if owners.iter().all(|&owner| owner == f_idx) {
                    continue;
                }
                if self.call_targets.contains(&target) {
                    continue;
                }
                match self.branch_sources.get(&target) {
                    Some(sources) => {
                        if sources
                            .iter()
                            .any(|(owner, s)| *owner != f_idx && !Self::retargetable(s))
                        {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            return true;
        }
        let blocked = |sources: &[(usize, Instr)]| {
            sources
                .iter()
                .any(|(owner, s)| *owner != f_idx && !Self::retargetable(s))
        };
        for &target in self.call_targets.range(range.clone()) {
            if self.data_refs.contains(&target) {
                return false;
            }
            match self.branch_sources.get(&target) {
                Some(sources) => {
                    if blocked(sources) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        for (&target, owners) in self.branch_owners.range(range.clone()) {
            if owners.iter().all(|&owner| owner == f_idx) {
                continue;
            }
            if self.call_targets.contains(&target) {
                continue;
            }
            match self.branch_sources.get(&target) {
                Some(sources) => {
                    if blocked(sources) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Whether a foreign edge's source instruction can be re-encoded to reach
    /// an appended layout: near-form branches and calls with room for a rel32.
    pub fn retargetable(source: &Instr) -> bool {
        !source.pinned
            && source.len >= 5
            && ((source.iced.is_jcc_short_or_near() && source.len == 6)
                || (source.iced.is_jmp_short_or_near() && source.len == 5)
                || (source.iced.is_call_near() && source.len == 5))
    }

    /// Metadata extents or discovered roots, expressed as section-relative RVAs.
    fn region_bounds(
        pe: &PeLayout,
        data: &[u8],
        sec: &SectionHeader,
        roots: &BTreeSet<u32>,
    ) -> Vec<(u32, u32)> {
        if !pe.runtime_functions.is_empty() {
            return pe
                .runtime_functions
                .iter()
                .filter(|r| sec.contains_rva(r.start))
                .map(|r| (r.start - sec.virtual_address, r.end - sec.virtual_address))
                .collect();
        }
        let range = pe.section_raw_range(sec, data.len());
        let sec_len = (range.end - range.start) as u32;

        let starts: BTreeSet<u32> = roots
            .iter()
            .filter_map(|&rva| {
                rva.checked_sub(sec.virtual_address)
                    .filter(|&rel| rel < sec_len)
            })
            .collect();
        if starts.is_empty() {
            return Vec::new();
        }

        let starts: Vec<u32> = starts.into_iter().collect();
        let mut bounds = Vec::with_capacity(starts.len());
        for (i, &s) in starts.iter().enumerate() {
            let end = starts.get(i + 1).copied().unwrap_or(sec_len);
            if end > s {
                bounds.push((s, end));
            }
        }
        bounds
    }

    /// Follow decoded control flow from declared entries and exports. Only
    /// actual direct calls introduce function roots; E8 inside data/immediates
    /// never does. Unknown indirect targets remain undiscovered and untouched.
    fn discover_roots(pe: &PeLayout, data: &[u8]) -> BTreeSet<u32> {
        let mut roots = pe.code_roots.clone();
        let mut pending: Vec<u32> = roots.iter().copied().collect();
        let mut visited = BTreeSet::new();
        while let Some(rva) = pending.pop() {
            if !visited.insert(rva) {
                continue;
            }
            let Some(sec) = pe.executable_sections().find(|s| s.contains_rva(rva)) else {
                continue;
            };
            let Some(off) = pe.rva_to_offset(rva) else {
                continue;
            };
            let end = (sec.raw_ptr as usize + sec.raw_size as usize).min(data.len());
            if off >= end {
                continue;
            }
            let mut decoder = Decoder::with_ip(
                64,
                &data[off..end.min(off + 15)],
                pe.va(rva),
                DecoderOptions::NONE,
            );
            let iced = decoder.decode();
            if iced.is_invalid() {
                continue;
            }
            let ins = Instr {
                off,
                rva,
                len: iced.len(),
                pinned: false,
                dead: false,
                iced,
            };
            if let Some(target) = ins.branch_target_rva(pe.image_base) {
                pending.push(target);
            }
            if ins.iced.is_call_near() {
                let target = ins.iced.near_branch_target().wrapping_sub(pe.image_base) as u32;
                if pe.executable_sections().any(|s| s.contains_rva(target)) {
                    roots.insert(target);
                    pending.push(target);
                }
            }
            if ins.falls_through() {
                if let Some(next) = rva.checked_add(ins.len as u32) {
                    pending.push(next);
                }
            }
        }
        roots
    }

    /// Linearly decodes one function region and splits it into blocks/chains.
    #[allow(clippy::too_many_arguments)]
    fn lift_region(
        pe: &PeLayout,
        data: &[u8],
        sec: &SectionHeader,
        start_rel: u32,
        end_rel: u32,
        f_idx: usize,
        branch_owners: &mut BTreeMap<u32, Vec<usize>>,
        metadata_only_pins: &mut BTreeSet<u32>,
    ) -> Option<Function> {
        let off = sec.raw_ptr as usize + start_rel as usize;
        let region_len = (end_rel - start_rel) as usize;
        let base_rva = sec.virtual_address + start_rel;

        let mut decoder = Decoder::with_ip(
            64,
            &data[off..off + region_len],
            pe.va(base_rva),
            DecoderOptions::NONE,
        );
        let mut instrs: Vec<Instr> = Vec::new();
        let mut cur = off;
        loop {
            let ins = decoder.decode();
            if ins.is_invalid() {
                break;
            }
            let len = ins.len();
            let rva = sec.virtual_address + (cur - sec.raw_ptr as usize) as u32;
            let pinned = pe.is_protected(cur..cur + len)
                || pe.is_metadata_pinned(rva..rva + len as u32);
            instrs.push(Instr {
                off: cur,
                rva: sec.virtual_address + (cur - sec.raw_ptr as usize) as u32,
                len,
                pinned,
                dead: false,
                iced: ins,
            });
            cur += len;
            if cur >= off + region_len {
                break;
            }
        }
        if instrs.is_empty() {
            return None;
        }
        let resolved_indirect = crate::indirect::resolve(
            pe,
            &instrs,
            pe.eh_continuations.iter().copied().chain(
                pe.cpp_eh
                    .get(&base_rva)
                    .into_iter()
                    .flat_map(|i| i.continuations.iter().copied()),
            ),
        );
        let entries = pe
            .eh_continuations
            .iter()
            .copied()
            .chain(
                pe.cpp_eh
                    .get(&base_rva)
                    .into_iter()
                    .flat_map(|i| i.continuations.iter().copied()),
            )
            .collect();
        let jump_tables = crate::indirect::tables(pe, data, &instrs, &entries);
        // Metadata-backed extents may contain inline data and jump tables.
        // Only instructions reached from the entry through decoded edges can
        // be rewritten. Unknown indirect destinations stay untouched.
        {
            let starts: BTreeMap<u32, usize> = instrs
                .iter()
                .enumerate()
                .map(|(i, ins)| (ins.rva, i))
                .collect();
            let mut pending = vec![base_rva];
            pending.extend(
                pe.eh_continuations
                    .range(base_rva..base_rva + region_len as u32)
                    .copied(),
            );
            if let Some(info) = pe.cpp_eh.get(&base_rva) {
                pending.extend(
                    info.continuations
                        .range(base_rva..base_rva + region_len as u32)
                        .copied(),
                );
            }
            if let Some(info) = pe.c_specific.get(&base_rva) {
                pending.extend(
                    info.scopes
                        .iter()
                        .filter(|s| s.target != 0)
                        .map(|s| s.target),
                );
            }
            let mut reached = HashSet::new();
            let mut ambiguous = false;
            while let Some(rva) = pending.pop() {
                let Some(&i) = starts.get(&rva) else {
                    if rva >= base_rva && rva < base_rva + region_len as u32 {
                        ambiguous = true;
                    }
                    continue;
                };
                if !reached.insert(i) {
                    continue;
                }
                let ins = &instrs[i];
                if let Some(target) = ins.branch_target_rva(pe.image_base) {
                    pending.push(target);
                }
                if let Some(&target) = resolved_indirect.get(&ins.rva) {
                    pending.push(target);
                }
                for table in jump_tables.iter().filter(|t| t.branch == ins.rva) {
                    pending.extend(table.targets.iter().copied());
                }
                // Windows user-mode INT 29h terminates the process. Padding
                // after it can contain bytes outside the linear instruction set.
                let fast_fail = pe.windows_user_mode
                    && ins.iced.mnemonic() == iced_x86::Mnemonic::Int
                    && ins.iced.immediate8() == 0x29;
                if ins.falls_through() && !fast_fail {
                    pending.push(ins.rva + ins.len as u32);
                }
            }
            for (i, ins) in instrs.iter_mut().enumerate() {
                if ins.pinned && !ambiguous && reached.contains(&i)
                    && !pe.is_protected(ins.off..ins.off + ins.len)
                {
                    metadata_only_pins.insert(ins.rva);
                }
                ins.pinned |= ambiguous || !reached.contains(&i);
                ins.dead = !ambiguous && !reached.contains(&i);
            }
        }
        // Keep only the prefix that decoded cleanly. Trailing undecodable
        // bytes stay unlifted; data or padding that happens to decode can
        // still be included. Verification re-decodes exactly this span.
        let end_rva = sec.virtual_address + (cur - sec.raw_ptr as usize) as u32;

        // Record every direct branch, including targets outside this region.
        // Filtering here would discard the cross-region references that
        // the movement guard needs to see.
        let targets: HashSet<u32> = instrs
            .iter()
            .filter(|i| i.is_direct_branch())
            .filter_map(|i| i.branch_target_rva(pe.image_base))
            .chain(resolved_indirect.values().copied())
            .chain(jump_tables.iter().flat_map(|t| t.targets.iter().copied()))
            .collect();
        for t in &targets {
            branch_owners.entry(*t).or_default().push(f_idx);
        }

        // Boundaries: region start, branch targets, after each terminator.
        let mut bounds: BTreeSet<usize> = BTreeSet::from([0]);
        let scope_boundaries: BTreeSet<_> = pe
            .c_specific
            .get(&base_rva)
            .into_iter()
            .flat_map(|info| &info.scopes)
            .flat_map(|s| [s.begin, s.end, s.target])
            .collect();
        for (k, ins) in instrs.iter().enumerate() {
            if k > 0
                && (targets.contains(&ins.rva)
                    || scope_boundaries.contains(&ins.rva)
                    || pe.eh_continuations.contains(&ins.rva)
                    || pe
                        .cpp_eh
                        .get(&base_rva)
                        .is_some_and(|i| i.continuations.contains(&ins.rva))
                    || instrs[k - 1].ends_block())
            {
                bounds.insert(k);
            }
        }
        let bounds: Vec<usize> = bounds.into_iter().collect();
        let mut spans: Vec<(usize, usize)> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
        if let Some(&last) = bounds.last() {
            if last < instrs.len() {
                spans.push((last, instrs.len()));
            }
        }
        let blocks: Vec<Block> = spans
            .iter()
            .map(|&(s, e)| Block {
                start_rva: instrs[s].rva,
                end_rva: instrs[e - 1].rva + instrs[e - 1].len as u32,
                instrs: instrs[s..e].to_vec(),
            })
            .collect();

        // Chains: maximal runs of blocks connected by fall-through edges.
        let mut chains: Vec<Chain> = Vec::new();
        let mut cur_chain: Vec<usize> = vec![0];
        for bi in 1..blocks.len() {
            if blocks[bi - 1]
                .instrs
                .last()
                .is_some_and(|last| !last.falls_through())
            {
                chains.push(Chain {
                    blocks: std::mem::take(&mut cur_chain),
                });
            }
            cur_chain.push(bi);
        }
        chains.push(Chain { blocks: cur_chain });

        Some(Function {
            start_rva: base_rva,
            end_rva,
            off,
            instr_count: instrs.len(),
            blocks,
            chains,
            resolved_indirect,
            jump_tables,
        })
    }
}
