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
}

impl Analysis {
    /// Lifts all executable sections of the image.
    pub fn run(pe: &PeLayout, data: &[u8]) -> Result<Analysis> {
        let mut functions = Vec::new();
        let mut branch_owners: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut call_targets = pe.relocated_code_references(data);
        call_targets.extend(pe.data_code_references(data));
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
                    Self::lift_region(pe, data, sec, start_rel, end_rel, f_idx, &mut branch_owners)
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
                                call_targets.insert(rva);
                            }
                        }
                    }
                    if ins.iced.is_call_near() {
                        call_targets.insert(
                            ins.iced.near_branch_target().wrapping_sub(pe.image_base) as u32,
                        );
                    }
                }
                functions.push(func);
            }
        }

        Ok(Analysis {
            functions,
            branch_owners,
            call_targets,
        })
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
        if range.start >= range.end {
            return false;
        }
        self.branch_owners
            .range(range.clone())
            .any(|(_, owners)| owners.iter().any(|&owner| owner != f_idx))
            || self.call_targets.range(range).next().is_some()
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
                || pe
                    .metadata_pinned
                    .iter()
                    .any(|range| range.start < rva + len as u32 && rva < range.end);
            instrs.push(Instr {
                off: cur,
                rva: sec.virtual_address + (cur - sec.raw_ptr as usize) as u32,
                len,
                pinned,
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
                if ins.falls_through() {
                    pending.push(ins.rva + ins.len as u32);
                }
            }
            for (i, ins) in instrs.iter_mut().enumerate() {
                ins.pinned |= ambiguous || !reached.contains(&i);
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
        })
    }
}
