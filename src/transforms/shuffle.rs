//! Pass 3 — Basic Block Shuffling.
//!
//! Blocks are grouped into *chains* (maximal runs of blocks connected by
//! fall-through edges — see `analysis`). Control never *enters* a chain
//! through a fall-through, so a chain can be laid out anywhere inside its
//! function as long as every branch that targets it is patched explicitly —
//! exactly the "rewrite control flow to jump between blocks" strategy that
//! makes static layout assumptions useless.
//!
//! A chain is only moved when it passes these conservative checks:
//!
//! - it is not the function's entry chain (entry RVAs must not change),
//! - it ends in a no-fall-through terminator (`jmp`/`ret`),
//! - it contains no bytes covered by a base relocation fixup,
//! - none of its bytes may be a known target from outside the function
//!   (tail-merged code, jump thunks, external call targets).
//!
//! Consecutive movable chains are relayouted together in a random order;
//! every direct branch (jcc/jmp/loop/jrcxz/call) whose target moved gets its
//! displacement rewritten in place, preserving each branch's original width
//! (rel8 stays rel8). If any displacement would overflow its encoding, the
//! whole function is reverted to its original bytes.

use std::collections::HashMap;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::analysis::{Analysis, Function};
use crate::pe::PeLayout;
use crate::stats::Counters;

/// Configuration for basic block shuffling.
#[derive(Debug, Clone)]
pub struct Config {
    /// Probability [0, 1] that a function's movable chains are shuffled.
    pub probability: f64,
}

/// One relayout operation: move `size` bytes from `src_off` to `dst_off`.
struct Relayout {
    src_rel: usize,
    dst_rel: usize,
    size: usize,
}

/// One displacement rewrite: write `value` as `width` bytes at `off_rel`.
struct DisplPatch {
    off_rel: usize,
    width: usize,
    value: i64,
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
        if pe
            .runtime_functions
            .iter()
            .any(|r| r.start < func.end_rva && func.start_rva < r.end)
        {
            c.skipped_metadata += 1;
            continue;
        }
        if rng.gen::<f64>() >= cfg.probability {
            continue;
        }
        if func.chains.len() < 2 {
            continue;
        }
        let size = (func.end_rva - func.start_rva) as usize;
        let snapshot = data[func.off..func.off + size].to_vec();

        match shuffle_function(analysis, pe, func, f_idx, &snapshot, data, rng) {
            Ok(applied) => {
                if applied {
                    c.applied += 1;
                }
            }
            Err(()) => {
                // Any failed invariant: restore original bytes entirely.
                data[func.off..func.off + size].copy_from_slice(&snapshot);
                c.reverted += 1;
            }
        }
    }
    c
}

/// Attempts to shuffle one function. `Ok(true)` = relayouted, `Ok(false)` =
/// nothing moved, `Err(())` = function reverted.
///
/// `snapshot` holds the function's bytes *before* shuffling; relayouts copy
/// from it so overlapping moves can never corrupt contents.
#[allow(clippy::too_many_arguments)]
fn shuffle_function(
    analysis: &Analysis,
    pe: &PeLayout,
    func: &Function,
    f_idx: usize,
    snapshot: &[u8],
    data: &mut [u8],
    rng: &mut impl Rng,
) -> Result<bool, ()> {
    let base = func.start_rva;

    // Which chains can move, and why not.
    let movable: Vec<bool> = func
        .chains
        .iter()
        .enumerate()
        .map(|(ci, chain)| {
            if ci == 0 {
                return false; // function entry: RVAs must stay stable
            }
            let ends_clean = chain.blocks.last().is_some_and(|&bi| {
                func.blocks[bi]
                    .instrs
                    .last()
                    .is_some_and(|last| !last.falls_through())
            });
            if !ends_clean {
                return false;
            }
            let no_pinned = chain
                .blocks
                .iter()
                .all(|&bi| func.blocks[bi].instrs.iter().all(|i| !i.pinned));
            if !no_pinned {
                return false;
            }
            // An external target may be inside a block, not only at a
            // boundary recognized by this function's local decode.
            chain.blocks.iter().all(|&bi| {
                let block = &func.blocks[bi];
                !analysis.range_externally_referenced(f_idx, block.start_rva..block.end_rva)
            })
        })
        .collect();

    // Maximal runs of consecutive movable chains.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut k = 0;
    while k < movable.len() {
        if !movable[k] {
            k += 1;
            continue;
        }
        let s = k;
        while k < movable.len() && movable[k] {
            k += 1;
        }
        if k - s >= 2 {
            runs.push((s, k));
        }
    }
    if runs.is_empty() {
        return Ok(false);
    }

    // Block start RVA → chain index (for patch lookups).
    let mut block_chain: HashMap<u32, usize> = HashMap::new();
    for (ci, chain) in func.chains.iter().enumerate() {
        for &bi in &chain.blocks {
            block_chain.insert(func.blocks[bi].start_rva, ci);
        }
    }

    // Plan: random chain order per run, then byte deltas.
    let mut delta: HashMap<usize, i64> = HashMap::new();
    let mut relayouts: Vec<Relayout> = Vec::new();
    for &(cs, ce) in &runs {
        let mut order: Vec<usize> = (cs..ce).collect();
        let mut changed = false;
        for _ in 0..8 {
            order.shuffle(rng);
            if order.iter().enumerate().any(|(k, &v)| cs + k != v) {
                changed = true;
                break;
            }
        }
        if !changed {
            continue;
        }

        // Lay the permuted chains back-to-back inside the run's span.
        let mut cursor = chain_start_rva(func, cs) as i64 - base as i64;
        for &ci in &order {
            let old_start = chain_start_rva(func, ci) as i64 - base as i64;
            let chain_size = chain_size(func, ci) as i64;
            delta.insert(ci, cursor - old_start);
            relayouts.push(Relayout {
                src_rel: old_start as usize,
                dst_rel: cursor as usize,
                size: chain_size as usize,
            });
            cursor += chain_size;
        }
    }
    if relayouts.is_empty() {
        return Ok(false);
    }

    // Patch every direct branch whose target chain moved. Block starts within
    // a moved chain shift together with it, so branches internal to a chain
    // need no patch (their delta cancels out) — they are rewritten with the
    // same value, which is harmless and keeps the logic simple.
    let mut patches: Vec<DisplPatch> = Vec::new();
    for block in func.blocks.iter() {
        let Some(&bchain) = block_chain.get(&block.start_rva) else {
            return Err(());
        };
        let bdelta = delta.get(&bchain).copied().unwrap_or(0);
        for ins in &block.instrs {
            let is_call = ins.iced.is_call_near();
            if !ins.is_direct_branch() && !is_call {
                continue;
            }
            let target_rva = ins.branch_target_rva(pe.image_base);
            let target_rva = match target_rva {
                Some(t) => t,
                // Direct jcc/jmp always have a target; calls don't count as
                // "direct branches" but do have a near-branch target.
                None if is_call => {
                    (ins.iced.near_branch_target().wrapping_sub(pe.image_base)) as u32
                }
                None => return Err(()),
            };
            let tdelta = match block_chain.get(&target_rva) {
                // Target is a block of this function: it may have moved.
                Some(&tchain) => delta.get(&tchain).copied().unwrap_or(0),
                // Target outside this function (call/jmp into another
                // function): a static address that never moves.
                None => 0,
            };
            if tdelta == 0 && bdelta == 0 {
                continue;
            }

            let width = branch_width(ins, is_call);
            let new_branch_rva = ins.rva as i64 + bdelta;
            let new_target_rva = target_rva as i64 + tdelta;
            let disp = new_target_rva - (new_branch_rva + ins.len as i64);

            let fits = match width {
                1 => i8::try_from(disp).is_ok(),
                _ => i32::try_from(disp).is_ok(),
            };
            if !fits {
                return Err(()); // cannot widen in place: revert the function
            }
            patches.push(DisplPatch {
                off_rel: (ins.rva as i64 + bdelta) as usize - base as usize + ins.len - width,
                width,
                value: disp,
            });
        }
    }

    // Apply: relayout bytes (from the snapshot), then rewrite displacements.
    for r in &relayouts {
        let src = &snapshot[r.src_rel..r.src_rel + r.size];
        data[func.off + r.dst_rel..func.off + r.dst_rel + r.size].copy_from_slice(src);
    }
    for p in &patches {
        let off = func.off + p.off_rel;
        let bytes = p.value.to_le_bytes();
        data[off..off + p.width].copy_from_slice(&bytes[..p.width]);
    }
    // Finally, relocate every RIP-relative memory operand inside a moved
    // chain (`lea`, IAT calls through `[rip+IAT]`, global loads/stores, ...).
    // The target data does not move, so the absolute address must survive:
    // re-encoding at the new IP recomputes the stored displacement. This is
    // what makes shuffling safe on real code, which references data
    // RIP-relative almost exclusively.
    for block in func.blocks.iter() {
        let Some(&bchain) = block_chain.get(&block.start_rva) else {
            return Err(());
        };
        let Some(bdelta) = delta.get(&bchain).copied() else {
            continue; // chain did not move
        };
        if bdelta == 0 {
            continue;
        }
        for ins in &block.instrs {
            if !ins.iced.is_ip_rel_memory_operand() {
                continue;
            }
            let new_rva = (ins.rva as i64 + bdelta) as u32;
            let Some(bytes) = super::relocate_ip_relative(&ins.iced, pe.va(new_rva), ins.len)
            else {
                return Err(()); // cannot fix in place: revert the function
            };
            let off = func.off + (new_rva - base) as usize;
            data[off..off + ins.len].copy_from_slice(&bytes);
        }
    }
    Ok(true)
}

fn chain_start_rva(func: &Function, ci: usize) -> u32 {
    let chain = &func.chains[ci];
    func.blocks[chain.blocks[0]].start_rva
}

fn chain_size(func: &Function, ci: usize) -> u32 {
    let chain = &func.chains[ci];
    let first = &func.blocks[chain.blocks[0]];
    let last = &func.blocks[*chain.blocks.last().unwrap()];
    last.end_rva - first.start_rva
}

/// Original displacement width of a branch: 1 (rel8) or 4 (rel32).
fn branch_width(ins: &crate::analysis::Instr, is_call: bool) -> usize {
    if is_call {
        return 4;
    }
    let i = &ins.iced;
    if i.is_jcc_short() || i.is_jmp_short() || i.is_loop() || i.is_loopcc() || i.is_jcx_short() {
        1
    } else {
        4
    }
}
