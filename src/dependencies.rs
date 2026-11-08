//! Instruction dependency analysis: the per-basic-block DAG.
//!
//! For a straight-line sequence of instructions, edges are introduced for
//! every true dependency:
//!
//! - **Register dependencies** — read-after-write (RAW), write-after-read
//!   (WAR) and write-after-write (WAW) on GPRs (normalized to their 64-bit
//!   name so sub-register aliasing is always honored) and on vector/mask
//!   registers.
//! - **Memory ordering** — every memory access is ordered after all previous
//!   memory accesses (a conservative load/store chain).
//! - **Calls & side effects** — calls, string instructions, fences,
//!   locked/privileged/system instructions are full barriers.
//! - **Flags** — `RFLAGS` reads and all modifications (including set,
//!   cleared, and undefined flags) are ordered as one conservative register.
//!
//! The DAG is consumed by a randomized variant of Kahn's algorithm
//! ([`random_topo_order`]) which repeatedly picks *uniformly at random*
//! from the current frontier (instructions with no unresolved dependencies).

use std::collections::HashMap;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register};
use rand::Rng;

use crate::analysis::Instr;

/// A dependency DAG over `n` instructions. `deps[i]` lists the indices that
/// must be scheduled before `i`.
pub struct Dag {
    pub deps: Vec<Vec<usize>>,
}

fn reads(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn writes(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Instructions whose side effects escape register/memory tracking; they are
/// serialized against everything else.
fn is_barrier(ins: &Instruction) -> bool {
    if ins.is_call_near()
        || ins.is_call_near_indirect()
        || ins.is_call_far()
        || ins.is_call_far_indirect()
        || ins.is_string_instruction()
        || ins.is_privileged()
        || ins.has_lock_prefix()
    {
        return true;
    }
    if matches!(
        ins.flow_control(),
        FlowControl::XbeginXabortXend | FlowControl::Exception | FlowControl::Interrupt
    ) {
        return true;
    }
    // Everything outside this integer subset may fault or expose implicit
    // x87/MXCSR/system state that this DAG does not model.
    !matches!(
        ins.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Lea
            | Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Not
            | Mnemonic::Neg
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Imul
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Bswap
            | Mnemonic::Stc
            | Mnemonic::Clc
            | Mnemonic::Cmc
            | Mnemonic::Nop
    )
}

/// Builds the dependency DAG for one basic block's instruction sequence.
pub fn build(instrs: &[Instr]) -> Dag {
    build_with_stack_policy(instrs, false)
}
pub(crate) fn build_private_stack(instrs: &[Instr]) -> Dag {
    build_with_stack_policy(instrs, true)
}
fn build_with_stack_policy(instrs: &[Instr], private_stack: bool) -> Dag {
    let n = instrs.len();
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];

    let mut last_writer: HashMap<Register, usize> = HashMap::new();
    let mut readers: HashMap<Register, Vec<usize>> = HashMap::new();
    let mut mem_ops: Vec<usize> = Vec::new();
    let mut last_flag_writer: Option<usize> = None;
    let mut flag_readers: Vec<usize> = Vec::new();
    // Most recent barrier; every later instruction depends on it, and through
    // it transitively on everything before it. Without this, instructions
    // after a barrier could be scheduled *before* it (register state was
    // cleared, so they had no edge back), letting a topological order move
    // code across a call — corrupting both semantics and RIP-relative
    // displacement targets.
    let mut last_barrier: Option<usize> = None;

    let add_edge = |deps: &mut Vec<Vec<usize>>, from: usize, to: usize| {
        if !deps[to].contains(&from) {
            deps[to].push(from);
        }
    };

    let mut factory = InstructionInfoFactory::new();
    for (i, item) in instrs.iter().enumerate() {
        let info = factory.info(&item.iced);
        let touches_memory = info
            .used_memory()
            .iter()
            .any(|m| !matches!(m.access(), OpAccess::None | OpAccess::NoMemAccess));

        let seg_write = info.used_registers().iter().any(|r| {
            writes(r.access())
                && matches!(
                    r.register(),
                    Register::ES
                        | Register::CS
                        | Register::SS
                        | Register::DS
                        | Register::FS
                        | Register::GS
                )
        });

        // Every instruction that follows a barrier must be scheduled after
        // it (transitively closing over all earlier instructions as well).
        if let Some(b) = last_barrier {
            add_edge(&mut deps, b, i);
        }

        if is_barrier(&item.iced) || seg_write || (touches_memory && !private_stack) {
            for j in 0..i {
                add_edge(&mut deps, j, i);
            }
            // A barrier re-orders the whole world: reset aliasing state.
            last_writer.clear();
            readers.clear();
            mem_ops.clear();
            mem_ops.push(i);
            last_flag_writer = Some(i);
            flag_readers.clear();
            last_barrier = Some(i);
            continue;
        }

        // Normalize overlapping GPR and XMM/YMM/ZMM register families.
        let mut reg_reads: Vec<Register> = Vec::new();
        let mut reg_writes: Vec<Register> = Vec::new();
        for used in info.used_registers() {
            let reg = used.register().full_register();
            if reads(used.access()) && !reg_reads.contains(&reg) {
                reg_reads.push(reg);
            }
            if writes(used.access()) && !reg_writes.contains(&reg) {
                reg_writes.push(reg);
            }
        }

        // RAW: reads depend on the current writer (done before writes so that
        // read-modify-write operands see the *previous* writer).
        for &reg in &reg_reads {
            if let Some(&w) = last_writer.get(&reg) {
                add_edge(&mut deps, w, i);
            }
            readers.entry(reg).or_default().push(i);
        }
        // WAW + WAR (a read-modify-write register never depends on itself).
        for &reg in &reg_writes {
            if let Some(&w) = last_writer.get(&reg) {
                if w != i {
                    add_edge(&mut deps, w, i);
                }
            }
            if let Some(rs) = readers.get(&reg) {
                for &r in rs {
                    if r != i {
                        add_edge(&mut deps, r, i);
                    }
                }
            }
            readers.remove(&reg);
            last_writer.insert(reg, i);
        }

        // Memory ordering: a conservative total order among memory accesses.
        if touches_memory {
            for &m in &mem_ops {
                let a = &instrs[m].iced;
                let b = &item.iced;
                let disjoint = private_stack
                    && a.memory_base() == Register::RSP
                    && b.memory_base() == Register::RSP
                    && a.memory_index() == Register::None
                    && b.memory_index() == Register::None
                    && (a.memory_displacement64() as u128 + a.memory_size().size() as u128
                        <= b.memory_displacement64() as u128
                        || b.memory_displacement64() as u128 + b.memory_size().size() as u128
                            <= a.memory_displacement64() as u128);
                if !disjoint {
                    add_edge(&mut deps, m, i);
                }
            }
            mem_ops.push(i);
        }

        // RFLAGS, tracked like a register. Constant set/clear operations and
        // undefined results are writes too; ignoring them could move a carry
        // consumer across stc/clc or a flag-clobbering instruction.
        // `prev_flag_writer` is captured before any update so that a single
        // instruction that both reads and writes RFLAGS (`adc`, `sbb`, `rcr`,
        // ...) edges against the *previous* writer instead of itself — a
        // self-edge here would poison the topological sort with a cycle.
        let flag_reads = item.iced.rflags_read();
        let flag_writes = item.iced.rflags_modified();
        let prev_flag_writer = last_flag_writer;
        if flag_writes != 0 {
            if let Some(w) = prev_flag_writer {
                if w != i {
                    add_edge(&mut deps, w, i);
                }
            }
            for &r in &flag_readers {
                if r != i {
                    add_edge(&mut deps, r, i);
                }
            }
            last_flag_writer = Some(i);
            flag_readers.clear();
        }
        if flag_reads != 0 {
            if let Some(w) = prev_flag_writer {
                add_edge(&mut deps, w, i);
            }
            flag_readers.push(i);
        }
    }

    Dag { deps }
}

/// Randomized Kahn's algorithm: at every step pick a uniformly random node
/// from the frontier (no unresolved dependencies).
pub fn random_topo_order(deps: &[Vec<usize>], rng: &mut impl Rng) -> Vec<usize> {
    let n = deps.len();
    let mut indegree: Vec<usize> = deps.iter().map(Vec::len).collect();
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, d) in deps.iter().enumerate() {
        for &j in d {
            dependents[j].push(i);
        }
    }

    let mut frontier: Vec<usize> = (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while !frontier.is_empty() {
        let k = rng.gen_range(0..frontier.len());
        let node = frontier.swap_remove(k);
        order.push(node);
        for &d in &dependents[node] {
            indegree[d] -= 1;
            if indegree[d] == 0 {
                frontier.push(d);
            }
        }
    }
    debug_assert_eq!(order.len(), n);
    order
}
