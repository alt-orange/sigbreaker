//! Semantics-preserving binary transformation passes.

pub mod relayout;
pub mod reorder;
pub mod segment_inject;
pub mod shuffle;

use iced_x86::{Encoder, Instruction};

/// Re-encodes an instruction at a fixed IP, returning the encoded bytes.
///
/// Returns `None` if the instruction cannot be encoded. Callers compare the
/// encoded length against the original instruction's length to decide whether
/// an in-place patch is possible (SigBreaker never changes code size).
pub fn encode_at(instr: Instruction, ip: u64) -> Option<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    encoder.encode(&instr, ip).ok()?;
    let buffer = encoder.take_buffer();
    (!buffer.is_empty()).then_some(buffer)
}

/// Re-encodes `instr` at `ip` and requires the result to be exactly
/// `expected_len` bytes. Used when patching a single operand (e.g. a
/// RIP-relative displacement) in place: a different length would shift every
/// later instruction, which SigBreaker never allows.
pub fn encode_exact(instr: &Instruction, ip: u64, expected_len: usize) -> Option<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    let n = encoder.encode(instr, ip).ok()?;
    let buffer = encoder.take_buffer();
    (n == expected_len && !buffer.is_empty()).then_some(buffer)
}

/// Relocates an instruction to `new_ip` while preserving the *absolute*
/// target of a RIP-relative memory operand (the encoder recomputes the
/// relative displacement from the new IP). Returns `None` when the
/// re-encoding does not reproduce the original length exactly.
pub fn relocate_ip_relative(instr: &Instruction, new_ip: u64, len: usize) -> Option<Vec<u8>> {
    if !instr.is_ip_rel_memory_operand() {
        return None;
    }
    let mut moved = *instr;
    // `memory_displacement64` is the resolved absolute address for RIP-relative
    // operands; keeping it fixed and re-encoding at `new_ip` adjusts the
    // stored displacement by exactly `old_ip - new_ip`.
    let target = instr.memory_displacement64();
    moved.set_memory_displacement64(target);
    encode_exact(&moved, new_ip, len)
}
