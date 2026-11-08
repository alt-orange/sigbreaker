//! Semantics-preserving binary transformation passes.

pub mod opcode_alias;
pub mod relayout;
pub mod reorder;
pub mod segment_inject;
pub mod shuffle;

use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction};

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

/// Byte offset of the opcode when the instruction is a register-register
/// MR/RM pair of an aliasable operation: ADD, OR, ADC, SBB, AND, SUB, XOR,
/// CMP and MOV all exist in a memory-destination (MR) and a register-
/// destination (RM) form that differ in opcode bit 1 and in which ModRM field
/// carries the destination. For two register operands the forms assemble to
/// the same machine effects, so flipping that bit while swapping the ModRM
/// reg and rm fields rewrites the instruction into the equivalent encoding.
///
/// The scan handles legacy prefixes and a REX byte; VEX/EVEX opcodes and any
/// trailing immediate or displacement byte are rejected. Returns the opcode
/// byte index and, when present, the REX byte index.
fn alias_opcode_index(bytes: &[u8]) -> Option<(usize, Option<usize>)> {
    let mut i = 0;
    while i < bytes.len()
        && matches!(
            bytes[i],
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
        )
    {
        i += 1;
    }
    let rex = (i < bytes.len() && (0x40..=0x4F).contains(&bytes[i])).then(|| {
        let at = i;
        i += 1;
        at
    });
    let opcode = *bytes.get(i)?;
    // ALU operations live in groups of eight opcodes (ADD 00-05, OR 08-0D,
    // ADC, SBB, AND, SUB, XOR 30-35, CMP 38-3D) where bit 0 selects the
    // operand size and bit 1 the MR/RM direction; opcodes with bit 2 set are
    // immediate forms. MOV register-register pairs are 88-8B. Segment and
    // other special MOVs are excluded.
    let aliasable = (opcode < 0x40 && opcode & 0b100 == 0) || (0x88..=0x8B).contains(&opcode);
    if !aliasable {
        return None;
    }
    let modrm = *bytes.get(i + 1)?;
    if modrm >> 6 != 0b11 {
        return None; // a memory operand makes the two forms semantically distinct
    }
    if i + 2 != bytes.len() {
        return None; // reg,reg forms never carry immediates or displacements
    }
    Some((i, rex))
}

/// Rewrites `bytes` into an equivalent aliased encoding in place when one
/// exists. Every candidate is self-verified: the aliased bytes are decoded
/// again and must match the original decode exactly once normalized back to
/// the original opcode - same length, same mnemonic, same operand registers,
/// same memory and immediate effects. Returns whether a patch was applied.
pub fn alias_in_place(bytes: &mut [u8], ip: u64) -> bool {
    let Some((index, rex)) = alias_opcode_index(bytes) else {
        return false;
    };
    let original = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode();
    if original.is_invalid() {
        return false;
    }
    let mut aliased = bytes.to_vec();
    aliased[index] ^= 0x02;
    let modrm = aliased[index + 1];
    aliased[index + 1] = 0b1100_0000 | ((modrm & 0b0000_0111) << 3) | (modrm >> 3 & 0b0000_0111);
    // The register fields swap, so their REX extension bits swap as well:
    // REX.R extends the reg field, REX.B the rm field. X is unused for
    // register-register forms and stays untouched.
    if let Some(at) = rex {
        let r = (aliased[at] >> 2) & 1;
        let b = aliased[at] & 1;
        aliased[at] = (aliased[at] & 0xF8) | (b << 2) | r;
    }
    let decoded = Decoder::with_ip(64, &aliased, ip, DecoderOptions::NONE).decode();
    if decoded.is_invalid() || decoded.len() != original.len() {
        return false;
    }
    let mut normalized = decoded;
    normalized.set_code(original.code());
    if normalized != original {
        return false;
    }
    bytes.copy_from_slice(&aliased);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_aliases(bytes: &[u8]) {
        let mut data = bytes.to_vec();
        assert!(alias_in_place(&mut data, 0x140000000), "{bytes:02x?}");
        assert_ne!(data, bytes, "{bytes:02x?} was not aliased");
        let mut back = data.clone();
        assert!(alias_in_place(&mut back, 0x140000000));
        assert_eq!(
            back, bytes,
            "aliasing is not an involution for {bytes:02x?}"
        );
    }

    fn reject(bytes: &[u8]) {
        let mut data = bytes.to_vec();
        assert!(!alias_in_place(&mut data, 0x140000000), "{bytes:02x?}");
    }

    #[test]
    fn alu_register_pairs_alias_in_both_directions() {
        // xor eax, ebx (31 c3) / xor ebx, eax-form (33 c3); mov rbp, rsp both
        // forms; byte and REX variants.
        for bytes in [
            &[0x31, 0xC3][..],       // xor eax, ebx (MR)
            &[0x33, 0xC3][..],       // xor ebx, eax (RM)
            &[0x48, 0x89, 0xEC][..], // mov rsp, rbp (MR)
            &[0x48, 0x8B, 0xEC][..], // mov rbp, rsp (RM)
            &[0x44, 0x89, 0xF8][..], // mov eax, r15d (MR, REX.R)
            &[0x88, 0xD1][..],       // mov cl, dl (byte, MR)
            &[0x8A, 0xD1][..],       // mov dl, cl (byte, RM)
            &[0x66, 0x31, 0xDB][..], // xor bx, bx with operand-size prefix
            &[0x00, 0xC8][..],       // add al, cl (MR)
        ] {
            assert_aliases(bytes);
        }
    }

    #[test]
    fn memory_and_escaped_forms_are_left_alone() {
        for bytes in [
            &[0x03, 0x45, 0x08][..], // add eax, [rbp+8]: RM with disp8
            &[0x89, 0x45, 0xF8][..], // mov [rbp-8], eax: MR with disp8
            &[0x31, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00][..], // xor [abs], eax
            &[0x83, 0xC0, 0x01][..], // add eax, 1: immediate
            &[0xB8, 0x00, 0x00, 0x00, 0x00][..], // mov eax, imm32
            &[0x0F, 0x1F, 0x40, 0x00][..], // nop: escaped opcode
            &[0xC4, 0xC1, 0x74, 0x58, 0xD2][..], // VEX: vaddps
            &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00][..], // lea
        ] {
            reject(bytes);
        }
    }
}
