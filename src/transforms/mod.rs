//! Semantics-preserving binary transformation passes.

pub mod opcode_alias;
pub mod relayout;
pub mod reorder;
pub mod segment_inject;
pub mod shuffle;

use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, Register};

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

/// Byte offsets of the opcode and optional REX prefix after legacy prefixes.
fn opcode_offsets(bytes: &[u8]) -> (usize, Option<usize>) {
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
    (i, rex)
}

/// Switches equivalent ALU/MOV direction encodings or changes unused encoding
/// bits in selected legacy instructions. Verify the operands and length before publishing.
pub fn alias_in_place(bytes: &mut [u8], ip: u64) -> bool {
    let (index, rex) = opcode_offsets(bytes);
    let Some(&opcode) = bytes.get(index) else {
        return false;
    };
    let mov = (0x88..=0x8B).contains(&opcode);
    let alu = opcode < 0x40 && opcode & 0b100 == 0;
    let push_or_pop = (0x50..=0x5F).contains(&opcode);
    let mov_immediate = (0xB0..=0xBF).contains(&opcode);
    let scalar_modrm = matches!(opcode, 0x80 | 0x81 | 0x83..=0x85 | 0xC0 | 0xC1 | 0xC6 | 0xC7);
    if !(mov || alu || push_or_pop || mov_immediate || scalar_modrm || opcode == 0x8D) {
        return false;
    }
    let original = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode();
    if original.is_invalid() || original.len() != bytes.len() {
        return false;
    }
    let mut aliased = bytes.to_vec();
    let modrm = bytes.get(index + 1).copied().unwrap_or(0);
    let swapped = (mov || alu) && modrm >> 6 == 3 && index + 2 == bytes.len();
    let mut unused_scale = false;
    if swapped {
        aliased[index] ^= 0x02;
        aliased[index + 1] = 0xC0 | ((modrm & 7) << 3) | (modrm >> 3 & 7);
        if let Some(at) = rex {
            let r = (aliased[at] >> 2) & 1;
            let b = aliased[at] & 1;
            aliased[at] = (aliased[at] & 0xFA) | (b << 2) | r;
        }
    } else if push_or_pop || mov_immediate {
        let Some(at) = rex else { return false };
        aliased[at] ^= 0x02; // The register is encoded in the opcode and REX.B.
    } else if (mov || scalar_modrm || opcode == 0x8D)
        && original.flow_control() == iced_x86::FlowControl::Next
        // Leave the exact opcode prefix of stack-restoring instructions for
        // the version-1 epilogue recognizer. SUB is a stack allocation.
        && (original.op0_register().full_register() != Register::RSP
            || original.mnemonic() == iced_x86::Mnemonic::Sub && modrm >> 6 == 3)
    {
        if modrm >> 6 != 3 && modrm & 7 == 4 {
            // With no index register the scale has no effect on the address.
            if original.memory_index() != Register::None {
                return false;
            }
            aliased[index + 2] ^= 0x40;
            unused_scale = true;
        } else {
            let Some(at) = rex else { return false };
            aliased[at] ^= 0x02; // REX.X extends the SIB index field.
        }
    } else {
        return false;
    }
    let mut decoded = Decoder::with_ip(64, &aliased, ip, DecoderOptions::NONE).decode();
    if decoded.is_invalid() || decoded.len() != original.len() {
        return false;
    }
    if swapped {
        decoded.set_code(original.code());
    }
    if unused_scale && decoded.memory_index() == Register::None {
        decoded.set_memory_index_scale(original.memory_index_scale());
    }
    if decoded != original {
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
            &[0x48, 0x8B, 0x04, 0x4C][..], // mov rax,[rsp+rcx*2]
            &[0x4A, 0x8B, 0x04, 0x24][..], // mov rax,[rsp+r12]
            &[0x49, 0x8D, 0x65, 0x10][..], // lea rsp,[r13+16]
            &[0x48, 0x83, 0xC4, 0x28][..], // add rsp,40
        ] {
            reject(bytes);
        }
    }

    #[test]
    fn ignored_rex_and_sib_bits_alias_in_both_directions() {
        for bytes in [
            &[0x41, 0x57][..],                   // push r15
            &[0x41, 0x5F][..],                   // pop r15
            &[0x48, 0x89, 0x5C, 0x24, 0x08][..], // mov [rsp+8],rbx
            &[0x48, 0x8D, 0x6C, 0x24, 0x20][..], // lea rbp,[rsp+32]
            &[0x48, 0x8B, 0x4D, 0x08][..],       // mov rcx,[rbp+8]
            &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00][..], // lea rax,[rip]
            &[0x48, 0x83, 0xEC, 0x28][..],       // sub rsp,40
        ] {
            assert_aliases(bytes);
        }
    }
}
