#[allow(dead_code)]
mod common;

use common::TestPe;
use iced_x86::Register;
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{
    analysis::Analysis,
    pe::PeFile,
    transforms::{reorder, segment_inject, shuffle},
};

fn metadata_fixture(code: &[u8]) -> TestPe {
    let mut fixture = TestPe::new().with_code(code);
    // PE exception directory points inside .rdata, not a specially named section.
    fixture.data[0xE0..0xE4].copy_from_slice(&0x2040u32.to_le_bytes());
    fixture.data[0xE4..0xE8].copy_from_slice(&12u32.to_le_bytes());
    fixture.data[0x840..0x844].copy_from_slice(&0x1000u32.to_le_bytes());
    fixture.data[0x844..0x848].copy_from_slice(&(0x1000 + code.len() as u32).to_le_bytes());
    fixture.data[0x848..0x84C].copy_from_slice(&0x2080u32.to_le_bytes());
    fixture.data[0x880] = 1; // UNWIND_INFO version 1, no unwind codes
    fixture
}

#[test]
fn committed_private_stack_and_saved_nonvolatile_scheduling_preserve_state() {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
    use std::collections::BTreeMap;
    let code = [
        0x48, 0x89, 0x4C, 0x24, 8, 0x48, 0x89, 0x54, 0x24, 16, // successful home-slot writes
        0x53, 0x48, 0x83, 0xEC, 32, 0x90, // save rbx, allocate, end prologue
        0x89, 0x44, 0x24, 48, 0x89, 0x4C, 0x24, 56, // independent private stores
        0x8B, 0x44, 0x24, 48, 0x8B, 0x4C, 0x24, 56, 0x89, 0xC3, 0x89, 0xCA, 0x89, 0xD8, 0x48, 0x83,
        0xC4, 32, 0x5B, 0xC3,
    ];
    let execute = |bytes: &[u8]| {
        let mut regs = BTreeMap::from([
            (Register::RAX, 101u64),
            (Register::RCX, 303),
            (Register::RDX, 707),
            (Register::RBX, 999),
            (Register::RSP, 0x1000),
        ]);
        let mut mem = BTreeMap::<u64, u8>::new();
        let mut decoder = Decoder::with_ip(64, bytes, 0x140001000, DecoderOptions::NONE);
        while decoder.can_decode() {
            let i = decoder.decode();
            let read = |reg: Register, regs: &BTreeMap<Register, u64>| {
                let value = regs.get(&reg.full_register()).copied().unwrap_or(0);
                if reg.is_gpr32() {
                    value & 0xFFFFFFFF
                } else {
                    value
                }
            };
            let address = regs[&Register::RSP].wrapping_add(i.memory_displacement64());
            match i.mnemonic() {
                Mnemonic::Nop => {}
                Mnemonic::Mov => {
                    let size = i.memory_size().size();
                    let value = if i.op1_kind() == OpKind::Memory {
                        (0..size).fold(0u64, |v, b| {
                            v | ((*mem.get(&(address + b as u64)).unwrap_or(&0) as u64) << (8 * b))
                        })
                    } else {
                        read(i.op1_register(), &regs)
                    };
                    if i.op0_kind() == OpKind::Memory {
                        for b in 0..size {
                            mem.insert(address + b as u64, (value >> (8 * b)) as u8);
                        }
                    } else {
                        regs.insert(i.op0_register().full_register(), value);
                    }
                }
                Mnemonic::Push => {
                    let value = read(i.op0_register(), &regs);
                    let sp = regs[&Register::RSP] - 8;
                    regs.insert(Register::RSP, sp);
                    for b in 0..8 {
                        mem.insert(sp + b, (value >> (8 * b)) as u8);
                    }
                }
                Mnemonic::Pop => {
                    let sp = regs[&Register::RSP];
                    let value = (0..8).fold(0u64, |v, b| {
                        v | ((*mem.get(&(sp + b)).unwrap_or(&0) as u64) << (8 * b))
                    });
                    regs.insert(i.op0_register(), value);
                    regs.insert(Register::RSP, sp + 8);
                }
                Mnemonic::Sub => {
                    let sp = regs[&Register::RSP] - i.immediate(1);
                    regs.insert(Register::RSP, sp);
                }
                Mnemonic::Add => {
                    let sp = regs[&Register::RSP] + i.immediate(1);
                    regs.insert(Register::RSP, sp);
                }
                Mnemonic::Ret => break,
                _ => panic!("unexpected {i}"),
            }
        }
        (regs, mem)
    };
    let mut fixture = metadata_fixture(&code);
    fixture.data[0x880..0x888].copy_from_slice(&[1, 15, 2, 0, 15, 0x32, 11, 0x30]);
    let pe = PeFile::parse(fixture.data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let mut memory_moved = false;
    let mut nonvolatile_moved = false;
    for seed in 0..32 {
        let mut data = pe.data.clone();
        reorder::run(
            &a,
            pe.layout(),
            &mut data,
            &reorder::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(seed),
        );
        let output = &data[0x400..0x400 + code.len()];
        assert_eq!(execute(output), execute(&code));
        assert_eq!(&output[..15], &code[..15]);
        assert_eq!(&output[code.len() - 6..], &code[code.len() - 6..]);
        memory_moved |= output[16..32] != code[16..32];
        nonvolatile_moved |= output[32..38] != code[32..38];
    }
    assert!(memory_moved && nonvolatile_moved);
}

#[test]
fn embedded_call_byte_does_not_split_metadata_function() {
    let pe = PeFile::parse(
        metadata_fixture(&[
            0x48, 0xB8, 0xE8, 0, 0, 0, 0, 0, 0, 0, // mov rax, 0xe8
            0xC3,
        ])
        .data,
    )
    .unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(a.functions.len(), 1);
    assert_eq!(a.functions[0].instr_count, 2);
    assert_eq!(a.functions[0].end_rva, 0x100B);
}

#[test]
fn injection_preserves_inline_data_but_changes_reachable_instruction() {
    let pe = PeFile::parse(
        metadata_fixture(&[
            0xEB, 3, // jump over inline bytes
            0x8B, 0x40, 0, // decodable data, must remain untouched
            0x8B, 0x40, 0, // reachable mov eax, [rax+0]
            0xC3,
        ])
        .data,
    )
    .unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let mut output = pe.data.clone();
    let counters = segment_inject::run(
        &a,
        pe.layout(),
        &mut output,
        &segment_inject::Config {
            probability: 1.0,
            segments: vec![Register::DS],
        },
        &mut StdRng::seed_from_u64(42),
    );
    assert_eq!(counters.applied, 1);
    assert_eq!(&output[0x402..0x405], &pe.data[0x402..0x405]);
    assert_eq!(&output[0x405..0x408], &[0x3E, 0x8B, 0]);
}

#[test]
fn movement_preserves_functions_with_exception_handlers() {
    let mut fixture = metadata_fixture(common::SAMPLE_CODE);
    fixture.data[0x880] = 1 | (1 << 3); // version 1, EHANDLER
    fixture.data[0x884..0x888].copy_from_slice(&0x1000u32.to_le_bytes());
    let pe = PeFile::parse(fixture.data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let mut output = pe.data.clone();
    let mut rng = StdRng::seed_from_u64(42);
    let r = reorder::run(
        &a,
        pe.layout(),
        &mut output,
        &reorder::Config { probability: 1.0 },
        &mut rng,
    );
    let s = shuffle::run(
        &a,
        pe.layout(),
        &mut output,
        &shuffle::Config { probability: 1.0 },
        &mut rng,
    );
    assert_eq!(output, pe.data);
    assert_eq!(r.skipped_metadata, 1);
    assert_eq!(s.skipped_metadata, 1);
}

#[test]
fn metadata_register_reordering_changes_code_and_preserves_result() {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use std::collections::HashMap;
    let code = [
        0x90, // retained entry/prologue boundary
        0xB8, 1, 0, 0, 0, // eax = 1
        0xB9, 2, 0, 0, 0, // ecx = 2
        0xBA, 3, 0, 0, 0, // edx = 3
        0x01, 0xC8, // eax += ecx
        0x01, 0xD0, // eax += edx
        0xC3,
    ];
    let pe = PeFile::parse(metadata_fixture(&code).data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let mut changed = false;
    for seed in 0..32 {
        let mut output = pe.data.clone();
        let r = reorder::run(
            &a,
            pe.layout(),
            &mut output,
            &reorder::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(seed),
        );
        changed |= r.applied > 0;
        assert_eq!(&output[..0x401], &pe.data[..0x401]);
        assert_eq!(
            &output[0x400 + code.len()..],
            &pe.data[0x400 + code.len()..]
        );
        let mut regs = HashMap::<Register, u32>::new();
        let mut decoder = Decoder::with_ip(
            64,
            &output[0x400..0x400 + code.len()],
            pe.layout().va(0x1000),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let ins = decoder.decode();
            match ins.mnemonic() {
                Mnemonic::Mov => {
                    regs.insert(ins.op0_register(), ins.immediate32());
                }
                Mnemonic::Add => {
                    let value = regs[&ins.op0_register()] + regs[&ins.op1_register()];
                    regs.insert(ins.op0_register(), value);
                }
                Mnemonic::Nop | Mnemonic::Ret => (),
                _ => panic!("unexpected instruction"),
            }
        }
        assert_eq!(regs[&Register::EAX], 6);
    }
    assert!(
        changed,
        "must exercise real reordering, not a metadata skip"
    );
}

#[test]
fn prologue_and_stack_restoration_remain_byte_identical() {
    let code = [
        0x50, // push rax
        0xB8, 1, 0, 0, 0, 0xB9, 2, 0, 0, 0, 0x58, // pop rax
        0xC3,
    ];
    let mut fixture = metadata_fixture(&code);
    fixture.data[0x881] = 11; // all candidate movs belong to the prologue
    let pe = PeFile::parse(fixture.data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    for seed in 0..32 {
        let mut output = pe.data.clone();
        reorder::run(
            &a,
            pe.layout(),
            &mut output,
            &reorder::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(seed),
        );
        assert_eq!(output, pe.data);
    }
}

#[test]
fn unsupported_unwind_formats_never_enable_register_scheduling() {
    let code = [0x90, 0xB8, 1, 0, 0, 0, 0xB9, 2, 0, 0, 0, 0xC3];
    for header in [1 | (1 << 3), 1 | (2 << 3), 2, 3] {
        let mut fixture = metadata_fixture(&code);
        fixture.data[0x880] = header;
        fixture.data[0x884..0x888].copy_from_slice(&0x1000u32.to_le_bytes());
        let pe = PeFile::parse(fixture.data).unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        let mut output = pe.data.clone();
        let counters = reorder::run(
            &a,
            pe.layout(),
            &mut output,
            &reorder::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(42),
        );
        assert_eq!(output, pe.data);
        assert_eq!(counters.applied, 0);
        assert_eq!(counters.skipped_metadata, 1);
    }
}

#[test]
fn relocation_directory_survives_section_rename() {
    let mut fixture = TestPe::new();
    fixture.data[0x198..0x1A0].copy_from_slice(b"renamed\0");
    let pe = PeFile::parse(fixture.data).unwrap();
    assert!(pe.layout().is_protected(0x810..0x818));
}

#[test]
fn unsorted_overlapping_relocations_protect_the_full_union() {
    let mut fixture = TestPe::new();
    // Two eight-byte fixups in descending order, four bytes apart.
    fixture.data[0xC08..0xC0A].copy_from_slice(&0xA014u16.to_le_bytes());
    fixture.data[0xC0A..0xC0C].copy_from_slice(&0xA010u16.to_le_bytes());
    let pe = PeFile::parse(fixture.data).unwrap();
    let layout = pe.layout();
    assert_eq!(layout.relocation_count(), 2);
    assert!(!layout.is_protected(0x80F..0x810));
    assert!(layout.is_protected(0x810..0x811));
    assert!(layout.is_protected(0x815..0x816));
    assert!(layout.is_protected(0x81B..0x81C));
    assert!(!layout.is_protected(0x81C..0x81D));
}

#[test]
fn rejects_truncated_exception_directory_and_short_optional_header() {
    let mut fixture = metadata_fixture(&[0xC3]);
    fixture.data[0xE4..0xE8].copy_from_slice(&11u32.to_le_bytes());
    assert!(PeFile::parse(fixture.data).is_err());
    let mut fixture = TestPe::new();
    fixture.data[0x54..0x56].copy_from_slice(&2u16.to_le_bytes());
    assert!(PeFile::parse(fixture.data).is_err());
}

#[test]
fn chained_unwind_protects_primary_and_rejects_cycles_and_mismatches() {
    let mut p = metadata_fixture(&[0x90, 0x48, 0x89, 0xC8, 0xC3]);
    p.data[0x410..0x412].copy_from_slice(&[0x90, 0xC3]);
    p.data[0xE4..0xE8].copy_from_slice(&24u32.to_le_bytes());
    for (at, value) in [
        (0x84C, 0x1010u32),
        (0x850, 0x1012),
        (0x854, 0x2090),
        (0x894, 0x1000),
        (0x898, 0x1005),
        (0x89C, 0x2080),
    ] {
        p.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    p.data[0x890] = 1 | 4 << 3;
    let pe = PeFile::parse(p.data.clone()).unwrap();
    assert_eq!(pe.layout().metadata_pinned, vec![0x1000..0x1005]);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(a.functions[0]
        .blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .all(|i| i.pinned));
    let mut aliased = pe.data.clone();
    let c = sigbraker::transforms::opcode_alias::run(
        &a,
        pe.layout(),
        &mut aliased,
        &sigbraker::transforms::opcode_alias::Config { probability: 1.0 },
        &mut StdRng::seed_from_u64(42),
    );
    assert_eq!(c.applied, 1);
    assert_eq!(&aliased[0x400..0x405], &[0x90, 0x48, 0x8B, 0xC1, 0xC3]);
    let mut with_fixup = p.data.clone();
    with_fixup[0xC00..0xC04].copy_from_slice(&0x1000u32.to_le_bytes());
    with_fixup[0xC08..0xC0A].copy_from_slice(&0xA000u16.to_le_bytes());
    let fixed = PeFile::parse(with_fixup).unwrap();
    let analysis = Analysis::run(fixed.layout(), &fixed.data).unwrap();
    let mut aliased = fixed.data.clone();
    let c = sigbraker::transforms::opcode_alias::run(
        &analysis,
        fixed.layout(),
        &mut aliased,
        &sigbraker::transforms::opcode_alias::Config { probability: 1.0 },
        &mut StdRng::seed_from_u64(42),
    );
    assert_eq!(c.applied, 0);
    assert_eq!(aliased, fixed.data);
    let mut mismatch = p.data.clone();
    mismatch[0x89C..0x8A0].copy_from_slice(&0x2084u32.to_le_bytes());
    assert!(PeFile::parse(mismatch).is_err());
    p.data[0x880] = 1 | 4 << 3;
    p.data.copy_within(0x84C..0x858, 0x884);
    assert!(PeFile::parse(p.data)
        .unwrap_err()
        .to_string()
        .contains("cyclic"));
}

#[test]
fn readonly_rva_and_absolute_tables_protect_interior_code() {
    let mut p = metadata_fixture(&[0x90, 0x90, 0xC3]);
    p.data[0x820..0x824].copy_from_slice(&0x1001u32.to_le_bytes());
    p.data[0x828..0x830].copy_from_slice(&0x140001002u64.to_le_bytes());
    let pe = PeFile::parse(p.data).unwrap();
    let targets = pe.layout().data_code_references(&pe.data);
    assert!(targets.contains(&0x1001));
    assert!(targets.contains(&0x1002));
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(a.range_externally_referenced(0, 0x1001..0x1003));
}

#[test]
fn lea_scheduling_changes_code_and_preserves_address_arithmetic() {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use std::collections::HashMap;
    let code = [0x90, 0x8D, 0x41, 3, 0x8D, 0x51, 5, 0x01, 0xD0, 0xC3];
    let pe = PeFile::parse(metadata_fixture(&code).data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let mut changed = false;
    for seed in 0..32 {
        let mut output = pe.data.clone();
        let count = reorder::run(
            &a,
            pe.layout(),
            &mut output,
            &reorder::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(seed),
        );
        changed |= count.applied > 0;
        for input in [0u32, 1, 100, u32::MAX] {
            let mut regs = HashMap::from([(Register::RCX, input)]);
            let mut d = Decoder::with_ip(
                64,
                &output[0x400..0x400 + code.len()],
                pe.layout().va(0x1000),
                DecoderOptions::NONE,
            );
            while d.can_decode() {
                let i = d.decode();
                match i.mnemonic() {
                    Mnemonic::Lea => {
                        let value =
                            regs[&i.memory_base()].wrapping_add(i.memory_displacement64() as u32);
                        regs.insert(i.op0_register(), value);
                    }
                    Mnemonic::Add => {
                        let value = regs[&i.op0_register()].wrapping_add(regs[&i.op1_register()]);
                        regs.insert(i.op0_register(), value);
                    }
                    Mnemonic::Nop | Mnemonic::Ret => (),
                    _ => panic!("unexpected instruction"),
                }
            }
            assert_eq!(regs[&Register::EAX], input.wrapping_mul(2).wrapping_add(8));
        }
    }
    assert!(changed);
}
