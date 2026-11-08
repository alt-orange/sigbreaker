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
    for header in [1 | (1 << 3), 1 | (2 << 3), 1 | (4 << 3), 2, 3] {
        let mut fixture = metadata_fixture(&code);
        fixture.data[0x880] = header;
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
fn rejects_truncated_exception_directory_and_short_optional_header() {
    let mut fixture = metadata_fixture(&[0xC3]);
    fixture.data[0xE4..0xE8].copy_from_slice(&11u32.to_le_bytes());
    assert!(PeFile::parse(fixture.data).is_err());
    let mut fixture = TestPe::new();
    fixture.data[0x54..0x56].copy_from_slice(&2u16.to_le_bytes());
    assert!(PeFile::parse(fixture.data).is_err());
}
