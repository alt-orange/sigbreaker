#[allow(dead_code)]
mod common;
use common::TestPe;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{analysis::Analysis, pe::PeFile, transforms::relayout};
use std::collections::BTreeSet;

fn fixture() -> PeFile {
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    fixture_code(&code)
}

fn fixture_code(code: &[u8]) -> PeFile {
    let mut p = TestPe::new().with_code(code);
    p.data[0xE0..0xE4].copy_from_slice(&0x2040u32.to_le_bytes());
    p.data[0xE4..0xE8].copy_from_slice(&12u32.to_le_bytes());
    p.data[0x840..0x844].copy_from_slice(&0x1000u32.to_le_bytes());
    p.data[0x844..0x848].copy_from_slice(&(0x1000 + code.len() as u32).to_le_bytes());
    p.data[0x848..0x84C].copy_from_slice(&0x2080u32.to_le_bytes());
    p.data[0x880] = 1;
    PeFile::parse(p.data).unwrap()
}

#[test]
fn relocation_preserves_padded_msvc_prologue_and_epilogues() {
    let code = [
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, // padded push rbx; sub rsp,32
        0x85, 0xC9, 0x74, 11, 0xB8, 1, 0, 0, 0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xB8, 2, 0, 0,
        0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3,
    ];
    let mut data = fixture_code(&code).data;
    data[0x880..0x888].copy_from_slice(&[1, 6, 2, 0, 6, 0x32, 2, 0x30]);
    let mut pe = PeFile::parse(data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let count = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(count.applied, 1);
    let f = pe.layout().runtime_functions.last().unwrap();
    let start = pe.layout().rva_to_offset(f.start).unwrap();
    let end = pe.layout().rva_to_offset(f.end - 1).unwrap() + 1;
    assert_eq!(&pe.data[start..start + 6], &code[..6]);
    let epilogue = [0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];
    assert_eq!(
        pe.data[start..end]
            .windows(6)
            .filter(|w| *w == epilogue)
            .count(),
        2
    );
}

#[test]
fn planner_widens_short_conditional_branch() {
    let mut code = vec![0x85, 0xC9, 0x74, 0, 0xC3];
    code.extend(std::iter::repeat_n(0x90, 200));
    code.push(0xC3);
    let p = fixture_code(&code);
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let encoded =
        relayout::encode_function(&a.functions[0], p.layout().va(0x4000), &[0, 2, 1], &p.data)
            .unwrap();
    let mut d = Decoder::with_ip(
        64,
        &encoded.code,
        p.layout().va(0x4000),
        DecoderOptions::NONE,
    );
    let _ = d.decode();
    let branch = d.decode();
    assert_eq!(branch.mnemonic(), Mnemonic::Je);
    assert_eq!(branch.len(), 6);
    assert_eq!(
        branch.near_branch_target(),
        encoded.address_map[&p.layout().va(0x1004)]
    );
}

#[test]
fn planner_preserves_external_rip_memory_target() {
    let p = fixture_code(&[
        0x8B, 0x05, 0xFA, 0x0F, 0, 0, // mov eax,[rip+0xffa] -> RVA 0x2000
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ]);
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let encoded =
        relayout::encode_function(&a.functions[0], p.layout().va(0x4000), &[0, 2, 1], &p.data)
            .unwrap();
    let mut d = Decoder::with_ip(
        64,
        &encoded.code,
        p.layout().va(0x4000),
        DecoderOptions::NONE,
    );
    assert_eq!(d.decode().ip_rel_memory_address(), p.layout().va(0x2000));
}

#[test]
fn absolute_interior_code_pointer_prevents_movement() {
    let mut bytes = fixture().data;
    bytes[0x810..0x818].copy_from_slice(&0x14000100Au64.to_le_bytes());
    bytes[0xC08..0xC0A].copy_from_slice(&0xA010u16.to_le_bytes());
    let mut p = PeFile::parse(bytes.clone()).unwrap();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    assert!(a.range_externally_referenced(0, 0x1001..0x1010));
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 0);
    assert_eq!(bytes, p.data);
}

#[test]
fn expanded_layout_is_deterministic_and_preserves_overlay() {
    let mut first = fixture();
    first.data.extend_from_slice(b"test overlay data");
    let overlay = first.data.len() - 17;
    let mut second = PeFile::parse(first.data.clone()).unwrap();
    for p in [&mut first, &mut second] {
        let a = Analysis::run(p.layout(), &p.data).unwrap();
        let c = relayout::run(&a, p, 1.0, &mut StdRng::seed_from_u64(7)).unwrap();
        assert_eq!(c.applied, 1);
    }
    assert_eq!(first.data, second.data);
    assert_eq!(&first.data[first.data.len() - 17..], b"test overlay data");
    assert!(first.data.len() - 17 > overlay);
}

// Tiny semantic oracle for this fixture. It follows generated control flow,
// including inserted jumps, rather than comparing instruction multisets.
fn evaluate(pe: &PeFile, zero: bool) -> u32 {
    let mut ip = pe.layout().va(0x1000);
    let mut eax = 0;
    for _ in 0..20 {
        let off = pe
            .layout()
            .rva_to_offset((ip - pe.layout().image_base) as u32)
            .unwrap();
        let mut d = Decoder::with_ip(64, &pe.data[off..], ip, DecoderOptions::NONE);
        let ins = d.decode();
        ip = ins.next_ip();
        match ins.mnemonic() {
            Mnemonic::Test => (),
            Mnemonic::Je => {
                if zero {
                    ip = ins.near_branch_target();
                }
            }
            Mnemonic::Jmp => ip = ins.near_branch_target(),
            Mnemonic::Mov => {
                assert_eq!(ins.op0_register(), Register::EAX);
                eax = ins.immediate32();
            }
            Mnemonic::Ret => return eax,
            _ => panic!("invalid emitted instruction {ins}"),
        }
    }
    panic!("unexpected loop")
}

#[test]
fn expanded_layout_preserves_both_paths_and_publishes_unwind_entries() {
    let mut p = fixture();
    let original = p.data.clone();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert!(p.data.len() > original.len());
    assert_eq!(p.layout().runtime_functions.len(), 1);
    assert_eq!(p.layout().sections.len(), 3);
    assert_eq!(p.layout().sections[0].name(), ".text");
    assert!(p.layout().sections[0].raw_size > 0x200);
    assert!(p.data[0x405..0x410].iter().all(|b| *b == 0xCC));
    assert_ne!(&p.data[0x400..0x410], &original[0x400..0x410]);
    assert_eq!(evaluate(&p, false), 1);
    assert_eq!(evaluate(&p, true), 2);
    let new = p.layout().runtime_functions.last().unwrap();
    assert_eq!(p.layout().unwind_info(new.start).unwrap().rva, 0x2080);
}

#[test]
fn planner_inserts_fallthrough_jump_and_rejects_duplicate_blocks() {
    let p = fixture();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let f = &a.functions[0];
    let encoded = relayout::encode_function(f, p.layout().va(0x4000), &[0, 2, 1], &p.data).unwrap();
    assert_eq!(encoded.inserted_jumps, 1);
    assert_eq!(encoded.address_map.len(), f.instr_count);
    assert!(relayout::encode_function(f, p.layout().va(0x4000), &[0, 1, 1], &p.data).is_err());
}

#[test]
fn occupied_header_slot_and_overlay_are_preserved() {
    let mut p = fixture();
    p.data[0x1C0..0x1E8].fill(0xA5);
    p.data.extend_from_slice(b"overlay survives text growth");
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert!(p.data[0x1C0..0x1E8].iter().all(|b| *b == 0xA5));
    assert!(p.data.ends_with(b"overlay survives text growth"));
}

#[test]
fn text_grows_without_a_new_header_or_executable_section() {
    let mut p = fixture();
    p.data[0x1C0..0x1E8].fill(0xA5);
    let original = p.data.clone();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert_eq!(p.layout().sections.len(), 3);
    assert!(p.data[0x405..0x410].iter().all(|b| *b == 0xCC));
    assert_ne!(&p.data[0x400..0x410], &original[0x400..0x410]);
    assert_eq!(evaluate(&p, true), 2);
    assert_eq!(evaluate(&p, false), 1);
    assert!(!p.layout().sections.last().unwrap().is_executable());
}

#[test]
fn reprocessing_preserves_entry_chain_and_behavior() {
    let mut p = fixture();
    for seed in [42, 7, 17] {
        let a = Analysis::run(p.layout(), &p.data).unwrap();
        let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(seed)).unwrap();
        assert!(c.applied > 0);
        assert_eq!(evaluate(&p, true), 2);
        assert_eq!(evaluate(&p, false), 1);
    }
    assert_eq!(p.layout().sections.len(), 3);
    assert_eq!(
        p.layout()
            .sections
            .iter()
            .filter(|s| s.is_executable())
            .count(),
        1
    );
}

#[test]
fn growing_prefixes_expand_dense_memory_instructions_without_shuffling() {
    let mut p = fixture_code(&[0x85, 0xC9, 0x74, 3, 0x8B, 0x02, 0xC3, 0x8B, 0x02, 0xC3]);
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let cfg = sigbraker::transforms::segment_inject::Config {
        probability: 1.0,
        segments: vec![Register::DS],
    };
    let mut inplace = p.data.clone();
    assert_eq!(
        sigbraker::transforms::segment_inject::run(
            &a,
            p.layout(),
            &mut inplace,
            &cfg,
            &mut StdRng::seed_from_u64(42)
        )
        .applied,
        0
    );
    let count =
        relayout::run_with_segments(&a, &mut p, 0.0, &mut StdRng::seed_from_u64(42), Some(&cfg))
            .unwrap();
    assert_eq!(count.applied, 1);
    let f = p.layout().runtime_functions.last().unwrap();
    let start = p.layout().rva_to_offset(f.start).unwrap();
    let end = p.layout().rva_to_offset(f.end - 1).unwrap() + 1;
    let mut d = Decoder::with_ip(
        64,
        &p.data[start..end],
        p.layout().va(f.start),
        DecoderOptions::NONE,
    );
    let instructions: Vec<_> = d.iter().collect();
    let loads: Vec<_> = instructions
        .iter()
        .filter(|i| i.mnemonic() == Mnemonic::Mov)
        .collect();
    assert_eq!(loads.len(), 2);
    for load in loads {
        assert_eq!(load.segment_prefix(), Register::DS);
        assert_eq!(load.len(), 3);
        assert_eq!(load.memory_base(), Register::RDX);
    }
    assert_eq!(
        instructions[1].near_branch_target(),
        instructions
            .iter()
            .rfind(|i| i.mnemonic() == Mnemonic::Mov)
            .unwrap()
            .ip()
    );
}

#[test]
fn growing_prefixes_support_one_and_two_blocks_and_preserve_results() {
    for code in [
        vec![0x8B, 0x02, 0x01, 0xC0, 0xC3],
        vec![0x8B, 0x02, 0xEB, 0, 0x01, 0xC0, 0xC3],
    ] {
        let mut pe = fixture_code(&code);
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        assert!(a.functions[0].blocks.len() < 3);
        let snapshot = pe.data.clone();
        let shuffle = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
        assert_eq!(shuffle.applied, 0);
        assert_eq!(shuffle.skipped_reasons["too few blocks to shuffle"], 1);
        assert_eq!(snapshot, pe.data);
        let cfg = sigbraker::transforms::segment_inject::Config {
            probability: 1.0,
            segments: vec![Register::DS],
        };
        let grown = relayout::run_with_segments(
            &a,
            &mut pe,
            1.0,
            &mut StdRng::seed_from_u64(42),
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(grown.applied, 1);
        for value in [0u32, 1, 123, u32::MAX] {
            let mut ip = pe.layout().va(0x1000);
            let mut eax = 0;
            let mut returned = false;
            for _ in 0..12 {
                let off = pe
                    .layout()
                    .rva_to_offset((ip - pe.layout().image_base) as u32)
                    .unwrap();
                let ins = Decoder::with_ip(64, &pe.data[off..], ip, DecoderOptions::NONE).decode();
                ip = ins.next_ip();
                match ins.mnemonic() {
                    Mnemonic::Jmp => ip = ins.near_branch_target(),
                    Mnemonic::Mov => {
                        assert_eq!(ins.memory_base(), Register::RDX);
                        assert_eq!(ins.segment_prefix(), Register::DS);
                        eax = value;
                    }
                    Mnemonic::Add => {
                        assert_eq!(ins.op0_register(), Register::EAX);
                        assert_eq!(ins.op1_register(), Register::EAX);
                        eax = eax.wrapping_add(eax);
                    }
                    Mnemonic::Ret => {
                        returned = true;
                        break;
                    }
                    _ => panic!("unexpected instruction {ins}"),
                }
            }
            assert!(returned);
            assert_eq!(eax, value.wrapping_mul(2));
        }
    }
}

#[test]
fn rebuilt_text_can_move_data_rvas_and_raw_offsets_without_new_sections() {
    let source = fixture_code(&[
        0x8B, 0x05, 0xFA, 0x0F, 0, 0, 0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0,
        0, 0xC3,
    ]);
    let mut data = source.data;
    data[0xC08..0xC0A].copy_from_slice(&0xA010u16.to_le_bytes());
    data[0x810..0x818].copy_from_slice(&0x140002020u64.to_le_bytes());
    let certificate = data.len() as u32;
    data[0xE8..0xEC].copy_from_slice(&certificate.to_le_bytes());
    data[0xEC..0xF0].copy_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(b"testcert");
    let mut pe = PeFile::parse(data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let plan = sigbraker::writer::SectionPlan::new(&pe).unwrap();
    let start = plan.rva;
    let encoded =
        relayout::encode_function(&a.functions[0], pe.layout().va(start), &[0, 2, 1], &pe.data)
            .unwrap();
    let end = start + encoded.code.len() as u32;
    let mut payload = encoded.code;
    payload.resize(0x2000, 0); // .text grows beyond its old virtual allocation
    let mut jump = vec![0xE9];
    jump.extend_from_slice(&((start as i64 - 0x1005) as i32).to_le_bytes());
    plan.commit(
        &mut pe,
        payload,
        &[(start, end, 0x2080)],
        &[(0x400, jump)],
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(pe.layout().sections.len(), 3);
    let rdata = pe
        .layout()
        .sections
        .iter()
        .find(|s| s.name() == ".rdata")
        .unwrap();
    assert!(rdata.virtual_address > 0x2000);
    assert!(rdata.raw_ptr > 0x800);
    let delta = rdata.virtual_address - 0x2000;
    let load = pe.layout().rva_to_offset(start).unwrap();
    let instruction = Decoder::with_ip(
        64,
        &pe.data[load..],
        pe.layout().va(start),
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(
        instruction.ip_rel_memory_address(),
        pe.layout().va(0x2000 + delta)
    );
    assert_eq!(pe.layout().unwind_info(start).unwrap().rva, 0x2080 + delta);
    let slot = pe.layout().rva_to_offset(0x2010 + delta).unwrap();
    assert_eq!(
        u64::from_le_bytes(pe.data[slot..slot + 8].try_into().unwrap()),
        pe.layout().va(0x2020 + delta)
    );
    let cert = u32::from_le_bytes(pe.data[0xE8..0xEC].try_into().unwrap()) as usize;
    assert_eq!(&pe.data[cert..cert + 8], b"testcert");
    assert!(pe.data[0x405..0x416].iter().all(|b| *b == 0xCC));
}
