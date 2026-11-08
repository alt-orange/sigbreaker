//! Regression cases for control-flow and scheduling correctness.

#[allow(dead_code)]
mod common;

use iced_x86::{Decoder, DecoderOptions};
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{
    analysis::{Analysis, Instr},
    dependencies,
    pe::PeFile,
    transforms::{reorder, shuffle},
    verify,
};

use common::{TestPe, TEXT_FILE_OFF};

fn decode(code: &[u8]) -> Vec<Instr> {
    let mut decoder = Decoder::with_ip(64, code, 0x1400_01000, DecoderOptions::NONE);
    let mut instrs = Vec::new();
    while decoder.can_decode() {
        let off = decoder.position();
        let iced = decoder.decode();
        assert!(!iced.is_invalid(), "invalid regression fixture at {off}");
        instrs.push(Instr {
            off,
            rva: 0x1000 + off as u32,
            len: iced.len(),
            pinned: false,
            iced,
        });
    }
    instrs
}

#[test]
fn conditional_branches_end_blocks_but_keep_fallthrough() {
    for code in [
        &[0x74, 0x00][..], // jz
        &[0x75, 0x00][..], // jnz
        &[0xE2, 0x00][..], // loop
        &[0xE3, 0x00][..], // jrcxz
    ] {
        let instrs = decode(code);
        assert!(instrs[0].ends_block());
        assert!(instrs[0].falls_through());
    }
    for code in [&[0xEB, 0x00][..], &[0xC3][..], &[0xFF, 0xE0][..]] {
        let instrs = decode(code);
        assert!(instrs[0].ends_block());
        assert!(!instrs[0].falls_through());
    }
}

#[test]
fn shuffle_preserves_entry_fallthrough_and_taken_destination() {
    let fixture = TestPe::new().with_code(&[
        0x85, 0xC9, // test ecx, ecx
        0x74, 0x06, // jz second arm
        0xB8, 1, 0, 0, 0, 0xC3, // mov eax, 1; ret (fall-through)
        0x85, 0xD2, 0x74, 0x06, // second conditional makes both remaining arms reachable
        0xB8, 2, 0, 0, 0, 0xC3, // mov eax, 2; ret
        0xB8, 3, 0, 0, 0, 0xC3, // another movable arm
    ]);
    let pe = PeFile::parse(fixture.data).unwrap();
    let layout = pe.layout();
    let analysis = Analysis::run(layout, &pe.data).unwrap();
    let mut moved = false;

    for seed in 0..32 {
        let mut data = pe.data.clone();
        let counters = shuffle::run(
            &analysis,
            layout,
            &mut data,
            &shuffle::Config { probability: 1.0 },
            &mut StdRng::seed_from_u64(seed),
        );
        moved |= counters.applied > 0;
        // The displacement may change, but the untaken edge must still
        // reach mov eax, 1 at the original next address.
        assert_eq!(
            &data[TEXT_FILE_OFF + 4..TEXT_FILE_OFF + 10],
            &pe.data[TEXT_FILE_OFF + 4..TEXT_FILE_OFF + 10],
            "fall-through changed for seed {seed}",
        );
        let mut decoder = Decoder::with_ip(
            64,
            &data[TEXT_FILE_OFF + 2..TEXT_FILE_OFF + 4],
            layout.va(0x1002),
            DecoderOptions::NONE,
        );
        let branch = decoder.decode();
        let target_rva = (branch.near_branch_target() - layout.image_base) as u32;
        let target = layout.rva_to_offset(target_rva).unwrap();
        assert_eq!(&data[target..target + 3], &[0x85, 0xD2, 0x74]);
        assert_eq!(&data[target + 4..target + 10], &[0xB8, 2, 0, 0, 0, 0xC3]);
        verify::verify(layout, &data, &analysis).unwrap();
    }
    assert!(moved, "fixture must exercise an actual chain movement");
}

#[test]
fn flag_set_clear_and_undefined_results_order_consumers() {
    for code in [
        &[0xF9, 0x11, 0xD8][..],                   // stc; adc eax, ebx
        &[0xF8, 0x11, 0xD8][..],                   // clc; adc eax, ebx
        &[0x11, 0xD8, 0xF9][..],                   // adc eax, ebx; stc (WAR)
        &[0xF9, 0xF8][..],                         // stc; clc (WAW)
        &[0x0F, 0xBC, 0xCA, 0x0F, 0x92, 0xC0][..], // bsf ecx, edx; setc al
    ] {
        let instrs = decode(code);
        let dag = dependencies::build(&instrs);
        assert_eq!(instrs.len(), 2);
        for seed in 0..32 {
            let order =
                dependencies::random_topo_order(&dag.deps, &mut StdRng::seed_from_u64(seed));
            assert_eq!(order, [0, 1], "flag dependency lost for {code:02X?}");
        }
    }
}

#[test]
fn mixed_vector_widths_preserve_raw_war_and_waw_dependencies() {
    for code in [
        // vmovaps ymm0, ymm1; movaps xmm2, xmm0 (RAW)
        &[0xC5, 0xFC, 0x28, 0xC1, 0x0F, 0x28, 0xD0][..],
        // movaps xmm2, xmm0; vmovaps ymm0, ymm1 (WAR)
        &[0x0F, 0x28, 0xD0, 0xC5, 0xFC, 0x28, 0xC1][..],
        // movaps xmm0, xmm1; vmovaps ymm0, ymm2 (WAW)
        &[0x0F, 0x28, 0xC1, 0xC5, 0xFC, 0x28, 0xC2][..],
    ] {
        let instrs = decode(code);
        let dag = dependencies::build(&instrs);
        assert_eq!(instrs.len(), 2);
        for seed in 0..32 {
            assert_eq!(
                dependencies::random_topo_order(&dag.deps, &mut StdRng::seed_from_u64(seed)),
                [0, 1],
                "overlapping vector registers reordered for {code:02X?}",
            );
        }
    }
}

#[test]
fn independent_register_writes_remain_schedulable_in_either_order() {
    let instrs = decode(&[0x89, 0xC8, 0x89, 0xDA]); // mov eax, ecx; mov edx, ebx
    let dag = dependencies::build(&instrs);
    let mut saw_original = false;
    let mut saw_reverse = false;
    for seed in 0..32 {
        let order = dependencies::random_topo_order(&dag.deps, &mut StdRng::seed_from_u64(seed));
        saw_original |= order == [0, 1];
        saw_reverse |= order == [1, 0];
    }
    assert!(saw_original && saw_reverse);
}

#[test]
fn decoded_calls_outside_source_section_are_recorded() {
    let fixture = TestPe::new().with_code(&[
        0xE8, 0xFC, 0x0F, 0, 0, // call RVA 0x2001, outside .text
        0xC3,
    ]);
    let pe = PeFile::parse(fixture.data).unwrap();
    let analysis = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(analysis.externally_referenced(0, 0x2001));
    assert!(analysis.range_externally_referenced(0, 0x2000..0x2002));
    assert!(!analysis.range_externally_referenced(0, 0x2000..0x2001));
    assert!(!analysis.range_externally_referenced(0, 0x2001..0x2001));
}

#[test]
fn cross_function_target_inside_block_prevents_reorder_and_shuffle() {
    let mut code = vec![0xCC; 35];
    code[..23].copy_from_slice(&[
        0xE8, 0x1B, 0, 0, 0,    // call function at 0x1020
        0xC3, // entry chain ends
        0xB8, 1, 0, 0, 0, // mov eax, 1 at 0x1006
        0xB9, 2, 0, 0, 0, // mov ecx, 2 at 0x100b (external target)
        0xC3, 0xBA, 3, 0, 0, 0, // mov edx, 3
        0xC3,
    ]);
    code[32..].copy_from_slice(&[0xEB, 0xE9, 0xC3]); // jmp 0x100b; ret
    let pe = PeFile::parse(TestPe::new().with_code(&code).data).unwrap();
    let layout = pe.layout();
    let analysis = Analysis::run(layout, &pe.data).unwrap();
    assert_eq!(analysis.functions[0].start_rva, 0x1000);
    assert_eq!(analysis.functions[1].start_rva, 0x1020);
    assert!(analysis.externally_referenced(0, 0x100B));
    assert!(analysis.range_externally_referenced(0, 0x1006..0x1011));
    assert!(!analysis.range_externally_referenced(0, 0x1006..0x100B));
    assert!(!analysis.externally_referenced(1, 0x100B));
    assert!(!analysis.functions[0]
        .blocks
        .iter()
        .any(|b| b.start_rva == 0x100B));

    for seed in 0..32 {
        let mut data = pe.data.clone();
        let mut rng = StdRng::seed_from_u64(seed);
        reorder::run(
            &analysis,
            layout,
            &mut data,
            &reorder::Config { probability: 1.0 },
            &mut rng,
        );
        assert_eq!(
            &data[TEXT_FILE_OFF + 6..TEXT_FILE_OFF + 17],
            &pe.data[TEXT_FILE_OFF + 6..TEXT_FILE_OFF + 17],
        );
        let lifted = Analysis::run(layout, &data).unwrap();
        shuffle::run(
            &lifted,
            layout,
            &mut data,
            &shuffle::Config { probability: 1.0 },
            &mut rng,
        );
        assert_eq!(
            &data[TEXT_FILE_OFF + 6..TEXT_FILE_OFF + 17],
            &pe.data[TEXT_FILE_OFF + 6..TEXT_FILE_OFF + 17],
        );
    }
}
