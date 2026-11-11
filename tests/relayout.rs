#[allow(dead_code)]
mod common;
use common::TestPe;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{analysis::Analysis, pe::PeFile, transforms::relayout};

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
fn bounded_absolute_rva_and_relative_jump_tables_follow_relocated_cases() {
    for kind in 0..3 {
        let dispatch: Vec<u8> = match kind {
            0 => vec![0x48, 0x8D, 0x15, 0xF3, 0x0F, 0, 0, 0xFF, 0x24, 0xCA],
            1 => vec![
                0x48, 0x8D, 0x15, 0xF3, 0xEF, 0xFF, 0xFF, 0x8B, 0x84, 0x8A, 0, 0x20, 0, 0, 0x48,
                0x01, 0xD0, 0xFF, 0xE0,
            ],
            _ => vec![
                0x48, 0x8D, 0x15, 0xF3, 0x0F, 0, 0, 0x48, 0x63, 0x04, 0x8A, 0x48, 0x01, 0xD0, 0xFF,
                0xE0,
            ],
        };
        let first = 0x1006 + dispatch.len() as u32;
        let mut code = vec![0x48, 0x83, 0xF9, 1, 0x77, (dispatch.len() + 12) as u8];
        code.extend(dispatch);
        for value in [11u8, 22, 33] {
            code.extend_from_slice(&[0xB8, value, 0, 0, 0, 0xC3]);
        }
        let mut data = fixture_code(&code).data;
        data[0x800..0x820].fill(0);
        for (i, target) in [first, first + 6].iter().enumerate() {
            match kind {
                0 => data[0x800 + i * 8..0x808 + i * 8]
                    .copy_from_slice(&(0x140000000u64 + *target as u64).to_le_bytes()),
                1 => data[0x800 + i * 4..0x804 + i * 4].copy_from_slice(&target.to_le_bytes()),
                _ => data[0x800 + i * 4..0x804 + i * 4]
                    .copy_from_slice(&(*target as i32 - 0x2000).to_le_bytes()),
            }
        }
        if kind == 0 {
            data[0xC08..0xC0A].copy_from_slice(&0xA000u16.to_le_bytes());
            data[0xC0A..0xC0C].copy_from_slice(&0xA008u16.to_le_bytes());
        } else {
            data[0xF0..0xF8].fill(0);
        }
        let mut pe = PeFile::parse(data.clone()).unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        assert_eq!(a.functions[0].jump_tables.len(), 1, "kind {kind}");
        let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
        assert_eq!(c.applied, 1, "kind {kind}: {c}");
        let table = pe.layout().rva_to_offset(0x2000).unwrap();
        for i in 0..2 {
            let target = match kind {
                0 => {
                    (u64::from_le_bytes(
                        pe.data[table + i * 8..table + i * 8 + 8]
                            .try_into()
                            .unwrap(),
                    ) - pe.layout().image_base) as u32
                }
                1 => u32::from_le_bytes(
                    pe.data[table + i * 4..table + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                ),
                _ => {
                    (0x2000i64
                        + i32::from_le_bytes(
                            pe.data[table + i * 4..table + i * 4 + 4]
                                .try_into()
                                .unwrap(),
                        ) as i64) as u32
                }
            };
            assert!(target >= 0x4000);
            let at = pe.layout().rva_to_offset(target).unwrap();
            assert_eq!(
                &pe.data[at..at + 5],
                &[0xB8, if i == 0 { 11 } else { 22 }, 0, 0, 0]
            );
        }
        // No bound, or a join into the dispatch, must not establish a table.
        data[0x404] = 0xEB;
        let pe = PeFile::parse(data).unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        assert!(a.functions[0].jump_tables.is_empty());
    }
}

#[test]
fn wipe_ignores_relocation_records_but_preserves_fixup_targets() {
    for keep_body in [false, true] {
        let mut data = fixture().data;
        // The pair of 16-bit relocation entries looks like the code RVA
        // 0x100a to an untyped scan. The separate DIR64 fixup is a real pointer.
        data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());
        data[0xC04..0xC10].copy_from_slice(&[16, 0, 0, 0, 0x0A, 0x10, 0, 0, 0x20, 0xA0, 0, 0]);
        if keep_body {
            data[0x820..0x828].copy_from_slice(&0x14000100Au64.to_le_bytes());
        }
        // A symbol map forces the append strategy without changing the code.
        let mut pe = PeFile::parse_with_symbols(data.clone(), [(0x1000, "entry".into())].into())
            .unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
        assert_eq!(c.applied, 1);
        assert_eq!(pe.layout().sections.last().unwrap().name(), ".sbrk");
        let old = pe.layout().rva_to_offset(0x1000).unwrap();
        assert_eq!(pe.data[old], 0xE9);
        if keep_body {
            assert_eq!(c.original_bytes_wiped, 0);
            assert_eq!(&pe.data[old + 5..old + 16], &data[0x405..0x410]);
        } else {
            assert_eq!(c.wiped_original, 1);
            assert_eq!(c.original_bytes_wiped, 11);
            assert_eq!(&pe.data[old + 5..old + 16], &[0xCC; 11]);
        }
    }
}

#[test]
fn wipe_preserves_a_foreign_branch_target_trimmed_from_the_copy() {
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
        0xB8, 3, 0, 0, 0, 0xC3,
    ];
    let mut data = fixture_code(&code).data;
    for (at, value) in [(0xE4, 24u32), (0x84C, 0x1080), (0x850, 0x1085), (0x854, 0x2090)] {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[0x890] = 1;
    data[0x480..0x485].copy_from_slice(&[0xE9, 0x8B, 0xFF, 0xFF, 0xFF]); // jmp 0x1010
    let mut pe = PeFile::parse_with_symbols(data, [(0x1000, "entry".into())].into()).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(a.functions[0].blocks.last().unwrap().instrs[0].dead);
    let c = relayout::run_with_segments(
        &a,
        &mut pe,
        1.0,
        &mut StdRng::seed_from_u64(42),
        None,
        relayout::Options {
            wipe_original: true,
            ..relayout::Options::default()
        },
    )
    .unwrap();
    assert_eq!(c.applied, 1);
    assert_eq!(c.wiped_original, 0);
    let old = pe.layout().rva_to_offset(0x1000).unwrap();
    assert_eq!(pe.data[old], 0xE9);
    assert_eq!(&pe.data[old + 5..old + code.len()], &code[5..]);
}

#[test]
fn retained_entry_can_route_a_proven_call_site_to_its_copy() {
    let code = [
        0x48, 0x83, 0xEC, 0x28, 0x90, // sub rsp, 40; nop
        0xE8, 0x76, 0, 0, 0, 0xCC, // call 0x1080; int3
        0x48, 0x83, 0xC4, 0x28, 0xC3, // add rsp, 40; ret
    ];
    for call_is_address_taken in [false, true] {
        let mut data = fixture_code(&code).data;
        data[0x880..0x888].copy_from_slice(&[1, 4, 1, 0, 4, 0x42, 0, 0]);
        data[0x480] = 0xC3;
        data[0x820..0x824].copy_from_slice(&0x1001u32.to_le_bytes());
        if call_is_address_taken {
            data[0x824..0x828].copy_from_slice(&0x1005u32.to_le_bytes());
        }
        let mut pe = PeFile::parse_with_symbols(data, [(0x1000, "entry".into())].into()).unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        let c = relayout::run_with_segments(
            &a,
            &mut pe,
            1.0,
            &mut StdRng::seed_from_u64(42),
            None,
            relayout::Options {
                junk_probability: 1.0,
                wipe_original: true,
                ..Default::default()
            },
        )
        .unwrap();
        let layout = pe.layout();
        let entry = layout.rva_to_offset(0x1000).unwrap();
        assert_eq!(&pe.data[entry..entry + 5], &code[..5]);
        assert_eq!(c.wiped_original, 0);
        if call_is_address_taken {
            assert_eq!(c.redirected_original_calls, 0);
            assert_eq!(&pe.data[entry..entry + code.len()], &code);
            continue;
        }
        assert_eq!(c.redirected_original_calls, 1);
        let jump = Decoder::with_ip(64, &pe.data[entry + 5..], layout.va(0x1005), DecoderOptions::NONE)
            .decode();
        assert_eq!(jump.mnemonic(), Mnemonic::Jmp);
        let target = jump.near_branch_target();
        let offset = layout.rva_to_offset((target - layout.image_base) as u32).unwrap();
        let call = Decoder::with_ip(64, &pe.data[offset..], target, DecoderOptions::NONE).decode();
        assert_eq!(call.mnemonic(), Mnemonic::Call);
        assert_eq!(call.near_branch_target(), layout.va(0x1080));
    }
}

#[test]
fn opaque_metadata_fallback_expands_headers_and_preserves_rvas_and_overlay() {
    let mut data = fixture().data;
    // A second region has an unknown language handler. It must remain intact.
    data[0x480..0x486].copy_from_slice(&[0xB8, 9, 0, 0, 0, 0xC3]);
    for (at, value) in [
        (0xE4, 24u32),
        (0x84C, 0x1080),
        (0x850, 0x1086),
        (0x854, 0x2090),
        (0x894, 0x1080),
    ] {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[0x890] = 9;
    data[0x898..0x8A8].copy_from_slice(b"opaque-EH-data!!");
    // Occupied header padding must be preserved, so a new header needs space.
    data[0x1C0..0x1E8].fill(0xAB);
    let overlay = data.len() as u32;
    data[0xE8..0xEC].copy_from_slice(&overlay.to_le_bytes());
    data[0xEC..0xF0].copy_from_slice(&16u32.to_le_bytes());
    data.extend_from_slice(b"certificate-data");
    let before = PeFile::parse(data).unwrap();
    let mut pe = PeFile::parse(before.data.clone()).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let counters = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(counters.applied, 1);
    assert_eq!(pe.layout().sections.len(), 4);
    for (old, new) in before.layout().sections.iter().zip(&pe.layout().sections) {
        assert_eq!(old.virtual_address, new.virtual_address);
        assert_eq!(new.raw_ptr, old.raw_ptr + 0x200);
    }
    assert_eq!(&pe.data[0x3C0..0x3E8], &[0xAB; 40]);
    let opaque = pe.layout().rva_to_offset(0x2090).unwrap();
    assert_eq!(&pe.data[opaque..opaque + 24], &before.data[0x890..0x8A8]);
    let old_entry = pe.layout().rva_to_offset(0x1000).unwrap();
    assert_eq!(pe.data[old_entry], 0xE9);
    assert_eq!(
        &pe.data[old_entry + 5..old_entry + 16],
        &[0xCC; 11]
    );
    let certificate = u32::from_le_bytes(pe.data[0xE8..0xEC].try_into().unwrap()) as usize;
    assert_eq!(&pe.data[certificate..certificate + 16], b"certificate-data");
    assert!(pe
        .layout()
        .runtime_functions
        .iter()
        .any(|r| r.start == 0x1000));
    // Reprocessing appends another uniquely named section and preserves lookup.
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(7)).unwrap();
    assert_eq!(pe.layout().sections.last().unwrap().name(), ".sbrk1");
}

#[test]
fn resolved_register_jump_rewrites_its_interior_lea_target() {
    let code = [
        0x85, 0xC9, 0x74, 12, 0x48, 0x8D, 0x05, 11, 0, 0, 0, 0x48, 0x89, 0xC2, 0xFF, 0xE2, 0xB8, 1,
        0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    let mut pe = fixture_code(&code);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(a.functions[0].resolved_indirect.get(&0x100E), Some(&0x1016));
    let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1, "{c}");
    let moved = pe.layout().runtime_functions.last().unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let f = a
        .functions
        .iter()
        .find(|f| f.start_rva == moved.start)
        .unwrap();
    assert_eq!(f.resolved_indirect.len(), 1);
    let target = *f.resolved_indirect.values().next().unwrap();
    assert!(moved.contains(&target));
    let at = pe.layout().rva_to_offset(target).unwrap();
    let ins = Decoder::with_ip(
        64,
        &pe.data[at..],
        pe.layout().va(target),
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(ins.mnemonic(), Mnemonic::Mov);
    assert_eq!(ins.immediate32(), 2);
}

#[test]
fn external_rip_lea_to_an_interior_instruction_is_rewritten() {
    let mut data = fixture().data;
    for (at, value) in [
        (0xE4, 24u32),
        (0x84C, 0x1080),
        (0x850, 0x1088),
        (0x854, 0x2090),
    ] {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[0x890] = 1;
    data[0x480..0x488].copy_from_slice(&[0x48, 0x8D, 0x05, 0x83, 0xFF, 0xFF, 0xFF, 0xC3]); // lea rax,[0x100A]
    let mut pe = PeFile::parse(data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(a.address_references.contains_key(&0x100A));
    let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1, "{c}");
    let source = pe.layout().rva_to_offset(0x1080).unwrap();
    let ins = Decoder::with_ip(
        64,
        &pe.data[source..],
        pe.layout().va(0x1080),
        DecoderOptions::NONE,
    )
    .decode();
    let target = (ins.ip_rel_memory_address() - pe.layout().image_base) as u32;
    assert!(target >= 0x4000);
    let at = pe.layout().rva_to_offset(target).unwrap();
    assert_eq!(&pe.data[at..at + 5], &[0xB8, 2, 0, 0, 0]);
}

#[test]
fn version_two_epilogue_distances_follow_shuffled_blocks() {
    let code = [
        0x48, 0x83, 0xEC, 0x28, 0x85, 0xC9, 0x74, 10, 0xB8, 1, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28,
        0xC3, 0xB8, 2, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3,
    ];
    let mut data = fixture_code(&code).data;
    data[0x880..0x88C].copy_from_slice(&[2, 4, 5, 0, 1, 6, 11, 6, 1, 6, 0, 6]);
    data[0x88C..0x890].copy_from_slice(&[4, 0x42, 0, 0]);
    // Five slots: size=1 (RET), two explicit end distances, padding, alloc.
    let mut pe = PeFile::parse(data).unwrap();
    assert_eq!(
        pe.layout()
            .unwind_info(0x1000)
            .unwrap()
            .v2
            .as_ref()
            .unwrap()
            .epilogues
            .len(),
        2
    );
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1, "{c}");
    let f = pe.layout().runtime_functions.last().unwrap();
    let v2 = pe
        .layout()
        .unwind_info(f.start)
        .unwrap()
        .v2
        .as_ref()
        .unwrap();
    assert_eq!(v2.epilogues.len(), 2);
    for epilogue in &v2.epilogues {
        assert_eq!(
            pe.data[pe.layout().rva_to_offset(epilogue.start).unwrap()],
            0xC3
        );
    }
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
        relayout::encode_function(&a.functions[0], p.layout().va(0x4000), &[0, 2, 1], &p.data, usize::MAX, None)
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
        relayout::encode_function(&a.functions[0], p.layout().va(0x4000), &[0, 2, 1], &p.data, usize::MAX, None)
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
fn absolute_interior_code_pointer_preserves_the_original_body() {
    let mut bytes = fixture().data;
    bytes[0x810..0x818].copy_from_slice(&0x14000100Au64.to_le_bytes());
    bytes[0xC08..0xC0A].copy_from_slice(&0xA010u16.to_le_bytes());
    let mut p = PeFile::parse(bytes.clone()).unwrap();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    assert!(a.range_externally_referenced(0, 0x1001..0x1010));
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert_eq!(c.wiped_original, 0);
    let old = p.layout().rva_to_offset(0x1000).unwrap();
    assert_eq!(&p.data[old + 5..old + 16], &bytes[0x405..0x410]);
    let pointer = p.layout().rva_to_offset(0x2010).unwrap();
    assert_eq!(&p.data[pointer..pointer + 8], &0x14000100Au64.to_le_bytes());
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
    assert_eq!(p.layout().runtime_functions.len(), 2);
    assert_eq!(p.layout().sections.len(), 4);
    assert_eq!(p.layout().sections[0].name(), ".text");
    assert_eq!(p.layout().sections[0].raw_size, 0x200);
    assert_eq!(p.layout().sections.last().unwrap().name(), ".sbrk");
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
    let encoded = relayout::encode_function(f, p.layout().va(0x4000), &[0, 2, 1], &p.data, usize::MAX, None).unwrap();
    assert_eq!(encoded.inserted_jumps, 1);
    assert_eq!(encoded.address_map.len(), f.instr_count);
    assert!(relayout::encode_function(f, p.layout().va(0x4000), &[0, 1, 1], &p.data, usize::MAX, None).is_err());
}

#[test]
fn occupied_header_slot_and_overlay_are_preserved() {
    let mut p = fixture();
    p.data[0x1C0..0x1E8].fill(0xA5);
    p.data.extend_from_slice(b"overlay survives text growth");
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert!(p.data[0x3C0..0x3E8].iter().all(|b| *b == 0xA5));
    assert!(p.data.ends_with(b"overlay survives text growth"));
}

#[test]
fn relocation_appends_an_executable_section_and_preserves_text_size() {
    let mut p = fixture();
    p.data[0x1C0..0x1E8].fill(0xA5);
    let original = p.data.clone();
    let a = Analysis::run(p.layout(), &p.data).unwrap();
    let c = relayout::run(&a, &mut p, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 1);
    assert_eq!(p.layout().sections.len(), 4);
    assert_eq!(p.layout().sections[0].raw_size, 0x200);
    let old = p.layout().rva_to_offset(0x1000).unwrap();
    assert!(p.data[old + 5..old + 16].iter().all(|b| *b == 0xCC));
    assert_ne!(&p.data[old..old + 16], &original[0x400..0x410]);
    assert_eq!(evaluate(&p, true), 2);
    assert_eq!(evaluate(&p, false), 1);
    assert!(p.layout().sections.last().unwrap().is_executable());
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
    assert_eq!(p.layout().sections.len(), 6);
    assert_eq!(
        p.layout()
            .sections
            .iter()
            .filter(|s| s.is_executable())
            .count(),
        4
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
        relayout::run_with_segments(&a, &mut p, 0.0, &mut StdRng::seed_from_u64(42), Some(&cfg), relayout::Options::default())
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
            relayout::Options::default(),
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
fn unreachable_padding_diversifies_short_functions_without_segment_prefixes() {
    for (code, block_count) in [
        (&[0xB8, 42, 0, 0, 0, 0xC3][..], 1),
        (&[0xEB, 0, 0xB8, 42, 0, 0, 0, 0xC3][..], 2),
    ] {
        for (shuffle_prob, junk_prob, expected) in [(1.0, 0.0, 0), (0.0, 1.0, 0), (1.0, 1.0, 1)] {
            let mut pe = fixture_code(code);
            let a = Analysis::run(pe.layout(), &pe.data).unwrap();
            assert_eq!(a.functions[0].blocks.len(), block_count);
            let snapshot = pe.data.clone();
            let c = relayout::run_with_segments(
                &a,
                &mut pe,
                shuffle_prob,
                &mut StdRng::seed_from_u64(42),
                None,
                relayout::Options {
                    junk_probability: junk_prob,
                    ..relayout::Options::default()
                },
            )
            .unwrap();
            assert_eq!(c.applied, expected);
            if expected == 0 {
                assert_eq!(pe.data, snapshot);
                continue;
            }

            assert!(c.junk_inserted > 0);
            let layout = pe.layout();
            let entry = Decoder::with_ip(64, &pe.data[0x400..], layout.va(0x1000), DecoderOptions::NONE)
                .decode();
            assert_eq!(entry.mnemonic(), Mnemonic::Jmp);
            let mut ip = entry.near_branch_target();
            let relocated = layout.runtime_functions.last().unwrap();
            assert_eq!(ip, layout.va(relocated.start));
            let decode = |ip| {
                let off = layout.rva_to_offset((ip - layout.image_base) as u32).unwrap();
                Decoder::with_ip(64, &pe.data[off..], ip, DecoderOptions::NONE).decode()
            };
            if block_count == 2 {
                let branch = decode(ip);
                assert_eq!(branch.mnemonic(), Mnemonic::Jmp);
                ip = branch.near_branch_target();
            }
            let mov = decode(ip);
            assert_eq!(mov.mnemonic(), Mnemonic::Mov);
            assert_eq!(mov.op0_register(), Register::EAX);
            assert_eq!(mov.immediate32(), 42);
            let mut ret = decode(mov.next_ip());
            if ret.mnemonic() == Mnemonic::Jmp {
                assert!(ret.near_branch_target() > ret.next_ip());
                ret = decode(ret.near_branch_target());
            }
            assert_eq!(ret.mnemonic(), Mnemonic::Ret);
            assert!(ret.next_ip() < layout.va(relocated.end));
        }
    }
}

#[test]
fn interior_junk_is_skipped_and_keeps_the_prologue_and_epilogue_contiguous() {
    let prologue = [0x48, 0x83, 0xEC, 0x28]; // sub rsp, 40
    let epilogue = [0x48, 0x83, 0xC4, 0x28, 0xC3]; // add rsp, 40; ret
    let widened_epilogue = [0x48, 0x81, 0xC4, 0x28, 0, 0, 0, 0xC3];
    let mut code = prologue.to_vec();
    code.extend([0xB8, 42, 0, 0, 0]); // mov eax, 42
    for _ in 0..10 {
        code.extend([0x83, 0xC0, 1]); // add eax, 1
    }
    code.extend(epilogue);
    let mut data = fixture_code(&code).data;
    data[0x880..0x888].copy_from_slice(&[1, 4, 1, 0, 4, 0x42, 0, 0]);
    let mut pe = PeFile::parse(data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(a.functions[0].blocks.len(), 1);
    let counters = relayout::run_with_segments(
        &a,
        &mut pe,
        1.0,
        &mut StdRng::seed_from_u64(42),
        None,
        relayout::Options {
            junk_probability: 1.0,
            alias_probability: 1.0,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(counters.applied, 1);

    let layout = pe.layout();
    let moved = layout.runtime_functions.last().unwrap();
    let start = layout.rva_to_offset(moved.start).unwrap();
    assert_eq!(&pe.data[start..start + prologue.len()], &[0x4A, 0x83, 0xEC, 0x28]);
    let mut ip = layout.va(moved.start) + prologue.len() as u64;
    let mut jumps = 0;
    let mut adds = 0;
    loop {
        assert!(ip < layout.va(moved.end));
        let off = start + (ip - layout.va(moved.start)) as usize;
        let ins = Decoder::with_ip(64, &pe.data[off..], ip, DecoderOptions::NONE).decode();
        ip = ins.next_ip();
        match ins.mnemonic() {
            Mnemonic::Jmp => {
                assert!(ins.near_branch_target() > ip);
                ip = ins.near_branch_target();
                jumps += 1;
            }
            Mnemonic::Mov => assert_eq!(ins.immediate32(), 42),
            Mnemonic::Add if ins.op0_register() == Register::EAX => adds += 1,
            Mnemonic::Add if ins.op0_register() == Register::RSP => {
                assert_eq!(
                    &pe.data[off..off + widened_epilogue.len()],
                    &widened_epilogue
                );
                break;
            }
            _ => panic!("unexpected instruction {ins}"),
        }
    }
    assert!(jumps >= 2);
    assert_eq!(adds, 10);
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
    let plan = sigbraker::writer::SectionPlan::new_with_address_rewrites(&pe, false).unwrap();
    let start = plan.rva;
    let encoded =
        relayout::encode_function(&a.functions[0], pe.layout().va(start), &[0, 2, 1], &pe.data, usize::MAX, None)
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
        &std::collections::BTreeMap::new(),
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

#[test]
fn entry_jump_does_not_clobber_a_branch_target_reached_from_outside_the_window() {
    // The 5-byte entry trampoline overwrites [start, start + 5). The first
    // instruction (`test ecx, ecx`) is only two bytes, so the jump also clobbers
    // the loop head at 0x1002. A `jg 0x1002` at 0x1007 still points there from
    // outside the window, so the retained body would run a corrupted target. The
    // function must be declined rather than relocated.
    let code = [
        0x85, 0xC9, // 0x1000  test ecx, ecx       (2 bytes; first instruction)
        0xFF, 0xC9, // 0x1002  dec ecx             (loop head, inside the window)
        0x83, 0xF9, 0x00, // 0x1004  cmp ecx, 0
        0x7F, 0xF9, // 0x1007  jg 0x1002           (surviving source, outside the window)
        0xC3, // 0x1009  ret
    ];
    let mut pe = fixture_code(&code);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(a.functions[0].blocks.len(), 3);
    assert!(a.branch_sources.contains_key(&0x1002));
    let snapshot = pe.data.clone();
    let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.applied, 0, "{c}");
    assert_eq!(
        c.skipped_reasons["entry jump would clobber a live interior target"], 1,
        "{c}"
    );
    assert_eq!(pe.data, snapshot, "declined function must be left byte-for-byte");
}

#[test]
fn entry_jump_may_relocate_when_the_only_window_source_is_overwritten_too() {
    // Here the branch into the window (`jmp 0x1004`) lives at 0x1002, inside the
    // trampoline's [start, start + 5) range, so it is overwritten together with
    // the target it feeds: nothing survives to reach the clobbered bytes, and
    // the function stays eligible. The two-block body is diversified through the
    // unreachable-padding path.
    let code = [
        0x8B, 0x02, // 0x1000  mov eax, [rdx]      (2 bytes; first instruction)
        0xEB, 0x00, // 0x1002  jmp 0x1004          (source inside the window)
        0x01, 0xC0, // 0x1004  add eax, eax        (target inside the window)
        0xC3, // 0x1006  ret
    ];
    let mut pe = fixture_code(&code);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(a.functions[0].blocks.len(), 2);
    let c = relayout::run_with_segments(
        &a,
        &mut pe,
        1.0,
        &mut StdRng::seed_from_u64(42),
        None,
        relayout::Options { junk_probability: 1.0, ..relayout::Options::default() },
    )
    .unwrap();
    assert_eq!(c.applied, 1, "{c}");
    assert_eq!(
        c.skipped_reasons
            .get("entry jump would clobber a live interior target")
            .copied()
            .unwrap_or(0),
        0,
        "{c}"
    );
}





