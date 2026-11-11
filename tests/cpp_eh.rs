#[allow(dead_code)]
mod common;
use common::TestPe;
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{analysis::Analysis, pe::PeFile, transforms::relayout};

fn put(d: &mut [u8], at: usize, value: u32) {
    d[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn fixture(fh4: bool) -> Vec<u8> {
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    let mut d = TestPe::new().with_code(&code).data;
    d[0x800..0xA00].fill(0);
    for (at, value) in [
        (0xD0, 0x2000),
        (0xD4, 40),
        (0x800, 0x2040),
        (0x80C, 0x2080),
        (0x810, 0x2060),
        (0x840, 0x20A0),
        (0x860, 0x20A0),
        (0xE0, 0x2140),
        (0xE4, 12),
        (0x940, 0x1000),
        (0x944, 0x1010),
        (0x948, 0x20D0),
        (0x8D4, 0x11C0),
        (0x8D8, 0x3000),
        (0xF0, 0),
        (0xF4, 0),
    ] {
        put(&mut d, at, value);
    }
    d[0x880..0x891].copy_from_slice(b"vcruntime140.dll\0");
    let name = if fh4 {
        b"\0\0__CxxFrameHandler4\0"
    } else {
        b"\0\0__CxxFrameHandler3\0"
    };
    d[0x8A0..0x8A0 + name.len()].copy_from_slice(name);
    d[0x8D0] = 9;
    d[0x5C0..0x5C6].copy_from_slice(&[0xFF, 0x25, 0x9A, 0x0E, 0, 0]);
    d[0x5D0] = 0xC3;
    d[0xC00..0xE00].fill(0);
    if fh4 {
        d[0xC00] = 0x38;
        for (at, value) in [(0xC01, 0x3040), (0xC05, 0x3060), (0xC09, 0x3080)] {
            put(&mut d, at, value);
        }
        d[0xC40..0xC43].copy_from_slice(&[4, 8, 8]); // two no-action unwind states
        d[0xC60..0xC64].copy_from_slice(&[2, 0, 0, 2]); // one try, states 0,0,1
        put(&mut d, 0xC64, 0x30A0);
        d[0xC80..0xC87].copy_from_slice(&[6, 0, 0, 8, 2, 12, 4]);
        d[0xCA0..0xCA2].copy_from_slice(&[2, 0x10]);
        put(&mut d, 0xCA2, 0x11D0);
        d[0xCA6] = 20; // one function-relative continuation at +10
    } else {
        for (at, value) in [
            (0xC00, 0x19930522),
            (0xC04, 2),
            (0xC08, 0x3040),
            (0xC14, 3),
            (0xC18, 0x3080),
            (0xC40, u32::MAX),
            (0xC48, u32::MAX),
            (0xC80, 0x1000),
            (0xC84, u32::MAX),
            (0xC88, 0x1004),
            (0xC8C, 0),
            (0xC90, 0x100A),
            (0xC94, 1),
        ] {
            put(&mut d, at, value);
        }
    }
    d
}

#[test]
fn fh3_and_fh4_state_maps_follow_shuffled_instruction_spans() {
    for fh4 in [false, true] {
        let mut pe = PeFile::parse(fixture(fh4)).unwrap();
        assert_eq!(pe.layout().cpp_eh.len(), 1);
        let original = pe.layout().cpp_eh[&0x1000].clone();
        assert_eq!(original.is_fh4(), fh4);
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        let counters = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
        assert_eq!(counters.applied, 1, "{fh4}: {counters}");
        let moved = pe
            .layout()
            .cpp_eh
            .values()
            .find(|i| i.function.start != 0x1000)
            .unwrap();
        assert_eq!(moved.is_fh4(), fh4);
        assert_eq!(moved.handler, original.handler);
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        let f = a
            .functions
            .iter()
            .find(|f| f.start_rva == moved.function.start)
            .unwrap();
        for ins in f.blocks.iter().flat_map(|b| &b.instrs) {
            if ins.iced.mnemonic() != iced_x86::Mnemonic::Mov {
                continue;
            }
            let idx = moved.states.partition_point(|s| s.0 <= ins.rva);
            let state = moved.states[idx - 1].1;
            assert_eq!(state, if ins.iced.immediate32() == 1 { 0 } else { 1 });
        }
        if fh4 {
            assert_eq!(moved.continuations.len(), 1);
            assert!(moved
                .continuations
                .iter()
                .all(|r| moved.function.contains(r)));
        }
    }
}

#[test]
fn fh3_relocated_catch_keeps_its_handler_identity_and_parent_frame_offset() {
    let mut data = fixture(false);
    let catch_code = data[0x400..0x410].to_vec();
    data[0x5D0..0x5E0].copy_from_slice(&catch_code);
    for (at, value) in [
        (0xE4, 24),
        (0x94C, 0x11D0),
        (0x950, 0x11E0),
        (0x954, 0x20D0),
        (0xC04, 3),
        (0xC0C, 1),
        (0xC10, 0x30B0),
        (0xC14, 4),
        (0xC50, u32::MAX),
        (0xC98, 0x11D0),
        (0xC9C, 2),
        (0xCB0, 0),
        (0xCB4, 1),
        (0xCB8, 2),
        (0xCBC, 1),
        (0xCC0, 0x30D0),
        (0xCD0, 0x40), // handler adjectives
        (0xCD8, 0x18), // catch object displacement
        (0xCDC, 0x11D0),
        (0xCE0, 0x28), // parent frame displacement
    ] {
        put(&mut data, at, value);
    }
    let original_handler = data[0xCD0..0xCE4].to_vec();
    let mut pe = PeFile::parse(data).unwrap();
    let analysis = Analysis::run(pe.layout(), &pe.data).unwrap();
    let counters = relayout::run(&analysis, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(counters.relocated_fh3, 2);

    let original = pe.layout().rva_to_offset(0x30D0).unwrap();
    assert_eq!(&pe.data[original..original + 20], &original_handler);
    let relocated: Vec<_> = pe
        .layout()
        .cpp_eh
        .values()
        .filter(|cpp| cpp.function.start >= 0x4000)
        .collect();
    assert_eq!(relocated.len(), 2);
    for cpp in relocated {
        let info = pe.layout().unwind_info(cpp.function.start).unwrap();
        let unwind = pe.layout().rva_to_offset(info.rva).unwrap();
        let language = unwind + 4 + (pe.data[unwind + 2] as usize).div_ceil(2) * 4 + 4;
        let read_rva = |at| u32::from_le_bytes(pe.data[at..at + 4].try_into().unwrap());
        let func_info = pe.layout().rva_to_offset(read_rva(language)).unwrap();
        let tries = pe.layout().rva_to_offset(read_rva(func_info + 16)).unwrap();
        let handler = pe.layout().rva_to_offset(read_rva(tries + 16)).unwrap();
        assert_eq!(&pe.data[handler..handler + 12], &original_handler[..12]);
        assert_eq!(&pe.data[handler + 16..handler + 20], &original_handler[16..]);
        let is_catch = cpp.states.iter().all(|&(_, state)| state == 2);
        assert_eq!(
            read_rva(handler + 12),
            if is_catch { cpp.function.start } else { 0x11D0 }
        );
    }
}

#[test]
fn malformed_cpp_tables_fail_closed_and_unknown_identity_is_not_guessed() {
    for (fh4, at, value) in [
        (false, 0xC00, 0),
        (false, 0xC04, u32::MAX),
        (false, 0xC40, 1),
        (true, 0xC09, 0x4000),
        (true, 0xC05, u32::MAX),
    ] {
        let mut d = fixture(fh4);
        put(&mut d, at, value);
        assert!(PeFile::parse(d).is_err(), "{fh4}/{at:x}");
    }
    let mut d = fixture(true);
    d[0xC00] |= 0x80;
    assert!(PeFile::parse(d).is_err());
    let mut d = fixture(true);
    d[0x8A2] = b'X';
    let pe = PeFile::parse(d).unwrap();
    assert!(pe.layout().cpp_eh.is_empty());
}

#[test]
fn explicit_static_gs_identity_preserves_aligned_cookie_trailer() {
    let mut d = fixture(true);
    d[0x8A2] = b'X';
    d[0x8DC..0x8E8].copy_from_slice(&[0x57, 0, 0, 0, 8, 0, 0, 0, 0xF0, 0xFF, 0xFF, 0xFF]);
    let symbols = sigbraker::exception::map_symbols(
        "0001:000001C0 __GSHandlerCheck_EH4 00000001400011C0 f runtime.lib",
        0x140000000,
    )
    .unwrap();
    let mut pe = PeFile::parse_with_symbols(d, symbols).unwrap();
    let expected = pe.layout().cpp_eh[&0x1000].gs_data.clone();
    assert_eq!(expected.len(), 12);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let c = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(c.relocated_fh4, 1);
    let moved = pe
        .layout()
        .cpp_eh
        .values()
        .find(|i| i.function.start != 0x1000)
        .unwrap();
    assert_eq!(moved.gs_data, expected);
    assert!(sigbraker::exception::map_symbols("no identities", 0x140000000).is_err());
}
