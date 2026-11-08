#[allow(dead_code)]
mod common;
use common::TestPe;
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{analysis::Analysis, exception, pe::PeFile, transforms::relayout};

fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    let mut d = TestPe::new().with_code(&code).data;
    d[0x800..0x828].fill(0);
    put(&mut d, 0xD0, 0x2000);
    put(&mut d, 0xD4, 40);
    put(&mut d, 0x800, 0x2040);
    put(&mut d, 0x80C, 0x2080);
    put(&mut d, 0x810, 0x2060);
    put(&mut d, 0x840, 0x20A0);
    put(&mut d, 0x860, 0x20A0);
    d[0x880..0x891].copy_from_slice(b"vcruntime140.dll\0");
    let name = b"\0\0__C_specific_handler\0";
    d[0x8A0..0x8A0 + name.len()].copy_from_slice(name);
    put(&mut d, 0xE0, 0x2140);
    put(&mut d, 0xE4, 12);
    put(&mut d, 0x940, 0x1000);
    put(&mut d, 0x944, 0x1010);
    put(&mut d, 0x948, 0x20D0);
    d[0x8D0] = 9; // version 1, EHANDLER
    put(&mut d, 0x8D4, 0x11C0);
    put(&mut d, 0x8D8, 1); // one scope, catch arm at 0x100A
    for (at, value) in [
        (0x8DC, 0x1000),
        (0x8E0, 0x100A),
        (0x8E4, 1),
        (0x8E8, 0x100A),
    ] {
        put(&mut d, at, value);
    }
    d[0x5C0..0x5C6].copy_from_slice(&[0xFF, 0x25, 0x9A, 0x0E, 0, 0]); // jmp [IAT 0x2060]
    put(&mut d, 0xF0, 0);
    put(&mut d, 0xF4, 0);
    d
}

#[test]
fn c_specific_scopes_split_with_layout_and_keep_continuation_and_priority() {
    let mut pe = PeFile::parse(fixture()).unwrap();
    assert_eq!(pe.layout().c_specific.len(), 1);
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let f = &a.functions[0];
    let old = &pe.layout().c_specific[&0x1000];
    let encoded =
        relayout::encode_function(f, pe.layout().va(0x4000), &[0, 2, 1], &pe.data, usize::MAX, None).unwrap();
    let rewritten = exception::relocate(
        old,
        pe.layout().image_base,
        &encoded.address_map,
        &encoded.spans,
    )
    .unwrap();
    assert_eq!(rewritten.len(), 2); // first scope became discontiguous
    for (pc, range) in &encoded.spans {
        let rva = (pc - pe.layout().image_base) as u32;
        let was_protected = (0x1000..0x100A).contains(&rva);
        assert_eq!(
            rewritten
                .iter()
                .any(|s| s.begin as u64 + pe.layout().image_base <= range.start
                    && range.end <= s.end as u64 + pe.layout().image_base),
            was_protected
        );
    }
    for scope in &rewritten {
        assert_eq!(
            scope.target as u64 + pe.layout().image_base,
            encoded.address_map[&pe.layout().va(0x100A)]
        );
    }
    let counters = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(counters.applied, 1);
    assert_eq!(counters.relocated_c_specific, 1);
    let f = pe.layout().runtime_functions.last().unwrap();
    assert_ne!(pe.layout().unwind_info(f.start).unwrap().rva, 0x20D0);
    assert!(!pe.layout().c_specific[&f.start].scopes.is_empty());
}

#[test]
fn unrecognized_handler_identity_is_pinned_and_malformed_scopes_are_rejected() {
    let mut unknown = fixture();
    unknown[0x8A2] = b'X';
    let mut pe = PeFile::parse(unknown.clone()).unwrap();
    assert!(pe.layout().c_specific.is_empty());
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(
        relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42))
            .unwrap()
            .applied,
        0
    );
    assert_eq!(pe.data, unknown);
    for (at, value) in [
        (0x8D8, u32::MAX),
        (0x8DC, 0x0FFF),
        (0x8E0, 0x1020),
        (0x8E4, 0x2000),
        (0x8E8, 0x1020),
    ] {
        let mut d = fixture();
        put(&mut d, at, value);
        assert!(
            PeFile::parse(d).is_err(),
            "invalid scope {at:x} was accepted"
        );
    }
}

#[test]
fn guard_flag_without_a_table_allows_movement_and_bad_scope_boundaries_stay_pinned() {
    for guarded in [false, true] {
        let mut d = fixture();
        if guarded {
            // Load config in .reloc has enough room; no base-reloc directory.
            put(&mut d, 0x118, 0x3000);
            put(&mut d, 0x11C, 148);
            d[0xC00..0xC94].fill(0);
            put(&mut d, 0xC00, 148);
            put(&mut d, 0xC90, 0x00400000);
        } else {
            put(&mut d, 0x8DC, 0x1001);
        }
        let mut pe = PeFile::parse(d.clone()).unwrap();
        let a = Analysis::run(pe.layout(), &pe.data).unwrap();
        assert_eq!(
            relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42))
                .unwrap()
                .applied,
            u64::from(guarded)
        );
        if !guarded {
            assert_eq!(pe.data, d);
        }
    }
}

#[test]
fn guarded_continuation_table_is_rewritten_and_sorted_with_scope_targets() {
    let mut d = fixture();
    put(&mut d, 0x118, 0x3000);
    put(&mut d, 0x11C, 280);
    d[0xC00..0xD18].fill(0);
    put(&mut d, 0xC00, 280);
    put(&mut d, 0xC90, 0x00400000);
    d[0xD08..0xD10].copy_from_slice(&0x140003180u64.to_le_bytes());
    d[0xD10..0xD18].copy_from_slice(&2u64.to_le_bytes());
    put(&mut d, 0xD80, 0x1004);
    put(&mut d, 0xD84, 0x100A);
    let mut pe = PeFile::parse(d.clone()).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    let counters = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(counters.applied, 1);
    assert_eq!(pe.layout().eh_continuations.len(), 2);
    let f = pe.layout().runtime_functions.last().unwrap();
    assert!(pe.layout().eh_continuations.iter().all(|r| f.contains(r)));
    let scope = &pe.layout().c_specific[&f.start];
    assert!(pe
        .layout()
        .eh_continuations
        .contains(&scope.scopes[0].target));
    // An append layout retains the old body and needs both sets of targets.
    let symbols = std::collections::BTreeMap::from([(0x11C0, "__C_specific_handler".to_owned())]);
    let mut appended = PeFile::parse_with_symbols(d.clone(), symbols).unwrap();
    let a = Analysis::run(appended.layout(), &appended.data).unwrap();
    relayout::run(&a, &mut appended, 1.0, &mut StdRng::seed_from_u64(42)).unwrap();
    assert_eq!(appended.layout().eh_continuations.len(), 4);
    assert!(appended.layout().eh_continuations.contains(&0x1004));
    assert!(appended.layout().eh_continuations.contains(&0x100A));
    assert!(appended
        .layout()
        .eh_continuations
        .iter()
        .any(|r| *r >= 0x4000));
    for values in [[0x100A, 0x1004], [0x1004, 0x1004], [0x1004, 0x4000]] {
        let mut invalid = d.clone();
        put(&mut invalid, 0xD80, values[0]);
        put(&mut invalid, 0xD84, values[1]);
        assert!(PeFile::parse(invalid).is_err());
    }
    put(&mut d, 0xD80, 0x1001);
    let mut pe = PeFile::parse(d).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(
        relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42))
            .unwrap()
            .applied,
        0
    );
}

#[test]
fn mutated_imports_thunks_and_scope_tables_reject_cleanly() {
    use rand::Rng;
    let mut rng = StdRng::seed_from_u64(0x534548);
    let fields = [
        0xD0, 0xD4, 0x800, 0x80C, 0x810, 0x840, 0x860, 0x8D0, 0x8D4, 0x8D8, 0x8DC, 0x8E0, 0x8E4,
        0x8E8, 0x5C0, 0x5C2,
    ];
    for case in 0..1024 {
        let mut d = fixture();
        let field = fields[rng.gen_range(0..fields.len())];
        put(&mut d, field, rng.gen());
        assert!(
            std::panic::catch_unwind(|| {
                if let Ok(mut pe) = PeFile::parse(d) {
                    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
                    let _ = relayout::run(&a, &mut pe, 1.0, &mut StdRng::seed_from_u64(42));
                }
            })
            .is_ok(),
            "mutation {case} panicked"
        );
    }
}

