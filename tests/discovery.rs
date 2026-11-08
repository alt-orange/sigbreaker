#[allow(dead_code)]
mod common;
use common::TestPe;
use sigbraker::{analysis::Analysis, pe::PeFile};

#[test]
fn exports_seed_discovery_but_forwarder_strings_and_embedded_calls_do_not() {
    let mut p = TestPe::new().with_code(&[0xC3]);
    p.data[0x410..0x416].copy_from_slice(&[0xB8, 7, 0, 0, 0, 0xC3]);
    // Unreachable E8 bytes are not a source of function roots.
    p.data[0x420..0x425].copy_from_slice(&[0xE8, 0x1B, 0, 0, 0]);
    p.data[0xC8..0xCC].copy_from_slice(&0x1100u32.to_le_bytes());
    p.data[0xCC..0xD0].copy_from_slice(&0x80u32.to_le_bytes());
    p.data[0x514..0x518].copy_from_slice(&2u32.to_le_bytes());
    p.data[0x51C..0x520].copy_from_slice(&0x1140u32.to_le_bytes());
    p.data[0x540..0x544].copy_from_slice(&0x1010u32.to_le_bytes());
    p.data[0x544..0x548].copy_from_slice(&0x1150u32.to_le_bytes());
    p.data[0x550..0x559].copy_from_slice(b"other.fn\0");
    let pe = PeFile::parse(p.data).unwrap();
    assert_eq!(
        pe.layout().code_roots.iter().copied().collect::<Vec<_>>(),
        vec![0x1000, 0x1010]
    );
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(
        a.functions.iter().map(|f| f.start_rva).collect::<Vec<_>>(),
        vec![0x1000, 0x1010]
    );
}

#[test]
fn decoded_call_seeds_a_function_but_immediate_e8_does_not() {
    let mut p = TestPe::new().with_code(&[
        0xB8, 0xE8, 0, 0, 0, // mov eax,232
        0xE8, 6, 0, 0, 0, // call 0x1010
        0xC3,
    ]);
    p.data[0x410] = 0xC3;
    let pe = PeFile::parse(p.data).unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert_eq!(
        a.functions.iter().map(|f| f.start_rva).collect::<Vec<_>>(),
        vec![0x1000, 0x1010]
    );
}

#[test]
fn rip_relative_interior_code_reference_is_recorded() {
    let pe = PeFile::parse(
        TestPe::new()
            .with_code(&[
                0x48, 0x8D, 0x05, 1, 0, 0, 0, // lea rax,[rip+1] -> RVA 0x1008
                0xC3, 0x90, 0xC3,
            ])
            .data,
    )
    .unwrap();
    let a = Analysis::run(pe.layout(), &pe.data).unwrap();
    assert!(a.range_externally_referenced(0, 0x1008..0x1009));
}

#[test]
fn malformed_section_extents_and_odd_relocation_blocks_are_rejected() {
    for (at, value) in [
        (0x15C, 0xFFFF_F000u32), // raw pointer beyond file
        (0x158, 0x10000),        // raw size beyond file
        (0x17C, 0x1100),         // overlapping virtual sections
        (0x184, 0x410),          // overlapping raw sections
        (0x154, 0xFFFF_FFFF),    // virtual range overflow
        (0xC04, 11),             // odd relocation block size
    ] {
        let mut p = TestPe::new().with_code(&[0xC3]);
        p.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            PeFile::parse(p.data).is_err(),
            "accepted malformed field {at:x}"
        );
    }
}
