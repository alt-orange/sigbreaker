//! End-to-end tests over a synthetic x86-64 PE image.

mod common;

use std::path::PathBuf;

use clap::Parser;
use common::{TestPe, SAMPLE_CODE};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use sigbraker::cli::Cli;
use sigbraker::pe::PeFile;
use sigbraker::pipeline;

struct TempExe {
    path: PathBuf,
}

impl TempExe {
    fn write(bytes: &[u8]) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sigbraker-test-{}-{}.exe",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::write(&p, bytes).expect("write temp exe");
        TempExe { path: p }
    }

    fn cli(&self, extra: &[&str]) -> Cli {
        let mut args = vec![
            "sigbraker".to_string(),
            self.path.to_string_lossy().into_owned(),
            "--output".into(),
            out_path(&self.path).to_string_lossy().into_owned(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        Cli::parse_from(args)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(out_path(&self.path));
    }
}

fn out_path(input: &std::path::Path) -> PathBuf {
    let stem = input.file_stem().unwrap().to_string_lossy();
    input.with_file_name(format!("{stem}.out.exe"))
}

/// Process-local unique suffix, independent of Windows clock resolution.
fn rand_suffix() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Linearly decodes a `.text` section and returns (len, mnemonic) pairs;
/// used to compare instruction multisets.
fn decode_text(code: &[u8]) -> Vec<(usize, Mnemonic)> {
    let mut decoder = Decoder::with_ip(64, code, 0x1400_01000, DecoderOptions::NONE);
    let mut consumed = 0usize;
    let mut out = Vec::new();
    while consumed < code.len() {
        let ins = decoder.decode();
        if ins.is_invalid() {
            break;
        }
        consumed += ins.len();
        out.push((ins.len(), ins.mnemonic()));
    }
    out
}

#[test]
fn sample_code_decodes_as_expected() {
    // Guard the fixture itself: every SAMPLE_CODE byte must decode cleanly.
    let decoded = decode_text(SAMPLE_CODE);
    assert!(!decoded.is_empty());
    assert!(decoded.iter().all(|(len, _)| *len > 0));
}

#[test]
fn pipeline_transforms_and_verifies() {
    let pe = TestPe::new().with_sample_code();
    let exe = TempExe::write(&pe.data);
    let cli = exe.cli(&[
        "--seed",
        "42",
        "--seg-prob",
        "0.0",
        "--reorder-prob",
        "1.0",
        "--shuffle-prob",
        "1.0",
    ]);

    let report = pipeline::run(&cli).expect("pipeline must succeed");
    assert!(report.contains("Verification                Passed"), "report:\n{report}");

    let out = out_path(&exe.path);
    let out_bytes = std::fs::read(&out).expect("output written");
    assert_ne!(out_bytes, pe.data, "output must differ from input");

    // Output must still parse as a 64-bit PE.
    let reparsed = sigbraker::pe::PeFile::parse(out_bytes.clone()).expect("output parses as PE");
    assert_eq!(reparsed.layout().image_base, 0x140_000_000);

    // Instruction multiset must be preserved (reorder + shuffle only move
    // whole instructions; segment injection is disabled in this run).
    let mut before = decode_text(pe.text());
    let mut after = decode_text(&out_bytes[0x400..0x600]);
    before.sort();
    after.sort();
    assert_eq!(before, after, "instruction multiset must be preserved");
}

#[test]
fn same_seed_same_output() {
    let pe = TestPe::new().with_sample_code();
    let exe = TempExe::write(&pe.data);
    let args = [
        "--seed",
        "7",
        "--seg-prob",
        "0.5",
        "--reorder-prob",
        "1.0",
        "--shuffle-prob",
        "1.0",
    ];

    let r1 = pipeline::run(&exe.cli(&args)).expect("run 1");
    let o1 = std::fs::read(out_path(&exe.path)).unwrap();
    std::fs::write(&exe.path, &pe.data).unwrap();
    let r2 = pipeline::run(&exe.cli(&args)).expect("run 2");
    let o2 = std::fs::read(out_path(&exe.path)).unwrap();
    assert_eq!(o1, o2, "same seed must give identical output");
    assert_eq!(r1, r2);
}

#[test]
fn relocation_appends_and_wipes_original_code_with_any_section_name() {
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    let mut data = TestPe::new().with_code(&code).data;
    for (offset, value) in [
        (0xE0, 0x2040u32),
        (0xE4, 12),
        (0x840, 0x1000),
        (0x844, 0x1010),
        (0x848, 0x2080),
    ] {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[0x880] = 1;
    for name in [b".text", b".code"] {
        data[0x148..0x14D].copy_from_slice(name);
        let exe = TempExe::write(&data);
        for (flags, keep) in [
            (vec![], false),
            (vec!["--keep-original"], true),
            (vec!["--wipe-original"], false),
            (vec!["--wipe-original", "--keep-original"], true),
            (vec!["--keep-original", "--wipe-original"], false),
        ] {
            let mut args = vec!["--no-seg-inject", "--no-reorder", "--no-alias"];
            args.extend(flags);
            pipeline::run(&exe.cli(&args)).unwrap();
            let pe = PeFile::parse(std::fs::read(out_path(&exe.path)).unwrap()).unwrap();
            let layout = pe.layout();
            let appended = layout.sections.last().unwrap();
            assert_eq!(appended.name(), ".sbrk");
            let off = layout.rva_to_offset(0x1000).unwrap();
            let jump = Decoder::with_ip(64, &pe.data[off..], layout.va(0x1000), DecoderOptions::NONE)
                .decode();
            assert_eq!(jump.mnemonic(), Mnemonic::Jmp);
            assert_eq!(jump.near_branch_target(), layout.va(appended.virtual_address));
            let body = &pe.data[off + 5..off + code.len()];
            if keep {
                assert_eq!(body, &code[5..]);
            } else {
                assert_eq!(body, &[0xCC; 11]);
            }
        }
    }
}

fn global_fixture() -> TempExe {
    let code = [
        0xB8, 1, 0, 0, 0, // mov eax, 1
        0x03, 0x05, 0x19, 0x30, 0, 0, // add eax, [game+0x4024]
        0x03, 0x05, 0xEF, 0x0F, 0, 0, // add eax, [game+0x2000]
        0x85, 0xC9, // test ecx, ecx
        0x74, 0x03, // je 0x1018
        0xFF, 0xC0, 0xC3, // inc eax; ret
        0xC3, // ret
    ];
    let mut data = TestPe::new().with_code(&code).data;
    data[0x46..0x48].copy_from_slice(&5u16.to_le_bytes());
    data[0x90..0x94].copy_from_slice(&0x6000u32.to_le_bytes());
    data[0xE0..0xE4].copy_from_slice(&0x2040u32.to_le_bytes());
    data[0xE4..0xE8].copy_from_slice(&12u32.to_le_bytes());
    data[0x840..0x844].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0x844..0x848].copy_from_slice(&(0x1000 + code.len() as u32).to_le_bytes());
    data[0x848..0x84C].copy_from_slice(&0x2080u32.to_le_bytes());
    data[0x880] = 1;

    data.resize(0x1200, 0);
    for (at, name, rva, raw, flags) in [
        (0x1C0, b".data", 0x4000u32, 0xE00u32, 0xC000_0040u32),
        (0x1E8, b".auxx", 0x5000u32, 0x1000u32, 0x6000_0020u32),
    ] {
        data[at..at + name.len()].copy_from_slice(name);
        for (field, value) in [(8, 0x200), (12, rva), (16, 0x200), (20, raw), (36, flags)] {
            data[at + field..at + field + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    data[0x210..0x238].fill(0xA5); // Force header expansion on append.
    data[0x1000] = 0xC3;
    data[0xE20..0xE28].copy_from_slice(&[3, 0, 0, 0, 7, 0, 0, 0]);
    data[0xC08..0xC0A].copy_from_slice(&0xA010u16.to_le_bytes()); // DIR64 at RVA 0x2010
    data[0x810..0x818].copy_from_slice(&0x140004024u64.to_le_bytes());
    TempExe::write(&data)
}

#[test]
fn global_slots_move_data_and_retarget_original_and_appended_code() {
    let exe = global_fixture();
    let map = TempExe::write(b"global 0x4020 8 8\nglobal 0x2000 16 16\nrip 0x1005\nrip 0x100b\n");
    let path = map.path.to_str().unwrap();
    let mut runs = Vec::new();
    for slot in ["5", "17", "5"] {
        let report = pipeline::run(&exe.cli(&[
            "--global-map",
            path,
            "--global-slot",
            slot,
            "--no-seg-inject",
            "--no-reorder",
            "--no-alias",
            "--keep-original",
            "--junk-prob",
            "0",
        ]))
        .unwrap();
        let pe = PeFile::parse(std::fs::read(out_path(&exe.path)).unwrap()).unwrap();
        let layout = pe.layout();
        let section = |name| layout.sections.iter().find(|s| s.name() == name).unwrap();
        assert_eq!(section(".text").virtual_address, 0x1000);
        assert_eq!(section(".sbdata").characteristics, 0xC000_0040);
        assert_eq!(section(".sbro").characteristics, 0x4000_0040);
        let slot = slot.parse::<u32>().unwrap();
        let writable = section(".sbdata").virtual_address + slot * 8;
        let read_only = section(".sbro").virtual_address + slot * 16;
        assert!(report.contains(&format!("RVA 0x4020 -> {writable:#x}")));
        let bytes = |rva, size| {
            let start = layout.rva_to_offset(rva).unwrap();
            &pe.data[start..start + size]
        };
        assert_eq!(bytes(0x4020, 8), &[0; 8]);
        assert_eq!(bytes(0x2000, 16), &[0; 16]);
        assert_eq!(bytes(writable, 8), &[3, 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!(bytes(read_only, 16), b"SIGBREAKER-DATA!");
        assert_eq!(bytes(0x2010, 8), &layout.va(writable + 4).to_le_bytes());
        let rip_targets = |rva, size| {
            Decoder::with_ip(64, bytes(rva, size), layout.va(rva), DecoderOptions::NONE)
                .into_iter()
                .filter(|ins| ins.is_ip_rel_memory_operand())
                .map(|ins| ins.ip_rel_memory_address())
                .collect::<Vec<_>>()
        };
        let expected = [layout.va(writable + 4), layout.va(read_only)];
        assert_eq!(rip_targets(0x1005, 12), expected);
        let appended = section(".sbrk").virtual_address;
        let moved = layout
            .runtime_functions
            .iter()
            .find(|f| f.start >= appended)
            .unwrap();
        assert_eq!(
            rip_targets(moved.start, (moved.end - moved.start) as usize),
            expected
        );
        runs.push((writable, read_only, pe.data));
    }
    assert_ne!(runs[0].0, runs[1].0);
    assert_ne!(runs[0].1, runs[1].1);
    assert_eq!(runs[0], runs[2]);
}

#[test]
fn missing_global_reference_leaves_existing_output_intact() {
    let exe = global_fixture();
    let map = TempExe::write(b"global 0x4020 8 8\n");
    let output = out_path(&exe.path);
    std::fs::write(&output, b"previous output").unwrap();
    let error = pipeline::run(&exe.cli(&["--global-map", map.path.to_str().unwrap()])).unwrap_err();
    assert!(format!("{error:#}").contains("missing 'rip 0x1005'"));
    assert_eq!(std::fs::read(output).unwrap(), b"previous output");
}

#[test]
fn automatic_data_move_finds_leaf_references_and_moves_loader_fixups() {
    let original = global_fixture();
    let mut data = std::fs::read(&original.path).unwrap();
    // A leaf in the second executable section has no runtime-function entry.
    data[0x1C8..0x1CC].copy_from_slice(&0x280u32.to_le_bytes()); // .data virtual tail
    data[0x1000..0x100D].copy_from_slice(&[
        0x8B, 0x05, 0x1E, 0xF0, 0xFF, 0xFF, // mov eax, [RVA 0x4024]
        0x03, 0x05, 0x54, 0xF2, 0xFF, 0xFF, // add eax, [RVA 0x4260]
        0xC3,
    ]);
    data[0xF4..0xF8].copy_from_slice(&24u32.to_le_bytes());
    data[0xC0C..0xC10].copy_from_slice(&0x4000u32.to_le_bytes());
    data[0xC10..0xC14].copy_from_slice(&12u32.to_le_bytes());
    data[0xC14..0xC18].copy_from_slice(&[0x30, 0xA0, 0x38, 0xA0]);
    data[0xE30..0xE38].copy_from_slice(&0x140004024u64.to_le_bytes());
    data[0xE38..0xE40].copy_from_slice(&0x140005000u64.to_le_bytes());
    let exe = TempExe::write(&data);
    let output = out_path(&exe.path);
    for (slot, destination) in [("0", 0x6000), ("1", 0x7000)] {
        let report = pipeline::run(&exe.cli(&[
            "--auto-globals",
            "--global-slot",
            slot,
            "--no-seg-inject",
            "--no-reorder",
            "--no-alias",
            "--junk-prob",
            "0",
        ]))
        .unwrap();
        assert!(report.contains(&format!("RVA 0x4000 -> {destination:#x}")));
        let pe = PeFile::parse(std::fs::read(&output).unwrap()).unwrap();
        let layout = pe.layout();
        let bytes = |rva, size| {
            let offset = layout.rva_to_offset(rva).unwrap();
            &pe.data[offset..offset + size]
        };
        assert_eq!(bytes(0x4000, 0x200), &[0; 0x200]);
        assert_eq!(bytes(destination + 0x20, 8), &data[0xE20..0xE28]);
        let mut leaf = Decoder::with_ip(
            64,
            bytes(0x5000, 13),
            layout.va(0x5000),
            DecoderOptions::NONE,
        );
        assert_eq!(
            leaf.decode().ip_rel_memory_address(),
            layout.va(destination + 0x24)
        );
        assert_eq!(
            leaf.decode().ip_rel_memory_address(),
            layout.va(destination + 0x260)
        );
        assert!(layout
            .sections
            .iter()
            .any(|s| s.name() == ".sbdata" && s.contains_rva(destination + 0x260)));
        assert!(layout.rva_to_offset(destination + 0x260).is_none());
        for site in [0x2010, destination + 0x30] {
            assert_eq!(bytes(site, 8), &layout.va(destination + 0x24).to_le_bytes());
        }
        assert_eq!(
            bytes(destination + 0x38, 8),
            &layout.va(0x5000).to_le_bytes()
        );
        assert_eq!(bytes(0x300C, 4), &destination.to_le_bytes());
        let old = layout.rva_to_offset(0x4030).unwrap();
        let new = layout.rva_to_offset(destination + 0x30).unwrap();
        assert!(!layout.is_protected(old..old + 8));
        assert!(layout.is_protected(new..new + 8));
        assert!(layout.sections.iter().any(|s| s.name() == ".sbrk"));
    }

    // A possible RVA in ordinary data is ambiguous and must never be guessed.
    data[0x820..0x824].copy_from_slice(&0x4024u32.to_le_bytes());
    std::fs::write(&exe.path, &data).unwrap();
    let before = std::fs::read(&output).unwrap();
    let err = pipeline::run(&exe.cli(&["--auto-globals"])).unwrap_err();
    assert!(format!("{err:#}").contains("possible untyped .data reference"));
    assert_eq!(std::fs::read(output).unwrap(), before);
}

#[test]
fn report_counts_changed_functions_and_excludes_checksum_only_edits() {
    let mut code = vec![0x90; 16];
    code[..6].copy_from_slice(&[0xE8, 11, 0, 0, 0, 0xC3]);
    code.extend_from_slice(&[0x8B, 0x40, 0, 0xC3]);
    let exe = TempExe::write(&TestPe::new().with_code(&code).data);
    let report = pipeline::run(&exe.cli(&[
        "--seg-prob",
        "1",
        "--segments",
        "ds",
        "--no-reorder",
        "--no-shuffle",
    ]))
    .unwrap();
    assert!(
        report.contains("Functions changed           1 / 2 (50.00%)"),
        "{report}"
    );
    let control =
        pipeline::run(&exe.cli(&["--no-seg-inject", "--no-reorder", "--no-shuffle"])).unwrap();
    assert!(
        control.contains("Functions changed           0 / 2 (0.00%)"),
        "{control}"
    );
}

#[test]
fn defaults_enable_full_coverage_and_growth_can_be_disabled() {
    let mut pe = TestPe::new().with_code(&[0x8B, 0x02, 0x01, 0xC0, 0xC3]);
    for (at, value) in [
        (0xE0, 0x2040u32),
        (0xE4, 12),
        (0x840, 0x1000),
        (0x844, 0x1005),
        (0x848, 0x2080),
    ] {
        pe.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    pe.data[0x880] = 1;
    let exe = TempExe::write(&pe.data);
    let defaults = exe.cli(&[]);
    assert_eq!(
        (
            defaults.seg_prob,
            defaults.reorder_prob,
            defaults.shuffle_prob,
            defaults.alias_prob
        ),
        (1.0, 1.0, 1.0, 1.0)
    );
    let report = pipeline::run(&defaults).unwrap();
    let default_bytes = std::fs::read(out_path(&exe.path)).unwrap();
    assert!(default_bytes.len() > pe.data.len());
    assert_eq!(default_bytes[0x400], 0xE9);
    assert!(report.contains("Functions changed           1 / 1 (100.00%)"));
    pipeline::run(&exe.cli(&[
        "--grow-segments",
        "--seg-prob",
        "1",
        "--reorder-prob",
        "1",
        "--shuffle-prob",
        "1",
    ]))
    .unwrap();
    assert_eq!(default_bytes, std::fs::read(out_path(&exe.path)).unwrap());
    for flags in [
        vec!["--no-grow-segments"],
        vec!["--grow-segments", "--no-grow-segments"],
        vec!["--no-seg-inject"],
    ] {
        // Default-on passes must all be off for the function to stay
        // byte-identical; each case then isolates one disable switch.
        let mut args = vec!["--no-shuffle", "--no-reorder", "--no-alias"];
        args.extend(flags);
        let report = pipeline::run(&exe.cli(&args)).unwrap();
        assert!(
            report.contains("Functions changed           0 / 1 (0.00%)"),
            "{report}"
        );
        assert_eq!(
            pe.data.len(),
            std::fs::read(out_path(&exe.path)).unwrap().len()
        );
    }
    let report = pipeline::run(&exe.cli(&[
        "--no-shuffle",
        "--no-reorder",
        "--no-grow-segments",
        "--grow-segments",
    ]))
    .unwrap();
    assert!(report.contains("Functions changed           1 / 1 (100.00%)"));
}

#[test]
fn relocation_preserves_in_place_opcode_aliases() {
    let mut pe = TestPe::new().with_code(&[
        0x48, 0x89, 0x5C, 0x24, 8, // mov [rsp+8], rbx
        0x48, 0x89, 0xC8, // mov rax, rcx
        0xC3,
    ]);
    for (at, value) in [
        (0xE0, 0x2040u32),
        (0xE4, 12),
        (0x840, 0x1000),
        (0x844, 0x1009),
        (0x848, 0x2080),
    ] {
        pe.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    pe.data[0x880..0x888].copy_from_slice(&[1, 5, 2, 0, 5, 0x34, 1, 0]);
    let exe = TempExe::write(&pe.data);
    let report = pipeline::run(&exe.cli(&["--no-seg-inject", "--no-reorder"])).unwrap();
    assert!(report.contains("Functions changed           1 / 1"), "{report}");
    let bytes = std::fs::read(out_path(&exe.path)).unwrap();
    let output = sigbraker::pe::PeFile::parse(bytes).unwrap();
    let layout = output.layout();
    let entry = layout.rva_to_offset(0x1000).unwrap();
    assert_eq!(output.data[entry], 0xE9);
    let moved = layout.runtime_functions.last().unwrap();
    let start = layout.rva_to_offset(moved.start).unwrap();
    assert_eq!(&output.data[start..start + 5], &[0x48, 0x89, 0x5C, 0x64, 8]);
    let jump = Decoder::with_ip(
        64,
        &output.data[start + 5..],
        layout.va(moved.start + 5),
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(jump.mnemonic(), Mnemonic::Jmp);
    let resume = (jump.near_branch_target() - layout.image_base) as u32;
    let resume = layout.rva_to_offset(resume).unwrap();
    assert_eq!(&output.data[resume..resume + 3], &[0x48, 0x8B, 0xC1]);
}

#[test]
fn info_mode_writes_nothing() {
    let pe = TestPe::new().with_sample_code();
    let exe = TempExe::write(&pe.data);
    let cli = exe.cli(&["--info"]);
    let report = pipeline::run(&cli).expect("info run");
    assert!(report.contains("analysis only"));
    assert!(
        !out_path(&exe.path).exists(),
        "info mode must not write output"
    );
}

#[test]
fn rejects_non_x64() {
    let mut pe = TestPe::new();
    pe.data[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    let exe = TempExe::write(&pe.data);
    assert!(pipeline::run(&exe.cli(&[])).is_err());
}

#[test]
fn rejects_truncated_and_garbage() {
    assert!(sigbraker::pe::PeFile::parse(b"MZ short".to_vec()).is_err());
    assert!(sigbraker::pe::PeFile::parse(vec![0u8; 0x41]).is_err());
    let mut good = TestPe::new();
    good.data[0x40] = b'X'; // break PE signature
    assert!(sigbraker::pe::PeFile::parse(good.data).is_err());
}
