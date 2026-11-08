//! End-to-end tests over a synthetic x86-64 PE image.

mod common;

use std::path::PathBuf;

use clap::Parser;
use common::{TestPe, SAMPLE_CODE};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use sigbraker::cli::Cli;
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
    assert!(report.contains("verified : OK"), "report:\n{report}");

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
        report.contains("transformed: 1/2 functions (50.00%)"),
        "{report}"
    );
    let control =
        pipeline::run(&exe.cli(&["--no-seg-inject", "--no-reorder", "--no-shuffle"])).unwrap();
    assert!(
        control.contains("transformed: 0/2 functions (0.00%)"),
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
            defaults.shuffle_prob
        ),
        (1.0, 1.0, 1.0)
    );
    let report = pipeline::run(&defaults).unwrap();
    let default_bytes = std::fs::read(out_path(&exe.path)).unwrap();
    assert!(default_bytes.len() > pe.data.len());
    assert_eq!(default_bytes[0x400], 0xE9);
    assert!(report.contains("transformed: 1/1 functions (100.00%)"));
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
        let mut args = vec!["--no-shuffle", "--no-reorder"];
        args.extend(flags);
        let report = pipeline::run(&exe.cli(&args)).unwrap();
        assert!(
            report.contains("transformed: 0/1 functions (0.00%)"),
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
    assert!(report.contains("transformed: 1/1 functions (100.00%)"));
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
