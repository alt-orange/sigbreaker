#[allow(dead_code)]
mod common;

use clap::Parser;
use common::TestPe;
use sigbraker::{cli::Cli, pe::PeFile, pipeline, writer::SectionPlan};

fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn generated_section(payload_size: usize) -> Vec<u8> {
    let code = [
        0x85, 0xc9, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
    ];
    let mut data = TestPe::new().with_code(&code).data;
    for (at, value) in [
        (0xe0, 0x2040),
        (0xe4, 12),
        (0x840, 0x1000),
        (0x844, 0x1010),
        (0x848, 0x2080),
        (0x108, 0x2100),
        (0x10c, 28),
    ] {
        put(&mut data, at, value);
    }
    data[0x880] = 1;
    let overlay = data.len() as u32;
    for (at, value) in [
        (0xe8, overlay),
        (0xec, 16),
        (0x4c, overlay),
        (0x90c, 2),
        (0x910, 4),
        (0x918, overlay),
    ] {
        put(&mut data, at, value);
    }
    data.extend_from_slice(b"debug-and-cert!!");
    let mut pe = PeFile::parse(data).unwrap();
    let plan = SectionPlan::new(&pe).unwrap();
    let rva = plan.rva;
    let mut payload = vec![0x90; payload_size];
    payload[..code.len()].copy_from_slice(&code);
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&((rva - 0x1005) as i32).to_le_bytes());
    plan.commit(
        &mut pe,
        payload,
        &[(rva, rva + code.len() as u32, 0x2080)],
        &[(0x400, jump)],
        &Default::default(),
    )
    .unwrap();
    // Both added headers must preserve occupied header padding.
    pe.data[0x1e8..0x238].fill(0xa5);
    pe.update_checksum();
    pe.data
}

#[test]
fn lzma_round_trip_preserves_metadata_overlay_and_reprocessing() {
    let directory = std::env::temp_dir().join(format!("sigbraker-compress-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("input.exe");
    let output = directory.join("output.exe");
    let source = generated_section(0x10000);
    std::fs::write(&input, &source).unwrap();
    let cli = |compressed: bool| {
        let mut args = vec![
            "sigbraker".to_owned(),
            input.to_string_lossy().into_owned(),
            "-o".into(),
            output.to_string_lossy().into_owned(),
            "--no-seg-inject".into(),
            "--no-alias".into(),
            "--no-reorder".into(),
            "--no-shuffle".into(),
        ];
        if compressed {
            args.push("--compress".into());
        }
        Cli::parse_from(args)
    };
    let report = pipeline::run(&cli(true)).unwrap();
    assert!(report.contains("Section                     .sbrk LZMA"), "{report}");
    let packed = std::fs::read(&output).unwrap();
    assert!(packed.len() < source.len());
    assert_eq!(PeFile::parse(packed.clone()).unwrap().data, source);

    // A second processing pass restores and republishes the canonical PE.
    std::fs::write(&input, &packed).unwrap();
    pipeline::run(&cli(false)).unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), source);
    pipeline::run(&cli(true)).unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), packed);

    let pe_header = u32::from_le_bytes(packed[0x3c..0x40].try_into().unwrap()) as usize;
    let table = pe_header + 24 + 240;
    let count = u16::from_le_bytes(packed[pe_header + 6..pe_header + 8].try_into().unwrap());
    let pack_header = (0..count as usize)
        .map(|i| table + i * 40)
        .find(|&at| &packed[at..at + 7] == b".sbpack")
        .unwrap();
    let raw = u32::from_le_bytes(
        packed[pack_header + 20..pack_header + 24]
            .try_into()
            .unwrap(),
    ) as usize;
    let payload = u32::from_le_bytes(packed[raw + 20..raw + 24].try_into().unwrap()) as usize;
    let mut malformed = packed;
    malformed[raw + payload + 1..raw + payload + 5].fill(0xff);
    assert!(PeFile::parse(malformed).is_err());

    let small = generated_section(0x200);
    std::fs::write(&input, &small).unwrap();
    let report = pipeline::run(&cli(true)).unwrap();
    assert!(report.contains("Status                      Skipped (no net size savings)"));
    assert_eq!(std::fs::read(&output).unwrap(), small);

    std::fs::remove_file(input).unwrap();
    std::fs::remove_file(output).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
