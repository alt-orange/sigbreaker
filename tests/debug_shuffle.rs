//! Opt-in local dump harness; input path comes from SB_INPUT.
#![allow(dead_code)]

use rand::rngs::StdRng;
use rand::SeedableRng;
use sigbraker::analysis::Analysis;
use sigbraker::pe::PeFile;
use sigbraker::transforms::{reorder, segment_inject, shuffle};

fn dump(label: &str, data: &[u8], func: &sigbraker::analysis::Function) {
    let len = (func.end_rva - func.start_rva) as usize;
    let mut dec = iced_x86::Decoder::with_ip(
        64,
        &data[func.off..func.off + len],
        0x140000000u64 + func.start_rva as u64,
        iced_x86::DecoderOptions::NONE,
    );
    println!(
        "--- {label} ({} instrs expected, span {len}) ---",
        func.instr_count
    );
    let mut n = 0;
    loop {
        let ins = dec.decode();
        if ins.is_invalid() {
            println!("    <INVALID at instr {n}>");
            break;
        }
        println!("    {ins}");
        n += 1;
        if dec.can_decode() {
            continue;
        }
        break;
    }
    println!("    total decoded: {n}");
}

#[test]
#[ignore = "manual dump harness; requires SB_INPUT"]
fn debug_reorder_then_shuffle() {
    let raw = std::fs::read(std::env::var("SB_INPUT").expect("SB_INPUT path required")).unwrap();
    let mut pe = PeFile::parse(raw).unwrap();
    let layout = pe.layout().clone();
    let analysis = Analysis::run(&layout, &pe.data).unwrap();

    // The old hard-coded heuristic start is not a runtime-function entry.
    // Allow an explicit target, otherwise dump the first supported function.
    let target = std::env::var("SB_TARGET_RVA")
        .ok()
        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex SB_TARGET_RVA"));
    let func = match target {
        Some(rva) => analysis
            .functions
            .iter()
            .find(|f| f.start_rva <= rva && rva < f.end_rva),
        None => analysis.functions.first(),
    }
    .expect("no supported function at requested RVA");
    println!(
        "function {:#x}: {} blocks, {} chains, {} instrs",
        func.start_rva,
        func.blocks.len(),
        func.chains.len(),
        func.instr_count
    );

    let orig = pe.data.clone();
    dump("original", &orig, func);

    let mut rng = StdRng::seed_from_u64(1234);
    let segcfg = segment_inject::Config {
        probability: 0.35,
        segments: vec![
            iced_x86::Register::ES,
            iced_x86::Register::CS,
            iced_x86::Register::SS,
            iced_x86::Register::DS,
        ],
    };
    let segc = segment_inject::run(&analysis, &layout, &mut pe.data, &segcfg, &mut rng);
    println!("seg_inject: {segc:?}");
    dump("after seg_inject", &pe.data, func);

    let rcfg = reorder::Config { probability: 0.5 };
    let rc = reorder::run(&analysis, &layout, &mut pe.data, &rcfg, &mut rng);
    println!("reorder: {rc:?}");
    dump("after reorder", &pe.data, func);

    let scfg = shuffle::Config { probability: 0.5 };
    let lifted = Analysis::run(&layout, &pe.data).unwrap();
    let sc = shuffle::run(&lifted, &layout, &mut pe.data, &scfg, &mut rng);
    println!("shuffle: {sc:?}");
    dump("after shuffle", &pe.data, func);
}
