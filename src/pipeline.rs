//! Pipeline: parse → lift → diversify → verify → write.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::analysis::Analysis;
use crate::cli::Cli;
use crate::pe::PeFile;
use crate::transforms::{relayout, reorder, segment_inject, shuffle};
use crate::verify;

/// Runs SigBreaker end-to-end and returns a human-readable report.
pub fn run(cli: &Cli) -> Result<String> {
    for (name, p) in [
        ("--seg-prob", cli.seg_prob),
        ("--reorder-prob", cli.reorder_prob),
        ("--shuffle-prob", cli.shuffle_prob),
    ] {
        if !(0.0..=1.0).contains(&p) {
            bail!("{name} must be within [0, 1], got {p}");
        }
    }

    let raw = std::fs::read(&cli.input)
        .with_context(|| format!("failed to read {}", cli.input.display()))?;
    let mut pe = PeFile::parse(raw)?;
    if let Some(path) = &cli.handler_map {
        let symbols = crate::exception::map_symbols(
            &std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?,
            pe.layout().image_base,
        )?;
        pe = PeFile::parse_with_symbols(pe.data, symbols)?;
    }
    let layout = pe.layout().clone();

    let mut rng = StdRng::seed_from_u64(cli.seed);
    let analysis = Analysis::run(&layout, &pe.data)?;

    let total_instr: usize = analysis.functions.iter().map(|f| f.instr_count).sum();
    let total_blocks: usize = analysis.functions.iter().map(|f| f.blocks.len()).sum();
    let total_chains: usize = analysis.functions.iter().map(|f| f.chains.len()).sum();

    let mut report = String::new();
    let _ = writeln!(
        report,
        "SigBreaker 1.0 — BLARE binary diversification engine"
    );
    let _ = writeln!(
        report,
        "  image    : base {:#x}, entry RVA {:#x}, {} bytes",
        layout.image_base,
        layout.entry_rva,
        pe.data.len()
    );
    let _ = writeln!(
        report,
        "  lifted   : {} functions, {total_blocks} blocks, {total_chains} chains, {total_instr} instructions, {} relocation-protected ranges",
        analysis.functions.len(),
        layout.relocation_count()
    );

    if cli.info {
        let _ = writeln!(
            report,
            "  mode     : analysis only (--info); nothing was modified"
        );
        return Ok(report);
    }
    // Growing prefixes are automatic where supported. Disabling injection also
    // disables growth; metadata-free inputs retain their in-place fallback.
    let grow_segments = cli.grow_segments
        && !cli.no_grow_segments
        && !cli.no_seg_inject
        && !cli.segments.is_empty()
        && cli.seg_prob > 0.0
        && !layout.runtime_functions.is_empty();
    // Count unique functions by their final code bytes, excluding header-only
    // changes, reverted edits, and duplicate transformations across passes.
    let original_data = pe.data.clone();

    let mut pass = |name: &str, detail: String, c: crate::stats::Counters| {
        let _ = writeln!(report, "  [pass] {name}: {detail} ({c})");
    };

    // Pass 1 — segment selector injection.
    if !cli.no_seg_inject && !cli.segments.is_empty() {
        let segments: Vec<iced_x86::Register> = cli.segments.iter().map(|s| s.register()).collect();
        let cfg = segment_inject::Config {
            probability: cli.seg_prob,
            segments: segments.clone(),
        };
        let c = segment_inject::run(&analysis, &layout, &mut pe.data, &cfg, &mut rng);
        let whitelist: Vec<String> = segments.iter().map(|r| format!("{r:?}")).collect();
        pass(
            "segment selector injection",
            format!("whitelist [{}]", whitelist.join(", ")),
            c,
        );
    }

    // Pass 2 — instruction reordering.
    if !cli.no_reorder {
        let cfg = reorder::Config {
            probability: cli.reorder_prob,
        };
        let c = reorder::run(&analysis, &layout, &mut pe.data, &cfg, &mut rng);
        pass(
            "instruction reordering",
            "DAG-based randomized topological order".into(),
            c,
        );
    }

    // Re-lift before shuffling: reordering moved instructions inside blocks,
    // so every instruction offset and RIP-relative target in `analysis` is
    // stale. Shuffling only moves whole chains and patches branches — but it
    // must do so against the *current* bytes. The original analysis is kept
    // for the verify pass, which checks the structural invariant "the transformed
    // image still decodes to the original instruction count".
    let lifted = Analysis::run(&layout, &pe.data)?;
    if !cli.no_verify {
        verify::verify(&layout, &pe.data, &analysis)?;
    }

    // Pass 3 — basic block shuffling.
    if !cli.no_shuffle || grow_segments {
        if !layout.runtime_functions.is_empty() {
            let segments = grow_segments.then(|| segment_inject::Config {
                probability: cli.seg_prob,
                segments: cli.segments.iter().map(|s| s.register()).collect(),
            });
            let c = relayout::run_with_segments(
                &lifted,
                &mut pe,
                if cli.no_shuffle {
                    0.0
                } else {
                    cli.shuffle_prob
                },
                &mut rng,
                segments.as_ref(),
            )?;
            pass(
                "basic block relocation",
                "explicit jumps, updated runtime-function table, preserved opaque metadata".into(),
                c,
            );
        } else {
            let cfg = shuffle::Config {
                probability: cli.shuffle_prob,
            };
            let c = shuffle::run(&lifted, &layout, &mut pe.data, &cfg, &mut rng);
            pass(
                "basic block shuffling",
                "fall-through-safe chain relayout".into(),
                c,
            );
        }
    }

    if !cli.no_verify {
        if layout.runtime_functions.is_empty() {
            verify::verify(&layout, &pe.data, &analysis)?;
        }
        let _ = writeln!(
            report,
            "  verified : OK — in-place decoding and generated instruction/branch layouts checked"
        );
    }

    let transformed = analysis
        .functions
        .iter()
        .filter(|func| {
            let range = func.off..func.off + (func.end_rva - func.start_rva) as usize;
            pe.layout()
                .rva_to_offset(func.start_rva)
                .is_some_and(|off| original_data[range.clone()] != pe.data[off..off + range.len()])
        })
        .count();
    let total = analysis.functions.len();
    let percentage = if total == 0 {
        0.0
    } else {
        100.0 * transformed as f64 / total as f64
    };
    let _ = writeln!(
        report,
        "  transformed: {transformed}/{total} functions ({percentage:.2}%)"
    );

    pe.update_checksum();
    let out_path = cli
        .output
        .clone()
        .unwrap_or_else(|| default_output(&cli.input));
    crate::writer::write_atomic(&out_path, &pe.data)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    let _ = writeln!(report, "  output   : {}", out_path.display());

    Ok(report)
}

fn default_output(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    let name = format!("{stem}.sigbrk.exe");
    input.with_file_name(name)
}
