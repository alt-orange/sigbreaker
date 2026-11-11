//! Pipeline: parse → lift → diversify → verify → write.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::analysis::Analysis;
use crate::cli::Cli;
use crate::pe::PeFile;
use crate::transforms::{opcode_alias, relayout, reorder, segment_inject, shuffle};
use crate::verify;

/// Runs SigBreaker end-to-end and returns a human-readable report.
pub fn run(cli: &Cli) -> Result<String> {
    run_with_progress(cli, |_| {})
}

/// Runs SigBreaker and reports stages as they start.
pub fn run_with_progress(cli: &Cli, mut progress: impl FnMut(&str)) -> Result<String> {
    for (name, p) in [
        ("--seg-prob", cli.seg_prob),
        ("--reorder-prob", cli.reorder_prob),
        ("--shuffle-prob", cli.shuffle_prob),
        ("--junk-prob", cli.junk_prob),
        ("--alias-prob", cli.alias_prob),
    ] {
        if !(0.0..=1.0).contains(&p) {
            bail!("{name} must be within [0, 1], got {p}");
        }
    }

    progress("Reading PE and unwind metadata");
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
    progress("Analyzing executable code and references");
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
    // Count unique functions by their final code bytes, excluding header-only
    // changes, reverted edits, and duplicate transformations across passes.
    let original_data = pe.data.clone();
    let original_regions: Vec<_> = analysis
        .functions
        .iter()
        .map(verify::Region::from)
        .collect();
    let move_globals = cli.auto_globals || cli.global_map.is_some();
    let (layout, analysis, shifted_regions) = if move_globals {
        progress(if cli.auto_globals {
            "Discovering and relocating .data references"
        } else {
            "Relocating selected globals"
        });
        let map = cli
            .global_map
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))
            })
            .transpose()?;
        let slot = cli
            .global_slot
            .unwrap_or_else(|| StdRng::seed_from_u64(cli.seed ^ 0x474C_4F42_414C).gen());
        let moved = crate::globals::relocate(&mut pe, &analysis, map.as_deref(), slot)
            .with_context(|| match &cli.global_map {
                Some(path) => format!("failed to apply global map {}", path.display()),
                None => "failed to automatically relocate .data".to_owned(),
            })?;
        if cli.auto_globals {
            let _ = writeln!(
                report,
                "  globals  : .data moved automatically (slot {slot})"
            );
        } else {
            let _ = writeln!(report, "  globals  : {} moved (slot {slot})", moved.len());
        }
        for (old, new) in moved {
            let _ = writeln!(report, "    RVA {old:#x} -> {new:#x}");
        }
        drop(analysis);
        let layout = pe.layout().clone();
        let analysis = Analysis::run(&layout, &pe.data)?;
        let regions: Vec<_> = analysis
            .functions
            .iter()
            .map(verify::Region::from)
            .collect();
        (layout, analysis, Some(regions))
    } else {
        (layout, analysis, None)
    };
    let verification_regions = shifted_regions.as_deref().unwrap_or(&original_regions);
    // Growing prefixes are automatic where supported. Disabling injection also
    // disables growth; metadata-free inputs retain their in-place fallback.
    let grow_segments = cli.grow_segments
        && !cli.no_grow_segments
        && !cli.no_seg_inject
        && !cli.segments.is_empty()
        && cli.seg_prob > 0.0
        && !layout.runtime_functions.is_empty();

    let mut pass = |name: &str, detail: String, c: crate::stats::Counters| {
        let _ = writeln!(report, "  [pass] {name}: {detail} ({c})");
    };

    // Pass 1 — segment selector injection.
    progress("Applying in-place transformations");
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

    // Keep the original verification spans, but release the instruction and
    // reference graphs before lifting the modified bytes.
    drop(analysis);
    // Pass 3 — opcode aliasing, in place. Runs after reordering so it is the
    // last writer of the in-place bytes.
    let alias_in_place = !cli.no_alias && cli.alias_prob > 0.0;
    if alias_in_place {
        progress("Analyzing reordered code and aliasing opcodes");
        let lifted = Analysis::run(&layout, &pe.data)?;
        let cfg = opcode_alias::Config {
            probability: cli.alias_prob,
        };
        let c = opcode_alias::run(&lifted, &layout, &mut pe.data, &cfg, &mut rng);
        pass(
            "opcode aliasing",
            "equivalent ALU/MOV forms and unused bits in legacy encodings".into(),
            c,
        );
    }
    if !cli.no_verify {
        verify::verify_regions(&layout, &pe.data, verification_regions.iter().copied())?;
    }

    // Pass 3 — basic block shuffling.
    if !cli.no_shuffle || grow_segments {
        // Relocation must see the final in-place instruction encodings.
        progress("Analyzing modified code for block relocation");
        let lifted = Analysis::run(&layout, &pe.data)?;
        progress("Relocating basic blocks");
        if !layout.runtime_functions.is_empty() {
            let segments = grow_segments.then(|| segment_inject::Config {
                probability: cli.seg_prob,
                segments: cli.segments.iter().map(|s| s.register()).collect(),
            });
            let c = relayout::run_with_alias_state(
                &lifted,
                &mut pe,
                if cli.no_shuffle {
                    0.0
                } else {
                    cli.shuffle_prob
                },
                &mut rng,
                segments.as_ref(),
                relayout::Options {
                    junk_probability: cli.junk_prob,
                    wipe_original: cli.wipe_original && !cli.keep_original,
                    alias_probability: if cli.no_alias { 0.0 } else { cli.alias_prob },
                },
                alias_in_place,
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
            verify::verify_regions(&layout, &pe.data, verification_regions.iter().copied())?;
        }
        let _ = writeln!(
            report,
            "  verified : OK — in-place decoding and generated instruction/branch layouts checked"
        );
    }

    let transformed = original_regions
        .iter()
        .filter(|func| {
            let range = func.offset..func.offset + func.len;
            pe.layout()
                .rva_to_offset(func.start_rva)
                .is_some_and(|off| original_data[range.clone()] != pe.data[off..off + range.len()])
        })
        .count();
    let total = original_regions.len();
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
    let compressed = if cli.compress_section {
        progress("Compressing the generated section with LZMA");
        crate::compression::compress(&pe)?
    } else {
        None
    };
    if cli.compress_section {
        match &compressed {
            Some(packed) => {
                let _ = writeln!(
                    report,
                    "  compression: {} LZMA {} -> {} bytes; file {} -> {} bytes",
                    packed.section,
                    packed.original_size,
                    packed.packed_size,
                    pe.data.len(),
                    packed.data.len()
                );
            }
            None => {
                let _ = writeln!(
                    report,
                    "  compression: skipped; no generated section with net size savings"
                );
            }
        }
    }
    progress("Writing output");
    let output = compressed
        .as_ref()
        .map_or(pe.data.as_slice(), |packed| packed.data.as_slice());
    crate::writer::write_atomic(&out_path, output)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    let _ = writeln!(report, "  output   : {}", out_path.display());

    Ok(report)
}

fn default_output(input: &Path) -> PathBuf {
    let mut name = input
        .file_stem()
        .unwrap_or_else(|| OsStr::new("output"))
        .to_os_string();
    let extension = input
        .extension()
        .filter(|extension| !extension.is_empty())
        .unwrap_or_else(|| OsStr::new("exe"));
    name.push(".sigbrk.");
    name.push(extension);
    input.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_preserves_the_input_extension() {
        for (input, expected) in [
            ("bin/client.dll", "bin/client.sigbrk.dll"),
            ("bin/loader_ui.exe", "bin/loader_ui.sigbrk.exe"),
            ("bin/module", "bin/module.sigbrk.exe"),
        ] {
            assert_eq!(default_output(Path::new(input)), Path::new(expected));
        }
    }
}
