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
use crate::report::{field, number, size};
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
    let input_size = raw.len();
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
    let _ = writeln!(report, "Input");
    field(&mut report, 2, "File", cli.input.display());
    field(&mut report, 2, "Size", size(input_size as u64));
    if input_size != pe.data.len() {
        field(
            &mut report,
            2,
            "Decoded file size",
            size(pe.data.len() as u64),
        );
    }
    field(
        &mut report,
        2,
        "Image base",
        format_args!("{:#x}", layout.image_base),
    );
    field(
        &mut report,
        2,
        "Entry RVA",
        format_args!("{:#x}", layout.entry_rva),
    );
    field(&mut report, 2, "Seed", number(cli.seed));
    let _ = writeln!(report, "\nAnalysis");
    for (label, count) in [
        ("Functions", analysis.functions.len()),
        ("Instructions", total_instr),
        ("Blocks", total_blocks),
        ("Chains", total_chains),
        ("Protected ranges", layout.relocation_count()),
    ] {
        field(&mut report, 2, label, number(count as u64));
    }

    if cli.info {
        field(&mut report, 2, "Mode", "analysis only (--info)");
        return Ok(format!(
            "SigBreaker {}\n\n{report}",
            env!("CARGO_PKG_VERSION")
        ));
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
    let mut globals_report = String::new();
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
            field(&mut globals_report, 2, "Mode", ".data moved automatically");
        } else {
            field(
                &mut globals_report,
                2,
                "Objects moved",
                number(moved.len() as u64),
            );
        }
        field(&mut globals_report, 2, "Layout slot", slot);
        for (old, new) in moved {
            let _ = writeln!(globals_report, "  RVA {old:#x} -> {new:#x}");
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

    let mut passes = String::new();
    let mut pass =
        |name: &str, unit: &str, settings: Option<(&str, String)>, c: crate::stats::Counters| {
            let _ = writeln!(passes, "\n  {name}");
            if let Some((label, value)) = settings {
                field(&mut passes, 4, label, value);
            }
            c.write_report(&mut passes, unit);
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
            "Segment selector injection",
            "instructions",
            Some(("Prefix whitelist", whitelist.join(", "))),
            c,
        );
    }

    // Pass 2 — instruction reordering.
    if !cli.no_reorder {
        let cfg = reorder::Config {
            probability: cli.reorder_prob,
        };
        let c = reorder::run(&analysis, &layout, &mut pe.data, &cfg, &mut rng);
        pass("Instruction reordering", "runs", None, c);
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
        pass("Opcode aliasing", "instructions", None, c);
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
            pass("Basic block relocation", "functions", None, c);
        } else {
            let cfg = shuffle::Config {
                probability: cli.shuffle_prob,
            };
            let c = shuffle::run(&lifted, &layout, &mut pe.data, &cfg, &mut rng);
            pass("Basic block shuffling", "functions", None, c);
        }
    }

    if !cli.no_verify && layout.runtime_functions.is_empty() {
        verify::verify_regions(&layout, &pe.data, verification_regions.iter().copied())?;
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
    progress("Writing output");
    let output = compressed
        .as_ref()
        .map_or(pe.data.as_slice(), |packed| packed.data.as_slice());
    crate::writer::write_atomic(&out_path, output)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    let mut result = format!("SigBreaker {}\n\nResult\n", env!("CARGO_PKG_VERSION"));
    field(
        &mut result,
        2,
        "Functions changed",
        format!(
            "{} / {} ({percentage:.2}%)",
            number(transformed as u64),
            number(total as u64)
        ),
    );
    field(
        &mut result,
        2,
        "Verification",
        if cli.no_verify {
            "Skipped (--no-verify)"
        } else {
            "Passed"
        },
    );
    field(&mut result, 2, "Input size", size(input_size as u64));
    field(&mut result, 2, "Output size", size(output.len() as u64));
    field(&mut result, 2, "Output file", out_path.display());
    if cli.compress_section {
        let _ = writeln!(result, "\nCompression");
        match &compressed {
            Some(packed) => {
                field(
                    &mut result,
                    2,
                    "Section",
                    format!("{} LZMA", packed.section),
                );
                field(&mut result, 2, "Before", size(packed.original_size as u64));
                field(&mut result, 2, "After", size(packed.packed_size as u64));
                field(
                    &mut result,
                    2,
                    "File bytes saved",
                    size((pe.data.len() - output.len()) as u64),
                );
            }
            None => field(&mut result, 2, "Status", "Skipped (no net size savings)"),
        }
    }
    let _ = writeln!(result, "\n{report}");
    if !globals_report.is_empty() {
        let _ = writeln!(result, "Globals\n{globals_report}");
    }
    if !passes.is_empty() {
        let _ = write!(result, "Passes\n{passes}");
    }
    Ok(result)
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
