//! Move explicitly described ordinary data objects into appended PE sections.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{bail, ensure, Context, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Register};

use crate::analysis::Analysis;
use crate::pe::{PeFile, SectionHeader};
use crate::writer::{align, append_section, next_section_rva};

mod automatic;

const READ_ONLY_DATA: u32 = 0x4000_0040;
const WRITABLE_DATA: u32 = 0xC000_0040;

struct Global {
    rvas: Range<u32>,
    bytes: Range<usize>,
    alignment: u32,
    characteristics: u32,
    destination: u32,
    referenced: bool,
}

struct RipSite {
    instruction: Instruction,
    displacement_rva: u32,
    object: usize,
    target_rva: u32,
}

fn number(s: &str) -> Result<u32> {
    Ok(if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)?
    } else {
        s.parse()?
    })
}

fn overlaps<T: Ord>(a: &Range<T>, b: &Range<T>) -> bool {
    a.start < b.end && b.start < a.end
}

fn section_at(pe: &PeFile, rva: u32) -> Result<&SectionHeader> {
    pe.layout()
        .sections
        .iter()
        .find(|s| s.contains_rva(rva))
        .with_context(|| format!("unmapped RVA {rva:#x}"))
}

fn file_range(pe: &PeFile, rva: u32, size: u32) -> Result<Range<usize>> {
    let section = section_at(pe, rva)?;
    let offset = rva - section.virtual_address;
    ensure!(
        offset
            .checked_add(size)
            .is_some_and(|end| end <= section.raw_size),
        "range at RVA {rva:#x} is not entirely file-backed"
    );
    let start = section.raw_ptr as usize + offset as usize;
    Ok(start..start + size as usize)
}

fn image_rva(pe: &PeFile, va: u64) -> Option<u32> {
    va.checked_sub(pe.layout().image_base)
        .and_then(|rva| u32::try_from(rva).ok())
}

fn global_at(globals: &[Global], rva: u32) -> Option<usize> {
    let i = globals.partition_point(|g| g.rvas.end <= rva);
    globals.get(i).filter(|g| g.rvas.contains(&rva)).map(|_| i)
}

fn rip_target(pe: &PeFile, ins: &Instruction) -> Option<u32> {
    ins.is_ip_rel_memory_operand()
        .then(|| image_rva(pe, ins.ip_rel_memory_address()))
        .flatten()
}

fn moved_target(global: &Global, old: u32) -> u32 {
    global.destination + (old - global.rvas.start)
}

fn parse_map(pe: &PeFile, map: &str) -> Result<(Vec<Global>, BTreeSet<u32>)> {
    let mut globals = Vec::new();
    let mut rip_sites = BTreeSet::new();
    for (line, row) in map.lines().enumerate() {
        let row = row.split('#').next().unwrap_or_default();
        let fields: Vec<_> = row.split_whitespace().collect();
        (|| -> Result<()> {
            match fields.as_slice() {
                [] => (),
                ["global", rva, size, alignment] => {
                    let (rva, size, alignment) = (number(rva)?, number(size)?, number(alignment)?);
                    ensure!(size != 0, "empty global");
                    ensure!(
                        alignment.is_power_of_two()
                            && alignment <= 4096
                            && rva.is_multiple_of(alignment),
                        "global alignment must be a power of two up to 4096 and match its RVA"
                    );
                    let section = section_at(pe, rva)?;
                    ensure!(
                        matches!(
                            (section.name(), section.characteristics),
                            (".data", WRITABLE_DATA) | (".rdata", READ_ONLY_DATA)
                        ),
                        "global must be in an ordinary .data or .rdata section"
                    );
                    let end = rva.checked_add(size).context("global RVA overflow")?;
                    let bytes = file_range(pe, rva, size)?;
                    ensure!(
                        end - section.virtual_address <= section.virtual_size,
                        "global overlaps section padding"
                    );
                    ensure!(
                        !pe.layout().is_protected(bytes.clone()),
                        "global contains a base relocation"
                    );
                    globals.push(Global {
                        rvas: rva..end,
                        bytes,
                        alignment,
                        characteristics: section.characteristics,
                        destination: 0,
                        referenced: false,
                    });
                }
                ["rip", rva] => {
                    ensure!(rip_sites.insert(number(rva)?), "duplicate RIP reference");
                }
                _ => bail!("expected 'global RVA SIZE ALIGNMENT' or 'rip INSTRUCTION_RVA'"),
            }
            Ok(())
        })()
        .with_context(|| format!("global map line {}", line + 1))?;
    }
    globals.sort_by_key(|g| g.rvas.start);
    ensure!(!globals.is_empty(), "global map has no objects");
    ensure!(
        !globals.windows(2).any(|w| overlaps(&w[0].rvas, &w[1].rvas)),
        "overlapping globals"
    );
    Ok((globals, rip_sites))
}

fn metadata_ranges(
    pe: &PeFile,
    analysis: &Analysis,
    globals: &[Global],
) -> Result<Vec<Range<usize>>> {
    let mut metadata = pe.layout().unwind_bytes.clone();
    metadata.extend(pe.layout().eh_continuation_table.clone());
    metadata.extend(
        analysis
            .functions
            .iter()
            .flat_map(|f| f.jump_tables.iter())
            .map(|t| t.bytes.clone()),
    );
    for i in (0..16).filter(|&i| i != 4) {
        metadata.extend(pe.directory(i)?);
    }
    if let Some(exports) = pe.directory(0)? {
        let field = |offset| {
            u32::from_le_bytes(
                pe.data[exports.start + offset..exports.start + offset + 4]
                    .try_into()
                    .unwrap(),
            )
        };
        let count = field(20);
        if count != 0 {
            let table = file_range(
                pe,
                field(28),
                count.checked_mul(4).context("export table overflow")?,
            )?;
            for &entry in pe.data[table.clone()].as_chunks::<4>().0 {
                let rva = u32::from_le_bytes(entry);
                ensure!(
                    global_at(globals, rva).is_none(),
                    "exported global at RVA {rva:#x}"
                );
            }
            metadata.push(table);
        }
    }
    for global in globals {
        ensure!(
            !metadata.iter().any(|r| overlaps(r, &global.bytes)),
            "global at RVA {:#x} overlaps PE metadata",
            global.rvas.start
        );
    }
    Ok(metadata)
}

fn read_rip_sites(
    pe: &PeFile,
    analysis: &Analysis,
    globals: &[Global],
    sites: BTreeSet<u32>,
    metadata: &[Range<usize>],
) -> Result<BTreeMap<u32, RipSite>> {
    let mut decoded = BTreeMap::new();
    let mut previous_end = 0;
    for rva in sites {
        let section = section_at(pe, rva)?;
        ensure!(
            section.is_executable(),
            "RIP reference at {rva:#x} is outside executable code"
        );
        let at = file_range(pe, rva, 1)?.start;
        let end = pe.layout().section_raw_range(section, pe.data.len()).end;
        let mut decoder = Decoder::with_ip(
            64,
            &pe.data[at..end.min(at + 15)],
            pe.layout().va(rva),
            DecoderOptions::NONE,
        );
        let ins = decoder.decode();
        let (target, object) = rip_target(pe, &ins)
            .and_then(|target| global_at(globals, target).map(|object| (target, object)))
            .with_context(|| {
                format!("instruction at {rva:#x} does not reference a selected global")
            })?;
        let constants = decoder.get_constant_offsets(&ins);
        let instruction_bytes = at..at + ins.len();
        ensure!(
            ins.memory_base() == Register::RIP
                && !matches!(ins.segment_prefix(), Register::FS | Register::GS)
                && constants.displacement_size() == 4
                && !pe.layout().is_protected(instruction_bytes.clone())
                && !metadata.iter().any(|r| overlaps(r, &instruction_bytes)),
            "unsupported RIP reference at {rva:#x}"
        );
        ensure!(
            rva >= previous_end,
            "overlapping RIP instructions at {rva:#x}"
        );
        previous_end = rva + ins.len() as u32;
        let g = &globals[object];
        ensure!(
            ins.memory_size().size() <= (g.rvas.end - target) as usize,
            "RIP access at {rva:#x} crosses the global's end"
        );
        decoded.insert(
            rva,
            RipSite {
                instruction: ins,
                displacement_rva: rva + constants.displacement_offset() as u32,
                object,
                target_rva: target,
            },
        );
    }
    for ins in analysis
        .functions
        .iter()
        .flat_map(|f| &f.blocks)
        .flat_map(|b| &b.instrs)
        .filter(|i| !i.dead)
    {
        let end = ins.rva + ins.len as u32;
        for (&rva, listed) in decoded.range(ins.rva.saturating_sub(14)..end) {
            ensure!(
                rva + listed.instruction.len() as u32 <= ins.rva || rva == ins.rva,
                "RIP reference at {rva:#x} overlaps a decoded instruction at {:#x}",
                ins.rva
            );
        }
        let Some(target) = rip_target(pe, &ins.iced) else {
            continue;
        };
        let i = globals.partition_point(|g| g.rvas.end <= target);
        if let Some(g) = globals.get(i) {
            if g.rvas.contains(&target) {
                ensure!(
                    decoded.contains_key(&ins.rva),
                    "missing 'rip {:#x}' for global {:#x}",
                    ins.rva,
                    g.rvas.start
                );
            } else {
                ensure!(
                    target.saturating_add(ins.iced.memory_size().size() as u32) <= g.rvas.start,
                    "RIP access at {:#x} crosses a global's start",
                    ins.rva
                );
            }
        }
    }
    Ok(decoded)
}

/// An explicit map supplies object boundaries and reference sites. Automatic
/// mode uses the whole writable data section as the unit of relocation.
pub(crate) fn relocate(
    pe: &mut PeFile,
    analysis: &Analysis,
    map: Option<&str>,
    slot: u8,
) -> Result<Vec<(u32, u32)>> {
    let fixups = base_fixups(pe)?;
    let (mut globals, rip_sites) = match map {
        Some(map) => parse_map(pe, map)?,
        None => automatic::discover(pe, &fixups)?,
    };
    let metadata = metadata_ranges(pe, analysis, &globals)?;
    let rip_sites = read_rip_sites(pe, analysis, &globals, rip_sites, &metadata)?;

    let mut output = None;
    for (name, characteristics) in [(".sbdata", WRITABLE_DATA), (".sbro", READ_ONLY_DATA)] {
        let current = output.as_ref().unwrap_or(pe);
        let Some(alignment) = globals
            .iter()
            .filter(|g| g.characteristics == characteristics)
            .map(|g| g.alignment)
            .max()
        else {
            continue;
        };
        let section_rva = next_section_rva(current)?;
        let mut payload = vec![0; (u32::from(slot) * alignment) as usize];
        let mut zero_fill = 0;
        for g in globals
            .iter_mut()
            .filter(|g| g.characteristics == characteristics)
        {
            let next = u32::try_from(payload.len())?
                .checked_add(zero_fill)
                .context("global payload overflow")?;
            let offset = align(next, g.alignment)?;
            g.destination = section_rva
                .checked_add(offset)
                .context("global destination overflow")?;
            payload.resize(offset as usize, 0);
            payload.extend_from_slice(&pe.data[g.bytes.clone()]);
            zero_fill = g.rvas.end - g.rvas.start - u32::try_from(g.bytes.len())?;
        }
        let (data, _) = append_section(
            current,
            section_rva,
            name,
            characteristics,
            &payload,
            zero_fill,
        )?;
        output = Some(PeFile::parse_with_symbols(
            data,
            pe.layout().handler_symbols.clone(),
        )?);
    }
    let mut output = output.context("no global sections planned")?;

    for (rva, site) in rip_sites {
        let g = &mut globals[site.object];
        let new = moved_target(g, site.target_rva);
        let ins = site.instruction;
        let new_va = pe.layout().va(new);
        let delta = i32::try_from(i128::from(new_va) - i128::from(ins.next_ip()))
            .context("moved global exceeds RIP-relative displacement range")?;
        let bytes = file_range(&output, site.displacement_rva, 4)?;
        output.data[bytes].copy_from_slice(&delta.to_le_bytes());
        let bytes = file_range(&output, rva, ins.len() as u32)?;
        let patched =
            Decoder::with_ip(64, &output.data[bytes], ins.ip(), DecoderOptions::NONE).decode();
        let mut expected = ins;
        expected.set_memory_displacement64(new_va);
        ensure!(
            patched == expected,
            "failed to verify patched RIP reference at {rva:#x}"
        );
        g.referenced = true;
    }

    for (&rva, &value) in &fixups {
        let Some(old) = image_rva(pe, value) else {
            continue;
        };
        let Some(i) = global_at(&globals, old) else {
            continue;
        };
        let bytes = file_range(pe, rva, 8)?;
        ensure!(
            !metadata.iter().any(|r| overlaps(r, &bytes)),
            "PE metadata at {rva:#x} references a selected global"
        );
        let destination =
            global_at(&globals, rva).map_or(rva, |object| moved_target(&globals[object], rva));
        let g = &mut globals[i];
        let new = pe.layout().va(moved_target(g, old));
        let bytes = file_range(&output, destination, 8)?;
        output.data[bytes].copy_from_slice(&new.to_le_bytes());
        g.referenced = true;
    }
    if map.is_none() {
        automatic::retarget_metadata(&mut output, &globals[0])?;
    }

    let mut moved = Vec::with_capacity(globals.len());
    for g in globals {
        let old = g.rvas.start;
        ensure!(g.referenced, "global {old:#x} has no verified references");
        let bytes = file_range(&output, old, u32::try_from(g.bytes.len())?)?;
        output.data[bytes].fill(0);
        moved.push((old, g.destination));
    }
    *pe = PeFile::parse_with_symbols(output.data, pe.layout().handler_symbols.clone())?;
    Ok(moved)
}

fn base_fixups(pe: &PeFile) -> Result<BTreeMap<u32, u64>> {
    let mut fixups = BTreeMap::new();
    pe.visit_base_relocations(|kind, rva| {
        ensure!(
            kind == 10,
            "unsupported base relocation type {kind} in global relocation"
        );
        let bytes = file_range(pe, rva, 8)?;
        ensure!(
            fixups
                .range(rva.saturating_sub(7)..rva.saturating_add(8))
                .next()
                .is_none(),
            "overlapping base relocation at {rva:#x}"
        );
        fixups.insert(rva, u64::from_le_bytes(pe.data[bytes].try_into()?));
        Ok(())
    })?;
    Ok(fixups)
}
