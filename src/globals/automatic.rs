//! Binary-only relocation of a whole, conventional writable data section.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{bail, ensure, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};

use super::{file_range, image_rva, moved_target, overlaps, rip_target, Global, WRITABLE_DATA};
use crate::{
    pe::{PeFile, UnwindKind},
    writer::align,
};

const PAGE: u32 = 0x1000;

pub(super) fn discover(
    pe: &PeFile,
    fixups: &BTreeMap<u32, u64>,
) -> Result<(Vec<Global>, BTreeSet<u32>)> {
    let opt = optional_header(pe);
    let layout = pe.layout();
    ensure!(
        word(&pe.data[opt + 108..]) <= 16,
        "nonstandard PE directories prevent automatic data relocation"
    );
    ensure!(
        word(&pe.data[opt + 32..]) == PAGE
            && layout
                .sections
                .iter()
                .all(|s| s.virtual_address.is_multiple_of(PAGE)),
        "--auto-globals requires page-aligned PE sections"
    );
    let mut sections = layout.sections.iter().filter(|s| s.name() == ".data");
    let data = sections
        .next()
        .context("--auto-globals requires a .data section")?;
    ensure!(
        sections.next().is_none()
            && data.characteristics == WRITABLE_DATA
            && data.virtual_size != 0
            && data.raw_size != 0,
        "--auto-globals requires one ordinary .data section with initialized bytes"
    );
    let rvas = data.virtual_address..data.virtual_address + data.raw_size.max(data.virtual_size);
    let global = Global {
        bytes: file_range(pe, rvas.start, data.raw_size)?,
        rvas,
        alignment: PAGE,
        characteristics: WRITABLE_DATA,
        destination: 0,
        referenced: false,
    };
    check_metadata(pe)?;
    scan_data(pe, &global.rvas, fixups)?;
    let sites = scan_code(pe, &global.rvas, fixups)?;
    Ok((vec![global], sites))
}

fn optional_header(pe: &PeFile) -> usize {
    word(&pe.data[0x3C..]) as usize + 24
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

fn address(bytes: &[u8]) -> Result<u64> {
    Ok(if bytes.len() == 4 {
        u64::from(word(bytes))
    } else {
        u64::from_le_bytes(bytes.try_into()?)
    })
}

fn check_metadata(pe: &PeFile) -> Result<()> {
    for index in [7, 8, 9, 11, 13, 14, 15] {
        ensure!(
            pe.directory(index)?.is_none(),
            "unsupported PE data directory {index} for automatic data relocation"
        );
    }
    if let Some(config) = pe.directory(10)? {
        for field in [192, 200, 224, 240, 248] {
            if field + 8 <= config.len() {
                ensure!(
                    pe.data[config.start + field..config.start + field + 8]
                        .iter()
                        .all(|&b| b == 0),
                    "unsupported load-config metadata at offset {field}"
                );
            }
        }
    }
    let layout = pe.layout();
    for function in &layout.runtime_functions {
        let rva = function.start;
        let info = layout.unwind_info(rva).context("missing unwind record")?;
        ensure!(
            matches!(info.kind, UnwindKind::Plain | UnwindKind::Chained { .. })
                || layout.c_specific.contains_key(&rva)
                || layout.cpp_eh.contains_key(&rva)
                || layout.gs_handlers.contains_key(&rva),
            "opaque unwind metadata at RVA {rva:#x} prevents automatic data relocation"
        );
    }
    Ok(())
}

fn candidate(pe: &PeFile, moved: &Range<u32>, value: u64) -> bool {
    let hits = |rva| moved.contains(&rva) || points_past(pe, moved, rva);
    u32::try_from(value).is_ok_and(hits) || image_rva(pe, value).is_some_and(hits)
}

fn points_past(pe: &PeFile, moved: &Range<u32>, rva: u32) -> bool {
    rva == moved.end && !pe.layout().sections.iter().any(|s| s.contains_rva(rva))
}

fn scan_data(pe: &PeFile, moved: &Range<u32>, fixups: &BTreeMap<u32, u64>) -> Result<()> {
    let mut typed = read_pogo(pe, moved)?.payloads;
    typed.extend(pe.directory(5)?);
    for (&site, &value) in fixups {
        let source = site..site + 8;
        ensure!(
            !overlaps(&source, moved) || source.end <= moved.end && source.start >= moved.start,
            "base relocation at RVA {site:#x} straddles .data"
        );
        if let Some(target) = image_rva(pe, value) {
            ensure!(
                !points_past(pe, moved, target),
                "base relocation at RVA {site:#x} points just beyond .data"
            );
        }
    }
    for section in pe.layout().sections.iter().filter(|s| !s.is_executable()) {
        let bytes = pe.layout().section_raw_range(section, pe.data.len());
        for width in [4, 8] {
            for (offset, window) in pe.data[bytes.clone()].windows(width).enumerate() {
                if !candidate(pe, moved, address(window)?) {
                    continue;
                }
                let file = bytes.start + offset..bytes.start + offset + width;
                if typed.iter().any(|table| overlaps(table, &file)) {
                    continue;
                }
                let rva = section.virtual_address + offset as u32;
                if fixups
                    .range(rva.saturating_sub(7)..rva + width as u32)
                    .next()
                    .is_some()
                {
                    continue;
                }
                bail!("possible untyped .data reference at RVA {rva:#x}");
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct Pogo {
    payloads: Vec<Range<usize>>,
    fields: BTreeSet<u32>,
}

// Microsoft linkers emit POGO subsection records even in images without PDBs.
fn read_pogo(pe: &PeFile, moved: &Range<u32>) -> Result<Pogo> {
    let mut pogo = Pogo::default();
    let Some(directory) = pe.directory(6)? else {
        return Ok(pogo);
    };
    ensure!(
        directory.len().is_multiple_of(28),
        "invalid debug directory"
    );
    for entry in pe.data[directory].as_chunks::<28>().0 {
        if word(&entry[12..]) != 13 {
            continue;
        }
        let rva = word(&entry[20..]);
        let size = word(&entry[16..]);
        let payload = file_range(pe, rva, size)?;
        ensure!(
            payload.start == word(&entry[24..]) as usize && !overlaps(&(rva..rva + size), moved),
            "unsupported POGO debug record location"
        );
        let data = &pe.data[payload.clone()];
        ensure!(
            matches!(data.get(..4), Some(b"\0\0\0\0" | b"GCTL" | b"OGPS")),
            "unrecognized POGO record format"
        );
        let mut at = 4;
        while at < data.len() {
            let header = data.get(at..at + 8).context("truncated POGO record")?;
            let start = word(header);
            let end = start
                .checked_add(word(&header[4..]))
                .context("POGO range overflow")?;
            if overlaps(&(start..end), moved) || moved.contains(&start) {
                ensure!(
                    start >= moved.start && end <= moved.end,
                    "POGO range crosses .data"
                );
                pogo.fields.insert(rva + at as u32);
            }
            let name = data[at + 8..]
                .iter()
                .position(|&byte| byte == 0)
                .context("unterminated POGO record name")?;
            at = align(u32::try_from(at + 8 + name + 1)?, 4)? as usize;
        }
        ensure!(at == data.len(), "truncated POGO record alignment");
        pogo.payloads.push(payload);
    }
    Ok(pogo)
}

fn scan_code(
    pe: &PeFile,
    moved: &Range<u32>,
    fixups: &BTreeMap<u32, u64>,
) -> Result<BTreeSet<u32>> {
    let layout = pe.layout();
    let sections: Vec<_> = layout.executable_sections().collect();
    let mut coverage: Vec<_> = sections
        .iter()
        .map(|s| vec![0u8; s.raw_size as usize])
        .collect();
    let mut pending: Vec<_> = layout
        .code_roots
        .iter()
        .copied()
        .filter(|&rva| rva != 0)
        .chain(layout.runtime_functions.iter().map(|f| f.start))
        .chain(
            layout
                .c_specific
                .values()
                .flat_map(|c| &c.scopes)
                .filter_map(|s| (s.target != 0).then_some(s.target)),
        )
        .chain(layout.relocated_code_references(&pe.data))
        .collect();
    let mut rip_sites = BTreeSet::new();
    while let Some(rva) = pending.pop() {
        let index = sections
            .iter()
            .position(|s| s.contains_rva(rva))
            .with_context(|| format!("code target {rva:#x} is outside executable sections"))?;
        let section = sections[index];
        let offset = (rva - section.virtual_address) as usize;
        let marked = &mut coverage[index];
        match marked.get(offset) {
            Some(1) => continue,
            Some(0) => (),
            Some(_) => bail!("overlapping executable instructions at RVA {rva:#x}"),
            None => bail!("code target {rva:#x} is not file-backed"),
        }
        let at = section.raw_ptr as usize + offset;
        let end = section.raw_ptr as usize + section.raw_size as usize;
        let mut decoder =
            Decoder::with_ip(64, &pe.data[at..end], layout.va(rva), DecoderOptions::NONE);
        let ins = decoder.decode();
        ensure!(
            !ins.is_invalid(),
            "invalid executable instruction at RVA {rva:#x}"
        );
        let span = &mut marked[offset..offset + ins.len()];
        ensure!(
            span.iter().all(|&n| n == 0),
            "overlapping executable instructions at RVA {rva:#x}"
        );
        span.fill(2);
        span[0] = 1;
        let ip_target = rip_target(pe, &ins);
        if let Some(target) = ip_target {
            let size = ins.memory_size().size() as u32;
            if moved.contains(&target) {
                rip_sites.insert(rva);
            } else {
                ensure!(
                    !(target < moved.start && target.saturating_add(size) > moved.start)
                        && !points_past(pe, moved, target),
                    "RIP reference at RVA {rva:#x} crosses or ends at the .data boundary"
                );
            }
            if ins.mnemonic() == Mnemonic::Lea && sections.iter().any(|s| s.contains_rva(target)) {
                pending.push(target);
            }
        }
        let flow = ins.flow_control();
        if matches!(
            flow,
            FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            ensure!(
                matches!(
                    ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ),
                "unsupported branch at RVA {rva:#x}"
            );
            pending
                .push(image_rva(pe, ins.near_branch_target()).context("branch leaves the image")?);
        }
        if matches!(
            flow,
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        ) {
            ensure!(
                ip_target.is_some_and(|target| layout.import_slots.contains(&target)),
                "unresolved indirect control flow at RVA {rva:#x}"
            );
        }
        ensure!(
            flow != FlowControl::XbeginXabortXend,
            "transactional control flow at RVA {rva:#x}"
        );
        if matches!(
            flow,
            FlowControl::Next
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::ConditionalBranch
        ) {
            pending.push(rva + ins.len() as u32);
        }

        let constants = decoder.get_constant_offsets(&ins);
        let branch = matches!(
            flow,
            FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        );
        for (offset, size, skip) in [
            (
                constants.displacement_offset(),
                constants.displacement_size(),
                ins.is_ip_rel_memory_operand(),
            ),
            (
                constants.immediate_offset(),
                constants.immediate_size(),
                branch,
            ),
            (
                constants.immediate_offset2(),
                constants.immediate_size2(),
                branch,
            ),
        ] {
            if skip || size < 4 {
                continue;
            }
            let value = address(&pe.data[at + offset..at + offset + size])?;
            ensure!(
                !candidate(pe, moved, value)
                    || (size == 8 && fixups.contains_key(&(rva + offset as u32))),
                "possible untyped .data reference in code at RVA {rva:#x}"
            );
        }
    }
    for (section, marked) in sections.into_iter().zip(coverage) {
        let bytes = &pe.data[layout.section_raw_range(section, pe.data.len())];
        let mut offset = 0;
        while offset < bytes.len() {
            if marked[offset] != 0 || matches!(bytes[offset], 0 | 0x90 | 0xCC) {
                offset += 1;
                continue;
            }
            let rva = section.virtual_address + offset as u32;
            let ins = Decoder::with_ip(64, &bytes[offset..], layout.va(rva), DecoderOptions::NONE)
                .decode();
            ensure!(
                ins.mnemonic() == Mnemonic::Nop
                    && marked[offset..offset + ins.len()].iter().all(|&n| n == 0),
                "unclassified executable bytes at RVA {rva:#x}"
            );
            offset += ins.len();
        }
    }
    Ok(rip_sites)
}

pub(super) fn retarget_metadata(pe: &mut PeFile, global: &Global) -> Result<()> {
    for field in read_pogo(pe, &global.rvas)?.fields {
        let bytes = file_range(pe, field, 4)?;
        let old = word(&pe.data[bytes.clone()]);
        pe.data[bytes].copy_from_slice(&moved_target(global, old).to_le_bytes());
    }
    let Some(directory) = pe.directory(5)? else {
        return Ok(());
    };
    let mut blocks = Vec::new();
    let mut at = directory.start;
    while at < directory.end {
        let page = word(&pe.data[at..]);
        let size = word(&pe.data[at + 4..]) as usize;
        ensure!(
            page.is_multiple_of(PAGE) && size.is_multiple_of(4),
            "unaligned PE base relocation block"
        );
        let mut block = pe.data[at..at + size].to_vec();
        let mapped = if global.rvas.contains(&page) {
            moved_target(global, page)
        } else {
            page
        };
        block[..4].copy_from_slice(&mapped.to_le_bytes());
        blocks.push((mapped, block));
        at += size;
    }
    blocks.sort_by_key(|(page, _)| *page);
    let mut at = directory.start;
    for (_, block) in blocks {
        pe.data[at..at + block.len()].copy_from_slice(&block);
        at += block.len();
    }
    Ok(())
}
