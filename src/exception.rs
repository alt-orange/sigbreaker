//! Identification and relocation of AMD64 C-specific SEH scope tables.
//! Handler identity comes from a named import reached through a direct thunk.
use crate::pe::PeLayout;
use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub begin: u32,
    pub end: u32,
    pub handler: u32,
    pub target: u32,
}

#[derive(Debug, Clone)]
pub struct CSpecific {
    pub handler: u32,
    pub scopes: Vec<Scope>,
    pub table_bytes: Range<usize>,
    pub gs_data: Vec<u8>,
}

fn bytes<'a>(pe: &PeLayout, data: &'a [u8], rva: u32, size: usize) -> Result<&'a [u8]> {
    let off = pe
        .rva_to_offset(rva)
        .context("unmapped exception/import data")?;
    let last = rva
        .checked_add(u32::try_from(size.checked_sub(1).context("empty range")?)?)
        .context("RVA overflow")?;
    if pe.rva_to_offset(last) != Some(off + size - 1) {
        bail!("noncontiguous exception/import data");
    }
    data.get(off..off + size)
        .context("truncated exception/import data")
}
fn word(pe: &PeLayout, data: &[u8], rva: u32) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(pe, data, rva, 4)?.try_into()?))
}
fn string(pe: &PeLayout, data: &[u8], rva: u32) -> Result<String> {
    let mut out = Vec::new();
    for i in 0..4096 {
        let c = bytes(
            pe,
            data,
            rva.checked_add(i).context("string RVA overflow")?,
            1,
        )?[0];
        if c == 0 {
            return Ok(String::from_utf8(out)?);
        }
        out.push(c);
    }
    bail!("unterminated import name")
}

/// Named imports indexed by their IAT slot RVA. Bound/ordinal imports do not
/// establish a handler identity and are deliberately not guessed.
pub fn imports(
    pe: &PeLayout,
    data: &[u8],
    directory: Option<Range<usize>>,
) -> Result<BTreeMap<u32, (String, String)>> {
    let mut result = BTreeMap::new();
    let Some(range) = directory else {
        return Ok(result);
    };
    for at in (range.start..range.end).step_by(20) {
        let entry = data
            .get(at..at + 20)
            .filter(|_| at + 20 <= range.end)
            .context("truncated import descriptor")?;
        if entry.iter().all(|b| *b == 0) {
            return Ok(result);
        }
        let get = |i| u32::from_le_bytes(entry[i..i + 4].try_into().unwrap());
        let library = string(pe, data, get(12))?.to_ascii_lowercase();
        let iat = get(16);
        let table = if get(0) != 0 { get(0) } else { iat };
        if get(0) == 0 && get(4) != 0 {
            continue;
        } // bound addresses without names
        let mut terminated = false;
        for index in 0..data.len() / 8 {
            let delta = u32::try_from(index * 8)?;
            let value = u64::from_le_bytes(
                bytes(
                    pe,
                    data,
                    table.checked_add(delta).context("import overflow")?,
                    8,
                )?
                .try_into()?,
            );
            if value == 0 {
                terminated = true;
                break;
            }
            if value >> 63 == 0 && value <= u32::MAX as u64 {
                let name = string(
                    pe,
                    data,
                    (value as u32)
                        .checked_add(2)
                        .context("import name overflow")?,
                )?;
                result.insert(
                    iat.checked_add(delta).context("IAT overflow")?,
                    (library.clone(), name),
                );
            }
        }
        if !terminated {
            bail!("unterminated import thunk table");
        }
    }
    bail!("unterminated import descriptor table")
}

pub fn is_c_specific(
    pe: &PeLayout,
    data: &[u8],
    imports: &BTreeMap<u32, (String, String)>,
    handler: u32,
) -> bool {
    handler_name(pe, data, imports, handler).as_deref() == Some("__C_specific_handler")
}

pub fn handler_name(
    pe: &PeLayout,
    data: &[u8],
    imports: &BTreeMap<u32, (String, String)>,
    handler: u32,
) -> Option<String> {
    let mut rva = handler;
    let mut seen = BTreeSet::new();
    for _ in 0..8 {
        if !seen.insert(rva) {
            return None;
        }
        let off = pe.rva_to_offset(rva)?;
        let raw = data.get(off..off.saturating_add(15).min(data.len()))?;
        let ins = Decoder::with_ip(64, raw, pe.va(rva), DecoderOptions::NONE).decode();
        if ins.is_invalid()
            || pe.rva_to_offset(rva.saturating_add(ins.len() as u32 - 1))
                != Some(off + ins.len() - 1)
        {
            return None;
        }
        if ins.is_jmp_near_indirect() && ins.is_ip_rel_memory_operand() {
            let slot = ins
                .ip_rel_memory_address()
                .checked_sub(pe.image_base)
                .and_then(|v| u32::try_from(v).ok())?;
            return imports.get(&slot).and_then(|(library, name)| {
                matches!(
                    library.as_str(),
                    "vcruntime140.dll"
                        | "vcruntime140d.dll"
                        | "vcruntime140_1.dll"
                        | "vcruntime140_1d.dll"
                        | "ntdll.dll"
                        | "msvcrt.dll"
                )
                .then(|| name.clone())
            });
        }
        if !ins.is_jmp_short_or_near() {
            return None;
        }
        let next = ins
            .near_branch_target()
            .checked_sub(pe.image_base)
            .and_then(|v| u32::try_from(v).ok())?;
        rva = next;
    }
    None
}

pub fn parse(
    pe: &PeLayout,
    data: &[u8],
    function: Range<u32>,
    handler: u32,
    table: u32,
) -> Result<CSpecific> {
    let count = word(pe, data, table)? as usize;
    if count > data.len() / 16 {
        bail!("invalid C-specific scope count");
    }
    let size = 4usize
        .checked_add(count * 16)
        .context("scope size overflow")?;
    let raw = bytes(pe, data, table, size)?;
    let mut scopes = Vec::new();
    for at in (4..size).step_by(16) {
        let get = |i| u32::from_le_bytes(raw[at + i..at + i + 4].try_into().unwrap());
        let scope = Scope {
            begin: get(0),
            end: get(4),
            handler: get(8),
            target: get(12),
        };
        if scope.begin >= scope.end || scope.begin < function.start || scope.end > function.end {
            bail!("scope outside owning runtime function");
        }
        if scope.target != 0 && !function.contains(&scope.target) {
            bail!("exception continuation outside owning function");
        }
        if scope.handler != 1
            && !pe
                .executable_sections()
                .any(|s| s.contains_rva(scope.handler))
        {
            bail!("unmapped filter/finally handler");
        }
        // Separate funclets retain their original entries and unwind records.
        if function.contains(&scope.handler) {
            bail!("in-function filter/finally funclet unsupported");
        }
        if scope.target == 0 && scope.handler == 1 {
            bail!("invalid finally handler sentinel");
        }
        scopes.push(scope);
    }
    let off = pe.rva_to_offset(table).unwrap();
    Ok(CSpecific {
        handler,
        scopes,
        table_bytes: off..off + size,
        gs_data: Vec::new(),
    })
}

/// GS cookie offsets are frame-relative, so an unchanged prologue/frame allows
/// byte-exact copying. Bit 2 adds aligned-base offset and alignment mask words.
pub fn gs_data(pe: &PeLayout, data: &[u8], rva: u32) -> Result<Vec<u8>> {
    let flags = word(pe, data, rva)?;
    Ok(bytes(pe, data, rva, if flags & 4 != 0 { 12 } else { 4 })?.to_vec())
}

/// Explicit linker-map identities allow statically linked handlers to be used
/// without guessing an ABI from machine-code prefixes or unversioned metadata.
pub fn map_symbols(text: &str, image_base: u64) -> Result<BTreeMap<u32, String>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 || !fields[0].contains(':') {
            continue;
        }
        let name = fields[1];
        if !matches!(
            name,
            "__C_specific_handler"
                | "__CxxFrameHandler3"
                | "__CxxFrameHandler4"
                | "__GSHandlerCheck"
                | "__GSHandlerCheck_SEH"
                | "__GSHandlerCheck_EH"
                | "__GSHandlerCheck_EH4"
        ) {
            continue;
        }
        let va =
            u64::from_str_radix(fields[2], 16).context("invalid linker-map handler address")?;
        let rva = u32::try_from(
            va.checked_sub(image_base)
                .context("linker map uses a different image base")?,
        )?;
        if result
            .insert(rva, name.to_owned())
            .is_some_and(|old| old != name)
        {
            bail!("conflicting linker-map handler symbols");
        }
    }
    if result.is_empty() {
        bail!("linker map contains no supported handler identities");
    }
    Ok(result)
}

/// Relocate each scope's coverage, splitting discontiguous ranges while keeping
/// original nesting/handler priority. Each tuple maps an original PC to emitted
/// bytes; synthetic fall-through jumps carry their original successor PC.
pub fn relocate(
    info: &CSpecific,
    image_base: u64,
    map: &BTreeMap<u64, u64>,
    spans: &[(u64, Range<u64>)],
) -> Result<Vec<Scope>> {
    let mut result = Vec::new();
    for scope in &info.scopes {
        let target = if scope.target == 0 {
            0
        } else {
            u32::try_from(
                map.get(&(image_base + scope.target as u64))
                    .context("unmapped exception continuation")?
                    .checked_sub(image_base)
                    .context("continuation underflow")?,
            )?
        };
        let mut ranges: Vec<_> = spans
            .iter()
            .filter(|(old, _)| {
                *old >= image_base + scope.begin as u64 && *old < image_base + scope.end as u64
            })
            .map(|(_, range)| range.clone())
            .collect();
        ranges.sort_by_key(|r| r.start);
        let mut merged: Vec<Range<u64>> = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut().filter(|last| last.end == range.start) {
                last.end = range.end;
            } else {
                merged.push(range);
            }
        }
        if merged.is_empty() {
            bail!("scope has no emitted instructions");
        }
        for range in merged {
            result.push(Scope {
                begin: u32::try_from(
                    range
                        .start
                        .checked_sub(image_base)
                        .context("scope underflow")?,
                )?,
                end: u32::try_from(
                    range
                        .end
                        .checked_sub(image_base)
                        .context("scope underflow")?,
                )?,
                handler: scope.handler,
                target,
            });
        }
    }
    Ok(result)
}
