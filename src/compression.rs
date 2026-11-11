//! Optional LZMA storage for a generated .sbrk section.
//! A TLS callback restores it before the image's original callbacks execute.

use anyhow::{ensure, Context, Result};
use lzma_rust2::{LzmaOptions, LzmaReader, LzmaWriter};
use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::pe::PeFile;
use crate::writer::{align, append_section, next_section_rva, RawShift};

#[path = "compression/decoder.rs"]
mod decoder;

const MAGIC: &[u8; 8] = b"SBRKCMP1";
const RECOVERY_SIZE: usize = 124;
const DECODER: &[u8] = include_bytes!("compression/decoder.bin");

pub(crate) struct Compressed {
    pub data: Vec<u8>,
    pub section: String,
    pub original_size: usize,
    pub packed_size: usize,
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(data, at, 4)?.try_into()?))
}

fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(data, at, 8)?.try_into()?))
}

fn bytes(data: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    data.get(at..at.checked_add(len).context("compression range overflow")?)
        .context("truncated compression metadata")
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn offset(pe: &PeFile, rva: u32) -> Result<usize> {
    pe.layout()
        .rva_to_offset(rva)
        .context("unmapped compression reference")
}

fn directory(pe: &PeFile, opt: usize, index: usize) -> Result<(u32, usize)> {
    if u32_at(&pe.data, opt + 108)? as usize <= index {
        return Ok((0, 0));
    }
    Ok((
        u32_at(&pe.data, opt + 112 + index * 8)?,
        u32_at(&pe.data, opt + 116 + index * 8)? as usize,
    ))
}

fn allocate(data: &mut Vec<u8>, len: usize, alignment: u32) -> Result<usize> {
    let at = align(u32::try_from(data.len())?, alignment)? as usize;
    data.resize(
        at.checked_add(len)
            .context("compression metadata overflow")?,
        0,
    );
    Ok(at)
}

fn append(data: &mut Vec<u8>, value: &[u8], alignment: u32) -> Result<usize> {
    let at = allocate(data, value.len(), alignment)?;
    data[at..at + value.len()].copy_from_slice(value);
    Ok(at)
}

fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

fn write_shift(data: &mut [u8], at: usize, shift: &RawShift) {
    for (index, value) in [
        shift.slot,
        shift.header_growth,
        shift.insert,
        shift.insertion_size,
    ]
    .into_iter()
    .enumerate()
    {
        put64(data, at + index * 8, value as u64);
    }
}

fn undo_shift(data: &mut Vec<u8>, record: &[u8], at: usize) -> Result<()> {
    let slot = usize::try_from(u64_at(record, at)?)?;
    let growth = usize::try_from(u64_at(record, at + 8)?)?;
    let insert = usize::try_from(u64_at(record, at + 16)?)?;
    let len = usize::try_from(u64_at(record, at + 24)?)?;
    let start = insert
        .checked_add(growth)
        .context("compression undo overflow")?;
    bytes(data, start, len)?;
    data.drain(start..start + len);
    bytes(data, slot, growth)?;
    data.drain(slot..slot + growth);
    Ok(())
}

/// Restore our compressed output to its exact PE representation for analysis.
pub(crate) fn unpack(data: &[u8]) -> Result<Option<Vec<u8>>> {
    if data.len() < 64 || &data[..2] != b"MZ" {
        return Ok(None);
    }
    let pe = u32_at(data, 0x3c)? as usize;
    let Some(signature) = data.get(pe..pe.saturating_add(4)) else {
        return Ok(None);
    };
    if signature != b"PE\0\0" {
        return Ok(None);
    }
    let count = u16::from_le_bytes(bytes(data, pe + 6, 2)?.try_into()?) as usize;
    ensure!(count <= 96, "too many sections in compressed image");
    let optional_size = u16::from_le_bytes(bytes(data, pe + 20, 2)?.try_into()?) as usize;
    let table = pe
        .checked_add(24 + optional_size)
        .context("PE table overflow")?;
    for index in 0..count {
        let section = table + index * 40;
        let header = bytes(data, section, 40)?;
        if !header[..8].starts_with(b".sbpack") {
            continue;
        }
        let raw = u32_at(header, 20)? as usize;
        let size = u32_at(header, 16)? as usize;
        let record = bytes(data, raw, size)?;
        if !record.starts_with(MAGIC) {
            continue;
        }
        ensure!(
            u32_at(record, 8)? == 1,
            "unsupported .sbrk compression version"
        );
        let raw_size = u32_at(record, 16)? as usize;
        let packed_at = u32_at(record, 20)? as usize;
        let packed_size = u32_at(record, 24)? as usize;
        let original_size = usize::try_from(u64_at(record, 28)?)?;
        let headers_size = u32_at(record, 36)? as usize;
        let patches_count = u32_at(record, 40)? as usize;
        let removed_at = usize::try_from(u64_at(record, 44)?)?;
        ensure!(
            original_size
                <= data
                    .len()
                    .checked_add(raw_size)
                    .context("PE size overflow")?,
            "invalid recovered PE size"
        );
        let original_headers = bytes(record, RECOVERY_SIZE, headers_size)?;
        ensure!(
            headers_size <= original_size && removed_at <= data.len(),
            "invalid compression recovery ranges"
        );
        let compressed = bytes(record, packed_at, packed_size)?;
        ensure!(
            u64_at(compressed, 5)? == raw_size as u64,
            "LZMA size mismatch"
        );
        let mut reader = LzmaReader::new_mem_limit(compressed, 64 * 1024, None)?;
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(raw_size)?;
        reader
            .by_ref()
            .take(raw_size as u64 + 1)
            .read_to_end(&mut decoded)?;
        ensure!(decoded.len() == raw_size, "incorrect restored .sbrk size");
        let mut restored = Vec::new();
        restored.try_reserve_exact(
            data.len()
                .checked_add(raw_size)
                .context("PE size overflow")?,
        )?;
        restored.extend_from_slice(&data[..removed_at]);
        restored.extend_from_slice(&decoded);
        restored.extend_from_slice(&data[removed_at..]);
        undo_shift(&mut restored, record, 84)?;
        undo_shift(&mut restored, record, 52)?;
        ensure!(
            restored.len() == original_size,
            "compression recovery size mismatch"
        );
        restored[..headers_size].copy_from_slice(original_headers);
        let mut cursor = RECOVERY_SIZE + headers_size;
        ensure!(
            patches_count <= record.len() / 12,
            "excessive recovery patches"
        );
        for _ in 0..patches_count {
            let at = usize::try_from(u64_at(record, cursor)?)?;
            let len = u32_at(record, cursor + 8)? as usize;
            cursor = cursor.checked_add(12).context("recovery patch overflow")?;
            let value = bytes(record, cursor, len)?;
            bytes(&restored, at, len)?;
            restored[at..at + len].copy_from_slice(value);
            cursor = cursor.checked_add(len).context("recovery patch overflow")?;
        }
        ensure!(
            hash(&restored) == u64_at(record, 116)?,
            "compressed PE integrity check failed"
        );
        return Ok(Some(restored));
    }
    Ok(None)
}

/// Compress the largest .sbrk, retaining the output only when its file is smaller.
pub(crate) fn compress(pe: &PeFile) -> Result<Option<Compressed>> {
    let Some(target) = pe
        .layout()
        .sections
        .iter()
        .filter(|s| s.name().starts_with(".sbrk") && s.is_executable() && s.raw_size != 0)
        .max_by_key(|s| s.raw_size)
        .copied()
    else {
        return Ok(None);
    };
    ensure!(
        pe.layout().windows_user_mode,
        "section compression requires a Windows user-mode EXE or DLL"
    );
    let opt = u32_at(&pe.data, 0x3c)? as usize + 24;
    let optional_size = u16::from_le_bytes(bytes(&pe.data, opt - 4, 2)?.try_into()?);
    ensure!(
        optional_size >= 192,
        "TLS compression requires room for ten PE data directories"
    );
    let raw_size = target.raw_size as usize;
    let original = bytes(&pe.data, target.raw_ptr as usize, raw_size)?;
    let mut encoder = LzmaWriter::new_use_header(
        Vec::new(),
        &LzmaOptions::with_preset(6),
        Some(raw_size as u64),
    )?;
    encoder.write_all(original)?;
    let compressed = encoder.finish()?;
    if compressed.len() + DECODER.len() >= raw_size {
        return Ok(None);
    }
    for index in [0, 2, 6, 10, 11, 12, 14] {
        let (start, size) = directory(pe, opt, index)?;
        let end = start
            .checked_add(u32::try_from(size)?)
            .context("directory RVA overflow")?;
        ensure!(
            size == 0
                || end <= target.virtual_address
                || start >= target.virtual_address + target.virtual_size.max(target.raw_size),
            "loader metadata directory {index} overlaps the compressed section"
        );
    }

    let headers_size = u32_at(&pe.data, opt + 60)? as usize;
    let mut restore_patches = Vec::new();
    let mut debug_fields = Vec::new();
    let (debug_rva, debug_size) = directory(pe, opt, 6)?;
    if debug_rva != 0 {
        ensure!(
            debug_size.is_multiple_of(28),
            "invalid debug directory size"
        );
        let at = offset(pe, debug_rva)?;
        for entry in (0..debug_size).step_by(28) {
            let field = at + entry + 24;
            debug_fields.push(field);
            restore_patches.push((field, bytes(&pe.data, field, 4)?.to_vec()));
        }
    }
    if let Some((pointer, _)) = pe.layout().eh_continuation_fields {
        restore_patches.push((pointer, bytes(&pe.data, pointer, 8)?.to_vec()));
    }
    let (load_config_rva, load_config_size) = directory(pe, opt, 10)?;
    let cfg = if load_config_rva != 0 && load_config_size >= 148 {
        let at = offset(pe, load_config_rva)?;
        let flags = u32_at(&pe.data, at + 144)?;
        if u32_at(&pe.data, at)? >= 148 && flags & 0x500 != 0 {
            for (field, len) in [(128, 8), (136, 8), (144, 4)] {
                restore_patches.push((at + field, bytes(&pe.data, at + field, len)?.to_vec()));
            }
            Some((at, flags))
        } else {
            None
        }
    } else {
        None
    };
    let mut pack = vec![0u8; RECOVERY_SIZE];
    pack[..8].copy_from_slice(b"SBRKPEND");
    put32(&mut pack, 8, 1);
    put32(&mut pack, 12, target.virtual_address);
    put32(&mut pack, 16, target.raw_size);
    put32(&mut pack, 24, u32::try_from(compressed.len())?);
    put64(&mut pack, 28, pe.data.len() as u64);
    put32(&mut pack, 36, u32::try_from(headers_size)?);
    put32(&mut pack, 40, u32::try_from(restore_patches.len())?);
    put64(&mut pack, 116, hash(&pe.data));
    pack.extend_from_slice(bytes(&pe.data, 0, headers_size)?);
    for (at, value) in &restore_patches {
        pack.extend_from_slice(&(*at as u64).to_le_bytes());
        pack.extend_from_slice(&u32::try_from(value.len())?.to_le_bytes());
        pack.extend_from_slice(value);
    }
    let compressed_at = append(&mut pack, &compressed, 8)?;
    put32(&mut pack, 20, u32::try_from(compressed_at)?);
    let pack_rva = next_section_rva(pe)?;
    let rva = |at: usize| -> Result<u32> {
        pack_rva
            .checked_add(u32::try_from(at)?)
            .context("packed section RVA overflow")
    };

    // Keep import descriptors and the additional API thunks available to the loader.
    let (imports_rva, _) = directory(pe, opt, 1)?;
    let mut imports = Vec::new();
    if imports_rva != 0 {
        let mut at = offset(pe, imports_rva)?;
        loop {
            let descriptor = bytes(&pe.data, at, 20)?;
            if descriptor.iter().all(|&byte| byte == 0) {
                break;
            }
            for field in [0, 12, 16] {
                ensure!(
                    !target.contains_rva(u32_at(descriptor, field)?),
                    "import metadata overlaps the compressed section"
                );
            }
            ensure!(
                imports.len() < pe.data.len(),
                "unterminated import directory"
            );
            imports.extend_from_slice(descriptor);
            at += 20;
        }
    }
    let names = [
        "VirtualProtect",
        "FlushInstructionCache",
        "VirtualAlloc",
        "VirtualFree",
    ];
    let mut name_rvas = Vec::new();
    for name in names {
        let mut value = vec![0, 0];
        value.extend_from_slice(name.as_bytes());
        value.push(0);
        name_rvas.push(rva(append(&mut pack, &value, 2)?)?);
    }
    let module_name = rva(append(&mut pack, b"KERNEL32.dll\0", 1)?)?;
    let lookup = allocate(&mut pack, 40, 8)?;
    let iat = allocate(&mut pack, 40, 8)?;
    for (index, value) in name_rvas.iter().enumerate() {
        put64(&mut pack, lookup + index * 8, u64::from(*value));
        put64(&mut pack, iat + index * 8, u64::from(*value));
    }
    let mut added = [0u8; 20];
    put32(&mut added, 0, rva(lookup)?);
    put32(&mut added, 12, module_name);
    put32(&mut added, 16, rva(iat)?);
    imports.extend_from_slice(&added);
    imports.extend_from_slice(&[0; 20]);
    let imports_at = append(&mut pack, &imports, 4)?;

    // The decompressor precedes every existing TLS callback for EXEs and DLLs.
    let (tls_rva, tls_size) = directory(pe, opt, 9)?;
    let mut tls = [0u8; 40];
    let mut callbacks = Vec::new();
    if tls_rva != 0 {
        ensure!(tls_size >= 40, "truncated TLS directory");
        tls.copy_from_slice(bytes(&pe.data, offset(pe, tls_rva)?, 40)?);
        let start = u64_at(&tls, 0)?;
        let end = u64_at(&tls, 8)?;
        let section_start = pe.layout().va(target.virtual_address);
        let section_end = section_start + u64::from(target.virtual_size.max(target.raw_size));
        ensure!(
            start == end || end <= section_start || start >= section_end,
            "TLS initial data overlaps the compressed section"
        );
        let index = u64_at(&tls, 16)?;
        ensure!(
            index < section_start || index >= section_end,
            "TLS index overlaps the compressed section"
        );
        let callback_va = u64_at(&tls, 24)?;
        if callback_va != 0 {
            let callback_rva = u32::try_from(
                callback_va
                    .checked_sub(pe.layout().image_base)
                    .context("invalid TLS callback pointer")?,
            )?;
            let mut at = offset(pe, callback_rva)?;
            loop {
                let value = u64_at(&pe.data, at)?;
                if value == 0 {
                    break;
                }
                callbacks.push(value);
                at += 8;
            }
        }
    }
    if u64_at(&tls, 16)? == 0 {
        let index = allocate(&mut pack, 4, 4)?;
        put64(&mut tls, 16, pe.layout().va(rva(index)?));
    }
    let callbacks_at = allocate(&mut pack, (callbacks.len() + 2) * 8, 8)?;
    for (index, value) in callbacks.iter().enumerate() {
        put64(&mut pack, callbacks_at + (index + 1) * 8, *value);
    }
    put64(&mut tls, 24, pe.layout().va(rva(callbacks_at)?));
    let tls_at = append(&mut pack, &tls, 8)?;

    let cfg_table = if let Some((at, flags)) = cfg {
        let stride = 4 + (flags >> 28) as usize;
        let count = usize::try_from(u64_at(&pe.data, at + 136)?)?;
        ensure!(
            count <= pe.data.len() / stride,
            "excessive CFG function count"
        );
        let pointer = u64_at(&pe.data, at + 128)?;
        let mut entries = Vec::new();
        if count != 0 {
            let source = offset(
                pe,
                u32::try_from(
                    pointer
                        .checked_sub(pe.layout().image_base)
                        .context("invalid CFG table pointer")?,
                )?,
            )?;
            entries.extend_from_slice(bytes(&pe.data, source, count * stride)?);
        }
        entries.resize((count + 1) * stride, 0);
        let table = append(&mut pack, &entries, 4)?;
        Some((table, stride, count + 1))
    } else {
        None
    };

    let mut relocations: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
    let mut deferred = Vec::new();
    pe.visit_base_relocations(|kind, field| {
        if target.contains_rva(field) {
            ensure!(
                matches!(kind, 3 | 10),
                "unsupported compressed-section base relocation {kind}"
            );
            let width = if kind == 10 { 8 } else { 4 };
            ensure!(
                field
                    .checked_add(width)
                    .is_some_and(|end| end <= target.virtual_address + target.raw_size),
                "compressed relocation crosses initialized bytes"
            );
            deferred.push((field, kind));
        } else if cfg.is_none() || field != load_config_rva + 128 {
            relocations
                .entry(field & !0xfff)
                .or_default()
                .push((kind << 12) | (field as u16 & 0xfff));
        }
        Ok(())
    })?;
    let deferred_at = allocate(&mut pack, deferred.len() * 8, 4)?;
    for (index, &(field, kind)) in deferred.iter().enumerate() {
        put32(&mut pack, deferred_at + index * 8, field);
        put32(&mut pack, deferred_at + index * 8 + 4, u32::from(kind));
    }
    for at in (0..=callbacks.len()).map(|i| callbacks_at + i * 8).chain(
        [0, 8, 16, 24]
            .into_iter()
            .filter(|&field| u64_at(&tls, field).unwrap_or(0) != 0)
            .map(|field| tls_at + field),
    ) {
        let field = rva(at)?;
        relocations
            .entry(field & !0xfff)
            .or_default()
            .push(0xa000 | (field as u16 & 0xfff));
    }
    if cfg.is_some() {
        let field = load_config_rva + 128;
        relocations
            .entry(field & !0xfff)
            .or_default()
            .push(0xa000 | (field as u16 & 0xfff));
    }
    let reloc_at = allocate(&mut pack, 0, 4)?;
    for (page, mut fields) in relocations {
        fields.sort_unstable();
        fields.dedup();
        if fields.len() % 2 != 0 {
            fields.push(0);
        }
        pack.extend_from_slice(&page.to_le_bytes());
        pack.extend_from_slice(&u32::try_from(8 + fields.len() * 2)?.to_le_bytes());
        for field in fields {
            pack.extend_from_slice(&field.to_le_bytes());
        }
    }
    let reloc_size = pack.len() - reloc_at;

    let (exception_rva, exception_size) = directory(pe, opt, 3)?;
    let mut runtime = Vec::new();
    if exception_rva != 0 {
        ensure!(
            exception_size.is_multiple_of(12),
            "invalid exception directory size"
        );
        let at = offset(pe, exception_rva)?;
        for entry in bytes(&pe.data, at, exception_size)?.chunks_exact(12) {
            runtime.push((u32_at(entry, 0)?, u32_at(entry, 4)?, u32_at(entry, 8)?));
        }
    }
    let runtime_size = (runtime.len() + decoder::RUNTIME_FUNCTIONS.len()) * 12;
    let runtime_at = allocate(&mut pack, runtime_size, 4)?;
    let guard_at = match &pe.layout().eh_continuation_table {
        Some(table) => Some(append(
            &mut pack,
            bytes(&pe.data, table.start, table.len())?,
            4,
        )?),
        None => None,
    };
    let stub_rva = align(rva(pack.len())?, u32_at(&pe.data, opt + 32)?)?;
    stub_rva
        .checked_add(u32::try_from(DECODER.len())?)
        .context("decoder section RVA overflow")?;
    let callback = stub_rva
        .checked_add(decoder::ENTRY_OFFSET)
        .context("TLS callback RVA overflow")?;
    put64(&mut pack, callbacks_at, pe.layout().va(callback));
    if let Some((table, stride, count)) = cfg_table {
        // The appended callback has the greatest RVA in this sorted table.
        put32(&mut pack, table + (count - 1) * stride, callback);
    }
    for &(begin, end, unwind) in decoder::RUNTIME_FUNCTIONS {
        runtime.push((stub_rva + begin, stub_rva + end, stub_rva + unwind));
    }
    runtime.sort_unstable_by_key(|entry| entry.0);
    ensure!(
        !runtime.windows(2).any(|w| w[0].1 > w[1].0),
        "overlapping decoder runtime entries"
    );
    for (index, &(begin, end, unwind)) in runtime.iter().enumerate() {
        for (field, value) in [begin, end, unwind].into_iter().enumerate() {
            put32(&mut pack, runtime_at + index * 12 + field * 4, value);
        }
    }

    let mut stub = DECODER.to_vec();
    let config = decoder::CONFIG_OFFSET;
    for (index, value) in [
        target.virtual_address,
        target.raw_size,
        rva(compressed_at)?,
        u32::try_from(compressed.len())?,
        rva(iat)?,
        rva(iat + 8)?,
        rva(iat + 16)?,
        rva(iat + 24)?,
        rva(deferred_at)?,
        u32::try_from(deferred.len())?,
    ]
    .into_iter()
    .enumerate()
    {
        put32(&mut stub, config + 8 + index * 4, value);
    }
    put64(&mut stub, config + 48, pe.layout().image_base);

    let (output, first_shift) = append_section(pe, pack_rva, ".sbpack", 0xc0000040, &pack, 0)?;
    let first = PeFile::parse_with_symbols(output, pe.layout().handler_symbols.clone())?;
    let (mut output, second_shift) =
        append_section(&first, stub_rva, ".sbinit", 0x60000020, &stub, 0)?;
    let removed_at = second_shift.map(first_shift.map(target.raw_ptr as usize)?)?;
    let pack_at = second_shift.map(offset(&first, pack_rva)?)?;
    output[pack_at..pack_at + 8].copy_from_slice(MAGIC);
    write_shift(&mut output, pack_at + 52, &first_shift);
    write_shift(&mut output, pack_at + 84, &second_shift);
    put64(&mut output, pack_at + 44, removed_at as u64);
    for (index, start, len) in [
        (1, rva(imports_at)?, imports.len()),
        (3, rva(runtime_at)?, runtime_size),
        (5, rva(reloc_at)?, reloc_size),
        (9, rva(tls_at)?, 40),
    ] {
        put32(&mut output, opt + 112 + index * 8, start);
        put32(&mut output, opt + 116 + index * 8, u32::try_from(len)?);
    }
    let directory_count = u32_at(&output, opt + 108)?.max(10);
    put32(&mut output, opt + 108, directory_count);
    if let (Some(guard), Some((pointer, _))) = (guard_at, pe.layout().eh_continuation_fields) {
        let field = second_shift.map(first_shift.map(pointer)?)?;
        put64(&mut output, field, pe.layout().va(rva(guard)?));
    }
    if let (Some((original, flags)), Some((table, _, count))) = (cfg, cfg_table) {
        let at = second_shift.map(first_shift.map(original)?)?;
        put64(&mut output, at + 128, pe.layout().va(rva(table)?));
        put64(&mut output, at + 136, count as u64);
        put32(&mut output, at + 144, flags | 0x400);
    }

    // Removing the raw .sbrk bytes leaves its virtual destination zero-filled.
    // Relocate every documented raw-file pointer across that removal.
    let table = opt + usize::from(optional_size);
    let section_count = u16::from_le_bytes(bytes(&output, opt - 18, 2)?.try_into()?) as usize;
    let mut raw_fields = vec![opt - 12];
    if directory_count > 4 {
        raw_fields.push(opt + 112 + 4 * 8);
    }
    for index in 0..section_count {
        let at = table + index * 40;
        if u32_at(&output, at + 12)? == target.virtual_address {
            put32(
                &mut output,
                at + 8,
                target.virtual_size.max(target.raw_size),
            );
            put32(&mut output, at + 16, 0);
            put32(&mut output, at + 20, 0);
        } else {
            raw_fields.push(at + 20);
        }
        raw_fields.extend([at + 24, at + 28]);
    }
    for original_field in debug_fields {
        raw_fields.push(second_shift.map(first_shift.map(original_field)?)?);
    }
    for field in raw_fields {
        let value = u32_at(&output, field)? as usize;
        if value >= removed_at + raw_size {
            put32(&mut output, field, u32::try_from(value - raw_size)?);
        } else {
            ensure!(
                value == 0 || value < removed_at,
                "file pointer targets removed .sbrk storage"
            );
        }
    }
    let code_size = u32_at(&output, opt + 4)?
        .checked_sub(target.raw_size)
        .context("SizeOfCode underflow")?;
    put32(&mut output, opt + 4, code_size);
    output.drain(removed_at..removed_at + raw_size);
    if output.len() >= pe.data.len() {
        return Ok(None);
    }
    crate::pe::update_checksum_at(&mut output, opt + 64);
    ensure!(
        unpack(&output)?.as_deref() == Some(pe.data.as_slice()),
        "compressed PE failed exact recovery"
    );
    Ok(Some(Compressed {
        data: output,
        section: target.name().to_owned(),
        original_size: raw_size,
        packed_size: compressed.len(),
    }))
}
