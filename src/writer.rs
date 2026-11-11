//! Write generated code by growing .text or appending an executable section.
use crate::pe::PeFile;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Publish a complete output on the destination filesystem. Failures leave an
/// existing destination intact; temporary files are removed on all error paths.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..100 {
        let temp = parent.join(format!(
            ".sigbraker-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp);
        let mut file = match file {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        return result;
    }
    bail!("unable to create unique output temporary file")
}
use anyhow::{bail, Context, Result};

pub fn align(value: u32, alignment: u32) -> Result<u32> {
    if !alignment.is_power_of_two() {
        bail!("invalid PE alignment");
    }
    Ok(value
        .checked_add(alignment - 1)
        .context("alignment overflow")?
        & !(alignment - 1))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .context("truncated PE field")?
            .try_into()?,
    ))
}
fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub struct SectionPlan {
    pub rva: u32,
    opt: usize,
    append_section: bool,
}

pub(crate) fn next_section_rva(pe: &PeFile) -> Result<u32> {
    let opt = u32_at(&pe.data, 0x3C)? as usize + 24;
    let end = pe.layout().sections.iter().try_fold(0u32, |end, s| {
        Ok::<_, anyhow::Error>(
            end.max(
                s.virtual_address
                    .checked_add(s.virtual_size.max(s.raw_size))
                    .context("section RVA overflow")?,
            ),
        )
    })?;
    align(end, u32_at(&pe.data, opt + 32)?)
}

impl SectionPlan {
    pub fn retains_original_bodies(&self) -> bool {
        self.append_section
    }
    /// Plan a new executable section while preserving existing virtual addresses.
    pub fn new(pe: &PeFile) -> Result<Self> {
        Self::new_with_address_rewrites(pe, true)
    }
    pub fn new_with_address_rewrites(pe: &PeFile, force_append: bool) -> Result<Self> {
        let opt = u32_at(&pe.data, 0x3C)? as usize + 24;
        // Opaque language metadata cannot be rebased when .text pushes data
        // sections to new RVAs. Append a section instead, preserving every
        // existing RVA and retaining bodies whose reference closure is unknown.
        let text = pe.layout().executable_sections().find(|s| s.name() == ".text");
        let append_section = pe.layout().runtime_functions.iter().any(|f| {
            pe.layout().unwind_info(f.start).is_some_and(|info| {
                matches!(info.kind, crate::pe::UnwindKind::Unsupported { .. })
                    || (matches!(info.kind, crate::pe::UnwindKind::Handler { .. })
                        && !pe.layout().c_specific.contains_key(&f.start))
            })
        }) || pe.layout().executable_sections().count() != 1
            || !pe.layout().handler_symbols.is_empty()
            || force_append;
        match text.filter(|_| !append_section) {
            Some(text) => Ok(Self {
                rva: text.virtual_address
                    .checked_add(text.raw_size)
                    .context(".text append RVA overflow")?,
                opt,
                append_section: false,
            }),
            None => Ok(Self {
                rva: next_section_rva(pe)?,
                opt,
                append_section: true,
            }),
        }
    }
    /// Publish generated code using the planned section layout.
    pub fn commit(
        self,
        pe: &mut PeFile,
        code: Vec<u8>,
        entries: &[(u32, u32, u32)],
        patches: &[(usize, Vec<u8>)],
        generated_unwind: &std::collections::BTreeMap<u32, u32>,
    ) -> Result<()> {
        self.commit_with_metadata(pe, code, entries, patches, generated_unwind, &[], &[])
    }
    pub fn commit_with_metadata(
        self,
        pe: &mut PeFile,
        mut code: Vec<u8>,
        entries: &[(u32, u32, u32)],
        patches: &[(usize, Vec<u8>)],
        generated_unwind: &std::collections::BTreeMap<u32, u32>,
        metadata_patches: &[(usize, Vec<u8>)],
        wipes: &[(usize, usize)],
    ) -> Result<()> {
        if self.append_section {
            return self.commit_section(pe, code, entries, patches, metadata_patches, wipes);
        }
        let text = *pe
            .layout()
            .sections
            .iter()
            .find(|s| s.name() == ".text" && s.is_executable())
            .context("missing .text")?;
        let replaced: std::collections::BTreeSet<_> = patches
            .iter()
            .map(|(off, _)| text.virtual_address + (*off - text.raw_ptr as usize) as u32)
            .collect();
        let mut trampolines = Vec::new();
        let mut chain_fixups = Vec::new();
        for f in pe
            .layout()
            .runtime_functions
            .iter()
            .filter(|f| replaced.contains(&f.start))
        {
            let info = pe.layout().unwind_info(f.start).unwrap();
            if let crate::pe::UnwindKind::Chained {
                begin,
                end,
                unwind_rva,
            } = info.kind
            {
                code.resize(align(u32::try_from(code.len())?, 4)? as usize, 0);
                let offset = code.len();
                let source = pe.layout().rva_to_offset(info.rva).unwrap();
                code.extend_from_slice(&[0x21, 0, 0, pe.data[source + 3]]);
                for value in [begin, end, unwind_rva] {
                    code.extend_from_slice(&value.to_le_bytes());
                }
                trampolines.push((f.start, f.start + 5, self.rva + u32::try_from(offset)?));
                chain_fixups.push((offset + 12, unwind_rva));
            }
        }
        code.resize(align(u32::try_from(code.len())?, 4)? as usize, 0);
        let table_offset = code.len();
        let table_count = pe.layout().runtime_functions.len() - replaced.len()
            + entries.len()
            + trampolines.len();
        let payload_size = table_offset
            .checked_add(
                table_count
                    .checked_mul(12)
                    .context("runtime table overflow")?,
            )
            .context("payload overflow")?;
        let mut layout = crate::rebuild::Layout::new(pe, payload_size)?;
        layout.structures()?;
        let mut table = Vec::new();
        for f in pe
            .layout()
            .runtime_functions
            .iter()
            .filter(|f| !replaced.contains(&f.start))
        {
            let info = pe
                .layout()
                .unwind_info(f.start)
                .context("missing unwind info")?;
            table.push((f.start, f.end, layout.rva(info.rva)?));
        }
        for &(begin, end, unwind) in entries {
            table.push((
                begin,
                end,
                // A generated unwind RVA can numerically equal a reused old
                // data-section unwind RVA (the grown .text starts where .rdata
                // once lived), so provenance is keyed by the owning entry,
                // not by the RVA value alone.
                if generated_unwind.get(&begin).copied() == Some(unwind) {
                    unwind
                } else {
                    layout.rva(unwind)?
                },
            ));
        }
        table.extend(trampolines);
        for (offset, rva) in chain_fixups {
            code[offset..offset + 4].copy_from_slice(&layout.rva(rva)?.to_le_bytes());
        }
        table.sort_unstable_by_key(|r| r.0);
        if table.windows(2).any(|w| w[0].1 > w[1].0) {
            bail!("overlapping rebuilt runtime functions");
        }
        for (begin, end, unwind) in table {
            for value in [begin, end, unwind] {
                code.extend_from_slice(&value.to_le_bytes());
            }
        }
        let text = pe.layout().sections[layout.text_index];
        let insert = layout.text_end_raw;
        let mut output = Vec::with_capacity(pe.data.len() + layout.raw_growth as usize);
        output.extend_from_slice(&pe.data[..insert]);
        output.resize(insert + layout.raw_growth as usize, 0);
        output.extend_from_slice(&pe.data[insert..]);
        layout.code(&mut output)?;
        let source = code.clone();
        // Only instruction bytes are patched here. Generated branch/scope RVAs
        // already refer to their final .text addresses and must not be treated
        // as old data RVAs merely because their numeric ranges overlap.
        for &(begin, end, _) in entries {
            let mut at = (begin - self.rva) as usize;
            let limit = (end - self.rva) as usize;
            while at < limit {
                let ins = iced_x86::Decoder::with_ip(
                    64,
                    &source[at..limit],
                    pe.layout().va(self.rva + at as u32),
                    iced_x86::DecoderOptions::NONE,
                )
                .decode();
                if ins.is_invalid() {
                    bail!("invalid generated instruction in rebuilt .text");
                }
                layout.patch_instruction(&source[at..at + ins.len()], ins.ip(), &mut code, at)?;
                at += ins.len();
            }
        }
        output[insert..insert + code.len()].copy_from_slice(&code);
        layout.apply(&mut output)?;
        for (at, bytes) in metadata_patches {
            let dest = layout.raw(*at)?;
            output
                .get_mut(dest..dest + bytes.len())
                .context("metadata patch outside file")?
                .copy_from_slice(bytes);
        }
        let original_table_rva = u32_at(&pe.data, self.opt + 112 + 3 * 8)?;
        let original_table_size = u32_at(&pe.data, self.opt + 116 + 3 * 8)? as usize;
        let original_table = pe
            .layout()
            .rva_to_offset(original_table_rva)
            .context("original runtime table")?;
        let retired_table = layout.raw(original_table)?;
        output[retired_table..retired_table + original_table_size].fill(0);
        let active_unwind: std::collections::BTreeSet<_> = pe
            .layout()
            .runtime_functions
            .iter()
            .filter(|f| !replaced.contains(&f.start))
            .map(|f| pe.layout().unwind_info(f.start).unwrap().rva)
            .chain(
                entries
                    .iter()
                    .filter(|e| generated_unwind.get(&e.0).copied() != Some(e.2))
                    .map(|e| e.2),
            )
            .collect();
        for f in pe
            .layout()
            .runtime_functions
            .iter()
            .filter(|f| replaced.contains(&f.start))
        {
            let info = pe.layout().unwind_info(f.start).unwrap();
            if !active_unwind.contains(&info.rva) {
                if let Some(scope) = pe.layout().c_specific.get(&f.start) {
                    let from = layout.raw(pe.layout().rva_to_offset(info.rva).unwrap())?;
                    let to = layout.raw(scope.table_bytes.end - 1)? + 1;
                    output[from..to].fill(0);
                }
            }
        }
        for (off, bytes) in patches {
            let start = text.virtual_address + (*off - text.raw_ptr as usize) as u32;
            let extent = pe
                .layout()
                .runtime_function_at(start)
                .context("entry patch has no function extent")?;
            let end = *off + (extent.end - extent.start) as usize;
            if *off < text.raw_ptr as usize || end > insert || bytes.len() != 5 {
                bail!("entry rewrite outside original .text");
            }
            output[*off..end].fill(0xCC);
            output[*off..*off + bytes.len()].copy_from_slice(bytes);
        }
        put(
            &mut output,
            self.opt + 112 + 3 * 8,
            self.rva
                .checked_add(u32::try_from(table_offset)?)
                .context("runtime table RVA overflow")?,
        );
        put(
            &mut output,
            self.opt + 116 + 3 * 8,
            u32::try_from(table_count * 12)?,
        );
        let rebuilt = PeFile::parse_with_symbols(output, pe.layout().handler_symbols.clone())?;
        if rebuilt.layout().sections.len() != pe.layout().sections.len()
            || rebuilt
                .layout()
                .sections
                .iter()
                .zip(&pe.layout().sections)
                .any(|(a, b)| a.name != b.name)
        {
            bail!(".text rebuild changed the original section set");
        }
        *pe = rebuilt;
        Ok(())
    }

    /// Preserve all existing virtual addresses, including unclassified language
    /// data. Only documented raw-file offsets change when headers/overlay move.
    fn commit_section(
        self,
        pe: &mut PeFile,
        mut code: Vec<u8>,
        entries: &[(u32, u32, u32)],
        patches: &[(usize, Vec<u8>)],
        metadata_patches: &[(usize, Vec<u8>)],
        wipes: &[(usize, usize)],
    ) -> Result<()> {
        code.resize(align(u32::try_from(code.len())?, 4)? as usize, 0);
        let table_offset = code.len();
        let mut runtime = pe
            .layout()
            .runtime_functions
            .iter()
            .map(|f| {
                (
                    f.start,
                    f.end,
                    pe.layout().unwind_info(f.start).unwrap().rva,
                )
            })
            .chain(entries.iter().copied())
            .collect::<Vec<_>>();
        runtime.sort_unstable_by_key(|r| r.0);
        if runtime.windows(2).any(|w| w[0].1 > w[1].0) {
            bail!("overlapping appended runtime entries");
        }
        for &(begin, end, unwind) in &runtime {
            for value in [begin, end, unwind] {
                code.extend_from_slice(&value.to_le_bytes());
            }
        }
        let (mut output, shift) = append_section(pe, self.rva, ".sbrk", 0x6000_0020, &code, 0)?;
        put(
            &mut output,
            self.opt + 112 + 3 * 8,
            self.rva
                .checked_add(u32::try_from(table_offset)?)
                .context("runtime table overflow")?,
        );
        put(
            &mut output,
            self.opt + 116 + 3 * 8,
            u32::try_from(code.len() - table_offset)?,
        );
        for (off, bytes) in patches.iter().chain(metadata_patches) {
            let dest = shift.map(*off)?;
            output
                .get_mut(dest..dest + bytes.len())
                .context("entry patch outside file")?
                .copy_from_slice(bytes);
        }
        // Wipe spans exclude the entry jumps and any jump-table bytes.
        for (off, len) in wipes {
            let dest = shift.map(*off)?;
            output
                .get_mut(dest..dest + *len)
                .context("original body wipe outside file")?
                .fill(0xCC);
        }
        *pe = PeFile::parse_with_symbols(output, pe.layout().handler_symbols.clone())?;
        Ok(())
    }
}

pub(crate) struct RawShift {
    pub(crate) slot: usize,
    pub(crate) header_growth: usize,
    pub(crate) insert: usize,
    pub(crate) insertion_size: usize,
}

impl RawShift {
    pub(crate) fn map(&self, old: usize) -> Result<usize> {
        old.checked_add(if old >= self.slot {
            self.header_growth
        } else {
            0
        })
        .and_then(|v| {
            v.checked_add(if old >= self.insert {
                self.insertion_size
            } else {
                0
            })
        })
        .context("raw offset overflow")
    }
}

/// Append initialized bytes and an optional zero-filled virtual tail.
pub(crate) fn append_section(
    pe: &PeFile,
    rva: u32,
    prefix: &str,
    characteristics: u32,
    payload: &[u8],
    zero_fill: u32,
) -> Result<(Vec<u8>, RawShift)> {
    let opt = u32_at(&pe.data, 0x3C)? as usize + 24;
    let count = pe.layout().sections.len();
    if count >= 96 {
        bail!("appending would exceed the Windows PE section limit");
    }
    let new_count = (count + 1) as u16;
    let table = opt + u16::from_le_bytes(pe.data[opt - 4..opt - 2].try_into()?) as usize;
    let slot = table
        .checked_add(count.checked_mul(40).context("section table overflow")?)
        .context("section table overflow")?;
    let file_align = u32_at(&pe.data, opt + 36)?;
    let section_align = u32_at(&pe.data, opt + 32)?;
    if section_align < 4096 || file_align > section_align {
        bail!("unsupported low-alignment appended section");
    }
    let old_headers = u32_at(&pe.data, opt + 60)? as usize;
    let first_raw = pe
        .layout()
        .sections
        .iter()
        .filter(|s| s.raw_size != 0)
        .map(|s| s.raw_ptr as usize)
        .min()
        .context("no file-backed sections")?;
    let free_slot = slot + 40 <= old_headers.min(first_raw)
        && pe
            .data
            .get(slot..slot + 40)
            .is_some_and(|b| b.iter().all(|&v| v == 0));
    let header_growth = if free_slot {
        0
    } else {
        align(40, file_align)? as usize
    };
    if old_headers > first_raw || slot > old_headers {
        bail!("section table exceeds file-backed PE headers");
    }
    let new_headers = u32::try_from(old_headers + header_growth)?;
    if pe
        .layout()
        .sections
        .iter()
        .any(|s| s.virtual_address < new_headers)
    {
        bail!("expanded PE headers overlap a section RVA");
    }
    let insert = pe
        .layout()
        .sections
        .iter()
        .filter(|s| s.raw_size != 0)
        .try_fold(old_headers, |end, s| {
            Ok::<_, anyhow::Error>(
                end.max(
                    (s.raw_ptr as usize)
                        .checked_add(s.raw_size as usize)
                        .context("raw section overflow")?,
                ),
            )
        })?;
    let raw = align(
        u32::try_from(
            insert
                .checked_add(header_growth)
                .context("raw offset overflow")?,
        )?,
        file_align,
    )? as usize;
    let initialized_size = u32::try_from(payload.len())?;
    let virtual_size = initialized_size
        .checked_add(zero_fill)
        .context("appended virtual size overflow")?;
    let raw_size = align(initialized_size, file_align)? as usize;
    let insertion_size = raw
        .checked_sub(insert + header_growth)
        .context("append alignment underflow")?
        .checked_add(raw_size)
        .context("append size overflow")?;
    let shift = RawShift {
        slot,
        header_growth,
        insert,
        insertion_size,
    };
    let mut output = Vec::new();
    output.extend_from_slice(&pe.data[..slot]);
    output.resize(slot + header_growth, 0);
    output.extend_from_slice(&pe.data[slot..insert]);
    output.resize(raw, 0);
    output.extend_from_slice(payload);
    output.resize(raw + raw_size, 0);
    output.extend_from_slice(&pe.data[insert..]);
    let raw_field = |output: &mut [u8], field: usize| -> Result<()> {
        let old = u32_at(&pe.data, field)?;
        if old != 0 {
            put(
                output,
                shift.map(field)?,
                u32::try_from(shift.map(old as usize)?)?,
            );
        }
        Ok(())
    };
    raw_field(&mut output, opt - 12)?;
    for i in 0..count {
        for off in [20, 24, 28] {
            raw_field(&mut output, table + i * 40 + off)?;
        }
    }
    let dirs = u32_at(&pe.data, opt + 108)? as usize;
    if dirs > 4 {
        raw_field(&mut output, opt + 112 + 4 * 8)?;
    }
    if dirs > 6 {
        let debug_rva = u32_at(&pe.data, opt + 112 + 6 * 8)?;
        let debug_size = u32_at(&pe.data, opt + 116 + 6 * 8)? as usize;
        if debug_rva != 0 {
            if !debug_size.is_multiple_of(28) {
                bail!("malformed debug directory");
            }
            let debug = pe
                .layout()
                .rva_to_offset(debug_rva)
                .context("unmapped debug directory")?;
            for off in (0..debug_size).step_by(28) {
                raw_field(&mut output, debug + off + 24)?;
            }
        }
    }
    let mut name = [0u8; 8];
    let suffix = (0..)
        .map(|i| {
            if i == 0 {
                prefix.to_owned()
            } else {
                format!("{prefix}{i}")
            }
        })
        .find(|n| !pe.layout().sections.iter().any(|s| s.name() == n))
        .unwrap();
    if suffix.len() > 8 {
        bail!("no available section name");
    }
    name[..suffix.len()].copy_from_slice(suffix.as_bytes());
    output[slot..slot + 40].fill(0);
    output[slot..slot + 8].copy_from_slice(&name);
    for (off, value) in [
        (8, virtual_size),
        (12, rva),
        (16, u32::try_from(raw_size)?),
        (20, u32::try_from(raw)?),
        (36, characteristics),
    ] {
        put(&mut output, slot + off, value);
    }
    output[opt - 18..opt - 16].copy_from_slice(&new_count.to_le_bytes());
    put(&mut output, opt + 60, new_headers);
    put(
        &mut output,
        opt + 56,
        align(
            rva.checked_add(virtual_size.max(u32::try_from(raw_size)?))
                .context("image size overflow")?,
            section_align,
        )?,
    );
    let size_field = if characteristics & 0x20 != 0 {
        opt + 4
    } else {
        opt + 8
    };
    put(
        &mut output,
        size_field,
        u32_at(&pe.data, size_field)?
            .checked_add(u32::try_from(raw_size)?)
            .context("section size total overflow")?,
    );
    Ok((output, shift))
}
