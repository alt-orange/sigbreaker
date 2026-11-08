//! Rebuild .text with generated code; preserve the original section set.
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
}
impl SectionPlan {
    pub fn new(pe: &PeFile) -> Result<Self> {
        let opt = u32_at(&pe.data, 0x3C)? as usize + 24;
        let text = pe
            .layout()
            .sections
            .iter()
            .find(|s| s.name() == ".text" && s.is_executable())
            .context("output rebuild requires .text")?;
        Ok(Self {
            rva: text
                .virtual_address
                .checked_add(text.raw_size)
                .context(".text append RVA overflow")?,
            opt,
        })
    }
    /// Rebuild the existing .text section, moving later raw data and rebasing
    /// supported address-bearing PE structures. Function sizes are unrestricted.
    pub fn commit(
        self,
        pe: &mut PeFile,
        mut code: Vec<u8>,
        entries: &[(u32, u32, u32)],
        patches: &[(usize, Vec<u8>)],
        generated_unwind: &std::collections::BTreeSet<u32>,
    ) -> Result<()> {
        let text = *pe
            .layout()
            .sections
            .iter()
            .find(|s| s.name() == ".text")
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
                if generated_unwind.contains(&unwind) {
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
                    .filter(|e| !generated_unwind.contains(&e.2))
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
                .runtime_functions
                .iter()
                .find(|f| f.start == start)
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
        let rebuilt = PeFile::parse(output)?;
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
}
