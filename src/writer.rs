//! Append-only PE section writer. Existing section offsets and overlays stay fixed.
use crate::pe::{PeFile, SectionHeader};
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
    raw: u32,
    header: usize,
    opt: usize,
    coff: usize,
    section_alignment: u32,
    file_alignment: u32,
    extend: Option<SectionHeader>,
    name: [u8; 8],
}

impl SectionPlan {
    pub fn new(pe: &PeFile) -> Result<Self> {
        let coff = u32_at(&pe.data, 0x3C)? as usize + 4;
        let opt = coff + 20;
        let optional_size = u16::from_le_bytes(pe.data[coff + 16..coff + 18].try_into()?) as usize;
        let count = pe.layout().sections.len();
        if count >= 96 {
            bail!("PE section-count limit reached");
        }
        let header = opt + optional_size + count * 40;
        let first_raw = pe
            .layout()
            .sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .map(|s| s.raw_ptr as usize)
            .min()
            .context("no file-backed sections")?;
        let header_limit = (u32_at(&pe.data, opt + 60)? as usize)
            .min(first_raw)
            .min(pe.data.len());
        let spare_header =
            header + 40 <= header_limit && pe.data[header..header + 40].iter().all(|&b| b == 0);
        if optional_size < 144 || u32_at(&pe.data, opt + 108)? < 4 {
            bail!("missing exception data-directory slot");
        }
        let section_alignment = u32_at(&pe.data, opt + 32)?;
        let file_alignment = u32_at(&pe.data, opt + 36)?;
        align(0, file_alignment)?;
        let end = pe
            .layout()
            .sections
            .iter()
            .try_fold(pe.layout().size_of_image, |end, s| {
                Ok::<_, anyhow::Error>(
                    end.max(
                        s.virtual_address
                            .checked_add(s.virtual_size.max(s.raw_size))
                            .context("section overflow")?,
                    ),
                )
            })?;
        let rva = align(end, section_alignment)?;
        let mut name = *b".sbrk\0\0\0";
        for index in 0..96 {
            let candidate = if index == 0 {
                ".sbrk".to_owned()
            } else {
                format!(".sbrk{index}")
            };
            if !pe.layout().sections.iter().any(|s| s.name() == candidate) {
                name.fill(0);
                name[..candidate.len()].copy_from_slice(candidate.as_bytes());
                break;
            }
        }
        let (header, raw, extend) = if spare_header {
            (
                header,
                align(u32::try_from(pe.data.len())?, file_alignment)?,
                None,
            )
        } else {
            // Extending the final mapped/file-backed section needs no new
            // header or shifted raw offsets. Refuse overlays and virtual-only
            // tails, whose bytes could acquire different mapped contents.
            let (index, last) = pe
                .layout()
                .sections
                .iter()
                .enumerate()
                .max_by_key(|(_, s)| s.virtual_address)
                .context("no sections")?;
            if last.raw_size < last.virtual_size
                || last.raw_size == 0
                || last.raw_ptr as u64 + last.raw_size as u64 != pe.data.len() as u64
                || last.characteristics & 0x80 != 0
            {
                bail!("no section-header room and final section cannot safely grow");
            }
            let raw = last
                .raw_ptr
                .checked_add(
                    rva.checked_sub(last.virtual_address)
                        .context("section RVA order")?,
                )
                .context("extended raw overflow")?;
            if raw % file_alignment != 0 {
                bail!("extended section raw alignment mismatch");
            }
            (opt + optional_size + index * 40, raw, Some(*last))
        };
        Ok(Self {
            rva,
            raw,
            header,
            opt,
            coff,
            section_alignment,
            file_alignment,
            extend,
            name,
        })
    }

    /// Build privately, validate by reparsing, then commit the complete image.
    /// `entries` contains only new runtime functions; old entries remain valid.
    pub fn commit(
        self,
        pe: &mut PeFile,
        mut code: Vec<u8>,
        entries: &[(u32, u32, u32)],
        patches: &[(usize, Vec<u8>)],
    ) -> Result<()> {
        let code_size = u32::try_from(code.len())?;
        code.resize(align(code_size, 4)? as usize, 0);
        let table_offset = u32::try_from(code.len())?;
        let mut table = Vec::new();
        for f in &pe.layout().runtime_functions {
            let info = pe
                .layout()
                .unwind_info(f.start)
                .context("missing unwind info")?;
            table.push((f.start, f.end, info.rva));
        }
        table.extend_from_slice(entries);
        table.sort_unstable_by_key(|r| r.0);
        if table.windows(2).any(|w| w[0].1 > w[1].0) {
            bail!("overlapping generated runtime functions");
        }
        for &(begin, end, unwind) in &table {
            code.extend_from_slice(&begin.to_le_bytes());
            code.extend_from_slice(&end.to_le_bytes());
            code.extend_from_slice(&unwind.to_le_bytes());
        }
        let virtual_size = u32::try_from(code.len())?;
        let raw_size = align(virtual_size, self.file_alignment)?;
        let image_size = align(
            self.rva
                .checked_add(virtual_size)
                .context("image overflow")?,
            self.section_alignment,
        )?;
        let mut output = pe.data.clone();
        output.resize(
            self.raw.checked_add(raw_size).context("file overflow")? as usize,
            0,
        );
        output[self.raw as usize..self.raw as usize + code.len()].copy_from_slice(&code);
        for (off, bytes) in patches {
            if off
                .checked_add(bytes.len())
                .is_none_or(|end| end > pe.data.len())
            {
                bail!("patch outside original image");
            }
            output[*off..*off + bytes.len()].copy_from_slice(bytes);
        }
        if let Some(last) = self.extend {
            let delta = self.rva - last.virtual_address;
            put(
                &mut output,
                self.header + 8,
                delta
                    .checked_add(virtual_size)
                    .context("extended virtual size overflow")?,
            );
            put(
                &mut output,
                self.header + 16,
                delta
                    .checked_add(raw_size)
                    .context("extended raw size overflow")?,
            );
            // Keep existing permissions, add executable/read/code, and retain
            // unwind metadata by clearing DISCARDABLE for the enlarged section.
            put(
                &mut output,
                self.header + 36,
                (last.characteristics | 0x6000_0020) & !0x0200_0000,
            );
        } else {
            output[self.header..self.header + 8].copy_from_slice(&self.name);
            put(&mut output, self.header + 8, virtual_size);
            put(&mut output, self.header + 12, self.rva);
            put(&mut output, self.header + 16, raw_size);
            put(&mut output, self.header + 20, self.raw);
            put(&mut output, self.header + 36, 0x6000_0020);
            output[self.coff + 2..self.coff + 4]
                .copy_from_slice(&((pe.layout().sections.len() + 1) as u16).to_le_bytes());
        }
        put(&mut output, self.opt + 56, image_size);
        put(
            &mut output,
            self.opt + 4,
            u32_at(&pe.data, self.opt + 4)?
                .checked_add(raw_size)
                .context("code size overflow")?,
        );
        put(
            &mut output,
            self.opt + 112 + 3 * 8,
            self.rva
                .checked_add(table_offset)
                .context("table overflow")?,
        );
        put(
            &mut output,
            self.opt + 112 + 3 * 8 + 4,
            u32::try_from(table.len() * 12)?,
        );
        *pe = PeFile::parse(output)?;
        Ok(())
    }
}
