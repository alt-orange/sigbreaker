//! Minimal 64-bit PE reader.
//!
//! Parses sections, exports, runtime-function metadata and base relocations.
//! Expanded layouts are committed separately by `writer` and reparsed here.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{bail, Context, Result};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const MACHINE_AMD64: u16 = 0x8664;
const OPTION_MAGIC_PE32PLUS: u16 = 0x020B;

/// A parsed section-header table entry.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Section name with trailing NUL bytes trimmed.
    pub fn name(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        std::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0
    }

    /// Whether `rva` falls inside the section's virtual range.
    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(size)
    }
}

/// Pure PE metadata (everything except the file bytes themselves).
///
/// The split exists so transformation passes can hold an immutable borrow of
/// the layout and a mutable borrow of the file data at the same time.
#[derive(Debug, Clone)]
pub struct PeLayout {
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub sections: Vec<SectionHeader>,
    /// Authoritative code extents from the PE exception directory.
    pub runtime_functions: Vec<Range<u32>>,
    pub code_roots: BTreeSet<u32>,
    /// Code ranges whose original unwind addresses are referenced by chains.
    pub metadata_pinned: Vec<Range<u32>>,
    pub c_specific: BTreeMap<u32, crate::exception::CSpecific>,
    pub guarded_eh_continuations: bool,
    pub import_slots: BTreeSet<u32>,
    unwind: BTreeMap<u32, UnwindInfo>,
    /// File-offset ranges the loader patches via `.reloc`; never touch these.
    protected: Vec<Range<usize>>,
    checksum_off: usize,
}

/// Information needed to preserve the Windows unwind contract in place.
#[derive(Debug, Clone)]
pub struct UnwindInfo {
    pub rva: u32,
    pub prologue_end: u32,
    /// Only plain version-1 functions are supported by the register scheduler.
    /// Handler-bearing, chained, and newer formats remain pinned.
    pub permits_register_reordering: bool,
    pub kind: UnwindKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindKind {
    Plain,
    Handler {
        flags: u8,
        handler_rva: u32,
        data_rva: u32,
    },
    Chained {
        begin: u32,
        end: u32,
        unwind_rva: u32,
    },
    Unsupported {
        version: u8,
        flags: u8,
    },
}

impl PeLayout {
    pub fn unwind_info(&self, function_start: u32) -> Option<&UnwindInfo> {
        self.unwind.get(&function_start)
    }
    /// Virtual address of an RVA.
    pub fn va(&self, rva: u32) -> u64 {
        self.image_base.wrapping_add(rva as u64)
    }

    /// Converts an RVA to a file offset, if the section's raw data covers it.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let sec = self.sections.iter().find(|s| s.contains_rva(rva))?;
        let delta = rva.checked_sub(sec.virtual_address)?;
        if delta >= sec.raw_size {
            return None;
        }
        Some(sec.raw_ptr as usize + delta as usize)
    }

    /// Raw byte range of a section, clamped to the file length.
    pub fn section_raw_range(&self, sec: &SectionHeader, file_len: usize) -> Range<usize> {
        let start = (sec.raw_ptr as usize).min(file_len);
        let end = start.saturating_add(sec.raw_size as usize).min(file_len);
        start..end
    }

    /// Executable, file-backed sections (the ones BLARE lifts).
    pub fn executable_sections(&self) -> impl Iterator<Item = &SectionHeader> + '_ {
        self.sections.iter().filter(|s| s.is_executable())
    }

    /// Whether a byte range overlaps any base-relocation fixup.
    pub fn is_protected(&self, range: Range<usize>) -> bool {
        self.protected
            .iter()
            .any(|p| p.start < range.end && range.start < p.end)
    }

    /// Number of relocation fixups discovered.
    pub fn relocation_count(&self) -> usize {
        self.protected.len()
    }

    /// Conservative address-taken references carried by absolute base fixups.
    pub fn relocated_code_references(&self, data: &[u8]) -> BTreeSet<u32> {
        self.protected
            .iter()
            .filter_map(|r| {
                let bytes: [u8; 8] = data.get(r.start..r.start + 8)?.try_into().ok()?;
                let rva = u64::from_le_bytes(bytes).checked_sub(self.image_base)?;
                let rva = u32::try_from(rva).ok()?;
                self.executable_sections()
                    .any(|s| s.contains_rva(rva))
                    .then_some(rva)
            })
            .collect()
    }

    /// Conservative RVA and VA pointer-table analysis. Values are candidates,
    /// not proof of an executable edge; false positives only restrict movement.
    pub fn data_code_references(&self, data: &[u8]) -> BTreeSet<u32> {
        let mut targets = BTreeSet::new();
        for section in self
            .sections
            .iter()
            .filter(|s| !s.is_executable() && s.characteristics & 0x8000_0000 == 0)
        {
            let range = self.section_raw_range(section, data.len());
            for at in (range.start..range.end).step_by(4) {
                if self
                    .c_specific
                    .values()
                    .any(|info| info.table_bytes.contains(&at))
                {
                    continue;
                }
                if let Some(bytes) = data.get(at..at + 4).filter(|_| at + 4 <= range.end) {
                    let rva = u32::from_le_bytes(bytes.try_into().unwrap());
                    if self.executable_sections().any(|s| s.contains_rva(rva)) {
                        targets.insert(rva);
                    }
                }
                if let Some(bytes) = data.get(at..at + 8).filter(|_| at + 8 <= range.end) {
                    if let Some(rva) = u64::from_le_bytes(bytes.try_into().unwrap())
                        .checked_sub(self.image_base)
                        .and_then(|v| u32::try_from(v).ok())
                    {
                        if self.executable_sections().any(|s| s.contains_rva(rva)) {
                            targets.insert(rva);
                        }
                    }
                }
            }
        }
        targets
    }
}

/// A parsed 64-bit PE file, ready for in-place transformation.
#[derive(Debug)]
pub struct PeFile {
    pub data: Vec<u8>,
    layout: PeLayout,
}

impl PeFile {
    /// Parses headers and validates this is a 64-bit x86 PE image.
    pub fn parse(data: Vec<u8>) -> Result<PeFile> {
        let len = data.len();
        if len < 0x40 {
            bail!("file too small to be a PE image ({len} bytes)");
        }
        if u16_le(&data, 0)? != 0x5A4D {
            bail!("missing MZ signature");
        }
        let pe_off = u32_le(&data, 0x3C)? as usize;
        if pe_off + 24 > len || &data[pe_off..pe_off + 4] != b"PE\0\0" {
            bail!("missing PE signature");
        }

        let coff = pe_off + 4;
        if u16_le(&data, coff)? != MACHINE_AMD64 {
            bail!("not an AMD64 (x86-64) image; SigBreaker 1.0 only supports 64-bit x86 PE");
        }
        let num_sections = u16_le(&data, coff + 2)? as usize;
        let optional_size = u16_le(&data, coff + 16)? as usize;

        let opt = pe_off + 24;
        if optional_size < 112 {
            bail!("PE32+ optional header is too short");
        }
        if opt + optional_size > len {
            bail!("optional header extends past end of file");
        }
        if u16_le(&data, opt)? != OPTION_MAGIC_PE32PLUS {
            bail!("not a PE32+ image (missing 0x20B optional-header magic)");
        }

        let entry_rva = u32_le(&data, opt + 16)?;
        let image_base = u64_le(&data, opt + 24)?;
        let size_of_image = u32_le(&data, opt + 56)?;
        let checksum_off = opt + 64;

        let table = opt + optional_size;
        if table + num_sections * 40 > len {
            bail!("section table extends past end of file");
        }
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = table + i * 40;
            let mut name = [0u8; 8];
            name.copy_from_slice(&data[s..s + 8]);
            sections.push(SectionHeader {
                name,
                virtual_size: u32_le(&data, s + 8)?,
                virtual_address: u32_le(&data, s + 12)?,
                raw_size: u32_le(&data, s + 16)?,
                raw_ptr: u32_le(&data, s + 20)?,
                characteristics: u32_le(&data, s + 36)?,
            });
        }
        for (i, section) in sections.iter().enumerate() {
            let virtual_end = section
                .virtual_address
                .checked_add(section.virtual_size.max(section.raw_size))
                .context("section virtual range overflow")?;
            if virtual_end > size_of_image {
                bail!("section extends beyond SizeOfImage");
            }
            let raw_end = section.raw_ptr as u64 + section.raw_size as u64;
            if section.raw_size > 0
                && (raw_end > len as u64 || (section.raw_ptr as usize) < table + num_sections * 40)
            {
                bail!("section raw range is truncated or overlaps headers");
            }
            for other in &sections[..i] {
                if section.virtual_address
                    < other
                        .virtual_address
                        .saturating_add(other.virtual_size.max(other.raw_size))
                    && other.virtual_address < virtual_end
                {
                    bail!("overlapping section virtual ranges");
                }
                if section.raw_size > 0
                    && other.raw_size > 0
                    && (section.raw_ptr as u64) < other.raw_ptr as u64 + other.raw_size as u64
                    && (other.raw_ptr as u64) < raw_end
                {
                    bail!("overlapping section raw ranges");
                }
            }
        }

        let layout = PeLayout {
            image_base,
            entry_rva,
            size_of_image,
            checksum_off,
            sections,
            protected: Vec::new(),
            runtime_functions: Vec::new(),
            code_roots: BTreeSet::from([entry_rva]),
            metadata_pinned: Vec::new(),
            c_specific: BTreeMap::new(),
            guarded_eh_continuations: false,
            import_slots: BTreeSet::new(),
            unwind: BTreeMap::new(),
        };
        let directory = |index: usize| -> Result<Option<Range<usize>>> {
            let count = u32_le(&data, opt + 108)? as usize;
            if index >= count {
                return Ok(None);
            }
            let at = 112 + index * 8;
            if at + 8 > optional_size {
                bail!("truncated data directory");
            }
            let rva = u32_le(&data, opt + at)?;
            let size = u32_le(&data, opt + at + 4)?;
            if rva == 0 && size == 0 {
                return Ok(None);
            }
            if rva == 0 || size == 0 {
                bail!("incomplete data directory");
            }
            let last = rva
                .checked_add(size - 1)
                .context("data directory overflow")?;
            let start = layout
                .rva_to_offset(rva)
                .context("unmapped data directory")?;
            let end = layout
                .rva_to_offset(last)
                .context("unmapped data directory end")?
                + 1;
            if end > data.len() || end.checked_sub(start) != Some(size as usize) {
                bail!("data directory is not contiguous and file-backed");
            }
            Ok(Some(start..end))
        };
        let mut runtime_functions = Vec::new();
        let mut unwind = BTreeMap::new();
        let mut metadata_pinned = Vec::new();
        let mut code_roots = layout.code_roots.clone();
        let imports = crate::exception::imports(&layout, &data, directory(1)?)?;
        let guarded_eh_continuations = if let Some(config) = directory(10)? {
            config.len() >= 148
                && u32_le(&data, config.start)? >= 148
                && u32_le(&data, config.start + 144)? & 0x0040_0000 != 0
        } else {
            false
        };
        let mut c_specific = BTreeMap::new();
        if let Some(exports) = directory(0)? {
            if exports.len() < 40 {
                bail!("truncated export directory");
            }
            let count = u32_le(&data, exports.start + 20)? as usize;
            let table_rva = u32_le(&data, exports.start + 28)?;
            if count > data.len() / 4 {
                bail!("invalid export count");
            }
            if count > 0 {
                let table = layout
                    .rva_to_offset(table_rva)
                    .context("unmapped export address table")?;
                for i in 0..count {
                    let rva = u32_le(&data, table + i * 4)?;
                    // An EAT value inside the export directory is a forwarder
                    // string, even when the directory is in an executable section.
                    let forwarded = layout
                        .rva_to_offset(rva)
                        .is_some_and(|off| exports.contains(&off));
                    if !forwarded && layout.executable_sections().any(|s| s.contains_rva(rva)) {
                        code_roots.insert(rva);
                    }
                }
            }
        }
        if let Some(range) = directory(3)? {
            if range.len() % 12 != 0 {
                bail!("malformed exception directory");
            }
            for at in (range.start..range.end).step_by(12) {
                let start = u32_le(&data, at)?;
                let end = u32_le(&data, at + 4)?;
                if start >= end
                    || !layout.executable_sections().any(|s| {
                        start >= s.virtual_address
                            && end as u64 <= s.virtual_address as u64 + s.raw_size as u64
                    })
                {
                    bail!("invalid runtime function extent");
                }
                runtime_functions.push(start..end);
                let unwind_rva = u32_le(&data, at + 8)?;
                let header = layout
                    .rva_to_offset(unwind_rva)
                    .context("unmapped unwind info")?;
                let bytes = data
                    .get(header..header + 4)
                    .context("truncated unwind info")?;
                let version = bytes[0] & 7;
                let flags = bytes[0] >> 3;
                let prologue_end = start
                    .checked_add(bytes[1] as u32)
                    .context("prologue overflow")?;
                if version == 1 && prologue_end > end {
                    bail!("prologue exceeds function extent");
                }
                let slots_end = header + 4 + (bytes[2] as usize).div_ceil(2) * 4;
                if version == 1 && slots_end > data.len() {
                    bail!("truncated unwind codes");
                }
                let kind = if version == 1 && flags & !7 == 0 {
                    if flags & 4 != 0 {
                        if flags & 3 != 0 {
                            bail!("chained unwind record also declares a handler");
                        }
                        let begin = u32_le(&data, slots_end)?;
                        let chain_end = u32_le(&data, slots_end + 4)?;
                        let chain_unwind = u32_le(&data, slots_end + 8)?;
                        if begin >= chain_end || layout.rva_to_offset(chain_unwind).is_none() {
                            bail!("invalid chained runtime function");
                        }
                        metadata_pinned.push(begin..chain_end);
                        UnwindKind::Chained {
                            begin,
                            end: chain_end,
                            unwind_rva: chain_unwind,
                        }
                    } else if flags & 3 != 0 {
                        let handler_rva = u32_le(&data, slots_end)?;
                        if !layout
                            .executable_sections()
                            .any(|s| s.contains_rva(handler_rva))
                        {
                            bail!("unmapped exception handler");
                        }
                        code_roots.insert(handler_rva);
                        let data_rva = unwind_rva
                            .checked_add((slots_end + 4 - header) as u32)
                            .context("handler data overflow")?;
                        if crate::exception::is_c_specific(&layout, &data, &imports, handler_rva) {
                            let scopes = crate::exception::parse(
                                &layout,
                                &data,
                                start..end,
                                handler_rva,
                                data_rva,
                            )?;
                            for scope in &scopes.scopes {
                                if scope.handler > 1 {
                                    code_roots.insert(scope.handler);
                                }
                            }
                            c_specific.insert(start, scopes);
                        }
                        UnwindKind::Handler {
                            flags,
                            handler_rva,
                            data_rva: unwind_rva
                                .checked_add((slots_end + 4 - header) as u32)
                                .context("handler data overflow")?,
                        }
                    } else {
                        UnwindKind::Plain
                    }
                } else {
                    UnwindKind::Unsupported { version, flags }
                };
                unwind.insert(
                    start,
                    UnwindInfo {
                        rva: unwind_rva,
                        prologue_end,
                        permits_register_reordering: version == 1
                            && flags == 0
                            && unwind_rva % 4 == 0,
                        kind,
                    },
                );
            }
            runtime_functions.sort_by_key(|r| r.start);
            if runtime_functions.windows(2).any(|w| w[0].end > w[1].start) {
                bail!("overlapping runtime function extents");
            }
            // A chain references a complete primary runtime record. Require a
            // matching parsed record and reject cycles before any transform.
            for info in unwind.values() {
                let mut current = info;
                let mut seen = BTreeSet::new();
                while let UnwindKind::Chained {
                    begin,
                    end,
                    unwind_rva,
                } = current.kind
                {
                    if !seen.insert(current.rva) {
                        bail!("cyclic unwind chain");
                    }
                    if !runtime_functions.contains(&(begin..end)) {
                        bail!("unresolved chained function extent");
                    }
                    current = unwind.get(&begin).context("unresolved unwind chain")?;
                    if current.rva != unwind_rva {
                        bail!("chained unwind address mismatch");
                    }
                }
            }
        }
        let protected = collect_relocations(&data, &layout, directory(5)?)?;
        Ok(PeFile {
            data,
            layout: PeLayout {
                protected,
                runtime_functions,
                unwind,
                code_roots,
                metadata_pinned,
                c_specific,
                guarded_eh_continuations,
                import_slots: imports.keys().copied().collect(),
                ..layout
            },
        })
    }

    /// Immutable view of the pure metadata, safe to share with passes.
    pub fn layout(&self) -> &PeLayout {
        &self.layout
    }

    /// Recomputes and stores the PE optional-header checksum.
    pub fn update_checksum(&mut self) {
        let off = self.layout.checksum_off;
        self.data[off..off + 4].fill(0);

        let mut acc: u64 = 0;
        let (pairs, tail) = self.data.as_chunks::<2>();
        for pair in pairs {
            acc += u16::from_le_bytes(*pair) as u64;
        }
        if let Some(&last) = tail.first() {
            acc += last as u64;
        }
        // Fold the accumulator into 16 bits, then combine with the file size.
        while acc > 0xFFFF {
            acc = (acc & 0xFFFF) + (acc >> 16);
        }
        let checksum = (acc as u32).wrapping_add(self.data.len() as u32);
        self.data[off..off + 4].copy_from_slice(&checksum.to_le_bytes());
    }
}

fn u16_le(d: &[u8], off: usize) -> Result<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .context("truncated PE header")
}

fn u32_le(d: &[u8], off: usize) -> Result<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .context("truncated PE header")
}

fn u64_le(d: &[u8], off: usize) -> Result<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .context("truncated PE header")
}

/// Walks the `.reloc` section and records the file offset of every fixup.
///
/// Anything a relocation points at must stay byte-for-byte in place: the
/// loader writes to those RVAs at load time, so moving or re-encoding the
/// bytes underneath would corrupt the fixup.
fn collect_relocations(
    data: &[u8],
    layout: &PeLayout,
    directory: Option<Range<usize>>,
) -> Result<Vec<Range<usize>>> {
    let mut out = Vec::new();
    let Some(directory) = directory else {
        return Ok(out);
    };
    let start = directory.start;
    let end = directory.end;
    let mut off = start;
    while off + 8 <= end {
        let page_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        if block_size < 8 || block_size % 2 != 0 || off + block_size as usize > end {
            bail!("malformed relocation block");
        }
        let entries = (block_size as usize - 8) / 2;
        for k in 0..entries {
            let e = u16::from_le_bytes(data[off + 8 + k * 2..off + 10 + k * 2].try_into().unwrap());
            if e >> 12 == 0 {
                continue; // IMAGE_REL_BASED_ABSOLUTE: padding
            }
            let rva = page_rva.wrapping_add((e & 0xFFF) as u32);
            if let Some(target) = layout.rva_to_offset(rva) {
                // Fixups are 4 or 8 bytes wide; reserve 8 conservatively.
                out.push(target..target + 8);
            }
        }
        off += block_size as usize;
    }
    if off != end {
        bail!("truncated relocation block");
    }
    Ok(out)
}
