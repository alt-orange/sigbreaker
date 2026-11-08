//! Rebase standard PE data structures when .text grows. Unknown address-bearing
//! formats fail closed; no untyped word is rewritten by numeric resemblance.
use crate::{
    pe::{PeFile, UnwindKind},
    writer::align,
};
use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

fn u32_at(d: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        d.get(at..at + 4)
            .context("truncated PE rebuild field")?
            .try_into()?,
    ))
}
fn u64_at(d: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        d.get(at..at + 8)
            .context("truncated PE rebuild field")?
            .try_into()?,
    ))
}

pub struct Layout<'a> {
    pe: &'a PeFile,
    pub text_index: usize,
    pub text_end_raw: usize,
    pub raw_growth: u32,
    pub rva_growth: u32,
    pub opt: usize,
    pub table: usize,
    pub text_raw_size: u32,
    pub text_virtual_size: u32,
    owned: Vec<Range<usize>>,
    edits: BTreeMap<usize, Vec<u8>>,
}

impl<'a> Layout<'a> {
    pub fn new(pe: &'a PeFile, payload_size: usize) -> Result<Self> {
        let opt = u32_at(&pe.data, 0x3C)? as usize + 24;
        let table = opt + u16::from_le_bytes(pe.data[opt - 4..opt - 2].try_into()?) as usize;
        let file_alignment = u32_at(&pe.data, opt + 36)?;
        let section_alignment = u32_at(&pe.data, opt + 32)?;
        if section_alignment < 4096 || file_alignment > section_alignment {
            bail!("unsupported low-alignment PE rebuild");
        }
        let sections = &pe.layout().sections;
        let text_index = sections
            .iter()
            .position(|s| s.name() == ".text" && s.is_executable())
            .context("output rebuild requires .text")?;
        let text = sections[text_index];
        if sections.iter().enumerate().any(|(i, s)| {
            i != text_index
                && (s.is_executable()
                    || s.virtual_address <= text.virtual_address
                    || (s.raw_size > 0 && s.raw_ptr < text.raw_ptr + text.raw_size))
        }) {
            bail!("unsupported section ordering or additional executable section in .text rebuild");
        }
        let text_virtual_size = text
            .raw_size
            .checked_add(u32::try_from(payload_size)?)
            .context(".text size overflow")?;
        let text_raw_size = align(text_virtual_size, file_alignment)?;
        let raw_growth = text_raw_size - text.raw_size;
        let new_end = align(
            text.virtual_address
                .checked_add(text_raw_size)
                .context(".text RVA overflow")?,
            section_alignment,
        )?;
        let next = sections
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != text_index)
            .map(|(_, s)| s.virtual_address)
            .min()
            .unwrap_or(new_end);
        let rva_growth = new_end.saturating_sub(next);
        if rva_growth % 4096 != 0 {
            bail!("rebuild requires page-aligned data relocation");
        }
        Ok(Self {
            pe,
            text_index,
            text_end_raw: text.raw_ptr as usize + text.raw_size as usize,
            raw_growth,
            rva_growth,
            opt,
            table,
            text_raw_size,
            text_virtual_size,
            owned: Vec::new(),
            edits: BTreeMap::new(),
        })
    }
    pub fn rva(&self, rva: u32) -> Result<u32> {
        if self
            .pe
            .layout()
            .sections
            .iter()
            .enumerate()
            .any(|(i, s)| i != self.text_index && s.contains_rva(rva))
        {
            rva.checked_add(self.rva_growth)
                .context("rebased RVA overflow")
        } else {
            Ok(rva)
        }
    }
    pub fn va(&self, va: u64) -> Result<u64> {
        match va
            .checked_sub(self.pe.layout().image_base)
            .and_then(|r| u32::try_from(r).ok())
        {
            Some(r) => Ok(self.pe.layout().image_base + self.rva(r)? as u64),
            None => Ok(va),
        }
    }
    pub fn raw(&self, raw: usize) -> Result<usize> {
        if raw >= self.text_end_raw {
            raw.checked_add(self.raw_growth as usize)
                .context("file offset overflow")
        } else {
            Ok(raw)
        }
    }
    fn offset(&self, rva: u32) -> Result<usize> {
        self.pe
            .layout()
            .rva_to_offset(rva)
            .context("unmapped rebuild structure")
    }
    fn own(&mut self, at: usize, size: usize) -> Result<()> {
        if at
            .checked_add(size)
            .is_none_or(|end| end > self.pe.data.len())
        {
            bail!("truncated rebuild structure");
        }
        if at < self.text_end_raw && at + size > self.text_end_raw {
            bail!("metadata crosses the .text growth boundary");
        }
        self.owned.push(at..at + size);
        Ok(())
    }
    fn put(&mut self, at: usize, bytes: Vec<u8>) -> Result<()> {
        self.own(at, bytes.len())?;
        if let Some(old) = self.edits.insert(at, bytes.clone()) {
            if old != bytes {
                bail!("conflicting typed PE fixups");
            }
        }
        Ok(())
    }
    fn rva_field(&mut self, at: usize) -> Result<()> {
        self.put(
            at,
            self.rva(u32_at(&self.pe.data, at)?)?.to_le_bytes().to_vec(),
        )
    }
    fn va_field(&mut self, at: usize) -> Result<()> {
        self.put(
            at,
            self.va(u64_at(&self.pe.data, at)?)?.to_le_bytes().to_vec(),
        )
    }
    fn raw_field(&mut self, at: usize) -> Result<()> {
        let value = u32_at(&self.pe.data, at)?;
        self.put(
            at,
            if value == 0 {
                0
            } else {
                u32::try_from(self.raw(value as usize)?)?
            }
            .to_le_bytes()
            .to_vec(),
        )
    }
    fn string(&mut self, rva: u32) -> Result<()> {
        let at = self.offset(rva)?;
        let len = self.pe.data[at..]
            .iter()
            .take(4096)
            .position(|c| *c == 0)
            .context("unterminated rebuild string")?
            + 1;
        self.own(at, len)
    }
    fn dir(&self, index: usize) -> Result<Option<(u32, usize, usize)>> {
        if index >= u32_at(&self.pe.data, self.opt + 108)? as usize {
            return Ok(None);
        }
        let r = u32_at(&self.pe.data, self.opt + 112 + index * 8)?;
        let size = u32_at(&self.pe.data, self.opt + 116 + index * 8)? as usize;
        if r == 0 && size == 0 {
            return Ok(None);
        }
        if r == 0 || size == 0 {
            bail!("incomplete rebuild data directory");
        }
        let at = if index == 4 {
            r as usize
        } else {
            self.offset(r)?
        };
        Ok(Some((r, at, size)))
    }
    fn thunks(&mut self, rva: u32) -> Result<()> {
        let start = self.offset(rva)?;
        for index in 0..self.pe.data.len() / 8 {
            let at = start + index * 8;
            let value = u64_at(&self.pe.data, at)?;
            self.own(at, 8)?;
            if value == 0 {
                return Ok(());
            }
            if value >> 63 == 0 && value <= u32::MAX as u64 {
                let name = value as u32;
                self.own(self.offset(name)?, 2)?;
                self.string(name.checked_add(2).context("import hint/name overflow")?)?;
                self.put(at, (self.rva(name)? as u64).to_le_bytes().to_vec())?;
            }
        }
        bail!("unterminated rebuild import table")
    }
    fn resource(
        &mut self,
        base: u32,
        relative: u32,
        seen: &mut BTreeSet<u32>,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 || !seen.insert(relative) {
            bail!("cyclic resource directory");
        }
        let at = self.offset(base.checked_add(relative).context("resource overflow")?)?;
        let named = u16::from_le_bytes(
            self.pe
                .data
                .get(at + 12..at + 14)
                .context("resource header")?
                .try_into()?,
        ) as usize;
        let ids = u16::from_le_bytes(
            self.pe
                .data
                .get(at + 14..at + 16)
                .context("resource header")?
                .try_into()?,
        ) as usize;
        self.own(at, 16 + (named + ids) * 8)?;
        for i in 0..named + ids {
            let field = at + 16 + i * 8;
            let name = u32_at(&self.pe.data, field)?;
            if name >> 31 != 0 {
                let string = self.offset(
                    base.checked_add(name & 0x7fff_ffff)
                        .context("resource name overflow")?,
                )?;
                let len = u16::from_le_bytes(
                    self.pe
                        .data
                        .get(string..string + 2)
                        .context("resource name")?
                        .try_into()?,
                ) as usize;
                self.own(string, 2 + len * 2)?;
            }
            let child = u32_at(&self.pe.data, field + 4)?;
            if child >> 31 != 0 {
                self.resource(base, child & 0x7fff_ffff, seen, depth + 1)?;
            } else {
                let entry =
                    self.offset(base.checked_add(child).context("resource leaf overflow")?)?;
                self.own(entry, 16)?;
                self.rva_field(entry)?;
                self.own(
                    self.offset(u32_at(&self.pe.data, entry)?)?,
                    u32_at(&self.pe.data, entry + 4)? as usize,
                )?;
            }
        }
        Ok(())
    }
    pub fn structures(&mut self) -> Result<()> {
        if self.rva_growth != 0 {
            for (start, info) in self
                .pe
                .layout()
                .runtime_functions
                .iter()
                .filter_map(|f| self.pe.layout().unwind_info(f.start).map(|i| (f.start, i)))
            {
                if matches!(info.kind, UnwindKind::Unsupported { .. })
                    || (matches!(info.kind, UnwindKind::Handler { .. })
                        && !self.pe.layout().c_specific.contains_key(&start))
                {
                    bail!("cannot rebuild growing .text across opaque exception metadata at RVA {start:#x}; no output was written");
                }
            }
        }
        let section_count = self.pe.layout().sections.len();
        for i in 0..section_count {
            let at = self.table + i * 40;
            if i == self.text_index {
                self.put(at + 8, self.text_virtual_size.to_le_bytes().to_vec())?;
                self.put(at + 16, self.text_raw_size.to_le_bytes().to_vec())?;
            } else {
                self.rva_field(at + 12)?;
                self.raw_field(at + 20)?;
            }
            for off in [24, 28] {
                self.raw_field(at + off)?;
            }
        }
        self.put(
            self.opt + 56,
            u32_at(&self.pe.data, self.opt + 56)?
                .checked_add(self.rva_growth)
                .context("image size overflow")?
                .max(align(
                    self.pe.layout().sections[self.text_index]
                        .virtual_address
                        .checked_add(self.text_raw_size)
                        .context("text image end overflow")?,
                    u32_at(&self.pe.data, self.opt + 32)?,
                )?)
                .to_le_bytes()
                .to_vec(),
        )?;
        self.put(
            self.opt + 4,
            u32_at(&self.pe.data, self.opt + 4)?
                .checked_add(self.raw_growth)
                .context("code size overflow")?
                .to_le_bytes()
                .to_vec(),
        )?;
        self.raw_field(self.opt - 12)?; // COFF PointerToSymbolTable
        for i in 0..(u32_at(&self.pe.data, self.opt + 108)? as usize).min(16) {
            if self.dir(i)?.is_some() {
                if !matches!(i, 0 | 1 | 2 | 3 | 4 | 5 | 6 | 9 | 10 | 12) && self.rva_growth != 0 {
                    bail!("unsupported populated data directory {i} for .text rebuild");
                }
                if i == 4 {
                    self.raw_field(self.opt + 112 + i * 8)?;
                } else {
                    self.rva_field(self.opt + 112 + i * 8)?;
                }
            }
        }
        if let Some((_, at, size)) = self.dir(0)? {
            self.own(at, 40)?;
            for off in [12, 28, 32, 36] {
                self.rva_field(at + off)?;
            }
            self.string(u32_at(&self.pe.data, at + 12)?)?;
            let funcs = u32_at(&self.pe.data, at + 20)? as usize;
            let names = u32_at(&self.pe.data, at + 24)? as usize;
            let eat = self.offset(u32_at(&self.pe.data, at + 28)?)?;
            self.own(eat, funcs.checked_mul(4).context("export count")?)?;
            for n in 0..funcs {
                self.rva_field(eat + n * 4)?;
            }
            let nt = self.offset(u32_at(&self.pe.data, at + 32)?)?;
            self.own(nt, names.checked_mul(4).context("export name count")?)?;
            for n in 0..names {
                self.rva_field(nt + n * 4)?;
                self.string(u32_at(&self.pe.data, nt + n * 4)?)?;
            }
            self.own(
                self.offset(u32_at(&self.pe.data, at + 36)?)?,
                names.checked_mul(2).context("ordinal count")?,
            )?;
            self.own(at, size)?;
        }
        if let Some((_, at, size)) = self.dir(1)? {
            self.own(at, size)?;
            for entry in (at..at + size).step_by(20) {
                if self
                    .pe
                    .data
                    .get(entry..entry + 20)
                    .context("import descriptor")?
                    .iter()
                    .all(|b| *b == 0)
                {
                    break;
                }
                for off in [0, 12, 16] {
                    self.rva_field(entry + off)?;
                }
                self.string(u32_at(&self.pe.data, entry + 12)?)?;
                for off in [0, 16] {
                    let value = u32_at(&self.pe.data, entry + off)?;
                    if value != 0 {
                        self.thunks(value)?;
                    }
                }
            }
        }
        if let Some((rva, _, _)) = self.dir(2)? {
            self.resource(rva, 0, &mut BTreeSet::new(), 0)?;
        }
        if let Some((_, at, size)) = self.dir(3)? {
            self.own(at, size)?;
            for record in (at..at + size).step_by(12) {
                self.rva_field(record + 8)?;
            }
        }
        for f in &self.pe.layout().runtime_functions {
            let info = self.pe.layout().unwind_info(f.start).unwrap();
            let at = self.offset(info.rva)?;
            let end = at + 4 + (self.pe.data[at + 2] as usize).div_ceil(2) * 4;
            self.own(at, end - at)?;
            match info.kind {
                UnwindKind::Plain => {}
                UnwindKind::Chained { .. } => {
                    self.own(end, 12)?;
                    self.rva_field(end + 8)?;
                }
                UnwindKind::Handler { .. } => {
                    self.own(end, 4)?;
                    if let Some(c) = self.pe.layout().c_specific.get(&f.start) {
                        self.own(c.table_bytes.start, c.table_bytes.len())?;
                    }
                }
                UnwindKind::Unsupported { .. } => {}
            }
        }
        if let Some((_, at, size)) = self.dir(5)? {
            self.own(at, size)?;
            let mut block = at;
            while block < at + size {
                let page = u32_at(&self.pe.data, block)?;
                let len = u32_at(&self.pe.data, block + 4)? as usize;
                if len < 8 || block + len > at + size {
                    bail!("invalid rebuild relocation block");
                }
                self.rva_field(block)?;
                for entry in (block + 8..block + len).step_by(2) {
                    let value = u16::from_le_bytes(self.pe.data[entry..entry + 2].try_into()?);
                    if value >> 12 == 0 {
                        continue;
                    }
                    if value >> 12 != 10 {
                        if self.rva_growth == 0 {
                            continue;
                        }
                        bail!("unsupported base relocation type {}", value >> 12);
                    }
                    self.va_field(
                        self.offset(
                            page.checked_add((value & 0xfff) as u32)
                                .context("fixup overflow")?,
                        )?,
                    )?;
                }
                block += len;
            }
        }
        if let Some((_, at, size)) = self.dir(6)? {
            if size % 28 != 0 {
                bail!("malformed debug directory");
            }
            self.own(at, size)?;
            for entry in (at..at + size).step_by(28) {
                self.rva_field(entry + 20)?;
                self.raw_field(entry + 24)?;
                let raw = u32_at(&self.pe.data, entry + 24)? as usize;
                let len = u32_at(&self.pe.data, entry + 16)? as usize;
                if raw != 0 && len != 0 {
                    self.own(raw, len)?;
                }
            }
        }
        if let Some((_, at, size)) = self.dir(9)? {
            if size < 40 {
                bail!("truncated TLS directory");
            }
            self.own(at, size)?;
            for off in [0, 8, 16, 24] {
                self.va_field(at + off)?;
            }
        }
        if let Some((_, at, size)) = self.dir(10)? {
            self.own(at, size)?;
            if size >= 96 {
                let cookie = u64_at(&self.pe.data, at + 88)?;
                if cookie != 0 {
                    let r = u32::try_from(
                        cookie
                            .checked_sub(self.pe.layout().image_base)
                            .context("security cookie VA")?,
                    )?;
                    self.own(self.offset(r)?, 8)?;
                }
            }
            if self.rva_growth != 0 {
                for off in [192, 200, 224, 240, 248] {
                    if off + 8 <= size && u64_at(&self.pe.data, at + off)? != 0 {
                        bail!("unsupported extended load-config metadata at offset {off}");
                    }
                }
            }
            for field in [
                40, 80, 88, 96, 112, 120, 128, 160, 176, 208, 216, 232, 256, 264, 280, 288, 296,
                304, 312, 320,
            ] {
                if field + 8 <= size {
                    self.va_field(at + field)?;
                }
            }
            if size >= 264 {
                let va = u64_at(&self.pe.data, at + 256)?;
                if va != 0 {
                    let meta = self.offset(u32::try_from(
                        va.checked_sub(self.pe.layout().image_base)
                            .context("volatile metadata VA")?,
                    )?)?;
                    if u32_at(&self.pe.data, meta)? != 24
                        || self
                            .pe
                            .data
                            .get(meta + 8..meta + 24)
                            .context("volatile metadata header")?
                            .iter()
                            .any(|b| *b != 0)
                    {
                        bail!(
                            "nonempty volatile metadata tables are not supported by .text rebuild"
                        );
                    }
                    self.own(meta, 24)?;
                }
            }
            for (pointer, count) in [(128, 136), (160, 168), (176, 184), (264, 272)] {
                if count + 8 > size {
                    continue;
                }
                let va = u64_at(&self.pe.data, at + pointer)?;
                let n = usize::try_from(u64_at(&self.pe.data, at + count)?)?;
                if va == 0 || n == 0 {
                    continue;
                }
                let r = va
                    .checked_sub(self.pe.layout().image_base)
                    .context("guard table VA")?;
                let table = self.offset(u32::try_from(r)?)?;
                let stride = if pointer == 128 {
                    4 + (u32_at(&self.pe.data, at + 144)? >> 28) as usize
                } else {
                    4
                };
                self.own(table, n.checked_mul(stride).context("guard table count")?)?;
                for i in 0..n {
                    self.rva_field(table + i * stride)?;
                }
            }
        }
        if let Some((_, at, size)) = self.dir(12)? {
            self.own(at, size)?;
        }
        if self.rva_growth != 0 {
            for section in self
                .pe
                .layout()
                .sections
                .iter()
                .filter(|s| !s.is_executable())
            {
                let range = self
                    .pe
                    .layout()
                    .section_raw_range(section, self.pe.data.len());
                for at in (range.start..range.end.saturating_sub(3)).step_by(4) {
                    if self.owned.iter().any(|r| r.start <= at && at + 4 <= r.end) {
                        continue;
                    }
                    let value = u32_at(&self.pe.data, at)?;
                    if self.rva(value)? != value {
                        bail!("unclassified image-relative data reference at file offset {at:#x}");
                    }
                    if at + 8 <= range.end {
                        let value = u64_at(&self.pe.data, at)?;
                        if self.va(value)? != value {
                            bail!("unclassified absolute data reference at file offset {at:#x}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn patch_instruction(
        &self,
        source: &[u8],
        ip: u64,
        output: &mut [u8],
        off: usize,
    ) -> Result<()> {
        let mut d = Decoder::with_ip(64, source, ip, DecoderOptions::NONE);
        let ins = d.decode();
        if ins.is_invalid() {
            bail!("invalid instruction during PE rebasing");
        }
        if ins.is_ip_rel_memory_operand() {
            if let Some((table, _, size)) = self.dir(3)? {
                if ins
                    .ip_rel_memory_address()
                    .checked_sub(self.pe.layout().image_base)
                    .is_some_and(|r| r >= table as u64 && r < table as u64 + size as u64)
                {
                    bail!(
                        "direct reference to the runtime table prevents retiring its old storage"
                    );
                }
            }
            let target = self.va(ins.ip_rel_memory_address())?;
            if target != ins.ip_rel_memory_address() {
                let constants = d.get_constant_offsets(&ins);
                if constants.displacement_size() != 4 {
                    bail!("unsupported IP-relative displacement width");
                }
                let displacement = i32::try_from(target as i128 - ins.next_ip() as i128)
                    .context("rebased memory reference exceeds rel32")?;
                let at = off + constants.displacement_offset();
                output[at..at + 4].copy_from_slice(&displacement.to_le_bytes());
            }
        }
        Ok(())
    }
    pub fn code(&mut self, output: &mut [u8]) -> Result<()> {
        if self.rva_growth == 0 {
            return Ok(());
        }
        let text = self.pe.layout().sections[self.text_index];
        let range = text.virtual_address..text.virtual_address + text.raw_size;
        let mut pending: Vec<_> = self
            .pe
            .layout()
            .code_roots
            .iter()
            .copied()
            .chain(self.pe.layout().runtime_functions.iter().map(|f| f.start))
            .chain(
                self.pe
                    .layout()
                    .c_specific
                    .values()
                    .flat_map(|c| &c.scopes)
                    .filter(|s| s.target != 0)
                    .map(|s| s.target),
            )
            .chain(self.pe.layout().relocated_code_references(&self.pe.data))
            .collect();
        let mut seen = BTreeMap::<u32, Instruction>::new();
        let mut covered = vec![false; text.raw_size as usize];
        let mut dispatch = BTreeSet::new();
        if let Some((_, at, size)) = self.dir(10)? {
            for field in [112, 120, 280, 288, 296] {
                if field + 8 > size {
                    continue;
                }
                let slot = u64_at(&self.pe.data, at + field)?
                    .checked_sub(self.pe.layout().image_base)
                    .and_then(|r| u32::try_from(r).ok());
                let target = slot
                    .and_then(|r| self.pe.layout().rva_to_offset(r))
                    .and_then(|off| u64_at(&self.pe.data, off).ok())
                    .and_then(|v| v.checked_sub(self.pe.layout().image_base))
                    .and_then(|r| u32::try_from(r).ok());
                if let Some(target) = target {
                    dispatch.insert(target);
                }
            }
        }
        while let Some(rva) = pending.pop() {
            if !range.contains(&rva) || seen.contains_key(&rva) {
                continue;
            }
            let at = self.offset(rva)?;
            let end = (text.raw_ptr + text.raw_size) as usize;
            let mut decoder = Decoder::with_ip(
                64,
                &self.pe.data[at..end],
                self.pe.layout().va(rva),
                DecoderOptions::NONE,
            );
            let ins = decoder.decode();
            if ins.is_invalid() {
                bail!("unclassified code at RVA {rva:#x}");
            }
            if ins.flow_control() == FlowControl::IndirectBranch {
                let import = ins.is_ip_rel_memory_operand()
                    && ins
                        .ip_rel_memory_address()
                        .checked_sub(self.pe.layout().image_base)
                        .and_then(|r| u32::try_from(r).ok())
                        .is_some_and(|r| self.pe.layout().import_slots.contains(&r));
                if !import && !dispatch.contains(&rva) {
                    bail!(
                        "unresolved indirect branch at RVA {rva:#x} prevents data-section rebasing"
                    );
                }
            }
            let rel = (rva - text.virtual_address) as usize;
            if covered[rel..rel + ins.len()].iter().any(|b| *b) {
                bail!("overlapping instruction roots in .text");
            }
            covered[rel..rel + ins.len()].fill(true);
            seen.insert(rva, ins);
            if ins.is_ip_rel_memory_operand() {
                if let Some(target) = ins
                    .ip_rel_memory_address()
                    .checked_sub(self.pe.layout().image_base)
                    .and_then(|r| u32::try_from(r).ok())
                {
                    if range.contains(&target) && ins.mnemonic() == Mnemonic::Lea {
                        pending.push(target);
                    }
                }
            }
            if ins.is_call_near() || ins.is_jcc_short_or_near() || ins.is_jmp_short_or_near() {
                if let Some(target) = ins
                    .near_branch_target()
                    .checked_sub(self.pe.layout().image_base)
                    .and_then(|r| u32::try_from(r).ok())
                {
                    pending.push(target);
                }
            }
            if matches!(
                ins.flow_control(),
                FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
            ) {
                pending.push(rva + ins.len() as u32);
            }
        }
        for (rva, ins) in &seen {
            let at = self.offset(*rva)?;
            self.patch_instruction(&self.pe.data[at..at + ins.len()], ins.ip(), output, at)?;
            for op in 0..ins.op_count() {
                if ins.op_kind(op) == OpKind::Immediate64
                    && self.va(ins.immediate64())? != ins.immediate64()
                    && !self.pe.layout().is_protected(at..at + ins.len())
                {
                    bail!("unrelocated absolute address in instruction");
                }
            }
        }
        let mut i = 0;
        while i < covered.len() {
            if covered[i]
                || self
                    .owned
                    .iter()
                    .any(|r| r.contains(&(text.raw_ptr as usize + i)))
                || matches!(self.pe.data[text.raw_ptr as usize + i], 0 | 0x90 | 0xCC)
            {
                i += 1;
                continue;
            }
            let ins = Decoder::with_ip(
                64,
                &self.pe.data[text.raw_ptr as usize + i..(text.raw_ptr + text.raw_size) as usize],
                self.pe.layout().va(text.virtual_address + i as u32),
                DecoderOptions::NONE,
            )
            .decode();
            if ins.is_jmp_short_or_near()
                && ins
                    .near_branch_target()
                    .checked_sub(self.pe.layout().image_base)
                    .and_then(|r| u32::try_from(r).ok())
                    .is_some_and(|r| {
                        self.pe
                            .layout()
                            .runtime_functions
                            .iter()
                            .any(|f| f.start == r)
                    })
            {
                i += ins.len();
                continue;
            }
            if ins.mnemonic() == Mnemonic::Nop {
                i += ins.len();
            } else {
                bail!("unclassified executable bytes at RVA {:#x}; full .text rebuild requires resolved code",text.virtual_address+i as u32);
            }
        }
        Ok(())
    }
    pub fn apply(&self, output: &mut [u8]) -> Result<()> {
        for (at, bytes) in &self.edits {
            let dest = self.raw(*at)?;
            output
                .get_mut(dest..dest + bytes.len())
                .context("rebuilt field outside file")?
                .copy_from_slice(bytes);
        }
        Ok(())
    }
}
