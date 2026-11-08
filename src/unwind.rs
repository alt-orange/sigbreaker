//! Version-2 AMD64 epilogue descriptors. Prologue operations retain their
//! original offsets; explicit epilogue distances are rebuilt after layout.
use anyhow::{bail, Context, Result};
use std::{collections::BTreeMap, ops::Range};

#[derive(Clone, Debug)]
pub struct V2 {
    pub epilogues: Vec<Range<u32>>,
    prologue_codes: Vec<u8>,
    header: [u8; 4],
}
impl V2 {
    pub fn parse(data: &[u8], function: Range<u32>) -> Result<Self> {
        let header: [u8; 4] = data
            .get(..4)
            .context("truncated v2 unwind header")?
            .try_into()?;
        let count = header[2] as usize;
        let slots = data
            .get(4..4 + count * 2)
            .context("truncated v2 unwind codes")?;
        let mut index = 0;
        let mut epilogues = Vec::new();
        if count != 0 && slots[1] & 15 == 6 {
            let size = slots[0] as u32;
            if size == 0 || slots[1] >> 4 > 1 {
                bail!("invalid v2 epilogue header");
            }
            let mut add = |distance: u32| -> Result<()> {
                let start = function
                    .end
                    .checked_sub(distance)
                    .context("v2 epilogue underflow")?;
                let end = start.checked_add(size).context("v2 epilogue overflow")?;
                if start < function.start || end > function.end {
                    bail!("v2 epilogue outside function");
                }
                epilogues.push(start..end);
                Ok(())
            };
            if slots[1] >> 4 == 1 {
                add(size)?;
            }
            index = 1;
            while index < count && slots[index * 2 + 1] & 15 == 6 {
                let distance = slots[index * 2] as u32 + ((slots[index * 2 + 1] >> 4) as u32) * 256;
                if distance != 0 {
                    add(distance)?;
                }
                index += 1;
            }
            if epilogues.is_empty() {
                bail!("v2 epilogue header without an epilogue");
            }
        }
        let codes = slots[index * 2..].to_vec();
        let mut previous = header[1];
        while index < count {
            let offset = slots[index * 2];
            let op = slots[index * 2 + 1] & 15;
            let info = slots[index * 2 + 1] >> 4;
            if offset > previous {
                bail!("unordered v2 prologue operations");
            }
            previous = offset;
            let size = match op {
                0 | 2 | 3 | 10 => 1,
                1 if info == 0 => 2,
                1 if info == 1 => 3,
                4 | 8 => 2,
                5 | 9 => 3,
                _ => bail!("unsupported v2 unwind operation"),
            };
            index += size;
            if index > count {
                bail!("truncated v2 unwind operation");
            }
        }
        epilogues.sort_by_key(|e| e.start);
        if epilogues.windows(2).any(|w| w[0].end > w[1].start) {
            bail!("overlapping v2 epilogues");
        }
        Ok(Self {
            header,
            epilogues,
            prologue_codes: codes,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn relocate(
        &self,
        base: u64,
        map: &BTreeMap<u64, u64>,
        new_end: u32,
        original: &[u8],
        old_begin: u32,
        code: &[u8],
        new_begin: u32,
    ) -> Result<Vec<u8>> {
        let mut codes = Vec::new();
        if let Some(first) = self.epilogues.first() {
            codes.extend_from_slice(&[u8::try_from(first.len())?, 6]);
            for range in &self.epilogues {
                let start = u32::try_from(
                    map.get(&(base + range.start as u64))
                        .context("unmapped v2 epilogue")?
                        .checked_sub(base)
                        .context("v2 PC underflow")?,
                )?;
                let distance = new_end
                    .checked_sub(start)
                    .context("v2 epilogue beyond function")?;
                if distance > 4095 {
                    bail!("v2 epilogue distance exceeds 12 bits");
                }
                let old = (range.start - old_begin) as usize;
                let new = (start - new_begin) as usize;
                if original.get(old..old + range.len()) != code.get(new..new + range.len()) {
                    bail!("v2 epilogue bytes changed");
                }
                codes.extend_from_slice(&[distance as u8, ((distance >> 8) as u8) << 4 | 6]);
            }
            if codes.len() % 4 != 0 {
                codes.extend_from_slice(&[0, 6]);
            }
        }
        codes.extend_from_slice(&self.prologue_codes);
        let mut header = self.header;
        header[2] = u8::try_from(codes.len() / 2).context("too many v2 unwind slots")?;
        let mut out = header.to_vec();
        out.extend(codes);
        out.resize(out.len().div_ceil(4) * 4, 0);
        Ok(out)
    }
}
