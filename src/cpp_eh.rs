//! MSVC AMD64 FH3/FH4 language data. Decode typed records; never identify FH4
//! by its unversioned first byte. Handler identity must be established first.
//! See MSVC ehdata.h and ehdata4_export.h shipped with the compiler.
use crate::pe::PeLayout;
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

#[derive(Clone, Debug)]
pub struct CppEh {
    pub handler: u32,
    pub function: Range<u32>,
    pub owned: Vec<Range<usize>>,
    pub roots: BTreeSet<u32>,
    pub states: Vec<(u32, i32)>,
    pub continuations: BTreeSet<u32>,
    pub gs_data: Vec<u8>,
    format: Format,
}
#[derive(Clone, Debug)]
enum Format {
    Fh3(Vec<u8>),
    Fh4 {
        header: u8,
        bbt: u32,
        unwind: u32,
        frame: u32,
        tries: Vec<Try4>,
        segments: Vec<(u32, u32)>,
    },
}
#[derive(Clone, Debug)]
struct Try4 {
    states: [u32; 3],
    handlers: Vec<Handler4>,
}
#[derive(Clone, Debug)]
struct Handler4 {
    header: u8,
    adjectives: u32,
    type_rva: u32,
    object: u32,
    handler: u32,
    continuations: Vec<u32>,
}

struct Reader<'a> {
    pe: &'a PeLayout,
    data: &'a [u8],
    owned: Vec<Range<usize>>,
    roots: BTreeSet<u32>,
    budget: usize,
}
impl Reader<'_> {
    fn raw(&mut self, rva: u32, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let at = self.pe.rva_to_offset(rva).context("unmapped C++ EH data")?;
        let last = rva
            .checked_add(u32::try_from(size - 1)?)
            .context("C++ EH range overflow")?;
        if self.pe.rva_to_offset(last) != Some(at + size - 1) {
            bail!("noncontiguous C++ EH data");
        }
        let bytes = self
            .data
            .get(at..at + size)
            .context("truncated C++ EH data")?
            .to_vec();
        self.owned.push(at..at + size);
        Ok(bytes)
    }
    fn byte(&mut self, cursor: &mut u32) -> Result<u8> {
        let value = self.raw(*cursor, 1)?[0];
        *cursor = cursor.checked_add(1).context("C++ EH cursor overflow")?;
        Ok(value)
    }
    fn word(&mut self, cursor: &mut u32) -> Result<u32> {
        let value = u32::from_le_bytes(self.raw(*cursor, 4)?.try_into().unwrap());
        *cursor = cursor.checked_add(4).context("C++ EH cursor overflow")?;
        Ok(value)
    }
    fn uint(&mut self, cursor: &mut u32) -> Result<u32> {
        let first = self.byte(cursor)?;
        let length = (first.trailing_ones() as usize + 1).min(5);
        if length == 5 {
            return self.word(cursor);
        }
        let mut value = first as u32;
        for i in 1..length {
            value |= (self.byte(cursor)? as u32) << (8 * i);
        }
        Ok(value >> length)
    }
    fn count(&mut self, count: u32) -> Result<usize> {
        let n = count as usize;
        if n > self.budget {
            bail!("excessive C++ EH table count");
        }
        self.budget -= n;
        Ok(n)
    }
    fn compressed_count(&mut self, cursor: &mut u32) -> Result<usize> {
        let n = self.uint(cursor)?;
        self.count(n)
    }
    fn code(&mut self, rva: u32) -> Result<()> {
        if rva != 0 {
            if !self.pe.executable_sections().any(|s| s.contains_rva(rva)) {
                bail!("invalid C++ EH code target");
            }
            self.roots.insert(rva);
        }
        Ok(())
    }
    fn type_rva(&mut self, rva: u32) -> Result<()> {
        if rva != 0 && self.pe.rva_to_offset(rva).is_none() {
            bail!("unmapped C++ type descriptor");
        }
        Ok(())
    }
    fn handlers3(&mut self, rva: u32, count: u32) -> Result<()> {
        let n = self.count(count)?;
        let raw = self.raw(
            rva,
            n.checked_mul(20).context("FH3 handler count overflow")?,
        )?;
        for h in raw.as_chunks::<20>().0 {
            self.type_rva(get(h, 4))?;
            self.code(get(h, 12))?;
        }
        Ok(())
    }
    fn handlers4(&mut self, mut cursor: u32, function: &Range<u32>) -> Result<Vec<Handler4>> {
        let n = self.compressed_count(&mut cursor)?;
        let mut result = Vec::new();
        for _ in 0..n {
            let header = self.byte(&mut cursor)?;
            let ncont = (header >> 4) & 3;
            if header & 0xC0 != 0 || ncont == 3 {
                bail!("unsupported FH4 handler header");
            }
            let adjectives = if header & 1 != 0 {
                self.uint(&mut cursor)?
            } else {
                0
            };
            let type_rva = if header & 2 != 0 {
                self.word(&mut cursor)?
            } else {
                0
            };
            self.type_rva(type_rva)?;
            let object = if header & 4 != 0 {
                self.uint(&mut cursor)?
            } else {
                0
            };
            let handler = self.word(&mut cursor)?;
            self.code(handler)?;
            let mut continuations = Vec::new();
            for _ in 0..ncont {
                let target = if header & 8 != 0 {
                    self.word(&mut cursor)?
                } else {
                    function
                        .start
                        .checked_add(self.uint(&mut cursor)?)
                        .context("FH4 continuation overflow")?
                };
                self.code(target)?;
                continuations.push(target);
            }
            result.push(Handler4 {
                header,
                adjectives,
                type_rva,
                object,
                handler,
                continuations,
            });
        }
        Ok(result)
    }
    fn ips4(&mut self, mut cursor: u32, begin: u32) -> Result<Vec<(u32, i32)>> {
        if cursor == 0 {
            return Ok(Vec::new());
        }
        let n = self.compressed_count(&mut cursor)?;
        let mut pc = begin;
        let mut states = Vec::new();
        for _ in 0..n {
            pc = pc
                .checked_add(self.uint(&mut cursor)?)
                .context("FH4 IP delta overflow")?;
            let state = self.uint(&mut cursor)?;
            if state > i32::MAX as u32 {
                bail!("FH4 state overflow");
            }
            states.push((pc, state as i32 - 1));
        }
        Ok(states)
    }
}
fn get(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn set(d: &mut [u8], at: usize, value: u32) {
    d[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn word(d: &mut Vec<u8>, value: u32) {
    d.extend_from_slice(&value.to_le_bytes());
}
fn uint(d: &mut Vec<u8>, value: u32) {
    let n = if value < 1 << 7 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 21 {
        3
    } else if value < 1 << 28 {
        4
    } else {
        5
    };
    if n == 5 {
        d.push(15);
        word(d, value);
    } else {
        let encoded = ((value as u64) << n) | ((1u64 << (n - 1)) - 1);
        d.extend_from_slice(&encoded.to_le_bytes()[..n]);
    }
}

pub fn parse(
    pe: &PeLayout,
    data: &[u8],
    function: Range<u32>,
    handler: u32,
    data_rva: u32,
    fh4: bool,
) -> Result<CppEh> {
    let mut r = Reader {
        pe,
        data,
        owned: Vec::new(),
        roots: BTreeSet::new(),
        budget: data.len(),
    };
    let mut cursor = data_rva;
    let info_rva = r.word(&mut cursor)?;
    cursor = info_rva;
    let states;
    let mut continuations = BTreeSet::new();
    let format = if !fh4 {
        let raw = r.raw(cursor, 40)?;
        if get(&raw, 0) & 0x1FFF_FFFF != 0x1993_0522 {
            bail!("unsupported FH3 magic");
        }
        let n = r.count(get(&raw, 4))?;
        let unwind = r.raw(
            get(&raw, 8),
            n.checked_mul(8).context("FH3 unwind count overflow")?,
        )?;
        for (i, entry) in unwind.as_chunks::<8>().0.iter().enumerate() {
            let next = get(entry, 0) as i32;
            if next < -1 || next >= i as i32 {
                bail!("invalid FH3 unwind transition");
            }
            r.code(get(entry, 4))?;
        }
        let n = r.count(get(&raw, 12))?;
        let tries = r.raw(
            get(&raw, 16),
            n.checked_mul(20).context("FH3 try count overflow")?,
        )?;
        for t in tries.as_chunks::<20>().0 {
            if get(t, 0) > get(t, 4) || get(t, 4) > get(t, 8) {
                bail!("invalid FH3 try states");
            }
            r.handlers3(get(t, 16), get(t, 12))?;
        }
        let n = r.count(get(&raw, 20))?;
        let ips = r.raw(
            get(&raw, 24),
            n.checked_mul(8).context("FH3 IP count overflow")?,
        )?;
        states = ips
            .as_chunks::<8>()
            .0
            .iter()
            .map(|e| (get(e, 0), get(e, 4) as i32))
            .collect::<Vec<_>>();
        let est = get(&raw, 32);
        if est != 0 {
            let list = r.raw(est, 8)?;
            r.handlers3(get(&list, 4), get(&list, 0))?;
        }
        Format::Fh3(raw)
    } else {
        let header = r.byte(&mut cursor)?;
        if header & 0x80 != 0 {
            bail!("reserved FH4 function header bit");
        }
        let bbt = if header & 4 != 0 {
            r.uint(&mut cursor)?
        } else {
            0
        };
        let unwind = if header & 8 != 0 {
            r.word(&mut cursor)?
        } else {
            0
        };
        let try_rva = if header & 16 != 0 {
            r.word(&mut cursor)?
        } else {
            0
        };
        let ip_rva = r.word(&mut cursor)?;
        let frame = if header & 1 != 0 {
            r.uint(&mut cursor)?
        } else {
            0
        };
        if unwind != 0 {
            let mut u = unwind;
            let n = r.compressed_count(&mut u)?;
            for _ in 0..n {
                let field = r.uint(&mut u)?;
                if field & 3 != 0 {
                    let action = r.word(&mut u)?;
                    r.code(action)?;
                }
                if matches!(field & 3, 1 | 2) {
                    r.uint(&mut u)?;
                }
            }
        }
        let mut tries = Vec::new();
        if try_rva != 0 {
            let mut t = try_rva;
            let n = r.compressed_count(&mut t)?;
            for _ in 0..n {
                let states = [r.uint(&mut t)?, r.uint(&mut t)?, r.uint(&mut t)?];
                if states[0] > states[1] || states[1] > states[2] {
                    bail!("invalid FH4 try states");
                }
                let h = r.word(&mut t)?;
                let handlers = r.handlers4(h, &function)?;
                for h in &handlers {
                    continuations.extend(h.continuations.iter().copied());
                }
                tries.push(Try4 { states, handlers });
            }
        }
        let mut segments = Vec::new();
        if header & 2 != 0 {
            let mut seg = ip_rva;
            let n = r.compressed_count(&mut seg)?;
            for _ in 0..n {
                let start = r.word(&mut seg)?;
                let ip = r.word(&mut seg)?;
                r.code(start)?;
                // Decode every segment to validate/own shared tables.
                r.ips4(ip, start)?;
                segments.push((start, ip));
            }
            states = if let Some(&(_, ip)) = segments.iter().find(|s| s.0 == function.start) {
                r.ips4(ip, function.start)?
            } else {
                Vec::new()
            };
        } else {
            states = r.ips4(ip_rva, function.start)?;
        }
        Format::Fh4 {
            header,
            bbt,
            unwind,
            frame,
            tries,
            segments,
        }
    };
    if states.windows(2).any(|w| w[0].0 > w[1].0) || states.iter().any(|s| s.1 < -1) {
        bail!("invalid C++ IP-to-state map");
    }
    // Continuations are owned references, not roots that would pin the parent.
    for target in &continuations {
        r.roots.remove(target);
    }
    Ok(CppEh {
        handler,
        function,
        owned: r.owned,
        roots: r.roots,
        states,
        continuations,
        format,
        gs_data: Vec::new(),
    })
}

impl CppEh {
    pub fn is_fh4(&self) -> bool {
        matches!(self.format, Format::Fh4 { .. })
    }
    /// Handler data begins with an RVA to the function info. All emitted RVAs
    /// point into this copy or into unchanged original metadata/code entries.
    pub fn relocate(
        &self,
        base: u64,
        data_rva: u32,
        new_begin: u32,
        map: &BTreeMap<u64, u64>,
        spans: &[(u64, Range<u64>)],
    ) -> Result<Vec<u8>> {
        let mut ordered = spans.to_vec();
        ordered.sort_by_key(|s| s.1.start);
        let mut states = Vec::new();
        for (old, range) in &ordered {
            let old = u32::try_from(old.checked_sub(base).context("C++ source PC underflow")?)?;
            let idx = self.states.partition_point(|s| s.0 <= old);
            let state = if idx == 0 { -1 } else { self.states[idx - 1].1 };
            if states.last().is_none_or(|s: &(u32, i32)| s.1 != state) {
                states.push((
                    u32::try_from(
                        range
                            .start
                            .checked_sub(base)
                            .context("C++ destination PC underflow")?,
                    )?,
                    state,
                ));
            }
        }
        let mapped = |old: u32| -> Result<u32> {
            if self.function.contains(&old) {
                Ok(u32::try_from(
                    map.get(&(base + old as u64))
                        .context("unmapped FH4 continuation")?
                        .checked_sub(base)
                        .context("FH4 PC underflow")?,
                )?)
            } else {
                Ok(old)
            }
        };
        let rva_at = |offset: usize| {
            data_rva
                .checked_add(u32::try_from(offset).context("C++ output too large")?)
                .context("C++ output RVA overflow")
        };
        let mut out = Vec::new();
        let info_offset = 4 + self.gs_data.len();
        word(&mut out, rva_at(info_offset)?);
        out.extend_from_slice(&self.gs_data);
        match &self.format {
            Format::Fh3(raw) => {
                out.extend_from_slice(raw);
                set(&mut out, info_offset + 20, u32::try_from(states.len())?);
                set(&mut out, info_offset + 24, rva_at(info_offset + 40)?);
                for (ip, state) in states {
                    word(&mut out, ip);
                    word(&mut out, state as u32);
                }
            }
            Format::Fh4 {
                header,
                bbt,
                unwind,
                frame,
                tries,
                segments,
            } => {
                out.push(*header);
                if header & 4 != 0 {
                    uint(&mut out, *bbt);
                }
                if header & 8 != 0 {
                    word(&mut out, *unwind);
                }
                let try_field = out.len();
                if header & 16 != 0 {
                    word(&mut out, 0);
                }
                let ip_field = out.len();
                word(&mut out, 0);
                if header & 1 != 0 {
                    uint(&mut out, *frame);
                }
                if header & 16 != 0 {
                    let offset = out.len();
                    set(&mut out, try_field, rva_at(offset)?);
                    uint(&mut out, u32::try_from(tries.len())?);
                    let mut handler_fields = Vec::new();
                    for t in tries {
                        for s in t.states {
                            uint(&mut out, s);
                        }
                        handler_fields.push(out.len());
                        word(&mut out, 0);
                    }
                    for (t, field) in tries.iter().zip(handler_fields) {
                        let offset = out.len();
                        set(&mut out, field, rva_at(offset)?);
                        uint(&mut out, u32::try_from(t.handlers.len())?);
                        for h in &t.handlers {
                            out.push(h.header);
                            if h.header & 1 != 0 {
                                uint(&mut out, h.adjectives);
                            }
                            if h.header & 2 != 0 {
                                word(&mut out, h.type_rva);
                            }
                            if h.header & 4 != 0 {
                                uint(&mut out, h.object);
                            }
                            word(&mut out, h.handler);
                            for &old in &h.continuations {
                                let target = mapped(old)?;
                                if h.header & 8 != 0 {
                                    word(&mut out, target);
                                } else {
                                    uint(
                                        &mut out,
                                        target.checked_sub(new_begin).context(
                                            "external function-relative FH4 continuation",
                                        )?,
                                    );
                                }
                            }
                        }
                    }
                }
                let map_offset = out.len();
                uint(&mut out, u32::try_from(states.len())?);
                let mut previous = new_begin;
                for (ip, state) in states {
                    uint(
                        &mut out,
                        ip.checked_sub(previous).context("FH4 IP map order")?,
                    );
                    uint(&mut out, (state as i64 + 1) as u32);
                    previous = ip;
                }
                let mut ip_rva = rva_at(map_offset)?;
                if header & 2 != 0 {
                    let offset = out.len();
                    uint(&mut out, u32::try_from(segments.len())?);
                    for &(old, ip) in segments {
                        word(
                            &mut out,
                            if old == self.function.start {
                                new_begin
                            } else {
                                old
                            },
                        );
                        word(
                            &mut out,
                            if old == self.function.start {
                                ip_rva
                            } else {
                                ip
                            },
                        );
                    }
                    ip_rva = rva_at(offset)?;
                }
                set(&mut out, ip_field, ip_rva);
            }
        }
        Ok(out)
    }
}
