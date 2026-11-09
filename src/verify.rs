//! Post-transformation verification.
//!
//! Every lifted function region is re-decoded linearly from its entry. The
//! decode must (a) produce only valid instructions covering exactly the
//! original byte span, and (b) yield exactly as many instructions as the
//! original linear decode. This catches some encoding corruption; it does not
//! prove correct branch targets, memory operands, instruction order, exception
//! metadata, or behavioral equivalence, and it does not compare other bytes.

use anyhow::{bail, Result};
use iced_x86::{Decoder, DecoderOptions};

use crate::analysis::{Analysis, Function};
use crate::pe::PeLayout;

#[derive(Clone, Copy)]
pub(crate) struct Region {
    pub start_rva: u32,
    pub offset: usize,
    pub len: usize,
    instr_count: usize,
}

impl From<&Function> for Region {
    fn from(f: &Function) -> Self {
        Self {
            start_rva: f.start_rva,
            offset: f.off,
            len: (f.end_rva - f.start_rva) as usize,
            instr_count: f.instr_count,
        }
    }
}

pub fn verify(pe: &PeLayout, data: &[u8], analysis: &Analysis) -> Result<()> {
    verify_regions(pe, data, analysis.functions.iter().map(Region::from))
}

pub(crate) fn verify_regions(
    pe: &PeLayout,
    data: &[u8],
    regions: impl IntoIterator<Item = Region>,
) -> Result<()> {
    for func in regions {
        let mut decoder = Decoder::with_ip(
            64,
            &data[func.offset..func.offset + func.len],
            pe.va(func.start_rva),
            DecoderOptions::NONE,
        );
        let mut count = 0usize;
        let mut consumed = 0usize;
        while consumed < func.len {
            let ins = decoder.decode();
            if ins.is_invalid() {
                bail!(
                    "verification failed: function at RVA {:#x}: invalid instruction after {consumed} bytes",
                    func.start_rva
                );
            }
            consumed += ins.len();
            count += 1;
        }
        if count != func.instr_count {
            bail!(
                "verification failed: function at RVA {:#x}: expected {} instructions, re-decoded {count}",
                func.start_rva,
                func.instr_count
            );
        }
    }
    Ok(())
}
