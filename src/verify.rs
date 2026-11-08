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

use crate::analysis::Analysis;
use crate::pe::PeLayout;

pub fn verify(pe: &PeLayout, data: &[u8], analysis: &Analysis) -> Result<()> {
    for func in &analysis.functions {
        let len = (func.end_rva - func.start_rva) as usize;
        let mut decoder = Decoder::with_ip(
            64,
            &data[func.off..func.off + len],
            pe.va(func.start_rva),
            DecoderOptions::NONE,
        );
        let mut count = 0usize;
        let mut consumed = 0usize;
        while consumed < len {
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
