//! Builds a minimal but structurally valid x86-64 PE image for tests.
//!
//! Layout (file offsets):
//!   0x0000  DOS header (e_lfanew = 0x40)
//!   0x0040  PE signature + COFF + optional header (240 bytes)
//!   0x0148  section table (3 × 40 bytes)
//!   0x0400  .text  raw data  (RVA 0x1000)
//!   0x0800  .rdata raw data  (RVA 0x2000)
//!   0x0C00  .reloc raw data  (RVA 0x3000)

pub const TEXT_FILE_OFF: usize = 0x400;
pub const TEXT_RAW_SIZE: usize = 0x200;

/// Entry-point code plus a second function, designed to exercise all three
/// passes:
///
/// - `f0` (entry, RVA 0x1000): several block chains — the last three are
///   fall-through-safe and get shuffled.
/// - `f1` (RVA 0x1027, reached by a direct call): its last block contains a
///   reorderable instruction pair.
pub const SAMPLE_CODE: &[u8] = &[
    // f0 @ RVA 0x1000
    0x48, 0x89, 0xC8, // mov rax, rcx
    0x48, 0x01, 0xDA, // add rdx, rbx
    0x48, 0x85, 0xC9, // test rcx, rcx
    0x74, 0x0A, // jz 0x1015
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
    0xE9, 0x06, 0x00, 0x00, 0x00, // jmp 0x101B
    // L2 @ 0x1015
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xC3, // ret
    // L3 @ 0x101B
    0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
    0xC3, // ret
    0xE8, 0x00, 0x00, 0x00, 0x00, // call 0x1026 (f1, immediately after)
    // f1 @ RVA 0x1026
    0x89, 0xC8, // mov eax, ecx
    0x85, 0xC9, // test ecx, ecx
    0x74, 0x02, // jz 0x102E
    0xC3, // ret
    // L1 @ 0x102E — reorderable body
    0x89, 0xF1, // mov ecx, esi
    0x01, 0xDA, // add edx, ebx
    0x89, 0x02, // mov [rdx], eax
    0xC3, // ret
];

pub struct TestPe {
    pub data: Vec<u8>,
}

impl TestPe {
    pub fn new() -> Self {
        let mut d = vec![0u8; 0xE00];
        // DOS header.
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE signature.
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF header.
        d[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        d[0x46..0x48].copy_from_slice(&3u16.to_le_bytes()); // sections
        d[0x54..0x56].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
        d[0x56..0x58].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics
                                                                 // Optional header (PE32+).
        d[0x58..0x5A].copy_from_slice(&0x020Bu16.to_le_bytes()); // magic
        d[0x5C..0x60].copy_from_slice(&(TEXT_RAW_SIZE as u32).to_le_bytes()); // size of code
        d[0x68..0x6C].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        d[0x6C..0x70].copy_from_slice(&0x1000u32.to_le_bytes()); // base of code
        d[0x70..0x78].copy_from_slice(&0x140_000_000u64.to_le_bytes()); // image base
        d[0x78..0x7C].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        d[0x7C..0x80].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        d[0x80..0x82].copy_from_slice(&6u16.to_le_bytes()); // OS version
        d[0x88..0x8A].copy_from_slice(&6u16.to_le_bytes()); // image version
        d[0x90..0x94].copy_from_slice(&0x4000u32.to_le_bytes()); // size of image
        d[0x94..0x98].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
        d[0x9C..0x9E].copy_from_slice(&3u16.to_le_bytes()); // subsystem: console
        d[0xC4..0xC8].copy_from_slice(&16u32.to_le_bytes()); // number of data directories
        d[0xF0..0xF4].copy_from_slice(&0x3000u32.to_le_bytes()); // dir[5] reloc RVA
        d[0xF4..0xF8].copy_from_slice(&0xCu32.to_le_bytes()); // dir[5] reloc size
                                                              // Section table.
        let mut section =
            |at: usize, name: &[u8], vsz: u32, va: u32, raw: u32, ptr: u32, chars: u32| {
                d[at..at + name.len()].copy_from_slice(name);
                d[at + 8..at + 12].copy_from_slice(&vsz.to_le_bytes());
                d[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
                d[at + 16..at + 20].copy_from_slice(&raw.to_le_bytes());
                d[at + 20..at + 24].copy_from_slice(&ptr.to_le_bytes());
                d[at + 36..at + 40].copy_from_slice(&chars.to_le_bytes());
            };
        section(
            0x148,
            b".text\0\0\0",
            0x200,
            0x1000,
            0x200,
            0x400,
            0x6000_0020,
        );
        section(
            0x170,
            b".rdata\0\0",
            0x100,
            0x2000,
            0x200,
            0x800,
            0x4000_0040,
        );
        section(
            0x198,
            b".reloc\0\0",
            0x200,
            0x3000,
            0x200,
            0xC00,
            0x4200_0040,
        );
        d[0x800..0x810].copy_from_slice(b"SIGBREAKER-DATA!"); // .rdata payload
                                                              // .reloc: one block, one HIGHLOW fixup into .rdata (harmless here).
        d[0xC00..0xC04].copy_from_slice(&0x2000u32.to_le_bytes()); // page RVA
        d[0xC04..0xC08].copy_from_slice(&0xCu32.to_le_bytes()); // block size
        d[0xC08..0xC0A].copy_from_slice(&0x3010u16.to_le_bytes()); // type 3, offset 0x10
        d[0xC0A..0xC0C].copy_from_slice(&0x0000u16.to_le_bytes()); // padding
        TestPe { data: d }
    }

    pub fn with_sample_code(self) -> Self {
        self.with_code(SAMPLE_CODE)
    }

    pub fn with_code(mut self, code: &[u8]) -> Self {
        assert!(code.len() <= TEXT_RAW_SIZE);
        self.data[TEXT_FILE_OFF..TEXT_FILE_OFF + code.len()].copy_from_slice(code);
        self
    }

    /// Raw bytes of the `.text` section.
    pub fn text(&self) -> &[u8] {
        &self.data[TEXT_FILE_OFF..TEXT_FILE_OFF + TEXT_RAW_SIZE]
    }
}
