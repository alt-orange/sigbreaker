#[allow(dead_code)]
#[path = "../../tests/common/mod.rs"]
mod common;
fn main() {
    let directory = std::path::PathBuf::from(std::env::args_os().nth(1).expect("corpus directory"));
    std::fs::create_dir_all(&directory).unwrap();
    let code = [
        0x85, 0xC9, 0x74, 6, 0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3,
    ];
    let mut d = common::TestPe::new().with_code(&code).data;
    for (at, value) in [
        (0xE0, 0x2040u32),
        (0xE4, 12),
        (0x840, 0x1000),
        (0x844, 0x1010),
        (0x848, 0x2080),
    ] {
        d[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for version in [1u8, 2] {
        d[0x880] = version;
        std::fs::write(directory.join(format!("plain-v{version}.pe")), &d).unwrap();
    }
    std::fs::write(
        directory.join("metadata-free.pe"),
        common::TestPe::new().with_sample_code().data,
    )
    .unwrap();
}
