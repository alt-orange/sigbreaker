//! Reproducible mutation smoke tests. Fail on panics, allow explicit rejection.
#[allow(dead_code)]
mod common;
use rand::{rngs::StdRng, Rng, SeedableRng};
use sigbraker::{analysis::Analysis, pe::PeFile, writer::SectionPlan};

#[test]
fn mutated_headers_directories_and_sections_fail_cleanly() {
    let seed = common::TestPe::new().with_sample_code().data;
    let mut rng = StdRng::seed_from_u64(0x5342524B);
    let fields = [
        0x3C, 0x46, 0x54, 0x70, 0x78, 0x7C, 0x90, 0xC4, 0xC8, 0xCC, 0xE0, 0xE4, 0xF0, 0xF4, 0x150,
        0x154, 0x158, 0x15C, 0x178, 0x17C, 0x180, 0x184, 0xC00, 0xC04, 0xC08,
    ];
    for case in 0..2048 {
        let mut data = seed.clone();
        for _ in 0..rng.gen_range(1..=4) {
            let at = fields[rng.gen_range(0..fields.len())];
            data[at..at + 4].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
        }
        if case % 4 == 0 {
            data.truncate(rng.gen_range(0..data.len()));
        }
        let observation = std::panic::catch_unwind(|| {
            if let Ok(pe) = PeFile::parse(data) {
                let _ = Analysis::run(pe.layout(), &pe.data);
                let _ = SectionPlan::new(&pe);
            }
        });
        assert!(observation.is_ok(), "mutation case {case} panicked");
    }
}
