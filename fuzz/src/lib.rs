//! Native libFuzzer entry point; run_fuzz.ps1 instruments Rust with SanitizerCoverage.
use rand::{rngs::StdRng, SeedableRng};
use sigbraker::{
    analysis::Analysis,
    pe::PeFile,
    transforms::{relayout, reorder, segment_inject},
    verify,
};

/// libFuzzer owns the input buffer for the duration of this call.
///
/// # Safety
/// `data` must be valid for `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if size == 0 || data.is_null() || size > 2 * 1024 * 1024 {
        return 0;
    }
    let raw = unsafe { std::slice::from_raw_parts(data, size) };
    let Ok(mut pe) = PeFile::parse(raw.to_vec()) else {
        return 0;
    };
    let layout = pe.layout().clone();
    let Ok(a) = Analysis::run(&layout, &pe.data) else {
        return 0;
    };
    if a.functions.iter().map(|f| f.instr_count).sum::<usize>() > 100_000 {
        return 0;
    }
    let mut rng = StdRng::seed_from_u64(size as u64);
    segment_inject::run(
        &a,
        &layout,
        &mut pe.data,
        &segment_inject::Config {
            probability: 1.0,
            segments: vec![sigbraker::cli::SegmentName::Ds.register()],
        },
        &mut rng,
    );
    reorder::run(
        &a,
        &layout,
        &mut pe.data,
        &reorder::Config { probability: 1.0 },
        &mut rng,
    );
    // Verification may legitimately reject inconsistent or ambiguous input.
    if verify::verify(&layout, &pe.data, &a).is_err() {
        return 0;
    }
    let Ok(a) = Analysis::run(&layout, &pe.data) else {
        return 0;
    };
    let before = pe.data.clone();
    if relayout::run(&a, &mut pe, 1.0, &mut rng).is_err() {
        assert_eq!(pe.data, before, "failed relocation was not transactional");
    } else {
        let parsed = PeFile::parse(pe.data).expect("published output must reparse");
        let _ = Analysis::run(parsed.layout(), &parsed.data).expect("published output must lift");
    }
    0
}
