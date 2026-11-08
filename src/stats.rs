//! Shared per-pass counters used for the end-of-run report.

/// Counters accumulated by a single transformation pass.
///
/// Not every pass uses every counter; unused ones stay zero and are
/// omitted from the printed report.
#[derive(Debug, Default, Clone)]
pub struct Counters {
    /// Specific reasons for excluding functions from expanded layout.
    pub skipped_reasons: std::collections::BTreeMap<&'static str, u64>,
    /// Movement skipped because unwind/exception metadata is not rewritten.
    pub skipped_metadata: u64,
    /// Eligible items seen (instructions, blocks, functions…).
    pub candidates: u64,
    /// Items actually transformed.
    pub applied: u64,
    pub relocated_c_specific: u64,
    pub relocated_fh3: u64,
    pub relocated_fh4: u64,
    pub relocated_chained: u64,
    pub relocated_import_tails: u64,
    /// Instructions whose bytes were rewritten or relocated in place.
    pub instructions_touched: u64,
    /// Items skipped because they overlap a base-relocation fixup.
    pub skipped_pinned: u64,
    /// Items skipped because no length-preserving encoding existed.
    pub skipped_no_room: u64,
    /// Functions reverted to their original bytes after a failed transform.
    pub reverted: u64,
}

impl Counters {
    /// Formats the non-zero counters; falls back to "nothing done".
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        let mut push = |label: &str, v: u64| {
            if v != 0 {
                parts.push(format!("{label} {v}"));
            }
        };
        push("applied", self.applied);
        push("C-specific SEH functions", self.relocated_c_specific);
        push("C++ FH3 functions", self.relocated_fh3);
        push("C++ FH4 functions", self.relocated_fh4);
        push("chained unwind functions", self.relocated_chained);
        push("import-tail functions", self.relocated_import_tails);
        push("skipped (unwind/exception metadata)", self.skipped_metadata);
        push("instructions touched", self.instructions_touched);
        push("candidates", self.candidates);
        push("skipped (relocated bytes)", self.skipped_pinned);
        push("skipped (no in-place room)", self.skipped_no_room);
        push("reverted", self.reverted);
        for (reason, count) in &self.skipped_reasons {
            push(&format!("skipped ({reason})"), *count);
        }
        if parts.is_empty() {
            return "nothing done".to_string();
        }
        parts.join(", ")
    }
}

impl std::fmt::Display for Counters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}
