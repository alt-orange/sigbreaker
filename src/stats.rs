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
    /// Inert filler instructions inserted into unreachable gaps.
    pub junk_inserted: u64,
    /// Instructions rewritten into an equivalent aliased opcode encoding.
    pub aliases: u64,
    /// Relocated functions with bytes scrubbed from their original bodies.
    pub wiped_original: u64,
    /// Original body bytes covered by the scrub spans.
    pub original_bytes_wiped: u64,
    /// Calls in retained bodies redirected to their relocated counterparts.
    pub redirected_original_calls: u64,
    /// Items skipped because they overlap a base-relocation fixup.
    pub skipped_pinned: u64,
    /// Items skipped because no length-preserving encoding existed.
    pub skipped_no_room: u64,
    /// Functions reverted to their original bytes after a failed transform.
    pub reverted: u64,
}

impl Counters {
    /// Append counters with explicit units and skip reasons ordered by frequency.
    pub fn write_report(&self, output: &mut String, unit: &str) {
        use crate::report::{field, number, size};
        use std::fmt::Write as _;

        field(output, 4, &format!("Applied {unit}"), number(self.applied));
        for (label, count) in [
            ("Candidates", self.candidates),
            ("Reverted functions", self.reverted),
            ("Import-tail functions", self.relocated_import_tails),
            ("Junk instructions", self.junk_inserted),
            ("Aliased instructions", self.aliases),
            ("Original bodies wiped", self.wiped_original),
            ("Original calls redirected", self.redirected_original_calls),
        ] {
            if count != 0 {
                field(output, 4, label, number(count));
            }
        }
        if self.instructions_touched != 0
            && (unit != "instructions" || self.instructions_touched != self.applied)
        {
            field(
                output,
                4,
                "Instructions touched",
                number(self.instructions_touched),
            );
        }
        if self.original_bytes_wiped != 0 {
            field(
                output,
                4,
                "Original bytes wiped",
                size(self.original_bytes_wiped),
            );
        }
        let exception_counts = [
            ("C-specific SEH functions", self.relocated_c_specific),
            ("C++ FH3 functions", self.relocated_fh3),
            ("C++ FH4 functions", self.relocated_fh4),
            ("Chained unwind functions", self.relocated_chained),
        ];
        if exception_counts.iter().any(|(_, count)| *count != 0) {
            let _ = writeln!(output, "    Exception metadata");
            for (label, count) in exception_counts {
                if count != 0 {
                    field(output, 6, label, number(count));
                }
            }
        }
        let mut skipped: Vec<_> = [
            ("unwind/exception metadata", self.skipped_metadata),
            ("protected instructions", self.skipped_pinned),
            ("no in-place room", self.skipped_no_room),
        ]
        .into_iter()
        .chain(
            self.skipped_reasons
                .iter()
                .map(|(&reason, &count)| (reason, count)),
        )
        .filter(|(_, count)| *count != 0)
        .collect();
        skipped.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        if !skipped.is_empty() {
            let _ = writeln!(output, "    Skipped");
            for (reason, count) in skipped {
                let _ = writeln!(output, "      {:>10}  {reason}", number(count));
            }
        }
    }

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
        push("junk instructions", self.junk_inserted);
        push("aliased instructions", self.aliases);
        push("original bodies wiped", self.wiped_original);
        push("original bytes wiped", self.original_bytes_wiped);
        push("original calls redirected", self.redirected_original_calls);
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
