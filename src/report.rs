//! Shared formatting for terminal and TUI reports.

use std::fmt::{Display, Write};

/// Format an integer with thousands separators.
pub fn number(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(digit);
    }
    output
}

/// Show file sizes with binary units and their exact byte counts.
pub fn size(value: u64) -> String {
    if value < 1024 {
        return format!("{} bytes", number(value));
    }
    let mut scaled = value as f64;
    let mut unit = "bytes";
    for next in ["KiB", "MiB", "GiB", "TiB"] {
        scaled /= 1024.0;
        unit = next;
        if scaled < 1024.0 {
            break;
        }
    }
    format!("{scaled:.2} {unit} ({} bytes)", number(value))
}

/// Append one aligned label/value row to a plain-text report.
pub fn field(output: &mut String, indent: usize, label: &str, value: impl Display) {
    let _ = writeln!(output, "{:indent$}{label:<26}  {value}", "");
}

/// Presentation roles shared by the CLI and TUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Heading,
    Subheading,
    Success,
    Warning,
    Text,
}

/// Find the start of a value in an aligned report row.
pub fn value_start(line: &str) -> Option<usize> {
    let content = line.trim_start();
    content
        .find("  ")
        .map(|gap| line.len() - content.len() + gap + 2)
}

/// Classify a report line for consistent terminal highlighting.
pub fn line_kind(line: &str) -> LineKind {
    let content = line.trim_start();
    if content.is_empty() {
        return LineKind::Text;
    }
    if !line.starts_with(' ') {
        return LineKind::Heading;
    }
    if content.starts_with("Functions changed")
        || (content.starts_with("Verification") && content.contains("Passed"))
    {
        return LineKind::Success;
    }
    if content == "Skipped"
        || content.starts_with("Verification")
        || (line.starts_with("      ") && content.starts_with(|ch: char| ch.is_ascii_digit()))
    {
        return LineKind::Warning;
    }
    if value_start(line).is_none() {
        return LineKind::Subheading;
    }
    LineKind::Text
}
