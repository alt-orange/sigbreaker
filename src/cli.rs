//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use iced_x86::Register;

/// Segment selector names accepted by the `--segments` whitelist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SegmentName {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

impl SegmentName {
    /// Maps the CLI name to the iced-x86 register used when re-encoding.
    pub fn register(self) -> Register {
        match self {
            SegmentName::Es => Register::ES,
            SegmentName::Cs => Register::CS,
            SegmentName::Ss => Register::SS,
            SegmentName::Ds => Register::DS,
            SegmentName::Fs => Register::FS,
            SegmentName::Gs => Register::GS,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sigbraker",
    version,
    about = "SigBreaker 1.0 — binary diversification engine for x86-64 PE files",
    long_about = "SigBreaker experimentally diversifies x86-64 PE binaries \
with transformations intended to preserve behavior:\n\
  - segment selector injection (configurable whitelist, FS/GS off by default)\n\
  - equivalent encodings for selected instructions and relocated stack restores\n\
  - DAG-based instruction reordering inside basic blocks\n\
  - basic block shuffling with explicit control-flow patching\n\n\
Relocated functions are emitted into an appended executable section. Existing data RVAs \
are preserved, apart from data moved by the global options. \
Named FH3/FH4 and SEH \
handlers, explicit static-handler maps, bounded indirect targets, and guarded \
continuations are supported. Unknown formats stay pinned. Structural verification is not a proof of \
behavioral equivalence."
)]
pub struct Cli {
    /// Input x86-64 PE executable to diversify.
    pub input: PathBuf,

    /// Output path (defaults to `<stem>.sigbrk.<extension>` beside the input).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Linker /MAP file establishing statically linked CRT handler identities.
    #[arg(long)]
    pub handler_map: Option<PathBuf>,

    /// Map of initialized globals and their RIP-relative references in the input PE.
    #[arg(long, group = "global_layout", conflicts_with = "info")]
    pub global_map: Option<PathBuf>,

    /// Move a supported image's writable .data section using only the input PE.
    #[arg(long, group = "global_layout", conflicts_with = "info")]
    pub auto_globals: bool,

    /// Global layout slot (0–255). Defaults to a slot derived from --seed.
    #[arg(long, requires = "global_layout")]
    pub global_slot: Option<u8>,

    /// Deterministic RNG seed (same seed + same binary = same output).
    #[arg(long, default_value_t = 0x5349_4752)]
    pub seed: u64,

    /// Probability [0, 1] of injecting a segment override into an eligible instruction.
    #[arg(long, default_value_t = 1.0)]
    pub seg_prob: f64,

    /// Whitelist of segment overrides allowed for injection.
    ///
    /// FS and GS are excluded by default: they are reserved by the Windows
    /// kernel and userland for the TEB and other critical structures. Only
    /// enable them if the target environment (UEFI, custom OS, hypervisor)
    /// defines those segment descriptors.
    #[arg(long, value_delimiter = ',', default_value = "es,cs,ss,ds")]
    pub segments: Vec<SegmentName>,

    /// Probability [0, 1] of scheduling an eligible instruction run or block.
    #[arg(long, default_value_t = 1.0)]
    pub reorder_prob: f64,

    /// Probability [0, 1] of relocating eligible functions for block shuffling
    /// or unreachable padding, or shuffling block chains in place.
    #[arg(long, default_value_t = 1.0)]
    pub shuffle_prob: f64,

    /// Probability [0, 1] of adding unreachable filler at each eligible site
    /// in a relocated body, including jump-protected straight-line splits.
    #[arg(long, default_value_t = 1.0)]
    pub junk_prob: f64,

    /// Scrub eligible original bodies after relocation (enabled by default).
    /// Live interior references and embedded tables can require retaining bytes.
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = true, overrides_with = "keep_original")]
    pub wipe_original: bool,

    /// Preserve original bodies behind entry jumps.
    #[arg(long, overrides_with = "wipe_original")]
    pub keep_original: bool,

    /// Store the generated .sbrk section with LZMA and restore it during TLS startup.
    #[arg(long, alias = "compress")]
    pub compress_section: bool,

    /// Probability [0, 1] of using an equivalent encoding for an eligible instruction.
    #[arg(long, default_value_t = 1.0)]
    pub alias_prob: f64,

    /// Disable segment selector injection.
    #[arg(long)]
    pub no_seg_inject: bool,

    /// Allow segment prefixes to grow eligible relocated functions (enabled by default).
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = true, overrides_with = "no_grow_segments")]
    pub grow_segments: bool,

    /// Limit segment injection to existing instruction lengths.
    #[arg(long, overrides_with = "grow_segments")]
    pub no_grow_segments: bool,

    /// Disable instruction reordering.
    #[arg(long)]
    pub no_reorder: bool,

    /// Disable opcode aliasing.
    #[arg(long)]
    pub no_alias: bool,

    /// Disable block shuffling and relocation solely for unreachable padding.
    #[arg(long)]
    pub no_shuffle: bool,

    /// Skip post-transformation verification (not recommended).
    #[arg(long)]
    pub no_verify: bool,

    /// Only analyze the binary and print a report; do not transform or write.
    #[arg(long)]
    pub info: bool,
}
