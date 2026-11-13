//! SigBreaker 1.0 — CLI entry point.

use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};
use sigbraker::{
    cli::Cli,
    pipeline,
    report::{self, LineKind},
};

#[cfg(feature = "tui")]
mod tui;

fn main() -> ExitCode {
    let command = Cli::command();
    #[cfg(feature = "tui")]
    let command = command.arg(
        clap::Arg::new("tui")
            .long("tui")
            .help("Open the interactive terminal interface")
            .action(clap::ArgAction::SetTrue)
            .exclusive(true),
    );
    let matches = command.get_matches();
    #[cfg(feature = "tui")]
    if matches.get_flag("tui") {
        return match tui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                anstream::eprintln!("\x1b[31;1merror\x1b[0m: {err:#}");
                ExitCode::FAILURE
            }
        };
    }
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    match pipeline::run_with_progress(&cli, |stage| {
        anstream::eprintln!("\x1b[2m  > {stage}\x1b[0m")
    }) {
        Ok(report) => {
            anstream::eprintln!();
            print_report(&report);
            ExitCode::SUCCESS
        }
        Err(err) => {
            anstream::eprintln!("\x1b[31;1merror\x1b[0m: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn print_report(report: &str) {
    for line in report.lines() {
        let color = match report::line_kind(line) {
            LineKind::Heading => "\x1b[36;1m",
            LineKind::Subheading => "\x1b[1m",
            LineKind::Success => "\x1b[32m",
            LineKind::Warning => "\x1b[33m",
            LineKind::Text => "",
        };
        anstream::println!("{color}{line}\x1b[0m");
    }
}
