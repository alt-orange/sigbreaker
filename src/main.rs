//! SigBreaker 1.0 — CLI entry point.

use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};
use sigbraker::{cli::Cli, pipeline};

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
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        };
    }
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    match pipeline::run_with_progress(&cli, |stage| eprintln!("[sigbraker] {stage}")) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
