//! SigBreaker 1.0 — CLI entry point.

use std::process::ExitCode;

use clap::Parser;
use sigbraker::{cli::Cli, pipeline};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match pipeline::run(&cli) {
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
