//! # hightower (CLI) -- the driving ring
//!
//! Parses the command line and acts as the *composition root*: the one place
//! that constructs the concrete adapters from `hightower-adapters` and injects
//! them into the domain. This is the Rust equivalent of a `main()` that builds a
//! `Deps` struct and hands it to the rest of the app -- dependency injection
//! without a framework.
//!
//! No OS calls and no risk logic live here directly; both are reached through
//! core's ports.

mod report;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use hightower_adapters::procinfo::ToolHelpProcessLister;
use hightower_core::ports::ProcessLister;

use crate::report::render_process_table;

/// Top-level command line: `hightower <command>`.
///
/// (Python bridge: clap's derive macros turn this struct into an argument
/// parser, the way you would wire up `argparse` by hand -- except the parser is
/// generated from the types, so it can never drift out of sync with them.)
#[derive(Parser)]
#[command(
    name = "hightower",
    version,
    about = "Explain what is running on your PC, in plain language.",
    // Without this, clap turns the struct's doc comment (the Python-bridge note
    // above) into the long `--help` text, leaking internal commentary to users.
    long_about = None
)]
struct Cli {
    /// Which subcommand to run.
    #[command(subcommand)]
    command: Commands,
}

/// The subcommands hightower understands. `explain` joins this enum in a later
/// milestone.
#[derive(Subcommand)]
enum Commands {
    /// Scan running processes and explain them.
    Scan {
        /// Show every process (currently the only mode).
        // The flag exists now so the documented `hightower scan --all` works.
        // ponytail: --all is currently a no-op (everything is shown). Upgrade
        // path: once risk filtering exists (#8), the default hides trusted rows
        // and --all brings them back.
        #[arg(long)]
        all: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { all: _ } => run_scan(),
    }
}

/// Runs `hightower scan`: lists processes and prints them as a table.
fn run_scan() -> ExitCode {
    // Composition root: pick the real Windows implementation of the port. Swap
    // this one line for a fake and the rest of the flow is unchanged -- that is
    // the whole point of depending on the trait.
    let lister = ToolHelpProcessLister;

    match lister.list() {
        Ok(processes) => {
            println!("Scanned {} running processes:\n", processes.len());
            print!("{}", render_process_table(&processes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Only a failure of the whole enumeration reaches here; a single
            // process we could not describe is already handled as `restricted`.
            eprintln!("hightower: {error}");
            ExitCode::FAILURE
        }
    }
}
