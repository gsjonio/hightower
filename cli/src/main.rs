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

use hightower_adapters::knowledge::EmbeddedKnowledgeRepository;
use hightower_adapters::procinfo::ToolHelpProcessLister;
use hightower_adapters::signature::AuthenticodeVerifier;
use hightower_core::classify::Classifier;
use hightower_core::ports::{ProcessLister, SignatureVerifier};
use hightower_core::process::{ProcessInfo, ProcessVerdict, RiskLevel};
use hightower_core::rules::default_rules;

use crate::report::render_verdict_table;

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
        // path: once filtering exists, the default hides trusted rows and --all
        // brings them back.
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

/// Runs `hightower scan`: lists processes, verifies their signatures, classifies
/// each one, and prints the verdicts worst-first.
fn run_scan() -> ExitCode {
    // Composition root: pick the real Windows implementations of the ports. Swap
    // these for fakes and the rest of the flow is unchanged -- that is the whole
    // point of depending on the traits.
    let mut processes = match ToolHelpProcessLister.list() {
        Ok(processes) => processes,
        Err(error) => {
            // Only a failure of the whole enumeration reaches here; a single
            // process we could not describe is already handled as `restricted`.
            eprintln!("hightower: {error}");
            return ExitCode::FAILURE;
        }
    };

    verify_signatures_in_parallel(&mut processes);

    let knowledge = match EmbeddedKnowledgeRepository::new() {
        Ok(knowledge) => knowledge,
        Err(error) => {
            eprintln!("hightower: {error}");
            return ExitCode::FAILURE;
        }
    };
    let classifier = Classifier::new(default_rules(), Box::new(knowledge));

    // Python equivalent: verdicts = [classifier.classify(p) for p in processes]
    let mut verdicts: Vec<ProcessVerdict> = processes
        .iter()
        .map(|process| classifier.classify(process))
        .collect();

    // Worst-first so flagged processes surface at the top of the report.
    // Reverse turns the ascending Ord (trusted < review < suspicious) into
    // descending; the sort is stable, so same-risk rows keep their PID order.
    verdicts.sort_by_key(|verdict| std::cmp::Reverse(verdict.risk));

    let suspicious = verdicts
        .iter()
        .filter(|v| v.risk == RiskLevel::Suspicious)
        .count();
    let review = verdicts
        .iter()
        .filter(|v| v.risk == RiskLevel::Review)
        .count();
    println!(
        "Scanned {} processes: {suspicious} suspicious, {review} to review.\n",
        verdicts.len()
    );
    print!("{}", render_verdict_table(&verdicts));
    ExitCode::SUCCESS
}

/// Fills in each process's signature status, checking files in parallel.
///
/// Signature verification reads each file from disk, so doing it serially across
/// a few hundred processes is slow. We split the work across threads with
/// `std::thread::scope`.
///
/// Python bridge: in Python, `threading` barely helps CPU/IO-bound loops like
/// this because of the GIL (you would reach for `multiprocessing`). In Rust the
/// threads run in genuine parallel, and the compiler guarantees at compile time
/// that the chunks handed to different threads do not overlap -- `chunks_mut`
/// yields disjoint mutable slices, so there is no shared-mutation data race to
/// worry about.
fn verify_signatures_in_parallel(processes: &mut [ProcessInfo]) {
    if processes.is_empty() {
        return;
    }

    let verifier = AuthenticodeVerifier;
    let thread_count = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let chunk_size = processes.len().div_ceil(thread_count).max(1);

    std::thread::scope(|scope| {
        for chunk in processes.chunks_mut(chunk_size) {
            let verifier = &verifier;
            scope.spawn(move || {
                for process in chunk.iter_mut() {
                    // Compute the status first so the borrow of executable_path
                    // ends before we write to signature.
                    let status = match &process.executable_path {
                        Some(path) => verifier.verify(path),
                        None => continue,
                    };
                    process.signature = status;
                }
            });
        }
    });
}
