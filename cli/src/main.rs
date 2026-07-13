//! # hightower (CLI) -- the driving ring
//!
//! Parses the command line and acts as the *composition root*: the one place
//! that constructs the concrete adapters from `hightower-adapters` and injects
//! them into the `hightower-core` classifier. This is the Rust equivalent of a
//! `main()` that builds a `Deps` struct and hands it to the rest of the app --
//! dependency injection without a framework.
//!
//! No OS calls and no risk logic live here directly; both are reached through
//! core's ports.

fn main() {
    // Skeleton only. Real subcommands (`scan`, `explain`) arrive with clap in
    // milestone v0.2.0.
    println!("hightower {}", env!("CARGO_PKG_VERSION"));
    println!("Coming soon: `hightower scan --all`");
}
