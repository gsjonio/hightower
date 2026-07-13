# hightower

EN | [PT-BR](README.pt-BR.md)

[![CI](https://github.com/gsjonio/hightower/actions/workflows/ci.yml/badge.svg)](https://github.com/gsjonio/hightower/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gsjonio/hightower/actions/workflows/codeql.yml/badge.svg)](https://github.com/gsjonio/hightower/actions/workflows/codeql.yml)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange?logo=rust)](Cargo.toml)
[![Release](https://img.shields.io/github/v/release/gsjonio/hightower)](https://github.com/gsjonio/hightower/releases/latest)
[![License: MIT](https://img.shields.io/github/license/gsjonio/hightower)](LICENSE)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue?logo=github)](https://github.com/gsjonio/hightower/wiki)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-gugamenezes-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/gugamenezes)

A Windows command-line tool that lists every running process and explains, in
plain language, what each one is -- flagging the unknown or out-of-place ones.
Built for people who have no idea what all those names in Task Manager mean.

> New to Windows internals? Start with the beginner's guide
> ([docs/GUIDE.md](docs/GUIDE.md), pt-BR: [docs/GUIDE.pt-BR.md](docs/GUIDE.pt-BR.md))
> instead: it explains every term and table column in plain language.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Risk Heuristics & Disclaimer](#risk-heuristics--disclaimer)
- [Notes](#notes)
- [Support](#support)
- [License](#license)

## Features

- `hightower scan --all` -- list every running process with PID, full path,
  category, publisher (when verifiable), and a plain-language risk verdict.
- `hightower explain <name|pid>` -- a plain-language write-up of a single
  process: what it is, whether many copies is normal, expected vs. actual path.
- `hightower scan --json` -- the same scan as machine-readable JSON.
- Offline-first: no network, no telemetry, ever.

> Status: early development (v0.1.0). The commands above are the roadmap; see
> the [milestones](https://github.com/gsjonio/hightower/milestones).

## Install

Requires the Rust toolchain (1.82+). Windows only.

```sh
git clone https://github.com/gsjonio/hightower.git
cd hightower
cargo build -p hightower-cli --release
# binary at target/release/hightower.exe
```

## Architecture

hightower is a Cargo workspace laid out as a hexagonal (ports & adapters)
architecture, one crate per ring:

- **`core`** -- the domain and the ports (traits). Pure logic, **zero OS
  dependencies**. It does not depend on the `windows` crate, so any attempt to
  call Windows from the domain *fails to compile* -- the boundary is enforced by
  the compiler, not by code review.
- **`adapters`** -- the driven side: real Windows implementations of the ports
  (process listing via ToolHelp32, Authenticode signature checks) and the
  embedded known-process database.
- **`cli`** -- the driving side: argument parsing plus the composition root that
  wires the adapters into the core.

See the [Architecture wiki page](https://github.com/gsjonio/hightower/wiki/Architecture)
for the full rationale.

## Project Structure

```text
hightower/
├── core/        domain + ports (traits). No OS deps.
├── adapters/    Windows adapters (ToolHelp32, Authenticode) + known-process DB.
└── cli/         clap + composition root; produces the `hightower` binary.
```

## Usage

```sh
hightower scan --all          # explain every running process
hightower scan --json         # same, as JSON for scripts
hightower explain <name|pid>  # deep-dive a single process
```

## Risk Heuristics & Disclaimer

hightower is an **educational aid, not an antivirus.** It uses simple
heuristics to flag processes worth a human look:

1. A known Windows process name (e.g. `svchost.exe`) running from outside
   `%SystemRoot%\System32` / `SysWOW64` -- a classic masquerading technique.
2. A binary with no valid or trusted signature.
3. A process running from `Temp`, `Downloads`, or `AppData\Roaming` unsigned.
4. A name absent from the known-process database with no recognized publisher
   -- reported as `unknown, review manually`.

**These heuristics produce false positives and false negatives.** A `suspicious`
verdict does not mean malware, and a `trusted` verdict does not guarantee
safety. hightower never tells you to kill or delete a system process. When in
doubt, research the process or ask someone you trust -- do not act on the
verdict alone.

## Notes

- Some protected processes require an elevated (administrator) terminal for full
  details. Without it they appear as `restricted` -- they are never dropped and
  never crash the scan.
- No network access, no telemetry.

## Support

hightower is free and open source. If it saves you time, you can support its
development with a coffee. Thank you!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-gugamenezes-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/gugamenezes)

## License

[MIT](LICENSE)
