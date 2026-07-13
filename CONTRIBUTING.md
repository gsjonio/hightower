# Contributing to hightower

Thanks for wanting to help! hightower aims to explain Windows processes to
non-technical people, so contributions that improve clarity count just as much
as code.

## Setup

hightower is a Cargo workspace. From the repo root:

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

All four must pass. The Windows adapters and the `hightower` binary only build
on Windows; the pure `core` crate builds and tests anywhere.

## Architecture (the one rule that matters)

hightower is hexagonal, one crate per ring:

- `core/` -- domain + ports (traits). **Must never depend on the `windows`
  crate or do any OS I/O.** This is enforced by the compiler: `core` does not
  declare `windows` as a dependency, so a Windows import there fails to build.
- `adapters/` -- the real Windows implementations of the core ports.
- `cli/` -- argument parsing and the composition root.

If your change adds OS access, it belongs in `adapters/`, behind a port trait
defined in `core/`.

## Adding a known process

The most welcome first contribution: expanding the known-process database. Each
entry is a JSON object embedded in `adapters/`:

```json
{
  "processName": "svchost.exe",
  "expectedDirectories": ["%SystemRoot%\\System32", "%SystemRoot%\\SysWOW64"],
  "publisher": "Microsoft Windows",
  "category": "core-windows",
  "descriptionEN": "Generic host process for Windows services; multiple instances is normal.",
  "descriptionPT": "Processo host genérico para serviços do Windows; ter várias instâncias é normal."
}
```

Only add processes that are widely and publicly documented, and cite your source
in the PR description. Keep descriptions plain-language -- a non-technical reader
must understand them. Issues labelled `good-first-issue` are a good place to
start.

## Before opening a PR

- [ ] `cargo build --workspace` and `cargo test --workspace` pass
- [ ] `cargo fmt --check` and `cargo clippy --workspace -- -D warnings` are clean
- [ ] New non-trivial logic has a test
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] Docs updated if a command/flag changed (README.md, README.pt-BR.md,
      docs/GUIDE.md stay in sync)

## Scope

One logical change per PR. Small, focused PRs get reviewed and merged faster.
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`).

## Language

Code, comments, doc comments, commit messages, and technical docs are in
`en-US`. Only `README.pt-BR.md` and `docs/GUIDE.pt-BR.md` are in Portuguese.
