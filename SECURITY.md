# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, never in a public issue.
Use GitHub's private
[Security Advisories](https://github.com/gsjonio/hightower/security/advisories/new)
for this repository. You will get a response as soon as reasonably possible.

## What hightower does (and does not) do

hightower reads information about running processes. For some protected
processes it needs an elevated (administrator) terminal to read full details;
without elevation those processes are reported as `restricted` -- they are never
dropped and never crash the scan.

- **No network access, no telemetry.** hightower is offline-first. It does not
  phone home, upload process lists, or fetch anything at runtime.
- **Local read-only.** It does not modify, kill, or quarantine processes. It
  explains; the human decides.

## Handling of `unsafe` code

All calls into the Windows API live in the `adapters/` crate and require
`unsafe`. Every `unsafe` block is preceded by a `// SAFETY:` comment stating the
invariant upheld by hand. This is enforced at build time by the clippy lint
`clippy::undocumented_unsafe_blocks` (denied in `adapters/src/lib.rs`), so an
undocumented `unsafe` block fails CI. The pure `core/` crate contains no
`unsafe` and no OS access at all.

## Dependency auditing

CI runs [`cargo-audit`](https://github.com/rustsec/rustsec) against the
[RustSec Advisory Database](https://rustsec.org/) on every push and pull
request, and Dependabot proposes dependency updates weekly.

## Disclaimer

hightower's risk heuristics are an educational aid, not an antivirus. They
produce false positives and false negatives. A verdict is a prompt to
investigate, not a verdict of guilt or innocence.
