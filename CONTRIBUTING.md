# Contributing to satd

Thanks for your interest. satd is a Bitcoin Core-compatible full node in
Rust; the project's stability and correctness expectations are unusually
high because downstream packagers (Umbrel, Start9, BTCPay, distros) and
end-user wallets depend on its surfaces. This document covers what that
means in practice for contributors.

## Before you start

- **Security issues** — do **not** open a public issue or PR. Disclosure
  process is in [`SECURITY.md`](SECURITY.md).
- **Surface changes** — anything that touches an RPC method shape, CLI
  flag, `bitcoin.conf` key, file layout, or release-artifact name is
  governed by [`STABILITY_POLICY.md`](STABILITY_POLICY.md). Tier 1
  (Bitcoin-Core-compatible) surfaces have the strongest contract; please
  read the policy before proposing changes there.
- **Operator-facing changes** — if a flag, default, or signal changes
  behaviour the operator has to know about, update
  [`OPERATOR_ERGONOMICS.md`](OPERATOR_ERGONOMICS.md) in the same PR.

## Workflow

1. Fork the repo or create a branch (`feat/<topic>`, `fix/<topic>`,
   `chore/<topic>`, `docs/<topic>`).
2. Make focused commits. We prefer small, reviewable PRs over megapatches.
3. Run the local checks (below) before pushing.
4. Open a PR against `master`. Describe the motivation, the change, and
   how you verified it. If your change touches a Tier 1 surface, call that
   out explicitly and reference the relevant `STABILITY_POLICY.md` section.
5. CI must be green for a PR to be merged. CI runs the same checks listed
   below plus `cargo-deny` on dep-graph-touching PRs.

Stacked PRs are fine. State the merge order in each PR description and
land them in that order.

## Local checks

Before pushing, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
```

Integration tests live in `satd/tests/` and exercise a real regtest node;
they take a few minutes. Library-only iteration is fine with
`cargo test -p <crate>`, but the regtest suite must pass before opening a
PR that touches consensus, mempool, RPC, or P2P code.

## Commit messages

- One-line summary in the imperative ("add foo", not "added foo" or
  "adding foo"). Under ~70 chars.
- Optional body explaining motivation and trade-offs.
- Reference issues with `Fixes #N` or `Refs #N`.
- Subsystem prefixes are conventional but not required — examples: `node:`,
  `rpc:`, `mempool:`, `electrum:`, `esplora:`, `packaging:`, `docs:`.

Maintainers SSH-sign commits and tags (`ssh-keygen -Y sign`); contributors
are not required to. Verification details are in `SECURITY.md`.

## Code style

- Edition 2024 Rust. `cargo fmt` is the source of truth.
- `clippy` runs with `-D warnings` in CI; fix or `#[allow]` with a brief
  justification comment.
- Errors use `thiserror`. No `unwrap()` / `expect()` in non-test code
  unless an invariant proof is in a comment.
- All async code uses `tokio`. No `std::thread` for I/O.
- Storage writes use `StoreBatch` for atomicity.
- P2P uses the `bitcoin` crate's `NetworkMessage` types directly; no
  bespoke wire format.

## Tests

- Pure logic — unit tests next to the code (`#[cfg(test)] mod tests`).
- Anything that crosses a subsystem boundary — integration test in
  `satd/tests/regtest.rs` against a real regtest harness.
- New RPC methods and Esplora / Electrum endpoints — integration test
  asserting the wire shape for a representative request.
- Consensus-adjacent changes — extend the shadow-verifier coverage if
  applicable; mismatches must produce a structured `ShadowMismatch`.
  Script evaluation is shadow-checked against `libbitcoinconsensus`; the
  block-acceptance pipeline around it is covered by the differential
  battery — static fixtures in `node/tests/feature_block_consensus.rs`
  and the live-Core differential / fuzzer (`satd/tests/phase_c_differential.rs`,
  `fuzz/`). If your change touches block acceptance (PoW, commitments,
  sigops, BIP 34, value conservation, maturity, timestamps, locktime),
  add or extend a case there.

## AI-assisted contributions

AI-assisted contributions are welcome. The bar is the same as any other
contribution: the engineering has to be solid, the diff has to be one
you've read and understood, and you take responsibility for what you
submit. We don't require disclosure that an AI tool was used.

What we do expect:

- **Run the local checks on your own machine.** Don't trust an AI tool's
  claim that `cargo test` passes — run it. AI tools routinely hallucinate
  clean output, and "it compiled in the AI's head" is not the same as
  "it compiles."
- **Read the diff line by line before pushing.** Watch for: invented APIs
  (functions, methods, or crate features that don't exist), stubs the AI
  left behind from its own planning, tests that exercise the wrong path
  or assert against constants the implementation just produced, `unwrap`
  / `expect` sneaked into non-test code, drive-by reformatting of
  unrelated lines.
- **Submit changes you could have written or debugged unaided.** If you
  can't reason about why the diff is correct, you can't defend it in
  review and you can't maintain it after merge. Smaller PRs you fully
  understand beat sprawling PRs you don't.
- **The PR description states what the change does and how you verified
  it.** Reviewers will close PRs that read as unreviewed AI output.

Subsystems with sharper edges (consensus / verifier / connect-block,
RocksDB schema, P2P state machine, sighash and signature-verification
code) are the wrong place to learn — please get familiar with the
surrounding code before asking an AI to edit it.

## What not to send

- PRs that add features without an accompanying integration test.
- PRs that alter Tier 1 surfaces without a `STABILITY_POLICY.md` analysis.
- PRs that depend on unpublished or git-only crate versions.
- PRs that reformat files unrelated to the change.

## Licence

By contributing, you agree your contributions are licensed under the
project's MIT licence (see [`LICENSE`](LICENSE)).
