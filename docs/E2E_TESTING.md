# E2E Testing

This document is the contributor reference for satd's end-to-end
integration suite. The suite drives a real `satd` regtest node over
real sockets via real clients — `sat-cli` for JSON-RPC, `reqwest` for
Esplora REST, and the third-party `electrum-client` crate for the
Electrum protocol — and asserts the wire-level guarantees that
handler-level unit tests can't reach.

The strategic motivation is in the operator manual's "Native Protocol
Architecture" chapter (`docs/manual/src/native-protocol-surfaces.md`): satd's
"one process, one RocksDB" architecture means a write on any
protocol surface must propagate to every read surface. The E2E
suite, and especially the cross-surface test
(`test_e2e_cross_surface_esplora_broadcast_visible_in_rpc_and_electrum`),
is what holds that contract honest.

Updated: 2026-05-11.

## Running locally

```sh
# Pre-build sat-cli — the integration tests reach for it by path
# lookup (Path::new(CARGO_BIN_EXE_satd).parent().join("sat-cli"))
# rather than via the CARGO_BIN_EXE_* mechanism, so cargo's automatic
# bin build doesn't pick it up.
cargo build -p sat-cli --locked

# Run the full suite. Serialized — each test owns its own satd boot.
# `--features e2e` is mandatory: the e2e [[test]] target declares
# `required-features = ["e2e"]` so it stays out of `cargo test --all`.
cargo test --test e2e --locked --features e2e -- --test-threads=1

# Or a single test.
cargo test --test e2e --locked --features e2e \
  test_e2e_cross_surface_esplora_broadcast_visible_in_rpc_and_electrum \
  -- --test-threads=1 --exact
```

Local wall-clock is typically 15–20s for the full 18-test suite on a
modern dev box. On the hosted CI runner the same suite costs ~30s
once the workspace has built.

## Timeout knobs

| Env var | Effect | Default |
|---|---|---|
| `SATD_TEST_TIMEOUT_MULT` | Scales the harness's startup-wait deadline (used by the existing regtest suite as well). | 1.0 locally; 2 in CI. |
| `SATD_E2E_TIMEOUT_MULT` | Scales the per-poll deadlines inside E2E tests (`poll_until_json`, headers/scripthash subscribe waits). Independent of the unit-test mult because E2E chains poll loops on top of the startup wait. | Falls back to `SATD_TEST_TIMEOUT_MULT` when unset; 3 in CI. |
| `SATD_BACKFILL_PREFLIGHT_BYTES` | Bypasses the address-index backfill RPC's 80 GB free-disk pre-flight check. The production default is sized for mainnet; regtest chains are KB–MB. Set to `0` in CI; leave unset locally unless you're running backfill tests on a small disk. | Production default (80 GB). |
| `SATD_TEST_STDERR_DIR` | Redirects each spawned satd's stderr to `<dir>/satd-<port>-<ts>.stderr.log` instead of `/dev/null`. The escape hatch for diagnosing flakes — set it when something doesn't reproduce on a fresh run. | unset (silent). |

## Architecture

- **Per-test boot**: each `#[test]` creates a fresh `E2eNode` via
  `boot_with(&[...])`. State-mutating tests (mining, broadcasting)
  cannot share a boot.
- **OS-assigned ports**: pass `--esplorabind=127.0.0.1:0` and/or
  `--electrumbind=127.0.0.1:0`; `E2eNode` reads back the real port
  from `getserverstatus` after startup.
- **Poll, never sleep**: every assertion that depends on state
  convergence goes through `poll_until_json` (or the
  `electrum-client` `ping()`-then-pop pattern for subscriptions, since
  the third-party client has no background reader thread).
- **Strict teardown**: `TestNode::Drop` (in `tests/common/mod.rs`)
  kills the child process and removes the tempdir even on panic.
- **Serialized**: the e2e binary runs with `RUST_TEST_THREADS=1` in
  CI. Parallel boots of full satd processes on a 4-vCPU hosted
  runner contend on RPC/P2P binds and exhaust the runner's
  per-test startup watchdog.

## CI

The per-PR job runs the full E2E suite once as a step in the existing
`Tests` job (`.github/workflows/ci.yml`). The step's wall-clock is
~30s because the workspace has already been built by the previous
`cargo test --all` step; promoting it to its own job would pay the
toolchain-install cost twice and slow CI for no benefit.

The manual flake-gate workflow (`.github/workflows/e2e_flake_gate.yml`)
loops the E2E suite 10 consecutive times — fail-fast on the first
non-zero exit. Triggered via `workflow_dispatch`:

```sh
gh workflow run e2e_flake_gate.yml
# Or for a heavier release-confidence check:
gh workflow run e2e_flake_gate.yml -f iterations=30
```

Run it before tagging a release, or when investigating a suspected
flake. The iteration count is parameterised because triage runs (3–5
iterations) often want faster turnaround than the release-confidence
run (10+ iterations).

## When the suite flakes

> If a test in this suite flakes once in N runs, the bug is in the
> publisher/forwarder path, not the test.

The E2E suite is designed against the assumption that observable
state convergence is deterministic. A flake means a race in one of:

- `node-index/src/subscribe.rs` — `SubscriptionRegistry::maybe_notify`
  (dedup / drop ordering, queue cap interaction with
  `prune_empty`).
- `electrum-proto/src/subscribe.rs` — per-conn `scripthash_forwarder`
  task (channel cap, drop ordering during shutdown).
- `esplora-handlers/src/handlers/tx.rs` — `tx_broadcast` ordering vs.
  mempool admit (e.g., the broadcast returns 200 before the index
  has seen the mempool update).

Do not retry-mask. The flake-gate workflow exists specifically to
distinguish a transient runner artifact (rare; usually a hosted-CI
runner ENOSPC or OOM) from a real race. If 10 consecutive runs are
green and one in fifty is red and reproducible nowhere, that's
plausibly the runner. Anything closer to "flakes in less than 10
runs" is a real bug.

## Adding new tests

1. **State-mutating? Use `E2eNode::fresh()` (or `boot_with(&[...])`).**
   Read-only assertions can share the smoke node, but anything that
   mines, broadcasts, or subscribes needs its own boot.
2. **Poll, don't sleep.** Use `common::poll_until_json(probe,
   predicate, deadline_secs)` for any JSON probe. The deadline is
   scaled by `e2e_test_timeout(secs)` automatically.
3. **Use the shared helpers.** `DeterministicWallet::from_secret`,
   `build_signed_p2wpkh_spend_from_block1_coinbase`,
   `EsploraClient::{get, post_tx, post_tx_with_content_type}`,
   `sat_cli_for(&node)`. New surface? Add a similar thin wrapper, not
   raw `reqwest` calls scattered through test bodies.
4. **Name tests `test_e2e_<surface>_<assertion>`.** The group prefix
   (`jsonrpc`, `esplora`, `electrum`, `cross_surface`) helps when
   triaging a CI failure log.

## Cross-reference

- Per-surface tests live in groups within `satd/tests/e2e.rs`. The
  cross-surface test sits at the bottom of that file and is the only
  one that asserts on more than one surface in a single test.
- Shared harness: `satd/tests/common/mod.rs`. Lifted from
  `regtest.rs` to be reusable by both integration-test binaries.
- The non-E2E regtest harness still lives in `satd/tests/regtest.rs`
  and remains the right place for handler-level / RPC-shape tests
  that don't need a real wire client.
