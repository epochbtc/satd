# Stability & Compatibility Policy

This document defines satd's stability contract with integrators — BTCPayServer, NBXplorer, Umbrel, Start9, Sparrow, Electrum-personality clients, Fulcrum-personality clients, block explorers, any BDK-based wallet pointed at our APIs. It governs when we can change what, how removals are staged, and what invariants we hold across upgrades.

### Pre-1.0 (`0.x`) Application
While `satd` is in its `0.x` pre-1.0 phase, we strive to follow these rules to the greatest extent possible. However, to maintain development velocity, we reserve the right to accelerate deprecations (e.g., removing a surface in a subsequent `0.x` release rather than waiting 4 full releases). We will, however, always endeavor to provide clean migration paths and adhere to the state-management invariants described below. Once `1.0` is reached, the full deprecation cycles will be strictly enforced.

Every rule here is grounded in real-world observations from Bitcoin ecosystem release cycles. Each rule is annotated with the specific historical context it addresses. This is a binding policy on satd releases.

---

## Scope

Surfaces covered by this policy, in descending order of stability guarantee.

### Tier 1 — strict

Minimum 4-release deprecation cycle. Never removed without a resurrection flag.

- Bitcoin Core-compatible JSON-RPC wire shape: method names, response field names + types, error codes, pagination semantics.
- P2P wire protocol (standard Bitcoin messages — any satd-specific messages are Tier 2 unless explicitly promoted).
- Electrum protocol server semantics (the in-process server gated by `--electrum=1`; `electrum-proto` crate). Includes wire-protocol method shapes, subscription notification shapes, and TLS option semantics.
- Esplora REST paths and response shapes (the in-process server gated by `--esplora=1`; `esplora-handlers` crate). Includes route paths, JSON shapes, SSE event names + payloads, and auth modes.
- CLI flag names and default values (`-datadir`, `-prune`, `-txindex`, etc.).
- `bitcoin.conf` / `satd.conf` key names and defaults.
- On-disk directory layout names (`blocks/`, `chainstate/`, `indexes/`).
- Structured log JSON schema (`level`, `target`, `msg`, and any promoted field).
- `/health` and `/metrics` endpoint contracts.

### Tier 2 — moderate

Minimum 1 major-release deprecation cycle. Removal requires canary CI pass.

- satd-specific RPC extensions (opt-in per request, per the existing opt-in-rigor rule).
- `/metrics` label schema.
- Log line content (structure stays Tier 1; wording may change).
- Internal index file formats whose contents are externally readable.
- Streaming events gRPC API (`satd.events.v1`) and the Rust / Go SDKs (`satd-events-client`, `satdevents`) — see [Streaming API & SDK compatibility](#streaming-api--sdk-compatibility).

### Tier 3 — no stability guarantee

Must be clearly documented as unstable in the surface itself (`--help`, endpoint response, etc.).

- Experimental IPC surfaces (anything documented as unstable in its own `--help` or response).
- MCP tool schemas (the `rmcp` crate is version-gated; downstream MCP clients pin versions).
- Debug RPCs (`debug_*`, `test_*`).
- The status page's `/status.json`. It exists for the page's own refresh; build on `/metrics` or RPC instead.
- Undocumented fields (their existence alone does not make them Tier 1).

### Explicitly out of scope

satd does not implement Bitcoin Core's legacy wallet. Core's v30 removal of `addmultisigaddress`, `dumpprivkey`, `dumpwallet`, the `import*` family, `sethdseed`, `upgradewallet`, `include_watchonly`, `iswatchonly`, and the BDB wallet format is a surface we never exposed, so the corresponding downstream break is not one we can reproduce directly. PSBT construction, descriptor parsing, and external-signer coordination are in scope and subject to this policy.

---

## Streaming API & SDK compatibility

**Streaming API & SDKs (`satd.events.v1` over gRPC; `satd-events-client`, `satdevents`).**

- An SDK works with any node that speaks the same `schema_version` and is **at or above the SDK's own version**. New event kinds, categories and request fields are additive within a schema version; a node newer than its SDK simply carries features the SDK cannot ask for.
- An SDK **newer than its node** logs a warning when the node is **one minor version behind**, and **refuses to connect** when it is **two or more minor versions behind** (or a major version behind). Operators mid-upgrade can downgrade the refusal to a warning with an explicit opt-in.
- A `schema_version` mismatch is always a hard error, in either direction.
- **Request fields must degrade to a superset.** A new `SubscribeRequest` / `SubscribeControl` field, when ignored by an older node that predates it, must yield the same events or *more* — never fewer or different ones. A field that cannot satisfy this needs a schema bump. (Reviewers check this on every proto addition; it is what makes "warn" safe instead of "wrong data".)
- Both SDKs carry the node's version number. The Rust crate inherits the workspace version; the Go module is tagged `clients/go/vX.Y.Z` with the node's `X.Y.Z` at the same release commit.

The SDKs do not track which node version introduced which feature. The whole mechanism is two numbers and one comparison, made each time a stream opens.

**How a node advertises itself.** Every `Subscribe` and `Watch` response carries two gRPC response headers, sent when the stream opens and before any event:

| Header | Value |
|---|---|
| `satd-version` | The node's version, e.g. `0.6.0` or `0.6.0-pre`. |
| `satd-events-schema` | `NodeEvent.schema_version` as a decimal string, e.g. `1`. |

Nodes before 0.6.0 send neither header. An SDK treats a missing (or unparseable) `satd-version` as `0.5` and a missing `satd-events-schema` as `1`. Only major and minor versions are compared; the patch number and any `-pre` suffix are ignored.

---

## Deprecation and removal

**Minimum deprecation period for Tier 1:** four releases. A removal is not even eligible for consideration until the feature has been marked deprecated, emitted a warning on use, and had a documented replacement published for four major releases.

**Resurrection flag required.** Every Tier 1 removal ships with a `-deprecatedrpc=<name>` / `-legacy-<flag>` escape hatch that survives at least two major releases past the removal. The flag is announced in release notes and `--help`.

> *Historical Context:* Core v31 (2026-04-19) removed `settxfee` / `-paytxfee` with no escape hatch, but granted one to `startingheight`. Inconsistent resurrection policy is worse than a uniform one — infra maintainers can't predict what they'll have to rewrite.

**Removal budget:** no more than two Tier 1 removals per major release, and never two from the same subsystem in the same release.

> *Historical Context:* Core v30 (2025-10) removed 11 legacy wallet RPCs in a single release. BTCPay still carries a bash-paste workaround layer in `dockerfile-deps/Bitcoin/*/docker-entrypoint.sh` because the cohort was too large to absorb in one upgrade cycle.

**Deprecation ≠ scheduled removal.** Marking something deprecated means "discouraged for new code," not "will be deleted in N+2." Deletion requires a separate, deliberate proposal with a demonstrated migration story covering at least BTCPayServer, Umbrel, and Start9 integrations.

> *Historical Context:* Nicolas Dorier's 2019 argument in [bitcoin/bitcoin#16725](https://github.com/bitcoin/bitcoin/pull/16725) — the automatic-removal-after-deprecation habit silently breaks explorers and downstream signers that were never on anyone's radar when the deprecation was agreed.

---

## Migration invariants

These are hard constraints on upgrade paths. Violating any of them is a release blocker.

### 1. Auto-migrate on load; never error-and-punt.

If vN+1 requires format X and vN produced format Y, satd reads Y on startup, produces X in place, logs one `INFO` line, and proceeds. "Upgrade breaks existing installs until the user does X" is never acceptable.

### 2. Validation tightenings are breaking changes.

A new `require()` that rejects previously-valid data counts as a break. It triggers the same deprecation cycle and the same migration obligation as a format change.

> *Historical Context:* Core v31's `"Wallet name cannot be empty"` change — a pure validation addition that invalidates the empty-named default wallet Core itself had shipped for years. Dorier's 2026-04-21 X thread (3:54 AM, 21.9K views) documents the 200-line bash workaround it cost BTCPay. No bytes on disk changed; the impact was identical to a format change.

### 3. Do not break your own historical defaults.

Default values — config keys, directory names, index choices, default-on features — are part of the API contract. If we change a default, we handle the old value transparently on load, forever. Not for one release. Forever.

### 4. Backward-compat shim is the default; strict mode is opt-in.

When a validation or parsing rule tightens, the old permissive behavior stays the default for a full major-release cycle. New strictness ships behind a `--strict-<thing>` flag and is surfaced in release notes as an opt-in. Integrators decide when to flip it.

### 5. Move-aside, never delete, on migration.

Migrations may create new files, rename old ones, or abort. They may **never** call `unlink` / `rmdir` on user state — blocks, chainstate, indexes, or any future persistent storage. Migration code must:

- Write a pre-migration backup manifest to disk before any rename.
- Provide a `--dry-run` mode that prints the exact rename / create plan.
- Be covered by a fuzzing job over representative directory layouts.

> *Historical Context:* Core 30.0/30.1's `migratewallet` under `-walletdir` + pruning deleted the entire wallet directory in an error path. Binaries were pulled from bitcoincore.org on [2026-01-05](https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/); fix shipped in 30.2 on 2026-01-10. Root cause: a delete in an error branch, with no move-aside discipline and no pre-migration backup.

---

## Compatibility canary

Canaries gate every PR merge (not just release candidates) and boot real downstream integrations against the candidate satd to verify they come up clean. These are not test suites — they are real deployment artifacts. The bundled-Electrum / bundled-Esplora architecture is satd's headline claim; a regression that silently breaks Sparrow, BlueWallet, BDK, NBXplorer, or BTCPay invalidates that claim. Better to feel the pain of a flaky downstream blocking merges than to ship a release where the headline architecture quietly regressed.

### Currently gating

- **Esplora wire-shape canary** (`scripts/canary/esplora-smoke.sh`) — raw `curl` + `jq` against documented endpoints (`/blocks/tip/{height,hash}`, `/block/:hash`, `/address/:addr/{utxo,txs}`, `/tx/:txid/{,/hex,/outspends}`, `/mempool`, `/fee-estimates`). Catches wire-format breaks at a layer below the Rust `esplora-client` crate.
- **Electrum wire-shape canary** (`scripts/canary/electrum-smoke.sh`) — raw `nc` line-delimited JSON-RPC against `server.version`, `server.banner`, `blockchain.headers.subscribe`, `blockchain.estimatefee`, `blockchain.relayfee`. Catches wire-format breaks at a layer below the Rust `electrum-client` crate.
- **In-tree Electrum + Esplora protocol suite** (`satd/tests/e2e.rs`, PR-gated via `ci.yml`) — drives satd via the Rust `electrum-client` crate (same library BDK consumes) and `reqwest` for Esplora. Deeper protocol coverage than the wire-shape canaries above, complementary to them.
- **BDK descriptor-wallet canary** (`scripts/canary/bdk-smoke.sh` + the standalone `scripts/canary/bdk-canary` crate) — drives a real third-party wallet (`bdk_wallet` + `bdk_electrum` + `bdk_esplora`, the canonical consumer of both surfaces) through a full descriptor-wallet workflow against a live satd: gap-limit `full_scan` over **both** Electrum and Esplora with the same descriptor, coinbase-maturity accounting, a signed spend broadcast via Esplora `POST /tx` and observed over Electrum (cross-surface), and a confirm step — asserting the two surfaces report byte-identical balances at every stage. The real-consumer gate for the Electrum + Esplora surfaces (analogous to what NBXplorer/BTCPay are for the Core-client surface): exercises the realistic wallet path the wire-shape smoke jobs and per-endpoint oracles don't. Surfaced and now guards the Esplora coinbase-`vin` shape break (omitted `txid`/`vout`/`prevout`) that made strict typed clients fail to deserialize any coinbase-funded tx. The harness is a standalone cargo project (its own workspace + lockfile) so BDK's dependency tree never enters satd's own build.
- **NBXplorer integration canary** (`scripts/canary/nbxplorer-smoke.sh`) — boots the real `nicolasdorier/nbxplorer` Docker container (with a Postgres sidecar, required by NBXplorer 2.5+) against a satd regtest backend and asserts it handshakes, passes its RPC probe, and fully syncs **and indexes** 10 mined blocks over P2P. The first canary exercising a real third-party downstream end-to-end (RPC + P2P + block download), not an in-tree library. Surfaced and now guards four satd↔Core-client compatibility gaps: JSON-RPC 1.0/1.1 request acceptance, `getpeerinfo` field completeness (`timeoffset`/`inflight`), the per-IP inbound cap vs. loopback, and P2P new-tip block announcement. (The earlier `node is not in a connected state` symptom was a downstream artifact of those gaps — diagnosed and fixed, not a P2P-handshake defect.)
- **BTCPayServer canary** (`scripts/canary/btcpay-smoke.sh`) — boots the full `btcpayserver/btcpayserver` + NBXplorer + Postgres stack against a satd backend and asserts `GET /api/v1/health` reports `synchronized: true`. The top-of-stack, end-to-end "self-custody merchant stack runs on satd unmodified" gate; rides on the same satd surface the NBXplorer canary guards.
- **Electrum reference-wallet canary** (`scripts/canary/electrum-wallet-smoke.sh`) — runs the actual Electrum wallet (`spesmilo/electrum`, the canonical client) headless against satd's Electrum server. Distinct from the BDK canary (which drives the surface via the `electrum-client` library) and the `electrum-smoke` wire canary (raw `nc`): the reference wallet does **SPV** — it syncs and verifies the header chain (`blockchain.block.headers`) and checks **merkle proofs** (`blockchain.transaction.get_merkle`) for its txs. Asserts Electrum connects + SPV-syncs to satd's tip, then that a funded+matured wallet address yields an SPV-verified confirmed balance.
- **Core Lightning (CLN) canary** (`scripts/canary/cln-smoke.sh`) — runs a real CLN node (`elementsproject/lightningd`) with satd as its Bitcoin backend over JSON-RPC (the `bcli` plugin; no ZMQ). Exercises a strict slice of the RPC surface — `getchaininfo`, `getrawblockbyheight`, `getutxout`, `estimatefees`, `sendrawtransaction` — that other consumers don't hit the same way. Asserts CLN syncs against satd (`getinfo` blockheight == tip) and that a funded+matured wallet address shows in `listfunds`. Surfaced the Core-amount formatting fix (satd emitted BTC amounts as `0.00001` rather than Core's fixed-8-decimal `0.00001000`, which CLN's `bcli` `json_to_bitcoin_amount` parser rejected, blocking CLN startup).
- **LND Neutrino canary** (`scripts/canary/lnd-neutrino-smoke.sh`) — runs a real LND node (`lightninglabs/lnd`) as a BIP 157/158 light client (Neutrino) backed by satd over P2P. The dominant Lightning light-client backend; it is the only canary exercising satd's compact-block-filter serving over P2P (`--peerblockfilters=1` → `NODE_COMPACT_FILTERS`, `getcfilters`/`getcfheaders`/`getcfcheckpt`). Asserts LND reaches `synced_to_chain` at satd's tip, then that a single filter-matched funding block is selectively downloaded (the other ~110 synced by filter header alone) and credited to LND's wallet — the filter-match → targeted-block-download → wallet-credit path.
- **Bitcoin Core interop canary** (`scripts/canary/core-interop-smoke.sh`) — the only canary that tests satd against the reference implementation itself. Peers satd with a real `bitcoind` (the `bitcoin/bitcoin` image) regtest node and asserts bidirectional P2P interop: handshake + peer identity, **BIP 324 v2 encrypted transport** negotiation, block sync in **both** directions (satd↔Core), and tx relay in **both** directions. Catches consensus/relay/wire drift vs. Core directly rather than via a downstream's tolerance. Surfaced and now guards two satd P2P bugs: `getdata MSG_CMPCT_BLOCK` was silently dropped (so satd-mined blocks never reached a Core peer that requested the tip as a compact block), and `sendrawtransaction`-submitted txs were never announced to peers (so RPC broadcasts never propagated to the network).
- **Stratum V1 canary** (`scripts/canary/stratum-v1-smoke.sh`) — runs cpuminer, the Stratum V1 CPU miner the Stratum V2 Reference Implementation's own integration tests drive, against satd's Stratum V1 server on regtest. Asserts it authorizes with an `address.worker` username, finds a block through `mining.notify` / `mining.submit` that connects and pays its address, and is sent the job for a tip it did not mine.
- **Stratum V2 canary** (`scripts/canary/stratum-v2-smoke.sh`) — runs the Stratum V2 Reference Implementation's CPU miner (`mining_device`, built from the pinned `sv2-apps` tag) against satd's Stratum V2 listener. Asserts the Noise handshake succeeds with the server's authority key pinned and is refused with any other key, a standard channel opens, and the miner finds block after block across new tips. Surfaced the new-work starvation fixed before Stratum shipped: a session that served a miner's frames ahead of new work never sent the job for the tip the miner's own block made.
- **Stratum V2 Job Declaration canary** (`scripts/canary/stratum-jd-smoke.sh`) — runs the reference Job Declaration client, with a Bitcoin Core node peered with satd as its template source over IPC, and `mining_device` behind it. Asserts `AllocateMiningJobToken`, `DeclareMiningJob` with a real mempool transaction, and `SetCustomMiningJob` all succeed against satd, and that the declared job is mined into a block that connects, contains the transaction and pays the token's address. Surfaced the coinbase-prefix length check that refused the reference client's every custom job.

The canaries above run on `.github/workflows/canary.yml`, triggered on `pull_request`, weekly cron, and `workflow_dispatch`. They are marked as required status checks on the `master` branch protection.

### Keeping the pins current

Every downstream version the canaries run is pinned in one manifest, [`scripts/canary/PINS`](scripts/canary/PINS): container images by tag *and* digest (a tag can be re-pushed; a digest cannot), the Electrum AppImage by version and SHA-256. BDK is the exception, pinned by the canary crate's own `Cargo.lock`. The canary scripts, workflows and Rust harnesses read the manifest, and CI Lint runs `scripts/canary/pins.py check` so that nothing hard-codes a version beside it.

A canary pinned to a release nobody runs any more proves compatibility with nobody. The cadence:

- **Weekly.** The scheduled canary run's `Canary pin freshness` job compares every pin with upstream's newest stable release and keeps one issue, *Canary pins are behind upstream*, current: opened or updated while anything is behind, closed once nothing is.
- **Each release cycle.** The PR that opens a development cycle is followed by one that bumps every pin to its newest stable release and runs the canaries.
- **Out of band.** A downstream major release, or a release that fixes a security issue, is taken within two weeks.
- **At release time.** `scripts/canary/pins.py gate` must pass before a tag is pushed. It fails when a pin is more than one major version behind upstream (for `0.x` versions, the minor counts as the major), or behind a release that is more than six months old.

A bump that breaks a canary follows the failure triage below: if the break is satd's, fix it; if it is the downstream's, pin back to the last good release, file an issue, and record it in the manifest as `HOLD_<NAME>=<issue number>`. A held pin passes the gate, and stays visible in the weekly table, until the hold is removed. Sidecar images (Postgres, the Debian base Electrum runs in) are pinned for reproducibility but not tracked: their major versions are a choice, and a bump refreshes their digests.

#### Running the fleet with the opt-in surfaces enabled

By default every canary boots satd at stock defaults, which is what a downstream client actually meets and what PR gating should hold still. A separate question matters at release time: does *enabling* satd's opt-in surfaces perturb any downstream client? Dispatch the workflow with `features: on` to answer it — `scripts/canary/boot-satd.sh` then adds the silent-payment index, the events gRPC listener, the streaming WebSocket listener and an alert-webhook dispatcher to every node the fleet boots.

The profile is fixed inside `boot-satd.sh` rather than passed per job, so that "the fleet is green with the features enabled" means one definite configuration. Two consequences worth knowing:

- The two streaming listeners bind port `0` and nothing connects to them, and the webhook endpoint is the discard port. The surfaces are *running*, not *exercised*; what is under test is whether a node carrying that extra work still serves Esplora, Electrum, RPC and P2P identically.
- The Bitcoin Core block-acceptance differential job does not use `boot-satd.sh` (it drives satd from a Rust integration test), so it runs at defaults regardless of the input.

A `features: on` run writes its mode into the run title (`Canary (features=on)`), and the feature mode is part of the concurrency key, so a dispatch cannot be cancelled by the weekly cron on the same ref.

Expect retry noise in the log of a `features: on` run. The alert webhook points at the discard port, so every delivery attempt is refused and retried with backoff until it ages out. Lines like `webhook request failed; retrying` are the configuration working, not a fault to chase.

**Cutting a release requires one green `features: on` dispatch run** on the release commit, in addition to the PR-gating runs at defaults.

### Deferred

Listed for traceability; each will enter PR-gating on the same terms when its prerequisites are met:

- **Umbrel app**: install the satd Umbrel app on an Umbrel dev image; verify the dashboard reports the node as healthy. Blocked on shipping the satd Umbrel app first (see `ROADMAP.md` → "Ecosystem & Mobile Integration").

### Failure triage

A canary failure on a PR is treated as load-bearing, not a flake to dismiss. Diagnose in this order:

1. **Did this PR cause it?** Compare the diff to the failure mode. If yes, the PR author fixes or reverts.
2. **Is this a downstream-side regression?** Pin the affected downstream to the last-known-good version in the canary workflow, open a tracking issue, then unblock PRs.
3. **Is this an infrastructure flake** (image registry 5xx, transient network)? Rerun once via `workflow_dispatch`. If it fails again, treat as case (2).

**Never** mark a canary advisory-only as a flake response. The escape valve is to pin the downstream to a known-good version, not to weaken the gate.

> *Historical Context:* Core runs no such job. This is the single largest reason infra maintainers learn about breakages from user bug reports rather than from release notes. It is also the cheapest structural fix any node project can adopt.

---

## Infra liaison

One satd maintainer holds the explicit role of **infra liaison** per release cycle:

- Reviews every PR touching an RPC, CLI, config, on-disk, or API surface for downstream impact.
- Holds authority to block a removal or validation tightening that lacks a documented migration path.
- Is named in the release notes for each cycle.
- Rotates annually among the core maintainers.

> *Historical Context:* In large open-source projects, merge authority can sometimes concentrate without a dedicated advocate for downstream infrastructure maintainers. We establish this role to explicitly own infra-maintainer impact.

---

## Cultural rule

Adopt Linus Torvalds' posture for Tier 1: **we do not break userspace**. If an upgrade breaks an existing user's setup, it is our bug, not theirs. The fact that the old behavior was underdocumented, underspecified, or "shouldn't have worked" is irrelevant: they relied on it, we shipped it, we own the migration.

This posture is the backstop to every rule above. The other rules exist so that following this rule is feasible.

---

## References

- Bitcoin Core v31.0 release notes (2026-04-19).
- Bitcoin Core v30.0 release notes (2025-10) — legacy wallet RPC cohort removal.
- [bitcoincore.org wallet-migration-bug advisory, 2026-01-05](https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/).
- Nicolas Dorier, X `@NicolasDorier`, 2026-04-21 03:54 AM — `"Wallet name cannot be empty"` break, BTCPay 200-line workaround.
- [bitcoin/bitcoin#35055](https://github.com/bitcoin/bitcoin/issues/35055) — Vinnie Falco governance brief, 2026-04-11.
- [bitcoin/bitcoin#16725](https://github.com/bitcoin/bitcoin/pull/16725) — NicolasDorier, 2019, on explorer-breaking removals.
- [PR #31278](https://github.com/bitcoin/bitcoin/pull/31278) — Core v30.0 deprecation of `settxfee` / `paytxfee`.
- [PR #32138](https://github.com/bitcoin/bitcoin/pull/32138) — Core v31.0 removal of `settxfee` / `paytxfee`.
- [btcpayserver/dockerfile-deps](https://github.com/btcpayserver/dockerfile-deps) — BTCPay's accumulated Core-compatibility shim layer.
