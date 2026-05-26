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

### Tier 3 — no stability guarantee

Must be clearly documented as unstable in the surface itself (`--help`, endpoint response, etc.).

- IPC / gRPC experimental surfaces.
- MCP tool schemas (the `rmcp` crate is version-gated; downstream MCP clients pin versions).
- Debug RPCs (`debug_*`, `test_*`).
- Undocumented fields (their existence alone does not make them Tier 1).

### Explicitly out of scope

satd does not implement Bitcoin Core's legacy wallet. Core's v30 removal of `addmultisigaddress`, `dumpprivkey`, `dumpwallet`, the `import*` family, `sethdseed`, `upgradewallet`, `include_watchonly`, `iswatchonly`, and the BDB wallet format is a surface we never exposed, so the corresponding downstream break is not one we can reproduce directly. PSBT construction, descriptor parsing, and external-signer coordination are in scope and subject to this policy.

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

The wire-shape canaries above run on `.github/workflows/canary.yml`, triggered on `pull_request`, weekly cron, and `workflow_dispatch`. They are marked as required status checks on the `master` branch protection.

### Deferred

Listed for traceability; each will enter PR-gating on the same terms when its prerequisites are met:

- **NBXplorer integration canary** (`scripts/canary/nbxplorer-smoke.sh`) — runs the real `nicolasdorier/nbxplorer:<pin>` Docker container (with a Postgres sidecar, required by NBXplorer 2.5+) against a satd regtest backend. Postgres + container plumbing is wired up and works; the open issue is a P2P version-handshake interop with NBitcoin (NBXplorer's underlying lib) that surfaces as `node is not in a connected state` after TCP connect — needs deeper investigation. Job definition is commented out in `canary.yml`; the script in `scripts/canary/nbxplorer-smoke.sh` is left in-tree so the follow-up PR is small.
- **BTCPayServer**: boot `btcpayserver/btcpayserver` with satd as the Bitcoin backend; verify `/api/v1/server/info` responds healthy. Deferred because the BTCPay stack is a multi-container docker-compose (Postgres + NBXplorer + BTCPay + optional Tor) — a follow-up PR will compose this on top of the NBXplorer canary infrastructure.
- **Umbrel app**: install the satd Umbrel app on an Umbrel dev image; verify the dashboard reports the node as healthy. Blocked on shipping the satd Umbrel app first (`ECOSYSTEM.md` §6).

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
