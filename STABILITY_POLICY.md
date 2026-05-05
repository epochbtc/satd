# Stability & Compatibility Policy

This document defines satd's stability contract with integrators — BTCPayServer, NBXplorer, Umbrel, Start9, Sparrow, Electrum-personality clients, Fulcrum-personality clients, block explorers, any BDK-based wallet pointed at our APIs. It governs when we can change what, how removals are staged, and what invariants we hold across upgrades.

Every rule here is grounded in an observed incident from Bitcoin Core's 2025–2026 release cycle. Each rule is annotated with the specific scar it answers. This is not an aspirational ethics statement; it is a binding policy on satd releases.

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

> *Scar:* Core v31 (2026-04-19) removed `settxfee` / `-paytxfee` with no escape hatch, but granted one to `startingheight`. Inconsistent resurrection policy is worse than a uniform one — infra maintainers can't predict what they'll have to rewrite.

**Removal budget:** no more than two Tier 1 removals per major release, and never two from the same subsystem in the same release.

> *Scar:* Core v30 (2025-10) removed 11 legacy wallet RPCs in a single release. BTCPay still carries a bash-paste workaround layer in `dockerfile-deps/Bitcoin/*/docker-entrypoint.sh` because the cohort was too large to absorb in one upgrade cycle.

**Deprecation ≠ scheduled removal.** Marking something deprecated means "discouraged for new code," not "will be deleted in N+2." Deletion requires a separate, deliberate proposal with a demonstrated migration story covering at least BTCPayServer, Umbrel, and Start9 integrations.

> *Scar:* Nicolas Dorier's 2019 argument in [bitcoin/bitcoin#16725](https://github.com/bitcoin/bitcoin/pull/16725) — the automatic-removal-after-deprecation habit silently breaks explorers and downstream signers that were never on anyone's radar when the deprecation was agreed.

---

## Migration invariants

These are hard constraints on upgrade paths. Violating any of them is a release blocker.

### 1. Auto-migrate on load; never error-and-punt.

If vN+1 requires format X and vN produced format Y, satd reads Y on startup, produces X in place, logs one `INFO` line, and proceeds. "Upgrade breaks existing installs until the user does X" is never acceptable.

### 2. Validation tightenings are breaking changes.

A new `require()` that rejects previously-valid data counts as a break. It triggers the same deprecation cycle and the same migration obligation as a format change.

> *Scar:* Core v31's `"Wallet name cannot be empty"` change — a pure validation addition that invalidates the empty-named default wallet Core itself had shipped for years. Dorier's 2026-04-21 X thread (3:54 AM, 21.9K views) documents the 200-line bash workaround it cost BTCPay. No bytes on disk changed; the impact was identical to a format change.

### 3. Do not break your own historical defaults.

Default values — config keys, directory names, index choices, default-on features — are part of the API contract. If we change a default, we handle the old value transparently on load, forever. Not for one release. Forever.

### 4. Backward-compat shim is the default; strict mode is opt-in.

When a validation or parsing rule tightens, the old permissive behavior stays the default for a full major-release cycle. New strictness ships behind a `--strict-<thing>` flag and is surfaced in release notes as an opt-in. Integrators decide when to flip it.

### 5. Move-aside, never delete, on migration.

Migrations may create new files, rename old ones, or abort. They may **never** call `unlink` / `rmdir` on user state — blocks, chainstate, indexes, or any future persistent storage. Migration code must:

- Write a pre-migration backup manifest to disk before any rename.
- Provide a `--dry-run` mode that prints the exact rename / create plan.
- Be covered by a fuzzing job over representative directory layouts.

> *Scar:* Core 30.0/30.1's `migratewallet` under `-walletdir` + pruning deleted the entire wallet directory in an error path. Binaries were pulled from bitcoincore.org on [2026-01-05](https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/); fix shipped in 30.2 on 2026-01-10. Root cause: a delete in an error branch, with no move-aside discipline and no pre-migration backup.

---

## Compatibility canary

Every satd release candidate blocks on a CI job that boots real downstream integrations against the RC image and verifies they come up clean. These are not test suites — they are real deployment artifacts.

Mandatory canaries:

- **BTCPayServer**: boot `btcpayserver/btcpayserver` with satd as the Bitcoin backend; run their `dockerfile-deps` entrypoint; verify `/api/v1/server/info` responds healthy.
- **NBXplorer**: boot against satd; index recent regtest blocks; verify callback delivery.
- **Umbrel app**: install the satd Umbrel app on an Umbrel dev image; verify the dashboard reports the node as healthy.
- **Electrum-personality canary**: boot satd with `--electrum=1`; run an Electrum-client smoke suite (BlueWallet, Sparrow, or Electrum desktop in headless mode) against the endpoint; verify `server.version` handshake, `blockchain.scripthash.subscribe` notifications on a regtest mining tick, and `blockchain.transaction.broadcast` round-trip.
- **Esplora canary**: boot satd with `--esplora=1`; run BDK's Esplora integration tests against the endpoint; verify wire-shape parity for the implemented endpoint set.

The canary is not advisory. A failing canary blocks the RC until either the downstream is patched with our active support, or the breaking change is reverted. The canary matrix is versioned and its failures are archived with each RC.

> *Scar:* Core runs no such job. This is the single largest reason infra maintainers learn about breakages from user bug reports rather than from release notes. It is also the cheapest structural fix any node project can adopt.

---

## Infra liaison

One satd maintainer holds the explicit role of **infra liaison** per release cycle:

- Reviews every PR touching an RPC, CLI, config, on-disk, or API surface for downstream impact.
- Holds authority to block a removal or validation tightening that lacks a documented migration path.
- Is named in the release notes for each cycle.
- Rotates annually among the core maintainers.

> *Scar:* [bitcoin/bitcoin#35055](https://github.com/bitcoin/bitcoin/issues/35055) (Vinnie Falco's governance brief, 2026-04-11) documents Core's merge authority concentrating ~65% on one maintainer in 2025–2026. No one structurally owned infra-maintainer impact. We don't replicate that.

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
