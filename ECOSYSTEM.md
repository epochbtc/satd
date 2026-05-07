# Ecosystem Integration — Mobile + Packaging

Strategic direction for how satd integrates with the broader Bitcoin ecosystem: which mobile clients we target, which API surfaces we expose, and how we make satd easy to package for self-custody stacks (Umbrel, Start9, RaspiBlitz, MyNode, BTCPay, home-server distros).

Not a milestone spec. This doc guides future milestones and informs packaging / API decisions as they arise. Implementation status of each surface listed below is captured in `CORE_DIFFERENCES.md` and the "shipped" markers in `OPERATOR_ERGONOMICS.md`.

---

## Context: mobile full nodes are not the goal

A full validating Bitcoin node running 24/7 on a phone is neither technically feasible on iOS (no persistent P2P sockets while backgrounded, `BGProcessingTask` only grants burst windows while idle + charging) nor desirable (CGNAT free-rider, soft-fork upgrade drift, battery, bandwidth). No production mobile app ships one today. The entire mobile Bitcoin ecosystem — Blockstream/Green, Breez, Zeus, Mutiny, BDK — has converged on **BIP 157/158 compact block filters** or **Electrum / Esplora** against a trusted node.

AssumeUTXO helps the one-shot initial sync but does nothing for 24/7 operation cost, which is where iOS/Android background limits actually bite.

**Our model:** the mobile app holds keys and scans filters; **satd runs on the user's home server or Pi** and serves filters, mempool, blocks, history, and broadcast. One trusted party — the user themselves — and no custodial intermediary.

---

## Part 1 — Mobile integration: API surfaces

### Target outcome

A user who runs satd on a home server (or Pi) can point existing mobile wallets — BlueWallet, Nunchuk, Sparrow, Zeus, Mutiny — at their node over Tor/.onion with **no new native mobile client to build or maintain**. The wallet ecosystem is mature; we become the server half.

### Wallet-to-backend landscape

| Wallet | Backend protocol |
|---|---|
| BlueWallet, Nunchuk, Sparrow, Electrum | Electrum protocol |
| Sparrow (also) | Bitcoin Core JSON-RPC |
| Mutiny, BDK-based wallets | Esplora REST |
| Zeus (remote mode) | LND gRPC / REST |
| Zeus-embedded, Blixt, legacy Breez | BIP 157/158 P2P |
| Phoenix | ACINQ-trampolined (custodial-ish) |

On-chain wallets are dominated by **Electrum protocol**. LN-focused wallets split between embedded-Neutrino (BIP 157/158) and remote-LND (gRPC).

### Surfaces satd should expose, ranked by leverage

1. **Electrum protocol server.** ✅ Shipped (`electrum-proto` crate; `--electrum=1`). Largest wallet install base by far. Native implementation in-tree, sharing satd's chainstate (see Part 2 §4 for architecture and §4a for implementation strategy). Unlocks BlueWallet, Nunchuk, Sparrow, Electrum, and most hardware-wallet coordinators in one move.
2. **Esplora REST API.** ✅ Shipped (`esplora-handlers` crate; `--esplora=1`, on by default on loopback). Wire-shape parity with `blockstream.info` / `mempool.space` for the implemented endpoint set. Shares the address-history index with the Electrum server. Unlocks BDK-based wallets and Mutiny-alikes.
3. **BIP 157/158 P2P service.** ✅ Shipped (`node-filter-index` crate; `--blockfilterindex=basic --peerblockfilters=1`). `getcfilters` / `getcfheaders` / `getcfcheckpt` over standard P2P. Zeus-embedded / Blixt users can `addpeer` our .onion. Covers the LN-focused on-device validation niche.
4. **Bitcoin Core-compatible JSON-RPC** ✅ Shipped (80 methods). Protected by `STABILITY_POLICY.md` Tier 1 so Sparrow desktop, BTCPay, NBXplorer, and legacy scripts "just work."
5. **LND-compatible gRPC/REST** *(deferred)*. Would let Zeus / other LND-aware wallets treat satd as "my remote LND." Large surface; only worth it if we decide to go LN-first.

### Cross-cutting capabilities (enabled across multiple surfaces)

- **Mempool visibility** — accurate fee estimation, 0-conf incoming UX, RBF / double-spend detection.
- **Silent Payments (BIP 352) index.** Server-side scanning of every output's ECDH tweak; push only relevant outputs to the phone. Without server-side indexing, SP is impractical on mobile.
- **Push notifications** to the mobile wallet via APNs / FCM on relevant block / tx events so the app doesn't have to stay awake polling.
- **Tor / .onion reachability.** Phone connects over Tor on cellular, works through CGNAT, no port-forwarding, no home-IP leak.
- **txindex + filter service** for fast historical lookups instead of re-scanning from wallet birthday.

### What we explicitly do not build

- A native iOS or Android wallet. The existing wallet ecosystem is mature and well-maintained.
- On-device full-node validation on mobile. See context above.

---

## Part 2 — Packaging for self-custody stacks

### Target outcome

satd is as drop-in as Bitcoin Core for Umbrel, Start9 / StartOS, RaspiBlitz, MyNode, BTCPay Server Deployment, and homebrew / apt users. An Umbrel maintainer can ship a `satd` app with the same ergonomics as their existing `bitcoind` app, and power users on a Pi 5 can swap one for the other with a single config change.

### 1. Release pipeline

- **Multi-arch Docker images** (`linux/amd64`, `linux/arm64`) published to GHCR with stable tags + immutable digests. Table stakes for any container-based packaging.
- **Static / minimally-linked binaries** for `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, attached to GitHub Releases.
- **Reproducible builds** (Guix or Nix). Reference: Bitcoin Core's Guix pipeline. Packagers will not commit to an upstream whose binaries they can't verify.
- **Signing (modern stack, no GPG):**
  - **Tarballs + static binaries** — `minisign` (Ed25519) detached signatures. Public key published in `SECURITY.md` + README; at least two maintainers cross-sign.
  - **Docker images** — `cosign` keyless signing via GitHub Actions OIDC, attested to the Rekor transparency log. Gives SLSA-level provenance automatically; packagers verify against the workflow identity rather than a personal key.
  - **Git tags + maintainer commits** — SSH signatures (`ssh-keygen -Y sign`), verified against maintainers' GitHub-published pubkeys (`github.com/<user>.keys`) via an allowed-signers file. Zero new key infrastructure, matches GitHub's "Verified" badge.
- **Stable semver + public changelog**, explicit RPC-wire deprecation policy.
- **SBOM + `cargo deny`** in CI. Start9 in particular cares about dependency audit.

### 2. Runtime ergonomics

- **Systemd unit** in `contrib/systemd/satd.service`: `Type=notify` with `sd_notify(READY=1)` after RocksDB opens, `StateDirectory=satd`, `LimitNOFILE=65536`, `Restart=on-failure`, `TimeoutStopSec=10min` (RocksDB flush can be slow). OpenRC and runit units for StartOS / Alpine.
- **Clean SIGTERM shutdown** — RocksDB flush, undo-file sync, bounded under 10s. One botched shutdown = one corrupted chainstate = a packager bug ticket.
- **Health endpoint** (`GET /health` or `/rest/chaininfo.json`) returning `{tip, height, ibd, peers, synced}`, responding under 100 ms even during IBD. Both Umbrel and Start9 poll this constantly.
- **Prometheus `/metrics`** endpoint out of the box — block height, mempool size, peer count, RocksDB stats, verify time. Ship a Grafana dashboard JSON in `contrib/grafana/`.
- **Structured JSON logs** to stdout (already available via `tracing-subscriber` JSON layer). Docker log drivers just work.
- **Log noise discipline** — no per-block INFO lines. Packagers debug via `journalctl` and drown in chatty nodes.

### 3. Config + data layout

- Keep `bitcoin.conf`-compatible syntax (already present). Accept both `bitcoin.conf` and `satd.conf`. Every self-custody template assumes this shape.
- Both cookie and userpass RPC auth (already present).
- **Clean state separation** — `$datadir/blocks`, `$datadir/chainstate`, `$datadir/indexes`, `$datadir/wallets` each independently backup-able. Document in `docs/PACKAGING.md` which subdirs are "state" vs. "derived / safe to nuke."
- **First-class pruning + AssumeUTXO UX** — `-prune=N` + `-assumeutxo=<height>` as the documented recommended profile for Pi / resource-constrained deployments.
- **Tor-first defaults available** — `-listenonion`, `-onlynet=onion`, ControlPort auto-discovery. Both platforms run Tor by default.

### 4. Wallet-server protocols (Electrum + Esplora) — architecture

Both protocols ship as **native subsystems inside the satd binary**, gated by runtime flags (`--electrum=1`, `--esplora=1`). The `block-filter-index` Cargo feature additionally allows compiling out the BIP 158 codec entirely for a consensus-only build. The architectural story — and the headline differentiator over the bitcoind + electrs status quo — is that **Electrum and Esplora are query layers over satd's chainstate, not a separate process maintaining a parallel index**.

#### Why native + shared chainstate, not bundled electrs

A bundled-electrs companion solves install-friction but inherits the architectural costs of the two-process world: a duplicate RocksDB address-history index (~30-80 GB on a Pi at mainnet tip), parallel block re-scanning, and a reorg-window race where the Electrum view lags the chainstate. None of those go away by vendoring `electrs` alongside `satd`.

Native + shared chainstate gives:

- **One RocksDB instance.** Same WAL, same crash recovery, same backup target.
- **No duplicate scriptPubKey scanning.** The address-history index is updated inside the existing `connect_block` / `disconnect_block` loop.
- **Atomic reorg consistency.** The index update lives in the same `WriteBatch` as the chainstate update, so protocol handlers can never observe an index out of sync with the tip.
- **Sub-millisecond index lookups.** Function calls, not RPC.

That's the architectural claim worth making in the announcement. A bundled-electrs approach can't earn it.

#### Why a single binary, not separate companion binaries (for v1)

Originally this section proposed separate `sat-electrum` and `sat-esplora` companion binaries. Revisited: a single `satd` binary with feature flags is simpler to ship, package, document, and operate, and the failure-isolation arguments for separation are weaker than they look in modern Rust + tokio code with bounded subscription queues, request timeouts, and per-connection limits.

Concretely:

- **One systemd unit, one Docker image, one log stream, one PID.**
- **One dbcache budget**, one memory allocator, no double-counting RAM.
- **No RocksDB-secondary-mode coordination problem** — RocksDB doesn't allow concurrent writers; secondary-mode read-only access works but adds lag and schema-coordination headaches.
- **Feature flags address the "don't pay for what you don't use" concern.** `cargo build --no-default-features` produces a lean consensus-only binary; default build includes both protocols.

The case for separation gets stronger if Electrum subscriptions turn out to be the dominant memory pressure point in production (mobile wallets subscribing to thousands of scripthashes). Mitigation in v1: bounded subscription cap, per-connection memory accounting, easily-flippable feature flag. If pressure becomes real, a v1.x companion-binary split is cheap because the workspace is already structured as library crates (see §4a).

#### Future split into companion binaries (v2)

If operational data demands process isolation in v2 — e.g. Electrum subscription RAM pressure competing with UTXO cache, or a desire for tighter security boundaries on Tor-exposed protocol surfaces — the workspace structure supports adding `sat-electrum` and `sat-esplora` companion binaries that open the RocksDB datadir in **secondary mode** (read-only with WAL replay). Same library code, different deployment shape. v1.x release, not a rewrite.

This is explicitly deferred. Single-binary v1 is the simpler thing.

### 4a. Implementation strategy for Electrum + Esplora

#### Vendor electrs's protocol code, write the index ourselves

Neither romanz/electrs nor Blockstream/electrs is published as a usable library: romanz's internal modules are private (`mod`, not `pub mod`), Blockstream's is `pub mod` but git-only and never API-stable. In both, RocksDB access is hardcoded — there is no `Store` trait we could implement against satd's chainstate. The literal "import as crates" approach doesn't exist.

The realistic path is to **vendor specific source files** from romanz/electrs (MIT licensed, with attribution and license headers preserved) for the well-tested wire protocol layer, and write the index ourselves against satd's RocksDB. Vendor-worthy files (~1500 LOC total):

- `electrum.rs` — Electrum wire-protocol parsing + JSON-RPC method dispatch.
- `status.rs` — subscription state machine (`ScriptHashStatus`).
- `merkle.rs` — Electrum merkle-proof construction.
- `types.rs` — wire types.

Refactor their `Index` dependency from a concrete type to a small trait we own (~4-5 methods: `funding_for(scripthash)`, `spending_for(scripthash)`, `txids_at(height)`, `header_at(height)`, plus mempool variants).

Esplora REST handlers are a smaller protocol — no upstream borrow needed. Direct handler implementation against the same `Index` trait.

#### Workspace structure

Build the code as library crates so binary count is a packaging decision, not an architectural one:

- `node-index` — address-history index over RocksDB. The load-bearing crate; both protocols depend on it.
- `electrum-proto` — vendored Electrum protocol layer, depends on the `Index` trait from `node-index`.
- `esplora-handlers` — Esplora REST handlers, depends on the same `Index` trait.
- `satd` (binary) — pulls in all three behind feature flags (`electrum`, `esplora`).

Future companion binaries (`sat-electrum`, `sat-esplora` per §4 above) reuse the same library crates with thin `main.rs` shells.

#### Effort estimate (historical, for reference)

The pre-implementation estimate, recorded for posterity:

- **Address-history index** (`node-index` crate): ~3-5 weeks. Column-family layout, IBD-time backfill, online maintenance on connect / disconnect, reorg correctness, mempool tracking.
- **Esplora REST** (native, `esplora-handlers` crate): ~4-8 weeks on top of the index.
- **Electrum** (vendored protocol code, `electrum-proto` crate): ~3-5 weeks of vendoring + adaptation, parallelizable with Esplora.

Both protocols and the index landed in the timeframe estimated. The shipped surfaces are summarized in `CORE_DIFFERENCES.md` §"Native protocol surfaces"; operator flags and tuning live in `OPERATOR_ERGONOMICS.md` and `docs/api/esplora.md`.

#### Alternatives considered and rejected

- **Bundle electrs as a `sat-electrum` companion binary.** Marginal user-visible UX delta over separately-installed electrs (one install vs. two; auto-wired defaults). Does *not* fix the duplicate-index, parallel-block-rescan, or reorg-race problems — those are architectural, not packaging. Doesn't earn the headline.
- **Fork Blockstream/electrs and swap the storage layer.** ~4-6 weeks Electrum-only, ~8-10 with Esplora REST kept working. Inherits Blockstream's three-DB layout, bincode rows, and Liquid feature flags. Larger surface to maintain forever; less clean conceptually than vendoring just the protocol layer.
- **Full reimplementation of Electrum protocol.** ~12-16 weeks. Defensible but pays the cost of re-deriving well-tested wire-protocol parsing for no gain over vendoring.

### 5. Raspberry Pi ergonomics

- **ARM64-specific perf tuning** — benchmark `dbcache`, `maxmempool`, and parallel-verify defaults on 4 GB / 8 GB Pi 5. Don't inherit x86 defaults uncritically.
- **`iowait`-friendly** — batched RocksDB writes; optional `fsync=false` for USB-SSD + UPS setups.
- **Thermal-aware** — back off CPU-bound work under `nice` / `cpuset` throttling.
- **Unclean-shutdown resilience** — assume power-yank is routine; WAL + atomic UTXO batch writes must always survive.
- **Signed AssumeUTXO snapshots** hosted on a CDN (Cloudflare R2, IPFS, or similar) so Pi IBD drops from days to hours.

### 6. Ecosystem outreach (the non-code half)

- `docs/PACKAGING.md` — authoritative description of file layout, signals, health endpoint, config keys, upgrade / migration notes. Packagers read this file first.
- **Open the first Umbrel and Start9 app PRs ourselves.** Don't wait for volunteers.
- Recruit one Umbrel and one Start9 maintainer into early packaging review; their feedback on the first release pays off for every release after.
- **Publicly-reachable reference deployment** — satd on a real Pi 5 with the Umbrel app installed, linked from the README. "It works on my Pi" is less convincing than "here is the Umbrel dashboard."
- Maintainer presence in the relevant Matrix / Discord channels — `#umbrel-dev`, Start9 community, BTCPay ops.

### 7. Minimum-viable "packager-ready" gate

Six items to gate the first packager-friendly tag on:

1. Multi-arch Docker + signed tarballs in GitHub Releases ✅ shipped
2. Reproducible build (Guix or Nix) ✅ shipped (Nix; see `docs/PACKAGING.md` §"Reproducible build via Nix"). A Guix manifest may follow if a downstream packager needs it.
3. Systemd unit with `Type=notify` + verified graceful shutdown — `Type=simple` shipped; `Type=notify` upgrade pending
4. `/health` + `/metrics` endpoints ✅ shipped
5. Pruning + AssumeUTXO tested on a 4 GB Pi 5
6. `docs/PACKAGING.md` ✅ shipped + a working `umbrel-apps` PR

---

## Sequencing notes

Rough dependency order. Items 2-4 and 6 have shipped; 1 and 5 are partial; 7-8 remain.

1. **AssumeUTXO** *(partial)* — `loadtxoutset` and the snapshot-validation pipeline are wired; `--fast-start` (one-flag UX with embedded snapshot hash) is still future work. Already unlocks realistic Pi deployment for operators willing to fetch a snapshot manually.
2. **Address-history index** ✅ shipped — `node-index` crate; updated inside `connect_block` / `disconnect_block` for atomic reorg consistency.
3. **Esplora REST** ✅ shipped — `esplora-handlers` crate; on by default on loopback.
4. **Electrum protocol** ✅ shipped — `electrum-proto` crate; vendored protocol code from `romanz/electrs` (MIT) over the address-index trait surface.
5. **Packager-ready gate items** *(partial)* — `/health`, `/readyz`, `/metrics`, structured-JSON logs, profile presets, persistent reorg log + webhook, events bus, MCP server, multi-arch Docker images, signed tarballs, Nix flake reproducible build, systemd unit, and `docs/PACKAGING.md` are shipped. `Type=notify` systemd upgrade and the SBOM step remain — see `STABILITY_POLICY.md` for the canary-CI commitments that gate the first packager-friendly tag.
6. **BIP 157/158 P2P service** ✅ shipped — `node-filter-index` crate + `getcfilters` / `getcfheaders` / `getcfcheckpt` arms in `node/src/net/manager.rs`; deferred backfill via `backfillindex blockfilter`.
7. **Silent Payments index + push notifications** *(deferred)* — advanced mobile-specific capabilities. The SP index rides on the same scan-every-output infrastructure as the address-history index.
8. *(Deferred)* **LND-compatible gRPC** if LN focus becomes a priority.

---

## Open questions

Resolved (kept here for traceability; the resolution lives in code and `CORE_DIFFERENCES.md`):

- ~~Address-history index column-family layout.~~ **Resolved**: two CFs (`addr_funding`, `addr_spending`) keyed by `(scripthash[32], height_be[4], txid[32], vout/vin_be[4])`. See `node-index/src/keys.rs`.
- ~~Address index opt-in vs. on-by-default.~~ **Resolved**: on by default (`--addressindex=1`); opt out with `--addressindex=0`. Esplora and Electrum auto-require it.
- ~~AssumeUTXO interaction with the address-history index.~~ **Resolved**: deferred opt-in backfill via `backfillindex address` (and `backfillindex blockfilter` for the BIP 158 index). Operator triggers when convenient; node remains usable with partial history.

Open:

- Signed AssumeUTXO snapshot distribution — signing key policy, CDN choice, update cadence. Tied to `--fast-start` UX (Tier 2 #10 in `OPERATOR_ERGONOMICS.md`).
- Do we sponsor or upstream satd-specific presets to an existing mobile wallet (Nunchuk, BlueWallet) vs. being a pure server?
- Non-Tor cloud-accessible deployment path (HTTPS reverse proxy, Tailscale, mutual-TLS) — do we support it or intentionally de-emphasize in favor of Tor-first?
- Silent Payments index: built on top of the address-history index infrastructure, or as a parallel index? (Likely the former, given they share the same scan-every-output shape.)
