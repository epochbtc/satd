# Ecosystem Integration — Mobile + Packaging

Strategic direction for how satd integrates with the broader Bitcoin ecosystem: which mobile clients we target, which API surfaces we expose, and how we make satd easy to package for self-custody stacks (Umbrel, Start9, RaspiBlitz, MyNode, BTCPay, home-server distros).

Not a milestone spec. This doc guides future milestones and informs packaging / API decisions as they arise.

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

1. **Electrum protocol server.** Largest wallet install base by far. Either implemented in-tree (`sat-electrum`) or first-class integration / bundling of `electrs` or `Fulcrum`. Unlocks BlueWallet, Nunchuk, Sparrow, Electrum, and most hardware-wallet coordinators in one move.
2. **Esplora REST API.** Compatible with `blockstream.info` / `mempool.space` endpoints. Unlocks BDK-based wallets and Mutiny-alikes. Smaller ecosystem than Electrum but growing, and it is the BDK-native path.
3. **BIP 157/158 P2P service.** Near-free as part of being a well-behaved Bitcoin node — `getcfilters` / `getcfheaders` / `getcfcheckpt` over standard P2P. Zeus-embedded / Blixt users can `addpeer` our .onion. Low incremental cost; covers the LN-focused on-device validation niche.
4. **Bitcoin Core-compatible JSON-RPC** (already implemented). Protect wire-format compatibility going forward so Sparrow desktop, BTCPay, legacy scripts, and integrations "just work."
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
- **Signed artifacts** (minisign or detached GPG), keys published in `SECURITY.md`, at least two maintainers cross-signing.
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

### 4. Companion binaries

Ship Electrum / Esplora servers as **separate binaries in the workspace**:

- `sat-electrum` — Electrum protocol server (or first-class integration with `electrs` / `Fulcrum`).
- `sat-esplora` — Esplora REST server.
- `sat-index` *(optional)* — native index service if it provides capabilities neither covers.

Rationale: one process per container maps cleanly to Umbrel / Start9's container model. Keeps satd core lean. Optional `satd --with-electrum` bundle mode covers Pi users who prefer a single process.

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

1. Multi-arch Docker + signed tarballs in GitHub Releases
2. Reproducible build (Guix or Nix)
3. Systemd unit with `Type=notify` + verified graceful shutdown
4. `/health` + `/metrics` endpoints
5. Pruning + AssumeUTXO tested on a 4 GB Pi 5
6. `docs/PACKAGING.md` + a working `umbrel-apps` PR

---

## Sequencing notes

Rough dependency order (not a milestone plan — only what blocks what):

1. **AssumeUTXO** (already planned) — unlocks realistic Pi deployment.
2. **Packager-ready gate items** — infrastructure every integration rides on.
3. **BIP 157/158 P2P service** — cheapest mobile integration surface, also a general Bitcoin-network good citizen.
4. **Electrum protocol integration** (bundled `electrs` / `Fulcrum`, or native `sat-electrum`) — largest mobile-wallet unlock.
5. **Esplora REST** — BDK ecosystem.
6. **Silent Payments index + push notifications** — advanced mobile-specific capabilities that require server-side state.
7. *(Deferred)* **LND-compatible gRPC** if LN focus becomes a priority.

---

## Open questions

- Native `sat-electrum` vs. bundling `electrs` / `Fulcrum` — long-term maintenance vs. short-term leverage.
- Signed AssumeUTXO snapshot distribution — signing key policy, CDN choice, update cadence.
- Do we sponsor or upstream satd-specific presets to an existing mobile wallet (Nunchuk, BlueWallet) vs. being a pure server?
- Non-Tor cloud-accessible deployment path (HTTPS reverse proxy, Tailscale, mutual-TLS) — do we support it or intentionally de-emphasize in favor of Tor-first?
- Silent Payments index: do we design it as part of satd core, as a separate `sat-index` companion, or rely on an upstream like `sp-electrs`?
