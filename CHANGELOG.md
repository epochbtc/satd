# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.6.0**, a minor release on the 0.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.6.0-pre.md`](docs/release-notes/0.6.0-pre.md).

### Added

- The metrics and health endpoints can be served over TLS on a second port (`-metricstlsbind`), with optional client certificates (`-metricsmtls`), so Prometheus can scrape a node across a network without a reverse proxy (#752).
- The appliance images are published as release assets, alongside the
  tarballs and signed with the same minisign key. They fit GitHub's 2 GiB
  per-asset limit — `qemu-img` compresses them during the build — so there is
  no separate download host and nothing to reassemble (#742).
- Appliance images for **arm64** as well as amd64, for Apple Silicon and
  arm64 servers. The arm64 desktop carries Sparrow only, since Electrum and
  Liana publish no arm64 build; its welcome page names what is installed
  (#742).
- A status page on the metrics listener, `statuspage=1`: a single-page, self-refreshing `sat-tui` for a browser, with connection strings from `statusadvertise`. Off by default (#749).
- Streaming API: `Subscribe`/`Watch` responses carry `satd-version` and `satd-events-schema` gRPC headers; `STABILITY_POLICY.md` now states the SDK ↔ node compatibility rule.
- Rust SDK: warns when the node is one minor version behind, refuses two or more (`StreamError::NodeTooOld`, override `allow_old_node()`) and any schema mismatch (`StreamError::SchemaMismatch`); `StreamClient::node_version()`.
- Go SDK: the same check (`ErrNodeTooOld`, `WithAllowOldNode`, `ErrSchemaMismatch`, `WithLogger`, `Client.NodeVersion`); `Watch` now waits for response headers; the module is versioned with the node (`satdevents.Version`), next tag `clients/go/v0.6.0`.
- The Umbrel and StartOS packages open onto the status page, and the appliance turns it on; Umbrel publishes Esplora over TLS on 8431; the reference stack and the appliance serve metrics and the status page over native TLS on 9336 (#750).
- **Stratum V1 solo-mining server** (`--stratum=1`): miners connect to the node directly; the username is the payout address. Loopback by default, TLS/mTLS listener, refused on signet (#746).
- **Stratum V2** on the same server (`--stratumv2bind`): Noise NX transport, standard and extended channels, and an authority key persisted at `<datadir>/stratum_v2.key` so miners that pin it survive a restart (#748).
- **Stratum V2 Job Declaration** (`--stratumv2jd=1`), solo semantics: a miner declares its own transaction set from this node's mempool. New `getstratuminfo` RPC (#751).

### Fixed

- Compact block receive path hardened: a `cmpctblock`'s header is validated before the block is reconstructed, pending reconstructions are bounded per peer and expire, and a merkle mismatch after reconstruction falls back to fetching the full block instead of penalising the peer (Core parity; #763).
- Stratum work follows a tip the node reached through block download. Those blocks connect without a chain event, so work stayed on the old tip for up to 30 seconds after a node caught up — long enough for a Job Declaration client to be refused (#763).
- A node that mined its own chain, and so had never been sent a header by a peer, counted itself as still in initial block download and ignored every transaction its peers announced. It now takes them (#759).
- `verificationprogress` in `getblockchaininfo` and `getchainstates` is Bitcoin Core's transaction-count estimate, equal to Core's; it was the tip's timestamp over the current time and read 0.69 at genesis (#744).
- An appliance image can be built around a published release. The
  `--satd-source release` path asked for
  `satd-<version>-x86_64-linux-gnu.tar.gz`, a target triple and compression
  format the release has never used, so it always 404'd; released images now
  carry the signed release binary rather than a rebuild (#742).
- The appliance boot test waits for satd to finish starting instead of asking
  `systemctl is-active` once. The single call raced the unit and failed a
  release build with a diagnostic that showed the service running (#742).
- The Umbrel package takes its own host ports (8430, 8433, 8436, 8439, 50012), so it installs beside Bitcoin Node, Fulcrum and Ride The Lightning, and its backups leave the chain out (#743).
- The StartOS package's backups skip the AssumeUTXO background chainstate, and its sync check no longer reports `verificationprogress`, which read about 69% at genesis (#743).
- `getblocktemplate` now carries the retargeted difficulty at a retarget boundary (and after a testnet 20-minute gap) instead of the tip's bits, and reports `mintime` as median time past + 1 instead of `curtime` (#746).

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.5.2](docs/release-notes/0.5.2.md) | 2026-09-11 | Deployment and Bitcoin Core parity. Three new ways to run satd — a docker-compose **reference stack** with TLS everywhere and LND/CLN/RTL/Cashu/BTCPay overlays, a bootable **appliance image**, and **Umbrel and StartOS packages** — each installed and driven on a real server; `sat-cli`/`sat-tui` reach a TLS RPC listener; the container image ships `sat-tui` and a `HEALTHCHECK` and is **136 MB instead of 670 MB**. MCP is reachable by hostname (`-mcpallowedhost`, #734). The defects filed from the 0.5.1 functional-test review (#660–#673) and the ones Core's suite went on to find, closed in Core's direction: a mistyped RPC argument no longer discards the ones after it (#672), surplus arguments are refused (#688), `createrawtransaction`/`createpsbt` check the address network and parse amounts exactly (#689), mempool policy at Core parity — dust thresholds, feerate-diagram RBF, ephemeral dust, `submitpackage`/`testmempoolaccept` shapes (#660, #661, #665, #673), `getblocktemplate` proposal mode validates like `submitblock` (#663), more than a dozen RPC fields that were constants now come from the node (#667, #702), `-connect=0` no longer dials the address zero and a pinned node stops listening (#690), and two **security** fixes — `-whitelist` no longer reaches Tor or outbound peers (#701) and a proxied node no longer resolves peer hostnames locally (#668). An **IBD wedge** on fork-heavy networks, where a competing header could permanently replace the next block to fetch, is fixed and a damaged datadir heals on the first restart (#738). Drop-in binary upgrade, no reindex; `banlist.json` moves to Core's format, so delete it before any downgrade. |
| [0.5.1](docs/release-notes/0.5.1.md) | 2026-09-04 | A Bitcoin Core compatibility release. satd now runs **Core's own functional test suite**, unmodified and pinned to a Core release, with all 264 test files inventoried as run-or-skip-with-a-reason; the set gates every pull request and found twelve defects in shipped behaviour — an RPC `Content-Type` Core-derived clients reject outright, a startup listener answering "no such method" where Core answers "warming up", a `bitcoin.conf` fee-rate value silently discarded, a panic on any unparseable `-bind` (and no IPv6 bind at all), mempool chain limits enforcing a limit Core v31 no longer has, and an oversized locator banning the peer where Core only disconnects. The mempool event broadcast now holds a whole block's confirmations — its 1024-slot ring was smaller than a single mainnet block, so every subscriber silently lost roughly 37% of each block's burst (#682). Silent payments reach wallets that exist today via `blockchain.tweaks.subscribe` on the Electrum server, plus `tweak_unspent_only` cut-through and spendable silent-payment outputs (#609). **Breaking:** `getindexinfo` is now Core's method — satd's richer view moved to `getsatdindexinfo`; `uacomment` is now validated and an unparseable `minrelaytxfee`/`dustrelayfee` now stops the node. Drop-in binary upgrade, no reindex. |
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.5.2...HEAD
