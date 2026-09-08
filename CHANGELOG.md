# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.5.2**, a patch release on the 0.5.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.5.2-pre.md`](docs/release-notes/0.5.2-pre.md).

### Changed

- **Breaking:** `getdeploymentinfo` reports the buried deployments under
  Bitcoin Core's names — `dersig` is now `bip66` and `cltv` is now `bip65`
  (#666). It also honours the `blockhash` argument instead of ignoring it.
- **Breaking:** `validateaddress` describes a destination as Bitcoin Core
  does. `witness_version` and `witness_program` are omitted for a non-witness
  address instead of reporting `witness_version: -1`; `isscript` is now true
  for Taproot and anchor outputs and absent for an unknown witness version.
- **Breaking:** `converttopsbt` refuses a transaction carrying signature data
  unless `permitsigdata` is true, as Core does, instead of silently
  discarding it (#687).
- 24 RPCs accept the optional arguments Bitcoin Core declares for them, and
  an argument error is no longer a Rust `Debug` dump. `submitpackage`,
  `converttopsbt` and `utxoupdatepsbt` rejected their optional arguments
  outright (#687).
- A wrong-length hash and a right-length non-hex string report different
  errors, as Core's `ParseHashV` does; `getblockfrompeer` names the argument
  `blockhash`, as Core does (#692).
- **Breaking:** an RPC call that passes more arguments than the method
  declares is rejected with `-1`, as Core does, instead of being answered with
  the surplus ignored (#688).
- `generatetoaddress` and `generatetodescriptor` honour Core's `maxtries`
  argument, which also puts the first bound on satd's nonce grind (#688).
- `help <command>` answers for every registered RPC, including the ones the
  listing deliberately omits, and the listing itself now names every method
  satd registers — thirty were missing, among them the PSBT builders and
  satd's own index, quarantine and address-index RPCs (#692).

### Added

- `addconnection`, Bitcoin Core's hidden regtest-only RPC for opening an
  outbound connection of a chosen type (`outbound-full-relay`,
  `block-relay-only`, `addr-fetch`, `feeler`). `getpeerinfo` now reports the
  real `connection_type`, and each type behaves as Core's does.
- `validateaddress` reports *why* an address is invalid: Core's `error`
  string plus `error_locations` for a Bech32 checksum failure.
- `dumptxoutset` accepts Core's `type` argument (every Core-shaped call was
  previously a parse error), and resolves a relative `path` against the
  network data directory as Core does rather than the working directory.

### Fixed

- The ephemeral dust rule is enforced on the single-transaction path, as Core
  does: a transaction that spends a resident dust parent without sweeping its
  dust is refused `missing-ephemeral-spends` instead of accepted (#703).
- An ephemeral dust parent reached the mempool without a mempool `Enter`
  event, so a consumer reconstructing membership from the event stream
  disagreed with `getrawmempool` (#704).
- `submitpackage` could leave a zero-fee ephemeral-dust parent in the mempool
  after the child that was to sweep its dust was refused, stranding the dust —
  the one outcome the policy exists to prevent. The parent is now removed with
  the child (#673).
- `submitpackage` reported `bad-txns-inputs-missingorspent` for a child that
  left its parent's ephemeral dust unspent, burying the real reason. It now
  reports `missing-ephemeral-spends`, and the package result is `unspent-dust`
  rather than `transaction failed`, as Core does (#673).
- `getpeerinfo.permissions` was hardcoded `[]` while each peer's permissions
  were populated all along, so a `-whitelist`ed peer reported no grants at all.
  It now reports Core's `ToStrings` of the real flags (#667). `noban` also
  carries `download`, as Core's `NetPermissionFlags::NoBan` does — a reporting
  change, since the upload-budget check already honoured either flag.
- The `logging` RPC honours Core's wildcard set exactly: `""`, `1` and `all`
  all mean every category. `none` and `0` are rejected as unknown categories,
  as Core rejects them — they are `-debug` config spellings, and accepting them
  meant `logging '["none"]'` silently turned off all logging where Core refuses
  the call (#667).
- **Breaking:** two `-whitelist` grants were wider than Core's, and are
  narrowed to match: a bare `-whitelist=<subnet>` no longer grants `addr`, and
  `-whitelist=@<subnet>` — Core's "match this range, grant nothing" idiom —
  grants nothing instead of the implicit set, which had been silently handing
  out `noban` (#667).
- **Breaking (security):** `-whitelist` is inbound-only unless the entry
  carries an `out` token, as in Core, and an `out` entry applies only to
  *manual* outbound connections. satd swallowed the `in`/`out` tokens as no-ops
  and applied every entry in both directions, so `-whitelist=noban@<subnet>`
  made outbound peers in that range un-bannable and exempt from the upload
  budget (#701).
- **Security:** a peer arriving over the Tor hidden service is no longer
  matched against `-whitelist`. Tor forwards the service to a local socket, so
  every inbound onion peer looked like a loopback connection and inherited a
  `-whitelist=127.0.0.1` entry — the ordinary way to whitelist a local wallet
  integration — making anonymous remote peers un-bannable and exempt from the
  inbound connection caps. `-listenonion` now gets its own listener on
  `127.0.0.1:<port+1>` (Core's `onion_binds`), and peers accepted there are
  exempt from whitelist matching (#701).
- `getmemoryinfo` reported the process RSS as the secure-allocator pool's
  `used`, with `free`, `total` and both `chunks_*` invented around it. satd has
  no secure allocator, so the pool is empty and the numbers are zero (#667).
- `logging` reported from a static map initialised to "everything on" that
  nothing else in the process read: a node running with no `-debug` claimed 30
  categories enabled, and toggling one flipped a bit that never reached the log
  filter. It now reads and writes the node's live `EnvFilter`, lists the
  categories satd can actually act on, and answers Core's
  `-8 unknown logging category <cat>` (#667).
- `estimaterawfee` returned the same feerate for every horizon with `decay: 0`
  — not a value Core's estimator can produce — and zeroed buckets, and
  discarded `threshold` entirely. It now omits a horizon that does not track
  the target, omits the bucket fields satd has no data for, answers Core's
  "insufficient data" error when the estimator has none, and range-checks
  `threshold` (#667).

- `-connect=0` was parsed as the peer address `0`, so the node dialled
  `0.0.0.0:8333` at every startup. Core reads it as "open no outbound
  connections"; satd now does too, and any `-connect` stops the node dialling
  addresses it learned from gossip.

- `validateaddress` reported an address from another network as valid — it
  never checked the network at all.
- `getdeploymentinfo`: a 64-character `blockhash` that is not hexadecimal
  reported a length error; it now reports a hex error, as Core does.

- JSON-RPC: a mistyped argument no longer discards every argument after it.
  `generateblock` with a bad `transactions` silently ignored `submit=false`
  and mined a block. Wrong-typed arguments now return Core's `-3`
  `Wrong type passed:` error naming each one (#672).
- `sat-cli -named`: an argument with no `=` was silently dropped; it is now
  sent as a positional argument in Core's reserved `args` slot (#672).
- JSON-RPC: an error raised while reading a *later* argument no longer buries
  an earlier argument's type mismatch, which in a debug build closed the
  connection with no response at all (#672).
- `getnetworkhashps`: `nblocks` and `height` are signed again, so Core's
  documented `-1` works for both; out-of-range values now return Core's
  errors. The estimate counts the whole window's work rather than one block's,
  correcting a figure that was low by a factor of the window size — also
  reported by `getmininginfo.networkhashps` and the TUI.
- `getblockstats`: accepts a numeric height (Core's own help example) and the
  `stats` filter, both of which were rejected outright.
- P2P: a `block-relay-only` connection now actually withholds transaction and
  address relay instead of only being labelled as such — satd answered
  `getaddr`, ingested the peer's addresses, and announced its own transactions
  over links opened to prevent exactly that. `getpeerinfo.relaytxes` reports
  `false` for block-relay-only and feeler peers, as Core does.
- P2P: an `addr-fetch` connection now ends when the peer answers with
  `addrv2`, not only with the legacy `addr` — every BIP155-capable peer uses
  the former, so the connection previously held an outbound slot for the full
  five-minute expiry.
- `-connect`: gossiped and `peers.dat` addresses are no longer dialled. The
  previous gate ran where addresses were recorded, which `peers.dat` bypasses
  by being loaded before the setting is applied.
- `-connect=0` no longer raises the `peer_floor` alert threshold from 1 to 3,
  and is reported as `automatic_outbound` by `getconfig`, which could not
  otherwise tell a deliberately isolated node from a default one.
- SIGHUP: a `connect` change now applies the gossip-dialling disposition, and
  adding `connect=0` is no longer reported as "no changes detected".
- P2P: the per-type outbound connection limits are enforced against dials in
  flight, so concurrent `addconnection` calls can no longer exceed them.
- P2P: answering `getaddr` no longer re-enters the peer-table read lock, which
  `parking_lot` does not allow re-entrantly — a writer arriving between the two
  acquisitions deadlocked the manager's event loop.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.5.1](docs/release-notes/0.5.1.md) | 2026-09-04 | A Bitcoin Core compatibility release. satd now runs **Core's own functional test suite**, unmodified and pinned to a Core release, with all 264 test files inventoried as run-or-skip-with-a-reason; the set gates every pull request and found twelve defects in shipped behaviour — an RPC `Content-Type` Core-derived clients reject outright, a startup listener answering "no such method" where Core answers "warming up", a `bitcoin.conf` fee-rate value silently discarded, a panic on any unparseable `-bind` (and no IPv6 bind at all), mempool chain limits enforcing a limit Core v31 no longer has, and an oversized locator banning the peer where Core only disconnects. The mempool event broadcast now holds a whole block's confirmations — its 1024-slot ring was smaller than a single mainnet block, so every subscriber silently lost roughly 37% of each block's burst (#682). Silent payments reach wallets that exist today via `blockchain.tweaks.subscribe` on the Electrum server, plus `tweak_unspent_only` cut-through and spendable silent-payment outputs (#609). **Breaking:** `getindexinfo` is now Core's method — satd's richer view moved to `getsatdindexinfo`; `uacomment` is now validated and an unparseable `minrelaytxfee`/`dustrelayfee` now stops the node. Drop-in binary upgrade, no reindex. |
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.5.1...HEAD
