# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.5.1**, a patch release on the 0.5.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.5.1-pre.md`](docs/release-notes/0.5.1-pre.md).

### Fixed
- A mined or submitted block that was stored without connecting (a sibling won
  the race) no longer purges the mempool or reports a confirming height; every
  post-connect purge now reports the block's own height, never a tip re-read a
  later connect can have moved (#639)
- `gettxout` pairs its coin read, `bestblock` and height as one consistent
  chain view; previously a concurrent connect could pair the parent tip with
  coins the new block had already spent or created (#640)
- `getblockstats` fee fields (`totalfee`, `minfee`/`maxfee`, fee rates,
  `medianfee`) are now computed from the block's undo data and so are real for
  connected blocks — connecting a block removes exactly the coins it spends,
  so the previous live-UTXO lookup made every fee field structurally zero;
  `swtotal_size`/`swtotal_weight` are populated (#640)
- `verifychain` walks the active chain by parent pointers under a consistent
  view instead of trusting the height index, so a polluted index row can no
  longer fail (or falsely pass) verification (#640)
- `signrawtransactionwithkey` and `sat-cli`'s local PSBT signer can now spend untweaked
  P2TR outputs — the BIP 352 silent-payment shape — matching Bitcoin Core's key-path
  fallback (#609)
- Block subsidy halves every 150 blocks on regtest, matching Core's
  `nSubsidyHalvingInterval` (#608)
- Core-compat gaps from the #541 review (#548): `-testactivationheight=name@height`
  implemented (regtest-only, Core syntax, command-line and config-file occurrences
  merged as Core merges them); over-weight blocks reject `bad-blk-weight` after the
  witness rules as Core orders it, with `bad-blk-length` reserved for the
  stripped-size check; `getblocktemplate` matches Core's full pre/post-segwit
  template shape, including `default_witness_commitment` on every post-segwit
  template, witness transactions or not
- `gettxoutsetinfo` reads its tip, count, amount and histogram as one consistent
  view under the chain accept lock, so a concurrent connect can no longer skew the
  totals against the reported tip, and a failed flush is reported rather than
  answered with self-contradicting totals (#556)

## Deferred to 0.5.1

Held out of 0.5.0 so that release could stabilise. Written up in full in
[`docs/release-notes/0.5.1-pre.md`](docs/release-notes/0.5.1-pre.md).

### Added

**Bitcoin Core functional-test harness** (`contrib/core-functional/`) — runs
Core's own functional suite, unmodified, against satd, with every test file in
the pinned release inventoried as `run` or `skip` with a reason. Nightly
workflow, scoreboard in the Operator Manual. See
[Core Functional-Test Conformance](https://epochbtc.github.io/satd/core-functional.html). `feature_discover.py`, `rpc_deprecated.py`
and `rpc_uptime.py` were measured passing unmodified and moved into the run
set, taking the scoreboard to 10 tests.

### Fixed

**Bitcoin Core client compatibility.** Found by pointing Core's own functional
test framework at satd (see Added); each affects real Core-derived clients, not
only tests.

- `disconnectnode` now disconnects. It sent a ping to the named peer and
  returned success, leaving the connection open, so an operator cutting off a
  misbehaving peer was told it worked while the peer stayed connected. It also
  gained Core's `nodeid` form, refuses both or neither selector, and reports a
  peer it could not find instead of returning success.
- `-uacomment` is honored instead of accepted and ignored. It appends comments
  to the advertised user agent (`/satd:0.5.1(comment1; comment2)/`), rejecting
  the delimiters `/`, `:`, `(` and `)` inside a comment and refusing a total
  user agent over 256 bytes, both with Core's wording. Command-line and
  config-file occurrences accumulate, as Core accumulates list-valued options.
  Beyond losing the operator's label, ignoring it made every satd node on a
  host advertise an identical `subversion`. **Upgrade note:** the value was
  previously unvalidated because it was unused, so a `bitcoin.conf` carrying
  an unsafe comment now stops the node at startup.
- satd now sends P2P keepalive pings, and drops a peer that stops answering
  them. It answered a `ping` and had a `ping` RPC, but nothing ever pinged on
  its own, so a quiet link produced no evidence it was still alive and
  `getpeerinfo` never reported `pingtime`. Ping on connection setup and every
  two minutes thereafter, disconnect after twenty minutes without a pong (Core's
  `TIMEOUT_INTERVAL`), and report `pingtime`, `minping` and `pingwait`. The
  `ping` RPC shares the same accounting, and a ping-timeout drop is counted by
  `satd_peer_ping_timeouts_total`. `feature_framework_testshell.py` and
  `p2p_block_sync.py` were measured passing as a result and moved into the run
  set, taking the scoreboard to 12 tests; the other 21 rows that named the
  missing ping as their blocker were re-measured onto the blocker they now
  actually reach.
- `scantxoutset` scans the UTXO set for outputs paying a descriptor. satd's first
  descriptor support: `raw(<hex script>)` and `addr(<address>)` with BIP380
  checksums, plus Core's inference for the reported `desc`. Descriptor forms satd
  does not implement are refused by name rather than matching nothing. Takes the
  functional-test scoreboard from 6 tests to 7, and re-triages 23 rows onto
  measured causes.
- `syncwithvalidationinterfacequeue` blocks until the asynchronous event
  bridges have published everything emitted before the call, the settle barrier
  Core's test framework calls from `sync_all()`. With it, Core's framework can
  build its shared 199-block chain against satd, and the functional-test
  scoreboard goes from 3 tests to 6.
- `setmocktime` moves the node clock that block-template timestamps, the
  `time-too-new` future-block check and mempool entry time/expiry read. Gated
  to regtest exactly as Core gates it, and additionally carved out of
  `rpc:write` into a `test:clock` capability, so a delegated bearer token
  cannot move the clock even on regtest unless `auth.toml` grants it.
- JSON-RPC requests may pass `params` as an object, naming arguments the way
  Bitcoin Core does, instead of only as a positional array. An object `params`
  previously failed on every method. Names, aliases (`verbosity|verbose`),
  argument holes, options objects and the `args` mixed form all follow Core.
- RPC replies now carry exactly `Content-Type: application/json`, as Core's do,
  instead of `application/json; charset=utf-8`. Core-derived clients compare the
  header for equality, so the redundant parameter read to them as a non-JSON
  response.
- The startup RPC listener answers `-28 RPC in warmup` with the live progress
  line for any method it does not itself serve, instead of `-32601 Method not
  found`. `-28` is the code Core-compatible clients poll on while a node comes
  up; `-32601` reads as a permanent failure.
- A recognized-but-unsupported Core option passed on the command line is now
  skipped with a warning, as the same key in `bitcoin.conf` already was. Core
  treats the two as one namespace. Unrecognized options are still rejected, so
  a typo cannot be silently swallowed.
- 56 satd flags — including Core's own `-blockfilterindex` and
  `-peerblockfilters` — were reachable only in `--double-dash` form because the
  single-dash compatibility table had drifted from the parser. The set is now
  derived from the parser itself.
- `satd -version` prints `satd version <v>` (Core's shape; the word "version"
  was absent before), and a bad flag is reported as `Error parsing command line
  arguments: ...`, matching Core's wording.
- `-minrelaytxfee` / `-dustrelayfee` accept Core's BTC/kvB spelling
  (`0.00001`) alongside satd's integer sat/kvB. A value that cannot be parsed
  is now an error: the config-file path silently discarded one and relayed at
  the built-in default instead.
- `-blockfilterindex` may be given with no value, meaning `basic`, as in Core.
- An unparseable `-bind` reports the problem and exits instead of panicking,
  and an IPv6 literal is bracketed before it is joined to `-port`, so
  `-bind=::1` works at all.
- `getpeerinfo` gains Core's `addrbind` (the local end of each connection) and
  `bytessent_per_msg` / `bytesrecv_per_msg` (per-message-type wire tallies).
  Core-derived clients read all three without a null guard.
- A command-line option given twice now takes the last value, as in Core,
  instead of aborting startup. This is what lets a wrapper append an override
  onto a base command line. Repeatable options still accumulate.
- `-bind` is repeatable and accepts Core's `addr[:port][=onion]` form. An entry
  carrying a port uses it; a bare address combines with `-port`; an explicit
  `-bind` replaces the default listener rather than adding to it.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.5.0...HEAD
