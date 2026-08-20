# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.5.0**, the wallet-backend release. This is an index: every item
below is written up in full — with the reasoning, the observed symptom, and the
upgrade impact — in the in-development
[`docs/release-notes/0.5.0-pre.md`](docs/release-notes/0.5.0-pre.md).

### Added

**Silent payments (BIP 352)** — receive-side support end to end, opt-in at every
layer; a node that enables nothing behaves exactly as 0.4.0 did.

- `silentpaymentindex=1`: one self-authenticating tweak row per block, committed
  atomically with the chainstate, removed on reorg, rebuilt by
  `-reindex-chainstate`. Shared BIP 352 kernel in a new `node-sp-index` crate.
- Deferred backfill for existing datadirs — `backfillindex silentpayment`
  (anchored, resumable) with `pauseindex`/`resumeindex`/`cancelindex`,
  a `getindexinfo` section, and progress/state metrics.
- Measured disk footprint in the manual, replacing estimates that had drifted.
  The silent-payment index is ~13 GB for the full taproot era (not ~4 GB), grows
  ~1 GB/year, and takes 6 h 46 m to backfill on mainnet; `tweak_dust_limit`
  filters ~10% at 546 sat, not the ~85% previously documented. The rest of the
  column-family table is now measured too, including `undo` (~74 GB, not
  "rolling") and `coins` (~10 GB, not "tens of MB").
- **Tier 1** (zero custody): `tweaks` firehose category with cursor replay and
  taproot-activation cold sync, per-subscription `tweak_dust_limit` /
  `tweaks_only` / `tweak_outputs` filters, plus a `getsilentpaymentblockdata`
  RPC fallback. The scan key never leaves the client.
- **Tier 1.5**: mempool-time tweak firehose (`MempoolTweak`) — detection at
  mempool latency, still without uploading a scan key. Best-effort, no replay.
- **Tier 2** (scan key registered): server-side matching for confirmed *and*
  unconfirmed payments, emitting `SilentPaymentMatched` with the public tweak
  `T` and counter `k`. Scan secrets are per-connection, in memory only, and
  zeroized on drop. `RescanBlocks` is index-accelerated when the index is
  complete, falling back per block otherwise.
- Both SDKs expose all of it, and the Tier 2 matcher is proven against the
  BIP 352 reference vectors over the whole corpus (#592).

**Alerting & node health**

- Six detectors about the node itself — tip stall, low disk, congested mempool,
  peer floor, IBD completion, deep reorg — each reported through three surfaces
  at once: a `status` streaming event (bit 16, explicit-request only),
  `getwarnings` (which fires the Core-compatible `-alertnotify`), and a
  `satd_alert_active{kind}` gauge. Level-triggered with hysteresis; five
  hot-reloadable thresholds. `deep_reorg` reads depth and fork height from the
  durable reorg log.
- `alertfile=<path>`: any number of signed outbound webhooks, filtered by
  category/kind/severity. The HMAC covers the timestamp, delivery id and hook id
  as well as the body; delivery is serial and in-order per hook, retried with
  backoff, bounded, and never follows a redirect. Best-effort by design — the
  Streaming Consumption API remains the guaranteed surface. Contract:
  [`docs/api/webhooks.md`](docs/api/webhooks.md).
- `reorgwebhook=` keeps its payload and headers but now rides the same
  dispatcher, which also moves that outbound HTTP off the consensus runtime.

**Go SDK** — `clients/go` (`satdevents`), an independently versioned module at
full parity with `satd-events-client`: firehose, every watch kind, durable
cursors, reconnect, rescan, watch-set loaders, prefix re-filtering. Dependency
graph is gRPC and protobuf only; thirteen runnable examples; new
[Go SDK](https://epochbtc.github.io/satd/go-sdk.html) manual chapter.

**Rust SDK** — typed support for everything above (`Categories::STATUS` /
`TWEAKS`, `Event::Status`, `Event::BlockTweaks`, `Event::MempoolTweak`,
`Event::SilentPaymentMatched`, scan-key watch helpers that re-register on
reconnect) and two silent-payment examples covering both consumption modes.

**Tools & compatibility**

- `satd-chainstate-audit`: offline check of a stopped node's UTXO set, height
  index, txindex and cumulative counts against the blocks on its active chain.
  Diagnoses only. Opens RocksDB read-write — audit a *copy*. Not in the release
  tarballs or Docker image; build from source.
- `getblockfrompeer` (Core-compatible): re-fetch one block from one peer and
  repair its stored copy in place, instead of a full resync. Also replaces a
  stored copy that parses but is not the canonical block.
- Read (and optionally write) Bitcoin Core v28+ XOR-obfuscated block files —
  `blocks/xor.dat` is honored automatically, so the documented "reuse a Core
  `blocks/` directory" migration works against modern datadirs. Fresh satd dirs
  stay plaintext.

**Observability** — index-readiness metrics for all three DB-backed indexes
(#558), `satd_tip_last_connect_age_seconds`, `satd_disk_free_bytes` (sampled
even with the disk alert off), and per-hook `satd_alertwebhook_*` counters.

### Fixed

**Consensus parity with Bitcoin Core.** Each of these accepted or rejected a
block Core does not, i.e. a chain split with satd on the losing side.

- Three BIP 141 witness rules brought to exact Core parity — malformed coinbase
  witness nonce, witness data in a block committing to none, and a commitment
  never verified because no other transaction carries witness data.
- Transaction finality now matches Core exactly: the coinbase is subject to the
  check like any other transaction, and the locktime cutoff is strict. BIP 68's
  version gate compares unsigned, as Core does (#581).
- Median-time-past could be taken from a branch a reorg had already displaced,
  on both reorg paths and on the pipelined connect path. MTP gates BIP 113 and
  BIP 68, so the median decided transactions Core would have judged differently.
- The block-ingress mutation gate now ports Core's `IsBlockMutated` rule for
  rule — it gained the witness half and a merkle-root check, and stopped
  rejecting two shapes Core accepts (which, on a gate that bans at 100 points,
  was a way to ban honest peers).
- BIP 152 compact-block reconstruction no longer places one transaction in two
  slots when a short ID is repeated or two mempool transactions collide on one
  short ID; the affected slots are requested via `getblocktxn`, as Core does.
  Previously the duplicated transaction mutated the block, tripped the mutation
  gate, and banned the relaying peer.

**Chain safety, storage durability and recovery.** The bulk of this cycle. Each
of these could serve wrong answers, lose committed data, or wedge a node.

- The tip could advance onto blocks that were never connected, serving a UTXO
  set silently missing their outputs while reporting a healthy synced tip. Every
  connect path now requires a parent this chainstate actually connected, and
  startup walks the tip's ancestry and refuses to start (exit 3) on a hole.
- A reorg and the block connector could connect the same blocks concurrently;
  the reorg's rollback then discarded eight blocks of committed UTXOs. Both
  connect paths now hold `accept_lock`, and a rollback that would discard
  another writer's work refuses and stops the node with a consistent chainstate.
- A failed UTXO-cache flush destroyed the in-memory delta — a full disk silently
  discarded a whole flush window while the node continued. The batch is now
  handed back and the cache restored exactly.
- A crash could leave a `block_index` entry pointing at block bytes that never
  reached disk; block records are now fsync'd before the entry referencing them
  is committed. A torn flat-file record is truncated rather than appended past,
  and `getblock` verifies the block hash on read rather than serving whatever
  record an entry's offset happens to land on.
- A reorg could delete the height→hash and txindex rows the replacement block
  had just written (put-before-remove coalescing), surfacing as
  `getrawtransaction` reporting a confirmed transaction as unknown. satd now
  audits and rebuilds the height index at startup by walking the tip's ancestry.
- Three insert-after-invalidate races let the coin cache resurrect a coin a
  concurrent disconnect had retired — an in-memory phantom UTXO over a correct
  disk, observed as a multi-day `bad-txns-BIP30` wedge that a restart cleared
  (#583).
- `invalidateblock` could strand the connector on the branch it had just
  invalidated, and a stale height row could spin it with no sleep and no retry
  counter. IBD re-arm is no longer exclusively headers-driven, so a connector
  that tore down short of the headers tip no longer parks indefinitely (#582).
- `loadtxoutset` checked its precondition once and then streamed for minutes
  with a live connector free to advance the tip; it now claims the chainstate
  for its duration.
- On an AssumeUTXO node, background-chainstate index writes raced the snapshot
  chainstate's reorgs, and a background *validation* failure stopped the
  catch-up thread while `getchainstates` still reported the snapshot as fine.
- Missing or unreadable block data behind a live index entry is now reported as
  local corruption naming `getblockfrompeer`, instead of being indistinguishable
  from a pruned block.

**Reindex.** Any datadir that has been live through a reorg has fork blocks on
disk, so these were reachable in normal operation.

- Both replay paths selected the wrong chain: `-reindex` connected every block
  reachable from genesis as if it extended the tip, and `-reindex-chainstate`
  replayed whatever the height→hash index named. Both now select the most-work
  fully-connectable branch, recomputing chainwork and height from the stored
  headers; side-chain blocks are indexed but never connected.
- Neither path validated what it read — no proof-of-work check before a header
  influenced branch selection, and no `CheckBlock` on the bytes, so a single
  flipped bit could produce a header claiming astronomical work or a corrupt
  block connected as valid. Both now validate.
- `-reindex` no longer aborts permanently on a block it cannot replay (which
  left the node with no chain at all, failing identically on every retry) — it
  stops at that height, keeps everything below, and lets sync re-fetch the rest.
- `-reindex-chainstate` refuses to run when the block index cannot reach the
  height the chainstate was already at, instead of reporting success over a
  truncated UTXO set — which a pruned datadir hit every time.
- A chainstate reindex no longer takes consensus input from the height index it
  exists to distrust, and an exact chainwork tie keeps the branch the node is on.

**Mempool & mining**

- Mempool admission enforces transaction finality and BIP 68 sequence locks with
  Core's next-block semantics; a time-locked transaction was previously
  admitted, relayed, and mined into an invalid block (#588).
- `getblocktemplate` selection is now dependency- and finality-aware: inputs
  resolve against the UTXO set, CPFP children follow the parents that fund them,
  and non-final transactions are filtered at assembly (#589).

**RPC / Core compatibility**

- `confirmations` no longer ignores whether a block is on the active chain — a
  stale block 60,000 deep claimed 60,000 confirmations where Core reports `-1`
  (`getblock`, `getblockheader`, `getrawtransaction`). `nextblockhash` is no
  longer resolved through the height index for off-chain blocks.
- `mediantime` is now a real median-time-past walked through parent pointers,
  not the block's own timestamp (`getblock`, `getblockheader`, `getblockstats`,
  `getblockchaininfo`).
- `getindexinfo`'s `estimated_remaining_seconds` counted idle time as work; all
  three backfills now measure over time actually spent walking. Backfill cursors
  are read under a snapshot, so a reader can no longer pair one run's cursor
  with the next run's snapshot height — and the filter-index cursor is read
  through to the store, so a paused filter backfill no longer reads back as
  `idle` and never resumes (#555).
- `invalidateblock`/`reconsiderblock` report a failed re-activation as the
  partial success it is, and a failed reorg now logs the branch, each block, and
  the abort cause.

**Streaming SDKs**

- Four defects found by the Go SDK review were present in the Rust original and
  are fixed there too: a failed cursor-store write reported success on retry (an
  at-least-once violation), an auto-resumed lag re-subscribed unboundedly,
  prefix watches leaked bits below the declared bucket width, and
  `FileCursorStore` did not fsync.
- An *unset* protobuf field and a value this build does not *recognize* are now
  distinct variants on every open enum.
- The events-gRPC TLS listener advertised no ALPN protocol, so no standard gRPC
  client could reach it: the handshake completed, the certificate verified, and
  tonic then refused the connection because the server had selected nothing. It
  now offers `h2`. The HTTP/1.1 surfaces are unchanged and still advertise
  nothing.

**Operational**

- `/readyz` returns 503 while the connector cannot make progress (chain lag
  alone missed a node wedged at its own tip), and the warning clears on every
  path out of the wedge.
- `-alertnotify` for edge events is rate-limited per event id, and the window
  reports the *worst* occurrence rather than the first — a shallow reorg can no
  longer claim the window and reduce a deep one to a counter.
- The active-warnings set is capped at 256 ids; a `alertfile=` path change is
  reported as restart-required instead of silently reloading the old file.
- The shipped systemd units set `RestartPreventExitStatus=3`, so a node
  refusing to start on a damaged chainstate settles in `failed` state rather
  than restarting forever.
- `bad-txns-inputs-missingorspent` now logs the outpoint, txid, input index and
  height. The wire reject reason is unchanged.

### Changed

- Per-transaction mempool-acceptance lines moved from `info` to `debug`, and
  ANSI color is suppressed when stdout is not a terminal or `NO_COLOR` is set.
- `-reindex-chainstate` no longer resumes a partially replayed chainstate — it
  starts at genesis or refuses. Unchanged in practice (the daemon already
  cleared the UTXO set first); it makes the replay's verification inductive.
- `satd-chainstate-audit` no longer takes `--txindex`; it reads whether the
  index is complete from the datadir.
- Operator Manual style pass (house style in `docs/manual/STYLE.md`);
  `CORE_DIFFERENCES.md` gains node-health alerts and the webhook surface.
- CI: every third-party action is pinned by commit SHA. A differential parity
  harness drives both SDKs through one node and diffs their events on every PR,
  alongside the Go unit tests, an example build, and the Go E2E suite.

### Breaking

- **Security, both SDKs:** pairing a bearer token with an unencrypted connection
  is now refused instead of sending the credential — and any scan key registered
  over the same stream — in cleartext. `WithInsecureBearerToken` /
  `insecure_bearer_token` accept the risk explicitly. Node-side,
  `-eventsgrpcallowremote` with `-eventsgrpcauth` now requires TLS (mTLS
  satisfies it).
- **Webhooks:** the plaintext-HTTP gate no longer waives IPv4 link-local, so a
  node with an `http://169.254.…` hook URL will not start until the URL moves to
  `https://` or the stanza sets `allow_insecure_http = true`. Redirects are never
  followed on *any* hook, including `reorgwebhook=` — a receiver answering `3xx`
  must be repointed at its final URL.
- **Rust SDK:** `EvictReason` routed every unrecognized value into
  `Unspecified` in 0.4.0; an eviction reason added by a newer node now surfaces
  as `Unknown(i32)`.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.4.0...HEAD
