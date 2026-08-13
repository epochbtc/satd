# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

- Fixed: satd could advance its chain tip onto blocks it had never connected,
  serving a UTXO set silently missing every output those blocks created while
  reporting a healthy synced tip. Every connect path — both sequential (IBD)
  paths and the steady-state `accept_block` a synced node uses — now requires
  the parent to be a block this chainstate actually connected, not merely one
  whose hash matches; `connect_preprocessed_block` additionally checks that the
  block, the index entry authorising it and the hash the tip is set to all
  agree, the identity check its flat-file counterpart already had. At startup
  satd walks the tip's ancestry and refuses to start when it finds a block it
  never connected, rather than serving wrong `gettxout` answers, exiting with
  status 3 and naming `satd-chainstate-audit`; a broken parent pointer is
  reported separately, with `-reindex` as its remedy. An AssumeUTXO snapshot's
  unvalidated history is recognised and is not an error.
- `bad-txns-inputs-missingorspent` now logs the outpoint, txid, input index and
  height. The reject reason on the wire is unchanged.

- Fixed, Core compatibility: `confirmations` was computed from a block's height
  alone, with no check that the block is actually on the active chain. A valid
  block on a losing branch therefore reported the depth its height implied —
  one buried 60,000 deep claimed 60,000 confirmations — where Core reports
  `-1`. `getblock`, `getblockheader` and `getrawtransaction` are all corrected
  (`getrawtransaction` reports `0` for an off-chain block, matching Core's
  different convention there). `nextblockhash` was likewise resolved through
  the height index, handing an off-chain block the *active* chain's successor;
  it is now reported only for blocks on the active chain. Together these made a
  stale block and the canonical block at the same height indistinguishable
  through satd's own RPC, which actively impeded a fork investigation.
- Fixed: `mediantime` returned the block's own timestamp rather than the median
  of the block and its ten ancestors, on `getblock`, `getblockheader`,
  `getblockstats` and `getblockchaininfo`. It is now a real median-time-past,
  walked through parent pointers so a block off the active chain is measured
  against its own ancestry.

- satd now audits the height→hash index at startup and rebuilds missing rows
  by walking the tip's ancestry, so a gap left by the reorg batching defect
  below no longer needs a `-reindex` to clear. The height index is derived
  state: the active chain is the tip's ancestry by definition, so no other
  index row is consulted. One sequential scan; a clean node writes nothing.
  The pass only *adds* rows for heights that have none, and never overwrites
  one that is present — correcting a wrong row means choosing between branches
  by chainwork, which it does not do; rows it walks past that disagree with the
  tip's ancestry are logged. Heights whose blocks this chainstate has not
  validated are reported separately from real damage, so an AssumeUTXO node
  mid-validation is not told to reindex. Gaps it cannot rederive are logged as
  errors instead of passing silently.
- Fixed: a reorg could delete the height→hash and txindex rows the replacement
  block had just written. Disconnecting the displaced block and connecting the
  replacement coalesce into one write batch, which applies every put before
  every remove — so the remove of height H ran after the put of height H and
  won, though the put was the later operation. The other indexes were already
  deduplicated by key for this sequence; these two were not. `getblockhash`
  reports `Block height out of range` for a height in the middle of the active
  chain, but only after a restart — the height cache is sized to cover the
  whole chain, so a running node keeps answering correctly. The likelier and
  worse case needs no restart at all: a reorg routinely re-mines the
  transactions it displaces, and the txindex cache holds only a few hundred
  thousand entries, so within roughly a day of normal operation the evicted
  row surfaces as `getrawtransaction` reporting a transaction that is in the
  chain as unknown. A missing height row inside the
  eleven-block MTP window can also shift the median that gates BIP 113 and BIP
  68, which needs a restart within eleven blocks of the reorg to reach.
  Reindex and index backfills are not exposed; `-reindex` repairs existing
  damage.
- **Breaking, security:** both SDKs refused nothing when a bearer token was
  paired with an unencrypted connection — the credential, and any BIP 352 scan
  key registered over the same stream, went out in cleartext with no error and
  no warning. `Dial` / `connect()` now fail closed; `WithInsecureBearerToken` /
  `insecure_bearer_token` accept the risk explicitly for loopback and tests.
  The node closes the same hole from its end: `-eventsgrpcallowremote` with
  `-eventsgrpcauth` now requires `-eventsgrpctlscert`/`-eventsgrpctlskey`,
  matching the rule `-mcpallowremote` already enforces. mTLS satisfies it.
- Fixed: `getindexinfo`'s `estimated_remaining_seconds` counted idle time as
  work. It measured wall-clock since the backfill was *first* started, so a
  paused or restarted job extrapolated the downtime — pausing 48 hours at 10%
  projected 20 days against ~54 hours of real work left. All three backfills
  (address, filter, silent payments) now measure the rate over the span the
  runner has actually been walking, and report `0` (no estimate) for the first
  few seconds after a start, resume, or restart.
- The silent-payment backfill is now alertable. `satd_spindex_backfill_progress_ratio`
  alone could not distinguish a failed backfill from a disabled index or from a
  node that never needed one; three new gauges —
  `satd_spindex_enabled`, `satd_spindex_synced`, and
  `satd_spindex_backfill_state{state=...}` — separate those cases.
- Fixed: an AssumeUTXO background validation failure stopped the catch-up thread
  permanently while `getchainstates` still reported the snapshot as not
  rejected, with only a log line to show for it. It now raises a standing
  warning, so it reaches `getwarnings` and `-alertnotify`.
- Fixed: the silent-payment, filter and address backfill cursors are read under
  a RocksDB snapshot, so a reader can no longer pair one run's `cursor_height`
  with the next run's `snapshot_height` and report a just-restarted backfill as
  most of the way done. Only the silent-payment cursor is read by a metrics
  scrape today; the other two are read by `getindexinfo` and at startup.
- Fixed: changing `alertfile=` and sending SIGHUP reloaded the **old** file and
  logged success naming a path that was no longer configured. A path change is
  now reported as restart-required; editing the file's contents stays live.
- Fixed: the webhook plaintext-HTTP gate waived IPv4 link-local, so a hook URL
  of `http://169.254.169.254/...` was accepted without `allow_insecure_http`.
  Now only loopback and RFC1918 are waived, matching the IPv6 arm and the spec.
  **Breaking:** a node with a link-local hook URL will not start until the URL
  moves to `https://` or the stanza sets `allow_insecure_http = true`.
- `-alertnotify` for edge events (currently `deep_reorg`) is rate-limited to one
  exec per minute per event id, and the window reports the **worst** occurrence
  in it rather than the first — a shallow reorg can no longer claim the window
  and reduce a deep one to a counter. A strictly worse occurrence escalates
  immediately (once per window), the rest are held and paged when the window
  closes, and a burst that stops is drained by the health poll.
- Fixed: the active-warnings set is capped at 256 distinct ids, with the
  overflow counted in one `warnings.truncated` row. Ids that embed an
  identifier (one per corrupt block) could previously grow it without bound.

- **P2P hardening:** the block-ingress mutation gate now ports Core's
  `IsBlockMutated` rule for rule. It gained the witness half — a witness-mutated
  block (same hash, same merkle root) is rejected at ingress instead of one
  layer later — and a merkle-root mismatch. It also *stops* rejecting two shapes
  Core accepts: a block containing a 64-byte transaction when a coinbase is
  present, and any block whose parent is unknown. Both were stricter than Core
  on a gate that bans at 100 points, i.e. a way to ban honest peers.
- Fixed: `-reindex` no longer aborts permanently on a block it cannot replay.
  Because the chainstate is wiped before the replay begins, that abort left the
  node with no chain at all and failed identically on every retry. It now stops
  at that height, keeps everything below it, says so loudly, and lets normal
  sync re-fetch the rest from peers.
- Fixed: block data that is missing or unreadable behind a live `block_index`
  entry is now reported as local corruption — an error log and a standing
  warning naming `getblockfrompeer` — instead of being indistinguishable from a
  pruned block.
- CI: every third-party action is pinned by commit SHA; none run from a mutable
  branch ref. The fuzz job's pinned nightly now has a single source of truth.
- **Consensus fix:** the BIP 141 witness rules are now enforced exactly as
  Bitcoin Core enforces them. satd previously accepted three classes of block
  Core rejects — a malformed coinbase witness nonce, witness data hung off the
  coinbase in a block that commits to none, and a commitment that is never
  verified because no other transaction carries witness data. Each was a
  potential chain split with satd on the losing side.
- Fixed: a crash could leave a block's `block_index` entry pointing at block
  bytes that never reached disk. Block records are now fsync'd before the entry
  referencing them is committed, on every write path including IBD.
- Fixed: a torn flat-file record (ENOSPC mid-write) is truncated rather than
  appended past, so `-reindex` no longer silently skips the rest of that file;
  new `blk*.dat` files get a directory fsync.
- New `getblockfrompeer` RPC (Core-compatible) re-fetches one block from one
  peer and repairs its stored copy in place, so a lost block body no longer
  requires a full resync. It also replaces a stored copy that parses but is not
  the canonical block — a non-canonical witness leaves the block hash intact,
  so nothing else surfaces it.
- Fixed: `getblock` no longer serves a different block when an index entry's
  offset lands on another record; the block hash is verified on read.
- New **Go SDK** (`satdevents`) for the streaming API, at `clients/go/` as an
  independently versioned module (`clients/go/vX.Y.Z` tags): full parity with
  `satd-events-client` — firehose, all watch kinds, durable cursors, reconnect,
  rescan, watch-set loaders, prefix re-filtering — in Go idiom, with a published
  dependency graph of gRPC and protobuf only. Thirteen runnable examples; new
  [Go SDK](https://epochbtc.github.io/satd/go-sdk.html) manual chapter.
- CI: a **differential parity harness** drives both SDKs through an identical
  watch spec against one node and diffs their rendered events line by line, so
  Go/Rust parity is checked on every PR rather than asserted. Also PR-gating:
  the Go unit tests, a build of every example, and the Go E2E suite against the
  freshly built `satd` binary.
- SDK (`satd-events-client`): four defects found by the Go SDK review were
  present in the Rust original and are fixed — a failed cursor-store write no
  longer reports success on retry (an at-least-once violation on the
  commit-before-shutdown path), an auto-resumed lag now backs off instead of
  re-subscribing immediately and unboundedly, prefix watches mask the bits below
  the declared bucket width instead of leaking them, and `FileCursorStore`
  fsyncs the temp file and its directory.
- SDK (`satd-events-client`): an **unset** protobuf field and a value this build
  does not **recognize** are now different variants on every open enum
  (`StatusSeverity`, `StatusKind`, `StatusState`, `EvictReason`) — proto3's zero
  value decodes to `Unspecified`, anything unrecognized to `Unknown(i32)`.
  Behaviour change for `EvictReason`, which shipped in 0.4.0 routing *every*
  unrecognized value into `Unspecified` and leaving its `Unknown` variant
  unconstructible: an eviction reason added by a newer node was reported as
  "unspecified". `docs/api/streaming.md` now states the severity ranking
  normatively (`Unspecified` < `Info` < `Warning` < `Critical` < unrecognized).

- Silent payments (BIP 352): new workspace-internal `node-sp-index` crate — the
  shared BIP 352 kernel (input extraction, public tweak `T = input_hash · A`,
  scan loop) plus the `sp_tweaks` row/key codec, backfill cursor, read trait,
  and config. Validated against the BIP 352 v1.1.0 test vectors. Foundation
  only; not yet wired into the daemon.
- Silent payments (BIP 352): index write path. New `silentpaymentindex=1`
  runtime flag (default off, always compiled) makes `connect_block` stamp one
  self-authenticating tweak row per block at/above taproot activation (present
  even when empty), committed atomically with the chainstate; reorg disconnects
  remove it. `-reindex-chainstate` rebuilds it. New `satd_spindex_rows_total` /
  `satd_spindex_row_removes_total` metrics. Off ⇒ defaults byte-identical to
  0.4.0. Serving surfaces land in a later change.
- Silent payments (BIP 352): deferred backfill for enabling the index on an
  existing datadir. `backfillindex silentpayment` walks every block from taproot
  activation to the tip (undo-based, anchored, resumable across restart) and
  stamps a completeness marker; `pauseindex`/`resumeindex`/`cancelindex
  silentpayment` control it. `getindexinfo` gains a `silentpayments` section
  (synced + backfill progress) and a `satd_spindex_backfill_progress_ratio`
  gauge is exported; both measure progress across the walked span
  `[taproot activation, snapshot]` rather than the whole chain, and the ETA is
  reported only while a backfill is actually running and enabled. Until a backfill
  completes (or the sync ran from genesis
  with the index on), the index reports not-synced so tweak-serving surfaces
  refuse rather than return holes.
- Silent payments (BIP 352): streaming-API wire schema (`satd-events-proto`) for
  both consumption modes. Tier 1 adds a `tweaks` firehose category (bit 8 —
  explicit-request only, not part of the `categories=0` default) with per-block
  `BlockTweaks`/`TweakEntry` bodies and `tweak_dust_limit`/`tweaks_only`
  subscription knobs; Tier 2 adds a scan-key watch kind
  (`AddSilentPayments`/`RemoveSilentPayments`, `SetWatchSet.silent_payments`) and
  a `SilentPaymentMatched` body. Additive — the schema version does not bump and
  existing subscribers are unaffected. Emit, serving, and matching land in
  later changes; this is the schema pass both SDKs build on.
- Silent payments (BIP 352): Tier 1 serving. The node now emits a `BlockTweaks`
  event per connected block on the gRPC `Subscribe` firehose (only while a
  `tweaks` subscriber is attached) and replays it by index on `from_cursor`
  resume — a tweaks-only subscription cold-syncs from taproot activation in one
  subscription, exempt from the replay clamp because rows are self-authenticating
  and the exemption is gated on index completeness; a mixed-category subscription
  keeps the clamp. Per-subscription `tweak_dust_limit`/`tweaks_only` filters
  apply on live and replayed events. A `tweaks` subscription against a disabled
  or still-backfilling index is rejected in-band. New read-only JSON-RPC
  `getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` serves the
  same bytes as a fallback. WS/SSE and the typed SDK helpers land later.
- Silent payments (BIP 352): Tier 2 scan-key watch (confirmed path). A `Watch`
  client can register scan credentials (`AddSilentPayments` /
  `SetWatchSet.silent_payments`; up to 16/connection) and the node matches
  BIP 352 payments server-side, emitting a `SilentPaymentMatched` per matched
  output as blocks connect — including the public tweak `T` and output counter
  `k` so a light client re-derives the output key offline. Matching recomputes
  from the block + undo data (works with the index off) and does zero extra work
  when no target is registered. Scan secrets are held in-memory per connection,
  wrapped in a zeroize-on-drop buffer, and never persisted or logged. Mirrored on
  the WS/SSE surface. The typed SDK helpers land later.
- Silent payments (BIP 352): Tier 2 scan-key watch — mempool (unconfirmed)
  matching. A registered SP watch now also matches payments in accepted-but-
  unconfirmed transactions, emitting `SilentPaymentMatched` with
  `confirmed = false`; the block-connect scan re-emits the same match
  `confirmed = true` when it confirms (mirroring `ScriptMatched` mempool
  semantics). To classify inputs the mempool matcher needs the resolved prevout
  scripts, so while any SP watch is live the mempool retains them on each entry
  (a shared gate — the same counter the watch registry maintains); with no SP
  watch registered nothing extra is retained and the mempool event path is
  byte-identical to before. Best-effort like every mempool watch: a target
  registered after a tx was admitted matches it only once it confirms.
- Silent payments (BIP 352): index-accelerated rescan (D4). A `RescanBlocks`
  over a scan-key watch-set now takes the stored tweaks straight from the
  `sp_tweaks` index when it is enabled and complete — skipping the undo read and
  per-tx tweak recomputation on each block — gated per block on the row's
  embedded `block_hash` matching the block being scanned; a missing or
  mismatched row (or a disabled/incomplete index) transparently falls back to
  recomputing that block. Both paths run the same kernel, so acceleration never
  changes which payments a rescan finds. No new surface or config; a scan-key
  cold-sync just gets faster when the index is on.
- docs: Operator Manual style pass: controlled glossary, shorter sentences, standardized callouts (house style in `docs/manual/STYLE.md`); fixed stale `par`, `debug.log`, and release-target statements
- **Storage / Core compat**: read (and optionally write) Bitcoin Core v28+
  XOR-obfuscated block files — the `blocks/xor.dat` key is honored
  automatically, making the documented "reuse a Core `blocks/` directory"
  migration work against modern Core datadirs; `blocksxor` is now a real
  option (fresh satd dirs stay plaintext by default).
- Log hygiene: per-transaction mempool-acceptance lines are now logged at `debug` instead of `info` (they no longer flood the log during normal operation), and ANSI color is auto-detected — escapes are suppressed when stdout is not a terminal or when `NO_COLOR` is set, so piped/`journald`-captured logs stay clean.
- Silent payments (BIP 352): Rust SDK (`satd-events-client`) support for both
  consumption modes. Typed `Event::BlockTweaks` (Tier 1) and
  `Event::SilentPaymentMatched` (Tier 2); a `Categories::TWEAKS` bit and
  `SubscribeOptions::tweak_dust_limit` / `tweaks_only`; `WatchHandle` and
  `ResilientWatch` / `WatchSetBuilder` `add_silent_payments` /
  `remove_silent_payments` helpers (scan keys re-register on reconnect); and two
  runnable examples — `sp_light_scan.rs` (client-side scan off the tweaks
  firehose, scan key never sent) and `sp_wallet.rs` (scan-key watch, deriving
  each match's spending key offline from `tweak` + `k`).
- Silent payments (BIP 352): mempool-time tweak firehose ("Tier 1.5"). The node
  computes the public tweak `T = input_hash·A` at mempool admission and emits it
  as a `MempoolTweak` on the gRPC streaming firehose, so a zero-custody (Tier 1)
  client detects payments to it at mempool latency without uploading a scan key.
  Opt-in per subscription (`mempool_tweaks`, requires the `TWEAKS` category bit);
  best-effort and ephemeral — no cursor/replay, no retraction on RBF or eviction.
  The SDK exposes it as `SubscribeOptions::mempool_tweaks` and typed
  `Event::MempoolTweak`. Off by default: a node with no tweak-firehose subscriber
  does no extra work, and the mempool event path is byte-identical to before.
- Silent payments (BIP 352): tweak events can now carry the transaction's
  taproot outputs (`TweakEntry.taproot_outputs` — each `vout`, 32-byte x-only
  key, value), so a client confirms a derived output key against the actual
  on-chain output without fetching the transaction. Always populated on a
  `MempoolTweak` (there is no block to fall back to, and a `getrawtransaction`
  for an unconfirmed tx races eviction); opt-in per subscription for
  `BlockTweaks` via `tweak_outputs` (the confirmed firehose stays lean by
  default — the block is the fallback). The outputs are dropped by the on-disk
  index (no size increase, no reindex) and re-derived at serve time. SDK:
  `TweakEntry::taproot_outputs` and `SubscribeOptions::tweak_outputs`.
- Alerting: node-health events on the streaming API. A new `status` category
  (bit 16 — explicit-request only, so a `categories=0` subscriber is unaffected)
  carries `StatusEvent` bodies describing the node itself (`ibd_complete`,
  `tip_stall`, `disk_low`, `mempool_congested`, `peer_floor`, `deep_reorg`),
  level-triggered with paired `raised`/`cleared` states and an additive
  `details` string map. Served on gRPC and WS/SSE; **not** on the ZMQ
  `nodeevent` topic, which has no per-subscriber category mask (use `alertfile`
  webhooks or `-alertnotify` for health over ZMQ). Requires **`rpc:read` as well
  as `stream:subscribe`** where `-authfile` is in use — the bodies carry host
  telemetry (disk, peers, mempool occupancy, tip height) that the same
  capability gates on the RPC surface. Not replayable (no cursor —
  detectors re-raise standing conditions after a restart). Wire schema only in
  this change; the detectors that emit them land next.
- Alerting: node-health detectors. satd now watches six conditions about itself
  — stalled tip, low disk, congested mempool, peer starvation, IBD completion,
  deep reorg — and reports each through three surfaces at once: a `status`
  streaming event, an entry in `getwarnings` (which fires the Core-compatible
  `alertnotify` hook), and a `satd_alert_active{kind}` gauge. Standing
  conditions raise once and clear once, with hysteresis so a value sitting on
  the threshold does not flap. The one-shot events (`ibd_complete`,
  `deep_reorg`) fire `alertnotify` and the streaming event but deliberately do
  **not** enter `getwarnings` — nothing would ever clear them, and on chains
  where multi-block reorgs are routine that would wedge
  `getblockchaininfo.warnings` and the TUI modal permanently. Five new hot-reloadable thresholds
  (`alerttipstallseconds=3600` — `0` on regtest, `alertdiskfreemb=10240`,
  `alertmempoolfullpct=90`, `alertpeerfloor=3` — `0` on regtest, and capped by
  the number of `-connect=` peers when that is set —
  `alertreorgdepth=3` — `10` on test networks, `0` on regtest); `0` disables a
  detector. `deep_reorg` depth, fork
  height and new tip are read from the durable reorg log, so they are exact
  regardless of chain-event lag. Two new gauges close longstanding observability gaps
  independently of alerting: `satd_tip_last_connect_age_seconds` and
  `satd_disk_free_bytes`, the latter sampled even when `alertdiskfreemb=0`. The
  free-space probe is bounded and carried across polls, so a `blocksdir` on an
  unresponsive network mount stalls only the disk alert — never the other
  detectors — and strands at most one blocking thread rather than one per poll.
- Alerting: outbound webhooks. `alertfile=<path>` configures any number of
  signed HTTP hooks, each filtered by category/kind/severity. Bodies are
  byte-identical to the streaming API's JSON for the same event; delivery
  metadata rides in headers (`X-Satd-Signature`, `X-Satd-Timestamp`,
  `X-Satd-Delivery`, `X-Satd-Hook`, `X-Satd-Attempt`). The signature covers the
  timestamp, delivery id, and hook id as well as the body, so the idempotency
  key a receiver deduplicates on cannot be forged and a captured delivery is not
  a permanent replay token. Delivery is serial and in-order per hook,
  retried with exponential backoff on transient failures and skipped on a
  permanent 4xx. The per-hook queue is bounded and overflow **drops silently**
  — there is no in-band gap notice; the record is
  `satd_alertwebhook_dropped_total` and a log line. Redirects are never followed — a 3xx is a permanent drop, so a
  signed body cannot be steered to a host the alertfile never named. Delivery is
  **best-effort**: nothing is persisted, a hook that was down resumes at the
  live head, and drops are counted in `satd_alertwebhook_dropped_total`. The
  Streaming Consumption API remains the surface for guaranteed, resumable
  consumption. Hooks reload on SIGHUP
  (keep-last-good on error); per-hook counters are exported as
  `satd_alertwebhook_*`. The existing `reorgwebhook=` keys keep working with
  their original payload, headers, and retry schedule, now delivered by the same
  dispatcher — which also moves that outbound HTTP off the consensus runtime.
  They keep reporting `X-Satd-Webhook-Version: 1`; alertfile hooks report `2`.
  **Behavior change on `reorgwebhook=`:** redirects are no longer followed, so a
  receiver answering `3xx` (an `http`→`https` proxy hop, a trailing-slash
  redirect) must be repointed at its final URL — following one moves a signed
  body to a host the operator never named.
- docs: new `docs/api/webhooks.md` — the normative alert-webhook delivery
  contract (headers, HMAC signature with test vectors, retry classes,
  best-effort delivery semantics), linked from the streaming spec and the
  Operator Manual; `CORE_DIFFERENCES.md` gains entries for node-health alerts
  and the webhook surface.
- Alerting: Rust SDK (`satd-events-client`) support for node-health events. New
  `Categories::STATUS` bit and typed `Event::Status { kind, state, severity,
  message, details }` with open `StatusKind` / `StatusState` / `StatusSeverity`
  enums — an unrecognized value from a newer node surfaces as `Unknown(i32)`
  rather than an error, and `StatusSeverity` is ordered by severity rank
  (`Unspecified` < `Info` < `Warning` < `Critical` < `Unknown`) so a client
  filters with a comparison. All three are `#[non_exhaustive]`, so a condition added
  node-side stays additive for downstream consumers. New runnable
  `examples/health_watch.rs`.
- Fixed: `-reindex` mis-handled fork points in the block files. Block files hold
  every block the node fully received, including ones a later reorg orphaned, so
  any datadir that has been live through a reorg has forks on disk. The replay
  connected *every* block reachable from genesis as if it extended the tip
  instead of selecting the most-work branch — aborting with
  `bad-txns-inputs-missingorspent` when the two branches double-spent, and
  otherwise applying the losing branch's UTXO delta on top of the winning chain
  and reporting success over a corrupt UTXO set. The replay now selects by
  cumulative chainwork and connects only that branch; side-chain blocks are
  indexed (`DataStored`, addressable by hash) but never connected. Duplicate
  block records on disk are collapsed.
- Fixed: `-reindex-chainstate` no longer replays whatever chain the height→hash
  index names. That index is derived state and has been observed polluted with a
  fork block, which made the replay splice one branch onto another and report a
  completed reindex over a UTXO set built from both. The replay now selects the
  most-work fully-connectable branch of the block index, recomputing chainwork
  and height from the stored headers rather than trusting the index's own
  fields, and refuses to resume a partial chainstate that sits on a different
  branch. `invalidateblock` and header-only gaps are honored during selection.
- Fixed: both reindex paths now validate proof of work before letting a header
  influence branch selection. An 80-byte header always deserializes, so a single
  flipped bit in a record's `nBits` exponent produced a well-formed header
  claiming astronomical work — and since `connect_block` checks no PoW either,
  it would have been selected and connected as the tip, wedging the node on a
  branch it could never reorg away from.
- Fixed: `-reindex-chainstate` now refuses to run when the block index cannot
  produce a fully-connectable chain reaching the height the chainstate was
  already at, instead of reporting success over a truncated or empty UTXO set. A
  pruned datadir hit this every time: every block below the prune horizon is
  ineligible, so the replay connected nothing and the node came up at height 0
  with the tx and address indexes already stamped complete.
- Fixed: an exact chainwork tie during a chainstate reindex now keeps the branch
  the node was already on, rather than resolving by block hash — a node holding
  an equal-work stale sibling at its tip could otherwise rebuild onto the orphan.
- Fixed: side-chain blocks above the selected tip are no longer indexed by
  `-reindex`. `accept_headers` restores a "missing" height→hash row for any
  data-carrying entry whose height is vacant, so such an entry would have had one
  written for it on the next headers message — putting a losing branch into the
  active-chain index after all.
- Fixed: all reindex paths now refuse to connect a block that does not extend
  the chain being replayed — the invariant `connect_stored_block` has always
  enforced on the IBD path, now applied to both reindex replays as a
  belt-and-braces check behind the selection fixes above.
- Fixed: every reindex path now runs full context-free block validation
  (`CheckBlock`, as Core does) on the bytes it read. Flat-file records carry no
  checksum, so a bit flipped inside a transaction payload left the 80-byte
  header hashing correctly and the corrupted block was connected, its UTXO delta
  applied, and the reindex reported success.
- Changed: `-reindex-chainstate` no longer resumes a partially-replayed
  chainstate — the replay starts at genesis or refuses. The daemon already
  cleared the UTXO set before every run, so this is unchanged in practice; it
  makes the replay's verification inductive rather than conditional on where it
  started. Every block it connects is checked against the block files, so
  starting above genesis would validate blocks against index entries below it
  that nothing reconciled, and BIP68 (which reads a spent coin's MTP at that
  coin's creation height, anywhere in history) makes that hole unbounded.
- Fixed: a chainstate reindex no longer takes any consensus input from the
  height→hash index it exists to distrust. Median time past — which gates BIP113
  locktimes and, at the spent coin's height, BIP68 time-based sequence locks — is
  now resolved through the branch being replayed. The block index's stored header
  must also match the header in the block file before either replay path will use
  its parent link, chainwork or timestamp.

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
