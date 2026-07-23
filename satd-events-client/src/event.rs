//! Typed event model — an ergonomic mirror of the `satd.events.v1` wire
//! `NodeEvent.body` tagged union, so consumers `match` on a flat enum instead
//! of unwrapping nested protobuf `Option`s.
//!
//! Hashes and txids are carried as raw `Vec<u8>` in **internal (consensus)
//! byte order** — the order the wire and key derivation use, *not* the reversed
//! order block explorers and Bitcoin Core JSON-RPC display. Convert at the edge:
//! [`parse_txid`] returns a typed [`bitcoin::Txid`] (whose `Display` is explorer
//! order, and which drops into `bitcoin`-ecosystem APIs) with the `bitcoin`
//! feature, and [`display_hex`] returns a display-order hex string with no extra
//! dependency. Only hashes/txids are byte-reversed for display — do not apply
//! either helper to a public key or tweak (`output_pubkey`, `tweak`).

use satd_events_proto::v1 as pb;

/// Render a raw wire hash/txid (32 bytes, **internal / consensus byte order**,
/// as every hash and txid on this API is carried) as a lowercase hex string in
/// the reversed **display order** used by block explorers and Bitcoin Core
/// JSON-RPC.
///
/// Use it on a hash or txid field (`txid`, `block_hash`, …). Do **not** apply
/// it to a public key or tweak: those are raw bytes but are *not* reversed for
/// display. Needs no optional dependency; for a typed value use [`parse_txid`].
///
/// ```
/// # use satd_events_client::display_hex;
/// let internal: Vec<u8> = (0u8..32).collect(); // 00,01,…,1f
/// assert!(display_hex(&internal).starts_with("1f1e1d")); // reversed
/// ```
pub fn display_hex(internal_hash: &[u8]) -> String {
    internal_hash
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parse a raw wire txid (32 bytes, internal/consensus byte order) into a typed
/// [`bitcoin::Txid`]. The returned value's `Display` is the usual explorer /
/// JSON-RPC order, and it hands straight to `bitcoin`-ecosystem APIs
/// (`bitcoincore-rpc`, comparison against `getrawtransaction`, …).
///
/// A thin wrapper over [`bitcoin::Txid::from_slice`]; the block-hash equivalent
/// is `bitcoin::BlockHash::from_slice(bytes)`.
///
/// ```
/// # use satd_events_client::{parse_txid, display_hex};
/// let raw: Vec<u8> = (0u8..32).collect();
/// let txid = parse_txid(&raw).unwrap();
/// assert_eq!(txid.to_string(), display_hex(&raw)); // both reverse to display order
/// ```
#[cfg(feature = "bitcoin")]
pub fn parse_txid(raw: &[u8]) -> Result<bitcoin::Txid, bitcoin::hashes::FromSliceError> {
    use bitcoin::hashes::Hash as _;
    bitcoin::Txid::from_slice(raw)
}

/// Durable resume position, re-exported from the wire schema. Persist the
/// value returned by [`EventStream::cursor`](crate::EventStream::cursor) and
/// present it again as `from_cursor` to resume.
pub use satd_events_proto::v1::Cursor;

/// An outpoint (`txid:vout`), raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outpoint {
    /// Transaction id, 32 raw bytes (internal byte order — [`parse_txid`] or
    /// [`display_hex`] for a typed value / explorer-order string).
    pub txid: Vec<u8>,
    /// Output index.
    pub vout: u32,
}

/// Descriptor attribution for a [`ScriptMatched`](Event::ScriptMatched): which
/// descriptor watch a matched scripthash belongs to, and the exact coordinate the
/// server derived it at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorMatch {
    /// The descriptor string the watch was registered with.
    pub descriptor: String,
    /// The 0-based BIP-389 multipath branch the matched script came from (`<0;1>`
    /// → external = 0, change = 1; always 0 for a single-path descriptor).
    pub branch: u32,
    /// The absolute derivation index of the matched script — ready to use, no
    /// `gap_limit` arithmetic. `(branch, derivation_index)` is exactly what the
    /// server derived (correct for fixed and multipath descriptors alike); the
    /// server still tracks no derivation progress — advancing your gap limit
    /// remains your concern.
    pub derivation_index: u32,
}

/// Why a transaction left the mempool by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvictReason {
    /// Unspecified / not set.
    Unspecified,
    /// Evicted because the pool hit its byte budget.
    FullPool,
    /// Evicted on mempool-expiry.
    Expiry,
    /// Evicted because a connected block conflicts with it.
    BlockConflict,
    /// Evicted from the quarantine class on a fee-rate byte-budget overflow.
    Policy,
    /// An eviction reason this client build does not recognize.
    Unknown(i32),
}

impl From<pb::EvictReason> for EvictReason {
    fn from(r: pb::EvictReason) -> Self {
        match r {
            pb::EvictReason::Unspecified => EvictReason::Unspecified,
            pb::EvictReason::FullPool => EvictReason::FullPool,
            pb::EvictReason::Expiry => EvictReason::Expiry,
            pb::EvictReason::BlockConflict => EvictReason::BlockConflict,
            pb::EvictReason::Policy => EvictReason::Policy,
        }
    }
}

/// A k-bit prefix of `sha256(scriptPubKey)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptPrefix {
    /// The top `ceil(bits/8)` bytes, big-endian.
    pub prefix: Vec<u8>,
    /// Prefix length in bits.
    pub bits: u32,
}

/// One transaction's public silent-payment tweak, carried in a
/// [`Event::BlockTweaks`] for Tier 1 client-side scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TweakEntry {
    /// 33-byte compressed public tweak `T = input_hash · A` for the transaction.
    /// Always present — this is what a client feeds its own `b_scan` into to
    /// scan the transaction's outputs locally.
    pub tweak: Vec<u8>,
    /// The transaction's txid (internal/consensus byte order — [`parse_txid`] /
    /// [`display_hex`]). Empty when the subscription set `tweaks_only` (the
    /// compact, tweak-alone form).
    pub txid: Vec<u8>,
    /// The largest taproot output value in the transaction, in satoshis — a cap
    /// on what a payment here could be worth, for client-side dust triage. `0`
    /// under `tweaks_only`.
    pub max_value: u64,
}

/// A spent prevout that matched a prefix bucket (the spend side of a
/// [`Event::PrefixMatched`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentPrevout {
    /// The outpoint consumed.
    pub outpoint: Outpoint,
    /// The `scriptPubKey` it paid. Empty when the server did not retain it
    /// (mempool spend below the `full` retention tier) — resolve the outpoint
    /// yourself in that case.
    pub script_pubkey: Vec<u8>,
    /// The prevout value in satoshis. `None` when not retained (distinct from a
    /// genuine 0-value prevout, which is `Some(0)`).
    pub amount: Option<u64>,
}

impl From<pb::SpentPrevout> for SpentPrevout {
    fn from(s: pb::SpentPrevout) -> Self {
        SpentPrevout {
            outpoint: Outpoint { txid: s.outpoint_txid, vout: s.outpoint_vout },
            script_pubkey: s.script_pubkey,
            amount: s.has_amount.then_some(s.amount),
        }
    }
}

/// A transaction that fell inside a watched script-prefix bucket. Carries the
/// full serialized tx so the client filters the bucket against its real scripts
/// locally (the privacy contract — the server only learns the bucket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixMatch {
    /// The registered bucket that fired.
    pub prefix: ScriptPrefix,
    /// Consensus-serialized matching transaction.
    pub raw_tx: Vec<u8>,
    /// `false` = mempool, `true` = connected block.
    pub confirmed: bool,
    /// Block height when confirmed; 0 in the mempool.
    pub height: u32,
    /// Spend-side matched prevouts; empty for a pure funding (output) match.
    pub matched_prevouts: Vec<SpentPrevout>,
}

/// A typed streaming event — the flat mirror of `NodeEvent.body`.
///
/// `Eq` is not derived: the [`Lagged`](Event::Lagged) resume cursor is a
/// prost-generated type that is only `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A transaction entered the mempool.
    MempoolEnter {
        /// Transaction id.
        txid: Vec<u8>,
        /// Fee in satoshis.
        fee: u64,
        /// Virtual size in vbytes.
        vsize: u64,
        /// Fee rate in sat/kvB.
        fee_rate_sat_per_kvb: u64,
        /// Admission time, seconds since the Unix epoch.
        time: u64,
    },
    /// A mempool transaction was confirmed in a block.
    MempoolLeaveConfirmed {
        /// Transaction id.
        txid: Vec<u8>,
        /// Confirming block hash.
        block_hash: Vec<u8>,
        /// Confirming block height.
        height: u32,
    },
    /// A mempool transaction was evicted by policy.
    MempoolLeaveEvicted {
        /// Transaction id.
        txid: Vec<u8>,
        /// Eviction reason.
        reason: EvictReason,
    },
    /// A mempool transaction was replaced (RBF).
    MempoolLeaveReplaced {
        /// Transaction id.
        txid: Vec<u8>,
        /// The replacing transaction id.
        replacing_txid: Vec<u8>,
    },
    /// A block was connected to the active chain.
    BlockConnected {
        /// Block hash.
        hash: Vec<u8>,
        /// Block height.
        height: u32,
    },
    /// A block was disconnected (reorg).
    BlockDisconnected {
        /// Block hash.
        hash: Vec<u8>,
        /// Block height.
        height: u32,
    },
    /// A reorg marker, emitted once before the disconnect/connect sequence.
    Reorg {
        /// Height of the abandoned tip.
        from_height: u32,
        /// Hash of the abandoned tip.
        old_tip: Vec<u8>,
        /// Height of the new active tip.
        to_height: u32,
        /// Hash of the new active tip.
        new_tip: Vec<u8>,
    },
    /// A periodic heartbeat.
    Heartbeat {
        /// Publisher uptime in nanoseconds.
        uptime_ns: u64,
    },
    /// A watched outpoint was spent.
    OutpointSpent {
        /// The spent outpoint.
        outpoint: Outpoint,
        /// The spending transaction id.
        spending_txid: Vec<u8>,
        /// The spending input index.
        spending_vin: u32,
        /// `false` = seen in mempool, `true` = confirmed.
        confirmed: bool,
    },
    /// A watched script was matched on the funding or spending side.
    ScriptMatched {
        /// The matched scripthash.
        scripthash: Vec<u8>,
        /// The matching transaction id.
        txid: Vec<u8>,
        /// `true` = funding (output), `false` = spending (input).
        is_output: bool,
        /// vout if `is_output`, else vin.
        index: u32,
        /// `false` = mempool, `true` = confirmed.
        confirmed: bool,
        /// Matched value in satoshis: the funded output value (`is_output =
        /// true`) or the spent-prevout value (`is_output = false`). `Some` on
        /// the funding side and for confirmed spends; `Some` for mempool spends
        /// when the node retained the prevout value (`streamprevoutmeta >=
        /// amount`), else `None` (hash tier). `None` lets the consumer skip the
        /// enrichment `getrawtransaction` for the common single-coin case.
        amount: Option<u64>,
        /// Full consensus-serialized matching transaction, present only when
        /// this stream opted in via
        /// [`set_watch_options`](crate::WatchControls::set_watch_options) with
        /// `include_raw_tx = true`; `None` otherwise.
        raw_tx: Option<Vec<u8>>,
        /// Descriptor attribution: the descriptor watch(es) this scripthash
        /// belongs to, if it was registered via `add_descriptor`. Empty for a
        /// directly-watched script. See [`DescriptorMatch`].
        descriptors: Vec<DescriptorMatch>,
    },
    /// A watched txid appeared in the mempool or a connected block.
    TxidMatched {
        /// Transaction id.
        txid: Vec<u8>,
        /// `false` = mempool, `true` = confirmed.
        confirmed: bool,
        /// Block height when confirmed; 0 in the mempool.
        height: u32,
    },
    /// A watched tx was replaced in the mempool (RBF).
    TxidReplaced {
        /// Transaction id.
        txid: Vec<u8>,
        /// The replacing transaction id.
        replacing_txid: Vec<u8>,
    },
    /// A watched tx left the mempool by policy.
    TxidEvicted {
        /// Transaction id.
        txid: Vec<u8>,
        /// Free-text reason (`"full_pool"` | `"expiry"` | `"block_conflict"` |
        /// `"policy"`).
        reason: String,
    },
    /// A watched tx's confirming block was rolled back by a reorg.
    TxidUnconfirmed {
        /// Transaction id.
        txid: Vec<u8>,
        /// Height it had been confirmed at, now disconnected.
        prev_height: u32,
    },
    /// A depth alarm fired (single-shot).
    TxidDepthReached {
        /// Transaction id.
        txid: Vec<u8>,
        /// Confirmations reached (>= the requested depth).
        depth: u32,
        /// Active-chain height where the tx is confirmed.
        height: u32,
    },
    /// A lifecycle watch's `auto_close_depth` was reached (terminal).
    TxidFinalized {
        /// Transaction id.
        txid: Vec<u8>,
        /// Confirmations reached (>= `auto_close_depth`).
        depth: u32,
        /// Active-chain height where the tx is confirmed.
        height: u32,
    },
    /// A transaction fell inside a watched script-prefix bucket.
    PrefixMatched(PrefixMatch),
    /// In-band slow-consumer lag notice. Not an error: reconnect (Subscribe) or
    /// re-anchor (Watch) with `resume_cursor` to recover the dropped events.
    Lagged {
        /// Number of events dropped before this notice.
        dropped_count: u64,
        /// The anchor to resume from to recover the gap.
        resume_cursor: Option<Cursor>,
    },
    /// **SDK-synthesized — not a wire event.** Emitted by
    /// [`ResilientSubscription`](crate::ResilientSubscription) when a durable
    /// replay was clamped by the server to the most recent `MAX_REPLAY_BLOCKS`
    /// (10,000) blocks, so the confirmed history in `(resume_height,
    /// first_height)` was skipped. The live stream continues correctly from
    /// `first_height`; the gap is unrecoverable via this stream, so full-resync
    /// the skipped range from another source (e.g. RPC `getblock`). Emitted once
    /// per resume, immediately before the first replayed block.
    ReplayGap {
        /// The height the resume cursor expected next (`cursor.height + 1`).
        resume_height: u32,
        /// The first height the server actually delivered (`> resume_height`).
        first_height: u32,
    },
    /// A mid-stream re-anchor ([`WatchHandle::set_cursor`](crate::WatchHandle::set_cursor))
    /// was **admitted**. Confirmed-history replay follows this event (in height
    /// order) before the live tail resumes. When `clamped` is true the requested
    /// cursor predated the server's replay window: replay still runs, but only
    /// from `earliest_replayed`, so full-resync history below it from another
    /// source. This is the deterministic "accepted, replaying from X" signal.
    CursorAccepted {
        /// The cursor the server anchored to.
        from: Option<Cursor>,
        /// `true` → the replay window truncated the lower end of the gap.
        clamped: bool,
        /// First height the server will replay.
        earliest_replayed: u32,
    },
    /// A mid-stream re-anchor ([`WatchHandle::set_cursor`](crate::WatchHandle::set_cursor))
    /// was **not** admitted. The live stream is unchanged (still emitting from
    /// its prior position). Decide whether to retry, back off, or escalate to a
    /// full resnapshot based on `reason`; `current_head` is where the server is
    /// now.
    CursorRejected {
        /// Why the re-anchor was declined.
        reason: CursorRejectReason,
        /// The server's current resume position.
        current_head: Option<Cursor>,
    },
    /// An atomic watch-set replace ([`ResilientWatch::reload`](crate::ResilientWatch::reload),
    /// carried as `SetWatchSet`) was applied. The live watch-set now equals the
    /// reloaded truth; the counts are the server's authoritative diff by
    /// **effective coverage** (a scripthash covered by both the old and new set —
    /// even via a different mechanism — counts as `unchanged`, never gapped).
    WatchSetReplaced {
        /// Items newly watched.
        added: u32,
        /// Items released.
        removed: u32,
        /// Items in both the old and new set (kept without re-registration).
        unchanged: u32,
    },
    /// An atomic watch-set replace was **rejected**; the live watch-set is
    /// UNCHANGED (the prior set is still in effect). `reason` says which ceiling
    /// refused it, and `required`/`quota` are in the matching unit:
    /// [`QuotaExceeded`](WatchSetRejectReason::QuotaExceeded) — `required` units
    /// vs the `quota` ceiling; [`CapExceeded`](WatchSetRejectReason::CapExceeded)
    /// — `required` entries vs the per-connection entry cap (`quota`);
    /// [`Malformed`](WatchSetRejectReason::Malformed) — a client bug (bad element),
    /// `required`/`quota` are 0 and retrying the same set will not help. In every
    /// case the client's mirror still reflects the (unapplied) reloaded set, so a
    /// consumer that ignores this keeps an over-claiming mirror; react by
    /// reloading a set the server accepts.
    WatchSetRejected {
        /// Why the replace was refused.
        reason: WatchSetRejectReason,
        /// What the rejected target needs: units (`QuotaExceeded`) or entries
        /// (`CapExceeded`); 0 for `Malformed`.
        required: u64,
        /// The ceiling that refused it: unit quota (`QuotaExceeded`) or entry cap
        /// (`CapExceeded`); 0 for `Malformed`.
        quota: u64,
    },
    /// A bounded historical rescan ([`ResilientWatch::rescan`](crate::ResilientWatch::rescan))
    /// was **admitted**. Confirmed watch-matches for the scanned range follow
    /// this event (in height order), terminated by a [`RescanComplete`](Event::RescanComplete).
    /// `from_height`/`to_height` are the range the server will ACTUALLY scan:
    /// `clamped` is true when the requested upper bound exceeded the tip and was
    /// narrowed to it. A rescan is a side query — it does not advance the durable
    /// cursor, and its match events carry no resume cursor.
    RescanAccepted {
        /// First height that will be scanned (post-clamp).
        from_height: u32,
        /// Last height that will be scanned (post-clamp).
        to_height: u32,
        /// `true` → the requested range was narrowed to what the node holds.
        clamped: bool,
    },
    /// A bounded historical rescan was **not** admitted; no matches follow and
    /// the live stream is unchanged. `tip_height` is the server's current tip so
    /// a client can re-scope the range and retry.
    RescanRejected {
        /// Why the rescan was declined.
        reason: RescanRejectReason,
        /// The server's current active-chain tip height.
        tip_height: u32,
    },
    /// Terminal marker for a bounded historical rescan: the range has been fully
    /// scanned and every match delivered. `matches` counts the match events this
    /// rescan emitted (0 when the range held none). After this the stream resumes
    /// its prior live position.
    RescanComplete {
        /// The scanned range (post-clamp), echoing [`RescanAccepted`](Event::RescanAccepted).
        from_height: u32,
        /// The scanned range upper bound (post-clamp).
        to_height: u32,
        /// Number of match events emitted for this rescan.
        matches: u64,
    },
    /// One connected block's silent-payment tweaks — the Tier 1 (client-side
    /// scan, zero-custody) firehose payload. Arrives only for a subscription that
    /// set the [`TWEAKS`](crate::Categories::TWEAKS) category bit. For each entry,
    /// a client computes `T · b_scan` with its own scan secret and derives the
    /// candidate output key(s), so the scan key never leaves the device. See
    /// [`examples/sp_light_scan.rs`].
    BlockTweaks {
        /// The block these tweaks describe (internal/consensus byte order).
        block_hash: Vec<u8>,
        /// The block's height.
        height: u32,
        /// One entry per silent-payment-eligible transaction in the block.
        entries: Vec<TweakEntry>,
        /// `true` when a `tweak_dust_limit` or `tweaks_only` filter dropped or
        /// trimmed entries in this block (so an empty `entries` may mean
        /// "filtered out", not "none present").
        filtered: bool,
    },
    /// One accepted-but-unconfirmed transaction's silent-payment tweak — the
    /// Tier 1.5 (mempool-time, zero-custody) firehose payload. Arrives only for a
    /// subscription that set the [`TWEAKS`](crate::Categories::TWEAKS) category
    /// bit **and** [`SubscribeOptions::mempool_tweaks`](crate::SubscribeOptions::mempool_tweaks).
    /// Scan it exactly like a [`BlockTweaks`](Event::BlockTweaks) entry — compute
    /// `T · b_scan` and derive the candidate output key(s) — for mempool-latency
    /// detection. Ephemeral and best-effort: not replayable, no retraction on
    /// RBF/eviction; dedup by `entry.txid` (always present) against the confirmed
    /// `BlockTweaks`. See [`examples/sp_light_scan.rs`].
    MempoolTweak {
        /// The admitted transaction's tweak. Always full (`txid` present) —
        /// `tweaks_only` does not apply to mempool tweaks.
        entry: TweakEntry,
    },
    /// A BIP 352 silent payment paid a registered scan key — the Tier 2
    /// (scan-key watch, convenience) match, delivered on the `Watch` stream to a
    /// connection that registered the target via
    /// [`WatchHandle::add_silent_payments`](crate::WatchHandle::add_silent_payments).
    /// The node ran the ECDH; `tweak` + `k` let the wallet re-derive the output
    /// key — and, with its `b_spend`, the spending key — **offline**. See
    /// [`examples/sp_wallet.rs`].
    SilentPaymentMatched {
        /// The registered target's identity `b_scan·G` (33 bytes) this output
        /// paid — echoes which of your scan keys matched, never the secret.
        scan_pubkey: Vec<u8>,
        /// The paying transaction's txid (internal byte order — [`parse_txid`] /
        /// [`display_hex`]).
        txid: Vec<u8>,
        /// The matched output's index.
        vout: u32,
        /// The matched taproot output key (32-byte x-only).
        output_pubkey: Vec<u8>,
        /// The output value in satoshis.
        amount: u64,
        /// The transaction's 33-byte public tweak `T`. With `k`, re-derive the
        /// full output key offline: `P_k = B_spend + hash(b_scan·T || k)·G`.
        tweak: Vec<u8>,
        /// The BIP 352 output counter for this match — the `k` in the derivation.
        k: u32,
        /// The matched label integer, when the output paid a registered label
        /// (e.g. change is commonly label `0`); `None` for an unlabeled match.
        label: Option<u32>,
        /// `true` once seen in a connected block; `false` while only in the
        /// mempool (re-emitted `true` on confirmation).
        confirmed: bool,
        /// The confirming block height; `None` while unconfirmed.
        height: Option<u32>,
        /// The full serialized transaction, only when this connection opted in
        /// via `SetWatchOptions.include_raw_tx`; `None` otherwise.
        raw_tx: Option<Vec<u8>>,
    },
    /// A body this client build does not recognize (a newer server arm), or an
    /// event with no body set. Ignored by well-behaved consumers.
    Unknown,
}

/// Why a mid-stream re-anchor was declined by the server (see
/// [`Event::CursorRejected`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CursorRejectReason {
    /// Per-principal re-anchor rate limit exceeded — retry after a backoff.
    RateLimited,
    /// Another re-anchor is already draining (only one runs at a time) — retry
    /// once it completes.
    ConcurrentReanchor,
    /// The request carried no cursor (client bug).
    EmptyCursor,
    /// The server has no block source to replay from.
    NoSource,
    /// A reason code this client build does not recognize (a newer server).
    Unknown,
}

/// Why an atomic watch-set replace was declined by the server (see
/// [`Event::WatchSetRejected`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchSetRejectReason {
    /// The target set's total unit cost exceeds the principal's quota (`required`
    /// units vs the `quota` ceiling) — shed items and retry. Transient: a smaller
    /// set fits.
    QuotaExceeded,
    /// The target's watch-set **entry** count (`required`) exceeds the
    /// per-connection cap (`quota`, `streamwsmaxsubscriptions`). Distinct from
    /// `QuotaExceeded`: this bound applies even to a no-auth connection with no
    /// quota, and counts entries (a prefix is one) not units — shed entries and
    /// retry.
    CapExceeded,
    /// The server could not parse or expand an element of the snapshot (a bad
    /// scripthash, outpoint, txid, descriptor, or prefix). A full replace is
    /// all-or-nothing, so the whole snapshot was refused. This is a client bug —
    /// retrying the same set will not help.
    Malformed,
    /// A reason code this client build does not recognize (a newer server).
    Unknown,
}

/// Map the proto `WatchSetRejected.Reason` enum (an `i32` on the wire) to the
/// client enum, treating an unrecognized code as [`WatchSetRejectReason::Unknown`].
fn watch_set_reject_reason(reason: i32) -> WatchSetRejectReason {
    match pb::watch_set_rejected::Reason::try_from(reason) {
        Ok(pb::watch_set_rejected::Reason::QuotaExceeded) => WatchSetRejectReason::QuotaExceeded,
        Ok(pb::watch_set_rejected::Reason::CapExceeded) => WatchSetRejectReason::CapExceeded,
        Ok(pb::watch_set_rejected::Reason::Malformed) => WatchSetRejectReason::Malformed,
        Ok(pb::watch_set_rejected::Reason::Unspecified) | Err(_) => WatchSetRejectReason::Unknown,
    }
}

/// Why a bounded historical rescan was declined by the server (see
/// [`Event::RescanRejected`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RescanRejectReason {
    /// Per-principal rescan rate limit exceeded — retry after a backoff.
    RateLimited,
    /// Another rescan is already draining on this connection (only one runs at a
    /// time) — retry once it completes.
    ConcurrentRescan,
    /// `to_height < from_height`, or the range lies entirely above the tip.
    InvalidRange,
    /// The (clamped) span exceeds the server cap — page the range into smaller
    /// rescans.
    RangeTooLarge,
    /// The server has no block-scan source (no local block bodies/undo).
    NoSource,
    /// The connection watches nothing — a rescan could match nothing. Register a
    /// watch-set first.
    EmptyWatchSet,
    /// A reason code this client build does not recognize (a newer server).
    Unknown,
}

/// Map the proto `RescanRejected.Reason` enum (an `i32` on the wire) to the
/// client enum, treating an unrecognized code as [`RescanRejectReason::Unknown`].
fn rescan_reject_reason(reason: i32) -> RescanRejectReason {
    match pb::rescan_rejected::Reason::try_from(reason) {
        Ok(pb::rescan_rejected::Reason::RateLimited) => RescanRejectReason::RateLimited,
        Ok(pb::rescan_rejected::Reason::ConcurrentRescan) => RescanRejectReason::ConcurrentRescan,
        Ok(pb::rescan_rejected::Reason::InvalidRange) => RescanRejectReason::InvalidRange,
        Ok(pb::rescan_rejected::Reason::RangeTooLarge) => RescanRejectReason::RangeTooLarge,
        Ok(pb::rescan_rejected::Reason::NoSource) => RescanRejectReason::NoSource,
        Ok(pb::rescan_rejected::Reason::EmptyWatchSet) => RescanRejectReason::EmptyWatchSet,
        Ok(pb::rescan_rejected::Reason::Unspecified) | Err(_) => RescanRejectReason::Unknown,
    }
}

impl From<pb::NodeEvent> for Event {
    fn from(ev: pb::NodeEvent) -> Self {
        use pb::node_event::Body;
        let Some(body) = ev.body else { return Event::Unknown };
        match body {
            Body::Mempool(m) => mempool_event(m),
            Body::Chain(c) => chain_event(c),
            Body::Heartbeat(h) => Event::Heartbeat { uptime_ns: h.uptime_ns },
            Body::OutpointSpent(o) => Event::OutpointSpent {
                outpoint: Outpoint { txid: o.outpoint_txid, vout: o.outpoint_vout },
                spending_txid: o.spending_txid,
                spending_vin: o.spending_vin,
                confirmed: o.confirmed,
            },
            Body::ScriptMatched(s) => Event::ScriptMatched {
                scripthash: s.scripthash,
                txid: s.txid,
                is_output: s.is_output,
                index: s.index,
                confirmed: s.confirmed,
                amount: s.has_amount.then_some(s.amount),
                raw_tx: (!s.raw_tx.is_empty()).then_some(s.raw_tx),
                descriptors: s
                    .descriptor_matches
                    .into_iter()
                    .map(|d| DescriptorMatch {
                        descriptor: d.descriptor,
                        branch: d.branch,
                        derivation_index: d.derivation_index,
                    })
                    .collect(),
            },
            Body::TxidMatched(t) => Event::TxidMatched {
                txid: t.txid,
                confirmed: t.confirmed,
                height: t.height,
            },
            Body::TxidReplaced(t) => Event::TxidReplaced {
                txid: t.txid,
                replacing_txid: t.replacing_txid,
            },
            Body::TxidEvicted(t) => Event::TxidEvicted { txid: t.txid, reason: t.reason },
            Body::TxidUnconfirmed(t) => Event::TxidUnconfirmed {
                txid: t.txid,
                prev_height: t.prev_height,
            },
            Body::TxidDepthReached(t) => Event::TxidDepthReached {
                txid: t.txid,
                depth: t.depth,
                height: t.height,
            },
            Body::TxidFinalized(t) => Event::TxidFinalized {
                txid: t.txid,
                depth: t.depth,
                height: t.height,
            },
            // A PrefixMatched without its bucket is a degenerate message the
            // local re-filter cannot use (bits:0 matches nothing meaningfully);
            // surface it as Unknown rather than a structurally-valid-looking 0.
            Body::PrefixMatched(p) => match p.prefix {
                Some(sp) => Event::PrefixMatched(PrefixMatch {
                    prefix: ScriptPrefix { prefix: sp.prefix, bits: sp.bits },
                    raw_tx: p.raw_tx,
                    confirmed: p.confirmed,
                    height: p.height,
                    matched_prevouts: p.matched_prevouts.into_iter().map(Into::into).collect(),
                }),
                None => Event::Unknown,
            },
            Body::Lagged(l) => Event::Lagged {
                dropped_count: l.dropped_count,
                resume_cursor: l.resume_cursor,
            },
            Body::SetCursorResult(r) => match r.outcome {
                Some(pb::set_cursor_result::Outcome::Accepted(a)) => Event::CursorAccepted {
                    from: a.from,
                    clamped: a.clamped,
                    earliest_replayed: a.earliest_replayed,
                },
                Some(pb::set_cursor_result::Outcome::Rejected(rj)) => Event::CursorRejected {
                    reason: cursor_reject_reason(rj.reason),
                    current_head: rj.current_head,
                },
                // A result frame with no outcome set is a degenerate message.
                None => Event::Unknown,
            },
            Body::SetWatchSetResult(r) => match r.outcome {
                Some(pb::watch_set_result::Outcome::Accepted(a)) => Event::WatchSetReplaced {
                    added: a.added,
                    removed: a.removed,
                    unchanged: a.unchanged,
                },
                Some(pb::watch_set_result::Outcome::Rejected(rj)) => Event::WatchSetRejected {
                    reason: watch_set_reject_reason(rj.reason),
                    required: rj.required,
                    quota: rj.quota,
                },
                None => Event::Unknown,
            },
            Body::RescanResult(r) => match r.outcome {
                Some(pb::rescan_result::Outcome::Accepted(a)) => Event::RescanAccepted {
                    from_height: a.from_height,
                    to_height: a.to_height,
                    clamped: a.clamped,
                },
                Some(pb::rescan_result::Outcome::Rejected(rj)) => Event::RescanRejected {
                    reason: rescan_reject_reason(rj.reason),
                    tip_height: rj.tip_height,
                },
                None => Event::Unknown,
            },
            Body::RescanComplete(c) => Event::RescanComplete {
                from_height: c.from_height,
                to_height: c.to_height,
                matches: c.matches,
            },
            // BIP 352 silent payments (§7.7). Tier 1 firehose tweaks and the
            // Tier 2 scan-key match.
            Body::BlockTweaks(b) => Event::BlockTweaks {
                block_hash: b.block_hash,
                height: b.height,
                entries: b
                    .entries
                    .into_iter()
                    .map(|e| TweakEntry {
                        tweak: e.tweak,
                        txid: e.txid,
                        max_value: e.max_value,
                    })
                    .collect(),
                filtered: b.filtered,
            },
            Body::MempoolTweak(m) => Event::MempoolTweak {
                entry: m
                    .entry
                    .map(|e| TweakEntry {
                        tweak: e.tweak,
                        txid: e.txid,
                        max_value: e.max_value,
                    })
                    // A well-formed MempoolTweak always carries its entry; an
                    // absent one (malformed wire) degrades to an empty entry
                    // rather than dropping the event.
                    .unwrap_or(TweakEntry {
                        tweak: Vec::new(),
                        txid: Vec::new(),
                        max_value: 0,
                    }),
            },
            Body::SilentPaymentMatched(s) => Event::SilentPaymentMatched {
                scan_pubkey: s.scan_pubkey,
                txid: s.txid,
                vout: s.vout,
                output_pubkey: s.output_pubkey,
                amount: s.amount,
                tweak: s.tweak,
                k: s.k,
                label: s.has_label.then_some(s.label),
                confirmed: s.confirmed,
                // `height` is 0 on the wire while unconfirmed; surface `None`.
                height: s.confirmed.then_some(s.height),
                raw_tx: (!s.raw_tx.is_empty()).then_some(s.raw_tx),
            },
            // Forward-compatible catch-all: any body a still-newer proto adds maps
            // to `Unknown`. It is unreachable against the *current* workspace proto
            // (every body above is now typed), but retained so this crate keeps
            // compiling if the schema grows ahead of these arms — the same
            // resilience the SP bodies themselves relied on before they were typed.
            #[allow(unreachable_patterns)]
            _ => Event::Unknown,
        }
    }
}

/// Map the proto `CursorRejected.Reason` enum (an `i32` on the wire) to the
/// client enum, treating an unrecognized code as [`CursorRejectReason::Unknown`].
fn cursor_reject_reason(reason: i32) -> CursorRejectReason {
    match pb::cursor_rejected::Reason::try_from(reason) {
        Ok(pb::cursor_rejected::Reason::RateLimited) => CursorRejectReason::RateLimited,
        Ok(pb::cursor_rejected::Reason::ConcurrentReanchor) => {
            CursorRejectReason::ConcurrentReanchor
        }
        Ok(pb::cursor_rejected::Reason::EmptyCursor) => CursorRejectReason::EmptyCursor,
        Ok(pb::cursor_rejected::Reason::NoSource) => CursorRejectReason::NoSource,
        Ok(pb::cursor_rejected::Reason::Unspecified) | Err(_) => CursorRejectReason::Unknown,
    }
}

fn mempool_event(m: pb::MempoolEvent) -> Event {
    use pb::mempool_event::Body;
    match m.body {
        Some(Body::Enter(e)) => Event::MempoolEnter {
            txid: e.txid,
            fee: e.fee,
            vsize: e.vsize,
            fee_rate_sat_per_kvb: e.fee_rate_sat_per_kvb,
            time: e.time,
        },
        Some(Body::LeaveConfirmed(e)) => Event::MempoolLeaveConfirmed {
            txid: e.txid,
            block_hash: e.block_hash,
            height: e.height,
        },
        Some(Body::LeaveEvicted(e)) => {
            let reason = e.reason().into();
            Event::MempoolLeaveEvicted { txid: e.txid, reason }
        }
        Some(Body::LeaveReplaced(e)) => Event::MempoolLeaveReplaced {
            txid: e.txid,
            replacing_txid: e.replacing_txid,
        },
        None => Event::Unknown,
    }
}

fn chain_event(c: pb::ChainEvent) -> Event {
    use pb::chain_event::Body;
    match c.body {
        Some(Body::BlockConnected(b)) => Event::BlockConnected { hash: b.hash, height: b.height },
        Some(Body::BlockDisconnected(b)) => {
            Event::BlockDisconnected { hash: b.hash, height: b.height }
        }
        Some(Body::Reorg(r)) => Event::Reorg {
            from_height: r.from_height,
            old_tip: r.old_tip,
            to_height: r.to_height,
            new_tip: r.new_tip,
        },
        None => Event::Unknown,
    }
}
