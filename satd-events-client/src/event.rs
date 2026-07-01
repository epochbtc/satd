//! Typed event model — an ergonomic mirror of the `satd.events.v1` wire
//! `NodeEvent.body` tagged union, so consumers `match` on a flat enum instead
//! of unwrapping nested protobuf `Option`s.
//!
//! Hashes and txids are carried as raw `Vec<u8>` here; the optional `bitcoin`
//! feature layers typed conversions on top (the prefix-watch re-filter and
//! scripthash helpers).

use satd_events_proto::v1 as pb;

/// Durable resume position, re-exported from the wire schema. Persist the
/// value returned by [`EventStream::cursor`](crate::EventStream::cursor) and
/// present it again as `from_cursor` to resume.
pub use satd_events_proto::v1::Cursor;

/// An outpoint (`txid:vout`), raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outpoint {
    /// Transaction id, 32 raw bytes (internal byte order).
    pub txid: Vec<u8>,
    /// Output index.
    pub vout: u32,
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
    /// UNCHANGED (the prior set is still in effect). For
    /// [`QuotaExceeded`](WatchSetRejectReason::QuotaExceeded), the target's total
    /// quota cost (`required`) exceeds the principal's `quota` — shed items and
    /// retry. For [`Malformed`](WatchSetRejectReason::Malformed) the server could
    /// not parse or expand an element of the snapshot (`required`/`quota` are 0);
    /// this is a client bug, not a transient condition. Either way the client's
    /// mirror still reflects the (unapplied) reloaded set, so a consumer that
    /// ignores this keeps an over-claiming mirror; react by reloading a set that
    /// the server accepts.
    WatchSetRejected {
        /// Why the replace was refused.
        reason: WatchSetRejectReason,
        /// Total watch units the rejected target set needs (0 for `Malformed`).
        required: u64,
        /// The principal's quota ceiling (0 for `Malformed`).
        quota: u64,
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
    /// The target set's total unit cost exceeds the principal's quota — shed
    /// items and retry. Transient: a smaller set fits.
    QuotaExceeded,
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
        Ok(pb::watch_set_rejected::Reason::Malformed) => WatchSetRejectReason::Malformed,
        Ok(pb::watch_set_rejected::Reason::Unspecified) | Err(_) => WatchSetRejectReason::Unknown,
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
