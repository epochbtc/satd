//! Block-index access + the shared durable cursor-replay builder.
//!
//! The streaming event carriers (gRPC `Subscribe`, the `--streamws` WS/SSE
//! firehose) resume a client from a durable [`Cursor`](super::Cursor) by
//! replaying confirmed history forward from the block store, then joining the
//! live broadcast (the snapshot→live handoff). [`build_cursor_replay`] is the
//! single implementation of that handoff, shared by every carrier so the clamp,
//! reorg-safety, instance-epoch, and boundary-dedup semantics are identical on
//! the wire regardless of transport.
//!
//! The replay is **read-only and off the consensus hot path**: it reads blocks
//! the node already holds and never blocks, locks, or backpressures block
//! connection.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::BlockHash;

use crate::chain::events::ChainEvent;

use super::{
    Cursor, CursorRejectReason, EdgeStamp, EventPublisher, NodeEvent, NodeEventBody,
    SetCursorOutcome,
};

/// Upper bound on the confirmed-block span replayed for a single `from_cursor`
/// resume. A client resuming from a cursor more than this many blocks behind
/// the tip has its replay window clamped to the most recent `MAX_REPLAY_BLOCKS`
/// (logged); it should full-resync the older history out-of-band rather than
/// stream the whole chain over the event channel. Shared by every streaming
/// carrier so the cap is identical on the wire. This bounds both the
/// per-subscriber replay work and the boundary-dedup map built from the
/// captured snapshot.
pub const MAX_REPLAY_BLOCKS: u32 = 10_000;

/// Read-only active-chain access for confirmed cursor replay.
///
/// Implemented by [`ChainState`](crate::chain::state::ChainState). All methods
/// describe the **active chain** only.
pub trait BlockCursorSource: Send + Sync {
    /// Current active-chain tip height.
    fn current_tip_height(&self) -> u32;

    /// Active-chain block hashes for the heights in `[from, to]` (inclusive),
    /// height-ascending. Resolved by walking the active chain back from the tip
    /// **once** (O(tip − from), not O(span²)) so it is reorg-safe: it follows
    /// `prev_blockhash` from the tip and is therefore immune to the pollutable
    /// `height_hash` index (which `get_block_hash_by_height` reads and which a
    /// header-first / out-of-order `store_block` path can populate with a
    /// side-chain or header-only block). Heights above the tip are omitted; an
    /// active-chain block-index gap truncates the lower end of the range.
    fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)>;
}

impl BlockCursorSource for crate::chain::state::ChainState {
    fn current_tip_height(&self) -> u32 {
        // Inherent method on ChainState; no clash since the trait method
        // has a distinct name.
        self.tip_height()
    }

    fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)> {
        let (tip_hash, tip_height) = self.tip_snapshot();
        let hi = to.min(tip_height);
        if from > hi {
            return Vec::new();
        }
        // Walk back from the tip to `hi` first (these are above the requested
        // range), then collect `[from, hi]` descending and reverse. Using
        // `tip_snapshot` + `prev_blockhash` means the hashes are the genuine
        // active-chain blocks, not whatever the pollutable height→hash index
        // currently points at.
        let mut cur = tip_hash;
        let mut h = tip_height;
        while h > hi {
            match self.get_block_index(&cur) {
                Some(entry) => {
                    cur = entry.header.prev_blockhash;
                    h -= 1;
                }
                None => return Vec::new(),
            }
        }
        let mut out: Vec<(u32, BlockHash)> = Vec::with_capacity((hi - from + 1) as usize);
        loop {
            out.push((h, cur));
            if h == from {
                break;
            }
            match self.get_block_index(&cur) {
                Some(entry) => {
                    cur = entry.header.prev_blockhash;
                    h -= 1;
                }
                None => break,
            }
        }
        out.reverse();
        out
    }
}

/// Full block-body + undo access for a **bounded historical rescan**
/// ([`RescanBlocks`] on the Watch stream). Extends [`BlockCursorSource`]
/// (heights + hashes only) with the two reads the matcher needs to reproduce
/// confirmed watch-matches over a closed range: the block's transactions and
/// its undo data (spent-prevout coins, which drive input-side script/prefix
/// matching — the spending tx alone carries no prevout `scriptPubKey`).
///
/// Implemented by [`ChainState`](crate::chain::state::ChainState). Reads blocks
/// the node already holds; **read-only and off the consensus hot path**, exactly
/// like [`build_cursor_replay`].
///
/// [`RescanBlocks`]: https://docs.rs/satd-events-proto
pub trait BlockScanSource: BlockCursorSource {
    /// Full block for `hash`, or `None` if not held locally (pruned or
    /// header-only). A rescan silently skips heights whose body is unavailable.
    fn block_body(&self, hash: &BlockHash) -> Option<bitcoin::Block>;

    /// Undo data for `hash` (spent coins, one per non-coinbase input in connect
    /// order), or `None` if not held. Needed only when a script or prefix is
    /// watched; the caller skips fetching it otherwise.
    fn block_undo(&self, hash: &BlockHash) -> Option<crate::storage::undo::UndoData>;
}

impl BlockScanSource for crate::chain::state::ChainState {
    fn block_body(&self, hash: &BlockHash) -> Option<bitcoin::Block> {
        self.get_block(hash)
    }

    fn block_undo(&self, hash: &BlockHash) -> Option<crate::storage::undo::UndoData> {
        self.get_undo(hash)
    }
}

/// Span cap for a single [`RescanBlocks`]: the maximum number of blocks one
/// bounded historical rescan may scan. Set equal to [`MAX_REPLAY_BLOCKS`] — a
/// rescan does strictly more work per block (full body + undo read + matcher)
/// than a forward replay (index read + event synthesis), so it is capped no
/// looser. A client covering a wider range pages it into successive rescans.
pub const MAX_RESCAN_BLOCKS: u32 = MAX_REPLAY_BLOCKS;

/// Why a bounded historical rescan was refused. The carrier maps this to the
/// wire `RescanRejected.Reason`. `RateLimited` / `ConcurrentRescan` / `NoSource`
/// / `EmptyWatchSet` are decided by the carrier (rate policy, in-flight guard,
/// source/watch-set presence); [`plan_rescan`] produces only the range verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescanRejectReason {
    /// Per-principal rescan rate limit exceeded.
    RateLimited,
    /// Another rescan is already draining on this connection.
    ConcurrentRescan,
    /// `to < from`, or the requested range lies entirely above the active tip.
    InvalidRange,
    /// The (clamped) span exceeds [`MAX_RESCAN_BLOCKS`].
    RangeTooLarge,
    /// No block-scan source is configured (no local block bodies/undo).
    NoSource,
    /// The connection watches nothing — a rescan could match nothing.
    EmptyWatchSet,
}

/// The admitted, clamped range a rescan will actually scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RescanPlan {
    /// First height to scan (inclusive).
    pub from: u32,
    /// Last height to scan (inclusive), clamped to the active tip.
    pub to: u32,
    /// The requested upper bound exceeded the tip and was narrowed to it.
    pub clamped: bool,
}

/// Validate and clamp a requested rescan range `[from, to]` against `src`'s
/// active chain. Pure (no block reads): rejects an inverted range, a range
/// wholly above the tip, or one whose clamped span exceeds
/// [`MAX_RESCAN_BLOCKS`]; otherwise returns the range to scan with the upper end
/// clamped to the current tip (`clamped` set when narrowing occurred).
pub fn plan_rescan(
    src: &dyn BlockScanSource,
    from: u32,
    to: u32,
) -> Result<RescanPlan, RescanRejectReason> {
    if to < from {
        return Err(RescanRejectReason::InvalidRange);
    }
    let tip = src.current_tip_height();
    if from > tip {
        // Nothing on the active chain to scan (the whole range is in the future).
        return Err(RescanRejectReason::InvalidRange);
    }
    let hi = to.min(tip);
    let clamped = to > tip;
    let span = hi - from + 1;
    if span > MAX_RESCAN_BLOCKS {
        return Err(RescanRejectReason::RangeTooLarge);
    }
    Ok(RescanPlan {
        from,
        to: hi,
        clamped,
    })
}

/// Result of a durable cursor replay: the events to emit before the live
/// stream, plus the boundary-dedup keys the live filter uses to suppress
/// duplicates at the snapshot→live seam.
pub struct CursorReplay {
    /// Replay events in emit order: confirmed `BlockConnected` (height
    /// ascending) followed by the best-effort mempool window. Each carrier
    /// renders these its own way (gRPC → proto, WS/SSE → JSON), then joins
    /// live.
    pub events: Vec<NodeEvent>,
    /// Confirmed snapshot, height → hash. A live `BlockConnected` whose hash
    /// equals the captured hash at its height is a true duplicate (it connected
    /// during the subscribe→snapshot window) and must be dropped; a reorg
    /// replacement at the same height has a different hash and must be
    /// forwarded so the client's confirmed view stays correct.
    pub confirmed_dedup: HashMap<u32, BlockHash>,
    /// Highest replayed mempool `seq`. Live mempool events at or below it were
    /// already replayed and must be dropped.
    pub mempool_dedup_through: u64,
    /// First confirmed height the replay will emit (`from.height + 1` normally;
    /// higher when the requested span exceeded `max_blocks` and the lower end
    /// was clamped). `clamped` records whether that truncation happened, so a
    /// carrier can surface a deterministic "accepted but clamped — resync below
    /// this height" signal (see [`CursorAccepted`](crate::events) on the wire).
    /// When no confirmed replay runs (chain category masked off, or the cursor
    /// is at/after the tip), this is `from.height + 1` and `clamped` is false.
    pub earliest_replayed: u32,
    /// True when the requested replay span was older than `max_blocks` and the
    /// lower end was dropped.
    pub clamped: bool,
}

/// Build the durable cursor replay (snapshot→live handoff) shared by all
/// streaming carriers.
///
/// - **Confirmed** history is replayed forward from `from.height + 1` to the
///   current tip, gated on the chain category bit, **clamped** to the most
///   recent `max_blocks` (a far-behind cursor must not stream the whole chain),
///   and resolved reorg-safely via [`BlockCursorSource::active_chain_range`].
/// - **Mempool** history is replayed from the publisher's bounded ring, gated
///   on the mempool category bit. The cursor's `mempool_seq` is honored only
///   when `from.instance_id` matches the live publisher; on a mismatch (the
///   daemon restarted since the cursor was issued) the stale watermark is
///   discarded and the full retained window is replayed.
///
/// `category_mask` follows the wire convention (mempool=1, chain=2, tweaks=8);
/// pass [`ALL_CATEGORIES_DEFAULT`](super::ALL_CATEGORIES_DEFAULT) for "all".
///
/// `tweak_source` is the silent-payment index read handle, consulted only when
/// the `tweaks` bit is set. A **tweaks-only** subscription (`category_mask ==
/// tweaks`) against a complete index is exempt from the `max_blocks` clamp —
/// each `sp_tweaks` row embeds the hash of the block it describes (§3.2), so a
/// phone can cold-sync from taproot activation in one subscription without a
/// height→hash lookup. A **mixed** subscription keeps the clamp for every
/// category, so tweak and chain replay stay cursor-ordered. Callers that will
/// not serve tweaks (or reject before replay when the index is incomplete)
/// pass `None`.
pub fn build_cursor_replay(
    src: &dyn BlockCursorSource,
    publisher: &EventPublisher,
    from: Cursor,
    category_mask: u32,
    max_blocks: u32,
    tweak_source: Option<&dyn node_sp_index::SpIndex>,
) -> CursorReplay {
    use super::{CATEGORY_CHAIN, CATEGORY_TWEAKS};

    let snapshot_tip = src.current_tip_height();
    let chain_on = category_mask & CATEGORY_CHAIN != 0;
    let tweaks_on = category_mask & CATEGORY_TWEAKS != 0;
    // The tweak read handle is only relevant when the bit is set.
    let sp = tweak_source.filter(|_| tweaks_on);
    // Deep-replay exemption: a tweaks-ONLY subscription against a complete
    // index replays unclamped from the requested cursor. A partial index is
    // never treated as authoritative (the carrier rejects a replay request in
    // that state before calling us), so we still gate on `is_complete()`.
    let tweaks_only_sub = category_mask == CATEGORY_TWEAKS;
    let deep_exempt = tweaks_only_sub && sp.map(|s| s.is_complete()).unwrap_or(false);

    let requested_start = from.height.saturating_add(1);
    let mut start = requested_start;
    // Bound the confirmed replay span. A cursor far behind the tip would
    // otherwise stream the entire chain (a DoS amplification) and build an
    // unbounded boundary-dedup map. Replayed events carry their height cursor,
    // so a client can detect the resulting gap and full-resync the rest.
    // Only meaningful when confirmed history is actually being replayed (chain
    // and/or tweaks). The tweaks-only deep-replay exemption skips the clamp;
    // every other case (chain, or mixed chain+tweaks) keeps it.
    let clampable = (chain_on || tweaks_on) && !deep_exempt;
    if clampable && snapshot_tip >= start && snapshot_tip - start + 1 > max_blocks {
        let clamped = snapshot_tip - max_blocks + 1;
        tracing::warn!(
            target: "events::replay",
            requested_from = start,
            clamped_from = clamped,
            snapshot_tip,
            "from_cursor replay span exceeds cap; clamping (client should \
             full-resync earlier history)",
        );
        start = clamped;
    }
    let clamped = start != requested_start;

    let mut events: Vec<NodeEvent> = Vec::new();
    let mut confirmed_dedup: HashMap<u32, BlockHash> = HashMap::new();
    if deep_exempt && start <= snapshot_tip {
        // Unclamped tweaks-only cold-sync: read rows by height. Each row is
        // self-authenticating (carries its own block hash), so no
        // `active_chain_range` height→hash pass is needed. Below taproot
        // activation the index has no row — `NotFound` is skipped, not an error.
        let sp = sp.expect("deep_exempt implies a tweak source");
        for h in start..=snapshot_tip {
            if let Ok(row) = sp.tweaks_at(h) {
                events.push(synth_block_tweaks(publisher, h, row));
            }
        }
    } else if (chain_on || tweaks_on) && start <= snapshot_tip {
        // Clamped window: walk the active chain once, interleaving each
        // height's BlockConnected (if requested) and its BlockTweaks (if
        // requested) so cursors stay monotonic across a mixed subscription.
        for (h, hash) in src.active_chain_range(start, snapshot_tip) {
            if chain_on {
                confirmed_dedup.insert(h, hash);
                events.push(synth_block_connected(publisher, h, hash));
            }
            if let Some(sp) = sp
                && let Ok(row) = sp.tweaks_at(h)
                && row.block_hash == hash
            {
                events.push(synth_block_tweaks(publisher, h, row));
            }
        }
    }

    let mut mempool_dedup_through = 0u64;
    if category_mask & 1 != 0 {
        let mempool_since = if from.instance_id == publisher.instance_id() {
            from.mempool_seq
        } else {
            tracing::info!(
                target: "events::replay",
                cursor_instance = from.instance_id,
                live_instance = publisher.instance_id(),
                "from_cursor instance mismatch (daemon restarted since cursor \
                 issued); discarding stale mempool_seq, replaying full window",
            );
            0
        };
        let mp = publisher.replay_mempool_since(mempool_since);
        if let Some(last) = mp.last() {
            mempool_dedup_through = last.stamp.seq;
        }
        events.extend(mp);
    }

    CursorReplay {
        events,
        confirmed_dedup,
        mempool_dedup_through,
        earliest_replayed: start,
        clamped,
    }
}

/// Synthesize a confirmed `BlockConnected` replay event for `height` from a
/// captured snapshot `hash`. The stamp's `seq` is 0 and `edge_seen_at_ns` is 0
/// — a replayed confirmed event is positioned by its durable `(height,
/// tx_index)` cursor, not the volatile per-publisher seq.
fn synth_block_connected(publisher: &EventPublisher, height: u32, hash: BlockHash) -> NodeEvent {
    let cursor = Cursor {
        height,
        tx_index: 0,
        mempool_seq: 0,
        instance_id: publisher.instance_id(),
    };
    NodeEvent::with_cursor(
        synth_stamp(publisher),
        Some(cursor),
        NodeEventBody::Chain(ChainEvent::BlockConnected { hash, height }),
    )
}

/// Synthesize a confirmed `BlockTweaks` replay event for `height` from an
/// `sp_tweaks` row. Positioned by the same durable `(height, tx_index=0)`
/// cursor as the confirmed chain replay, so a tweaks subscriber can resume
/// mid-sync. The row embeds the block hash it describes, so the event is
/// self-authenticating with no height→hash lookup.
fn synth_block_tweaks(
    publisher: &EventPublisher,
    height: u32,
    row: node_sp_index::SpBlockRow,
) -> NodeEvent {
    let cursor = Cursor {
        height,
        tx_index: 0,
        mempool_seq: 0,
        instance_id: publisher.instance_id(),
    };
    NodeEvent::with_cursor(
        synth_stamp(publisher),
        Some(cursor),
        NodeEventBody::BlockTweaks(super::BlockTweaks::from_row(height, &row)),
    )
}

/// Build the in-band [`NodeEventBody::Lagged`] notice a carrier emits when it
/// drops events for a slow subscriber: `dropped_count` skipped, with
/// `resume_cursor` (the last position delivered before the gap) so the client
/// can reconnect via `from_cursor` and recover the gap. Carried as a
/// synthesized event (seq 0) so every transport renders it the same way.
pub fn lagged_event(
    publisher: &EventPublisher,
    dropped_count: u64,
    resume_cursor: Cursor,
) -> NodeEvent {
    NodeEvent::with_cursor(
        synth_stamp(publisher),
        Some(resume_cursor),
        NodeEventBody::Lagged {
            dropped_count,
            resume_cursor,
        },
    )
}

/// Build the in-band [`NodeEventBody::SetCursorResult`] ack a carrier emits when
/// a mid-stream re-anchor is **admitted**: emitted (seq 0) immediately ahead of
/// the replay batch so the client knows replay is now running. `clamped` /
/// `earliest_replayed` come straight from the [`CursorReplay`] the carrier is
/// about to drain.
pub fn cursor_accepted_event(
    publisher: &EventPublisher,
    from: Cursor,
    clamped: bool,
    earliest_replayed: u32,
) -> NodeEvent {
    NodeEvent::new(
        synth_stamp(publisher),
        NodeEventBody::SetCursorResult(SetCursorOutcome::Accepted {
            from,
            clamped,
            earliest_replayed,
        }),
    )
}

/// Build the in-band [`NodeEventBody::SetCursorResult`] notice a carrier emits
/// when a mid-stream re-anchor is **not** admitted (rate limit, a re-anchor
/// already draining, an empty cursor, or no block source). The live stream is
/// unchanged; `current_head` is the subscriber's current resume position so the
/// client can retry, back off, or escalate to a full resnapshot.
pub fn cursor_rejected_event(
    publisher: &EventPublisher,
    reason: CursorRejectReason,
    current_head: Cursor,
) -> NodeEvent {
    NodeEvent::new(
        synth_stamp(publisher),
        NodeEventBody::SetCursorResult(SetCursorOutcome::Rejected {
            reason,
            current_head,
        }),
    )
}

/// Edge stamp for a synthesized (replay / lag) event: real `node_id`/`region`,
/// but `seq` and `edge_seen_at_ns` are 0 — such an event is positioned by its
/// cursor, not the volatile per-publisher seq.
fn synth_stamp(publisher: &EventPublisher) -> EdgeStamp {
    let edge = publisher.edge();
    EdgeStamp {
        node_id: edge.node_id,
        region: edge.region,
        edge_seen_at_ns: 0,
        edge_wall_ns: now_wall_ns(),
        seq: 0,
    }
}

fn now_wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CATEGORY_CHAIN, CATEGORY_TWEAKS, EdgeIdentity};
    use bitcoin::hashes::Hash;

    /// A `BlockCursorSource` with a flat synthetic active chain `[1, tip]`.
    struct FlatChain {
        tip: u32,
    }

    impl BlockCursorSource for FlatChain {
        fn current_tip_height(&self) -> u32 {
            self.tip
        }
        fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)> {
            let hi = to.min(self.tip);
            if from > hi {
                return Vec::new();
            }
            (from..=hi)
                .map(|h| (h, BlockHash::from_byte_array([h as u8; 32])))
                .collect()
        }
    }

    // Bodies are unused by `plan_rescan` (pure range planning); the flat chain
    // holds no real blocks.
    impl BlockScanSource for FlatChain {
        fn block_body(&self, _hash: &BlockHash) -> Option<bitcoin::Block> {
            None
        }
        fn block_undo(&self, _hash: &BlockHash) -> Option<crate::storage::undo::UndoData> {
            None
        }
    }

    #[test]
    fn plan_rescan_clamps_upper_to_tip() {
        let src = FlatChain { tip: 100 };
        let plan = plan_rescan(&src, 10, 500).expect("admitted");
        assert_eq!((plan.from, plan.to), (10, 100));
        assert!(plan.clamped, "upper bound above tip → clamped");
    }

    #[test]
    fn plan_rescan_within_chain_is_not_clamped() {
        let src = FlatChain { tip: 100 };
        let plan = plan_rescan(&src, 10, 90).expect("admitted");
        assert_eq!((plan.from, plan.to, plan.clamped), (10, 90, false));
    }

    #[test]
    fn plan_rescan_rejects_inverted_range() {
        let src = FlatChain { tip: 100 };
        assert_eq!(plan_rescan(&src, 50, 40), Err(RescanRejectReason::InvalidRange));
    }

    #[test]
    fn plan_rescan_rejects_range_above_tip() {
        let src = FlatChain { tip: 100 };
        assert_eq!(
            plan_rescan(&src, 101, 200),
            Err(RescanRejectReason::InvalidRange)
        );
    }

    #[test]
    fn plan_rescan_rejects_span_over_cap() {
        // A clamped span exceeding MAX_RESCAN_BLOCKS is refused.
        let src = FlatChain {
            tip: MAX_RESCAN_BLOCKS + 10,
        };
        assert_eq!(
            plan_rescan(&src, 0, MAX_RESCAN_BLOCKS),
            Err(RescanRejectReason::RangeTooLarge)
        );
        // Exactly at the cap is admitted.
        let plan = plan_rescan(&src, 1, MAX_RESCAN_BLOCKS).expect("at-cap admitted");
        assert_eq!(plan.to - plan.from + 1, MAX_RESCAN_BLOCKS);
    }

    #[test]
    fn plan_rescan_single_height() {
        let src = FlatChain { tip: 100 };
        let plan = plan_rescan(&src, 42, 42).expect("admitted");
        assert_eq!((plan.from, plan.to, plan.clamped), (42, 42, false));
    }

    fn publisher() -> std::sync::Arc<EventPublisher> {
        EventPublisher::new(EdgeIdentity::new([0xab; 16], Some("us-east1")).unwrap(), 16)
    }

    fn cursor(height: u32) -> Cursor {
        Cursor {
            height,
            tx_index: 0,
            mempool_seq: 0,
            instance_id: 0,
        }
    }

    #[test]
    fn in_window_replay_is_not_clamped() {
        let src = FlatChain { tip: 5 };
        let pubr = publisher();
        // chain-only mask (2); from height 2 ⇒ replay 3,4,5.
        let r = build_cursor_replay(&src, &pubr, cursor(2), 2, MAX_REPLAY_BLOCKS, None);
        assert!(!r.clamped);
        assert_eq!(r.earliest_replayed, 3, "earliest = from.height + 1");
        assert_eq!(r.events.len(), 3);
    }

    #[test]
    fn over_window_replay_reports_clamp() {
        let src = FlatChain { tip: 100 };
        let pubr = publisher();
        // max_blocks = 10; from height 2 would need 98 blocks ⇒ clamp the lower
        // end to tip - max_blocks + 1 = 91.
        let r = build_cursor_replay(&src, &pubr, cursor(2), 2, 10, None);
        assert!(r.clamped, "an over-window span is reported as clamped");
        assert_eq!(r.earliest_replayed, 91);
        assert_eq!(r.events.len(), 10, "exactly max_blocks replayed");
    }

    #[test]
    fn cursor_at_tip_is_not_clamped() {
        let src = FlatChain { tip: 5 };
        let pubr = publisher();
        // from the tip ⇒ nothing to replay, earliest = from.height + 1, no clamp.
        let r = build_cursor_replay(&src, &pubr, cursor(5), 2, MAX_REPLAY_BLOCKS, None);
        assert!(!r.clamped);
        assert_eq!(r.earliest_replayed, 6);
        assert!(r.events.is_empty());
    }

    #[test]
    fn chain_masked_off_does_not_clamp() {
        let src = FlatChain { tip: 100 };
        let pubr = publisher();
        // Ancient cursor that WOULD clamp if chain were on, but the chain
        // category bit (2) is masked off (mask = 1, mempool only). No confirmed
        // blocks replay, so the report must be "nothing skipped".
        let r = build_cursor_replay(&src, &pubr, cursor(2), 1, 10, None);
        assert!(!r.clamped, "no clamp reported when chain replay is masked off");
        assert_eq!(r.earliest_replayed, 3, "earliest = from.height + 1");
        assert!(
            r.events.is_empty(),
            "no confirmed blocks emitted with chain masked off"
        );
    }

    /// A mock tweak index over `[activation, tip]`. Rows carry the same
    /// synthetic block hash `FlatChain` uses (`[height; 32]`), so the mixed
    /// (`active_chain_range`) path's hash-match guard accepts them.
    struct MockSp {
        complete: bool,
        activation: u32,
        tip: u32,
    }

    impl node_sp_index::SpIndex for MockSp {
        fn tweaks_at(
            &self,
            height: u32,
        ) -> Result<node_sp_index::SpBlockRow, node_sp_index::SpIndexError> {
            if height < self.activation || height > self.tip {
                return Err(node_sp_index::SpIndexError::NotFound(height));
            }
            Ok(node_sp_index::SpBlockRow {
                block_hash: BlockHash::from_byte_array([height as u8; 32]),
                entries: vec![],
            })
        }
        fn is_complete(&self) -> bool {
            self.complete
        }
    }

    fn tweaks_count(r: &CursorReplay) -> usize {
        r.events
            .iter()
            .filter(|e| matches!(e.body, NodeEventBody::BlockTweaks(_)))
            .count()
    }

    #[test]
    fn tweaks_only_replay_is_unclamped_when_index_complete() {
        // tweaks-only mask (8), complete index, cursor far behind the tip: the
        // deep-replay exemption waives the clamp and replays every block.
        let src = FlatChain { tip: 50 };
        let pubr = publisher();
        let sp = MockSp { complete: true, activation: 1, tip: 50 };
        let r = build_cursor_replay(&src, &pubr, cursor(0), CATEGORY_TWEAKS, 10, Some(&sp));
        assert!(!r.clamped, "tweaks-only + complete index is exempt from the clamp");
        assert_eq!(r.earliest_replayed, 1);
        assert_eq!(tweaks_count(&r), 50, "all 50 blocks replayed unclamped");
        // No chain events on a tweaks-only subscription.
        assert!(r.events.iter().all(|e| matches!(e.body, NodeEventBody::BlockTweaks(_))));
    }

    #[test]
    fn tweaks_only_replay_clamps_when_index_incomplete() {
        // Without completeness the exemption does not apply, so the shared
        // builder falls back to the clamp (the carrier additionally rejects
        // such a replay in-band, but the builder itself must stay bounded).
        let src = FlatChain { tip: 50 };
        let pubr = publisher();
        let sp = MockSp { complete: false, activation: 1, tip: 50 };
        let r = build_cursor_replay(&src, &pubr, cursor(0), CATEGORY_TWEAKS, 10, Some(&sp));
        assert!(r.clamped, "incomplete index → clamped, not exempt");
        assert_eq!(tweaks_count(&r), 10, "clamped to the most recent max_blocks");
    }

    #[test]
    fn mixed_replay_keeps_clamp_and_interleaves() {
        // chain|tweaks (2|8): a mixed subscription keeps the clamp for both, and
        // per-height ordering is BlockConnected then BlockTweaks so cursors stay
        // monotonic.
        let src = FlatChain { tip: 50 };
        let pubr = publisher();
        let sp = MockSp { complete: true, activation: 1, tip: 50 };
        let mask = CATEGORY_CHAIN | CATEGORY_TWEAKS;
        let r = build_cursor_replay(&src, &pubr, cursor(0), mask, 10, Some(&sp));
        assert!(r.clamped, "mixed subscription keeps the clamp");
        assert_eq!(tweaks_count(&r), 10);
        assert_eq!(r.events.len(), 20, "10 chain + 10 tweak events");
        // First clamped height is 41; its chain event precedes its tweak event.
        assert!(matches!(
            r.events[0].body,
            NodeEventBody::Chain(ChainEvent::BlockConnected { height: 41, .. })
        ));
        assert!(matches!(&r.events[1].body, NodeEventBody::BlockTweaks(bt) if bt.height == 41));
        // Cursors are non-decreasing in height across the interleave.
        let heights: Vec<u32> = r.events.iter().filter_map(|e| e.cursor.map(|c| c.height)).collect();
        assert!(heights.windows(2).all(|w| w[0] <= w[1]), "cursor heights monotonic");
    }

    #[test]
    fn tweaks_replay_skips_below_activation() {
        // Heights below taproot activation have no row; they are skipped, not
        // errored, so the replay starts cleanly at activation.
        let src = FlatChain { tip: 30 };
        let pubr = publisher();
        let sp = MockSp { complete: true, activation: 20, tip: 30 };
        let r = build_cursor_replay(&src, &pubr, cursor(0), CATEGORY_TWEAKS, 10_000, Some(&sp));
        assert_eq!(tweaks_count(&r), 11, "only heights 20..=30 have rows");
    }

    #[test]
    fn tweaks_source_ignored_when_bit_not_set() {
        // A chain-only subscription never consults the tweak source.
        let src = FlatChain { tip: 5 };
        let pubr = publisher();
        let sp = MockSp { complete: true, activation: 1, tip: 5 };
        let r = build_cursor_replay(&src, &pubr, cursor(0), CATEGORY_CHAIN, 10_000, Some(&sp));
        assert_eq!(tweaks_count(&r), 0, "no tweak events without the tweaks bit");
    }
}
