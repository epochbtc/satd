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

use super::{Cursor, EdgeStamp, EventPublisher, NodeEvent, NodeEventBody};

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
/// `category_mask` follows the wire convention (mempool=1, chain=2); pass
/// `u32::MAX` for "all".
pub fn build_cursor_replay(
    src: &dyn BlockCursorSource,
    publisher: &EventPublisher,
    from: Cursor,
    category_mask: u32,
    max_blocks: u32,
) -> CursorReplay {
    let snapshot_tip = src.current_tip_height();
    let mut start = from.height.saturating_add(1);
    // Bound the confirmed replay span. A cursor far behind the tip would
    // otherwise stream the entire chain (a DoS amplification) and build an
    // unbounded boundary-dedup map. Replayed events carry their height cursor,
    // so a client can detect the resulting gap and full-resync the rest.
    if snapshot_tip >= start && snapshot_tip - start + 1 > max_blocks {
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

    let mut events: Vec<NodeEvent> = Vec::new();
    let mut confirmed_dedup: HashMap<u32, BlockHash> = HashMap::new();
    if category_mask & 2 != 0 && start <= snapshot_tip {
        for (h, hash) in src.active_chain_range(start, snapshot_tip) {
            confirmed_dedup.insert(h, hash);
            events.push(synth_block_connected(publisher, h, hash));
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
    }
}

/// Synthesize a confirmed `BlockConnected` replay event for `height` from a
/// captured snapshot `hash`. The stamp's `seq` is 0 and `edge_seen_at_ns` is 0
/// — a replayed confirmed event is positioned by its durable `(height,
/// tx_index)` cursor, not the volatile per-publisher seq.
fn synth_block_connected(publisher: &EventPublisher, height: u32, hash: BlockHash) -> NodeEvent {
    let edge = publisher.edge();
    let stamp = EdgeStamp {
        node_id: edge.node_id,
        region: edge.region,
        edge_seen_at_ns: 0,
        edge_wall_ns: now_wall_ns(),
        seq: 0,
    };
    let cursor = Cursor {
        height,
        tx_index: 0,
        mempool_seq: 0,
        instance_id: edge.instance_id,
    };
    NodeEvent::with_cursor(
        stamp,
        Some(cursor),
        NodeEventBody::Chain(ChainEvent::BlockConnected { hash, height }),
    )
}

fn now_wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
