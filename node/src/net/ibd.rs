use bitcoin::BlockHash;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::chain::state::ChainState;
use crate::net::peer::PeerId;

/// Phase of the IBD process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdPhase {
    HeaderDownload,
    Swarming,
    Done,
}

/// Per-peer tracking during IBD.
struct PeerSlots {
    /// Heights currently in-flight for this peer.
    assigned: Vec<u32>,
    /// Lifetime counter of blocks received from this peer.
    blocks_received: u64,
    /// Last time we received a block from this peer.
    last_activity: Instant,
    /// Number of distinct release *events* since the last successful block
    /// delivery from this peer. Reset to 0 on `block_received`. One event
    /// covers a burst of per-height releases that happen within
    /// `FAILURE_DEDUP_WINDOW` of each other — without that dedupe, a peer
    /// holding 16 near-cursor heights that all time out on the same pass
    /// would be counted as 16 failures in one go and dropped instantly even
    /// though it had been silent for only 15s.
    consecutive_failures: u32,
    /// Last time `record_failure` actually incremented `consecutive_failures`
    /// for this peer. Used to dedupe release bursts.
    last_failure_at: Option<Instant>,
}

/// BitTorrent-style download coordinator for parallel IBD.
///
/// Assigns random blocks from across the chain to many peers simultaneously,
/// maximizing download parallelism and avoiding the "slow peer bottleneck"
/// that sequential range assignment creates.
pub struct IbdScheduler {
    phase: IbdPhase,
    target_height: u32,

    /// Global pool of block heights still needing download, shuffled randomly.
    pending: VecDeque<u32>,

    /// Heights currently assigned to a peer (in-flight).
    in_flight: HashMap<u32, PeerId>,

    /// When each height was first assigned, for per-height stale detection.
    in_flight_at: HashMap<u32, Instant>,

    /// When the peer now holding each in-flight height was asked for it.
    /// `in_flight_at` survives hand-offs, so the 60s guard sees a height that
    /// no peer delivers; the near-cursor timeout judges the holder, and keyed
    /// on the first request it released a height from a peer that had only
    /// just been handed it (#972).
    requested_at: HashMap<u32, Instant>,

    /// How long a peer may hold blocks without delivering one before it is
    /// disconnected. Core's adaptive `m_block_stalling_timeout`: doubled,
    /// up to [`STALL_TIMEOUT_MAX`], each time a peer is dropped for stalling,
    /// so a node short of bandwidth does not drop every peer in turn, and
    /// brought back towards [`STALL_TIMEOUT_BASE`] as blocks connect.
    stall_timeout: Duration,

    /// Heights that have been downloaded (DataStored).
    downloaded: HashSet<u32>,

    /// Per-peer tracking.
    peer_slots: HashMap<PeerId, PeerSlots>,

    /// Max blocks in-flight per peer.
    per_peer_limit: u32,

    /// Max total blocks downloaded ahead of connect cursor.
    max_ahead: u32,

    /// Current connect cursor (last connected height).
    connect_cursor: u32,

    /// Height-to-hash mapping (populated from chain_state during creation).
    height_to_hash: HashMap<u32, BlockHash>,

    /// Per-(height, peer) cooldown timestamp. When a height is released from
    /// a peer (timeout or notfound), that peer is barred from being re-issued
    /// the same height until `cooldown_until > now`. Prevents the "silent
    /// peer keeps getting re-assigned the same height" wedge observed at
    /// height 785197 on the 2026-05-13 mainnet IBD run, where the 15s
    /// near-cursor timeout released a stuck height back to pending and the
    /// same peer immediately re-claimed it via its priority-zone scan.
    height_peer_cooldown: HashMap<u32, HashMap<PeerId, Instant>>,
}

/// The stall timeout's floor. Core starts at 2s, but judges only the peer
/// whose block the window is waiting on; satd judges every peer holding
/// blocks, and has used 15s for that.
pub const STALL_TIMEOUT_BASE: Duration = Duration::from_secs(15);

/// The stall timeout's ceiling, Core's `BLOCK_STALLING_TIMEOUT_MAX`.
pub const STALL_TIMEOUT_MAX: Duration = Duration::from_secs(64);

/// How long a peer is barred from re-claiming a height after it failed to
/// deliver. Pegged longer than the per-height stale timeout so the release
/// loop cannot reset it back to the same peer on the next pass.
const PEER_HEIGHT_COOLDOWN: Duration = Duration::from_secs(60);

/// Per-peer dedupe window for failure counting. A burst of per-height
/// releases for the same peer within this window counts as one failure
/// event — otherwise a peer with 16 near-cursor heights that all time out
/// in a single 15s pass would jump straight past the threshold and get
/// dropped on the very first stall instead of after sustained silence.
const FAILURE_DEDUP_WINDOW: Duration = Duration::from_secs(20);

/// Number of distinct release events since the last successful delivery
/// before a peer is considered silent and eligible for disconnect. With
/// `FAILURE_DEDUP_WINDOW=20s` this means ~60s of sustained silence before
/// a peer gets dropped.
pub const SILENT_PEER_FAILURE_THRESHOLD: u32 = 3;

impl IbdScheduler {
    /// Create a new scheduler for heights `(current_tip+1)..=target_height`.
    /// Shuffles the pending pool randomly for BitTorrent-style distribution.
    pub fn new(
        target_height: u32,
        current_tip: u32,
        chain_state: &ChainState,
        max_ahead: u32,
    ) -> Self {
        let mut heights: Vec<u32> = ((current_tip + 1)..=target_height).collect();
        heights.shuffle(&mut rand::thread_rng());

        // Build height-to-hash mapping
        let mut height_to_hash = HashMap::with_capacity(heights.len());
        for &h in &heights {
            if let Some(hash) = chain_state.get_block_hash_by_height(h) {
                height_to_hash.insert(h, hash);
            }
        }

        Self {
            phase: IbdPhase::Swarming,
            target_height,
            pending: VecDeque::from(heights),
            in_flight: HashMap::new(),
            in_flight_at: HashMap::new(),
            requested_at: HashMap::new(),
            stall_timeout: STALL_TIMEOUT_BASE,
            downloaded: HashSet::new(),
            peer_slots: HashMap::new(),
            // Match Bitcoin Core's MAX_BLOCKS_IN_TRANSIT_PER_PEER (16). The
            // previous limit (128) packed our getdata to peers with batches
            // 8x larger than what stock peers expect to process. On the
            // mainnet 2026-05-13 wedge run, peers consistently disconnected
            // us after ~60s with most of their assignment unfulfilled — the
            // smaller batch lets peers cycle through requests faster and
            // reduces wasted in-flight assignments when a peer drops.
            per_peer_limit: 16,
            max_ahead,
            connect_cursor: current_tip,
            height_to_hash,
            height_peer_cooldown: HashMap::new(),
        }
    }

    /// Record that `peer` failed to deliver `height`. Always sets the
    /// per-(peer, height) anti-affinity cooldown so the same peer cannot be
    /// re-issued the same height on the next assign pass. Bumps the peer's
    /// `consecutive_failures` counter at most once per `FAILURE_DEDUP_WINDOW`
    /// so a single stall pass that releases many heights from one peer
    /// counts as one failure event, not N.
    fn record_failure(&mut self, peer: PeerId, height: u32) {
        let now = Instant::now();
        let until = now + PEER_HEIGHT_COOLDOWN;
        self.height_peer_cooldown
            .entry(height)
            .or_default()
            .insert(peer, until);
        if let Some(slots) = self.peer_slots.get_mut(&peer) {
            let should_count = match slots.last_failure_at {
                Some(prev) => now.duration_since(prev) >= FAILURE_DEDUP_WINDOW,
                None => true,
            };
            if should_count {
                slots.consecutive_failures = slots.consecutive_failures.saturating_add(1);
                slots.last_failure_at = Some(now);
            }
        }
    }

    /// True if `peer` is currently barred from being assigned `height`.
    ///
    /// Anti-affinity only kicks in when there is more than one peer to
    /// choose from. With a single peer (regtest, early connect-out) there
    /// is no alternative — applying the cooldown would make `height`
    /// permanently unassignable until the cooldown expires, causing a
    /// connector wedge that's strictly worse than letting the same peer
    /// retry. Mainnet IBD has 50+ peers so this never trips there.
    fn is_peer_on_cooldown(&self, height: u32, peer: PeerId, now: Instant) -> bool {
        if self.peer_slots.len() <= 1 {
            return false;
        }
        self.height_peer_cooldown
            .get(&height)
            .and_then(|m| m.get(&peer))
            .is_some_and(|&until| now < until)
    }

    /// Peers whose `consecutive_failures` since their last successful delivery
    /// is at or above `threshold`. Intended for the manager to disconnect
    /// silent peers that hold slots but never deliver.
    ///
    /// Returns empty when the peer pool is at or below the threshold size —
    /// disconnecting a peer when we have no fallback would halt IBD outright.
    /// The mainnet wedge this defends against only manifests with many
    /// peers; regtest / single-peer setups can tolerate slow delivery.
    pub fn silent_peers(&self, threshold: u32) -> Vec<PeerId> {
        if self.peer_slots.len() <= 1 {
            return Vec::new();
        }
        self.peer_slots
            .iter()
            .filter(|(_, s)| s.consecutive_failures >= threshold)
            .map(|(&p, _)| p)
            .collect()
    }

    /// Update the max-ahead window at runtime (e.g. for percentage recomputation).
    pub fn set_max_ahead(&mut self, max_ahead: u32) {
        self.max_ahead = max_ahead;
    }

    /// Assign blocks to a peer for download. Returns hashes to request via GetData.
    /// Respects per-peer limits and the max-ahead window.
    /// Always prioritizes blocks near the connect cursor to avoid deadlocks.
    pub fn assign_blocks(&mut self, peer_id: PeerId) -> Vec<BlockHash> {
        self.assign_blocks_up_to(peer_id, u32::MAX)
    }

    /// [`Self::assign_blocks`], never past `max_height`: the highest block
    /// the peer can serve. Heights above it stay in the pool for others.
    pub fn assign_blocks_up_to(&mut self, peer_id: PeerId, max_height: u32) -> Vec<BlockHash> {
        let slots = self
            .peer_slots
            .entry(peer_id)
            .or_insert_with(|| PeerSlots {
                assigned: Vec::new(),
                blocks_received: 0,
                last_activity: Instant::now(),
                consecutive_failures: 0,
                last_failure_at: None,
            });

        let current_assigned = slots.assigned.len() as u32;
        if current_assigned >= self.per_peer_limit {
            return Vec::new();
        }

        let budget = (self.per_peer_limit - current_assigned) as usize;
        let mut hashes = Vec::with_capacity(budget);
        let mut assigned_heights = Vec::with_capacity(budget);
        let now = Instant::now();
        // Heights popped from the shared pending pool that this peer is on
        // cooldown for. We push these back to the tail so the pool isn't
        // drained from the perspective of other peers' next assign_blocks.
        let mut deferred: Vec<u32> = Vec::new();

        // Priority zone: always try to assign blocks near the connect cursor.
        // This prevents stalls where random blocks are downloaded far ahead but the
        // connect thread is blocked waiting for the next sequential block.
        // 256 blocks ensures the near-cursor region is well-covered across multiple peers.
        //
        // The zone is exempt from `max_ahead`. The window counts heights that
        // are downloaded but not yet connected, and those only drain as the
        // cursor advances; if the window is full while the height the
        // connector needs next is not in flight (released from a peer that
        // did not deliver it, or after a restart with a smaller window), a
        // gated zone would never hand that height out again and the download
        // would stop for good. Core's window is measured from the last common
        // block, so the blocks just above it are always inside
        // (`nWindowEnd`, `net_processing.cpp:1436-1441`). The overshoot is
        // bounded by the zone's 256 heights.
        let priority_end = (self.connect_cursor + 256).min(self.target_height).min(max_height);
        for h in (self.connect_cursor + 1)..=priority_end {
            if hashes.len() >= budget {
                break;
            }
            if self.downloaded.contains(&h) || self.in_flight.contains_key(&h) {
                continue;
            }
            if self.is_peer_on_cooldown(h, peer_id, now) {
                continue;
            }
            if let Some(&hash) = self.height_to_hash.get(&h) {
                self.in_flight.insert(h, peer_id);
                self.in_flight_at.entry(h).or_insert_with(Instant::now);
                self.requested_at.insert(h, Instant::now());
                assigned_heights.push(h);
                hashes.push(hash);
            }
        }

        // Then fill remaining budget from the shuffled pending pool
        let mut attempts = 0;
        while hashes.len() < budget && !self.pending.is_empty() {
            attempts += 1;
            if attempts > self.pending.len() + budget {
                break;
            }

            // Respect max_ahead window
            let total_ahead =
                self.downloaded.len() as u32 + self.in_flight.len() as u32 + hashes.len() as u32;
            if total_ahead >= self.max_ahead {
                break;
            }

            let height = match self.pending.pop_front() {
                Some(h) => h,
                None => break,
            };

            // Already connected: a released height can sit in the pool while
            // its block arrives late and is connected from disk.
            if height <= self.connect_cursor || self.downloaded.contains(&height) {
                continue;
            }
            if self.in_flight.contains_key(&height) {
                continue;
            }
            if height > max_height || self.is_peer_on_cooldown(height, peer_id, now) {
                // Hold this height aside; a different peer's next call can
                // claim it. Pushed back to the pool after this peer's pass.
                deferred.push(height);
                continue;
            }

            if let Some(&hash) = self.height_to_hash.get(&height) {
                self.in_flight.insert(height, peer_id);
                self.in_flight_at.entry(height).or_insert_with(Instant::now);
                self.requested_at.insert(height, Instant::now());
                assigned_heights.push(height);
                hashes.push(hash);
            }
        }

        // Return cooldown-deferred heights to the pending pool so other peers
        // can pick them up. Pushed to the back to give the shuffled queue a
        // chance to rotate other candidates forward first.
        for h in deferred {
            self.pending.push_back(h);
        }

        if !assigned_heights.is_empty() {
            let slots = self.peer_slots.get_mut(&peer_id).unwrap();
            // A peer that owed nothing starts its stall clock now, as Core
            // sets `m_downloading_since` when a peer's first block goes in
            // flight. Its last delivery may be long past, from before a wait
            // with nothing to give it, and judged from then it would be
            // disconnected for stalling right after being asked. A peer that
            // still owes blocks keeps its clock.
            if slots.assigned.is_empty() {
                slots.last_activity = now;
            }
            slots.assigned.extend(assigned_heights);
        }

        hashes
    }

    /// Record that a block has been received and stored.
    ///
    /// A height is satisfied only by the block this scheduler currently wants
    /// there. `hash` is what the peer actually delivered, and it is checked
    /// against the row rather than trusted: once `header_rows_changed` re-keys
    /// a height from `A` to `B`, a late delivery of `A` — still in flight when
    /// the headers arrived — would otherwise mark the height downloaded. `B`
    /// would then never be requested again (`release_stale_inflight` only
    /// scans what is still in flight) and the connector would park on it for
    /// good: the very wedge the best-header rows exist to prevent, reached
    /// through the delivery door instead of the index.
    ///
    /// Only a height that is in flight counts, and only one above the connect
    /// cursor is recorded as downloaded. `downloaded` drains only as the
    /// cursor passes it, so an already-connected height recorded there would
    /// stay in the window for the rest of the download. The peer's activity
    /// clock and failure count move only for a block that was asked of that
    /// peer, as Core clears `m_stalling_since` only when a requested block
    /// arrives (`RemoveBlockRequest`, `net_processing.cpp:1199-1230`); a block nobody
    /// asked it for says nothing about the heights it still owes.
    ///
    /// Returns `true` if the peer has capacity for more work.
    pub fn block_received(&mut self, peer_id: PeerId, height: u32, hash: BlockHash) -> bool {
        let holder = if self.height_to_hash.get(&height) == Some(&hash) {
            self.in_flight.get(&height).copied()
        } else {
            None
        };
        if let Some(holder) = holder {
            // Clear the height from whichever peer actually holds it. After a
            // re-key and reassignment that need not be the peer delivering it,
            // and leaving the holder's slot occupied would leak its capacity.
            self.in_flight.remove(&height);
            self.in_flight_at.remove(&height);
            self.requested_at.remove(&height);
            if let Some(slots) = self.peer_slots.get_mut(&holder) {
                slots.assigned.retain(|&h| h != height);
            }
            if height > self.connect_cursor {
                self.downloaded.insert(height);
            }
            // Drop any cooldown entries for this height.
            self.height_peer_cooldown.remove(&height);
        }

        if let Some(slots) = self.peer_slots.get_mut(&peer_id) {
            if holder == Some(peer_id) {
                // The peer delivered what it was asked for: it is alive.
                slots.blocks_received += 1;
                slots.last_activity = Instant::now();
                slots.consecutive_failures = 0;
                slots.last_failure_at = None;
            }
            return (slots.assigned.len() as u32) < self.per_peer_limit / 2;
        }
        false
    }

    /// Handle peer disconnection: return in-flight heights to the pending pool.
    ///
    /// Intentionally does NOT clear `in_flight_at`. Reason: peer-disconnect
    /// churn can reassign the same height through a series of flaky peers,
    /// each of whom never delivers. If we reset the timestamp on every hop,
    /// `release_stale_inflight`'s 60s window never elapses and the height
    /// stalls silently forever. Preserving the original timestamp across
    /// peer-hand-offs means `release_stale_inflight` will eventually fire
    /// and force a fresh retry on whichever peer picks it up next.
    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        if let Some(slots) = self.peer_slots.remove(&peer_id) {
            for height in slots.assigned {
                self.in_flight.remove(&height);
                // in_flight_at is kept — see doc comment above. The holder's
                // own request time goes with the holder.
                self.requested_at.remove(&height);
                // Push to front for immediate reassignment
                self.pending.push_front(height);
            }
        }
        // Drop the departing peer from every per-height cooldown table.
        // Without this, a peer that flapped (disconnect/reconnect) would keep
        // its cooldown across the gap on a freshly-allocated PeerId, which
        // is harmless, but the entries pile up across hours of churn.
        self.height_peer_cooldown.retain(|_, m| {
            m.remove(&peer_id);
            !m.is_empty()
        });
    }

    /// The peer that has gone longest holding blocks without delivering one,
    /// past the stall timeout. Its blocks go back to the pool, the timeout
    /// doubles, and the caller disconnects it, as Core disconnects a peer
    /// stalling block download (`net_processing.cpp`, "Peer is stalling block
    /// download"). Call until `None`: each call judges the rest against the
    /// doubled timeout, as Core's later peers are.
    ///
    /// The stall check used to only take the blocks back. The peer stayed
    /// connected, unmarked, and could be handed the same heights again on the
    /// same tick, while the blocks it was still sending arrived unrequested
    /// (#972).
    pub fn take_stalled_peer(&mut self) -> Option<PeerId> {
        let now = Instant::now();
        let peer_id = self
            .peer_slots
            .iter()
            .filter(|(_, slots)| {
                !slots.assigned.is_empty()
                    && now.duration_since(slots.last_activity) > self.stall_timeout
            })
            .min_by_key(|(_, slots)| slots.last_activity)
            .map(|(&id, _)| id)?;
        self.peer_disconnected(peer_id);
        self.stall_timeout = (self.stall_timeout * 2).min(STALL_TIMEOUT_MAX);
        Some(peer_id)
    }

    /// The current stall timeout; see [`Self::take_stalled_peer`].
    pub fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    /// Return individual in-flight heights that have exceeded the per-height
    /// timeout back to pending, regardless of per-peer activity.
    ///
    /// This fixes the case where a peer stays active (delivering other blocks)
    /// but silently ignores specific heights (e.g., height 945208). `take_stalled_peer`
    /// cannot catch this because `last_activity` is refreshed by other deliveries.
    ///
    /// `near_cursor_timeout` (typically much shorter than `timeout`) applies to
    /// heights in `connect_cursor+1..=connect_cursor+10` — the immediate-next
    /// blocks the connector is blocked on. Without this, a single silently-
    /// dropping peer can stall IBD for the full 60s `timeout` per round even
    /// though dozens of other peers could deliver the same block instantly.
    /// The mainnet 2026-05-13 wedge at height 783563 showed peer 52 holding
    /// it for 2+ minutes with no delivery before any other peer was tried.
    ///
    /// Returns the number of heights returned to pending.
    pub fn release_stale_inflight(
        &mut self,
        timeout: Duration,
        near_cursor_timeout: Duration,
    ) -> usize {
        let now = Instant::now();
        let near_cursor_end = self.connect_cursor + 10;
        // Two clocks. The holder's own request: the near-cursor timeout (and
        // the 60s one) judges the peer holding the height from when it was
        // asked. The height's first request: the 60s guard catches a height
        // no peer delivers however often it moves. Only the holder's own
        // clock running out is its failure; on the other alone it may have
        // been asked a moment ago, and the delay is the peers' before it
        // (#972).
        let stale: Vec<(u32, PeerId, bool)> = self
            .in_flight
            .iter()
            .filter_map(|(&h, &p)| {
                let holder_timeout = if h > self.connect_cursor && h <= near_cursor_end {
                    near_cursor_timeout
                } else {
                    timeout
                };
                let over = |at: Option<&Instant>, limit| at.is_some_and(|at| now.duration_since(*at) > limit);
                let holder_failed = over(self.requested_at.get(&h), holder_timeout);
                (holder_failed || over(self.in_flight_at.get(&h), timeout)).then_some((h, p, holder_failed))
            })
            .collect();

        let count = stale.len();
        for (h, peer_id, holder_failed) in stale {
            self.in_flight.remove(&h);
            self.in_flight_at.remove(&h);
            self.requested_at.remove(&h);
            // Push to front — the connect loop is likely waiting for this height
            self.pending.push_front(h);
            if let Some(slots) = self.peer_slots.get_mut(&peer_id) {
                slots.assigned.retain(|&x| x != h);
            }
            // Mark this peer as failed for this height so the very next
            // assign_peer_work pass doesn't hand the same height right back
            // to the same silent peer (mainnet 2026-05-13 wedge at 785197).
            if holder_failed {
                self.record_failure(peer_id, h);
            }
        }
        count
    }

    /// Notify the scheduler that the connect cursor has advanced.
    /// Heights below the cursor are no longer relevant.
    pub fn connect_cursor_advanced(&mut self, new_tip: u32) {
        // Core's `BlockConnected` brings a doubled stall timeout back down by
        // 15% per block.
        if new_tip > self.connect_cursor {
            self.stall_timeout = self.stall_timeout.mul_f64(0.85).max(STALL_TIMEOUT_BASE);
        }
        self.connect_cursor = new_tip;
        // Remove from downloaded set — they've been connected
        self.downloaded.retain(|&h| h > new_tip);
        // Cooldown entries for heights at or below the cursor are dead state.
        self.height_peer_cooldown.retain(|&h, _| h > new_tip);
    }

    /// Get download progress: (downloaded, in_flight, pending, target).
    pub fn progress(&self) -> (usize, usize, usize, u32) {
        (
            self.downloaded.len(),
            self.in_flight.len(),
            self.pending.len(),
            self.target_height,
        )
    }

    /// Check whether all blocks have been downloaded.
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty() && self.in_flight.is_empty()
    }

    /// Get the current phase.
    pub fn phase(&self) -> IbdPhase {
        self.phase
    }

    /// Set the phase.
    pub fn set_phase(&mut self, phase: IbdPhase) {
        self.phase = phase;
    }

    /// Get the target height.
    pub fn target_height(&self) -> u32 {
        self.target_height
    }

    /// Get the connect cursor (last connected height).
    pub fn connect_cursor(&self) -> u32 {
        self.connect_cursor
    }

    /// Check if a height has been downloaded.
    pub fn is_downloaded(&self, height: u32) -> bool {
        self.downloaded.contains(&height)
    }

    /// True if `height` is in the pending pool waiting to be assigned.
    /// Diagnostic accessor for the connector-stuck-waiting-for-block-data log.
    pub fn pending_contains(&self, height: u32) -> bool {
        self.pending.iter().any(|&h| h == height)
    }

    /// True if `height` is currently assigned to a peer (in-flight).
    pub fn in_flight_contains(&self, height: u32) -> bool {
        self.in_flight.contains_key(&height)
    }

    /// True if the scheduler has a height→hash mapping for `height`.
    /// Populated at scheduler construction from `chain_state.get_block_hash_by_height`.
    /// A missing mapping means the priority loop's `height_to_hash.get(&h)`
    /// returns None and the height is skipped — a way for a height to
    /// silently never get assigned.
    pub fn height_to_hash_contains(&self, height: u32) -> bool {
        self.height_to_hash.contains_key(&height)
    }

    /// PeerId currently holding the in-flight assignment for `height`,
    /// if any. Diagnostic accessor used by the "Connector stuck waiting
    /// for block data" log so we can correlate stuck heights with
    /// specific peers.
    pub fn inflight_peer(&self, height: u32) -> Option<PeerId> {
        self.in_flight.get(&height).copied()
    }

    /// Age of the in_flight_at timestamp for `height`, in seconds.
    /// Used to verify that release_stale_inflight is actually firing
    /// for stuck heights — if this stays small (< stale timeout) across
    /// repeat diagnostic samples, something is refreshing the timestamp
    /// inside the 60s window.
    pub fn inflight_age_secs(&self, height: u32) -> Option<u64> {
        self.in_flight_at
            .get(&height)
            .map(|at| at.elapsed().as_secs())
    }

    /// Snapshot of how many heights the peer currently holds in
    /// in_flight. Diagnostic for "is the peer overloaded vs. just
    /// silently dropping requests".
    pub fn peer_inflight_count(&self, peer_id: PeerId) -> usize {
        self.peer_slots
            .get(&peer_id)
            .map(|s| s.assigned.len())
            .unwrap_or(0)
    }

    /// Heights currently requested from `peer_id`, ascending — behind
    /// `getpeerinfo`'s `inflight`.
    ///
    /// Scope, so a caller does not over-read it: this is the *IBD
    /// scheduler's* assignment set. Bitcoin Core fills the field from
    /// `mapBlocksInFlight`, which also covers the block requests a
    /// steady-state node makes off an `inv`; satd does not track those per
    /// peer, so once IBD is done this reports empty. That is still strictly
    /// better than the hardcoded `[]` it replaces — during the sync, when the
    /// field is the one that tells an operator which peer is stalling a
    /// download, it is now real.
    pub fn peer_inflight_heights(&self, peer_id: PeerId) -> Vec<u32> {
        let mut heights = self
            .peer_slots
            .get(&peer_id)
            .map(|s| s.assigned.clone())
            .unwrap_or_default();
        heights.sort_unstable();
        heights
    }

    /// Release a height that is in-flight to `owner_peer`. Returns
    /// `true` if the release happened. Returns `false` if the height
    /// is not in-flight or is held by a different peer (we don't want
    /// peer X's notfound to release peer Y's pending request).
    ///
    /// Unlike `release_stale_inflight`, this does NOT preserve
    /// `in_flight_at`. The 60s stale timer is a fallback for silently-
    /// dropping peers; an explicit notfound is authoritative — the
    /// peer told us it doesn't have the block. We reset the timer so
    /// the NEXT peer to be assigned gets a fresh 60s window.
    pub fn release_height(&mut self, height: u32, owner_peer: PeerId) -> bool {
        let owned_by = match self.in_flight.get(&height) {
            Some(&p) => p,
            None => return false,
        };
        if owned_by != owner_peer {
            return false;
        }
        self.in_flight.remove(&height);
        self.in_flight_at.remove(&height);
        self.requested_at.remove(&height);
        self.pending.push_front(height);
        if let Some(slots) = self.peer_slots.get_mut(&owner_peer) {
            slots.assigned.retain(|&x| x != height);
        }
        // Anti-affinity: an explicit notfound from this peer is even stronger
        // evidence than a timeout that we should not re-issue this height to
        // them. Record the failure so assign_blocks skips this peer for the
        // cooldown window.
        self.record_failure(owner_peer, height);
        true
    }

    /// Get list of all tracked peer IDs.
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peer_slots.keys().copied().collect()
    }

    /// Register a peer for tracking (called when new peers connect during IBD).
    pub fn register_peer(&mut self, peer_id: PeerId) {
        self.peer_slots.entry(peer_id).or_insert_with(|| PeerSlots {
            assigned: Vec::new(),
            blocks_received: 0,
            last_activity: Instant::now(),
            consecutive_failures: 0,
            last_failure_at: None,
        });
    }

    /// Mark a height as already downloaded (for crash-resume).
    pub fn mark_downloaded(&mut self, height: u32) {
        self.downloaded.insert(height);
        self.in_flight.remove(&height);
        // Keep in_flight_at in sync with in_flight — otherwise it's a
        // slow memory leak in crash-resume paths, and a stale
        // in_flight_at entry with no matching in_flight makes
        // release_stale_inflight do extra work-for-nothing on every tick.
        self.in_flight_at.remove(&height);
        self.requested_at.remove(&height);
        // Cooldowns for a downloaded height serve no purpose; drop them.
        self.height_peer_cooldown.remove(&height);
    }

    /// Follow a change to the height-index rows above the tip: the
    /// best-header chain moved to another branch, so the hash this scheduler
    /// holds for each changed height names a block nobody will serve.
    ///
    /// A height with a new hash is re-keyed and, if it had been assigned or
    /// delivered under the old hash, put back at the front of the queue so
    /// the block actually on the chain is fetched next. A height with no row
    /// any more (`None`) is dropped from every set. `best_header_height`
    /// pulls the target down after a heavier-but-shorter switch; a later
    /// `extend_target` raises it again. Returns `(requeued, dropped)`.
    pub fn header_rows_changed(
        &mut self,
        changes: &[(u32, Option<BlockHash>)],
        best_header_height: u32,
    ) -> (usize, usize) {
        let mut requeued = 0;
        let mut dropped = 0;
        for &(height, new_hash) in changes {
            if height <= self.connect_cursor {
                continue;
            }
            match new_hash {
                Some(hash) => {
                    if self.height_to_hash.get(&height) == Some(&hash) {
                        continue;
                    }
                    self.height_to_hash.insert(height, hash);
                    let was_taken = self.downloaded.remove(&height)
                        | self.release_from_flight(height);
                    self.height_peer_cooldown.remove(&height);
                    if was_taken && height <= self.target_height {
                        self.pending.push_front(height);
                        requeued += 1;
                    }
                }
                None => {
                    if self.height_to_hash.remove(&height).is_some() {
                        dropped += 1;
                    }
                    self.downloaded.remove(&height);
                    self.release_from_flight(height);
                    self.height_peer_cooldown.remove(&height);
                    // A pending entry with no mapping is skipped and discarded
                    // by `assign_blocks`; nothing to do here.
                }
            }
        }
        if best_header_height < self.target_height {
            self.target_height = best_header_height.max(self.connect_cursor);
        }
        (requeued, dropped)
    }

    /// Take a height out of flight without judging the peer that held it —
    /// the block it was asked for stopped being the right block. Returns
    /// whether it was in flight.
    fn release_from_flight(&mut self, height: u32) -> bool {
        let Some(peer_id) = self.in_flight.remove(&height) else {
            return false;
        };
        self.in_flight_at.remove(&height);
        self.requested_at.remove(&height);
        if let Some(slots) = self.peer_slots.get_mut(&peer_id) {
            slots.assigned.retain(|&h| h != height);
        }
        true
    }

    /// Extend the target height as more headers arrive.
    /// Adds newly available heights to the pending pool (shuffled).
    pub fn extend_target(&mut self, new_target: u32, chain_state: &ChainState) {
        if new_target <= self.target_height {
            return;
        }
        let old_target = self.target_height;
        self.target_height = new_target;

        // Collect and shuffle new heights
        let mut new_heights: Vec<u32> = ((old_target + 1)..=new_target).collect();
        new_heights.shuffle(&mut rand::thread_rng());

        // Build height-to-hash mapping for new heights
        for &h in &new_heights {
            if let Some(hash) = chain_state.get_block_hash_by_height(h) {
                self.height_to_hash.insert(h, hash);
            }
        }

        // Add to pending pool
        self.pending.extend(new_heights);

        tracing::debug!(
            old_target,
            new_target,
            pending = self.pending.len(),
            "IBD scheduler target extended"
        );
    }

    /// Generate a compact block state bitmap for the TUI.
    /// Each entry represents one block's state: 0=not-requested, 1=pending,
    /// 2=in-flight, 3=downloaded/stored.
    ///
    /// When the range exceeds `MAX_BITMAP` entries, the bitmap is sampled:
    /// `MAX_BITMAP` evenly-spaced entries are taken across the full range.
    /// Returns `(bitmap, sampled)` where `sampled` is true when sampling was used.
    pub fn block_bitmap(&self) -> (Vec<u8>, bool) {
        const MAX_BITMAP: usize = 50_000;

        let start = self.connect_cursor + 1;
        if start > self.target_height {
            return (Vec::new(), false);
        }
        let total = (self.target_height - start + 1) as usize;

        // Build a HashSet from pending for O(1) lookups (VecDeque::contains is O(n))
        let pending_set: HashSet<u32> = self.pending.iter().copied().collect();

        if total <= MAX_BITMAP {
            // Full bitmap — every block in the range
            let mut bitmap = Vec::with_capacity(total);
            for h in start..=self.target_height {
                let state = if self.downloaded.contains(&h) {
                    3
                } else if self.in_flight.contains_key(&h) {
                    2
                } else if pending_set.contains(&h) {
                    1
                } else {
                    0
                };
                bitmap.push(state);
            }
            (bitmap, false)
        } else {
            // Sampled bitmap — take MAX_BITMAP evenly-spaced samples
            let step = total as f64 / MAX_BITMAP as f64;
            let mut bitmap = Vec::with_capacity(MAX_BITMAP);
            for i in 0..MAX_BITMAP {
                let h = start + (i as f64 * step) as u32;
                let state = if self.downloaded.contains(&h) {
                    3
                } else if self.in_flight.contains_key(&h) {
                    2
                } else if pending_set.contains(&h) {
                    1
                } else {
                    0
                };
                bitmap.push(state);
            }
            (bitmap, true)
        }
    }

    /// Per-peer download statistics for TUI.
    pub fn peer_stats(&self) -> Vec<(PeerId, u64, usize)> {
        self.peer_slots
            .iter()
            .map(|(&id, s)| (id, s.blocks_received, s.assigned.len()))
            .collect()
    }
}

#[cfg(test)]
#[path = "ibd_ibdwindow_tests.rs"]
mod ibdwindow_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::chain::state::AssumeValid;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    fn make_chain_state_with_headers(num_headers: u32) -> (ChainState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-ibd-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
        .unwrap();

        // Build a chain of headers using test blocks
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent_hash = genesis.block_hash();
        for i in 1..=num_headers {
            let block = crate::chain::state::tests::build_test_block(
                parent_hash,
                i,
                1_300_000_000 + i,
            );
            // Accept the full block so we get both header and height_hash entries
            parent_hash = cs.accept_block(&block).unwrap().hash();
        }

        (cs, dir)
    }

    #[test]
    fn test_assign_blocks_no_overlap() {
        let (cs, dir) = make_chain_state_with_headers(100);
        // Reset tip to 0 to simulate IBD (we have headers but no connected blocks)
        // Actually, accept_block connected them. Instead, create scheduler from 0 to 100
        // using the chain_state that has height_to_hash for 1..=100.
        let mut sched = IbdScheduler::new(100, 0, &cs, 50_000);

        let h1 = sched.assign_blocks(1);
        let h2 = sched.assign_blocks(2);
        let h3 = sched.assign_blocks(3);

        // All hashes should be unique (no overlap)
        let mut all: Vec<BlockHash> = Vec::new();
        all.extend(&h1);
        all.extend(&h2);
        all.extend(&h3);
        let unique: HashSet<BlockHash> = all.iter().copied().collect();
        assert_eq!(all.len(), unique.len(), "No overlapping block assignments");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer is never asked for a block above the highest it can serve,
    /// from the priority zone or the pool, and what it cannot take stays
    /// available to the next peer.
    #[test]
    fn assign_blocks_up_to_stops_at_the_peers_height() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let mut sched = IbdScheduler::new(100, 0, &cs, 50_000);

        let short = sched.assign_blocks_up_to(1, 5);
        assert_eq!(short.len(), 5, "heights 1..=5 and nothing above");
        for hash in &short {
            let h = cs.get_block_index(hash).unwrap().height;
            assert!(h <= 5, "height {h} is above the peer's 5");
        }
        assert!(sched.assign_blocks_up_to(1, 5).is_empty());

        let full = sched.assign_blocks(2);
        assert!(!full.is_empty());
        assert!(full.iter().all(|hash| cs.get_block_index(hash).unwrap().height > 5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_randomized_distribution() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let sched = IbdScheduler::new(100, 0, &cs, 50_000);

        // Check that pending is not in sequential order
        let heights: Vec<u32> = sched.pending.iter().copied().collect();
        let mut sorted = heights.clone();
        sorted.sort();
        // With 100 elements shuffled, it's astronomically unlikely to be sorted
        assert_ne!(heights, sorted, "Blocks should be shuffled, not sequential");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The best-header chain moved above the tip. A height the scheduler had
    /// in flight, or had already delivered, under the old hash goes back to
    /// the front of the queue under the new one; a height whose row vanished
    /// is dropped; heights at or below the cursor are ignored; and the next
    /// assignment asks for the new hashes.
    #[test]
    fn header_rows_changed_requeues_reassigned_heights_under_the_new_hash() {
        use bitcoin::hashes::Hash as _;
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
        // Peer 1 takes the priority zone, heights 1..=16; height 2 arrives.
        assert_eq!(sched.assign_blocks(1).len(), 16);
        sched.block_received(1, 2, cs.get_block_hash_by_height(2).unwrap());
        assert!(sched.is_downloaded(2));
        let old1 = cs.get_block_hash_by_height(1).unwrap();

        let new1 = BlockHash::from_byte_array([0x11; 32]);
        let new2 = BlockHash::from_byte_array([0x22; 32]);
        let changes = [(1, Some(new1)), (2, Some(new2)), (20, None), (0, Some(old1))];
        assert_eq!(sched.header_rows_changed(&changes, 19), (2, 1));

        assert!(!sched.in_flight_contains(1), "no longer owed under the old hash");
        assert!(!sched.is_downloaded(2), "the delivered fork block is not the block");
        assert!(sched.pending_contains(1) && sched.pending_contains(2));
        assert!(!sched.peer_inflight_heights(1).contains(&1));
        assert!(!sched.height_to_hash_contains(20));
        assert_eq!(sched.target_height(), 19, "pulled down to the best header");

        let next = sched.assign_blocks(2);
        assert!(next.contains(&new1) && next.contains(&new2), "asks for the chain's blocks");
        assert!(!next.contains(&old1));

        // Re-keying an unchanged row is a no-op.
        assert_eq!(sched.header_rows_changed(&[(3, cs.get_block_hash_by_height(3))], 19), (0, 0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `getpeerinfo.inflight` was a hardcoded `[]`, which reads as "this peer
    /// owes us nothing" — the opposite of the answer when the question is
    /// which peer is stalling the download. The set is per peer, ascending,
    /// and shrinks as blocks arrive.
    #[test]
    fn peer_inflight_heights_reports_what_that_peer_owes() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let mut sched = IbdScheduler::new(100, 0, &cs, 50_000);

        assert!(
            sched.peer_inflight_heights(1).is_empty(),
            "a peer with no assignment owes nothing"
        );

        sched.assign_blocks(1);
        sched.assign_blocks(2);
        let one = sched.peer_inflight_heights(1);
        let two = sched.peer_inflight_heights(2);
        assert!(!one.is_empty(), "peer 1 was assigned work");
        assert!(!two.is_empty(), "peer 2 was assigned work");
        assert_eq!(one.len(), sched.peer_inflight_count(1));

        // Ascending, and belonging to exactly one peer.
        let mut sorted = one.clone();
        sorted.sort_unstable();
        assert_eq!(one, sorted, "heights come out in order");
        for h in &one {
            assert!(!two.contains(h), "height {h} is assigned to one peer only");
        }

        // Delivering a block removes just that height.
        let delivered = one[0];
        sched.block_received(1, delivered, cs.get_block_hash_by_height(delivered).unwrap());
        let after = sched.peer_inflight_heights(1);
        assert!(
            !after.contains(&delivered),
            "a delivered height is no longer outstanding: {after:?}"
        );
        assert_eq!(after.len(), one.len() - 1);
        // The other peer is untouched.
        assert_eq!(sched.peer_inflight_heights(2), two);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_disconnect_preserves_in_flight_at_timestamp() {
        // Regression: peer_disconnected used to clear in_flight_at alongside
        // in_flight. Under peer-disconnect churn near tip, a height would
        // bounce between flaky peers and the timestamp would reset on every
        // hop, so release_stale_inflight(60s) never fired and the block
        // stalled forever. See PR #74 for the observed mainnet incident.
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        let assigned = sched.assign_blocks(1);
        assert!(!assigned.is_empty());
        // Snapshot timestamps so we can verify they're preserved.
        let original_stamps: HashMap<u32, Instant> = sched.in_flight_at.clone();
        assert!(!original_stamps.is_empty());

        sched.peer_disconnected(1);
        // in_flight cleared, pending repopulated.
        assert_eq!(sched.in_flight.len(), 0);
        assert!(!sched.pending.is_empty());
        // Critical: timestamps survived the disconnect.
        assert_eq!(
            sched.in_flight_at, original_stamps,
            "peer_disconnected must preserve in_flight_at timestamps so \
             release_stale_inflight can fire across reassignment churn"
        );

        // Reassign to peer 2. Timestamps must remain the original ones
        // (or_insert_with preserves existing entries).
        sched.register_peer(2);
        let _ = sched.assign_blocks(2);
        for (h, ts) in &original_stamps {
            assert_eq!(
                sched.in_flight_at.get(h),
                Some(ts),
                "reassignment must not refresh timestamp for height {h}",
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn release_stale_inflight_fires_after_peer_churn() {
        // End-to-end: a height that bounces peer→peer via disconnect/
        // reassign cycles still gets released once the original timestamp
        // exceeds the timeout.
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        let _ = sched.assign_blocks(1);
        let heights_in_flight: Vec<u32> = sched.in_flight.keys().copied().collect();
        assert!(!heights_in_flight.is_empty());

        // Backdate every in_flight_at to 2 minutes ago.
        let old = Instant::now() - Duration::from_secs(120);
        for h in &heights_in_flight {
            sched.in_flight_at.insert(*h, old);
        }

        // Simulate peer churn: disconnect peer 1, reassign to peer 2.
        sched.peer_disconnected(1);
        sched.register_peer(2);
        let _ = sched.assign_blocks(2);

        // Even though the current assignment is fresh, the underlying
        // in_flight_at is still 2 minutes old → release must fire.
        let released = sched.release_stale_inflight(
            Duration::from_secs(60),
            Duration::from_secs(15),
        );
        assert!(
            released >= heights_in_flight.len(),
            "release_stale_inflight should fire for stale heights despite \
             peer churn; released={released} expected>={}",
            heights_in_flight.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn release_does_not_re_assign_to_same_peer() {
        // 2026-05-13 mainnet wedge: peer 1 silently held height 785197 and
        // the 15s near-cursor timeout released it back to pending. On the
        // very next assign_peer_work pass, peer 1's priority-zone scan
        // re-claimed the same height, looping forever. The cooldown must
        // block self-reassignment for at least the cooldown window.
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        // Cooldown logic only activates when >1 peer exists (no fallback
        // with a single peer). Register a second peer up front.
        sched.register_peer(2);

        // Peer 1 grabs blocks via the priority zone.
        let assigned_first = sched.assign_blocks(1);
        assert!(!assigned_first.is_empty());
        // Pick the first height peer 1 took and release it back.
        let stuck_height = *sched
            .peer_slots
            .get(&1)
            .and_then(|s| s.assigned.first())
            .expect("peer 1 has at least one assigned height");
        assert!(sched.release_height(stuck_height, 1));

        // Peer 1 asks for more work — without anti-affinity it would pop
        // stuck_height right back off the priority zone.
        let assigned_second = sched.assign_blocks(1);
        let took_back: bool = sched
            .peer_slots
            .get(&1)
            .map(|s| s.assigned.contains(&stuck_height))
            .unwrap_or(false);
        assert!(
            !took_back,
            "peer 1 must not be re-issued a height it just released; \
             second-pass assigned={assigned_second:?}"
        );
        // A different peer can still claim it freely.
        let _ = sched.assign_blocks(2);
        let peer2_has_it = sched
            .peer_slots
            .get(&2)
            .map(|s| s.assigned.contains(&stuck_height))
            .unwrap_or(false);
        assert!(
            peer2_has_it,
            "a fresh peer should be free to pick up the released height"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn silent_peer_flagged_after_repeated_releases() {
        // After SILENT_PEER_FAILURE_THRESHOLD distinct release events,
        // dedupe-spaced, the peer must show up in silent_peers() so the
        // manager can drop it. The dedupe window prevents a single burst
        // of N height-releases from counting as N events.
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);

        // silent_peers only fires with >1 peer so disconnecting one still
        // leaves a usable peer to take over. Register a second peer.
        sched.register_peer(2);

        let _ = sched.assign_blocks(1);
        let heights: Vec<u32> = sched
            .peer_slots
            .get(&1)
            .map(|s| s.assigned.iter().take(3).copied().collect())
            .unwrap_or_default();
        assert!(heights.len() >= 3, "need at least 3 assigned heights");
        for h in heights {
            assert!(sched.release_height(h, 1));
            // Backdate last_failure_at to escape the dedupe window so the
            // next release counts as a distinct event.
            if let Some(slots) = sched.peer_slots.get_mut(&1) {
                slots.last_failure_at =
                    Some(Instant::now() - (FAILURE_DEDUP_WINDOW + Duration::from_secs(1)));
            }
        }

        let silent = sched.silent_peers(SILENT_PEER_FAILURE_THRESHOLD);
        assert!(silent.contains(&1), "peer 1 should be flagged silent");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn release_burst_counts_as_single_failure_event() {
        // Regression for the 2026-05-13 over-trigger: a peer holding many
        // near-cursor heights that all time out in one release pass must
        // count as ONE failure event, not N. Otherwise the threshold is
        // crossed instantly on the first stall, before the peer has had
        // any chance to recover.
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);

        // silent_peers gating requires >1 peer; register a second.
        sched.register_peer(2);

        let _ = sched.assign_blocks(1);
        let heights: Vec<u32> = sched
            .peer_slots
            .get(&1)
            .map(|s| s.assigned.clone())
            .unwrap_or_default();
        assert!(heights.len() >= 3, "need at least 3 assigned heights");

        // Release all heights in a tight burst — within the dedupe window.
        for h in &heights {
            assert!(sched.release_height(*h, 1));
        }

        let failures = sched
            .peer_slots
            .get(&1)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0);
        assert_eq!(
            failures, 1,
            "a burst of {} releases inside the dedupe window must count as one event",
            heights.len()
        );
        let silent = sched.silent_peers(SILENT_PEER_FAILURE_THRESHOLD);
        assert!(
            !silent.contains(&1),
            "single stall pass must not cross the silent-peer threshold"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_received_resets_failure_counter() {
        // A successful delivery proves the peer is alive and absolves it of
        // its accumulated misses.
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);

        // Cooldown/silent-peer logic gated on >1 peer; register a second.
        sched.register_peer(2);

        let _ = sched.assign_blocks(1);
        let heights: Vec<u32> = sched
            .peer_slots
            .get(&1)
            .map(|s| s.assigned.iter().take(2).copied().collect())
            .unwrap_or_default();
        // Release two heights with the dedupe window backdated between so
        // both are counted as distinct failure events.
        for h in &heights {
            assert!(sched.release_height(*h, 1));
            if let Some(slots) = sched.peer_slots.get_mut(&1) {
                slots.last_failure_at =
                    Some(Instant::now() - (FAILURE_DEDUP_WINDOW + Duration::from_secs(1)));
            }
        }
        assert!(sched.peer_slots[&1].consecutive_failures >= 2);

        // Re-assign and deliver one.
        let _ = sched.assign_blocks(1);
        let delivered = sched
            .peer_slots
            .get(&1)
            .and_then(|s| s.assigned.first().copied());
        if let Some(h) = delivered {
            sched.block_received(1, h, cs.get_block_hash_by_height(h).unwrap());
            assert_eq!(sched.peer_slots[&1].consecutive_failures, 0);
            assert!(sched.peer_slots[&1].last_failure_at.is_none());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_peer_bypasses_cooldown_and_silent_disconnect() {
        // CI regression 2026-05-13: with one peer, releasing a height
        // applies a 60s cooldown to that peer, but there's no alternative
        // peer to take the height, so it becomes unassignable for 60s.
        // Drives test_parallel_ibd into a 3-minute timeout. Anti-affinity
        // and silent-peer disconnect must both no-op with a single peer.
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        let _ = sched.assign_blocks(1);
        let h = *sched
            .peer_slots
            .get(&1)
            .and_then(|s| s.assigned.first())
            .expect("peer 1 has assigned height");
        assert!(sched.release_height(h, 1));

        // Same peer must be free to re-claim the height — no alternative
        // exists with a single peer.
        let _ = sched.assign_blocks(1);
        let reclaimed = sched
            .peer_slots
            .get(&1)
            .map(|s| s.assigned.contains(&h))
            .unwrap_or(false);
        assert!(
            reclaimed,
            "single-peer scheduler must allow the only peer to re-claim a \
             released height — cooldown has nowhere else to go"
        );

        // Even with many releases on a single peer, silent_peers must be
        // empty — disconnecting the only peer would halt IBD outright.
        for _ in 0..10 {
            if let Some(slot_h) = sched
                .peer_slots
                .get(&1)
                .and_then(|s| s.assigned.first().copied())
            {
                assert!(sched.release_height(slot_h, 1));
            }
            let _ = sched.assign_blocks(1);
            if let Some(slots) = sched.peer_slots.get_mut(&1) {
                slots.last_failure_at =
                    Some(Instant::now() - (FAILURE_DEDUP_WINDOW + Duration::from_secs(1)));
            }
        }
        let silent = sched.silent_peers(SILENT_PEER_FAILURE_THRESHOLD);
        assert!(
            silent.is_empty(),
            "single-peer scheduler must never flag its only peer as silent"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_downloaded_clears_both_in_flight_maps() {
        let (cs, dir) = make_chain_state_with_headers(5);
        let mut sched = IbdScheduler::new(5, 0, &cs, 50_000);

        let _ = sched.assign_blocks(1);
        let height = *sched.in_flight.keys().next().expect("one in-flight");
        sched.mark_downloaded(height);
        assert!(!sched.in_flight.contains_key(&height));
        assert!(
            !sched.in_flight_at.contains_key(&height),
            "mark_downloaded must keep in_flight and in_flight_at in sync",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peer_disconnect_reassigns() {
        let (cs, dir) = make_chain_state_with_headers(50);
        let mut sched = IbdScheduler::new(50, 0, &cs, 50_000);

        let assigned = sched.assign_blocks(1);
        let assigned_count = assigned.len();
        assert!(assigned_count > 0);

        // Disconnect peer 1
        sched.peer_disconnected(1);

        // Their blocks should be back in the pool. Priority-zone claims do
        // NOT pop from pending, so a height claimed via the priority zone
        // and then released on disconnect appears twice in pending (the
        // duplicate is silently skipped by the contains_key check on the
        // next pop). Assert via uniqueness of heights covered.
        assert_eq!(sched.in_flight.len(), 0);
        let unique_heights: HashSet<u32> = sched.pending.iter().copied().collect();
        assert_eq!(
            unique_heights.len(),
            50,
            "all 50 distinct heights must be reachable from pending after disconnect"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stall_detection() {
        let (cs, dir) = make_chain_state_with_headers(50);
        let mut sched = IbdScheduler::new(50, 0, &cs, 50_000);

        let _ = sched.assign_blocks(1);

        // Artificially set last_activity to the past
        if let Some(slots) = sched.peer_slots.get_mut(&1) {
            slots.last_activity = Instant::now() - Duration::from_secs(120);
        }

        assert_eq!(sched.take_stalled_peer(), Some(1));
        assert_eq!(sched.take_stalled_peer(), None);

        // Peer should be removed and blocks returned
        assert!(!sched.peer_slots.contains_key(&1));
        assert_eq!(sched.in_flight.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #972: each peer dropped for stalling doubles the timeout the next is
    /// judged against, as Core's `m_block_stalling_timeout` does, so a node
    /// whose own link is slow drops one peer rather than all of them; and
    /// connected blocks bring it back down to the floor.
    #[test]
    fn a_stall_disconnect_doubles_the_timeout_for_the_next_peer() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let mut sched = IbdScheduler::new(100, 0, &cs, 50_000);
        for peer in 1..=3 {
            sched.assign_blocks(peer);
        }
        let idle = |sched: &mut IbdScheduler, peer: PeerId, secs: u64| {
            sched.peer_slots.get_mut(&peer).unwrap().last_activity =
                Instant::now() - Duration::from_secs(secs);
        };
        idle(&mut sched, 1, 20);
        idle(&mut sched, 2, 40);
        idle(&mut sched, 3, 70);

        // The longest-idle goes first; the timeout is then 30s, which peer 2
        // (40s) is still past, and then 60s, which peer 1 (20s) is not.
        assert_eq!(sched.take_stalled_peer(), Some(3));
        assert_eq!(sched.stall_timeout(), Duration::from_secs(30));
        assert_eq!(sched.take_stalled_peer(), Some(2));
        assert_eq!(sched.stall_timeout(), Duration::from_secs(60));
        assert_eq!(sched.take_stalled_peer(), None, "peer 1 is inside the doubled timeout");
        assert!(sched.peer_slots.contains_key(&1));

        // Capped at Core's 64s.
        idle(&mut sched, 1, 200);
        assert_eq!(sched.take_stalled_peer(), Some(1));
        assert_eq!(sched.stall_timeout(), STALL_TIMEOUT_MAX);

        // Each connected block takes 15% off, down to the floor.
        sched.connect_cursor_advanced(1);
        assert_eq!(sched.stall_timeout(), STALL_TIMEOUT_MAX.mul_f64(0.85));
        for tip in 2..20 {
            sched.connect_cursor_advanced(tip);
        }
        assert_eq!(sched.stall_timeout(), STALL_TIMEOUT_BASE);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #972 review: a peer that sat idle with nothing to download, for
    /// longer than the stall timeout, is not stalling when it is then given
    /// blocks. Its clock starts at the assignment. A peer that already owes
    /// blocks keeps its clock when given more.
    #[test]
    fn a_peer_given_work_after_an_idle_wait_is_not_stalling() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let mut sched = IbdScheduler::new(100, 0, &cs, 50_000);
        let long_ago = Instant::now() - Duration::from_secs(200);
        sched.register_peer(1);
        sched.peer_slots.get_mut(&1).unwrap().last_activity = long_ago;
        sched.assign_blocks(1);
        assert!(!sched.peer_slots[&1].assigned.is_empty());
        assert_eq!(sched.take_stalled_peer(), None, "peer 1 was asked just now");

        // Owing blocks, more work does not reset the clock.
        sched.register_peer(2);
        sched.assign_blocks_up_to(2, 30);
        assert!(!sched.peer_slots[&2].assigned.is_empty());
        let owed = sched.peer_slots[&2].assigned.len();
        sched.peer_slots.get_mut(&2).unwrap().last_activity = long_ago;
        sched.assign_blocks(2);
        assert!(sched.peer_slots[&2].assigned.len() > owed, "peer 2 was given more");
        assert_eq!(sched.peer_slots[&2].last_activity, long_ago);
        assert_eq!(sched.take_stalled_peer(), Some(2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #972: a near-cursor height handed to a new peer is judged from when
    /// that peer was asked. Inheriting the first request's timestamp, it was
    /// released from a peer asked a moment ago, and the peer was charged a
    /// failure for the delay of the one before it.
    #[test]
    fn a_handed_off_height_gives_its_new_holder_a_fresh_clock() {
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);
        sched.assign_blocks(1);
        let heights: Vec<u32> = sched.peer_inflight_heights(1);
        assert!(!heights.is_empty());
        // Asked of peer 1 twenty seconds ago: past the 15s near-cursor
        // timeout, inside the 60s one.
        let asked = Instant::now() - Duration::from_secs(20);
        for h in &heights {
            sched.in_flight_at.insert(*h, asked);
            sched.requested_at.insert(*h, asked);
        }

        sched.peer_disconnected(1);
        sched.register_peer(2);
        sched.assign_blocks(2);
        assert_eq!(sched.peer_inflight_heights(2).len(), heights.len());

        let released = sched.release_stale_inflight(Duration::from_secs(60), Duration::from_secs(15));
        assert_eq!(released, 0, "peer 2 was asked just now; nothing of its is stale");
        assert_eq!(sched.peer_slots[&2].consecutive_failures, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #972: the 60s guard still releases a height no peer has delivered in
    /// a minute, however recently it moved, but it does not charge the peer
    /// that has held it only a moment.
    #[test]
    fn the_first_request_guard_releases_without_charging_a_fresh_holder() {
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);
        sched.assign_blocks(1);
        let heights: Vec<u32> = sched.peer_inflight_heights(1);
        let first = Instant::now() - Duration::from_secs(120);
        for h in &heights {
            sched.in_flight_at.insert(*h, first);
        }

        let released = sched.release_stale_inflight(Duration::from_secs(60), Duration::from_secs(15));
        assert_eq!(released, heights.len());
        assert_eq!(sched.peer_slots[&1].consecutive_failures, 0, "peer 1 was asked a moment ago");
        let now = Instant::now();
        assert!(
            heights.iter().all(|&h| !sched.is_peer_on_cooldown(h, 1, now)),
            "peer 1 must not be barred from heights it was not given time to deliver"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_max_ahead_window() {
        let (cs, dir) = make_chain_state_with_headers(100);
        let mut sched = IbdScheduler::new(100, 0, &cs, 20); // Small max_ahead for testing

        // Assign blocks — should stop at max_ahead
        let h1 = sched.assign_blocks(1);
        // With per_peer_limit=128 but max_ahead=20, should get at most 20
        assert!(
            h1.len() <= 20,
            "Should respect max_ahead window, got {}",
            h1.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resume_partial_download() {
        let (cs, dir) = make_chain_state_with_headers(50);
        let mut sched = IbdScheduler::new(50, 0, &cs, 50_000);

        // Mark some heights as already downloaded
        for h in 1..=20 {
            sched.mark_downloaded(h);
        }

        // Assign blocks — should skip already-downloaded heights
        let hashes = sched.assign_blocks(1);
        // Heights 21-50 should be available (30 heights)
        // Some may be assigned, check none are from 1-20
        assert!(!hashes.is_empty());

        // Verify downloaded set
        for h in 1..=20 {
            assert!(sched.is_downloaded(h));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The delivery-door version of the wedge this scheduler's best-header
    /// rows exist to prevent. A height goes out under hash `A`; the headers
    /// move and `header_rows_changed` re-keys it to `B` and requeues it; the
    /// in-flight response carrying `A` then lands. It must not satisfy the
    /// height — `B` was never fetched, nothing else would ever ask for it,
    /// and the connector would wait on it forever.
    #[test]
    fn a_late_block_under_the_old_hash_does_not_satisfy_a_re_keyed_height() {
        use bitcoin::hashes::Hash as _;
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
        assert_eq!(sched.assign_blocks(1).len(), 16);
        let stale = cs.get_block_hash_by_height(3).unwrap();
        assert!(sched.in_flight_contains(3), "height 3 went out under the old hash");

        // The best-header chain moves: height 3 now names a different block.
        let fresh = BlockHash::from_byte_array([0x33; 32]);
        sched.header_rows_changed(&[(3, Some(fresh))], 20);
        assert!(sched.pending_contains(3), "requeued under the new hash");

        // Peer 1's in-flight response for the OLD hash arrives late.
        sched.block_received(1, 3, stale);

        assert!(!sched.is_downloaded(3), "the old block does not satisfy the height");
        assert!(sched.pending_contains(3), "height 3 is still owed");
        // And it is handed out again, under the new hash.
        let hashes = sched.assign_blocks(2);
        assert!(hashes.contains(&fresh), "re-requested as {fresh}: {hashes:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a re-key the height can be back in flight to a DIFFERENT peer by
    /// the time the right block arrives. Satisfying it must free the slot of
    /// the peer that actually holds it, not just the one that delivered.
    #[test]
    fn delivering_a_re_assigned_height_frees_the_holding_peers_slot() {
        let (cs, dir) = make_chain_state_with_headers(20);
        let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
        let real3 = cs.get_block_hash_by_height(3).unwrap();
        assert_eq!(sched.assign_blocks(1).len(), 16);

        // Re-key height 3 to the same hash it already has? No — take it out of
        // flight the way a row change does, then let peer 2 pick it up.
        assert!(sched.release_from_flight(3));
        sched.pending.push_front(3);
        let _ = sched.assign_blocks(2);
        assert!(
            sched.peer_inflight_heights(2).contains(&3),
            "peer 2 now holds height 3"
        );

        // Peer 1's original request lands — the right block, wrong peer.
        sched.block_received(1, 3, real3);

        assert!(sched.is_downloaded(3), "the right block satisfies the height");
        assert!(
            !sched.peer_inflight_heights(2).contains(&3),
            "peer 2's slot is freed, not leaked: {:?}",
            sched.peer_inflight_heights(2)
        );
        assert!(!sched.in_flight_contains(3));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_completion() {
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        // Assign all blocks to peer 1
        let _ = sched.assign_blocks(1);

        // Mark all as received
        for h in 1..=10 {
            sched.block_received(1, h, cs.get_block_hash_by_height(h).unwrap());
        }

        assert!(sched.is_complete());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
