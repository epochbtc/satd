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
}

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
            downloaded: HashSet::new(),
            peer_slots: HashMap::new(),
            per_peer_limit: 128,
            max_ahead,
            connect_cursor: current_tip,
            height_to_hash,
        }
    }

    /// Update the max-ahead window at runtime (e.g. for percentage recomputation).
    pub fn set_max_ahead(&mut self, max_ahead: u32) {
        self.max_ahead = max_ahead;
    }

    /// Assign blocks to a peer for download. Returns hashes to request via GetData.
    /// Respects per-peer limits and the max-ahead window.
    /// Always prioritizes blocks near the connect cursor to avoid deadlocks.
    pub fn assign_blocks(&mut self, peer_id: PeerId) -> Vec<BlockHash> {
        let slots = self
            .peer_slots
            .entry(peer_id)
            .or_insert_with(|| PeerSlots {
                assigned: Vec::new(),
                blocks_received: 0,
                last_activity: Instant::now(),
            });

        let current_assigned = slots.assigned.len() as u32;
        if current_assigned >= self.per_peer_limit {
            return Vec::new();
        }

        let budget = (self.per_peer_limit - current_assigned) as usize;
        let mut hashes = Vec::with_capacity(budget);
        let mut assigned_heights = Vec::with_capacity(budget);

        // Priority zone: always try to assign blocks near the connect cursor.
        // This prevents stalls where random blocks are downloaded far ahead but the
        // connect thread is blocked waiting for the next sequential block.
        // 256 blocks ensures the near-cursor region is well-covered across multiple peers.
        let priority_end = (self.connect_cursor + 256).min(self.target_height);
        for h in (self.connect_cursor + 1)..=priority_end {
            if hashes.len() >= budget {
                break;
            }
            let total_ahead =
                self.downloaded.len() as u32 + self.in_flight.len() as u32 + hashes.len() as u32;
            if total_ahead >= self.max_ahead {
                break;
            }
            if self.downloaded.contains(&h) || self.in_flight.contains_key(&h) {
                continue;
            }
            if let Some(&hash) = self.height_to_hash.get(&h) {
                self.in_flight.insert(h, peer_id);
                self.in_flight_at.entry(h).or_insert_with(Instant::now);
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

            if self.downloaded.contains(&height) {
                continue;
            }
            if self.in_flight.contains_key(&height) {
                continue;
            }

            if let Some(&hash) = self.height_to_hash.get(&height) {
                self.in_flight.insert(height, peer_id);
                self.in_flight_at.entry(height).or_insert_with(Instant::now);
                assigned_heights.push(height);
                hashes.push(hash);
            }
        }

        if !assigned_heights.is_empty() {
            let slots = self.peer_slots.get_mut(&peer_id).unwrap();
            slots.assigned.extend(assigned_heights);
        }

        hashes
    }

    /// Record that a block has been received and stored.
    /// Returns `true` if the peer has capacity for more work.
    pub fn block_received(&mut self, peer_id: PeerId, height: u32) -> bool {
        self.in_flight.remove(&height);
        self.in_flight_at.remove(&height);
        self.downloaded.insert(height);

        if let Some(slots) = self.peer_slots.get_mut(&peer_id) {
            slots.assigned.retain(|&h| h != height);
            slots.blocks_received += 1;
            slots.last_activity = Instant::now();
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
                // in_flight_at is kept — see doc comment above.
                // Push to front for immediate reassignment
                self.pending.push_front(height);
            }
        }
    }

    /// Detect stalled peers (no activity within timeout).
    /// Returns list of stalled peer IDs. Their blocks are returned to the pool.
    pub fn detect_stalls(&mut self, timeout: Duration) -> Vec<PeerId> {
        let now = Instant::now();
        let stalled: Vec<PeerId> = self
            .peer_slots
            .iter()
            .filter(|(_, slots)| {
                !slots.assigned.is_empty()
                    && now.duration_since(slots.last_activity) > timeout
            })
            .map(|(&id, _)| id)
            .collect();

        for &peer_id in &stalled {
            self.peer_disconnected(peer_id);
        }

        stalled
    }

    /// Return individual in-flight heights that have exceeded the per-height
    /// timeout back to pending, regardless of per-peer activity.
    ///
    /// This fixes the case where a peer stays active (delivering other blocks)
    /// but silently ignores specific heights (e.g., height 945208). `detect_stalls`
    /// cannot catch this because `last_activity` is refreshed by other deliveries.
    ///
    /// Returns the number of heights returned to pending.
    pub fn release_stale_inflight(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let stale: Vec<(u32, PeerId)> = self
            .in_flight_at
            .iter()
            .filter(|&(_, at)| now.duration_since(*at) > timeout)
            .filter_map(|(&h, _)| self.in_flight.get(&h).map(|&p| (h, p)))
            .collect();

        let count = stale.len();
        for (h, peer_id) in stale {
            self.in_flight.remove(&h);
            self.in_flight_at.remove(&h);
            // Push to front — the connect loop is likely waiting for this height
            self.pending.push_front(h);
            if let Some(slots) = self.peer_slots.get_mut(&peer_id) {
                slots.assigned.retain(|&x| x != h);
            }
        }
        count
    }

    /// Notify the scheduler that the connect cursor has advanced.
    /// Heights below the cursor are no longer relevant.
    pub fn connect_cursor_advanced(&mut self, new_tip: u32) {
        self.connect_cursor = new_tip;
        // Remove from downloaded set — they've been connected
        self.downloaded.retain(|&h| h > new_tip);
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
            parent_hash = cs.accept_block(&block).unwrap();
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
        let released = sched.release_stale_inflight(Duration::from_secs(60));
        assert!(
            released >= heights_in_flight.len(),
            "release_stale_inflight should fire for stale heights despite \
             peer churn; released={released} expected>={}",
            heights_in_flight.len()
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

        // Their blocks should be back in the pool
        assert_eq!(sched.in_flight.len(), 0);
        assert_eq!(sched.pending.len(), 50); // All 50 back in pending

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

        let stalled = sched.detect_stalls(Duration::from_secs(60));
        assert_eq!(stalled, vec![1]);

        // Peer should be removed and blocks returned
        assert!(!sched.peer_slots.contains_key(&1));
        assert_eq!(sched.in_flight.len(), 0);

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

    #[test]
    fn test_completion() {
        let (cs, dir) = make_chain_state_with_headers(10);
        let mut sched = IbdScheduler::new(10, 0, &cs, 50_000);

        // Assign all blocks to peer 1
        let _ = sched.assign_blocks(1);

        // Mark all as received
        for h in 1..=10 {
            sched.block_received(1, h);
        }

        assert!(sched.is_complete());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
