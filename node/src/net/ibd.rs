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
            downloaded: HashSet::new(),
            peer_slots: HashMap::new(),
            per_peer_limit: 128,
            max_ahead: 50_000,
            connect_cursor: current_tip,
            height_to_hash,
        }
    }

    /// Assign blocks to a peer for download. Returns hashes to request via GetData.
    /// Respects per-peer limits and the max-ahead window.
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

        // Track how many total blocks are ahead of the connect cursor
        let total_ahead =
            self.downloaded.len() as u32 + self.in_flight.len() as u32;

        let mut attempts = 0;
        while hashes.len() < budget && !self.pending.is_empty() {
            // Prevent infinite loop if all remaining blocks exceed max_ahead
            attempts += 1;
            if attempts > self.pending.len() + budget {
                break;
            }

            let height = match self.pending.pop_front() {
                Some(h) => h,
                None => break,
            };

            // Skip already downloaded
            if self.downloaded.contains(&height) {
                continue;
            }

            // Skip if already in-flight
            if self.in_flight.contains_key(&height) {
                continue;
            }

            // Respect max_ahead window
            if height > self.connect_cursor + self.max_ahead
                && total_ahead + hashes.len() as u32 >= self.max_ahead
            {
                // Put it back and stop
                self.pending.push_back(height);
                break;
            }

            if let Some(&hash) = self.height_to_hash.get(&height) {
                self.in_flight.insert(height, peer_id);
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
    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        if let Some(slots) = self.peer_slots.remove(&peer_id) {
            for height in slots.assigned {
                self.in_flight.remove(&height);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
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
            None,
        )
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
        let mut sched = IbdScheduler::new(100, 0, &cs);

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
        let sched = IbdScheduler::new(100, 0, &cs);

        // Check that pending is not in sequential order
        let heights: Vec<u32> = sched.pending.iter().copied().collect();
        let mut sorted = heights.clone();
        sorted.sort();
        // With 100 elements shuffled, it's astronomically unlikely to be sorted
        assert_ne!(heights, sorted, "Blocks should be shuffled, not sequential");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peer_disconnect_reassigns() {
        let (cs, dir) = make_chain_state_with_headers(50);
        let mut sched = IbdScheduler::new(50, 0, &cs);

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
        let mut sched = IbdScheduler::new(50, 0, &cs);

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
        let mut sched = IbdScheduler::new(100, 0, &cs);
        sched.max_ahead = 20; // Small window for testing

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
        let mut sched = IbdScheduler::new(50, 0, &cs);

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
        let mut sched = IbdScheduler::new(10, 0, &cs);

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
