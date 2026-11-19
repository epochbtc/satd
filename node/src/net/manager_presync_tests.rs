//! Headers presync in the peer manager (#1132): Core's
//! `TryLowWorkHeadersSync` and `IsContinuationOfLowWorkHeadersSync` in front
//! of header acceptance, and how the IBD header probe and the post-IBD poll
//! leave a sync in progress alone.

use super::*;
use crate::storage::blockindex::{add_u256, work_for_bits};

/// A regtest peer manager whose `-minimumchainwork` is `min_work`.
fn mk_pm(min_work: Option<[u8; 32]>) -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let mut cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        flat_files,
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    cs.set_minimum_chain_work(min_work);
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::new(Arc::new(cs), mempool, fee_estimator, Network::Regtest, shutdown_rx);
    (pm, dir)
}

fn add_peer(pm: &PeerManager, id: PeerId, noban: bool) -> mpsc::Receiver<NetworkMessage> {
    let addr = SocketAddr::from(([10, 64, 0, id as u8], 8333));
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.state = PeerState::Connected;
    info.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    info.permissions.noban = noban;
    let (tx, rx) = mpsc::channel::<NetworkMessage>(4096);
    pm.peers.write().insert(
        id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            header_sync: Default::default(),
            last_mempool_served: None,
            tx_relay: Default::default(),
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
    rx
}

/// `n` regtest headers on `prev`, one second apart from `time`.
fn headers_on(prev: bitcoin::BlockHash, n: usize, time: u32, tag: u8) -> Vec<bitcoin::block::Header> {
    let mut parent = prev;
    (0..n)
        .map(|i| {
            let mut h = bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: parent,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([tag; 32]),
                time: time + i as u32,
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            while crate::validation::pow::check_proof_of_work(&h).is_err() {
                h.nonce += 1;
            }
            parent = h.block_hash();
            h
        })
        .collect()
}

fn genesis() -> bitcoin::BlockHash {
    bitcoin::constants::genesis_block(Network::Regtest).block_hash()
}

fn genesis_chain(n: usize, tag: u8) -> Vec<bitcoin::block::Header> {
    headers_on(genesis(), n, 1_600_000_000, tag)
}

/// The work of genesis and `n` regtest headers on it.
fn work_at(n: usize) -> [u8; 32] {
    let one = work_for_bits(bitcoin::CompactTarget::from_consensus(0x207f_ffff));
    (0..=n).fold([0u8; 32], |acc, _| add_u256(&acc, &one))
}

fn getheaders(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<Vec<bitcoin::BlockHash>> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .filter_map(|m| match m {
            NetworkMessage::GetHeaders(gh) => Some(gh.locator_hashes),
            _ => None,
        })
        .collect()
}

/// Answer the peer's `getheaders` from `chain` the way Core's
/// `ProcessGetHeaders` does, until it stops asking.
fn serve(pm: &PeerManager, id: PeerId, rx: &mut mpsc::Receiver<NetworkMessage>, chain: &[bitcoin::block::Header]) -> usize {
    let mut answered = 0;
    while let Some(locator) = getheaders(rx).pop() {
        answered += 1;
        assert!(answered < 100, "header sync did not converge");
        let start = locator
            .iter()
            .find_map(|h| {
                if *h == genesis() {
                    return Some(0);
                }
                chain.iter().position(|c| c.block_hash() == *h).map(|i| i + 1)
            })
            .unwrap_or(0);
        pm.handle_headers(id, chain[start..chain.len().min(start + 2000)].to_vec());
    }
    answered
}

fn presync_height(pm: &PeerManager, id: PeerId) -> i64 {
    pm.peers.read().get(&id).map(|h| h.info.presync_height).unwrap()
}

/// A full batch below the threshold starts a presync: nothing is stored,
/// `presynced_headers` reports its height, and the next `getheaders`
/// continues from the last header it took.
#[test]
fn a_full_low_work_batch_starts_a_presync_and_stores_nothing() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let mut rx = add_peer(&pm, 1, false);
    let chain = genesis_chain(4000, 1);

    pm.handle_headers(1, chain[..2000].to_vec());
    assert_eq!(pm.chain_state.best_header_hash(), genesis(), "nothing stored");
    assert!(pm.chain_state.get_block_index(&chain[0].block_hash()).is_none());
    assert_eq!(presync_height(&pm, 1), 2000);
    let sent = getheaders(&mut rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][0], chain[1999].block_hash(), "continues from the last header");
    assert_eq!(sent[0].last(), Some(&genesis()), "then the chain start's locator");

    pm.handle_headers(1, chain[2000..].to_vec());
    assert_eq!(presync_height(&pm, 1), 4000);
    let json = pm.peers.read().get(&1).unwrap().info.to_rpc_json(&PeerStats::new(NetTotals::new()));
    assert_eq!(json["presynced_headers"], 4000);
    assert_eq!(pm.chain_state.best_header_hash(), genesis());
}

/// Core's "Ignoring low-work chain": a message below the threshold that is
/// not full means the peer's chain ends there. Nothing is stored and no
/// sync starts.
#[test]
fn a_short_low_work_batch_is_ignored() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let mut rx = add_peer(&pm, 1, false);
    let chain = genesis_chain(100, 2);
    pm.handle_headers(1, chain.clone());
    assert!(pm.chain_state.get_block_index(&chain[0].block_hash()).is_none());
    assert_eq!(presync_height(&pm, 1), -1);
    assert!(!pm.headers_syncs.lock().contains_key(&1));
    assert!(getheaders(&mut rx).is_empty());
}

/// The whole round: a chain that passes the threshold in presync is
/// downloaded again and stored, all of it.
#[test]
fn a_chain_with_enough_work_is_stored_after_its_redownload() {
    let (pm, _dir) = mk_pm(Some(work_at(9_000)));
    let mut rx = add_peer(&pm, 1, false);
    let chain = genesis_chain(10_000, 3);
    pm.handle_headers(1, chain[..2000].to_vec());
    let answered = serve(&pm, 1, &mut rx, &chain);
    assert_eq!(pm.chain_state.best_header_hash(), chain.last().unwrap().block_hash());
    assert_eq!(pm.chain_state.headers_tip_height(), 10_000);
    assert!(answered >= 9, "both passes: {answered} getheaders answered");
    assert!(!pm.headers_syncs.lock().contains_key(&1), "the sync is over");
    assert_eq!(presync_height(&pm, 1), -1);
}

/// A `noban` peer's headers skip the work check, as in Core.
#[test]
fn a_noban_peers_low_work_headers_are_stored() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let _rx = add_peer(&pm, 1, true);
    let chain = genesis_chain(100, 4);
    pm.handle_headers(1, chain.clone());
    assert_eq!(pm.chain_state.best_header_hash(), chain.last().unwrap().block_hash());
}

/// An empty `headers` ends a sync in progress, as in Core.
#[test]
fn an_empty_headers_message_ends_the_sync() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let _rx = add_peer(&pm, 1, false);
    pm.handle_headers(1, genesis_chain(2000, 5));
    assert_eq!(presync_height(&pm, 1), 2000);
    pm.handle_headers(1, Vec::new());
    assert_eq!(presync_height(&pm, 1), -1);
    assert!(!pm.headers_syncs.lock().contains_key(&1));
}

/// Core's `CheckHeadersPoW`: a batch with a header that does not meet its
/// own target, or that does not link up, is refused whole and the peer
/// punished, before any of it reaches a headers sync or the index.
#[test]
fn headers_failing_cores_pow_check_are_refused_whole() {
    let (pm, _dir) = mk_pm(None);
    let _rx = add_peer(&pm, 1, false);
    let mut chain = genesis_chain(10, 6);
    // A header whose hash misses its target (about half do on regtest).
    let mut bad = chain[9];
    while crate::validation::pow::check_proof_of_work(&bad).is_ok() {
        bad.nonce += 1;
    }
    chain[9] = bad;
    pm.handle_headers(1, chain.clone());
    assert!(pm.chain_state.get_block_index(&chain[0].block_hash()).is_none(), "none of the batch is stored");
    assert!(!pm.peers.read().contains_key(&1), "the peer is disconnected");

    let _rx = add_peer(&pm, 2, false);
    let mut gap = genesis_chain(10, 7);
    gap.remove(4);
    pm.handle_headers(2, gap.clone());
    assert!(pm.chain_state.get_block_index(&gap[0].block_hash()).is_none());
    assert!(!pm.peers.read().contains_key(&2), "non-continuous headers are punished");
}

/// The user's ruling on the stall probe (#1132): presync and redownload
/// progress counts as header progress. A presync leaves the header tip where
/// it is, and without this the probe would ask another peer every 10 s of it.
#[test]
fn presync_progress_holds_off_the_header_probe() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let _rx = add_peer(&pm, 1, false);
    let chain = genesis_chain(6000, 8);
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    pm.handle_headers(1, chain[..2000].to_vec());
    assert!(!pm.ibd_header_probe_due_at(at(0)), "the first check records the state");
    pm.handle_headers(1, chain[2000..4000].to_vec());
    assert!(!pm.ibd_header_probe_due_at(at(10)), "the presync moved: no stall");
    pm.handle_headers(1, chain[4000..].to_vec());
    assert!(!pm.ibd_header_probe_due_at(at(20)), "and moved again");
    assert_eq!(pm.chain_state.headers_tip_height(), 0, "the header tip never moved");
    assert!(pm.ibd_header_probe_due_at(at(30)), "a presync that stops is a stall");
}

/// The other half of that ruling: neither the stall probe nor the post-IBD
/// poll asks a peer with a headers sync in progress. Its answer would not
/// follow on from the presync, and would end it.
#[test]
fn the_probe_and_the_poll_leave_a_syncing_peer_alone() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let _rx1 = add_peer(&pm, 1, false);
    let _rx2 = add_peer(&pm, 2, false);
    pm.handle_headers(1, genesis_chain(2000, 9));
    assert!(pm.headers_syncs.lock().contains_key(&1));
    for _ in 0..5 {
        assert_eq!(pm.header_probe_peer(), Some(2), "the probe never picks the syncing peer");
    }
    assert_eq!(pm.header_poll_peers(), vec![2]);
}

/// The user's ruling on a clock far behind the chain (#1132): Core logs
/// "Failure when attempting to initiate headers sync" and aborts; satd logs
/// it and asks for a clean shutdown. No sync starts.
#[test]
fn a_clock_far_behind_the_chain_start_asks_for_shutdown() {
    let (pm, _dir) = mk_pm(Some(work_at(100_000)));
    let (tx, rx) = tokio::sync::watch::channel(false);
    pm.set_shutdown_sender(tx);
    let _rx = add_peer(&pm, 1, false);
    // A short recent chain, stored directly, is the chain start.
    let now = crate::time::now_secs() as u32;
    let recent = headers_on(genesis(), 11, now - 100, 10);
    assert_eq!(pm.chain_state.accept_headers(&recent).0, 11);
    let batch = headers_on(recent[10].block_hash(), 2000, now - 80, 11);

    // Three hours back: past Core's two-hour allowance.
    pm.handle_headers_at(1, batch.clone(), u64::from(now) - 3 * 60 * 60);
    assert!(*rx.borrow(), "shutdown was asked for");
    assert!(!pm.headers_syncs.lock().contains_key(&1), "no sync started");
    assert!(pm.chain_state.get_block_index(&batch[0].block_hash()).is_none());
}
