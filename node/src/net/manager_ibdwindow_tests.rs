//! Block download bookkeeping on a live `PeerManager`: who is charged for a
//! failed store, which peers are asked for blocks, and how the tip-following
//! sweep shares missing blocks out.

use super::*;
use crate::net::flow::InFlight;
use bitcoin::p2p::message_blockdata::Inventory;

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
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
        .unwrap(),
    );
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
    (pm, dir)
}

fn add_peer(pm: &PeerManager, id: PeerId, services: ServiceFlags, best_height: i32) -> mpsc::Receiver<NetworkMessage> {
    let addr = SocketAddr::from(([10, 62, 0, id as u8], 8333));
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.state = PeerState::Connected;
    info.services = services;
    info.best_height = best_height;
    let (tx, rx) = mpsc::channel::<NetworkMessage>(64);
    pm.peers.write().insert(
        id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            last_mempool_served: None,
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
    rx
}

fn ban_score(pm: &PeerManager, id: PeerId) -> u32 {
    pm.peers.read()[&id].info.ban_score
}

/// `n` blocks on top of genesis, not stored.
fn blocks(n: u32) -> Vec<bitcoin::Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    (1..=n)
        .map(|i| {
            let block = crate::chain::state::tests::build_test_block(parent, i, 1_300_000_000 + i);
            parent = block.block_hash();
            block
        })
        .collect()
}

fn blocks_asked(msgs: &[NetworkMessage]) -> Vec<bitcoin::BlockHash> {
    msgs.iter()
        .filter_map(|m| match m {
            NetworkMessage::GetData(inv) => Some(inv),
            _ => None,
        })
        .flatten()
        .filter_map(|i| match i {
            Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(*h),
            _ => None,
        })
        .collect()
}

fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// Make the block files unwritable: the append file read-only and its cached
/// handle dropped. `false` when the process can write it anyway (root).
fn break_block_files(pm: &PeerManager, dir: &tempfile::TempDir) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let blocks = dir.path().join("blocks");
    for entry in std::fs::read_dir(&blocks).unwrap() {
        let path = entry.unwrap().path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    std::fs::set_permissions(&blocks, std::fs::Permissions::from_mode(0o555)).unwrap();
    pm.chain_state.resync_block_append_pos().unwrap();
    let probe = std::fs::read_dir(&blocks).unwrap().next().unwrap().unwrap().path();
    std::fs::OpenOptions::new().append(true).open(probe).is_err()
}

fn restore_block_files(dir: &tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let blocks = dir.path().join("blocks");
    let _ = std::fs::set_permissions(&blocks, std::fs::Permissions::from_mode(0o755));
}

/// A block that could not be written to this node's own disk is not the
/// sender's fault. Core ends a failed write in `FatalError`, never
/// `Misbehaving`. A block that fails its checks still is.
#[test]
fn a_local_write_failure_does_not_charge_the_sender() {
    type Store = fn(&PeerManager, PeerId, bitcoin::Block);
    let paths: [(&str, Store, u32); 2] = [
        ("forward IBD", |pm, id, b| pm.handle_block_ibd(id, b), 10),
        ("background catch-up", |pm, id, b| pm.store_bg_block(id, b), 5),
    ];
    for (path, store, penalty) in paths {
        // The disk refuses the write.
        let (pm, dir) = mk_pm();
        let _rx = add_peer(&pm, 1, ServiceFlags::NETWORK, 1);
        if !break_block_files(&pm, &dir) {
            eprintln!("skipping: block files are writable despite their mode (running as root?)");
            restore_block_files(&dir);
            return;
        }
        let block = blocks(1).remove(0);
        let hash = block.block_hash();
        store(&pm, 1, block);
        restore_block_files(&dir);
        assert!(!pm.chain_state.has_block_data(&hash), "{path}: the write did not fail");
        assert_eq!(ban_score(&pm, 1), 0, "{path}: the sender was charged for our disk");

        // The block itself is bad.
        let (pm, _dir) = mk_pm();
        let _rx = add_peer(&pm, 1, ServiceFlags::NETWORK, 1);
        let mut block = blocks(1).remove(0);
        block.txdata[0].output[0].value = bitcoin::Amount::from_sat(1);
        store(&pm, 1, block);
        assert_eq!(ban_score(&pm, 1), penalty, "{path}: a bad block went uncharged");
    }
}

/// Core downloads only from a peer that advertises NODE_NETWORK or
/// NODE_NETWORK_LIMITED, and from a limited one only blocks within 286 of
/// its tip.
#[test]
fn ibd_work_goes_only_to_peers_that_can_serve_it() {
    let chain = blocks(5);
    let cases = [
        ("NODE_NETWORK", ServiceFlags::NETWORK, 5, true),
        ("no block service", ServiceFlags::WITNESS, 5, false),
        ("limited, every height recent", ServiceFlags::NETWORK_LIMITED, 5, true),
        ("limited, heights too deep", ServiceFlags::NETWORK_LIMITED, 300, false),
    ];
    for (what, services, best_height, expect) in cases {
        let (pm, _dir) = mk_pm();
        for b in &chain {
            pm.chain_state.accept_header(&b.header).unwrap();
        }
        *pm.ibd.write() = Some(IbdScheduler::new(5, 0, &pm.chain_state, 1024));
        let mut rx = add_peer(&pm, 1, services, best_height);
        pm.assign_peer_work(1);
        let asked = blocks_asked(&drain(&mut rx));
        assert_eq!(!asked.is_empty(), expect, "{what}: asked for {asked:?}");
    }
}

/// The tip-following sweep asks one peer per block. Across two passes, each
/// missing block is asked for exactly once; once that request is old, it is
/// asked of a different peer.
#[test]
fn the_sweep_asks_one_peer_per_block() {
    let (pm, _dir) = mk_pm();
    let chain = blocks(5);
    for b in &chain {
        pm.chain_state.accept_header(&b.header).unwrap();
    }
    let mut rxs: Vec<_> = (1..=3).map(|id| add_peer(&pm, id, ServiceFlags::NETWORK, 5)).collect();
    let peers = [1, 2, 3];

    pm.sweep_missing_blocks(&peers);
    pm.sweep_missing_blocks(&peers);
    let first: Vec<Vec<bitcoin::BlockHash>> = rxs.iter_mut().map(|rx| blocks_asked(&drain(rx))).collect();
    for b in &chain {
        let hash = b.block_hash();
        let times = first.iter().flatten().filter(|h| **h == hash).count();
        assert_eq!(times, 1, "block {hash} asked for {times} times: {first:?}");
    }

    // The requests age past the re-request delay.
    for asked in pm.in_flight_blocks.write().values_mut() {
        for r in asked.values_mut() {
            r.at -= SWEEP_REREQUEST_AFTER + Duration::from_secs(1);
        }
    }
    pm.sweep_missing_blocks(&peers);
    let second: Vec<Vec<bitcoin::BlockHash>> = rxs.iter_mut().map(|rx| blocks_asked(&drain(rx))).collect();
    for b in &chain {
        let hash = b.block_hash();
        let before: Vec<usize> = (0..3).filter(|i| first[*i].contains(&hash)).collect();
        let now: Vec<usize> = (0..3).filter(|i| second[*i].contains(&hash)).collect();
        assert_eq!(now.len(), 1, "block {hash} re-asked of {now:?}");
        assert_ne!(now, before, "block {hash} re-asked of the same peer");
    }
}

/// `notfound` for a background-download height releases it at once.
#[test]
fn notfound_releases_a_background_height() {
    let (pm, _dir) = mk_pm();
    let chain = blocks(2);
    for b in &chain {
        pm.chain_state.accept_header(&b.header).unwrap();
    }
    let _rx1 = add_peer(&pm, 1, ServiceFlags::NETWORK, 2);
    let _rx2 = add_peer(&pm, 2, ServiceFlags::NETWORK, 2);
    pm.bg_downloader.write().mark_in_flight(1, 1, Instant::now());
    pm.bg_downloader.write().mark_in_flight(2, 1, Instant::now());

    let notfound = |h: &bitcoin::Block| NetworkMessage::NotFound(vec![Inventory::WitnessBlock(h.block_hash())]);
    pm.handle_message(2, notfound(&chain[0]), InFlight::adopt(None));
    assert!(pm.bg_downloader.read().is_in_flight(1), "peer 2 was not asked for it");
    pm.handle_message(1, notfound(&chain[0]), InFlight::adopt(None));
    assert!(!pm.bg_downloader.read().is_in_flight(1), "notfound from the peer asked releases it");
    assert!(pm.bg_downloader.read().is_in_flight(2));
}

/// The sweep asks for a block only a peer known to have it: not one whose
/// best block is lower, and not a limited peer for a block deeper than it
/// keeps. A `notfound` frees the block for the next pass.
#[test]
fn the_sweep_asks_a_peer_that_has_the_block() {
    let (pm, _dir) = mk_pm();
    let chain = blocks(300);
    for b in &chain {
        pm.chain_state.accept_header(&b.header).unwrap();
    }
    let mut behind = add_peer(&pm, 1, ServiceFlags::NETWORK, 0);
    let mut limited = add_peer(&pm, 2, ServiceFlags::NETWORK_LIMITED, 300);
    let mut full = add_peer(&pm, 3, ServiceFlags::NETWORK, 300);
    pm.sweep_missing_blocks(&[1, 2, 3]);
    assert!(blocks_asked(&drain(&mut behind)).is_empty(), "a peer without the blocks was asked");
    // The limited peer keeps blocks 15..=300 (within 286 of its tip).
    let deep: Vec<bitcoin::BlockHash> = chain[..14].iter().map(|b| b.block_hash()).collect();
    let from_limited = blocks_asked(&drain(&mut limited));
    assert!(!from_limited.is_empty(), "the limited peer is asked for the blocks it keeps");
    assert!(from_limited.iter().all(|h| !deep.contains(h)), "a limited peer was asked for deep blocks");
    let asked = blocks_asked(&drain(&mut full));
    assert!(asked.contains(&chain[0].block_hash()), "the peer that has them was not asked: {asked:?}");

    // It answers notfound: the next pass may ask again at once.
    pm.handle_message(3, NetworkMessage::NotFound(vec![Inventory::WitnessBlock(chain[0].block_hash())]), InFlight::adopt(None));
    pm.sweep_missing_blocks(&[1, 2, 3]);
    assert!(blocks_asked(&drain(&mut full)).contains(&chain[0].block_hash()));
}
