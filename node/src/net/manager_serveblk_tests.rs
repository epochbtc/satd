//! Which blocks are served, and which services are advertised, as Core
//! decides them (`ProcessGetBlockData`, `BlockRequestAllowed`,
//! `g_local_services`): a pruned node is `NODE_NETWORK_LIMITED` and serves
//! nothing deeper, and a block off the active chain is served only if it was
//! validated.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetBlocksMessage;

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let store = Box::new(InMemoryStore::new());
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            store,
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

fn add_peer(pm: &PeerManager, id: PeerId, noban: bool) -> mpsc::Receiver<NetworkMessage> {
    let addr = SocketAddr::from(([10, 0, 0, id as u8], 8333));
    let mut info = PeerInfo::new(id, addr, Direction::Inbound);
    info.state = PeerState::Connected;
    info.permissions.noban = noban;
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
            tx_relay: Default::default(),
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
    rx
}

/// Mine `n` blocks on the tip, `tag` in the coinbase so a second branch at
/// the same heights is made of other blocks.
fn mine(pm: &PeerManager, n: usize, tag: u8) -> Vec<bitcoin::BlockHash> {
    let mempool = Mempool::new(1_000_000, 0);
    (0..n)
        .map(|_| {
            let block = crate::mining::miner::build_block_to_script(
                &pm.chain_state,
                &mempool,
                bitcoin::ScriptBuf::new_op_return([tag]),
                None,
            )
            .expect("mine regtest block");
            pm.chain_state.accept_block(&block).expect("accept block");
            block.block_hash()
        })
        .collect()
}

fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn served_blocks(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<bitcoin::BlockHash> {
    drain(rx)
        .into_iter()
        .map(|m| match m {
            NetworkMessage::Block(b) => b.block_hash(),
            other => panic!("expected a block, got {other:?}"),
        })
        .collect()
}

/// Core sets `NODE_NETWORK_LIMITED` on every node and `NODE_NETWORK` only on
/// one that keeps the whole chain. satd claimed `NODE_NETWORK` when pruned.
#[test]
fn a_pruned_node_advertises_network_limited_and_not_network() {
    let (pm, _dir) = mk_pm();
    let full = pm.local_services();
    assert!(full.has(ServiceFlags::NETWORK) && full.has(ServiceFlags::NETWORK_LIMITED), "{full}");
    assert!(full.has(ServiceFlags::WITNESS));

    pm.set_prune_manual(true);
    let pruned = pm.local_services();
    assert!(!pruned.has(ServiceFlags::NETWORK), "a pruned node cannot promise every block: {pruned}");
    assert!(pruned.has(ServiceFlags::NETWORK_LIMITED) && pruned.has(ServiceFlags::WITNESS), "{pruned}");

    // Our own address goes out with the same flags.
    pm.external_addrs.write().push(SocketAddr::from(([203, 0, 113, 50], 8333)));
    let _r = add_peer(&pm, 9, false);
    let Some(NetworkMessage::Addr(a)) = pm.self_advertise_externals(9) else { panic!("a legacy addr") };
    assert_eq!(a[0].1.services, pruned);
}

/// A block off the active chain is served only if this node validated it
/// (Core's `BlockRequestAllowed`); anything else is ignored, with no
/// `notfound`, as Core ignores it.
#[test]
fn a_stale_block_is_served_only_if_it_was_validated() {
    let (pm, _dir) = mk_pm();
    let a = mine(&pm, 3, 1);
    // The second block and its child are invalidated, and another branch
    // takes their place.
    pm.chain_state.invalidate_block(a[1]).unwrap();
    let b = mine(&pm, 3, 2);
    assert_eq!(pm.chain_state.tip_hash(), b[2]);
    let mut rx = add_peer(&pm, 1, false);

    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[2])]);
    assert!(drain(&mut rx).is_empty(), "an invalidated block is not served, and no notfound is sent");
    assert!(pm.peers.read().contains_key(&1), "the peer is not disconnected for it");
    pm.handle_getdata(1, vec![Inventory::CompactBlock(a[2])]);
    assert!(drain(&mut rx).is_empty(), "nor as a compact block");

    // Reconsidered, they are side-branch blocks never connected: Core does
    // not serve those either (no `BLOCK_VALID_SCRIPTS`).
    pm.chain_state.reconsider_block(a[1]).unwrap();
    assert_eq!(pm.chain_state.tip_hash(), b[2], "the other branch has more work");
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[1])]);
    assert!(drain(&mut rx).is_empty(), "a block never validated is not served");

    // Connected once and then reorged away, they were validated: Core serves
    // those for a month.
    pm.chain_state.invalidate_block(b[0]).unwrap();
    assert_eq!(pm.chain_state.tip_hash(), a[2]);
    pm.chain_state.reconsider_block(b[0]).unwrap();
    assert_eq!(pm.chain_state.tip_hash(), b[2]);
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[1])]);
    assert_eq!(served_blocks(&mut rx), vec![a[1]], "a validated stale block is served");

    // The active chain is served as before.
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(b[0])]);
    assert_eq!(served_blocks(&mut rx), vec![b[0]]);
}

/// A pruned node disconnects a peer that asks for a block more than
/// `NODE_NETWORK_LIMITED_MIN_BLOCKS` + 2 below its tip, so the depth it keeps
/// blocks to cannot be probed; a `noban` peer is still served.
#[test]
fn a_pruned_node_serves_nothing_below_the_limited_depth() {
    let (pm, _dir) = mk_pm();
    let chain = mine(&pm, 300, 1);
    pm.set_prune_manual(true);
    let tip = pm.chain_state.tip_height();
    let at = |height: u32| chain[height as usize - 1];

    let mut rx = add_peer(&pm, 1, false);
    let edge = tip - (NODE_NETWORK_LIMITED_MIN_BLOCKS + 2);
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(at(edge))]);
    assert_eq!(served_blocks(&mut rx), vec![at(edge)], "290 deep is still served");

    let mut whitelisted = add_peer(&pm, 2, true);
    pm.handle_getdata(2, vec![Inventory::WitnessBlock(at(edge - 1))]);
    assert_eq!(served_blocks(&mut whitelisted), vec![at(edge - 1)], "noban is exempt");

    pm.handle_getdata(1, vec![Inventory::WitnessBlock(at(edge - 1))]);
    assert!(drain(&mut rx).is_empty(), "nothing deeper");
    assert!(!pm.peers.read().contains_key(&1), "and the peer is disconnected");

    // An unpruned node serves the whole chain.
    pm.set_prune_manual(false);
    let mut rx3 = add_peer(&pm, 3, false);
    pm.handle_getdata(3, vec![Inventory::WitnessBlock(at(1))]);
    assert_eq!(served_blocks(&mut rx3), vec![at(1)]);
}

/// A pruned node's `getblocks` answer stops above the depth it may delete
/// within the hour (Core's `nPrunedBlocksLikelyToHave`).
#[test]
fn a_pruned_nodes_getblocks_stops_at_blocks_it_may_not_keep() {
    let (pm, dir) = mk_pm();
    let chain = mine(&pm, 300, 1);
    let tip = pm.chain_state.tip_height();
    let mut rx = add_peer(&pm, 1, false);
    let invd = |rx: &mut mpsc::Receiver<NetworkMessage>| -> Vec<bitcoin::BlockHash> {
        drain(rx)
            .into_iter()
            .flat_map(|m| match m {
                NetworkMessage::Inv(inv) => inv,
                other => panic!("expected an inv, got {other:?}"),
            })
            .map(|i| match i {
                Inventory::Block(h) => h,
                other => panic!("expected a block inv, got {other:?}"),
            })
            .collect()
    };
    let locator = |height: u32| vec![chain[height as usize - 1]];
    let none = bitcoin::BlockHash::from_byte_array([0; 32]);

    pm.handle_getblocks(1, GetBlocksMessage::new(locator(10), none));
    assert_eq!(invd(&mut rx).len(), 290, "an unpruned node invs from the fork point on");

    pm.set_prune_manual(true);
    pm.handle_getblocks(1, GetBlocksMessage::new(locator(10), none));
    assert!(invd(&mut rx).is_empty(), "a pruned node invs nothing it may soon delete");

    let from = tip - PRUNED_BLOCKS_LIKELY_TO_HAVE;
    pm.handle_getblocks(1, GetBlocksMessage::new(locator(from), none));
    let got = invd(&mut rx);
    assert_eq!(got.len(), PRUNED_BLOCKS_LIKELY_TO_HAVE as usize, "{} blocks", got.len());
    assert_eq!(got[0], chain[from as usize], "starting just above the cut");

    // Whether a block is still held comes from the block index, not from
    // reading the block: with every block file emptied, the index still
    // says the blocks are there, and the answer is the same.
    for f in std::fs::read_dir(dir.path().join("blocks")).unwrap() {
        let f = f.unwrap().path();
        if f.file_name().unwrap().to_string_lossy().starts_with("blk") {
            std::fs::OpenOptions::new().write(true).open(&f).unwrap().set_len(0).unwrap();
        }
    }
    assert!(pm.chain_state.get_block(&chain[from as usize]).is_none(), "premise: the block bodies are gone");
    pm.handle_getblocks(1, GetBlocksMessage::new(locator(from), none));
    assert_eq!(invd(&mut rx).len(), PRUNED_BLOCKS_LIKELY_TO_HAVE as usize, "no block is read to answer");
}

/// Core also refuses a validated stale block with 30 days' worth of proof of
/// work on top of it (`GetBlockProofEquivalentTime`), however recent its
/// timestamp: 4320 blocks at the best header's difficulty.
#[test]
fn a_stale_block_buried_under_a_month_of_work_is_not_served() {
    let (pm, _dir) = mk_pm();
    let a = mine(&pm, 2, 1);
    pm.chain_state.invalidate_block(a[1]).unwrap();
    let b = mine(&pm, 2, 2);
    pm.chain_state.reconsider_block(a[1]).unwrap();
    pm.chain_state.invalidate_block(b[0]).unwrap();
    pm.chain_state.reconsider_block(b[0]).unwrap();
    assert_eq!(pm.chain_state.tip_hash(), b[1]);
    let mut rx = add_peer(&pm, 1, false);
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[1])]);
    assert_eq!(served_blocks(&mut rx), vec![a[1]], "validated and recent");

    // b[1] already has one block's more work than a[1].
    mine(&pm, 4318, 2);
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[1])]);
    assert_eq!(served_blocks(&mut rx), vec![a[1]], "4319 blocks on top: still served");
    mine(&pm, 1, 2);
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(a[1])]);
    assert!(drain(&mut rx).is_empty(), "4320 blocks on top: a month of work, not served");

    // Whether a requested block is on the active chain comes from the height
    // index alone, never a walk from the tip, which a `getdata` naming an old
    // side block thousands of times would repeat for each entry. Proven by
    // pointing b[0]'s row at a[1]: judged by the index, b[0] is off the chain
    // under a month of work and is not served; a walk would find it and
    // serve it.
    let mut batch = crate::storage::StoreBatch::default();
    batch.height_hash_puts.push((pm.chain_state.get_block_index(&b[0]).unwrap().height, a[1]));
    pm.chain_state.store_for_test().write_batch(batch).unwrap();
    pm.handle_getdata(1, vec![Inventory::WitnessBlock(b[0])]);
    assert!(drain(&mut rx).is_empty(), "membership is read from the height index, without a walk");
}
