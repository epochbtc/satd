//! Header sync continuation: after a full `headers` batch, the next
//! `getheaders` to that peer starts from the last header it sent, as Core's
//! `ProcessHeadersMessage` does (`MaybeSendGetHeaders(pfrom,
//! GetLocator(pindexLast))`), whether or not the batch held new headers.

use super::*;

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

fn add_peer(pm: &PeerManager, id: PeerId) -> mpsc::Receiver<NetworkMessage> {
    let addr = SocketAddr::from(([10, 63, 0, id as u8], 8333));
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.state = PeerState::Connected;
    info.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    info.best_height = 3000;
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

fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// `n` regtest headers on top of genesis, timestamps from `time_base`.
fn header_chain(n: u32, time_base: u32) -> Vec<bitcoin::block::Header> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    (1..=n)
        .map(|i| {
            let mut block = bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(0x2000_0000),
                    prev_blockhash: parent,
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time: time_base + i,
                    bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txdata: Vec::new(),
            };
            crate::chain::state::tests::grind_test_pow(&mut block);
            parent = block.block_hash();
            block.header
        })
        .collect()
}

/// A peer whose active chain is `chain` answers a locator the way Core's
/// `ProcessGetHeaders` does: from the first locator hash on its chain (or
/// genesis), the next 2000 headers.
fn serve(chain: &[bitcoin::block::Header], locator: &[bitcoin::BlockHash]) -> Vec<bitcoin::block::Header> {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let fork_height = locator
        .iter()
        .find_map(|h| {
            if *h == genesis {
                return Some(0);
            }
            chain.iter().position(|hdr| hdr.block_hash() == *h).map(|i| i + 1)
        })
        .unwrap_or(0);
    chain[fork_height..chain.len().min(fork_height + 2000)].to_vec()
}

/// The node first learns a 2100-header branch from one peer. A second peer
/// is on a 3000-header chain that forks at genesis, so its first 2000
/// headers carry less work than the branch the node already has and do not
/// move the height rows. A locator built from those rows leads the second
/// peer back to genesis and the same 2000 headers on every request, and
/// header sync could not continue past the competing branch. Continuing
/// from the peer's last header reaches its tip.
#[test]
fn full_headers_batch_continues_from_the_peers_last_header() {
    let (pm, _dir) = mk_pm();
    let branch = header_chain(2100, 1_600_000_000);
    let chain = header_chain(3000, 1_500_000_000);

    let mut branch_rx = add_peer(&pm, 1);
    pm.handle_headers(1, branch[..2000].to_vec());
    pm.handle_headers(1, branch[2000..].to_vec());
    assert_eq!(pm.chain_state.best_header_hash(), branch.last().unwrap().block_hash());
    drain(&mut branch_rx);

    let mut rx = add_peer(&pm, 2);
    let mut request = match sync::make_getheaders(&pm.chain_state) {
        NetworkMessage::GetHeaders(gh) => Some(gh),
        _ => unreachable!(),
    };
    let mut rounds = 0;
    while let Some(gh) = request.take() {
        rounds += 1;
        assert!(rounds <= 10, "header sync did not converge");
        let reply = serve(&chain, &gh.locator_hashes);
        if reply.is_empty() {
            break;
        }
        pm.handle_headers(2, reply);
        request = drain(&mut rx).into_iter().rev().find_map(|m| match m {
            NetworkMessage::GetHeaders(gh) => Some(gh),
            _ => None,
        });
    }
    drain(&mut branch_rx);

    assert_eq!(
        pm.chain_state.best_header_hash(),
        chain.last().unwrap().block_hash(),
        "the second peer's chain has the most work; header sync must reach its tip"
    );
}

/// A full batch the node already has still asks that peer for what follows
/// it, from its last header. Core continues on a full batch whether or not it
/// held anything new.
#[test]
fn full_batch_of_known_headers_still_asks_for_the_next() {
    let (pm, _dir) = mk_pm();
    let chain = header_chain(2000, 1_500_000_000);
    let _rx1 = add_peer(&pm, 1);
    pm.handle_headers(1, chain.clone());

    let mut rx = add_peer(&pm, 2);
    pm.handle_headers(2, chain.clone());
    let asked: Vec<_> = drain(&mut rx)
        .into_iter()
        .filter_map(|m| match m {
            NetworkMessage::GetHeaders(gh) => Some(gh),
            _ => None,
        })
        .collect();
    assert_eq!(asked.len(), 1, "one getheaders to the peer that sent the full batch");
    assert_eq!(asked[0].locator_hashes[0], chain.last().unwrap().block_hash());

    // A short batch is the end of the peer's chain: no follow-up.
    pm.handle_headers(2, chain[..10].to_vec());
    assert!(
        !drain(&mut rx).iter().any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "a batch under 2000 headers ends the exchange"
    );
}

/// On the height rows the branch locator is the ordinary one. Off them it
/// starts with the branch's own blocks, spaced as Core spaces them, and
/// still ends at genesis.
#[test]
fn branch_locator_follows_the_branch_then_the_rows() {
    let (pm, _dir) = mk_pm();
    let cs = &pm.chain_state;
    let rows = header_chain(300, 1_500_000_000);
    let side = header_chain(200, 1_600_000_000);
    assert_eq!(cs.accept_headers(&rows).0, 300);
    assert_eq!(cs.accept_headers(&side).0, 200);

    let tip = rows.last().unwrap().block_hash();
    assert_eq!(sync::build_locator_for_branch(cs, tip).unwrap(), sync::build_locator(cs));

    let locator = sync::build_locator_for_branch(cs, side.last().unwrap().block_hash()).unwrap();
    let height_of = |h: &bitcoin::BlockHash| side.iter().position(|s| s.block_hash() == *h).map(|i| i as u32 + 1);
    let heights: Vec<u32> = locator.iter().filter_map(height_of).collect();
    assert_eq!(heights[..11], [200, 199, 198, 197, 196, 195, 194, 193, 192, 191, 189]);
    assert_eq!(heights.len(), locator.len() - 1, "every entry but genesis is on the branch");
    assert_eq!(
        *locator.last().unwrap(),
        bitcoin::constants::genesis_block(Network::Regtest).block_hash()
    );
    assert!(sync::build_locator_for_branch(cs, bitcoin::BlockHash::all_zeros()).is_none());
}

/// A full batch of new headers asks only the peer that sent it for more.
/// Asking three other peers too, on every batch, started three more request
/// chains per batch, each fetching the same headers to the tip: 5.6 GB of
/// `headers` for a 78 MB mainnet header chain (#1229).
#[test]
fn a_full_batch_asks_only_its_own_peer_for_more() {
    let (pm, _dir) = mk_pm();
    let chain = header_chain(2000, 1_500_000_000);
    let mut rx1 = add_peer(&pm, 1);
    let mut others: Vec<_> = (2..=4).map(|id| add_peer(&pm, id)).collect();

    pm.handle_headers(1, chain.clone());
    assert_eq!(pm.chain_state.headers_tip_height(), 2000, "the batch was new");

    let asked = drain(&mut rx1).iter().filter(|m| matches!(m, NetworkMessage::GetHeaders(_))).count();
    assert_eq!(asked, 1, "the sending peer is asked for the next batch");
    for rx in &mut others {
        assert!(
            !drain(rx).iter().any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
            "no other peer is asked for headers on a batch"
        );
    }
}

/// The periodic IBD header probe goes out only once the header tip has stood
/// still for `HEADER_PROBE_STALL`, and at most once per that interval. While
/// a request chain advances the tip, or a slow peer's answer is still on its
/// way, a probe would only start a second chain fetching the same headers
/// (#1229).
#[test]
fn the_periodic_header_probe_waits_for_a_stall() {
    let (pm, _dir) = mk_pm();
    let chain = header_chain(2000, 1_500_000_000);
    let _rx = add_peer(&pm, 1);
    let t0 = Instant::now();
    let at = |secs: u64| t0 + Duration::from_secs(secs);

    assert!(!pm.ibd_header_probe_due_at(at(0)), "the first check records the tip");
    assert!(!pm.ibd_header_probe_due_at(at(2)), "a tip still for 2 s may be a request in flight");
    assert!(!pm.ibd_header_probe_due_at(at(9)), "still under the stall time");
    assert!(pm.ibd_header_probe_due_at(at(10)), "still for the stall time: a stall");
    assert!(!pm.ibd_header_probe_due_at(at(12)), "one probe per interval, however long the stall");
    assert!(pm.ibd_header_probe_due_at(at(20)), "the next interval");

    pm.handle_headers(1, chain[..1000].to_vec());
    assert!(!pm.ibd_header_probe_due_at(at(22)), "the tip moved: header sync is progressing");
    assert!(!pm.ibd_header_probe_due_at(at(31)), "still under the stall time since it moved");
    assert!(pm.ibd_header_probe_due_at(at(32)), "and then stopped");
}

fn getheaders_sent(rx: &mut mpsc::Receiver<NetworkMessage>) -> usize {
    drain(rx).iter().filter(|m| matches!(m, NetworkMessage::GetHeaders(_))).count()
}

fn add_inbound_peer(pm: &PeerManager, id: PeerId) -> mpsc::Receiver<NetworkMessage> {
    let rx = add_peer(pm, id);
    let mut peers = pm.peers.write();
    let info = &mut peers.get_mut(&id).unwrap().info;
    info.direction = Direction::Inbound;
    info.conn_type = ConnType::Inbound;
    rx
}

/// A node whose best header is more than a day old syncs headers with one
/// peer, as Core does, not with every peer it connects to: each one would
/// otherwise send the whole header chain.
#[test]
fn a_node_far_behind_syncs_headers_with_one_peer() {
    let (pm, _dir) = mk_pm();
    let mut rxs: Vec<_> = (1..=4).map(|id| add_peer(&pm, id)).collect();

    pm.start_header_syncs();
    let asked: usize = rxs.iter_mut().map(getheaders_sent).sum();
    assert_eq!(asked, 1, "one sync peer");

    pm.start_header_syncs();
    let asked: usize = rxs.iter_mut().map(getheaders_sent).sum();
    assert_eq!(asked, 0, "while it syncs, no other peer starts");
}

/// A sync peer that answers with less than a full batch has no more headers
/// past ours (a peer still syncing itself, say), so the next peer starts at
/// once rather than after the stall probe.
#[test]
fn the_next_peer_syncs_when_the_sync_peer_runs_out() {
    let (pm, _dir) = mk_pm();
    let chain = header_chain(100, 1_500_000_000);
    let mut rxs: Vec<_> = (1..=4).map(|id| add_peer(&pm, id)).collect();
    pm.start_header_syncs();
    let first = rxs.iter_mut().position(|rx| getheaders_sent(rx) == 1).expect("one sync peer") as PeerId + 1;

    pm.handle_headers(first, chain);
    assert_eq!(pm.chain_state.headers_tip_height(), 100);
    pm.start_header_syncs();
    let asked: Vec<usize> = rxs.iter_mut().map(getheaders_sent).collect();
    assert_eq!(asked.iter().sum::<usize>(), 1, "exactly one more peer: {asked:?}");
    assert_eq!(asked[first as usize - 1], 0, "not the peer that ran out");
}

/// Once the best header is less than a day old, header sync runs with every
/// peer (Core's `m_best_header->Time() > NodeClock::now() - 24h`).
#[test]
fn every_peer_syncs_once_the_best_header_is_recent() {
    let (pm, _dir) = mk_pm();
    let now = crate::time::now_secs() as u32;
    let chain = header_chain(100, now - 3_600);
    let mut rxs: Vec<_> = (1..=4).map(|id| add_peer(&pm, id)).collect();
    pm.start_header_syncs();
    let first = rxs.iter_mut().position(|rx| getheaders_sent(rx) == 1).expect("one sync peer") as PeerId + 1;

    pm.handle_headers(first, chain);
    pm.start_header_syncs();
    let asked: Vec<usize> = rxs.iter_mut().map(getheaders_sent).collect();
    let mut expected = vec![1; 4];
    expected[first as usize - 1] = 0;
    assert_eq!(asked, expected, "every other peer starts");
}

/// The one sync peer is an outbound one while there is one: Core's
/// `fPreferredDownload`. Inbound peers are anyone who connected to us.
#[test]
fn an_inbound_peer_is_not_the_sync_peer_while_an_outbound_one_can_be() {
    let (pm, _dir) = mk_pm();
    let mut inbound = add_inbound_peer(&pm, 1);
    let mut outbound = add_peer(&pm, 2);

    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut inbound), 0);
    assert_eq!(getheaders_sent(&mut outbound), 1);
}

/// A preferred peer that has synced and run out no longer holds back the
/// non-preferred ones: with only inbound peers left to ask, one starts at
/// once, not after the stall probe.
#[test]
fn an_inbound_peer_syncs_once_the_outbound_one_runs_out() {
    let (pm, _dir) = mk_pm();
    let mut inbound = add_inbound_peer(&pm, 1);
    let mut outbound = add_peer(&pm, 2);
    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut outbound), 1);

    pm.handle_headers(2, header_chain(100, 1_500_000_000));
    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut inbound), 1, "the inbound peer takes the slot");
}

/// An outbound peer still in its version handshake does not hold back a
/// connected inbound one: the handshake may run to its timeout.
#[test]
fn a_handshaking_outbound_peer_does_not_hold_back_an_inbound_one() {
    let (pm, _dir) = mk_pm();
    let mut inbound = add_inbound_peer(&pm, 1);
    let _handshaking = add_peer(&pm, 2);
    pm.peers.write().get_mut(&2).unwrap().info.state = PeerState::Connecting;
    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut inbound), 1);
}

/// A feeler connection is dropped once its handshake is done and never
/// syncs headers, so it cannot hold the slot.
#[test]
fn a_feeler_never_syncs_headers() {
    let (pm, _dir) = mk_pm();
    let mut feeler = add_peer(&pm, 1);
    pm.peers.write().get_mut(&1).unwrap().info.conn_type = ConnType::Feeler;
    let mut outbound = add_peer(&pm, 2);
    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut feeler), 0);
    assert_eq!(getheaders_sent(&mut outbound), 1);
    assert_ne!(pm.header_probe_peer(), Some(1), "nor does the stall probe ask it");
}

/// With only inbound peers, one of them syncs.
#[test]
fn an_inbound_peer_syncs_when_there_is_no_outbound_one() {
    let (pm, _dir) = mk_pm();
    let mut rxs: Vec<_> = (1..=2).map(|id| add_inbound_peer(&pm, id)).collect();
    pm.start_header_syncs();
    let asked: usize = rxs.iter_mut().map(getheaders_sent).sum();
    assert_eq!(asked, 1);
}

/// The stall probe asks a peer header sync has not started with, so a
/// stalled sync peer is replaced rather than asked again.
#[test]
fn the_stall_probe_asks_a_peer_not_yet_syncing() {
    let (pm, _dir) = mk_pm();
    let mut rxs: Vec<_> = (1..=3).map(|id| add_peer(&pm, id)).collect();
    pm.start_header_syncs();
    let first = rxs.iter_mut().position(|rx| getheaders_sent(rx) == 1).expect("one sync peer") as PeerId + 1;

    let probed = pm.header_probe_peer().expect("a peer to probe");
    assert_ne!(probed, first, "the stalled sync peer is not asked again");
    let again = pm.header_probe_peer().expect("a peer to probe");
    assert!(again != first && again != probed, "each probe moves on to a new peer");

    // Every peer has started now: the probe goes round them, not back to
    // the same one. The sync peer, never probed yet, comes first.
    assert_eq!(pm.header_probe_peer(), Some(first));
    let rounds: std::collections::HashSet<PeerId> =
        (0..3).map(|_| pm.header_probe_peer().expect("a peer to probe")).collect();
    assert_eq!(rounds.len(), 3, "three probes, three different peers: {rounds:?}");
}

/// Before header sync has started with a peer, a block `inv` from it brings
/// a `getheaders` once per peer and once per block across peers (Core's
/// `inv` handler), so a newly found block is not answered with a header-chain
/// download from every peer announcing it.
#[test]
fn a_block_inv_brings_one_getheaders_per_block_before_sync() {
    let (pm, _dir) = mk_pm();
    let mut sync_rx = add_peer(&pm, 1);
    pm.start_header_syncs();
    assert_eq!(getheaders_sent(&mut sync_rx), 1);
    let mut rx2 = add_peer(&pm, 2);
    let mut rx3 = add_peer(&pm, 3);
    let block_a = bitcoin::BlockHash::from_byte_array([0xa1; 32]);
    let block_b = bitcoin::BlockHash::from_byte_array([0xb2; 32]);

    pm.handle_inv(2, vec![Inventory::Block(block_a)]);
    assert_eq!(getheaders_sent(&mut rx2), 1, "the first announcer of a block is asked");
    pm.handle_inv(3, vec![Inventory::Block(block_a)]);
    assert_eq!(getheaders_sent(&mut rx3), 0, "the same block from another peer is not");
    pm.handle_inv(2, vec![Inventory::Block(block_b)]);
    assert_eq!(getheaders_sent(&mut rx2), 0, "once per peer before its sync starts");
    pm.handle_inv(3, vec![Inventory::Block(block_b)]);
    assert_eq!(getheaders_sent(&mut rx3), 1, "a new block from a new peer is");

    // The sync peer itself is asked on every new block (throttle aside).
    pm.handle_inv(1, vec![Inventory::Block(block_b)]);
    assert_eq!(getheaders_sent(&mut sync_rx), 1);
}

/// The IBD connector decides on BulkLoad from the gap to the best header,
/// not to its scheduler's target: a fresh node starts IBD on its first
/// `headers` batch, 2,000 blocks, which alone is under the BulkLoad
/// threshold however long the chain behind it is.
#[test]
fn the_catch_up_gap_runs_to_the_best_header() {
    let (pm, _dir) = mk_pm();
    let _rx = add_peer(&pm, 1);
    pm.handle_headers(1, header_chain(2000, 1_500_000_000));
    pm.handle_headers(1, header_chain(2100, 1_500_000_000)[2000..].to_vec());
    assert_eq!(pm.chain_state.headers_tip_height(), 2100);
    assert_eq!(PeerManager::ibd_catchup_gap(&pm.chain_state, 2000), 2100);
    assert_eq!(PeerManager::ibd_catchup_gap(&pm.chain_state, 2500), 2500, "a target past the headers counts");
}
