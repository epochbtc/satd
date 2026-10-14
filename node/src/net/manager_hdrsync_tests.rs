//! Header sync continuation: after a full `headers` batch, the next
//! `getheaders` to that peer starts from the last header it sent, as Core's
//! `ProcessHeadersMessage` does (`MaybeSendGetHeaders(pfrom,
//! GetLocator(pindexLast))`), whether or not the batch held new headers.

use super::*;
use bitcoin::hashes::Hash as _;

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
            last_mempool_served: None,
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
