//! Core's per-message limits, the send-buffer bound on `getdata`, and the
//! BIP 157 request checks, against a live `PeerManager`.

use super::*;
use crate::net::flow::InFlight;
use crate::net::send_queue::{MAX_SEND_BUFFER_BYTES, queued_size};

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

/// A connected peer whose queue the test reads, `slots` messages deep.
fn add_peer(pm: &PeerManager, id: PeerId, addr: SocketAddr, slots: usize) -> mpsc::Receiver<NetworkMessage> {
    let mut info = PeerInfo::new(id, addr, Direction::Inbound);
    info.state = PeerState::Connected;
    let (tx, rx) = mpsc::channel::<NetworkMessage>(slots);
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

fn addr(last: u8) -> SocketAddr {
    SocketAddr::from(([10, 61, 0, last], 8333))
}

fn deliver(pm: &PeerManager, id: PeerId, msg: NetworkMessage) {
    pm.handle_message(id, msg, InFlight::adopt(None));
}

fn connected(pm: &PeerManager, id: PeerId) -> bool {
    pm.peers.read().contains_key(&id)
}

/// Mine `n` blocks of roughly `size` bytes each (the coinbase carries an
/// OP_RETURN of that size) and return their hashes in height order.
fn mine_big(pm: &PeerManager, n: usize, size: usize) -> Vec<bitcoin::BlockHash> {
    let mempool = Mempool::new(1_000_000, 0);
    (0..n)
        .map(|i| {
            let data = bitcoin::script::PushBytesBuf::try_from(vec![i as u8; size]).unwrap();
            let block = crate::mining::miner::build_block_to_script(
                &pm.chain_state,
                &mempool,
                bitcoin::ScriptBuf::new_op_return(&data),
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

// ---- Message count limits ----

/// Core's `MAX_INV_SZ`: an `inv` or `getdata` of more than 50,000 entries is
/// `Misbehaving` (`net_processing.cpp` INV / GETDATA). 50,000 is fine.
#[test]
fn inv_and_getdata_past_max_inv_sz_are_misbehaviour() {
    let (pm, _dir) = mk_pm();
    let entry = Inventory::Unknown { inv_type: 99, hash: [7u8; 32] };
    for (i, (make, name)) in [
        (NetworkMessage::Inv as fn(Vec<Inventory>) -> NetworkMessage, "inv"),
        (NetworkMessage::GetData as fn(Vec<Inventory>) -> NetworkMessage, "getdata"),
    ]
    .into_iter()
    .enumerate()
    {
        let (ok, over) = (2 * i as u8 + 1, 2 * i as u8 + 2);
        let _rx_ok = add_peer(&pm, ok.into(), addr(ok), 8);
        deliver(&pm, ok.into(), make(vec![entry; MAX_INV_PER_MSG]));
        assert!(connected(&pm, ok.into()), "{name} of {MAX_INV_PER_MSG} entries is allowed");

        let _rx_over = add_peer(&pm, over.into(), addr(over), 8);
        deliver(&pm, over.into(), make(vec![entry; MAX_INV_PER_MSG + 1]));
        assert!(!connected(&pm, over.into()), "{name} of {} entries disconnects", MAX_INV_PER_MSG + 1);
        assert!(pm.is_addr_banned(&addr(over)), "{name} past MAX_INV_SZ is misbehaviour");
    }
}

/// Core's `MAX_HEADERS_RESULTS`: a `headers` message of more than 2000 is
/// `Misbehaving`, before any header in it is looked at.
#[test]
fn headers_past_max_headers_results_are_misbehaviour() {
    let (pm, _dir) = mk_pm();
    let genesis = pm.chain_state.get_block_index(&pm.chain_state.tip_hash()).unwrap().header;

    let _rx = add_peer(&pm, 1, addr(1), 8);
    deliver(&pm, 1, NetworkMessage::Headers(vec![genesis; 2000]));
    assert!(connected(&pm, 1), "2000 headers are allowed");

    let _rx = add_peer(&pm, 2, addr(2), 8);
    deliver(&pm, 2, NetworkMessage::Headers(vec![genesis; 2001]));
    assert!(!connected(&pm, 2), "2001 headers disconnect");
    assert!(pm.is_addr_banned(&addr(2)), "2001 headers are misbehaviour");
}

/// Core's `MAX_ADDR_TO_SEND`: an `addr` or `addrv2` of more than 1000 entries
/// is `Misbehaving` (`ProcessAddrs`), and none of it is stored.
#[test]
fn addr_and_addrv2_past_max_addr_to_send_are_misbehaviour() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    let (pm, _dir) = mk_pm();
    let v1 = |n: usize| {
        NetworkMessage::Addr(
            (0..n)
                .map(|i| {
                    let a = SocketAddr::from(([44, 1, (i / 256) as u8, (i % 256) as u8], 8333));
                    (1_700_000_000, Address::new(&a, ServiceFlags::NETWORK))
                })
                .collect(),
        )
    };
    let v2 = |n: usize| {
        NetworkMessage::AddrV2(
            (0..n)
                .map(|i| AddrV2Message {
                    time: 1_700_000_000,
                    services: ServiceFlags::NETWORK,
                    addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(45, 1, (i / 256) as u8, (i % 256) as u8)),
                    port: 8333,
                })
                .collect(),
        )
    };
    for (i, make) in [&v1 as &dyn Fn(usize) -> NetworkMessage, &v2].into_iter().enumerate() {
        let (ok, over) = (2 * i as u8 + 1, 2 * i as u8 + 2);
        let _rx = add_peer(&pm, ok.into(), addr(ok), 8);
        deliver(&pm, ok.into(), make(1000));
        assert!(connected(&pm, ok.into()), "case {i}: 1000 addresses are allowed");

        let _rx = add_peer(&pm, over.into(), addr(over), 8);
        deliver(&pm, over.into(), make(1001));
        assert!(!connected(&pm, over.into()), "case {i}: 1001 addresses disconnect");
        assert!(pm.is_addr_banned(&addr(over)), "case {i}: 1001 addresses are misbehaviour");
    }
}

/// Core looks at a `notfound` only up to `MAX_PEER_TX_ANNOUNCEMENTS +
/// MAX_BLOCKS_IN_TRANSIT_PER_PEER` entries and ignores a longer one whole,
/// with no penalty. satd acts on the block entries of a `notfound` (it
/// releases those heights for another peer), so a longer one releases
/// nothing.
#[test]
fn notfound_past_the_limit_is_ignored() {
    use crate::net::limits::MAX_NOTFOUND_SZ;
    let (pm, _dir) = mk_pm();
    let hashes = mine_big(&pm, 4, 10);
    let filler = Inventory::Unknown { inv_type: 99, hash: [7u8; 32] };
    let notfound = |len: usize| {
        let mut inv: Vec<Inventory> = hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
        inv.resize(len, filler);
        NetworkMessage::NotFound(inv)
    };
    for (len, released) in [(MAX_NOTFOUND_SZ, true), (MAX_NOTFOUND_SZ + 1, false)] {
        let _rx = add_peer(&pm, 1, addr(1), 8);
        let mut sched = IbdScheduler::new(4, 0, &pm.chain_state, 1024);
        let assigned = sched.assign_blocks(1);
        assert_eq!(assigned.len(), 4, "every height in flight to peer 1");
        *pm.ibd.write() = Some(sched);

        deliver(&pm, 1, notfound(len));
        let ibd = pm.ibd.read();
        let still = (1..=4).filter(|h| ibd.as_ref().unwrap().in_flight_contains(*h)).count();
        assert_eq!(still == 0, released, "notfound of {len} entries: {still} heights still in flight");
        drop(ibd);
        assert!(connected(&pm, 1), "notfound of {len} entries is not misbehaviour");
        *pm.ibd.write() = None;
    }
}

// ---- getdata against the send buffer ----

/// Core stops serving a `getdata` once the bytes queued to the peer pass
/// `-maxsendbuffer` (`ProcessGetData` breaks on `fPauseSend`). satd read,
/// deserialized and queued every block asked for, so one request held a
/// peer's whole queue of blocks in memory.
#[test]
fn getdata_stops_serving_past_the_send_buffer() {
    let (pm, _dir) = mk_pm();
    let hashes = mine_big(&pm, 30, 100_000);
    let mut rx = add_peer(&pm, 1, addr(1), 256);

    pm.handle_getdata(1, hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect());
    let queued = drain(&mut rx);
    let bytes: usize = queued.iter().map(queued_size).sum();
    let largest = queued.iter().map(queued_size).max().unwrap_or(0);
    assert!(
        bytes <= MAX_SEND_BUFFER_BYTES + largest,
        "{} blocks, {bytes} bytes queued at once; the bound is {MAX_SEND_BUFFER_BYTES} plus one block",
        queued.len()
    );
    assert!(!queued.is_empty(), "the first blocks are served at once");
}

/// What the bound holds back is not lost: as the peer's queue drains, the
/// rest of the request is served, in the order asked, and the peer's next
/// message is read only once all of it has been. Each block is charged to
/// `-maxuploadtarget` once, as it is queued.
#[test]
fn getdata_resumes_as_the_queue_drains() {
    let (pm, _dir) = mk_pm();
    let hashes = mine_big(&pm, 30, 100_000);
    let mut rx = add_peer(&pm, 1, addr(1), 256);
    let queue = pm.peer_sender(1).unwrap().queue().clone();
    // A budget large enough never to refuse, so every block is counted.
    pm.set_max_upload_target(u64::MAX / 2);
    let charged_before = pm.upload_bytes.load(Ordering::Relaxed);

    // As the write loop hands the request over.
    queue.note_getdata_forwarded();
    deliver(&pm, 1, NetworkMessage::GetData(hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect()));
    assert!(queue.getdata_backlog() > 0, "the bound held part of the request back");
    assert!(queue.reading_paused(), "nothing more is read from the peer meanwhile");

    // The write loop, writing and asking for more.
    let mut served = Vec::new();
    let mut resumes = 0;
    while let Ok(msg) = rx.try_recv() {
        queue.sent(queued_size(&msg));
        match msg {
            NetworkMessage::Block(b) => served.push(b.block_hash()),
            other => panic!("unexpected {other:?}"),
        }
        if queue.take_resume() {
            resumes += 1;
            pm.resume_getdata(1);
        }
    }
    assert_eq!(served, hashes, "every block, in the order asked");
    assert!(resumes > 0);
    assert_eq!(queue.getdata_backlog(), 0);
    assert!(!queue.reading_paused(), "the peer is read again");
    assert_eq!(queue.queued_bytes(), 0);
    let charged: usize = served.iter().map(|h| pm.chain_state.get_block(h).unwrap().total_size()).sum();
    assert_eq!(pm.upload_bytes.load(Ordering::Relaxed) - charged_before, charged as u64);
}

/// A `MSG_CMPCT_BLOCK` entry whose `cmpctblock` could not be queued stays
/// first in the backlog, like every other entry, to be served once the
/// queue drains. It was popped as answered with nothing sent.
#[test]
fn a_compact_block_entry_that_cannot_be_queued_is_kept() {
    let (pm, _dir) = mk_pm();
    let chain = mine_big(&pm, 3, 10);
    let tip = *chain.last().unwrap();
    let mut rx = add_peer(&pm, 1, addr(1), 1);
    let sender = pm.peer_sender(1).unwrap();
    sender.try_send(NetworkMessage::Verack).unwrap();

    let mut not_found = Vec::new();
    assert!(
        !pm.serve_getdata_entry(1, &sender, Inventory::CompactBlock(tip), &mut not_found),
        "nothing could be queued, so the entry is not answered"
    );
    assert!(not_found.is_empty());

    assert_eq!(rx.try_recv().unwrap(), NetworkMessage::Verack);
    assert!(pm.serve_getdata_entry(1, &sender, Inventory::CompactBlock(tip), &mut not_found));
    match rx.try_recv() {
        Ok(NetworkMessage::CmpctBlock(c)) => assert_eq!(c.compact_block.header.block_hash(), tip),
        other => panic!("expected the cmpctblock, got {other:?}"),
    }
}

// ---- Peer text ----

/// Core keeps a peer's user agent only after `SanitizeString` (`cleanSubVer`)
/// and reports that in `getpeerinfo.subver`; satd logged and reported the raw
/// string, line breaks and escape sequences included.
#[test]
fn peer_user_agent_is_sanitized() {
    let mut info = PeerInfo::new(1, addr(1), Direction::Inbound);
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    info.set_version(VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&zero, ServiceFlags::NONE),
        sender: Address::new(&zero, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/Satoshi:27.0.0/\n2026-01-01T00:00:00Z INFO fake\x1b[0m".into(),
        start_height: 0,
        relay: true,
    });
    assert_eq!(info.user_agent, "/Satoshi:27.0.0/2026-01-01T00:00:00Z INFO fake0m");
}

/// Core reads the user agent as `LIMITED_STRING(strSubVer,
/// MAX_SUBVERSION_LENGTH)`. A longer one throws in deserialization, so the
/// `version` is dropped and the peer is left without a handshake until the
/// connect timeout; a later, well-formed `version` is accepted. satd took the
/// oversized one.
#[tokio::test]
async fn version_with_an_oversized_user_agent_is_ignored() {
    use crate::net::connection::Connection;
    use bitcoin::p2p::Magic;

    fn version(user_agent: String) -> NetworkMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        NetworkMessage::Version(VersionMessage {
            version: 70016,
            services,
            timestamp: crate::time::now_secs() as i64,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, services),
            nonce: 0x5eed,
            user_agent,
            start_height: 0,
            relay: true,
        })
    }

    let (pm, _dir) = mk_pm();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let (dialed, accepted) = tokio::join!(dialer, listener.accept());
    let (dialed, (accepted, peer_addr)) = (dialed.unwrap(), accepted.unwrap());
    let mut info = PeerInfo::new(1, peer_addr, Direction::Inbound);
    info.state = PeerState::Connecting;
    let (tx, _rx) = mpsc::channel::<NetworkMessage>(1);
    pm.peers.write().insert(
        1,
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
    let mut ours = Connection::with_magic(accepted, Magic::REGTEST);
    let mut theirs = Connection::with_magic(dialed, Magic::REGTEST);

    let handshake = pm.perform_handshake(1, &mut ours, Direction::Inbound, crate::time::now_secs());
    let remote = async {
        theirs.send(version("a".repeat(crate::MAX_SUBVERSION_LENGTH + 1))).await.unwrap();
        // An inbound node answers a `version` with its own. Nothing comes
        // back for the oversized one.
        let reply = tokio::time::timeout(Duration::from_millis(500), theirs.recv()).await;
        assert!(reply.is_err(), "an oversized user agent must not be answered, got {reply:?}");
        // A user agent of exactly the limit is fine, and completes the handshake.
        theirs.send(version("b".repeat(crate::MAX_SUBVERSION_LENGTH))).await.unwrap();
        loop {
            if matches!(theirs.recv().await.unwrap(), NetworkMessage::Verack) {
                break;
            }
        }
        theirs.send(NetworkMessage::Verack).await.unwrap();
    };
    let (handshake, ()) = tokio::join!(handshake, remote);
    let theirs_version = handshake.expect("the well-formed version completes the handshake");
    assert_eq!(theirs_version.user_agent.len(), crate::MAX_SUBVERSION_LENGTH);
}

// ---- BIP 157 requests (Core's `PrepareBlockFilterRequest`) ----

#[cfg(feature = "block-filter-index")]
mod bip157 {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};
    use node_filter_index::{FilterIndex, IndexError};

    /// A complete index of empty filters.
    struct EmptyFilters;

    impl FilterIndex for EmptyFilters {
        fn filter_at(&self, _: u8, _: u32) -> Result<Vec<u8>, IndexError> {
            Ok(Vec::new())
        }
        fn header_at(&self, _: u8, _: u32) -> Result<[u8; 32], IndexError> {
            Ok([0u8; 32])
        }
        fn headers_range(&self, _: u8, _: u32, _: u32) -> Result<Vec<[u8; 32]>, IndexError> {
            Ok(Vec::new())
        }
        fn checkpoints_to(&self, _: u8, _: u32) -> Result<Vec<[u8; 32]>, IndexError> {
            Ok(Vec::new())
        }
        fn is_complete(&self) -> bool {
            true
        }
    }

    fn serving_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
        let (pm, dir) = mk_pm();
        pm.set_filter_index(Arc::new(EmptyFilters), true);
        (pm, dir)
    }

    fn cfheaders(start_height: u32, stop_hash: bitcoin::BlockHash) -> NetworkMessage {
        NetworkMessage::GetCFHeaders(GetCFHeaders { filter_type: 0, start_height, stop_hash })
    }

    /// The request is answered and the peer kept: the must-succeed half of
    /// every refusal below.
    #[test]
    fn a_valid_request_is_served() {
        let (pm, _dir) = serving_pm();
        let chain = mine_big(&pm, 5, 10);
        let mut rx = add_peer(&pm, 1, addr(1), 8);
        deliver(&pm, 1, cfheaders(1, chain[4]));
        assert!(connected(&pm, 1));
        match rx.try_recv() {
            Ok(NetworkMessage::CFHeaders(h)) => assert_eq!(h.filter_hashes.len(), 5),
            other => panic!("expected cfheaders, got {other:?}"),
        }
        deliver(&pm, 1, NetworkMessage::GetCFCheckpt(GetCFCheckpt { filter_type: 0, stop_hash: chain[4] }));
        assert!(matches!(rx.try_recv(), Ok(NetworkMessage::CFCheckpt(_))));
        assert!(connected(&pm, 1));
    }

    /// Core disconnects (`fDisconnect`, no misbehaviour) a request satd cannot
    /// answer as asked: a filter type it does not serve, a stop hash it does
    /// not know or would not serve, a start above the stop, or a range over
    /// the message's limit. satd ignored every one of them.
    #[test]
    fn bad_requests_disconnect() {
        let (pm, _dir) = serving_pm();
        let chain = mine_big(&pm, 5, 10);
        let unknown = bitcoin::BlockHash::from_byte_array([0xab; 32]);
        let cases: Vec<(&str, NetworkMessage)> = vec![
            (
                "unsupported filter type",
                NetworkMessage::GetCFilters(GetCFilters { filter_type: 0x99, start_height: 0, stop_hash: chain[4] }),
            ),
            ("unknown stop hash", cfheaders(0, unknown)),
            ("start above stop", cfheaders(5, chain[3])),
            (
                "unsupported filter type, getcfcheckpt",
                NetworkMessage::GetCFCheckpt(GetCFCheckpt { filter_type: 1, stop_hash: chain[4] }),
            ),
            ("unknown stop hash, getcfcheckpt", NetworkMessage::GetCFCheckpt(GetCFCheckpt { filter_type: 0, stop_hash: unknown })),
        ];
        for (i, (case, msg)) in cases.into_iter().enumerate() {
            let id = 10 + i as PeerId;
            let mut rx = add_peer(&pm, id, addr(10 + i as u8), 8);
            deliver(&pm, id, msg);
            assert!(!connected(&pm, id), "{case}: the peer is disconnected");
            assert!(!pm.is_addr_banned(&addr(10 + i as u8)), "{case}: disconnected, not banned");
            assert!(rx.try_recv().is_err(), "{case}: nothing is served");
        }
    }

    /// A node that does not serve filters disconnects a peer that asks for
    /// them: Core's "peer requested unsupported block filter type" when
    /// `NODE_COMPACT_FILTERS` is not among the services it offered.
    #[test]
    fn a_request_to_a_node_not_serving_filters_disconnects() {
        let (pm, _dir) = mk_pm();
        let chain = mine_big(&pm, 2, 10);
        let _rx = add_peer(&pm, 1, addr(1), 8);
        deliver(&pm, 1, cfheaders(0, chain[1]));
        assert!(!connected(&pm, 1));
    }

    /// The range limits: 1000 heights for `getcfilters`, 2000 for
    /// `getcfheaders` (Core's `MAX_GETCFILTERS_SIZE`, `MAX_GETCFHEADERS_SIZE`).
    #[tokio::test]
    async fn a_range_past_the_limit_disconnects() {
        let (pm, _dir) = serving_pm();
        let chain = mine_big(&pm, 1001, 1);
        let _rx = add_peer(&pm, 1, addr(1), 2048);
        deliver(&pm, 1, NetworkMessage::GetCFilters(GetCFilters { filter_type: 0, start_height: 2, stop_hash: chain[1000] }));
        assert!(connected(&pm, 1), "1000 filters are allowed");
        let _rx = add_peer(&pm, 2, addr(2), 8);
        deliver(&pm, 2, NetworkMessage::GetCFilters(GetCFilters { filter_type: 0, start_height: 1, stop_hash: chain[1000] }));
        assert!(!connected(&pm, 2), "1001 filters disconnect");
    }

    /// A stop hash off the active chain: Core serves one it would relay (a
    /// block it validated, no more than a month older than the best header,
    /// `BlockRequestAllowed`) and disconnects for anything else. satd keeps
    /// filters for the active chain only, so it cannot serve the first kind;
    /// it ignores the request and keeps the peer. A header it has not
    /// validated is the second kind.
    #[test]
    fn an_off_chain_stop_hash() {
        let (pm, _dir) = serving_pm();
        let chain = mine_big(&pm, 3, 10);
        // A heavier branch from height 2, built on a second node and handed
        // over, so the block at height 3 is connected and then reorged out:
        // validated, and stale.
        let (other, _other_dir) = mk_pm();
        for h in &chain[..2] {
            other.chain_state.accept_block(&pm.chain_state.get_block(h).unwrap()).unwrap();
        }
        let branch = mine_big(&other, 2, 12);
        for h in &branch {
            pm.chain_state.accept_block(&other.chain_state.get_block(h).unwrap()).unwrap();
        }
        assert_eq!(pm.chain_state.tip_hash(), branch[1], "the heavier branch is active");
        let stale = pm.chain_state.get_block_index(&chain[2]).unwrap();
        assert_eq!(stale.status, crate::storage::blockindex::BlockStatus::Valid);

        let mut rx = add_peer(&pm, 1, addr(1), 8);
        deliver(&pm, 1, cfheaders(1, chain[2]));
        assert!(connected(&pm, 1), "a recent, validated stale block is not grounds to disconnect");
        assert!(rx.try_recv().is_err(), "but satd has no filter for it");

        // A header with no block behind it.
        let tip = pm.chain_state.tip_hash();
        let mut header = pm.chain_state.get_block_index(&tip).unwrap().header;
        header.prev_blockhash = tip;
        header.time += 1;
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        pm.chain_state.accept_headers(&[header]).1.map_or(Ok(()), Err).expect("header accepted");
        let _rx = add_peer(&pm, 2, addr(2), 8);
        deliver(&pm, 2, cfheaders(0, header.block_hash()));
        assert!(!connected(&pm, 2), "a header satd never validated is not a block it would serve");
    }
}

// ---- The write loop ----

/// A connected socket pair whose far end the test controls, and the near
/// end's halves with counters attached.
async fn socket_pair() -> (
    crate::net::connection::ConnectionReader,
    ConnectionWriter,
    tokio::net::TcpStream,
    Arc<PeerStats>,
) {
    use crate::net::connection::Connection;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (dialed, accepted) =
        tokio::join!(tokio::net::TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
    let (far, _) = accepted.unwrap();
    let conn = Connection::with_magic(dialed.unwrap(), bitcoin::p2p::Magic::REGTEST);
    let (reader, mut writer) = conn.split();
    let stats = PeerStats::new(NetTotals::new());
    writer.set_counters(stats.clone());
    (reader, writer, far, stats)
}

fn big(len: usize) -> NetworkMessage {
    NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from_static("bigmsg").unwrap(),
        payload: vec![0x5a; len],
    }
}

/// Everything a write loop needs, for a peer whose far end the test holds.
struct Loop {
    id: PeerId,
    event_rx: mpsc::Receiver<NetEvent>,
    msg_tx: crate::net::send_queue::PeerSender,
    read_tx: mpsc::Sender<NetworkMessage>,
    disconnect: Arc<tokio::sync::Notify>,
    /// The manager's drain wake-up.
    drain_now: Arc<tokio::sync::Notify>,
    stats: Arc<PeerStats>,
    far: tokio::net::TcpStream,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

async fn run_loop() -> Loop {
    let (_reader, mut writer, far, stats) = socket_pair().await;
    let (event_tx, event_rx) = mpsc::channel(64);
    let (msg_tx, mut msg_rx) = mpsc::channel::<NetworkMessage>(256);
    let msg_tx = crate::net::send_queue::PeerSender::from(msg_tx);
    let (read_tx, mut read_rx) = mpsc::channel::<NetworkMessage>(64);
    let disconnect = Arc::new(tokio::sync::Notify::new());
    let drain_now = Arc::new(tokio::sync::Notify::new());
    let queue = msg_tx.queue().clone();
    let (s, d, w) = (stats.clone(), disconnect.clone(), drain_now.clone());
    let task = tokio::spawn(async move {
        let _keep = _reader;
        PeerManager::peer_write_loop(
            7,
            &event_tx,
            &mut writer,
            &mut msg_rx,
            &mut read_rx,
            Some(s),
            Some(Arc::new(crate::net::flow::PeerFlow::new())),
            Some(w),
            Some(d),
            Some(queue),
        )
        .await
    });
    Loop { id: 7, event_rx, msg_tx, read_tx, disconnect, drain_now, stats, far, task }
}

/// Queue big messages until the socket stops taking bytes: the far end is
/// not reading and the write loop is parked in a write.
async fn park(l: &Loop) {
    // More than loopback socket buffers hold.
    for _ in 0..8 {
        l.msg_tx.try_send(big(3_900_000)).unwrap();
    }
    let mut last = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = l.stats.bytes_sent();
        if now == last && now > 0 {
            return;
        }
        last = now;
    }
}

/// `disconnectnode`, a ban and the ping timeout all reach the write loop
/// through the disconnect signal, which it only looked at between writes. A
/// peer that stopped reading kept the loop parked in a write, so the socket
/// and everything queued to it outlived the disconnect.
#[tokio::test]
async fn a_parked_write_ends_on_disconnect() {
    let l = run_loop().await;
    park(&l).await;
    l.disconnect.notify_one();
    let ended = tokio::time::timeout(Duration::from_secs(5), l.task)
        .await
        .expect("the write loop ends while its write is parked")
        .unwrap();
    assert_eq!(ended, Err("disconnected by manager".to_string()));
    drop(l.far);
}

/// Core drops a peer whose socket has taken nothing for `TIMEOUT_INTERVAL`
/// (20 minutes; `InactivityCheck`, "socket sending timeout"). A slow reader
/// is not a stalled one: the clock restarts whenever the socket takes bytes.
#[tokio::test(start_paused = true)]
async fn a_write_that_makes_no_progress_times_out() {
    use crate::net::send_queue::SEND_TIMEOUT;
    let l = run_loop().await;
    park(&l).await;
    let parked_at = tokio::time::Instant::now();
    let ended = tokio::time::timeout(SEND_TIMEOUT * 2, l.task)
        .await
        .expect("a write with no progress ends")
        .unwrap();
    let waited = parked_at.elapsed();
    let err = ended.expect_err("the loop ends with an error");
    assert!(err.contains("sending timeout"), "{err}");
    assert!(
        waited >= SEND_TIMEOUT - Duration::from_secs(60) && waited <= SEND_TIMEOUT + Duration::from_secs(60),
        "dropped after {waited:?}"
    );
    drop(l.far);
}

/// Core takes no further message from a peer while a `getdata` of its is
/// being served (`ProcessMessages`). The loop hands the manager the
/// `getdata` and then reads nothing until the manager has taken it in and
/// served all of it.
#[tokio::test]
async fn reading_waits_for_a_getdata_to_be_served() {
    let mut l = run_loop().await;
    let queue = l.msg_tx.queue().clone();
    l.read_tx.send(NetworkMessage::GetData(vec![])).await.unwrap();
    l.read_tx.send(NetworkMessage::SendHeaders).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), l.event_rx.recv()).await.unwrap();
    assert!(matches!(first, Some(NetEvent::MessageReceived { msg: NetworkMessage::GetData(_), .. })));
    tokio::time::timeout(Duration::from_secs(1), l.drain_now.notified())
        .await
        .expect("the manager is woken to serve the getdata, not left to its next tick");
    let early = tokio::time::timeout(Duration::from_millis(300), l.event_rx.recv()).await;
    assert!(early.is_err(), "nothing after the getdata is read before it is served");

    // Taken in with one entry still to serve: still waiting.
    queue.push_getdata(vec![Inventory::Unknown { inv_type: 99, hash: [1; 32] }]);
    queue.note_getdata_handled();
    let early = tokio::time::timeout(Duration::from_millis(300), l.event_rx.recv()).await;
    assert!(early.is_err(), "an unserved entry still holds the peer's next message");

    queue.pop_getdata();
    queue.wake_reader();
    let next = tokio::time::timeout(Duration::from_secs(5), l.event_rx.recv()).await.unwrap();
    assert!(matches!(next, Some(NetEvent::MessageReceived { msg: NetworkMessage::SendHeaders, .. })));
    l.disconnect.notify_one();
    let _ = l.task.await;
}

/// The loop asks the manager to serve more of a `getdata` backlog once the
/// queue is back under the send buffer, and holds the peer's messages while
/// it is over.
#[tokio::test]
async fn the_loop_asks_for_more_once_the_queue_drains() {
    use tokio::io::AsyncReadExt;
    let mut l = run_loop().await;
    let queue = l.msg_tx.queue().clone();
    queue.push_getdata(vec![Inventory::Unknown { inv_type: 99, hash: [1; 32] }]);
    // Over the buffer: two messages of 600 kB.
    l.msg_tx.try_send(big(600_000)).unwrap();
    l.msg_tx.try_send(big(600_000)).unwrap();
    // Let the far end read, so the queue drains.
    let mut far = l.far;
    let reader = tokio::spawn(async move {
        let mut sink = vec![0u8; 1 << 16];
        while far.read(&mut sink).await.is_ok_and(|n| n > 0) {}
    });
    let ev = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match l.event_rx.recv().await {
                Some(NetEvent::GetDataResume { id }) => return id,
                Some(_) => continue,
                None => panic!("the loop ended"),
            }
        }
    })
    .await
    .expect("a resume is asked for");
    assert_eq!(ev, l.id);
    tokio::time::timeout(Duration::from_secs(1), l.drain_now.notified())
        .await
        .expect("the manager is woken to serve it");
    assert_eq!(queue.queued_bytes(), 0);
    l.disconnect.notify_one();
    let _ = l.task.await;
    reader.abort();
}
