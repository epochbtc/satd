//! Transaction download scheduling against a live `PeerManager`: an
//! announced transaction is requested from one peer at a time, as Core's
//! `TxRequestTracker` does (`src/txrequest.h`), and the next announcer is
//! asked on expiry, `notfound` or disconnect. Before, every announcer was
//! sent a `getdata` at once, so a transaction announced by k peers was
//! downloaded k times.
//!
//! These tests move the node clock with the `setmocktime` mock, as Core's
//! `p2p_tx_download.py` does.

use super::*;
use crate::net::txrequest::{
    GETDATA_TX_INTERVAL, MAX_PEER_TX_ANNOUNCEMENTS, MAX_PEER_TX_REQUEST_IN_FLIGHT, NONPREF_PEER_TX_DELAY,
    OVERLOADED_PEER_TX_DELAY, TXID_RELAY_DELAY,
};

const SECOND: u64 = 1_000_000;

/// Holds the mock clock for one test and clears it on the way out.
pub(super) struct MockClock {
    now: u64,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl MockClock {
    pub(super) fn install() -> Self {
        let lock = crate::time::CLOCK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let now = crate::time::now_secs();
        crate::time::set_mock_time(Some(now));
        Self { now, _lock: lock }
    }

    /// Move the clock forward by `micros`, which must be whole seconds: the
    /// mock clock, like Core's, counts seconds.
    pub(super) fn advance(&mut self, micros: u64) {
        assert_eq!(micros % SECOND, 0);
        self.now += micros / SECOND;
        crate::time::set_mock_time(Some(self.now));
    }
}

impl Drop for MockClock {
    fn drop(&mut self) {
        crate::time::set_mock_time(None);
    }
}

/// A manager out of IBD: no transaction is fetched in IBD, and a test that
/// sees no `getdata` there proves nothing.
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(shutdown_tx);
    let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
    let tip = pm.chain_state.tip_hash();
    let block = crate::chain::state::tests::build_test_block(tip, 1, crate::time::now_secs() as u32);
    pm.chain_state.accept_block(&block).expect("block connects");
    assert!(!pm.is_ibd());
    (pm, dir)
}

/// A connected peer that relays by wtxid and serves blocks. Outbound is a
/// preferred announcer (Core's `fPreferredDownload`); inbound is not.
pub(super) fn add_peer(pm: &PeerManager, id: PeerId, direction: Direction) -> mpsc::Receiver<NetworkMessage> {
    add_peer_with(pm, id, direction, |_| {})
}

pub(super) fn add_peer_with(
    pm: &PeerManager,
    id: PeerId,
    direction: Direction,
    tweak: impl FnOnce(&mut PeerInfo),
) -> mpsc::Receiver<NetworkMessage> {
    add_peer_cap(pm, id, direction, 64, tweak)
}

/// [`add_peer_with`] with a send queue of `capacity` messages.
fn add_peer_cap(
    pm: &PeerManager,
    id: PeerId,
    direction: Direction,
    capacity: usize,
    tweak: impl FnOnce(&mut PeerInfo),
) -> mpsc::Receiver<NetworkMessage> {
    let addr: SocketAddr = format!("10.0.0.{id}:8333").parse().unwrap();
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = PeerState::Connected;
    info.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    info.wtxid_relay = true;
    tweak(&mut info);
    let (tx, rx) = mpsc::channel::<NetworkMessage>(capacity);
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

/// Every transaction entry of every `getdata` the peer was sent so far.
fn tx_getdata(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<Inventory> {
    let mut out = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        if let NetworkMessage::GetData(inv) = msg {
            out.extend(inv.into_iter().filter(|i| {
                matches!(i, Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_))
            }));
        }
    }
    out
}

fn wtxid(n: u32) -> bitcoin::Wtxid {
    let mut h = [0u8; 32];
    h[..4].copy_from_slice(&n.to_le_bytes());
    h[31] = 0x5a;
    bitcoin::Wtxid::from_byte_array(h)
}

/// A transaction with a witness spending an output nobody has: an orphan.
fn orphan_tx(seed: u8) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([seed; 32]), vout: 0 },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&[vec![0xaa]]),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: bitcoin::ScriptBuf::new_op_return([seed]),
        }],
    }
}

fn notfound(pm: &PeerManager, id: PeerId, inv: Vec<Inventory>) {
    pm.handle_message(id, NetworkMessage::NotFound(inv), crate::net::flow::InFlight::new(None));
}

/// Two preferred peers announce the same transaction: one `getdata` goes
/// out. The second peer is asked only once the first request expires, and
/// not a second earlier.
#[test]
fn a_second_announcer_is_asked_only_after_the_first_request_expires() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Outbound);
    let mut rx2 = add_peer(&pm, 2, Direction::Outbound);
    let w = wtxid(1);

    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    pm.handle_inv(2, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut rx1), vec![Inventory::WTx(w)], "the first announcer is asked");
    assert!(tx_getdata(&mut rx2).is_empty(), "and only the first: the request is in flight");

    clock.advance(GETDATA_TX_INTERVAL - SECOND);
    pm.send_all_tx_requests();
    assert!(tx_getdata(&mut rx2).is_empty(), "not before the request expires");

    clock.advance(SECOND);
    pm.send_all_tx_requests();
    assert_eq!(tx_getdata(&mut rx2), vec![Inventory::WTx(w)], "the second announcer, on expiry");
    assert!(tx_getdata(&mut rx1).is_empty(), "the first is never asked again");
}

/// A `notfound` from the asked peer hands the transaction to the next
/// announcer at once; a spurious `notfound` changes nothing.
#[test]
fn notfound_asks_the_next_announcer_at_once() {
    let _clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Outbound);
    let mut rx2 = add_peer(&pm, 2, Direction::Outbound);
    let w = wtxid(2);
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    pm.handle_inv(2, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut rx1).len(), 1);

    // A `notfound` for something never announced or asked is ignored.
    // (One for a transaction the peer itself announced retires that
    // announcement, as Core's `ReceivedResponse` does for a candidate.)
    notfound(&pm, 2, vec![Inventory::WTx(wtxid(0x99))]);
    notfound(&pm, 3, vec![Inventory::WTx(w)]);
    assert!(tx_getdata(&mut rx2).is_empty(), "a spurious notfound is ignored");
    notfound(&pm, 1, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut rx2), vec![Inventory::WTx(w)]);
}

/// The asked peer disconnecting hands the transaction to the next announcer
/// at once.
#[test]
fn a_disconnect_asks_the_next_announcer_at_once() {
    let _clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Outbound);
    let mut rx2 = add_peer(&pm, 2, Direction::Outbound);
    let w = wtxid(3);
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    pm.handle_inv(2, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut rx1).len(), 1);
    assert!(tx_getdata(&mut rx2).is_empty());

    pm.handle_peer_disconnected(1);
    assert_eq!(tx_getdata(&mut rx2), vec![Inventory::WTx(w)]);
}

/// An inbound (non-preferred) announcer is asked only after
/// `NONPREF_PEER_TX_DELAY`. An outbound announcer arriving inside that
/// window is asked at once, and the inbound one is then not asked at all.
#[test]
fn an_inbound_announcer_waits_and_an_outbound_one_inside_the_window_wins() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut inbound = add_peer(&pm, 1, Direction::Inbound);
    let w = wtxid(4);
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    assert!(tx_getdata(&mut inbound).is_empty(), "inbound: not at once");

    clock.advance(SECOND);
    let mut outbound = add_peer(&pm, 2, Direction::Outbound);
    pm.handle_inv(2, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut outbound), vec![Inventory::WTx(w)], "outbound: at once");

    clock.advance(NONPREF_PEER_TX_DELAY);
    pm.send_all_tx_requests();
    assert!(tx_getdata(&mut inbound).is_empty(), "the outbound peer's request is in flight");

    // Alone, an inbound announcer is asked exactly at its delay.
    let w2 = wtxid(5);
    pm.handle_inv(1, vec![Inventory::WTx(w2)]);
    clock.advance(NONPREF_PEER_TX_DELAY - SECOND);
    pm.send_all_tx_requests();
    assert!(tx_getdata(&mut inbound).is_empty());
    clock.advance(SECOND);
    pm.send_all_tx_requests();
    assert_eq!(tx_getdata(&mut inbound), vec![Inventory::WTx(w2)]);
}

/// A `noban` inbound peer is preferred, as in Core.
#[test]
fn a_noban_inbound_announcer_is_asked_at_once() {
    let _clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx = add_peer_with(&pm, 1, Direction::Inbound, |i| i.permissions.noban = true);
    pm.handle_inv(1, vec![Inventory::WTx(wtxid(6))]);
    assert_eq!(tx_getdata(&mut rx).len(), 1);
}

/// A txid announcement waits `TXID_RELAY_DELAY` while some peer relays by
/// wtxid, and not otherwise.
#[test]
fn a_txid_announcement_waits_while_a_wtxid_peer_is_connected() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx = add_peer_with(&pm, 1, Direction::Outbound, |i| i.wtxid_relay = false);
    let t1 = bitcoin::Txid::from_byte_array([0x11; 32]);
    pm.handle_inv(1, vec![Inventory::Transaction(t1)]);
    assert_eq!(tx_getdata(&mut rx), vec![Inventory::WitnessTransaction(t1)], "no wtxid peer: no delay");

    let _rx2 = add_peer(&pm, 2, Direction::Outbound);
    let t2 = bitcoin::Txid::from_byte_array([0x12; 32]);
    pm.handle_inv(1, vec![Inventory::Transaction(t2)]);
    assert!(tx_getdata(&mut rx).is_empty());
    clock.advance(TXID_RELAY_DELAY);
    pm.send_all_tx_requests();
    assert_eq!(tx_getdata(&mut rx), vec![Inventory::WitnessTransaction(t2)]);
}

/// A peer's announcements beyond `MAX_PEER_TX_ANNOUNCEMENTS` are ignored,
/// unless it holds the `relay` permission.
#[test]
fn announcements_beyond_the_per_peer_cap_are_ignored_without_relay_permission() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut plain = add_peer(&pm, 1, Direction::Inbound);
    let mut relay = add_peer_with(&pm, 2, Direction::Inbound, |i| i.permissions.relay = true);
    let inv: Vec<Inventory> = (0..=MAX_PEER_TX_ANNOUNCEMENTS as u32).map(|n| Inventory::WTx(wtxid(n))).collect();
    pm.handle_inv(1, inv.clone());
    // The relay peer's are other transactions, so peer 1's requests do not
    // stand in their way.
    let inv2: Vec<Inventory> =
        (0..=MAX_PEER_TX_ANNOUNCEMENTS as u32).map(|n| Inventory::WTx(wtxid(n + 1_000_000))).collect();
    pm.handle_inv(2, inv2);
    clock.advance(NONPREF_PEER_TX_DELAY);
    pm.send_all_tx_requests();
    let got = tx_getdata(&mut plain);
    assert_eq!(got.len(), MAX_PEER_TX_ANNOUNCEMENTS);
    assert_eq!(got[..], inv[..MAX_PEER_TX_ANNOUNCEMENTS], "the first 5000, in announcement order");
    assert_eq!(tx_getdata(&mut relay).len(), MAX_PEER_TX_ANNOUNCEMENTS + 1);
}

/// A peer with `MAX_PEER_TX_REQUEST_IN_FLIGHT` requests outstanding has its
/// further announcements delayed by `OVERLOADED_PEER_TX_DELAY`.
#[test]
fn an_overloaded_peer_s_announcements_are_delayed() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx = add_peer(&pm, 1, Direction::Outbound);
    let inv: Vec<Inventory> = (0..MAX_PEER_TX_REQUEST_IN_FLIGHT as u32).map(|n| Inventory::WTx(wtxid(n))).collect();
    pm.handle_inv(1, inv);
    assert_eq!(tx_getdata(&mut rx).len(), MAX_PEER_TX_REQUEST_IN_FLIGHT);

    let extra = wtxid(9_999);
    pm.handle_inv(1, vec![Inventory::WTx(extra)]);
    assert!(tx_getdata(&mut rx).is_empty(), "overloaded: not at once");
    clock.advance(OVERLOADED_PEER_TX_DELAY - SECOND);
    pm.send_all_tx_requests();
    assert!(tx_getdata(&mut rx).is_empty());
    clock.advance(SECOND);
    pm.send_all_tx_requests();
    assert_eq!(tx_getdata(&mut rx), vec![Inventory::WTx(extra)]);
}

/// Receiving the transaction forgets every other announcement of it: here
/// an orphan, which is kept and its parent fetched instead, and a refused
/// transaction. The other announcer is never asked, even after the request
/// would have expired.
#[test]
fn receiving_the_transaction_forgets_the_other_announcers() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Outbound);
    let mut rx2 = add_peer(&pm, 2, Direction::Outbound);

    let orphan = orphan_tx(0x41);
    let w = orphan.compute_wtxid();
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    pm.handle_inv(2, vec![Inventory::WTx(w)]);
    assert_eq!(tx_getdata(&mut rx1), vec![Inventory::WTx(w)]);
    pm.handle_tx(1, orphan.clone());
    assert!(pm.orphanage.contains(&orphan.compute_txid()));

    // The duplicate-inputs transaction is refused outright, and its txid is
    // its wtxid.
    let mut bad = orphan_tx(0x42);
    bad.input[0].witness = bitcoin::Witness::new();
    bad.input.push(bad.input[0].clone());
    let bad_txid = bad.compute_txid();
    pm.handle_inv(1, vec![Inventory::WTx(bad.compute_wtxid())]);
    pm.handle_inv(2, vec![Inventory::WTx(bad.compute_wtxid())]);
    assert_eq!(tx_getdata(&mut rx1), vec![Inventory::WTx(bad.compute_wtxid())]);
    pm.handle_tx(1, bad);

    let bad_wtxid = bitcoin::Wtxid::from_byte_array(bad_txid.to_byte_array());
    // Step past the delays and twice past the request expiry. Only the
    // orphan's missing parent may be asked for: both peers announced the
    // orphan, so both are candidates for its parent.
    let parent = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([0x41; 32]));
    for step in [TXID_RELAY_DELAY, GETDATA_TX_INTERVAL, GETDATA_TX_INTERVAL] {
        clock.advance(step);
        pm.send_all_tx_requests();
        for got in tx_getdata(&mut rx1).into_iter().chain(tx_getdata(&mut rx2)) {
            assert_eq!(got, parent, "nobody is asked again for a transaction we received");
        }
    }
    for hash in [w.to_byte_array(), bad_wtxid.to_byte_array()] {
        assert!(pm.tx_requests.lock().candidate_peers(&hash).is_empty());
    }
}

/// An orphan's missing parent is asked of its sender, and of every other
/// announcer of the orphan, one at a time, after `TXID_RELAY_DELAY` (the
/// parent goes by txid while wtxid peers are connected), as Core's
/// `MaybeAddOrphanResolutionCandidate`.
#[test]
fn an_orphan_s_parent_is_requested_once_through_the_scheduler() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Outbound);
    let mut rx2 = add_peer(&pm, 2, Direction::Outbound);
    let orphan = orphan_tx(0x51);
    let parent = bitcoin::Txid::from_byte_array([0x51; 32]);
    pm.handle_inv(1, vec![Inventory::WTx(orphan.compute_wtxid())]);
    pm.handle_inv(2, vec![Inventory::WTx(orphan.compute_wtxid())]);
    assert_eq!(tx_getdata(&mut rx1).len(), 1);
    pm.handle_tx(1, orphan);
    assert!(tx_getdata(&mut rx1).is_empty(), "the parent waits TXID_RELAY_DELAY");

    clock.advance(TXID_RELAY_DELAY);
    pm.send_all_tx_requests();
    let asked1 = tx_getdata(&mut rx1);
    let asked2 = tx_getdata(&mut rx2);
    assert_eq!(asked1.len() + asked2.len(), 1, "one request for the parent: {asked1:?} {asked2:?}");
    // The other announcer is the fallback.
    notfound(&pm, if asked1.is_empty() { 2 } else { 1 }, vec![Inventory::WitnessTransaction(parent)]);
    let fallback = if asked1.is_empty() { tx_getdata(&mut rx1) } else { tx_getdata(&mut rx2) };
    assert_eq!(fallback, vec![Inventory::WitnessTransaction(parent)]);
}

/// A transaction that confirms is forgotten: nobody is asked for it.
#[test]
fn a_confirmed_transaction_is_not_requested() {
    let mut clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx1 = add_peer(&pm, 1, Direction::Inbound);
    let tip = pm.chain_state.tip_hash();
    let block = crate::chain::state::tests::build_test_block(tip, 2, crate::time::now_secs() as u32 + 1);
    let coinbase = &block.txdata[0];
    pm.handle_inv(1, vec![Inventory::WTx(coinbase.compute_wtxid())]);
    pm.forget_tx_requests_for_block(&block);
    clock.advance(NONPREF_PEER_TX_DELAY);
    pm.send_all_tx_requests();
    assert!(tx_getdata(&mut rx1).is_empty());
}

/// A `getdata` the peer's full send queue refused is not a request: the
/// transaction stays this peer's to ask, and goes out on the next pass
/// once the queue drains, without waiting out the 60 s expiry.
#[test]
fn a_getdata_that_could_not_be_queued_is_retried_on_the_next_pass() {
    let _clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let mut rx = add_peer_cap(&pm, 1, Direction::Outbound, 1, |_| {});
    pm.send_to_peer(1, NetworkMessage::Verack);
    let w = wtxid(7);
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    assert!(matches!(rx.try_recv(), Ok(NetworkMessage::Verack)), "only the filler was queued");
    assert!(rx.try_recv().is_err());
    assert_eq!(pm.tx_requests.lock().count_in_flight(1), 0, "nothing sent, nothing in flight");

    pm.send_all_tx_requests();
    assert_eq!(tx_getdata(&mut rx), vec![Inventory::WTx(w)], "asked again at once");
    assert_eq!(pm.tx_requests.lock().count_in_flight(1), 1);
}

/// Fails every input that carries no witness, the way a script check fails
/// a segwit spend stripped of its witness, and passes the rest.
struct StrippedFails;

impl StrippedFails {
    fn check(tx: &bitcoin::Transaction) -> Result<(), crate::validation::script::ScriptError> {
        match tx.input.iter().position(|i| i.witness.is_empty()) {
            Some(input) => Err(crate::validation::script::ScriptError::VerifyFailed {
                input,
                reason: "Witness program was passed an empty witness".into(),
            }),
            None => Ok(()),
        }
    }
}

impl crate::validation::script::ScriptVerifier for StrippedFails {
    fn verify_transaction(
        &self,
        tx: &bitcoin::Transaction,
        _prev_outputs: &[bitcoin::TxOut],
        _height: u32,
    ) -> Result<(), crate::validation::script::ScriptError> {
        Self::check(tx)
    }

    fn verify_policy(
        &self,
        tx: &bitcoin::Transaction,
        _prev_outputs: &[bitcoin::TxOut],
    ) -> Result<(), crate::validation::script::ScriptError> {
        Self::check(tx)
    }
}

/// Two txid-relay peers announce a segwit transaction. The one asked sends
/// it stripped of its witness, which fails its scripts: Core's
/// `TX_WITNESS_STRIPPED`, after which nothing is forgotten
/// (`txdownloadman_impl.cpp:438-440`). A stripped transaction's wtxid is
/// its txid, so forgetting it dropped the other announcer, the one that can
/// send the witnessed copy.
#[test]
fn a_witness_stripped_reply_leaves_the_other_announcers_of_the_txid() {
    let _clock = MockClock::install();
    let p2wpkh = {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0x11; 20]);
        bitcoin::ScriptBuf::from_bytes(spk)
    };
    let prev = bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([0x61; 32]), vout: 0 };
    let coin = crate::storage::coinview::Coin {
        amount: 100_000,
        script_pubkey: p2wpkh.clone(),
        height: 1,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    };
    let (cs, mp, dir) =
        crate::mining::template::tests::make_funded_template_env_with(&[(prev, coin)], Box::new(StrippedFails));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(shutdown_tx);
    let pm = PeerManager::new(Arc::new(cs), Arc::new(mp), Arc::new(FeeEstimator::new()), Network::Regtest, shutdown_rx);
    let tip = pm.chain_state.tip_hash();
    let block = crate::chain::state::tests::build_test_block(tip, 1, crate::time::now_secs() as u32);
    pm.chain_state.accept_block(&block).expect("block connects");

    let witnessed = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: prev,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&[vec![0x30; 72], vec![0x02; 33]]),
        }],
        output: vec![bitcoin::TxOut { value: bitcoin::Amount::from_sat(90_000), script_pubkey: p2wpkh }],
    };
    let mut stripped = witnessed.clone();
    stripped.input[0].witness = bitcoin::Witness::new();
    let txid = witnessed.compute_txid();
    assert_eq!(stripped.compute_wtxid().to_byte_array(), txid.to_byte_array());

    let mut rx1 = add_peer_with(&pm, 1, Direction::Outbound, |i| i.wtxid_relay = false);
    let mut rx2 = add_peer_with(&pm, 2, Direction::Outbound, |i| i.wtxid_relay = false);
    pm.handle_inv(1, vec![Inventory::Transaction(txid)]);
    pm.handle_inv(2, vec![Inventory::Transaction(txid)]);
    assert_eq!(tx_getdata(&mut rx1), vec![Inventory::WitnessTransaction(txid)]);
    assert!(tx_getdata(&mut rx2).is_empty());

    pm.handle_tx(1, stripped);
    assert!(pm.mempool.get(&txid).is_none(), "the stripped copy fails its scripts");
    pm.send_all_tx_requests();
    assert_eq!(
        tx_getdata(&mut rx2),
        vec![Inventory::WitnessTransaction(txid)],
        "the other announcer is asked for the witnessed copy"
    );
    pm.handle_tx(2, witnessed);
    assert!(pm.mempool.get(&txid).is_some(), "the witnessed copy is accepted");
    let _ = std::fs::remove_dir_all(dir);
}
