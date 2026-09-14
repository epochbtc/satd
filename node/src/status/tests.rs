use super::*;
use crate::chain::state::tests::{build_test_block, make_chain_state};
use crate::mempool::fee::FeeEstimator;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;

/// Every combination of the phase inputs, against `/readyz`: the page never
/// reports `Ready`, or any at-the-tip phase, while `/readyz` is 503, and it
/// reports `Ready` whenever `/readyz` is 200 and nothing else is pending.
#[test]
fn status_top_line_state_matches_readyz() {
    let readyzs = [Ok(()), Err(NotReady::Stalled), Err(NotReady::Lag { lag: 7 })];
    for readyz in readyzs {
        for headers_stale in [false, true] {
            for background_validation in [false, true] {
                for indexes_building in [false, true] {
                    let i = PhaseInputs {
                        readyz: readyz.clone(),
                        headers_stale,
                        background_validation,
                        indexes_building,
                    };
                    let p = phase(&i);
                    let ctx = format!("{i:?} -> {p:?}");
                    if readyz.is_err() {
                        assert!(
                            matches!(p, Phase::Stalled | Phase::SyncingHeaders | Phase::SyncingBlocks),
                            "{ctx}"
                        );
                    }
                    if p == Phase::Ready {
                        assert!(readyz.is_ok(), "{ctx}");
                    }
                    if readyz == Err(NotReady::Stalled) {
                        assert_eq!(p, Phase::Stalled, "a stalled connector outranks all: {ctx}");
                    }
                    if readyz.is_ok() && !headers_stale && !background_validation && !indexes_building {
                        assert_eq!(p, Phase::Ready, "{ctx}");
                    }
                }
            }
        }
    }
}

/// The case `/readyz` cannot see: a node whose blocks keep up with a header
/// chain that is itself still downloading. `/readyz` reads 200; the page
/// must not say ready.
#[test]
fn headers_still_downloading_is_not_ready_on_the_page() {
    let p = phase(&PhaseInputs {
        readyz: Ok(()),
        headers_stale: true,
        background_validation: false,
        indexes_building: false,
    });
    assert_eq!(p, Phase::SyncingHeaders);
}

#[test]
fn rates_need_a_span_and_forget_old_samples() {
    let mut r = Rates::default();
    let t0 = Instant::now();
    assert_eq!(r.observe(t0, 100, 1000), (None, None));
    // Under the minimum span: no rate yet.
    assert_eq!(r.observe(t0 + Duration::from_secs(3), 130, 1000), (None, None));
    let (b, h) = r.observe(t0 + Duration::from_secs(10), 200, 1500);
    assert_eq!(b, Some(10.0));
    assert_eq!(h, Some(50.0));
    // Samples closer together than a second are not recorded, so a burst of
    // tabs does not crowd the window.
    let before = r.samples.len();
    r.observe(t0 + Duration::from_millis(10_200), 201, 1500);
    assert_eq!(r.samples.len(), before);
    // Past the window, the early samples fall out and the rate is measured
    // over what is left.
    r.observe(t0 + Duration::from_secs(40), 250, 1500);
    let (b, _) = r.observe(t0 + Duration::from_secs(75), 300, 1500);
    assert_eq!(r.samples.front().unwrap().0, t0 + Duration::from_secs(40), "{:?}", r.samples);
    assert_eq!(b, Some(50.0 / 35.0));
}

struct Fixture {
    ctx: MetricsContext,
    sources: StatusSources,
    dir: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(n: u32) -> Fixture {
    let (cs, dir) = make_chain_state();
    let cs = Arc::new(cs);
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for h in 1..=n {
        let b = build_test_block(parent, h, 1_300_000_000 + h);
        cs.accept_header(&b.header).unwrap();
        cs.store_block(&b).unwrap();
        cs.connect_stored_block(&b.block_hash()).unwrap();
        parent = b.block_hash();
    }
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::new(cs.clone(), mempool.clone(), fee_estimator.clone(), Network::Regtest, shutdown_rx);
    let ctx = MetricsContext {
        chain_state: cs,
        mempool,
        peer_manager: pm,
        network: Network::Regtest,
        start_time: Instant::now(),
        version: "test",
        addr_subs: None,
        addr_enabled: true,
        sp_enabled: false,
        filter_enabled: false,
        health: None,
        webhooks: None,
        status: None,
    };
    let sources = StatusSources::new(
        crate::rpc::server::ServerListenerStatus::new(),
        None,
        None,
        #[cfg(feature = "block-filter-index")]
        None,
        fee_estimator,
        true,
        true,
        true,
        vec![Advertised::parse("electrum=ssl://node.local:50002").unwrap()],
    );
    Fixture { ctx, sources, dir }
}

/// The snapshot is read on every poll of every open tab. It must never wait
/// on the lock block connection holds: hold it, and the build still returns.
///
/// Routing the build through `ChainState::utxo_set_info` (what
/// `gettxoutsetinfo` uses) makes this test fail, which is what keeps that
/// call off the page.
#[test]
fn status_request_does_not_take_accept_lock() {
    let f = Arc::new(fixture(3));
    let guard = f.ctx.chain_state.hold_accept_lock_for_test();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = {
        let f = f.clone();
        std::thread::spawn(move || {
            let snap = build(&f.ctx, &f.sources);
            let _ = tx.send(snap.sync.blocks);
        })
    };
    let got = rx.recv_timeout(Duration::from_secs(10));
    drop(guard);
    worker.join().unwrap();
    assert_eq!(got, Ok(3), "the snapshot waited on the accept lock");
}

#[test]
fn a_snapshot_of_a_short_regtest_chain() {
    let f = fixture(3);
    let snap = build(&f.ctx, &f.sources);
    assert_eq!(snap.network, "regtest");
    assert_eq!(snap.sync.blocks, 3);
    assert_eq!(snap.sync.headers, 3);
    // Test-chain timestamps are from 2011, so the header chain reads as a
    // day stale and the node as still syncing, as `initialblockdownload`
    // would say.
    assert_eq!(snap.phase, Phase::SyncingHeaders);
    assert!(snap.ready, "/readyz only measures lag, and there is none");
    assert!(snap.latest_block.is_none() && snap.fees.is_none(), "not shown while syncing");
    assert!(!snap.services.wallets_ready);
    assert_eq!(snap.services.esplora, ServiceState::Starting);
    assert_eq!(snap.indexes[0].name, "address");
    assert!(!snap.unclean_shutdown);
    let json = serde_json::to_value(&snap).unwrap();
    assert_eq!(json["phase"], "syncing_headers");
    assert_eq!(json["indexes"][0]["name"], "address");
    assert!(json["indexes"][0]["state"].is_string(), "{json}");
}

/// Once the clock is at the chain, the synced-only panels appear, and the
/// latest block is read from the chain rather than invented.
#[test]
fn a_synced_snapshot_carries_the_latest_block_and_fees() {
    let f = fixture(3);
    let tip_time = 1_300_000_003u64;
    // The node clock is process-global and other tests read it; pass the
    // reading instead of mocking it.
    let snap = build_at(&f.ctx, &f.sources, tip_time + 60);
    assert_ne!(snap.phase, Phase::SyncingHeaders, "{snap:?}");
    let block = snap.latest_block.expect("synced snapshot has the latest block");
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, f.ctx.chain_state.tip_hash());
    assert!(block.transactions >= 1);
    assert!(snap.fees.is_some());
}
