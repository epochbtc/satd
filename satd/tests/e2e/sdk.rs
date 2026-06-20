// End-to-end tests for the published Rust SDK (`satd-events-client`), driving a
// real `satd` regtest node over a real gRPC socket.
//
// The sibling `streaming.rs` proves the wire contract with a hand-rolled gRPC
// test client; this file proves the *SDK* against the same live node — the
// builder/connect path, the typed `Event` enum, watch helpers, durable cursor
// replay across a reconnect, and the privacy-preserving `PrefixWatcher`
// local re-filter. Folded into the `e2e` target via `mod sdk;` in `tests/e2e.rs`,
// so reach the shared harness through `crate::common`.

use std::time::Duration;

use satd_events_client::{
    Categories, Cursor, Event, PrefixWatcher, ResilientConfig, StreamClient, StreamError,
    SubscribeOptions,
};

use crate::common::{
    block1_coinbase_txid, build_signed_p2wpkh_spend_seq, display_to_internal_hex, e2e_test_timeout,
    DeterministicWallet, StreamingNode,
};

const WALLET_SEED: u8 = 0x11;

// ---- node-driving helpers (mirrors streaming.rs; that module's are private) --

async fn start_async(args: Vec<&'static str>) -> StreamingNode {
    tokio::task::spawn_blocking(move || StreamingNode::start(&args)).await.unwrap()
}

/// Start a node and mine 101 blocks to the wallet so block-1's coinbase is
/// mature and spendable.
async fn matured_node() -> (StreamingNode, DeterministicWallet) {
    let sn = start_async(vec![]).await;
    let wallet = DeterministicWallet::from_secret([WALLET_SEED; 32]);
    let addr = wallet.address.to_string();
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.mine(101, &addr)).await.unwrap();
    (sn, wallet)
}

async fn coinbase1(sn: &StreamingNode) -> String {
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || block1_coinbase_txid(&rpc)).await.unwrap()
}

async fn mine_n(sn: &StreamingNode, n: u32) {
    let rpc = sn.node.rpc_handle();
    let addr = DeterministicWallet::from_secret([0x99; 32]).address.to_string();
    tokio::task::spawn_blocking(move || rpc.mine(n, &addr)).await.unwrap();
}

/// Build + broadcast a block-1-coinbase spend to `dest_seed`'s address; returns
/// `(spend_display_txid, dest_spk)`.
async fn broadcast_spend(
    sn: &StreamingNode,
    wallet: &DeterministicWallet,
    dest_seed: u8,
    fee: u64,
) -> (String, bitcoin::ScriptBuf) {
    let dest = DeterministicWallet::from_secret([dest_seed; 32]).address.script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let dest2 = dest.clone();
    let (raw, txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_seq(&rpc, &w, dest2, fee, 0xffff_ffff)
    })
    .await
    .unwrap();
    let rpc2 = sn.node.rpc_handle();
    let got = tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw)).await.unwrap();
    assert_eq!(got, txid, "sendrawtransaction returns the computed txid");
    (txid, dest)
}

// ---- SDK helpers -------------------------------------------------------------

async fn connect(sn: &StreamingNode) -> StreamClient {
    StreamClient::builder(format!("http://127.0.0.1:{}", sn.grpc_port()))
        .keepalive_default()
        .connect()
        .await
        .expect("SDK connects to the gRPC listener")
}

/// The next event satisfying `pred`, within an overall deadline (scaled by
/// `SATD_E2E_TIMEOUT_MULT` under CI load, like the rest of the suite).
async fn next_matching(
    stream: &mut satd_events_client::EventStream,
    secs: u64,
    mut pred: impl FnMut(&Event) -> bool,
) -> Event {
    let fut = async {
        loop {
            let ev = stream.message().await.expect("no stream error").expect("not closed");
            if pred(&ev) {
                return ev;
            }
        }
    };
    tokio::time::timeout(e2e_test_timeout(secs), fut).await.expect("matching event within timeout")
}

fn txid_internal(display_hex: &str) -> [u8; 32] {
    let v = hex::decode(display_to_internal_hex(display_hex)).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

// ---- tests -------------------------------------------------------------------

/// `subscribe` delivers a typed `BlockConnected` when a block is mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_subscribe_delivers_block_connected() {
    let sn = start_async(vec![]).await;
    let mut client = connect(&sn).await;
    let mut stream = client
        .subscribe(SubscribeOptions { categories: Categories::CHAIN, ..Default::default() })
        .await
        .expect("subscribe");
    // Subscribe is live-only; let it register before mining.
    tokio::time::sleep(Duration::from_millis(600)).await;

    mine_n(&sn, 1).await;

    let ev = next_matching(&mut stream, 15, |e| matches!(e, Event::BlockConnected { .. })).await;
    let Event::BlockConnected { height, .. } = ev else { unreachable!() };
    assert_eq!(height, 1, "first mined block is height 1");
    // The confirmed cursor was captured and advanced.
    assert_eq!(stream.cursor().map(|c| c.height), Some(1));
}

/// `watch` + `add_outpoints` delivers `OutpointSpent` in the mempool, then again
/// once confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_watch_outpoint_spent_mempool_then_confirmed() {
    let (sn, wallet) = matured_node().await;
    let cb = coinbase1(&sn).await;
    let cb_bytes = txid_internal(&cb);

    let mut client = connect(&sn).await;
    let (watch, mut stream) = client.watch().await.expect("watch");
    watch.add_outpoints([(cb_bytes, 0)]).await.expect("add_outpoints");
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (spend_txid, _dest) = broadcast_spend(&sn, &wallet, 0x55, 10_000).await;

    let ev = next_matching(&mut stream, 15, |e| matches!(e, Event::OutpointSpent { .. })).await;
    let Event::OutpointSpent { outpoint, spending_txid, confirmed, .. } = ev else { unreachable!() };
    assert!(!confirmed, "first match is in the mempool");
    assert_eq!(outpoint.txid, cb_bytes.to_vec());
    assert_eq!(outpoint.vout, 0);
    assert_eq!(spending_txid, txid_internal(&spend_txid).to_vec());

    mine_n(&sn, 1).await;
    let ev = next_matching(
        &mut stream,
        15,
        |e| matches!(e, Event::OutpointSpent { confirmed, .. } if *confirmed),
    )
    .await;
    let Event::OutpointSpent { confirmed, .. } = ev else { unreachable!() };
    assert!(confirmed, "second match is confirmed");
}

/// A privacy-preserving prefix watch: register a coarse bucket, receive the
/// decoy-laden delivery, and re-filter it locally to the true funding match
/// with `PrefixWatcher`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_prefix_watch_local_refilter() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x59; 32]).address.script_pubkey();

    // Hold the real script client-side; register only its 8-bit bucket.
    let mut watcher = PrefixWatcher::new();
    watcher.watch_script(&dest);
    let prefixes = watcher.prefixes(8);

    let mut client = connect(&sn).await;
    let (watch, mut stream) = client.watch().await.expect("watch");
    watch.add_script_prefixes(prefixes).await.expect("add_script_prefixes");
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Fund `dest` — it appears as an output of the broadcast spend.
    broadcast_spend(&sn, &wallet, 0x59, 10_000).await;

    // Collect prefix deliveries until one re-filters to a true funding hit on
    // our script (the bucket may also carry decoys / the spend side).
    let dest_sh = satd_events_client::scripthash_of(dest.as_bytes());
    let found = tokio::time::timeout(e2e_test_timeout(15), async {
        loop {
            let ev = stream.message().await.expect("no error").expect("open");
            if let Event::PrefixMatched(m) = ev {
                let hits = watcher.filter(&m).expect("decode raw_tx");
                if hits.funding.iter().any(|f| f.scripthash == dest_sh) {
                    return hits;
                }
            }
        }
    })
    .await
    .expect("a prefix delivery re-filters to our funding output");

    assert!(found.is_match());
    let f = found.funding.iter().find(|f| f.scripthash == dest_sh).unwrap();
    assert_eq!(f.script_pubkey, dest, "re-filtered to the exact watched script");
}

/// Durable cursor replay: capture the cursor on a live stream, drop it, mine a
/// block while disconnected, then resume with `from_cursor` and observe the
/// missed block replayed — no gap across the reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_cursor_replay_resumes_across_reconnect() {
    let sn = start_async(vec![]).await;
    let mut client = connect(&sn).await;

    // First connection: mine 2 blocks, consume them, capture the cursor.
    let mut stream = client
        .subscribe(SubscribeOptions { categories: Categories::CHAIN, ..Default::default() })
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(600)).await;
    mine_n(&sn, 2).await;
    let _ = next_matching(&mut stream, 15, |e| matches!(e, Event::BlockConnected { height: 1, .. })).await;
    let _ = next_matching(&mut stream, 15, |e| matches!(e, Event::BlockConnected { height: 2, .. })).await;
    let cursor = *stream.cursor().expect("cursor captured");
    assert_eq!(cursor.height, 2);

    // Disconnect, then mine a block nobody is listening for.
    drop(stream);
    mine_n(&sn, 1).await;

    // Resume from the captured cursor: the server replays (height, tip], so the
    // first chain event is the block mined while we were gone — not a gap.
    let mut stream = client
        .subscribe(SubscribeOptions {
            categories: Categories::CHAIN,
            from_cursor: Some(cursor),
            ..Default::default()
        })
        .await
        .expect("resubscribe");
    let ev = next_matching(&mut stream, 15, |e| matches!(e, Event::BlockConnected { .. })).await;
    let Event::BlockConnected { height, .. } = ev else { unreachable!() };
    assert_eq!(height, 3, "replay resumes at cursor.height + 1, no gap");
}

/// The resilient wrapper connects lazily and replays from a `from_cursor` base.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_resilient_subscribe_replays_from_cursor() {
    let sn = start_async(vec![]).await;
    mine_n(&sn, 3).await;

    let client = connect(&sn).await;
    // Anchor at height 1 (instance_id is irrelevant for confirmed replay); the
    // server replays heights 2 and 3.
    let base = SubscribeOptions {
        categories: Categories::CHAIN,
        from_cursor: Some(Cursor { height: 1, tx_index: 0, mempool_seq: 0, instance_id: 0 }),
        ..Default::default()
    };
    let mut sub = client.resilient_subscribe(base, ResilientConfig::new());

    let ev = next_resilient(&mut sub, 15).await;
    let Event::BlockConnected { height, .. } = ev else { panic!("expected block, got {ev:?}") };
    assert_eq!(height, 2, "resilient subscription replays from cursor.height + 1");
}

/// Next event from a `ResilientSubscription`, panicking on timeout / error.
async fn next_resilient(
    sub: &mut satd_events_client::ResilientSubscription,
    secs: u64,
) -> Event {
    let fut = async {
        loop {
            match sub.next().await {
                Ok(Event::Heartbeat { .. }) => continue,
                Ok(ev) => return Ok::<Event, StreamError>(ev),
                Err(e) => return Err(e),
            }
        }
    };
    tokio::time::timeout(e2e_test_timeout(secs), fut)
        .await
        .expect("event within timeout")
        .expect("no stream error")
}
