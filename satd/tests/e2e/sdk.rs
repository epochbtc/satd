// End-to-end tests for the published Rust SDK (`satd-events-client`), driving a
// real `satd` regtest node over a real gRPC socket.
//
// The sibling `streaming.rs` proves the wire contract with a hand-rolled gRPC
// test client; this file proves the *SDK* against the same live node — the
// builder/connect path, the typed `Event` enum, watch helpers, durable cursor
// replay across a reconnect, and the privacy-preserving `PrefixWatcher`
// local re-filter. Folded into the `e2e` target via `mod sdk;` in `tests/e2e.rs`,
// so reach the shared harness through `crate::common`.

use std::sync::Arc;
use std::time::Duration;

use satd_events_client::{
    Categories, Cursor, Event, FileCursorStore, PrefixWatcher, ResilientConfig, StatusKind,
    StatusSeverity, StatusState, StreamClient, StreamError, SubscribeOptions,
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
    matured_node_args(vec![]).await
}

/// [`matured_node`] with extra daemon arguments.
async fn matured_node_args(args: Vec<&'static str>) -> (StreamingNode, DeterministicWallet) {
    let sn = start_async(args).await;
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

/// A tweaks-only cold sync anchored below the first block. A cursor names the
/// last height already scanned, so height 0 makes block 1 the first replayed.
fn tweak_cold_sync_opts() -> SubscribeOptions {
    SubscribeOptions {
        categories: Categories::TWEAKS,
        from_cursor: Some(Cursor { height: 0, tx_index: 0, mempool_seq: 0, instance_id: 0 }),
        ..Default::default()
    }
}

/// The height of the next `BlockTweaks`. A `ReplayGap` is fatal here rather than
/// logged: it names blocks that were never delivered, and an unscanned block is
/// an unseen payment.
async fn next_tweak_height(
    sub: &mut satd_events_client::ResilientSubscription,
    secs: u64,
) -> u32 {
    loop {
        match next_resilient(sub, secs).await {
            Event::BlockTweaks { height, .. } => return height,
            Event::ReplayGap { resume_height, first_height } => {
                panic!("replay gap ({resume_height}, {first_height}): a scan must never skip a block")
            }
            _ => continue,
        }
    }
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

/// A tweak scan killed mid-stream resumes without skipping a block, repeating at
/// most the one it had in hand.
///
/// This is the conformance property every silent-payment light client needs, and
/// the one a shipped wallet gets wrong (cake_wallet#3574): the persisted anchor
/// must never run ahead of the scanning. `resilience.rs` unit-tests
/// commit-on-poll against a mock store; nothing proved it end to end on the
/// tweaks path, where a skipped block is a missed payment rather than a missed
/// log line.
///
/// The kill is `drop` without `commit`, which is what a `SIGKILL` or a phone
/// suspending the process looks like to the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_tweak_scan_resumes_after_a_kill_without_skipping_a_block() {
    let sn = start_async(vec!["-silentpaymentindex=1"]).await;
    mine_n(&sn, 6).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let cursor_path = dir.path().join("sp.cursor");

    // Scan three blocks, then die: no `commit`, no clean shutdown. Commit-on-poll
    // means the store now holds block 2 — the anchor of the event *before* the
    // one that was in hand.
    let client = connect(&sn).await;
    let mut sub = client.resilient_subscribe(
        tweak_cold_sync_opts(),
        ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(&cursor_path))),
    );
    let mut before = Vec::new();
    for _ in 0..3 {
        before.push(next_tweak_height(&mut sub, 20).await);
    }
    assert_eq!(before, vec![1, 2, 3], "cold sync replays the taproot era in height order");
    drop(sub);
    drop(client);

    // A restarted process reads the file back and resumes from it.
    let client = connect(&sn).await;
    let mut sub = client.resilient_subscribe(
        tweak_cold_sync_opts(),
        ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(&cursor_path))),
    );
    let mut after = Vec::new();
    while after.last() != Some(&6) {
        after.push(next_tweak_height(&mut sub, 20).await);
    }

    assert_eq!(
        after,
        vec![3, 4, 5, 6],
        "the block that was in hand at the kill is rescanned, and exactly one is"
    );
    let mut union: Vec<u32> = before.iter().chain(after.iter()).copied().collect();
    union.sort_unstable();
    union.dedup();
    assert_eq!(
        union,
        (1..=6).collect::<Vec<u32>>(),
        "every block is scanned at least once across the kill — no gap at any height"
    );
}

/// The clean-shutdown path: `commit` before exiting, and the resume repeats
/// nothing.
///
/// The pair of tests brackets the contract — an uncommitted kill repeats exactly
/// one block, a committed shutdown repeats none — so a regression that advanced
/// the anchor early would break the first, and one that never advanced it would
/// break the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_tweak_scan_committed_shutdown_resumes_with_no_repeat() {
    let sn = start_async(vec!["-silentpaymentindex=1"]).await;
    mine_n(&sn, 5).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let cursor_path = dir.path().join("sp.cursor");

    let client = connect(&sn).await;
    let mut sub = client.resilient_subscribe(
        tweak_cold_sync_opts(),
        ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(&cursor_path))),
    );
    for _ in 0..3 {
        next_tweak_height(&mut sub, 20).await;
    }
    // The scan of block 3 is done, so its anchor is safe to persist now rather
    // than on a `next` that will never come.
    sub.commit().expect("commit writes the armed anchor");
    drop(sub);
    drop(client);

    let client = connect(&sn).await;
    let mut sub = client.resilient_subscribe(
        tweak_cold_sync_opts(),
        ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(&cursor_path))),
    );
    assert_eq!(
        next_tweak_height(&mut sub, 20).await,
        4,
        "a committed anchor resumes at the next unscanned block"
    );
}

}
/// Cut-through (`tweak_unspent_only`): an entry disappears once its taproot
/// outputs are spent, and the block says so with `filtered`.
///
/// The same height is scanned four times — before and after the spend, with the
/// filter off and on — so the test separates "the view changed" from "the index
/// changed". The row on disk is untouched throughout; only the served view moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_tweak_cut_through_drops_spent_entries() {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::OutPoint;
    use crate::common::{build_signed_p2tr_keypath_spend, p2tr_keypath_output};
    use std::str::FromStr;

    let (sn, wallet) = matured_node_args(vec!["-silentpaymentindex=1"]).await;
    let secp = Secp256k1::new();
    let (kp, p2tr) = p2tr_keypath_output(&secp, [0x33; 32]);

    // Funding: block-1's coinbase (P2WPKH) into a single taproot output. One
    // taproot output and one eligible input is the whole eligibility test, so
    // the index writes an entry for this transaction.
    let fee = 10_000u64;
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let spk = p2tr.clone();
    let (raw, txid_str) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_seq(&rpc, &w, spk, fee, 0xffff_ffff)
    })
    .await
    .unwrap();
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.send_raw_tx(&raw)).await.unwrap();
    mine_n(&sn, 1).await;
    let funded_height = 102u32;
    let funded_txid = bitcoin::Txid::from_str(&txid_str).expect("txid");
    let funded_value = 50 * 100_000_000 - fee;

    // While the coin is live, cut-through must keep the entry: this is the case
    // a wallet actually needs, and dropping it here would lose a payment.
    let client = connect(&sn).await;
    let entries = tweaks_at(&client, funded_height, false, true).await;
    assert_eq!(entries.0.len(), 1, "the eligible transaction is indexed");
    assert!(!entries.1, "nothing filtered with cut-through off");
    let (entries, filtered) = tweaks_at(&client, funded_height, true, true).await;
    assert_eq!(entries.len(), 1, "an unspent taproot output survives cut-through");
    assert!(!filtered, "nothing was dropped, so the block is not `filtered`");
    assert_eq!(entries[0].taproot_outputs.len(), 1);
    assert_eq!(entries[0].taproot_outputs[0].vout, 0);

    // Spend it, key-path, to a plain P2WPKH — so the spending transaction is not
    // itself silent-payment eligible and only the funding height carries a row.
    let (raw_spend, _spend_txid) = build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        OutPoint { txid: funded_txid, vout: 0 },
        p2tr.clone(),
        funded_value,
        DeterministicWallet::from_secret([0x44; 32]).address.script_pubkey(),
        fee,
    );
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.send_raw_tx(&raw_spend)).await.unwrap();
    mine_n(&sn, 1).await;

    // Same height, same row, spent coin: the entry is cut and the block admits
    // it, so an empty `entries` is never read as "this block had none".
    let (entries, filtered) = tweaks_at(&client, funded_height, true, true).await;
    assert!(entries.is_empty(), "a fully spent entry is cut through");
    assert!(filtered, "a dropped entry sets the block's `filtered` flag");

    // Control: with the filter off the same height still serves the entry, so
    // what changed is the view, not the index.
    let (entries, filtered) = tweaks_at(&client, funded_height, false, true).await;
    assert_eq!(entries.len(), 1, "the stored row is untouched by cut-through");
    assert!(!filtered);
}

/// Replay `height` on a tweaks-only subscription and return that block's entries
/// plus its `filtered` flag.
async fn tweaks_at(
    client: &StreamClient,
    height: u32,
    unspent_only: bool,
    outputs: bool,
) -> (Vec<satd_events_client::TweakEntry>, bool) {
    let mut client = client.clone();
    let mut stream = client
        .subscribe(SubscribeOptions {
            categories: Categories::TWEAKS,
            // A cursor names the last height already delivered, so anchor one
            // below the height under test.
            from_cursor: Some(Cursor {
                height: height - 1,
                tx_index: 0,
                mempool_seq: 0,
                instance_id: 0,
            }),
            tweak_outputs: outputs,
            tweak_unspent_only: unspent_only,
            ..Default::default()
        })
        .await
        .expect("tweaks subscribe");
    let ev = next_matching(&mut stream, 20, |e| {
        matches!(e, Event::BlockTweaks { height: h, .. } if *h == height)
    })
    .await;
    let Event::BlockTweaks { entries, filtered, .. } = ev else { unreachable!() };
    (entries, filtered)
}

/// The typed `Event::Status` path end to end: a real condition detected by a
/// real node, decoded by the SDK.
///
/// The threshold is moved *after* subscribing rather than set on the command
/// line: status events are not replayable, so a condition raised during startup
/// would never reach a client that had not finished connecting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_status_events_decode_typed() {
    let sn = start_async(vec![]).await;
    let mut client = connect(&sn).await;
    let mut stream = client
        .subscribe(SubscribeOptions { categories: Categories::STATUS, ..Default::default() })
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(600)).await;

    // An unreachable disk floor (2^44 MiB) fires `disk_low` on any filesystem.
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;

    let ev = next_matching(&mut stream, 45, |e| matches!(e, Event::Status { .. })).await;
    let Event::Status { kind, state, severity, message, details } = ev else { unreachable!() };
    assert_eq!(kind, StatusKind::DiskLow);
    assert_eq!(state, StatusState::Raised);
    assert_eq!(severity, StatusSeverity::Critical);
    assert!(!message.is_empty(), "a status event always carries a message");
    // `details` is the machine-readable half; a client switches on `kind` and
    // reads these rather than parsing the message.
    assert!(details.contains_key("free_bytes"), "details: {details:?}");
    assert!(details.contains_key("threshold_bytes"), "details: {details:?}");
    // Severity is ordered, so a client filters with a comparison.
    assert!(severity >= StatusSeverity::Warning);
    // Status events are not replayable and must not advance a resume position.
    assert!(stream.cursor().is_none(), "status must not anchor a cursor");
}

/// A `CHAIN`-only subscription must not receive status events: the category is
/// explicit-request only, which is what keeps an older client safe across a
/// node upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_status_absent_without_the_category_bit() {
    let sn = start_async(vec![]).await;
    let mut client = connect(&sn).await;
    let mut stream = client
        .subscribe(SubscribeOptions { categories: Categories::CHAIN, ..Default::default() })
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(600)).await;

    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;
    mine_n(&sn, 2).await;

    // Read a bounded number of events; a status body among them would be a bug.
    for _ in 0..4 {
        let Ok(Ok(Some(ev))) =
            tokio::time::timeout(Duration::from_secs(5), stream.message()).await
        else {
            break;
        };
        assert!(
            !matches!(ev, Event::Status { .. }),
            "a CHAIN-only subscription must never receive status events",
        );
    }
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
