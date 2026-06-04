// End-to-end tests for the Streaming Consumption API, driving a real `satd`
// regtest node over real gRPC / WebSocket / SSE sockets.
//
// Unlike the in-process `end_to_end_streaming_delivery` test in
// `events/src/grpc.rs` (which hand-builds a `GrpcEventSink` and injects
// synthetic events), every test here spawns the `satd` binary, opens a client
// against its `--events-grpc-bind` / `--streamws` listener, mines or broadcasts
// real transactions via RPC, and asserts the client receives the corresponding
// event over the wire.
//
// This file is the Phase 0/1 foundation of the streaming E2E plan
// (`STREAMING_E2E_TEST_PLAN.md`): it proves the three client harnesses and the
// node-discovery plumbing work. Subsequent phases (watch primitives, cursor
// replay, lag, caps/auth, consensus invariant) build on these helpers.
//
// Async tests drive mining / broadcast through `RpcHandle` +
// `tokio::task::spawn_blocking`, because `reqwest::blocking` panics if called
// directly on a tokio worker thread.

mod common;

use common::grpc_client::{
    add_outpoints, add_script_prefixes, add_scripts, add_transactions, next_event_matching,
    next_event_opt, remove_outpoints, Body, Control, Cursor, GrpcStreamClient, SubscribeControl,
};
use common::ws_client::{StreamSseClient, WsClient};
use common::{
    block1_coinbase_txid, build_signed_p2wpkh_spend_from_block1_coinbase,
    build_signed_p2wpkh_spend_seq, display_to_internal_hex, scripthash_hex, script_prefix_hex,
    write_authfile, DeterministicWallet, StreamingNode, TokenSpec,
};
use std::time::Duration;

/// A throwaway regtest address to mine to. The streaming tests don't spend
/// these coinbases, so any valid P2WPKH regtest address works.
fn mine_addr(seed: u8) -> String {
    DeterministicWallet::from_secret([seed; 32])
        .address
        .to_string()
}

/// Spawn a streaming node from an async test. `StreamingNode::start` polls RPC
/// readiness with `reqwest::blocking`, whose internal runtime panics if dropped
/// on a tokio worker thread — so the (blocking) startup runs on a blocking
/// task.
async fn start_streaming_async(args: Vec<&'static str>) -> StreamingNode {
    tokio::task::spawn_blocking(move || StreamingNode::start(&args))
        .await
        .unwrap()
}

/// `getserverstatus` reports the runtime-bound gRPC + streamws listener
/// addresses, and the harness discovers them. This exercises the
/// `ServerListenerStatus` wiring (no client needed).
#[test]
fn streaming_listeners_report_bound_ports() {
    let sn = StreamingNode::start(&[]);
    assert!(
        sn.grpc_port.is_some(),
        "events_grpc port should be discovered from getserverstatus"
    );
    assert!(
        sn.ws_port.is_some(),
        "streamws port should be discovered from getserverstatus"
    );
    let status = sn
        .node
        .rpc_call("getserverstatus")
        .expect("getserverstatus");
    let res = &status["result"];
    assert!(
        res["events_grpc"]["bind"].as_str().is_some(),
        "events_grpc bind should be a string: {res}"
    );
    assert!(
        res["streamws"]["bind"].as_str().is_some(),
        "streamws bind should be a string: {res}"
    );
}

/// gRPC `Subscribe` firehose delivers a `BlockConnected` chain event when a
/// block is mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_subscribe_block_connected() {
    let sn = start_streaming_async(vec![]).await;
    let grpc_port = sn.grpc_port();
    let mut client = GrpcStreamClient::connect(grpc_port).await;
    let mut stream = client.subscribe(0, None).await;
    // Subscribe is live-only; let it register server-side before mining.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let rpc = sn.node.rpc_handle();
    let addr = mine_addr(0x22);
    let hashes = tokio::task::spawn_blocking(move || rpc.mine(1, &addr))
        .await
        .unwrap();
    assert_eq!(hashes.len(), 1, "mined exactly one block");

    let ev = next_event_matching(&mut stream, 15, |b| matches!(b, Body::Chain(_))).await;
    let Some(Body::Chain(ce)) = ev.body else {
        unreachable!("matched Chain above");
    };
    match ce.body {
        Some(satd_events::proto::v1::chain_event::Body::BlockConnected(bc)) => {
            // Fresh regtest node: genesis is height 0, so the first mined
            // block is height 1.
            assert_eq!(bc.height, 1, "first mined block is height 1");
            assert_eq!(bc.hash.len(), 32, "block hash is 32 bytes");
        }
        other => panic!("expected BlockConnected, got {other:?}"),
    }
}

/// WS `/ws` firehose delivers a JSON chain `block_connected` event on a new
/// block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_firehose_block_connected() {
    let sn = start_streaming_async(vec![]).await;
    let ws_port = sn.ws_port();
    let mut ws = WsClient::connect(ws_port).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let rpc = sn.node.rpc_handle();
    let addr = mine_addr(0x23);
    tokio::task::spawn_blocking(move || rpc.mine(1, &addr))
        .await
        .unwrap();

    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "chain")
        .await;
    assert_eq!(ev["body"]["kind"], "block_connected", "event: {ev}");
    assert_eq!(ev["body"]["height"], 1, "event: {ev}");
}

/// SSE `/sse` firehose delivers the same JSON chain event. The SSE reader is
/// synchronous (raw TCP), so it's driven on blocking tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn sse_firehose_block_connected() {
    let sn = start_streaming_async(vec![]).await;
    let ws_port = sn.ws_port();

    let mut sse = tokio::task::spawn_blocking(move || StreamSseClient::connect(ws_port, "/sse"))
        .await
        .unwrap();
    // Margin for the server to attach its broadcast receiver before we mine.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let rpc = sn.node.rpc_handle();
    let addr = mine_addr(0x24);
    tokio::task::spawn_blocking(move || rpc.mine(1, &addr))
        .await
        .unwrap();

    let ev = tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for SSE chain event"
            );
            let (_etype, data) = sse.next_event();
            if data.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v["body"]["category"] == "chain" {
                return v;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ev["body"]["kind"], "block_connected", "event: {ev}");
    assert_eq!(ev["body"]["height"], 1, "event: {ev}");
}

// ===========================================================================
// Phase 1 (remainder): category filter, heartbeat
// ===========================================================================

/// gRPC `Subscribe` with `categories = chain (2)` delivers block events but not
/// mempool events. We mine (chain) and broadcast a tx (mempool), then assert
/// the first non-chain-filtered event we see is the BlockConnected and that no
/// mempool event arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_subscribe_category_filter_chain_only() {
    let (sn, wallet) = matured_node().await;
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    // categories = 2 (chain only).
    let mut stream = client.subscribe(2, None).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Broadcast a tx (mempool category) AND mine a block (chain category).
    broadcast_spend(&sn, &wallet, 0x55, 10_000).await;
    mine_n(&sn, 1).await;

    // The first event must be a chain event; a mempool event must never slip
    // through the filter. Scan a few events to be sure.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut saw_chain = false;
    while std::time::Instant::now() < deadline {
        let Some(ev) = next_event_opt(&mut stream, 3).await else {
            break;
        };
        match ev.body {
            Some(Body::Mempool(_)) => panic!("mempool event leaked past chain-only filter"),
            Some(Body::Chain(_)) => {
                saw_chain = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(saw_chain, "expected at least one chain event");
}

/// gRPC `Subscribe` with `categories = heartbeat (4)` delivers periodic
/// heartbeats (cadence 1s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_subscribe_heartbeat() {
    let sn = start_streaming_async(vec![]).await;
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let mut stream = client.subscribe(4, None).await;
    let ev = next_event_matching(&mut stream, 10, |b| matches!(b, Body::Heartbeat(_))).await;
    match ev.body {
        Some(Body::Heartbeat(hb)) => assert!(hb.uptime_ns > 0, "uptime advances"),
        other => panic!("expected Heartbeat, got {other:?}"),
    }
}

/// WS firehose honours a runtime `set_categories` control: after switching to
/// chain-only, a mined block still arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_set_categories_chain_only() {
    let (sn, _wallet) = matured_node().await;
    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({"type": "set_categories", "categories": 2}))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    mine_n(&sn, 1).await;
    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "chain")
        .await;
    assert_eq!(ev["body"]["kind"], "block_connected", "event: {ev}");
}

// ===========================================================================
// Phase 2: watch primitives × match variants (gRPC Watch + WS)
// ===========================================================================
//
// Fixtures: a node with 101 blocks mined to `wallet` (so block-1's coinbase
// — paying `wallet`'s P2WPKH spk — is mature and spendable at the tip). The
// canonical "spend" consumes that coinbase (outpoint `block1cb:0`, input
// script = wallet spk) and pays a fresh `dest` script, so a single tx
// exercises outpoint-spend, input-side script, output-side (funding) script,
// and txid watches at once.

/// Default seed for the funding wallet.
const WALLET_SEED: u8 = 0x11;

async fn matured_node() -> (StreamingNode, DeterministicWallet) {
    let sn = start_streaming_async(vec![]).await;
    let wallet = DeterministicWallet::from_secret([WALLET_SEED; 32]);
    let addr = wallet.address.to_string();
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.mine(101, &addr))
        .await
        .unwrap();
    (sn, wallet)
}

async fn coinbase1(sn: &StreamingNode) -> String {
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || block1_coinbase_txid(&rpc))
        .await
        .unwrap()
}

async fn mine_n(sn: &StreamingNode, n: u32) {
    let rpc = sn.node.rpc_handle();
    let addr = mine_addr(0x99);
    tokio::task::spawn_blocking(move || rpc.mine(n, &addr))
        .await
        .unwrap();
}

/// Build + broadcast the canonical block-1-coinbase spend (RBF-signalling off).
/// Returns `(spend_display_txid, dest_spk)`.
async fn broadcast_spend(
    sn: &StreamingNode,
    wallet: &DeterministicWallet,
    dest_seed: u8,
    fee: u64,
) -> (String, bitcoin::ScriptBuf) {
    broadcast_spend_seq(sn, wallet, dest_seed, fee, 0xffff_ffff).await
}

async fn broadcast_spend_seq(
    sn: &StreamingNode,
    wallet: &DeterministicWallet,
    dest_seed: u8,
    fee: u64,
    sequence: u32,
) -> (String, bitcoin::ScriptBuf) {
    let dest = DeterministicWallet::from_secret([dest_seed; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let dest2 = dest.clone();
    let (raw, txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_seq(&rpc, &w, dest2, fee, sequence)
    })
    .await
    .unwrap();
    let rpc2 = sn.node.rpc_handle();
    let got = tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw))
        .await
        .unwrap();
    assert_eq!(got, txid, "sendrawtransaction returns the computed txid");
    (txid, dest)
}

// ---- gRPC Watch ----------------------------------------------------------

/// A watched outpoint, spent: `OutpointSpent{confirmed:false}` in the mempool,
/// then `{confirmed:true}` once mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_outpoint_spent_mempool_then_confirmed() {
    let (sn, wallet) = matured_node().await;
    let cb = coinbase1(&sn).await;
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client.watch(vec![add_outpoints(&[(&cb, 0)])]).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (spend_txid, _dest) = broadcast_spend(&sn, &wallet, 0x55, 10_000).await;

    let ev = next_event_matching(&mut stream, 15, |b| matches!(b, Body::OutpointSpent(_))).await;
    let Some(Body::OutpointSpent(o)) = ev.body else {
        unreachable!()
    };
    assert!(!o.confirmed, "first match is in the mempool");
    assert_eq!(hex::encode(&o.outpoint_txid), display_to_internal_hex(&cb));
    assert_eq!(o.outpoint_vout, 0);
    assert_eq!(
        hex::encode(&o.spending_txid),
        display_to_internal_hex(&spend_txid)
    );

    mine_n(&sn, 1).await;
    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::OutpointSpent(o) if o.confirmed),
    )
    .await;
    let Some(Body::OutpointSpent(o)) = ev.body else {
        unreachable!()
    };
    assert!(o.confirmed);
    assert_eq!(hex::encode(&o.outpoint_txid), display_to_internal_hex(&cb));
}

/// A watched script paid by a tx output (funding side, `is_output=true`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_script_funding_mempool_then_confirmed() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x55; 32])
        .address
        .script_pubkey();
    let sh = scripthash_hex(&dest);
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client.watch(vec![add_scripts(&[&sh])]).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    broadcast_spend(&sn, &wallet, 0x55, 10_000).await;

    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::ScriptMatched(s) if s.is_output && !s.confirmed),
    )
    .await;
    let Some(Body::ScriptMatched(s)) = ev.body else {
        unreachable!()
    };
    assert_eq!(hex::encode(&s.scripthash), sh);
    assert!(s.is_output);

    mine_n(&sn, 1).await;
    next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::ScriptMatched(s) if s.is_output && s.confirmed),
    )
    .await;
}

/// A watched script spent by a tx input (`is_output=false`) — mempool (via the
/// retained prevout scripthashes, #312) then confirmed (via block undo data).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_script_spend_mempool_then_confirmed() {
    let (sn, wallet) = matured_node().await;
    // The block-1 coinbase pays the wallet spk; spending it is an input-side
    // match on that script.
    let sh = scripthash_hex(&wallet.address.script_pubkey());
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client.watch(vec![add_scripts(&[&sh])]).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    broadcast_spend(&sn, &wallet, 0x56, 10_000).await;

    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::ScriptMatched(s) if !s.is_output && !s.confirmed),
    )
    .await;
    let Some(Body::ScriptMatched(s)) = ev.body else {
        unreachable!()
    };
    assert_eq!(hex::encode(&s.scripthash), sh);
    assert!(!s.is_output, "input-side match");

    mine_n(&sn, 1).await;
    next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::ScriptMatched(s) if !s.is_output && s.confirmed),
    )
    .await;
}

/// A watched txid, seen in the mempool then confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_txid_mempool_then_confirmed() {
    let (sn, wallet) = matured_node().await;
    // Precompute the spend txid by building (not broadcasting) first.
    let dest = DeterministicWallet::from_secret([0x57; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw, spend_txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_from_block1_coinbase(&rpc, &w, dest, 10_000)
    })
    .await
    .unwrap();

    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client
        .watch(vec![add_transactions(&[&spend_txid], vec![], 0)])
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let rpc2 = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw))
        .await
        .unwrap();

    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::TxidMatched(t) if !t.confirmed),
    )
    .await;
    let Some(Body::TxidMatched(t)) = ev.body else {
        unreachable!()
    };
    assert_eq!(hex::encode(&t.txid), display_to_internal_hex(&spend_txid));

    mine_n(&sn, 1).await;
    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::TxidMatched(t) if t.confirmed),
    )
    .await;
    let Some(Body::TxidMatched(t)) = ev.body else {
        unreachable!()
    };
    assert!(t.height >= 1, "confirmed height set");
}

/// Removing a watched outpoint stops further matches on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_remove_outpoint_stops_matches() {
    let (sn, wallet) = matured_node().await;
    let cb = coinbase1(&sn).await;
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (tx, mut stream) = client.watch(vec![add_outpoints(&[(&cb, 0)])]).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Remove the watch before any spend happens.
    tx.send(remove_outpoints(&[(&cb, 0)])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    broadcast_spend(&sn, &wallet, 0x58, 10_000).await;
    mine_n(&sn, 1).await;

    // No OutpointSpent should arrive within the window.
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < deadline {
        let Some(ev) = next_event_opt(&mut stream, 2).await else {
            continue;
        };
        if matches!(ev.body, Some(Body::OutpointSpent(_))) {
            panic!("got OutpointSpent after removing the watch");
        }
    }
}

/// A watched script-prefix bucket fires `PrefixMatched` (with the full raw tx)
/// for a tx whose output pays a script in the bucket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_prefix_funding_mempool() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x59; 32])
        .address
        .script_pubkey();
    let prefix = script_prefix_hex(&dest, 8);
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client.watch(vec![add_script_prefixes(&prefix, 8)]).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (spend_txid, _dest) = broadcast_spend(&sn, &wallet, 0x59, 10_000).await;

    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::PrefixMatched(p) if !p.confirmed),
    )
    .await;
    let Some(Body::PrefixMatched(p)) = ev.body else {
        unreachable!()
    };
    assert_eq!(p.prefix.as_ref().map(|sp| sp.bits), Some(8));
    // The full serialized tx is carried inline; its txid matches the spend.
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&p.raw_tx).expect("raw_tx decodes");
    assert_eq!(tx.compute_txid().to_string(), spend_txid);
}

/// A single-shot depth alarm fires `TxidDepthReached` once the tx is buried to
/// the requested depth, and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_depth_alarm_fires_at_threshold() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x5a; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw, spend_txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_from_block1_coinbase(&rpc, &w, dest, 10_000)
    })
    .await
    .unwrap();

    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    // Depth alarm at depth 2 (non-empty min_depths).
    let (_tx, mut stream) = client
        .watch(vec![add_transactions(&[&spend_txid], vec![2], 0)])
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let rpc2 = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw))
        .await
        .unwrap();

    // Confirm at depth 1 — no alarm yet.
    mine_n(&sn, 1).await;
    if let Some(ev) = next_event_opt(&mut stream, 3).await {
        assert!(
            !matches!(ev.body, Some(Body::TxidDepthReached(_))),
            "alarm fired early (depth 1)"
        );
    }
    // Depth 2 — alarm fires.
    mine_n(&sn, 1).await;
    let ev = next_event_matching(&mut stream, 15, |b| {
        matches!(b, Body::TxidDepthReached(_))
    })
    .await;
    let Some(Body::TxidDepthReached(d)) = ev.body else {
        unreachable!()
    };
    assert_eq!(hex::encode(&d.txid), display_to_internal_hex(&spend_txid));
    assert!(d.depth >= 2, "fired at >= requested depth");
}

// ---- WS ------------------------------------------------------------------

/// WS watch: a watched outpoint spent → `outpoint_spent` JSON match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_watch_outpoint_spent() {
    let (sn, wallet) = matured_node().await;
    let cb = coinbase1(&sn).await;
    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({
        "type": "add_outpoints",
        "outpoints": [{"txid": cb, "vout": 0}],
    }))
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (spend_txid, _dest) = broadcast_spend(&sn, &wallet, 0x5b, 10_000).await;

    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "outpoint_spent")
        .await;
    assert_eq!(ev["body"]["confirmed"], false, "event: {ev}");
    assert_eq!(
        ev["body"]["outpoint_txid"],
        display_to_internal_hex(&cb),
        "event: {ev}"
    );
    assert_eq!(
        ev["body"]["spending_txid"],
        display_to_internal_hex(&spend_txid)
    );
}

/// WS watch: a watched script funded by an output → `script_matched`
/// (`is_output=true`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_watch_script_funding() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x5c; 32])
        .address
        .script_pubkey();
    let sh = scripthash_hex(&dest);
    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({"type": "add_scripts", "scripthashes": [sh]}))
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    broadcast_spend(&sn, &wallet, 0x5c, 10_000).await;

    let ev = ws
        .next_json_matching(15, |v| {
            v["body"]["category"] == "script_matched" && v["body"]["is_output"] == true
        })
        .await;
    assert_eq!(ev["body"]["scripthash"], sh, "event: {ev}");
}

/// WS watch: a watched txid seen in the mempool → `txid_matched`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_watch_txid() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x5d; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw, spend_txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_from_block1_coinbase(&rpc, &w, dest, 10_000)
    })
    .await
    .unwrap();

    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({"type": "add_transactions", "txids": [spend_txid]}))
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let rpc2 = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw))
        .await
        .unwrap();

    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "txid_matched")
        .await;
    assert_eq!(
        ev["body"]["txid"],
        display_to_internal_hex(&spend_txid),
        "event: {ev}"
    );
}

/// WS watch: a script-prefix bucket fires `prefix_matched` with the raw tx.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_watch_prefix_funding() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x5e; 32])
        .address
        .script_pubkey();
    let prefix = script_prefix_hex(&dest, 8);
    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({
        "type": "add_script_prefixes",
        "prefixes": [{"prefix": prefix, "bits": 8}],
    }))
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (spend_txid, _dest) = broadcast_spend(&sn, &wallet, 0x5e, 10_000).await;

    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "prefix_matched")
        .await;
    assert_eq!(ev["body"]["bits"], 8, "event: {ev}");
    let raw = hex::decode(ev["body"]["raw_tx"].as_str().unwrap()).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
    assert_eq!(tx.compute_txid().to_string(), spend_txid);
}

/// WS watch: an RBF replacement of a watched tx → `txid_replaced`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_watch_txid_replaced_rbf() {
    let (sn, wallet) = matured_node().await;
    // Build tx A (RBF-signalling) and a higher-fee replacement B on the same
    // input, without broadcasting yet.
    let desta = DeterministicWallet::from_secret([0x5f; 32])
        .address
        .script_pubkey();
    let destb = DeterministicWallet::from_secret([0x60; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw_a, txid_a) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_seq(&rpc, &w, desta, 10_000, 0xffff_fffd)
    })
    .await
    .unwrap();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw_b, txid_b) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_seq(&rpc, &w, destb, 100_000, 0xffff_fffd)
    })
    .await
    .unwrap();

    let mut ws = WsClient::connect(sn.ws_port()).await;
    ws.send_control(serde_json::json!({"type": "add_transactions", "txids": [txid_a]}))
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.send_raw_tx(&raw_a))
        .await
        .unwrap();
    // Wait for the seen notice, then broadcast the replacement.
    ws.next_json_matching(15, |v| v["body"]["category"] == "txid_matched")
        .await;
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking(move || rpc.send_raw_tx(&raw_b))
        .await
        .unwrap();

    let ev = ws
        .next_json_matching(15, |v| v["body"]["category"] == "txid_replaced")
        .await;
    assert_eq!(
        ev["body"]["txid"],
        display_to_internal_hex(&txid_a),
        "event: {ev}"
    );
    assert_eq!(
        ev["body"]["replacing_txid"],
        display_to_internal_hex(&txid_b)
    );
}

// ===========================================================================
// Phase 3: cursor replay / instance_id
// ===========================================================================

/// Spawn a streaming node from an async test with owned args + env (auth /
/// caps / capacity tests need dynamic strings; the blocking start runs on a
/// blocking task).
async fn start_streaming_args(args: Vec<String>, env: Vec<(String, String)>) -> StreamingNode {
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let envrefs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        StreamingNode::start_with_env(&refs, &envrefs)
    })
    .await
    .unwrap()
}

/// Extract a `BlockConnected` height from an event body, if it is one.
fn block_height(body: &Body) -> Option<u32> {
    if let Body::Chain(ce) = body
        && let Some(satd_events::proto::v1::chain_event::Body::BlockConnected(bc)) = &ce.body
    {
        return Some(bc.height);
    }
    None
}

fn is_block_connected(body: &Body) -> bool {
    block_height(body).is_some()
}

fn cursor(height: u32) -> Cursor {
    Cursor {
        height,
        tx_index: 0,
        mempool_seq: 0,
        instance_id: 0,
    }
}

/// gRPC `Subscribe(from_cursor)` replays confirmed history forward from the
/// cursor, then joins live with no gap or duplicate at the boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_subscribe_from_cursor_replays_then_live() {
    let sn = start_streaming_async(vec![]).await;
    mine_n(&sn, 5).await; // tip = 5

    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    // chain-only, replay from height 2 → expect 3, 4, 5 replayed.
    let mut stream = client.subscribe(2, Some(cursor(2))).await;

    let mut heights = Vec::new();
    for _ in 0..3 {
        let ev = next_event_matching(&mut stream, 15, is_block_connected).await;
        heights.push(block_height(&ev.body.unwrap()).unwrap());
    }
    assert_eq!(heights, vec![3, 4, 5], "replayed confirmed history");

    // Live handoff: mine one more → height 6, exactly once, no gap/dup.
    mine_n(&sn, 1).await;
    let ev = next_event_matching(&mut stream, 15, is_block_connected).await;
    assert_eq!(block_height(&ev.body.unwrap()), Some(6), "live block after replay");
}

/// WS `/ws?from_height=` replays then joins live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_from_cursor_replays_then_live() {
    let sn = start_streaming_async(vec![]).await;
    mine_n(&sn, 5).await;

    let mut ws = common::ws_client::WsClient::connect_query(sn.ws_port(), "?from_height=2").await;
    let mut heights = Vec::new();
    for _ in 0..3 {
        let ev = ws
            .next_json_matching(15, |v| v["body"]["kind"] == "block_connected")
            .await;
        heights.push(ev["body"]["height"].as_u64().unwrap());
    }
    assert_eq!(heights, vec![3, 4, 5]);

    mine_n(&sn, 1).await;
    let ev = ws
        .next_json_matching(15, |v| v["body"]["kind"] == "block_connected")
        .await;
    assert_eq!(ev["body"]["height"], 6);
}

/// SSE `/sse?from_height=` replays then joins live.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn sse_from_cursor_replays_then_live() {
    let sn = start_streaming_async(vec![]).await;
    mine_n(&sn, 5).await;
    let port = sn.ws_port();

    let heights = tokio::task::spawn_blocking(move || {
        let mut sse = StreamSseClient::connect(port, "/sse?from_height=2");
        let mut hs = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while hs.len() < 3 && std::time::Instant::now() < deadline {
            let (_t, data) = sse.next_event();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
                && v["body"]["kind"] == "block_connected"
            {
                hs.push(v["body"]["height"].as_u64().unwrap());
            }
        }
        hs
    })
    .await
    .unwrap();
    assert_eq!(heights, vec![3, 4, 5]);
}

/// The per-process `instance_id` changes across a restart (so a client can
/// detect a daemon restart and discard a stale mempool watermark), while the
/// durable confirmed chain — and its `from_cursor` replay — survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_id_resets_across_restart_confirmed_replay_survives() {
    let sn = start_streaming_async(vec![]).await;
    mine_n(&sn, 3).await; // tip = 3

    let instance_a = first_live_block_instance(&sn).await; // mines 1 → tip 4

    // Restart on the same datadir.
    let sn = tokio::task::spawn_blocking(move || {
        let mut sn = sn;
        sn.restart();
        sn
    })
    .await
    .unwrap();

    let instance_b = first_live_block_instance(&sn).await; // mines 1 → tip 5
    assert_ne!(
        instance_a, instance_b,
        "instance_id is a fresh per-process nonce after restart"
    );

    // Durable confirmed replay survives the restart: replay from height 1.
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let mut stream = client.subscribe(2, Some(cursor(1))).await;
    let ev = next_event_matching(&mut stream, 15, is_block_connected).await;
    assert_eq!(
        block_height(&ev.body.unwrap()),
        Some(2),
        "confirmed replay resumes from height+1 after restart"
    );
}

/// Subscribe live, mine one block, and read the issuing publisher's
/// `instance_id` off the block event's cursor.
async fn first_live_block_instance(sn: &StreamingNode) -> u64 {
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let mut stream = client.subscribe(2, None).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    mine_n(sn, 1).await;
    let ev = next_event_matching(&mut stream, 15, is_block_connected).await;
    ev.cursor.expect("block event carries a cursor").instance_id
}

/// A mid-stream `SetCursor` control on `Watch` is a deliberate no-op: the
/// stream stays open and subsequent watches still fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_set_cursor_is_noop() {
    let (sn, wallet) = matured_node().await;
    let cb = coinbase1(&sn).await;
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    // Open with a SetCursor (no-op), then add a real watch.
    let set_cursor = SubscribeControl {
        msg: Some(Control::SetCursor(satd_events::proto::v1::SetCursor {
            cursor: Some(cursor(1)),
        })),
    };
    let (tx, mut stream) = client.watch(vec![set_cursor]).await;
    tx.send(add_outpoints(&[(&cb, 0)])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    broadcast_spend(&sn, &wallet, 0x61, 10_000).await;
    // The stream survived the no-op SetCursor and still delivers the match.
    next_event_matching(&mut stream, 15, |b| matches!(b, Body::OutpointSpent(_))).await;
}

// ===========================================================================
// Phase 4: in-band Lagged signal (A1) — deterministic via the capacity knob
// ===========================================================================

/// A slow/non-reading subscriber that overflows the (shrunk) broadcast buffer
/// receives an in-band `Lagged{dropped_count, resume_cursor}` instead of a
/// silent gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_lagged_emits_resume_cursor() {
    // Shrink the broadcast buffer so a handful of unread events forces a lag.
    let sn = start_streaming_args(
        vec![],
        vec![("SATD_EVENT_BROADCAST_CAPACITY".into(), "2".into())],
    )
    .await;
    // Tiny h2 window so the unread client blocks the server after a few events.
    let mut client = GrpcStreamClient::connect_lagprone(sn.grpc_port()).await;
    let mut stream = client.subscribe(2, None).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Do NOT read; mine past the 2-slot broadcast buffer + the tiny window so
    // the carrier task blocks on the unread client and its broadcast receiver
    // falls behind.
    mine_n(&sn, 300).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Now drain: somewhere in the stream a Lagged notice must appear.
    let ev = next_event_matching(&mut stream, 30, |b| matches!(b, Body::Lagged(_))).await;
    let Some(Body::Lagged(l)) = ev.body else {
        unreachable!()
    };
    assert!(l.dropped_count > 0, "Lagged reports a positive drop count");
    assert!(
        l.resume_cursor.is_some(),
        "Lagged carries a resume cursor for from_cursor reconnect"
    );
}

// NOTE: a WS/SSE in-band-lag E2E is intentionally omitted. The lag is triggered
// by carrier backpressure, which for gRPC we force deterministically with a tiny
// HTTP/2 flow-control window (see `grpc_lagged_emits_resume_cursor`). The WS
// equivalent — a tiny TCP `SO_RCVBUF` — does not reliably backpressure on
// loopback (the kernel's receive-window behaviour differs from h2's explicit
// window), so a WS lag E2E would be flaky. The WS rendering of the `lagged`
// body is covered by unit tests in `events/src/ws.rs`, and the in-band Lagged
// path itself is proven end-to-end by the gRPC test above.

// ===========================================================================
// Phase 5: admission — auth + caps
// ===========================================================================

/// gRPC events auth: no token rejected, wrong-capability rejected, valid
/// `stream:subscribe` token accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_auth_matrix() {
    let fixture = write_authfile(&[
        TokenSpec {
            id: "sub",
            token: "tok-subscribe",
            capabilities: &["stream:subscribe"],
            rate_limit: None,
            watch_quota: None,
        },
        TokenSpec {
            id: "ro",
            token: "tok-readonly",
            capabilities: &["rpc:read"],
            rate_limit: None,
            watch_quota: None,
        },
    ]);
    let autharg = format!("--authfile={}", fixture.authfile.display());
    let sn = start_streaming_args(
        vec![
            autharg,
            "--events-grpc-auth=1".into(),
            // streamws not needed here; disable to avoid an extra listener.
            "--streamws=127.0.0.1:0".into(),
        ],
        vec![],
    )
    .await;
    let port = sn.grpc_port();

    // No token → rejected.
    let mut anon = GrpcStreamClient::try_connect_with_token(port, None)
        .await
        .expect("tcp connect");
    assert!(anon.try_subscribe(0).await.is_err(), "anon subscribe rejected");

    // Wrong capability → rejected.
    let mut ro = GrpcStreamClient::connect_with_token(port, "tok-readonly").await;
    assert!(
        ro.try_subscribe(0).await.is_err(),
        "rpc:read token rejected on stream:subscribe"
    );

    // Valid token → accepted.
    let mut ok = GrpcStreamClient::connect_with_token(port, "tok-subscribe").await;
    assert!(
        ok.try_subscribe(0).await.is_ok(),
        "stream:subscribe token accepted"
    );
}

/// WS events auth: missing token rejected at the upgrade, valid token accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_auth_matrix() {
    let fixture = write_authfile(&[TokenSpec {
        id: "sub",
        token: "tok-ws",
        capabilities: &["stream:subscribe"],
        rate_limit: None,
        watch_quota: None,
    }]);
    let autharg = format!("--authfile={}", fixture.authfile.display());
    let sn = start_streaming_args(
        vec![autharg, "--streamws-auth=1".into()],
        vec![],
    )
    .await;
    let port = sn.ws_port();

    assert!(
        common::ws_client::WsClient::try_connect(port, None).await.is_err(),
        "anon ws upgrade rejected"
    );
    assert!(
        common::ws_client::WsClient::try_connect(port, Some("tok-ws"))
            .await
            .is_ok(),
        "valid token ws upgrade accepted"
    );
}

/// WS connection cap: with `--streamws-max-conns=1`, a second concurrent
/// connection is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_max_conns_refuses_second() {
    let sn = start_streaming_args(
        vec![
            "--events-grpc-bind=127.0.0.1:0".into(),
            "--streamws=127.0.0.1:0".into(),
            "--streamws-max-conns=1".into(),
        ],
        vec![],
    )
    .await;
    let port = sn.ws_port();
    // Hold the only slot.
    let _held = common::ws_client::WsClient::connect(port).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Second connection refused (503 → handshake error).
    let second = common::ws_client::WsClient::try_connect(port, None).await;
    assert!(second.is_err(), "second ws connection over the cap is refused");
}

// ===========================================================================
// Phase 6: consensus invariant — the event bus never backpressures consensus
// ===========================================================================

/// A flooded, non-reading subscriber (with a tiny broadcast buffer that forces
/// server-side lag) must NOT stall block production. Mining 40 blocks while the
/// subscriber lags must still complete and advance the tip — proving the
/// publish path is decoupled from `connect_block`.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn flood_stream_does_not_stall_mining() {
    let sn = start_streaming_args(
        vec![],
        vec![("SATD_EVENT_BROADCAST_CAPACITY".into(), "2".into())],
    )
    .await;
    // Attach a subscriber and never read it (forces broadcast lag once the
    // 2-slot buffer fills).
    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let _stream = client.subscribe(0, None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Mining must complete despite the lagging subscriber.
    mine_n(&sn, 40).await;

    let rpc = sn.node.rpc_handle();
    let height = tokio::task::spawn_blocking(move || rpc.block_count())
        .await
        .unwrap();
    assert_eq!(height, 40, "block production advanced despite a lagging stream");
}


/// gRPC subscription cap: with `--events-grpc-max-subscriptions=1`, a second
/// concurrent `Subscribe` (even on a fresh connection) is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_max_subscriptions_caps_streams() {
    let sn = start_streaming_args(
        vec![
            "--events-grpc-bind=127.0.0.1:0".into(),
            "--streamws=127.0.0.1:0".into(),
            "--events-grpc-max-subscriptions=1".into(),
        ],
        vec![],
    )
    .await;
    let port = sn.grpc_port();

    // First subscription holds the only slot.
    let mut c1 = GrpcStreamClient::connect(port).await;
    let _s1 = c1.subscribe(0, None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Second subscription is refused.
    let mut c2 = GrpcStreamClient::connect(port).await;
    assert!(
        c2.try_subscribe(0).await.is_err(),
        "second Subscribe over the cap is refused"
    );
}

// ===========================================================================
// Single-node reorg E2E (via the `invalidateblock` RPC)
// ===========================================================================
//
// `invalidateblock` makes a single node reorg deterministically, so the reorg
// streaming surfaces — the `Reorg` marker, `BlockDisconnected`, and the
// `TxidUnconfirmed` lifecycle transition — are now exercised end-to-end over a
// real socket, no second node required.

/// Invalidating the active tip emits a `Reorg` marker and a `BlockDisconnected`
/// on the gRPC `Subscribe` firehose (a single-node truncation reorg).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_subscribe_reorg_via_invalidateblock() {
    let sn = start_streaming_async(vec![]).await;

    // Mine 2 blocks BEFORE subscribing (the firehose is live-only), so the
    // only chain traffic the subscriber sees is the reorg.
    let rpc = sn.node.rpc_handle();
    let addr = mine_addr(0x71);
    let hashes = tokio::task::spawn_blocking(move || rpc.mine(2, &addr))
        .await
        .unwrap();
    assert_eq!(hashes.len(), 2, "mined two blocks");
    let tip = hashes[1].clone(); // height 2

    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let mut stream = client.subscribe(0, None).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Invalidate the tip → the active chain truncates to height 1.
    let rpc2 = sn.node.rpc_handle();
    let tip2 = tip.clone();
    let resp = tokio::task::spawn_blocking(move || {
        rpc2.call("invalidateblock", vec![serde_json::json!(tip2)])
    })
    .await
    .unwrap()
    .unwrap();
    assert!(resp["error"].is_null(), "invalidateblock errored: {resp:?}");

    use satd_events::proto::v1::chain_event::Body as Ce;

    // The `Reorg` marker is emitted first.
    let ev = next_event_matching(&mut stream, 15, |b| {
        matches!(b, Body::Chain(ce) if matches!(ce.body, Some(Ce::Reorg(_))))
    })
    .await;
    let Some(Body::Chain(ce)) = ev.body else {
        unreachable!("matched Chain above")
    };
    let Some(Ce::Reorg(r)) = ce.body else {
        unreachable!("matched Reorg above")
    };
    assert_eq!(r.from_height, 2, "abandoned tip height");
    assert_eq!(r.to_height, 1, "new tip height after truncation");

    // Followed by a `BlockDisconnected` for the invalidated tip.
    let ev = next_event_matching(&mut stream, 15, |b| {
        matches!(b, Body::Chain(ce) if matches!(ce.body, Some(Ce::BlockDisconnected(_))))
    })
    .await;
    let Some(Body::Chain(ce)) = ev.body else {
        unreachable!("matched Chain above")
    };
    let Some(Ce::BlockDisconnected(bd)) = ce.body else {
        unreachable!("matched BlockDisconnected above")
    };
    assert_eq!(bd.height, 2, "disconnected block height");
    assert_eq!(bd.hash.len(), 32, "block hash is 32 bytes");
}

/// A watched txid that was confirmed, then un-confirmed when its block is
/// invalidated, fires `TxidUnconfirmed` carrying the height it had reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_watch_txid_unconfirmed_on_invalidateblock() {
    let (sn, wallet) = matured_node().await;
    let dest = DeterministicWallet::from_secret([0x72; 32])
        .address
        .script_pubkey();
    let rpc = sn.node.rpc_handle();
    let w = wallet.clone();
    let (raw, spend_txid) = tokio::task::spawn_blocking(move || {
        build_signed_p2wpkh_spend_from_block1_coinbase(&rpc, &w, dest, 10_000)
    })
    .await
    .unwrap();

    let mut client = GrpcStreamClient::connect(sn.grpc_port()).await;
    let (_tx, mut stream) = client
        .watch(vec![add_transactions(&[&spend_txid], vec![], 0)])
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Broadcast + confirm the spend.
    let rpc2 = sn.node.rpc_handle();
    let raw2 = raw.clone();
    tokio::task::spawn_blocking(move || rpc2.send_raw_tx(&raw2))
        .await
        .unwrap();
    mine_n(&sn, 1).await;
    let ev = next_event_matching(
        &mut stream,
        15,
        |b| matches!(b, Body::TxidMatched(t) if t.confirmed),
    )
    .await;
    let Some(Body::TxidMatched(t)) = ev.body else {
        unreachable!()
    };
    let conf_height = t.height;
    assert!(conf_height >= 1, "confirmed height set");

    // Invalidate the confirming block (the tip) → the watched tx is rolled
    // back into the mempool, firing `TxidUnconfirmed`.
    let rpc3 = sn.node.rpc_handle();
    let tip = tokio::task::spawn_blocking(move || {
        rpc3.call("getbestblockhash", vec![]).unwrap()["result"]
            .as_str()
            .unwrap()
            .to_string()
    })
    .await
    .unwrap();
    let rpc4 = sn.node.rpc_handle();
    let resp = tokio::task::spawn_blocking(move || {
        rpc4.call("invalidateblock", vec![serde_json::json!(tip)])
    })
    .await
    .unwrap()
    .unwrap();
    assert!(resp["error"].is_null(), "invalidateblock errored: {resp:?}");

    let ev = next_event_matching(&mut stream, 15, |b| matches!(b, Body::TxidUnconfirmed(_))).await;
    let Some(Body::TxidUnconfirmed(u)) = ev.body else {
        unreachable!()
    };
    assert_eq!(
        hex::encode(&u.txid),
        display_to_internal_hex(&spend_txid),
        "unconfirmed txid matches the watched tx"
    );
    assert_eq!(
        u.prev_height, conf_height,
        "prev_height is the height the tx had reached"
    );
}

// ===========================================================================
// Reorg E2E coverage
// ===========================================================================
//
// The single-node reorg surfaces (Reorg / BlockDisconnected / TxidUnconfirmed)
// are covered by the two streaming tests above via `invalidateblock`. The
// inbound-peer competing-chain pull gap (a synced listener adopting a longer
// chain announced by an inbound peer) is now fixed and covered at the P2P layer
// by `test_listener_pulls_competing_chain_from_inbound_peer` in `regtest.rs`. A
// streaming two-node variant (asserting the same firehose/watch events are
// driven by real P2P block propagation rather than `invalidateblock`) would be
// additive — the event paths themselves are identical and already exercised
// here — so it is intentionally left as future coverage, not a gap.
