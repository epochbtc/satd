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
    next_event_opt, remove_outpoints, Body, GrpcStreamClient,
};
use common::ws_client::{StreamSseClient, WsClient};
use common::{
    block1_coinbase_txid, build_signed_p2wpkh_spend_from_block1_coinbase,
    build_signed_p2wpkh_spend_seq, display_to_internal_hex, scripthash_hex, script_prefix_hex,
    DeterministicWallet, StreamingNode,
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
