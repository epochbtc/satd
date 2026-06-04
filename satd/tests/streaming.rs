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

use common::grpc_client::{next_event_matching, Body, GrpcStreamClient};
use common::ws_client::{StreamSseClient, WsClient};
use common::{DeterministicWallet, StreamingNode};
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
