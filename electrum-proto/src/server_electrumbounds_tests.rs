//! The per-request timeout and where a request's work runs.
//!
//! Handlers are synchronous: they read RocksDB and the flat files inline. A
//! handler that ran on the connection task held a runtime worker for as long
//! as it took, and the timeout wrapped around it could never fire, because
//! the dispatch finished on its first poll. These tests use a dispatch that
//! sleeps the thread, which is what a long index read looks like to the
//! runtime.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::*;

/// How long the `slow` method holds its thread.
const SLOW: Duration = Duration::from_millis(1_500);

/// `slow` sleeps the thread for [`SLOW`], then answers; every other method
/// answers at once.
fn slow_factory() -> ConnectionFactory {
    Arc::new(|_max_subs: usize| {
        let (_tx, rx) = mpsc::channel(1);
        let dispatch: BoxedDispatch = Box::new(|req: Request| {
            if req.method == "slow" {
                std::thread::sleep(SLOW);
            }
            Response::success(req.id.clone().unwrap_or(Value::Null), json!(req.method))
        });
        (dispatch, rx)
    })
}

fn config(request_timeout: Duration, max_conns: usize) -> ElectrumConfig {
    ElectrumConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        max_conns,
        request_timeout,
        ..Default::default()
    }
}

async fn send(stream: &mut BufReader<TcpStream>, id: u64, method: &str) {
    let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": []}).to_string();
    let w = stream.get_mut();
    w.write_all(line.as_bytes()).await.unwrap();
    w.write_all(b"\n").await.unwrap();
    w.flush().await.unwrap();
}

/// The next line from the server, or `None` at EOF.
async fn recv(stream: &mut BufReader<TcpStream>) -> Option<Value> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read_line(&mut line))
        .await
        .expect("no line or EOF within 10s")
        .unwrap_or(0);
    (n > 0).then(|| serde_json::from_str(line.trim_end()).expect("a JSON line"))
}

async fn connect(addr: SocketAddr) -> BufReader<TcpStream> {
    BufReader::new(TcpStream::connect(addr).await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_past_the_timeout_is_answered_with_an_error_and_the_connection_closed() {
    let server = ElectrumServer::bind_with_factory(config(Duration::from_millis(300), 4), slow_factory())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (sd_tx, sd_rx) = watch::channel(false);
    let join = tokio::spawn(server.serve(sd_rx));

    // A request inside the timeout is answered and the connection stays open.
    let mut fast = connect(addr).await;
    send(&mut fast, 1, "server.ping").await;
    assert_eq!(recv(&mut fast).await.expect("answer")["result"], "server.ping");

    let mut conn = connect(addr).await;
    let started = Instant::now();
    send(&mut conn, 2, "slow").await;
    let answer = recv(&mut conn).await.expect("an answer to the slow request");
    let waited = started.elapsed();
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("timed out")),
        "expected the timeout error, got {answer}"
    );
    assert!(
        waited < SLOW - Duration::from_millis(300),
        "the timeout answer took {waited:?}; it must not wait for the handler ({SLOW:?})"
    );
    // The handler's work cannot be stopped and the connection's state is
    // still inside it, so the connection ends after the error.
    assert_eq!(recv(&mut conn).await, None, "the connection must close after a timeout");

    // The other connection is unaffected.
    send(&mut fast, 3, "server.ping").await;
    assert_eq!(recv(&mut fast).await.expect("answer")["id"], 3);

    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// A blocking client on its own OS thread, so its clock and its reads do not
/// depend on the runtime under test having a free worker.
struct SyncClient(std::io::BufReader<std::net::TcpStream>);

impl SyncClient {
    fn connect(addr: SocketAddr) -> Self {
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        Self(std::io::BufReader::new(stream))
    }

    fn send(&mut self, id: u64, method: &str) {
        use std::io::Write as _;
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": []}).to_string();
        let w = self.0.get_mut();
        w.write_all(line.as_bytes()).unwrap();
        w.write_all(b"\n").unwrap();
    }

    fn recv(&mut self) -> Value {
        use std::io::BufRead as _;
        let mut line = String::new();
        let n = self.0.read_line(&mut line).expect("a line within 10s");
        assert!(n > 0, "EOF before an answer");
        serde_json::from_str(line.trim_end()).expect("a JSON line")
    }
}

/// One runtime worker, as on a small box where `--api-threads` is 1 or 2: a
/// slow request on one connection must not hold the worker that every other
/// connection (and Esplora, gRPC and `/metrics`) runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_slow_request_does_not_hold_up_other_connections() {
    let server = ElectrumServer::bind_with_factory(config(Duration::from_secs(30), 4), slow_factory())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (sd_tx, sd_rx) = watch::channel(false);
    let join = tokio::spawn(server.serve(sd_rx));

    let client = std::thread::spawn(move || {
        let mut slow = SyncClient::connect(addr);
        slow.send(1, "slow");
        // Let the slow request reach its handler.
        std::thread::sleep(Duration::from_millis(200));

        let mut other = SyncClient::connect(addr);
        let started = Instant::now();
        other.send(2, "server.ping");
        let answer = other.recv();
        let waited = started.elapsed();
        assert_eq!(answer["id"], 2);
        assert!(
            waited < Duration::from_millis(700),
            "a ping waited {waited:?} behind another connection's slow request"
        );

        // Slow but inside the timeout: answered normally, connection still usable.
        assert_eq!(slow.recv()["result"], "slow");
        slow.send(3, "server.ping");
        assert_eq!(slow.recv()["id"], 3);
    });
    let outcome = tokio::task::spawn_blocking(move || client.join()).await.unwrap();

    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A timed-out request's work keeps running on its thread. Its connection
/// gives up its slot only when that work ends, so a client that reconnects
/// after every timeout cannot pile up more running handlers than
/// `--electrummaxconns`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_request_keeps_its_connection_slot_until_its_work_ends() {
    let server = ElectrumServer::bind_with_factory(config(Duration::from_millis(200), 1), slow_factory())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (sd_tx, sd_rx) = watch::channel(false);
    let join = tokio::spawn(server.serve(sd_rx));

    let started = Instant::now();
    let mut first = connect(addr).await;
    send(&mut first, 1, "slow").await;
    let answer = recv(&mut first).await.expect("the timeout answer");
    assert!(answer["error"]["message"].as_str().is_some_and(|m| m.contains("timed out")));
    assert_eq!(recv(&mut first).await, None);

    // The handler is still sleeping: the only slot is still taken.
    assert!(started.elapsed() < SLOW - Duration::from_millis(400));
    let mut refused = connect(addr).await;
    let answer = recv(&mut refused).await.expect("the capacity answer");
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("capacity")),
        "a new connection was let in while the timed-out work still ran: {answer}"
    );

    // Once the work has ended the slot is free again.
    tokio::time::sleep((SLOW + Duration::from_millis(300)).saturating_sub(started.elapsed())).await;
    let mut admitted = connect(addr).await;
    send(&mut admitted, 2, "server.ping").await;
    assert_eq!(recv(&mut admitted).await.expect("answer")["id"], 2);

    sd_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}
