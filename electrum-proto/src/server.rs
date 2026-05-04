//! Electrum TCP server: accept loop, per-connection task, graceful
//! shutdown. TLS lands in PR-5.
//!
//! Lifecycle (matches the events stack and Esplora wiring):
//! 1. [`ElectrumServer::bind`] — pre-binds the [`TcpListener`] so a
//!    bind failure becomes a startup-fatal error rather than a logged
//!    warning in a detached task.
//! 2. [`ElectrumServer::serve`] — accepts connections, spawns one
//!    task per connection. Bounded by an [`Arc<Semaphore>`] sized
//!    from `config.max_conns`; a connection past the cap is rejected
//!    by writing one `JsonRpcError` and closing.
//! 3. Shutdown: a `watch::Receiver<bool>` flip to `true` closes the
//!    accept loop and signals every per-connection task to drain its
//!    in-flight request and exit.
//!
//! Per-connection state (subscriptions + notification fan-in) lives
//! in a [`ConnectionFactory`] callback that the server invokes once
//! per accepted connection. Production wires the factory in
//! [`Self::bind`] from an [`ElectrumState`]; tests pass an arbitrary
//! factory via [`Self::bind_with_factory`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};

use crate::config::ElectrumConfig;
use crate::dispatch::{Notification, Request, Response, dispatch_with_subscriptions};
use crate::error::JsonRpcError;
use crate::rpc::{FramingError, MAX_LINE_BYTES, read_line_bounded, write_line};
use crate::state::ElectrumState;
use crate::subscribe::{NOTIFY_CHANNEL_CAP, Subscriptions};

#[derive(Debug, Error)]
pub enum ElectrumServerError {
    #[error("bind to {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
}

/// Boxed sync dispatcher owned by a single connection. `FnMut` so the
/// closure can hold mutable per-connection state ([`Subscriptions`]).
pub type BoxedDispatch = Box<dyn FnMut(Request) -> Response + Send + 'static>;

/// Factory invoked once per accepted connection. Returns a fresh
/// dispatch closure plus the receiver end of the connection's
/// notification fan-in (subscription-pushed JSON lines).
pub type ConnectionFactory =
    Arc<dyn Fn(usize) -> (BoxedDispatch, mpsc::Receiver<String>) + Send + Sync + 'static>;

/// Production [`ConnectionFactory`]: wraps an [`ElectrumState`] in
/// per-connection [`Subscriptions`] + the subscription-aware
/// dispatcher.
pub fn state_connection_factory(state: Arc<ElectrumState>) -> ConnectionFactory {
    Arc::new(move |max_subs_per_conn: usize| {
        let (notify_tx, notify_rx) = mpsc::channel(NOTIFY_CHANNEL_CAP);
        let mut subs = Subscriptions::new(notify_tx, max_subs_per_conn);
        let st = state.clone();
        let chain = state.chain.clone();
        let extras = state.electrum_extras.clone();
        let dispatch: BoxedDispatch = Box::new(move |req: Request| {
            dispatch_with_subscriptions(&st, &mut subs, chain.as_ref(), extras.clone(), req)
        });
        (dispatch, notify_rx)
    })
}

/// Pre-bound Electrum TCP server. Construct via [`Self::bind`]; run
/// via [`Self::serve`] until the supplied shutdown watch flips.
pub struct ElectrumServer {
    listener: TcpListener,
    factory: ConnectionFactory,
    config: Arc<ElectrumConfig>,
    semaphore: Arc<Semaphore>,
}

impl ElectrumServer {
    /// Convenience: bind + wire production state-backed dispatch +
    /// per-connection subscriptions.
    pub async fn bind(
        config: ElectrumConfig,
        state: Arc<ElectrumState>,
    ) -> Result<Self, ElectrumServerError> {
        let factory = state_connection_factory(state);
        Self::bind_with_factory(config, factory).await
    }

    /// Bind with an explicit per-connection factory. Used by tests
    /// that don't have a real `ElectrumState`.
    pub async fn bind_with_factory(
        config: ElectrumConfig,
        factory: ConnectionFactory,
    ) -> Result<Self, ElectrumServerError> {
        let listener =
            TcpListener::bind(config.bind)
                .await
                .map_err(|source| ElectrumServerError::Bind {
                    addr: config.bind,
                    source,
                })?;
        let semaphore = Arc::new(Semaphore::new(config.max_conns.max(1)));
        Ok(Self {
            listener,
            factory,
            config: Arc::new(config),
            semaphore,
        })
    }

    /// Returns the bound address. Useful in tests where `bind` was
    /// `127.0.0.1:0` and the OS picked the port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the accept loop until `shutdown` flips to `true`. Spawns
    /// one task per connection; per-connection tasks observe the
    /// same shutdown watch and exit cleanly.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            bind = %self.config.bind,
            max_conns = self.config.max_conns,
            "Electrum server listening"
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("Electrum server shutdown signal received");
                    return;
                }
                accept = self.listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(error = %e, "Electrum accept error");
                            continue;
                        }
                    };
                    let permit = self.semaphore.clone().try_acquire_owned();
                    match permit {
                        Ok(permit) => {
                            tracing::debug!(peer = %peer, "Electrum connection accepted");
                            let factory = self.factory.clone();
                            let config = self.config.clone();
                            let conn_shutdown = shutdown.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let (dispatch, notify_rx) = factory(config.max_subs_per_conn);
                                if let Err(e) = handle_connection(stream, dispatch, notify_rx, config, conn_shutdown).await {
                                    tracing::debug!(peer = %peer, error = %e, "Electrum connection ended");
                                }
                            });
                        }
                        Err(_) => {
                            tracing::warn!(
                                peer = %peer,
                                "Electrum at-capacity rejection ({} max)",
                                self.config.max_conns
                            );
                            tokio::spawn(async move {
                                let _ = reject_overflow(stream).await;
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single connection until EOF, error, or shutdown.
///
/// Read loop is bounded:
/// - per-line size: [`MAX_LINE_BYTES`] (1 MiB)
/// - per-server connection count: enforced by the caller's semaphore
///   permit (not visible inside this fn)
///
/// Three select arms:
/// - `shutdown` — flipped from outside, returns immediately.
/// - `notify_rx` — subscription forwarders push notification JSON
///   lines here; we write them straight to the wire.
/// - `read_line_bounded` — inbound request from the client; parse,
///   dispatch, write response.
async fn handle_connection(
    stream: TcpStream,
    mut dispatch: BoxedDispatch,
    mut notify_rx: mpsc::Receiver<String>,
    _config: Arc<ElectrumConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), FramingError> {
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut buf: Vec<u8> = Vec::with_capacity(2048);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            Some(notif_json) = notify_rx.recv() => {
                write_line(&mut write_half, &notif_json).await?;
            }
            line = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES) => {
                let line = match line {
                    Ok(s) => s.to_string(),
                    Err(FramingError::Closed) => return Ok(()),
                    Err(e) => return Err(e),
                };
                let response = process_request(&mut dispatch, &line);
                if let Some(resp_json) = response {
                    write_line(&mut write_half, &resp_json).await?;
                }
            }
        }
    }
}

/// Parse + dispatch + serialize. Returns `None` for notifications
/// (requests with no `id`) since the spec says we don't reply.
fn process_request(dispatch: &mut BoxedDispatch, line: &str) -> Option<String> {
    let req = match Request::parse(line) {
        Ok(r) => r,
        Err(err) => {
            let resp = Response::error(Value::Null, err);
            return serde_json::to_string(&resp).ok();
        }
    };

    let is_notification = req.id.is_none();
    let resp = dispatch(req);

    if is_notification {
        return None;
    }
    serde_json::to_string(&resp).ok()
}

/// Render a JSON-RPC notification as a writeable line. Used by
/// subscription forwarders that build notifications and send them
/// onto the per-connection mpsc; living here keeps the wire-frame
/// construction single-sourced.
pub fn render_notification(n: &Notification) -> Result<String, serde_json::Error> {
    serde_json::to_string(n)
}

async fn reject_overflow(stream: TcpStream) -> io::Result<()> {
    let (_rd, mut wr) = stream.into_split();
    let err = JsonRpcError::new(4, "server is at connection capacity; please retry shortly");
    let resp = Response::error(Value::Null, err);
    if let Ok(s) = serde_json::to_string(&resp) {
        let _ = wr.write_all(s.as_bytes()).await;
        let _ = wr.write_all(b"\n").await;
        let _ = wr.flush().await;
    }
    wr.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn echo_factory() -> ConnectionFactory {
        Arc::new(|_max_subs: usize| {
            let (_tx, rx) = mpsc::channel(1);
            let dispatch: BoxedDispatch = Box::new(|req: Request| {
                Response::success(
                    req.id.clone().unwrap_or(Value::Null),
                    json!({ "method": req.method, "params": req.params }),
                )
            });
            (dispatch, rx)
        })
    }

    /// Factory whose dispatch closure forwards a fixed notification
    /// to the connection's notify_rx every time it's called. Used by
    /// the notification round-trip test below.
    fn notifying_factory() -> ConnectionFactory {
        Arc::new(|_max_subs: usize| {
            let (tx, rx) = mpsc::channel(8);
            let tx_for_dispatch = tx.clone();
            let dispatch: BoxedDispatch = Box::new(move |req: Request| {
                // After processing, push a server-pushed notification
                // for the same method. Sync send so the test can
                // observe it on the next select tick.
                let notif = Notification::new(
                    "blockchain.headers.subscribe",
                    json!([{"height": 1, "hex": ""}]),
                );
                let _ = tx_for_dispatch.try_send(serde_json::to_string(&notif).unwrap());
                Response::success(req.id.clone().unwrap_or(Value::Null), Value::Null)
            });
            (dispatch, rx)
        })
    }

    fn fixed_config() -> ElectrumConfig {
        ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            max_conns: 4,
            ..Default::default()
        }
    }

    async fn write_request(stream: &mut TcpStream, req: &Value) {
        let s = serde_json::to_string(req).unwrap();
        stream.write_all(s.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_response_line(reader: &mut tokio::io::BufReader<TcpStream>) -> String {
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await.unwrap();
        assert!(n > 0, "EOF before response arrived");
        buf.trim_end_matches('\n').to_string()
    }

    #[tokio::test]
    async fn server_round_trips_a_request() {
        let cfg = fixed_config();
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_request(
            &mut stream,
            &json!({"jsonrpc":"2.0","id":7,"method":"server.ping","params":[]}),
        )
        .await;

        let mut reader = tokio::io::BufReader::new(stream);
        let line = read_response_line(&mut reader).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["method"], "server.ping");

        sd_tx.send(true).unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn server_returns_parse_error_with_null_id() {
        let cfg = fixed_config();
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"not json\n").await.unwrap();
        stream.flush().await.unwrap();
        let mut reader = tokio::io::BufReader::new(stream);
        let line = read_response_line(&mut reader).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v["id"].is_null());
        assert_eq!(v["error"]["code"], -32700);

        sd_tx.send(true).unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_listener_promptly() {
        let cfg = fixed_config();
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let _addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));
        sd_tx.send(true).unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(500), join).await;
        assert!(res.is_ok(), "shutdown didn't close serve() in 500ms");
    }

    #[tokio::test]
    async fn at_capacity_rejection_response() {
        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            max_conns: 1,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let hold_stream = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream2 = TcpStream::connect(addr).await.unwrap();
        let mut reader2 = tokio::io::BufReader::new(stream2);
        let line = read_response_line(&mut reader2).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["error"]["code"], 4);

        drop(hold_stream);
        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn server_pushes_notification_after_dispatch() {
        let cfg = fixed_config();
        let server = ElectrumServer::bind_with_factory(cfg, notifying_factory())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_request(
            &mut stream,
            &json!({"jsonrpc":"2.0","id":1,"method":"blockchain.headers.subscribe","params":[]}),
        )
        .await;

        let mut reader = tokio::io::BufReader::new(stream);
        // First line is the response. Second line is the
        // server-pushed notification the dispatch closure scheduled.
        let line1 = read_response_line(&mut reader).await;
        let v1: Value = serde_json::from_str(&line1).unwrap();
        assert_eq!(v1["id"], 1);
        assert!(v1["result"].is_null());

        let line2 = read_response_line(&mut reader).await;
        let v2: Value = serde_json::from_str(&line2).unwrap();
        assert!(v2["id"].is_null(), "notification must have no id");
        assert_eq!(v2["method"], "blockchain.headers.subscribe");

        sd_tx.send(true).unwrap();
        join.await.unwrap();
    }
}
