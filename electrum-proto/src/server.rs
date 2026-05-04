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
//!    by writing one `JsonRpcError::subscription_cap`-style error and
//!    closing.
//! 3. Shutdown: a `watch::Receiver<bool>` flip to `true` closes the
//!    accept loop and signals every per-connection task to drain its
//!    in-flight request and exit.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::config::ElectrumConfig;
use crate::dispatch::{self, Notification, Request, Response};
use crate::error::JsonRpcError;
use crate::rpc::{FramingError, MAX_LINE_BYTES, read_line_bounded, write_line};
use crate::state::ElectrumState;

#[derive(Debug, Error)]
pub enum ElectrumServerError {
    #[error("bind to {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
}

/// Type-erased dispatcher. Production wires
/// [`StateDispatch`](StateDispatch); tests use any callable.
pub type DispatchFn = Arc<dyn Fn(Request) -> Response + Send + Sync + 'static>;

/// Bind production paths to [`crate::dispatch::dispatch`] over the
/// supplied [`ElectrumState`].
pub fn state_dispatcher(state: Arc<ElectrumState>) -> DispatchFn {
    Arc::new(move |req: Request| dispatch::dispatch(&state, req))
}

/// Pre-bound Electrum TCP server. Construct via [`Self::bind`]; run
/// via [`Self::serve`] until the supplied shutdown watch flips.
pub struct ElectrumServer {
    listener: TcpListener,
    dispatch: DispatchFn,
    config: Arc<ElectrumConfig>,
    semaphore: Arc<Semaphore>,
}

impl ElectrumServer {
    /// Convenience: bind + wire production state-backed dispatch.
    pub async fn bind(
        config: ElectrumConfig,
        state: Arc<ElectrumState>,
    ) -> Result<Self, ElectrumServerError> {
        let dispatch = state_dispatcher(state);
        Self::bind_with_dispatch(config, dispatch).await
    }

    /// Bind with an explicit dispatch closure. Used by tests to swap
    /// in a stub that doesn't require a real `ElectrumState`.
    pub async fn bind_with_dispatch(
        config: ElectrumConfig,
        dispatch: DispatchFn,
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
            dispatch,
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
                            let dispatch = self.dispatch.clone();
                            let config = self.config.clone();
                            let conn_shutdown = shutdown.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = handle_connection(stream, dispatch, config, conn_shutdown).await {
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
/// - per-request wall-clock: `config.request_timeout`
/// - per-server connection count: enforced by the caller's semaphore
///   permit (not visible inside this fn)
///
/// Notifications channel is wired in PR-4. The `select!` already has
/// the right shape; PR-4 just adds an arm.
async fn handle_connection(
    stream: TcpStream,
    dispatch: DispatchFn,
    config: Arc<ElectrumConfig>,
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
            line = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES) => {
                let line = match line {
                    Ok(s) => s.to_string(),
                    Err(FramingError::Closed) => return Ok(()),
                    Err(e) => return Err(e),
                };
                let response = process_request(&dispatch, &config, &line).await;
                if let Some(resp_json) = response {
                    write_line(&mut write_half, &resp_json).await?;
                }
            }
        }
    }
}

/// Parse + dispatch + serialize. Returns `None` for notifications
/// (requests with no `id`) since the spec says we don't reply.
/// Otherwise returns the response JSON string ready to write.
async fn process_request(
    dispatch: &DispatchFn,
    config: &ElectrumConfig,
    line: &str,
) -> Option<String> {
    let req = match Request::parse(line) {
        Ok(r) => r,
        Err(err) => {
            // Parse error: respond with id=null per JSON-RPC 2.0 §5.
            let resp = Response::error(Value::Null, err);
            return serde_json::to_string(&resp).ok();
        }
    };

    let is_notification = req.id.is_none();
    let id = req.id.clone().unwrap_or(Value::Null);

    // Run the (synchronous) dispatch on the blocking thread pool so
    // a slow handler (e.g. tx_merkle reading a block) doesn't block
    // the reactor. Wrapped in a per-request timeout.
    let dispatch = dispatch.clone();
    let req_for_dispatch = req;
    let timeout = config.request_timeout;
    let timed: Result<Result<Response, tokio::task::JoinError>, tokio::time::error::Elapsed> =
        tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || dispatch(req_for_dispatch)),
        )
        .await;

    let resp = match timed {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Response::error(id.clone(), JsonRpcError::internal("dispatcher panicked")),
        Err(_) => Response::error(
            id.clone(),
            JsonRpcError::internal(format!("request exceeded {}s timeout", timeout.as_secs())),
        ),
    };

    if is_notification {
        return None;
    }
    serde_json::to_string(&resp).ok()
}

/// Render a JSON-RPC notification (server push) as a writeable line.
/// Used by PR-4's subscription delivery; lives here so the transport
/// layer is the only place that constructs wire frames.
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

    fn echo_dispatcher() -> DispatchFn {
        Arc::new(|req: Request| {
            Response::success(
                req.id.clone().unwrap_or(Value::Null),
                json!({ "method": req.method, "params": req.params }),
            )
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
        let server = ElectrumServer::bind_with_dispatch(cfg, echo_dispatcher())
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
        let server = ElectrumServer::bind_with_dispatch(cfg, echo_dispatcher())
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
        let server = ElectrumServer::bind_with_dispatch(cfg, echo_dispatcher())
            .await
            .unwrap();
        let _addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));
        sd_tx.send(true).unwrap();
        // Should return well within the 1s upper bound; we use 500ms
        // so a flake on a loaded CI box still leaves slack.
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
        let server = ElectrumServer::bind_with_dispatch(cfg, echo_dispatcher())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        // First connection: occupies the only permit by holding the
        // socket open without sending. The per-conn task blocks in
        // read_line_bounded — no spawn_blocking is reached.
        let hold_stream = TcpStream::connect(addr).await.unwrap();
        // Yield long enough for accept + spawn to land.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second connection: must get the at-capacity rejection.
        let stream2 = TcpStream::connect(addr).await.unwrap();
        let mut reader2 = tokio::io::BufReader::new(stream2);
        let line = read_response_line(&mut reader2).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["error"]["code"], 4);

        drop(hold_stream);
        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }
}
