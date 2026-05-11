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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_rustls::TlsAcceptor;

use crate::config::ElectrumConfig;
use crate::dispatch::{Notification, Request, Requests, Response, dispatch_with_subscriptions};
use crate::error::JsonRpcError;
use crate::rpc::{FramingError, MAX_LINE_BYTES, read_line_bounded, write_line};
use crate::state::ElectrumState;
use crate::subscribe::{NOTIFY_CHANNEL_CAP, Subscriptions};
use tls_config::{ClientAuthPolicy, TlsConfigError, build_acceptor};

#[derive(Debug, Error)]
pub enum ElectrumServerError {
    #[error("bind to {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
    #[error("tls config: {0}")]
    Tls(#[from] TlsConfigError),
    #[error("tls misconfigured: tls_bind set without tls_cert_path / tls_key_path")]
    TlsMissingPaths,
    #[error("mtls misconfigured: mtls_enabled set without tls_bind")]
    MtlsWithoutTls,
    #[error("mtls misconfigured: mtls_enabled set without mtls_client_ca")]
    MtlsMissingCa,
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
///
/// Holds two optional listeners — `listener` for plain TCP (always
/// present unless removed) and `tls` for the rustls-wrapped variant.
/// Both share the same connection cap, dispatch factory, and
/// shutdown watch.
pub struct ElectrumServer {
    listener: TcpListener,
    tls: Option<(TcpListener, TlsAcceptor)>,
    /// Compiled allowlist applied after a successful mTLS handshake.
    /// `is_empty()` short-circuits to "any CA-signed cert is accepted".
    /// Held alongside the acceptor so `handle_tls_accept` doesn't have
    /// to reach back into the config on every connection.
    allow: tls_config::ClientAllowList,
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

        // Validate mTLS configuration up front so a misconfiguration
        // becomes a startup-fatal error rather than per-handshake
        // failures later. mTLS is meaningful only on the TLS surface;
        // requiring it without a TLS bind is operator confusion we
        // refuse to paper over.
        if config.mtls_enabled && config.tls_bind.is_none() {
            return Err(ElectrumServerError::MtlsWithoutTls);
        }
        if config.mtls_enabled && config.mtls_client_ca.is_none() {
            return Err(ElectrumServerError::MtlsMissingCa);
        }

        // If a TLS bind is configured, ALL of (tls_bind, tls_cert_path,
        // tls_key_path) must be set; partial configuration is a hard
        // startup error rather than silently ignored.
        let tls = match (
            config.tls_bind,
            config.tls_cert_path.as_ref(),
            config.tls_key_path.as_ref(),
        ) {
            (None, _, _) => None,
            (Some(_), None, _) | (Some(_), _, None) => {
                return Err(ElectrumServerError::TlsMissingPaths);
            }
            (Some(addr), Some(cert), Some(key)) => {
                // mTLS picks the client-auth policy. When disabled,
                // we keep the historical "any client" handshake; when
                // enabled, the operator's CA is the trust anchor and
                // unsigned clients are rejected at the rustls layer.
                let policy = match (config.mtls_enabled, config.mtls_client_ca.as_ref()) {
                    (true, Some(ca)) => ClientAuthPolicy::Required {
                        ca_path: ca.clone(),
                    },
                    (true, None) => unreachable!("mTLS validation above guarantees CA path"),
                    (false, _) => ClientAuthPolicy::Disabled,
                };
                let acceptor = build_acceptor(cert, key, &policy)?;
                let tls_listener = TcpListener::bind(addr)
                    .await
                    .map_err(|source| ElectrumServerError::Bind { addr, source })?;
                Some((tls_listener, acceptor))
            }
        };

        let allow = tls_config::ClientAllowList::new(config.mtls_client_allow.iter().cloned());

        let semaphore = Arc::new(Semaphore::new(config.max_conns.max(1)));
        Ok(Self {
            listener,
            tls,
            allow,
            factory,
            config: Arc::new(config),
            semaphore,
        })
    }

    /// Returns the plain-TCP bound address. Useful in tests where
    /// `bind` was `127.0.0.1:0` and the OS picked the port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns the TLS bound address if TLS is configured.
    pub fn local_tls_addr(&self) -> Option<io::Result<SocketAddr>> {
        self.tls.as_ref().map(|(l, _)| l.local_addr())
    }

    /// Run the accept loop until `shutdown` flips to `true`. Spawns
    /// one task per connection; per-connection tasks observe the
    /// same shutdown watch and exit cleanly. When TLS is configured,
    /// both listeners run in parallel — connections route to the
    /// same per-conn handler regardless of transport.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            bind = %self.config.bind,
            tls_bind = ?self.config.tls_bind,
            max_conns = self.config.max_conns,
            "Electrum server listening"
        );
        loop {
            // Match shape lets us conditionally enable the TLS arm
            // without blocking on a never-ready future when TLS isn't
            // configured.
            let tls_accept = async {
                match &self.tls {
                    Some((listener, _)) => listener.accept().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("Electrum server shutdown signal received");
                    return;
                }
                accept = self.listener.accept() => {
                    self.handle_plain_accept(accept, &shutdown);
                }
                accept = tls_accept => {
                    self.handle_tls_accept(accept, &shutdown);
                }
            }
        }
    }

    fn handle_plain_accept(
        &self,
        accept: io::Result<(TcpStream, SocketAddr)>,
        shutdown: &watch::Receiver<bool>,
    ) {
        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Electrum accept error");
                return;
            }
        };
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                tracing::debug!(peer = %peer, "Electrum connection accepted");
                let factory = self.factory.clone();
                let config = self.config.clone();
                let conn_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let (dispatch, notify_rx) = factory(config.max_subs_per_conn);
                    if let Err(e) =
                        handle_connection(stream, dispatch, notify_rx, config, conn_shutdown).await
                    {
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

    fn handle_tls_accept(
        &self,
        accept: io::Result<(TcpStream, SocketAddr)>,
        shutdown: &watch::Receiver<bool>,
    ) {
        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Electrum TLS accept error");
                return;
            }
        };
        let acceptor = match &self.tls {
            Some((_, a)) => a.clone(),
            None => return, // unreachable when accept arm is gated
        };
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                let factory = self.factory.clone();
                let config = self.config.clone();
                let conn_shutdown = shutdown.clone();
                let allow = self.allow.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Bound the TLS handshake so a half-open client
                    // can't sit on a connection permit forever
                    // (review-round-1 M2).
                    let handshake_timeout = config.request_timeout;
                    let tls_stream = match tokio::time::timeout(
                        handshake_timeout,
                        acceptor.accept(stream),
                    ).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::debug!(peer = %peer, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_elapsed) => {
                            tracing::warn!(
                                target = "electrum::server",
                                peer = %peer,
                                timeout_secs = handshake_timeout.as_secs(),
                                "TLS handshake timed out — closing connection",
                            );
                            return;
                        }
                    };
                    // After a successful (m)TLS handshake, optionally
                    // narrow to the operator's CN/SAN allowlist. When
                    // `allow` is empty (no allowlist configured), the
                    // CA bundle remains the only gate and this check
                    // is a no-op. When mTLS is disabled entirely, the
                    // handshake produces no peer cert and the check
                    // also returns Ok via the empty-allowlist
                    // short-circuit.
                    let (_, server_conn) = tls_stream.get_ref();
                    if config.mtls_enabled
                        && let Some(subject) = tls_config::peer_subject_label(server_conn)
                    {
                        tracing::info!(
                            peer = %peer,
                            subject = %subject,
                            "Electrum mTLS client accepted",
                        );
                    }
                    if let Err(rej) = tls_config::check_peer_allowed(server_conn, &allow) {
                        tracing::warn!(
                            peer = %peer,
                            subject = %rej.subject_label,
                            "Electrum mTLS client rejected by allowlist",
                        );
                        return;
                    }
                    let (dispatch, notify_rx) = factory(config.max_subs_per_conn);
                    if let Err(e) =
                        handle_connection(tls_stream, dispatch, notify_rx, config, conn_shutdown)
                            .await
                    {
                        tracing::debug!(peer = %peer, error = %e, "Electrum TLS connection ended");
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    peer = %peer,
                    "Electrum TLS at-capacity rejection ({} max)",
                    self.config.max_conns
                );
                tokio::spawn(async move {
                    // Same plain-text rejection over an unencrypted
                    // TCP stream — the client hasn't completed the
                    // TLS handshake yet, so there's no encryption
                    // context to use. They'll see a plain-JSON line
                    // before the connection drops.
                    let _ = reject_overflow(stream).await;
                });
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
async fn handle_connection<S>(
    stream: S,
    mut dispatch: BoxedDispatch,
    mut notify_rx: mpsc::Receiver<String>,
    config: Arc<ElectrumConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), FramingError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let request_timeout = config.request_timeout;
    let max_batch = config.max_batch_requests;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            Some(notif_json) = notify_rx.recv() => {
                // Bound the write so a stuck reader can't pin the
                // task indefinitely (review-round-1 M2).
                match tokio::time::timeout(
                    request_timeout,
                    write_line(&mut write_half, &notif_json),
                ).await {
                    Ok(res) => res?,
                    Err(_elapsed) => {
                        tracing::warn!(
                            target = "electrum::server",
                            timeout_secs = request_timeout.as_secs(),
                            "notification write timed out — closing connection",
                        );
                        return Ok(());
                    }
                }
            }
            line = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES) => {
                // The read itself isn't deadlined here — slowloris
                // protection rides on `request_timeout` bounding the
                // dispatch path below; an idle connection that never
                // writes a newline is harmless except for occupying
                // a connection slot, which the total-conn semaphore
                // already bounds.
                let line = match line {
                    Ok(s) => s.to_string(),
                    Err(FramingError::Closed) => return Ok(()),
                    Err(e) => return Err(e),
                };
                let response = match tokio::time::timeout(
                    request_timeout,
                    async { process_request(&mut dispatch, &line, max_batch) },
                ).await {
                    Ok(resp) => resp,
                    Err(_elapsed) => {
                        let err = JsonRpcError::bad_request(format!(
                            "request timed out after {}s", request_timeout.as_secs()
                        ));
                        let resp = Response::error(Value::Null, err);
                        Some(serde_json::to_string(&resp).unwrap_or_default())
                    }
                };
                if let Some(resp_json) = response {
                    match tokio::time::timeout(
                        request_timeout,
                        write_line(&mut write_half, &resp_json),
                    ).await {
                        Ok(res) => res?,
                        Err(_elapsed) => {
                            tracing::warn!(
                                target = "electrum::server",
                                timeout_secs = request_timeout.as_secs(),
                                "response write timed out — closing connection",
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Parse + dispatch + serialize. Returns `None` for notifications
/// (requests with no `id`) since the spec says we don't reply, and
/// also `None` when a batch contained ONLY notifications. Handles
/// both single requests and batch arrays per JSON-RPC 2.0 §6.
///
/// `max_batch_requests` rejects oversized batches before dispatching
/// any element, preventing a single 1 MiB line from forcing the
/// server through thousands of method calls (review-round-1 M5).
fn process_request(
    dispatch: &mut BoxedDispatch,
    line: &str,
    max_batch_requests: usize,
) -> Option<String> {
    match Requests::parse(line) {
        Ok(Requests::Single(req)) => {
            let is_notification = req.id.is_none();
            let resp = dispatch(req);
            if is_notification {
                None
            } else {
                serde_json::to_string(&resp).ok()
            }
        }
        Ok(Requests::Batch(reqs)) => {
            if reqs.len() > max_batch_requests {
                let err = JsonRpcError::bad_request(format!(
                    "batch too large: {} requests (cap = {max_batch_requests})",
                    reqs.len()
                ));
                let resp = Response::error(Value::Null, err);
                return serde_json::to_string(&resp).ok();
            }
            // Per spec: dispatch each, suppress responses for
            // notifications. If the batch contained only
            // notifications, return None (no response written).
            let mut responses: Vec<Response> = Vec::with_capacity(reqs.len());
            for req in reqs {
                let is_notification = req.id.is_none();
                let resp = dispatch(req);
                if !is_notification {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                None
            } else {
                serde_json::to_string(&responses).ok()
            }
        }
        Err(err) => {
            let resp = Response::error(Value::Null, err);
            serde_json::to_string(&resp).ok()
        }
    }
}

/// Render a JSON-RPC notification as a writeable line. Used by
/// subscription forwarders that build notifications and send them
/// onto the per-connection mpsc; living here keeps the wire-frame
/// construction single-sourced.
pub fn render_notification(n: &Notification) -> Result<String, serde_json::Error> {
    serde_json::to_string(n)
}

async fn reject_overflow(mut stream: TcpStream) -> io::Result<()> {
    // Code 1 (bad_request): mirrors electrs's "client overload" wire
    // shape — clients see a structured error and can retry with backoff
    // instead of treating the close as a network failure.
    let err = JsonRpcError::bad_request("server is at connection capacity; please retry shortly");
    let resp = Response::error(Value::Null, err);
    if let Ok(s) = serde_json::to_string(&resp) {
        let _ = stream.write_all(s.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
        let _ = stream.flush().await;
    }
    stream.shutdown().await
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
        // Reject uses electrs-style BadRequest (code 1) for at-capacity
        // refusal — same code path electrs uses for any handler-level
        // refusal so client retry/backoff logic doesn't have to special-
        // case our overflow signal.
        assert_eq!(v["error"]["code"], 1);

        drop(hold_stream);
        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn tls_round_trips_a_request() {
        use std::io::Write;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::pki_types::ServerName;

        // Generate a self-signed cert with rcgen and write it + the
        // private key to temp PEM files. ElectrumServer reads from
        // disk so this exercises the same load_certs / load_private_key
        // path as production.
        let san = ["localhost".to_string()];
        let cert = rcgen::generate_simple_self_signed(san).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert.cert.pem().as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(cert.key_pair.serialize_pem().as_bytes())
            .unwrap();

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        // Trust the test's self-signed cert in the client store.
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let der = cert.cert.der().clone();
        roots.add(der).unwrap();
        let client_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let dnsname = ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(dnsname, tcp).await.unwrap();
        let req = json!({"jsonrpc":"2.0","id":42,"method":"server.ping","params":[]});
        let s = serde_json::to_string(&req).unwrap();
        tls_stream.write_all(s.as_bytes()).await.unwrap();
        tls_stream.write_all(b"\n").await.unwrap();
        tls_stream.flush().await.unwrap();
        let mut reader = tokio::io::BufReader::new(tls_stream);
        let mut line = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
            .await
            .unwrap();
        let v: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["result"]["method"], "server.ping");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn tls_partial_config_is_a_hard_error() {
        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: None, // missing key path too
            tls_key_path: None,
            ..Default::default()
        };
        let result = ElectrumServer::bind_with_factory(cfg, echo_factory()).await;
        assert!(matches!(result, Err(ElectrumServerError::TlsMissingPaths)));
    }

    /// Mint a CA + a leaf signed by it. The CA cert is what the
    /// server's mTLS verifier trusts; the leaf is what the client
    /// presents during handshake. rcgen 0.13 splits "CA" from "leaf"
    /// via `KeyUsagePurpose::KeyCertSign` and a callback to
    /// `signed_by`.
    fn mint_ca_and_leaf(
        leaf_dns: &str,
    ) -> (
        rcgen::Certificate, // CA root
        rcgen::KeyPair,     // CA key (needed to sign more leaves)
        rcgen::Certificate, // leaf signed by CA
        rcgen::KeyPair,     // leaf private key
    ) {
        // CA
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        // Leaf
        let mut leaf_params = rcgen::CertificateParams::new(vec![leaf_dns.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, leaf_dns);
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &ca_cert, &ca_kp).unwrap();
        (ca_cert, ca_kp, leaf_cert, leaf_kp)
    }

    fn write_file(path: &std::path::Path, body: &str) {
        use std::io::Write;
        std::fs::File::create(path)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
    }

    /// Helper to build a client `TlsConnector` that trusts `ca_cert`
    /// and (optionally) presents a leaf cert + key during handshake.
    fn client_connector(
        ca_cert: &rcgen::Certificate,
        client_id: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> tokio_rustls::TlsConnector {
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let client_cfg = match client_id {
            Some((leaf, kp)) => {
                let leaf_der: CertificateDer<'static> = leaf.der().clone();
                let key_der: PrivateKeyDer<'static> =
                    PrivatePkcs8KeyDer::from(kp.serialize_der()).into();
                builder
                    .with_client_auth_cert(vec![leaf_der], key_der)
                    .unwrap()
            }
            None => builder.with_no_client_auth(),
        };
        TlsConnector::from(Arc::new(client_cfg))
    }

    /// Helper: run an Electrum request over a `tokio_rustls`-backed
    /// connection, asserting that the round trip completes. Used by
    /// the mTLS-happy-path tests below.
    async fn run_electrum_ping_over_tls(
        connector: tokio_rustls::TlsConnector,
        addr: SocketAddr,
        dns: &str,
    ) -> Value {
        use tokio_rustls::rustls::pki_types::ServerName;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let dnsname = ServerName::try_from(dns.to_string()).unwrap();
        let mut tls_stream = connector.connect(dnsname, tcp).await.unwrap();
        let req = json!({"jsonrpc":"2.0","id":7,"method":"server.ping","params":[]});
        let s = serde_json::to_string(&req).unwrap();
        tls_stream.write_all(s.as_bytes()).await.unwrap();
        tls_stream.write_all(b"\n").await.unwrap();
        tls_stream.flush().await.unwrap();
        let mut reader = tokio::io::BufReader::new(tls_stream);
        let mut line = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
            .await
            .unwrap();
        serde_json::from_str(line.trim_end()).unwrap()
    }

    /// mTLS happy-path: server requires a client cert signed by the
    /// configured CA; the client presents a valid leaf; the request
    /// round-trips end to end.
    #[tokio::test]
    async fn mtls_round_trip_with_valid_client_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost");
        // Mint a client leaf using the SAME CA root the server is
        // configured to trust.
        let mut client_params =
            rcgen::CertificateParams::new(vec!["alice.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice.test");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();
        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server.key.pem");
        let ca_path = dir.path().join("ca.pem");
        write_file(&server_cert_path, &server_cert.pem());
        write_file(&server_key_path, &server_kp.serialize_pem());
        write_file(&ca_path, &ca_cert.pem());

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let connector = client_connector(&ca_cert, Some((&client_cert, &client_kp)));
        let v = run_electrum_ping_over_tls(connector, tls_addr, "localhost").await;
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["method"], "server.ping");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// mTLS rejection: server requires a client cert; the client
    /// presents no cert. In TLS 1.3 the client's `connect()` may
    /// resolve locally before the server's verifier rejects, so we
    /// assert that the first application read returns an error /
    /// EOF rather than a JSON response.
    #[tokio::test]
    async fn mtls_rejects_handshake_without_client_cert() {
        use tokio_rustls::rustls::pki_types::ServerName;
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, _ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost");
        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server.key.pem");
        let ca_path = dir.path().join("ca.pem");
        write_file(&server_cert_path, &server_cert.pem());
        write_file(&server_key_path, &server_kp.serialize_pem());
        write_file(&ca_path, &ca_cert.pem());

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        // Client trusts the CA but presents no client cert.
        let connector = client_connector(&ca_cert, None);
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let dnsname = ServerName::try_from("localhost").unwrap();
        // Either `connect` itself errors (TLS 1.2 path), or it returns
        // Ok and the first read fails when the server's verifier
        // alert reaches the client (TLS 1.3 half-RTT). Both shapes
        // mean "the server refused this client" — we accept either.
        let assert_rejected = |outcome: Result<String, String>| {
            assert!(
                outcome.is_err(),
                "expected mTLS rejection, got JSON line: {outcome:?}"
            );
        };
        match connector.connect(dnsname, tcp).await {
            Err(_) => assert_rejected(Err("connect failed".into())),
            Ok(mut stream) => {
                let _ = stream
                    .write_all(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.ping\",\"params\":[]}\n",
                    )
                    .await;
                let _ = stream.flush().await;
                let mut reader = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line),
                )
                .await;
                let outcome: Result<String, String> = match read {
                    Ok(Ok(0)) => Err("EOF".into()),
                    Ok(Ok(_)) => Ok(line),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => panic!("read did not return promptly after server rejection"),
                };
                assert_rejected(outcome);
            }
        }

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// mTLS rejection: server requires CA-signed client cert; client
    /// presents a cert signed by a DIFFERENT CA. Server-side
    /// verifier rejects; in TLS 1.3 the rejection surfaces on the
    /// first read.
    #[tokio::test]
    async fn mtls_rejects_wrong_ca_client_cert() {
        use tokio_rustls::rustls::pki_types::ServerName;
        let dir = tempfile::tempdir().unwrap();
        let (good_ca, _good_ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost");
        let (_other_ca, _other_ca_kp, other_leaf, other_leaf_kp) = mint_ca_and_leaf("alice.test");
        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server.key.pem");
        let ca_path = dir.path().join("good-ca.pem");
        write_file(&server_cert_path, &server_cert.pem());
        write_file(&server_key_path, &server_kp.serialize_pem());
        write_file(&ca_path, &good_ca.pem());

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        // Client presents a leaf signed by a DIFFERENT CA. Trust the
        // SERVER cert's CA so the *server-auth* half of the handshake
        // succeeds (so we exercise the client-auth rejection path).
        let connector = client_connector(&good_ca, Some((&other_leaf, &other_leaf_kp)));
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let dnsname = ServerName::try_from("localhost").unwrap();
        // Same accept-both shape as the no-cert case above:
        // `connect()` may succeed locally in TLS 1.3 with the
        // rejection arriving on the first read.
        match connector.connect(dnsname, tcp).await {
            Err(_) => { /* connect-time rejection — accepted */ }
            Ok(mut stream) => {
                let _ = stream
                    .write_all(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.ping\",\"params\":[]}\n",
                    )
                    .await;
                let _ = stream.flush().await;
                let mut reader = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line),
                )
                .await;
                match read {
                    Ok(Ok(0)) => { /* EOF — expected */ }
                    Ok(Ok(_)) => panic!("expected mTLS rejection, got: {line:?}"),
                    Ok(Err(_)) => { /* IO error — expected */ }
                    Err(_) => panic!("read did not return promptly after server rejection"),
                }
            }
        }

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// Allowlist happy-path: server requires mTLS AND restricts
    /// principals to the named set. Client cert's CN matches one of
    /// them. The request round-trips end to end.
    #[tokio::test]
    async fn mtls_allowlist_accepts_matching_cn() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost");
        let mut client_params =
            rcgen::CertificateParams::new(vec!["alice.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();

        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server.key.pem");
        let ca_path = dir.path().join("ca.pem");
        write_file(&server_cert_path, &server_cert.pem());
        write_file(&server_key_path, &server_kp.serialize_pem());
        write_file(&ca_path, &ca_cert.pem());

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            mtls_client_allow: vec!["alice".to_string(), "bob".to_string()],
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        let connector = client_connector(&ca_cert, Some((&client_cert, &client_kp)));
        let v = run_electrum_ping_over_tls(connector, tls_addr, "localhost").await;
        assert_eq!(v["id"], 7);

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// Allowlist rejection: handshake succeeds (cert is CA-signed),
    /// but the leaf's CN / SAN don't match the allowlist. The
    /// connection is dropped post-handshake. The client sees a clean
    /// disconnect with no data.
    #[tokio::test]
    async fn mtls_allowlist_rejects_unlisted_principal() {
        use tokio_rustls::rustls::pki_types::ServerName;
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost");
        let mut client_params =
            rcgen::CertificateParams::new(vec!["mallory.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mallory");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();

        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server.key.pem");
        let ca_path = dir.path().join("ca.pem");
        write_file(&server_cert_path, &server_cert.pem());
        write_file(&server_key_path, &server_kp.serialize_pem());
        write_file(&ca_path, &ca_cert.pem());

        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            mtls_client_allow: vec!["alice".to_string(), "bob".to_string()],
            max_conns: 4,
            ..Default::default()
        };
        let server = ElectrumServer::bind_with_factory(cfg, echo_factory())
            .await
            .unwrap();
        let tls_addr = server.local_tls_addr().unwrap().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let join = tokio::spawn(server.serve(sd_rx));

        // Handshake succeeds — mallory has a valid CA-signed cert.
        // Post-handshake, the allowlist drops the connection before
        // any request can be dispatched. We assert the read returns
        // EOF rather than a response line.
        let connector = client_connector(&ca_cert, Some((&client_cert, &client_kp)));
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let dnsname = ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(dnsname, tcp).await.unwrap();
        // Send a request; the server-side allowlist check should have
        // already dropped the connection, so this write may or may not
        // succeed (TCP-level race), but the subsequent read must see
        // EOF — no JSON response is forthcoming.
        let _ = tls_stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.ping\",\"params\":[]}\n")
            .await;
        let mut reader = tokio::io::BufReader::new(tls_stream);
        let mut line = String::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line),
        )
        .await;
        match read {
            Ok(Ok(0)) => { /* clean EOF — expected */ }
            Ok(Ok(_)) => panic!("expected EOF after allowlist drop, got: {line:?}"),
            Ok(Err(_)) => { /* IO error — also acceptable (peer reset) */ }
            Err(_) => panic!("read did not return promptly after allowlist drop"),
        }

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// Misconfiguration: `mtls_enabled=true` without a CA path is a
    /// hard error at server-construction time.
    #[tokio::test]
    async fn mtls_without_ca_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_file(&cert_path, &cert.cert.pem());
        write_file(&key_path, &cert.key_pair.serialize_pem());
        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: Some("127.0.0.1:0".parse().unwrap()),
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            mtls_enabled: true,
            mtls_client_ca: None, // <-- the misconfiguration
            ..Default::default()
        };
        let result = ElectrumServer::bind_with_factory(cfg, echo_factory()).await;
        assert!(matches!(result, Err(ElectrumServerError::MtlsMissingCa)));
    }

    /// Misconfiguration: `mtls_enabled=true` without a TLS bind is a
    /// hard error at server-construction time.
    #[tokio::test]
    async fn mtls_without_tls_bind_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        write_file(&ca_path, "fake");
        let cfg = ElectrumConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_bind: None,
            mtls_enabled: true,
            mtls_client_ca: Some(ca_path),
            ..Default::default()
        };
        let result = ElectrumServer::bind_with_factory(cfg, echo_factory()).await;
        assert!(matches!(result, Err(ElectrumServerError::MtlsWithoutTls)));
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
