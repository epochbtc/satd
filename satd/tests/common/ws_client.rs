//! Real WebSocket + SSE clients for the streaming Consumption-API E2E suite.
//!
//! The `/ws` endpoint speaks bidirectional JSON (firehose events + watch-set
//! control + per-subscriber matches); `/sse` is a read-only JSON firehose with
//! optional `?from_*` durable-replay query params. Both are reached over the
//! daemon's `--streamws` listener. The SSE side reuses the raw-TCP reader
//! pattern proven by the Esplora `SseClient` in `tests/regtest.rs`; the WS side
//! needs a real WebSocket handshake, hence `tokio-tungstenite`.

#![allow(dead_code)]

use futures_util::{SinkExt as _, StreamExt as _};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub struct WsClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WsClient {
    /// Connect to `/ws` on a loopback streamws listener (no auth).
    pub async fn connect(port: u16) -> Self {
        Self::connect_path(port, "/ws", None).await.expect("ws connect")
    }

    /// Connect presenting a bearer token (for `--streamws-auth` nodes).
    pub async fn connect_with_token(port: u16, token: &str) -> Self {
        Self::connect_path(port, "/ws", Some(token))
            .await
            .expect("ws connect (token)")
    }

    /// Connect, returning the handshake error instead of panicking — used by
    /// the auth-rejection tests (server expected to refuse the upgrade).
    pub async fn try_connect(port: u16, token: Option<&str>) -> Result<Self, String> {
        Self::connect_path(port, "/ws", token).await
    }

    async fn connect_path(
        port: u16,
        path: &str,
        token: Option<&str>,
    ) -> Result<Self, String> {
        let url = format!("ws://127.0.0.1:{port}{path}");
        let mut req = url.into_client_request().map_err(|e| e.to_string())?;
        if let Some(t) = token {
            req.headers_mut().insert(
                "authorization",
                format!("Bearer {t}").parse().map_err(|_| "bad header".to_string())?,
            );
        }
        let (ws, _resp) = tokio_tungstenite::connect_async(req)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { ws })
    }

    /// Send a JSON control message (e.g. `{"type":"add_outpoints",...}`).
    pub async fn send_control(&mut self, json: serde_json::Value) {
        self.ws
            .send(Message::Text(json.to_string().into()))
            .await
            .expect("ws send");
    }

    /// Await the next JSON event, skipping ping/pong frames. Panics on
    /// timeout / close.
    pub async fn next_json(&mut self, secs: u64) -> serde_json::Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for ws message");
            let msg = tokio::time::timeout(remaining, self.ws.next())
                .await
                .expect("ws timeout")
                .expect("ws stream closed")
                .expect("ws error");
            match msg {
                Message::Text(t) => {
                    return serde_json::from_str(t.as_str()).expect("ws json parse");
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => panic!("ws closed by server"),
                _ => continue,
            }
        }
    }

    /// Await the next JSON event matching `pred` (skipping heartbeats / other
    /// firehose traffic), up to `secs` total.
    pub async fn next_json_matching(
        &mut self,
        secs: u64,
        pred: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for matching ws message");
            let v = self.next_json(remaining.as_secs().max(1)).await;
            if pred(&v) {
                return v;
            }
        }
    }

    /// Await the next JSON event, returning `None` on timeout / close — for
    /// negative assertions.
    pub async fn next_json_opt(&mut self, secs: u64) -> Option<serde_json::Value> {
        match tokio::time::timeout(Duration::from_secs(secs), self.ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str(t.as_str()).ok(),
            _ => None,
        }
    }
}

/// Raw-TCP SSE reader for the streaming `/sse` firehose. A thin async-free
/// reader (blocking `std::net`) mirroring the Esplora `SseClient` in
/// `regtest.rs`; the streaming `/sse` differs only in path and the optional
/// `?from_*` replay query string, so a separate type keeps the two suites
/// independent. Run from a blocking context (e.g. `spawn_blocking`) when
/// driven inside an async test.
pub struct StreamSseClient {
    reader: std::io::BufReader<std::net::TcpStream>,
}

impl StreamSseClient {
    /// Connect to `path` (e.g. `/sse` or `/sse?from_height=2`). Asserts 200.
    pub fn connect(port: u16, path: &str) -> Self {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::net::TcpStream;
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).expect("sse connect");
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).expect("status line");
        assert!(
            status_line.contains(" 200 "),
            "sse expected 200 OK; got: {}",
            status_line.trim()
        );
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).expect("header line");
            if header.trim().is_empty() {
                break;
            }
        }
        Self { reader }
    }

    /// Read the next complete SSE event, returning `(event_type, data)`.
    /// Skips `:`-comment keepalive lines.
    pub fn next_event(&mut self) -> (String, String) {
        use std::io::BufRead as _;
        let mut event_type = String::new();
        let mut data = String::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("sse read");
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                if !event_type.is_empty() || !data.is_empty() {
                    return (event_type, data);
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("event: ") {
                event_type = rest.to_string();
            } else if let Some(rest) = trimmed.strip_prefix("data: ") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest);
            }
        }
    }
}
