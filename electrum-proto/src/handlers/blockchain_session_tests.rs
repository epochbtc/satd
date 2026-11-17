//! A connection's protocol session ([`crate::dispatch::dispatch_session`]):
//! `server.version` negotiates once, a failed negotiation closes the
//! connection, and every other method is served at the negotiated version.

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::historycap_tests::{electrum_state, request, result};
use crate::dispatch::{Request, Response, dispatch_session};
use crate::state::ElectrumState;
use crate::subscribe::Subscriptions;
use crate::version::{ProtocolVersion, Session};

/// One connection: its state, session and subscriptions.
struct Conn {
    state: ElectrumState,
    session: Session,
    subs: Subscriptions,
    _dir: tempfile::TempDir,
    _rx: mpsc::Receiver<String>,
}

impl Conn {
    fn new() -> Self {
        let (state, dir) = electrum_state(100);
        let (tx, rx) = mpsc::channel(8);
        Self {
            state,
            session: Session::new(),
            subs: Subscriptions::new(tx, 10),
            _dir: dir,
            _rx: rx,
        }
    }

    fn send(&mut self, req: Request) -> Response {
        dispatch_session(
            &self.state,
            &mut self.session,
            &mut self.subs,
            self.state.chain.as_ref(),
            self.state.electrum_extras.clone(),
            req,
        )
    }

    fn call(&mut self, method: &str, params: Value) -> Response {
        self.send(Request {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: method.into(),
            params: Some(params),
        })
    }

    fn version(&mut self, params: Value) -> Response {
        self.call("server.version", params)
    }
}

fn error_message(resp: &Response) -> &str {
    &resp
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("expected an error, got {resp:?}"))
        .message
}

#[tokio::test]
async fn a_single_string_and_a_range_negotiate() {
    for (params, want) in [
        (json!(["w", "1.4"]), "1.4"),
        (json!(["w", ["1.4", "1.6"]]), "1.4"),
        // 1.5 inside a range.
        (json!(["w", ["1.2", "1.5"]]), "1.4"),
        (json!(["w", ["1.3", "1.4.2"]]), "1.4"),
        (json!(["w", "1.4.2-asof"]), "1.4.2-asof"),
        (json!(["w", ["1.4", "1.4.2-asof"]]), "1.4.2-asof"),
        // Extra arguments are ignored.
        (json!(["w", ["1.4", "1.6"], "extra", 9999.9, {"dd": {}}]), "1.4"),
    ] {
        let mut conn = Conn::new();
        let resp = conn.version(params.clone());
        assert!(!resp.close, "{params}");
        let got = result(resp);
        assert_eq!(got[1], want, "{params}");
        assert!(got[0].as_str().unwrap().starts_with("satd-"), "{got}");
    }
}

/// Only the first `server.version` is accepted (spec 1.4), with
/// ElectrumX's error, and the negotiated version stays.
#[tokio::test]
async fn a_second_server_version_is_refused() {
    let mut conn = Conn::new();
    result(conn.version(json!(["w", "1.4.2-asof"])));
    let again = conn.version(json!(["w", "1.4"]));
    assert_eq!(error_message(&again), "server.version already sent");
    assert_eq!(again.error.as_ref().unwrap().code, 1);
    assert!(!again.close, "a second server.version is refused, not fatal");
    assert_eq!(conn.session.version(), ProtocolVersion::parse("1.4.2"));
    assert_eq!(conn.session.negotiated().unwrap().answer, "1.4.2-asof");
}

/// No version in common: an error, and the connection closes (the spec's
/// "the server must close the connection"). Nothing is negotiated.
#[tokio::test]
async fn no_common_version_closes_the_connection() {
    for params in [json!(["w", "1.5"]), json!(["w", ["1.4.5", "1.7"]]), json!(["w", ["1.0", "1.3"]])] {
        let mut conn = Conn::new();
        let resp = conn.version(params.clone());
        assert_eq!(
            error_message(&resp),
            "unsupported protocol version; server speaks 1.4",
            "{params}"
        );
        assert!(resp.close, "{params}");
        assert!(conn.session.negotiated().is_none(), "{params}");
    }
    // A successful negotiation never closes.
    assert!(!Conn::new().version(json!(["w", "1.4"])).close);
}

/// `server.version` need not come first: a connection that never sends it is
/// served at 1.4, as before negotiation existed, and may negotiate later.
#[tokio::test]
async fn server_version_need_not_come_first() {
    let mut conn = Conn::new();
    let features = result(conn.call("server.features", json!([])));
    assert_eq!(features["protocol_min"], "1.4");
    assert_eq!(features["protocol_max"], "1.4");
    result(conn.send(request("blockchain.scripthash.get_balance")));
    assert_eq!(result(conn.version(json!(["w", "1.4"])))[1], "1.4");
}

/// A method the table does not list is "method not found" before and after
/// negotiation.
#[tokio::test]
async fn an_unknown_method_is_not_found() {
    let mut conn = Conn::new();
    let resp = conn.call("blockchain.no_such_method", json!([]));
    assert_eq!(resp.error.as_ref().unwrap().code, -32601, "{resp:?}");
    result(conn.version(json!(["w", "1.4"])));
    let resp = conn.call("mempool.get_info", json!([]));
    assert_eq!(resp.error.as_ref().unwrap().code, -32601, "{resp:?}");
}

/// Every method the table lists reaches its handler at 1.4: none answers
/// "method not found". Guards a table entry whose name is misspelt.
#[tokio::test]
async fn every_listed_method_reaches_its_handler() {
    for method in crate::version::all_methods() {
        let mut conn = Conn::new();
        let resp = conn.call(method, json!([]));
        if let Some(err) = &resp.error {
            assert_ne!(err.code, -32601, "{method}: {err:?}");
        }
    }
}
