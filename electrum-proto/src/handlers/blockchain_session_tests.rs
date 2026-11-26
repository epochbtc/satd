//! A connection's protocol session ([`crate::dispatch::dispatch_session`]):
//! `server.version` negotiates once, a failed negotiation closes the
//! connection, and every other method is served at the negotiated version.

use bitcoin::hashes::Hash as _;
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
        (json!(["w", "1.6"]), "1.6"),
        (json!(["w", ["1.4", "1.6"]]), "1.6"),
        // 1.5 inside a range.
        (json!(["w", ["1.2", "1.5"]]), "1.5"),
        (json!(["w", ["1.3", "1.4.2"]]), "1.4.2"),
        (json!(["w", "1.4.2-asof"]), "1.4.2-asof"),
        (json!(["w", ["1.4", "1.4.2-asof"]]), "1.4.2-asof"),
        // Extra arguments are ignored.
        (
            json!(["w", ["1.4", "1.6"], "extra", 9999.9, {"dd": {}}]),
            "1.6",
        ),
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
    assert!(
        !again.close,
        "a second server.version is refused, not fatal"
    );
    assert_eq!(conn.session.version(), ProtocolVersion::parse("1.4.2"));
    assert_eq!(conn.session.negotiated().unwrap().answer, "1.4.2-asof");
}

/// No version in common: an error, and the connection closes (the spec's
/// "the server must close the connection"). Nothing is negotiated.
#[tokio::test]
async fn no_common_version_closes_the_connection() {
    for params in [
        json!(["w", "1.3"]),
        json!(["w", ["1.7", "1.8"]]),
        json!(["w", ["1.0", "1.3"]]),
    ] {
        let mut conn = Conn::new();
        let resp = conn.version(params.clone());
        assert_eq!(
            error_message(&resp),
            "unsupported protocol version; server speaks 1.4 to 1.6",
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
    assert_eq!(features["protocol_max"], "1.6");
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

/// Every method the table lists reaches its handler at the first version
/// it is served at: none answers "method not found". Guards a table entry
/// whose name is misspelt.
#[tokio::test]
async fn every_listed_method_reaches_its_handler() {
    for (method, since) in crate::version::all_methods() {
        let mut conn = Conn::new();
        result(conn.version(json!(["w", since.to_string()])));
        let resp = conn.call(method, json!([]));
        if let Some(err) = &resp.error {
            assert_ne!(err.code, -32601, "{method}: {err:?}");
        }
    }
}

fn not_found(resp: &Response) -> bool {
    resp.error.as_ref().is_some_and(|e| e.code == -32601)
}

/// `blockchain.relayfee` is removed at 1.6 and served below it, including
/// on a connection that never negotiates; `mempool.get_info` is the other
/// way round.
#[tokio::test]
async fn relayfee_and_get_info_follow_the_version() {
    let mut never = Conn::new();
    result(never.call("blockchain.relayfee", json!([])));
    assert!(not_found(&never.call("mempool.get_info", json!([]))));
    for v in ["1.4", "1.4.2", "1.5"] {
        let mut conn = Conn::new();
        result(conn.version(json!(["w", v])));
        result(conn.call("blockchain.relayfee", json!([])));
        assert!(not_found(&conn.call("mempool.get_info", json!([]))), "{v}");
    }
    let mut conn = Conn::new();
    result(conn.version(json!(["w", ["1.4", "1.6"]])));
    assert!(not_found(&conn.call("blockchain.relayfee", json!([]))));
    result(conn.call("mempool.get_info", json!([])));
}

/// `mempool.get_info` reports `getmempoolinfo`'s three feerates, in
/// BTC/kvB, and `minrelaytxfee` is what `relayfee` answered.
#[tokio::test]
async fn get_info_matches_getmempoolinfo() {
    let mut old = Conn::new();
    let relayfee = result(old.call("blockchain.relayfee", json!([])));
    let mut conn = Conn::new();
    result(conn.version(json!(["w", "1.6"])));
    let info = result(conn.call("mempool.get_info", json!([])));
    let rpc = node::rpc::rawtx::get_mempool_info(&conn.state.mempool);
    for key in ["mempoolminfee", "minrelaytxfee", "incrementalrelayfee"] {
        let rpc_value: f64 = rpc[key].to_string().parse().unwrap();
        assert_eq!(
            info[key].as_f64(),
            Some(rpc_value),
            "{key}: {info} vs {rpc}"
        );
    }
    assert_eq!(info["minrelaytxfee"], relayfee);
    assert_eq!(info.as_object().unwrap().len(), 3, "{info}");
}

/// From 1.6 `block.headers` lists the headers; before it they are one
/// string. The same headers either way, with `cp_height` absent or zero; a
/// nonzero `cp_height` is refused at both.
#[tokio::test]
async fn block_headers_take_the_versions_shape() {
    let mut old = Conn::new();
    result(old.version(json!(["w", "1.4"])));
    let mut new = Conn::new();
    result(new.version(json!(["w", "1.6"])));
    for params in [json!([0, 3]), json!([0, 3, 0])] {
        let hex = result(old.call("blockchain.block.headers", params.clone()));
        let list = result(new.call("blockchain.block.headers", params.clone()));
        assert_eq!(hex["count"], 3);
        assert_eq!(list["count"], 3);
        assert_eq!(hex["max"], list["max"]);
        assert!(
            list.get("hex").is_none() && hex.get("headers").is_none(),
            "{list} {hex}"
        );
        let headers: Vec<&str> = list["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap())
            .collect();
        assert_eq!(headers.len(), 3);
        assert!(headers.iter().all(|h| h.len() == 160), "{headers:?}");
        assert_eq!(headers.concat(), hex["hex"].as_str().unwrap());
        assert_eq!(list.as_object().unwrap().len(), 3, "{list}");
    }
    // Past the tip: only the headers that exist.
    let tail = result(new.call(
        "blockchain.block.headers",
        json!([super::historycap_tests::TIP_HEIGHT, 5]),
    ));
    assert_eq!(tail["count"], 1);
    assert_eq!(tail["headers"].as_array().map(Vec::len), Some(1));
    for conn in [&mut old, &mut new] {
        let resp = conn.call("blockchain.block.headers", json!([0, 3, 5]));
        assert_eq!(
            error_message(&resp),
            "checkpoint proof (nonzero cp_height) is not supported by this server"
        );
    }
}

/// `estimatefee`'s `mode`: ECONOMICAL, CONSERVATIVE in any case, or no
/// mode; anything else is refused with ElectrumX's message.
#[tokio::test]
async fn estimatefee_takes_a_mode() {
    use super::estimatefee_conservative as conservative;
    assert!(!conservative(None).unwrap());
    assert!(!conservative(Some(&json!(null))).unwrap());
    assert!(!conservative(Some(&json!(7))).unwrap());
    assert!(!conservative(Some(&json!("ECONOMICAL"))).unwrap());
    assert!(!conservative(Some(&json!("economical"))).unwrap());
    assert!(conservative(Some(&json!("CONSERVATIVE"))).unwrap());
    assert!(conservative(Some(&json!("Conservative"))).unwrap());
    assert_eq!(
        conservative(Some(&json!("blend"))).unwrap_err().message,
        "unknown estimatefee mode: BLEND"
    );

    let mut conn = Conn::new();
    result(conn.version(json!(["w", "1.6"])));
    for params in [
        json!([6]),
        json!([6, "ECONOMICAL"]),
        json!([6, "CONSERVATIVE"]),
    ] {
        assert!(
            result(conn.call("blockchain.estimatefee", params.clone())).is_number(),
            "{params}"
        );
    }
    let resp = conn.call("blockchain.estimatefee", json!([6, "UNSET"]));
    assert_eq!(error_message(&resp), "unknown estimatefee mode: UNSET");
    assert_eq!(resp.error.as_ref().unwrap().code, 1);
}

/// `broadcast_package` refuses, before trying any member, an empty package
/// and one that is not a child with its parents, as `submitpackage` does.
#[tokio::test]
async fn broadcast_package_refuses_a_malformed_package() {
    use bitcoin::consensus::encode::serialize;
    let tx = |salt: u8| {
        let mut tx = crate::test_support::regtest_block(
            bitcoin::BlockHash::from_byte_array([salt; 32]),
            1,
            u32::from(salt),
            Vec::new(),
        )
        .txdata
        .remove(0);
        tx.input[0].previous_output =
            bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([salt; 32]), 0);
        hex::encode(serialize(&tx))
    };
    let mut conn = Conn::new();
    result(conn.version(json!(["w", "1.6"])));
    let resp = conn.call("blockchain.transaction.broadcast_package", json!([[]]));
    assert_eq!(
        error_message(&resp),
        "the tx package was rejected by network rules.\n\nArray must contain between 1 and 25 transactions."
    );
    // Two transactions, neither spending the other.
    let resp = conn.call(
        "blockchain.transaction.broadcast_package",
        json!([[tx(1), tx(2)]]),
    );
    assert_eq!(
        error_message(&resp),
        "the tx package was rejected by network rules.\n\npackage topology disallowed. \
         not child-with-parents or parents depend on each other."
    );
    let resp = conn.call("blockchain.transaction.broadcast_package", json!([["zz"]]));
    assert_eq!(resp.error.as_ref().unwrap().code, -32602, "{resp:?}");
}
