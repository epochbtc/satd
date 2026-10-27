//! The scripthash history cap on the Electrum methods whose cost follows
//! the whole history.
//!
//! The index here holds a five-transaction history (one transaction funds
//! and spends, one funds twice), so the cap counts transactions, not rows.
//! Each method is refused with a cap of four and answers exactly as before
//! with a cap of five. The chain is as tall as the history, so the
//! request's pinned tip covers every row. That the refusal reads only about `cap` rows is
//! proven against the chainstate-backed index in the `node` crate.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use bitcoin::{Network, OutPoint, Txid};
use node::chain::state::{AssumeValid, ChainState};
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::NoopVerifier;
use node_index::{
    AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, SpendIndex,
    SpendingRef, StatusUpdate, SubscribeError, Utxo,
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::config::ElectrumConfig;
use crate::dispatch::{Request, Response, dispatch, dispatch_with_subscriptions};
use crate::extras::RocksElectrumExtras;
use crate::handlers::mempool::FeeHistogramCache;
use crate::state::ElectrumState;
use crate::subscribe::Subscriptions;
use crate::types::scripthash_to_wire_hex;

pub(super) const SH: Scripthash = [0x5c; 32];

/// The fixture chain's height: the history's last row is at 9.
pub(super) const TIP_HEIGHT: u32 = 9;

pub(super) fn txid(n: u8) -> Txid {
    Txid::from_byte_array([n; 32])
}

/// Five transactions, six funding and two spending rows, in the
/// `(height, txid, vout/vin)` order the trait promises.
fn history() -> Vec<HistoryEntry> {
    let fund = |height, n, vout, amount_sat| HistoryEntry::Funding {
        height,
        txid: txid(n),
        vout,
        amount_sat,
    };
    vec![
        fund(3, 1, 0, 1_000),
        fund(5, 2, 0, 2_000),
        HistoryEntry::Spending {
            height: 5,
            txid: txid(2),
            vin: 0,
            prev_outpoint: OutPoint { txid: txid(1), vout: 0 },
        },
        fund(5, 3, 1, 3_000),
        fund(8, 4, 0, 4_000),
        fund(8, 4, 1, 5_000),
        HistoryEntry::Spending {
            height: 9,
            txid: txid(5),
            vin: 0,
            prev_outpoint: OutPoint { txid: txid(2), vout: 0 },
        },
    ]
}

/// The history above for `SH`; nothing for any other script.
#[derive(Default)]
struct FixedIndex {
    senders: Mutex<Vec<broadcast::Sender<StatusUpdate>>>,
}

impl AddressIndex for FixedIndex {
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        Ok(if *sh == SH { history() } else { Vec::new() })
    }
    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        Vec::new()
    }
    fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        Ok(if *sh == SH { (12_000, 0) } else { (0, 0) })
    }
    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        if *sh != SH {
            return Ok(Vec::new());
        }
        let utxo = |height, n, vout, amount_sat| Utxo {
            txid: txid(n),
            vout,
            height,
            amount_sat,
        };
        Ok(vec![utxo(5, 3, 1, 3_000), utxo(8, 4, 0, 4_000), utxo(8, 4, 1, 5_000)])
    }
    fn subscribe(&self, _sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        let (tx, rx) = broadcast::channel(4);
        self.senders.lock().push(tx);
        Ok(rx)
    }
}

struct NoSpends;

impl SpendIndex for NoSpends {
    fn spend_of(&self, _outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError> {
        Ok(None)
    }
    fn spends_of_tx(&self, _txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, IndexError> {
        Ok(Vec::new())
    }
}

struct NoBroadcast;

impl node::net::manager::TxBroadcaster for NoBroadcast {
    fn submit_and_announce(
        &self,
        _tx: bitcoin::Transaction,
        _source: node::mempool::pool::TxSource,
        _allow_quarantined: bool,
    ) -> Result<Txid, node::mempool::pool::MempoolError> {
        unreachable!("no test broadcasts")
    }
}

/// An Electrum state over an empty regtest chain and [`FixedIndex`], with
/// the history cap at `cap`.
pub(super) fn electrum_state(cap: usize) -> (ElectrumState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let chain = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            16,
            1,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    // A chain as tall as the history, so a request pinned to the tip reads
    // every row as confirmed.
    for salt in 0..TIP_HEIGHT {
        crate::test_support::extend_tip(&chain, salt);
    }
    let state = ElectrumState {
        chain: chain.clone(),
        mempool: Arc::new(Mempool::new(1_000_000, 0)),
        tx_broadcaster: Arc::new(NoBroadcast),
        address_index: Arc::new(FixedIndex::default()),
        spend_index: Arc::new(NoSpends),
        fee_estimator: Arc::new(FeeEstimator::new()),
        sp_index: None,
        electrum_extras: Arc::new(RocksElectrumExtras::new(chain)),
        network: Network::Regtest,
        config: Arc::new(ElectrumConfig {
            max_history_entries: cap,
            ..Default::default()
        }),
        fee_histogram_cache: Arc::new(FeeHistogramCache::new(Duration::from_secs(10))),
    };
    (state, dir)
}

pub(super) fn request(method: &str) -> Request {
    Request {
        jsonrpc: Some("2.0".into()),
        id: Some(json!(1)),
        method: method.into(),
        params: Some(json!([scripthash_to_wire_hex(&SH)])),
    }
}

fn call(cap: usize, method: &str) -> Response {
    let (state, _dir) = electrum_state(cap);
    dispatch(&state, request(method))
}

fn assert_refused(resp: &Response, cap: usize) {
    let err = resp.error.as_ref().unwrap_or_else(|| panic!("expected a refusal, got {resp:?}"));
    assert_eq!(err.code, 2, "{err:?}");
    assert_eq!(err.message, format!("history too large (cap = {cap} entries)"));
}

pub(super) fn result(resp: Response) -> Value {
    assert!(resp.error.is_none(), "expected an answer, got {resp:?}");
    resp.result.unwrap()
}

pub(super) fn hex(n: u8) -> String {
    txid(n).to_string()
}

#[test]
fn get_history_is_refused_over_the_cap_and_unchanged_at_it() {
    assert_refused(&call(4, "blockchain.scripthash.get_history"), 4);
    assert_eq!(
        result(call(5, "blockchain.scripthash.get_history")),
        json!([
            {"height": 3, "tx_hash": hex(1)},
            {"height": 5, "tx_hash": hex(2)},
            {"height": 5, "tx_hash": hex(3)},
            {"height": 8, "tx_hash": hex(4)},
            {"height": 9, "tx_hash": hex(5)},
        ])
    );
}

#[test]
fn get_balance_is_refused_over_the_cap_and_unchanged_at_it() {
    assert_refused(&call(4, "blockchain.scripthash.get_balance"), 4);
    assert_eq!(
        result(call(5, "blockchain.scripthash.get_balance")),
        json!({"confirmed": 12_000, "unconfirmed": 0})
    );
}

/// Three UTXOs, well under the cap: the refusal follows the history, which
/// is what the UTXO walk costs.
#[test]
fn listunspent_is_refused_over_the_history_cap_and_unchanged_at_it() {
    assert_refused(&call(4, "blockchain.scripthash.listunspent"), 4);
    assert_eq!(
        result(call(5, "blockchain.scripthash.listunspent")),
        json!([
            {"height": 5, "tx_hash": hex(3), "tx_pos": 1, "value": 3_000},
            {"height": 8, "tx_hash": hex(4), "tx_pos": 0, "value": 4_000},
            {"height": 8, "tx_hash": hex(4), "tx_pos": 1, "value": 5_000},
        ])
    );
}

/// `get_first_use` reads one block, so it answers at any cap.
#[test]
fn get_first_use_answers_whatever_the_cap() {
    for cap in [0, 5] {
        let got = result(call(cap, "blockchain.scripthash.get_first_use"));
        assert_eq!(got["height"], 3);
        assert_eq!(got["tx_hash"], hex(1));
    }
}

/// The status a subscribe answers with covers the history `get_history`
/// lists, so it is refused over the same cap, and the refused subscription
/// is not kept.
#[tokio::test]
async fn subscribe_is_refused_over_the_cap_and_not_kept() {
    let (state, _dir) = electrum_state(4);
    let (tx, _rx) = mpsc::channel(8);
    let mut subs = Subscriptions::new(tx, 10);
    let resp = dispatch_with_subscriptions(
        &state,
        &mut subs,
        state.chain.as_ref(),
        state.electrum_extras.clone(),
        request("blockchain.scripthash.subscribe"),
    );
    assert_refused(&resp, 4);
    assert_eq!(subs.scripthash_count(), 0, "a refused subscription must not be kept");

    let (state, _dir) = electrum_state(5);
    let resp = dispatch_with_subscriptions(
        &state,
        &mut subs,
        state.chain.as_ref(),
        state.electrum_extras.clone(),
        request("blockchain.scripthash.subscribe"),
    );
    let rows = node_index::history_rows(state.address_index.as_ref(), &SH, usize::MAX, |_| None)
        .unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(
        result(resp),
        json!(hex::encode(node_index::history_status_hash(&rows)))
    );
    assert_eq!(subs.scripthash_count(), 1);
}
