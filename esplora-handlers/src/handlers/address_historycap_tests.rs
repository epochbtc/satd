//! The history cap on the Esplora address routes whose cost follows the
//! whole history: the stats (`/address/:addr`, `/scripthash/:hash`), the
//! UTXO list, and the status stream (`.../sse`), whose updates come from a
//! status recompute over the history.
//!
//! The index holds a five-transaction history (one transaction funds and
//! spends, one funds twice), so the cap counts transactions, not rows. Each
//! route is refused with a cap of four and answers exactly as before with a
//! cap of five. That the refusal reads only about `cap` rows is proven
//! against the chainstate-backed index in the `node` crate.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
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
use tokio::sync::{Semaphore, broadcast};

use super::{build_address_info, build_utxos, compute_chain_stats_from_history};
use crate::config::EsploraConfig;
use crate::error::EsploraError;
use crate::state::EsploraState;

const SH: Scripthash = [0x5c; 32];

fn txid(n: u8) -> Txid {
    Txid::from_byte_array([n; 32])
}

/// Five transactions, five funding and two spending rows, in the
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

struct FixedIndex;

impl AddressIndex for FixedIndex {
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        Ok(if *sh == SH { history() } else { Vec::new() })
    }
    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        Vec::new()
    }
    fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        unreachable!("Esplora derives balances from the history")
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
        // The stream holds the receiver; the sender may go.
        Ok(broadcast::channel(4).1)
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

/// An Esplora state over an empty regtest chain and [`FixedIndex`], with
/// the history cap at `cap`.
fn esplora_state(cap: usize) -> (EsploraState, tempfile::TempDir) {
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
    let state = EsploraState {
        chain,
        mempool: Arc::new(Mempool::new(1_000_000, 0)),
        tx_broadcaster: Arc::new(NoBroadcast),
        address_index: Arc::new(FixedIndex),
        spend_index: Arc::new(NoSpends),
        fee_estimator: Arc::new(FeeEstimator::new()),
        network: Network::Regtest,
        config: Arc::new(EsploraConfig {
            max_history_entries: cap,
            ..Default::default()
        }),
        sse_semaphore: Arc::new(Semaphore::new(16)),
        work_permits: None,
    };
    (state, dir)
}

fn assert_refused(err: EsploraError, cap: usize) {
    assert!(matches!(err, EsploraError::HistoryTooLarge(c) if c == cap), "{err:?}");
    let msg = err.to_string();
    assert_eq!(msg, format!("Too many history entries (more than {cap} transactions)"));
    assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
}

#[test]
fn address_stats_are_refused_over_the_cap_and_unchanged_at_it() {
    let (state, _dir) = esplora_state(4);
    let err = build_address_info(&state, "label", &SH).expect_err("over the cap");
    assert_refused(err, 4);

    let (state, _dir) = esplora_state(5);
    let info = build_address_info(&state, "label", &SH).unwrap();
    let expected = compute_chain_stats_from_history(&history());
    assert_eq!(
        serde_json::to_value(&info.chain_stats).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&info.chain_stats).unwrap(),
        serde_json::json!({
            "tx_count": 5,
            "funded_txo_count": 5,
            "funded_txo_sum": 15_000,
            "spent_txo_count": 2,
            "spent_txo_sum": 3_000,
        })
    );
}

/// Three UTXOs, well under the cap: the refusal follows the history, which
/// is what the UTXO walk costs.
#[test]
fn utxo_list_is_refused_over_the_history_cap_and_unchanged_at_it() {
    let (state, _dir) = esplora_state(4);
    let err = build_utxos(&state, &SH).expect_err("over the cap");
    assert_refused(err, 4);

    let (state, _dir) = esplora_state(5);
    let got: Vec<(String, u32, u64)> = build_utxos(&state, &SH)
        .unwrap()
        .into_iter()
        .map(|u| (u.txid, u.vout, u.value))
        .collect();
    assert_eq!(
        got,
        vec![
            (txid(3).to_string(), 1, 3_000),
            (txid(4).to_string(), 0, 4_000),
            (txid(4).to_string(), 1, 5_000),
        ]
    );
}

/// The status stream's updates come from a recompute the notifier refuses
/// over the cap, so a stream for such a script would stay silent: it is
/// refused when it is opened.
#[tokio::test]
async fn status_stream_is_refused_over_the_cap_and_opens_at_it() {
    use axum::extract::{Path, State};

    let wire = hex::encode(SH);
    let (state, _dir) = esplora_state(4);
    match crate::handlers::sse::scripthash_sse(State(state), None, Path(wire.clone())).await {
        Err(err) => assert_refused(err, 4),
        Ok(_) => panic!("a stream over the cap must be refused"),
    }

    let (state, _dir) = esplora_state(5);
    assert!(
        crate::handlers::sse::scripthash_sse(State(state), None, Path(wire)).await.is_ok(),
        "a stream at the cap opens"
    );
}
