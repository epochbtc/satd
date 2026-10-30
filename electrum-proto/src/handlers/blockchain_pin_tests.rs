//! The stamped methods answer for the pinned tip (`node::chain::pin`): rows
//! confirmed above it confirmed while the request ran, and are served as
//! the unconfirmed transactions they were at the pin.
//!
//! The scripthash methods use the history-cap tests' five transactions, at
//! heights 3, 5, 5, 8 and 9 (the last spends tx 2's output). Pinned at 5,
//! the transactions at 8 and 9 are late. The fixture's txindex has none of
//! them, so a late row is height `0` with no fee.

use bitcoin::hashes::Hash as _;
use bitcoin::BlockHash;
use node::chain::pin::Pin;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::historycap_tests::{SH, TIP_HEIGHT, electrum_state, hex, request, result};
use super::{
    scripthash_get_balance, scripthash_get_history, scripthash_listunspent, transaction_get,
    transaction_get_merkle, transaction_id_from_pos,
};
use crate::dispatch::{Request, dispatch_with_subscriptions};
use crate::state::ElectrumState;
use crate::subscribe::Subscriptions;
use crate::test_support::extend_tip_with;
use crate::types::scripthash_to_wire_hex;

fn pin_at(height: u32) -> Pin {
    Pin {
        hash: BlockHash::all_zeros(),
        height,
        mempool: true,
    }
}

fn params() -> Value {
    json!([scripthash_to_wire_hex(&SH)])
}

#[test]
fn history_rows_above_the_pin_are_unconfirmed() {
    let (state, _dir) = electrum_state(100);
    assert_eq!(
        scripthash_get_history(&state, params(), &pin_at(5)).unwrap(),
        json!([
            {"height": 3, "tx_hash": hex(1)},
            {"height": 5, "tx_hash": hex(2)},
            {"height": 5, "tx_hash": hex(3)},
            {"height": 0, "tx_hash": hex(4)},
            {"height": 0, "tx_hash": hex(5)},
        ])
    );
    // Pinned at the history's top, nothing moves.
    let all = scripthash_get_history(&state, params(), &pin_at(9)).unwrap();
    assert_eq!(all.as_array().unwrap().last().unwrap()["height"], 9);
}

/// As of 5, the confirmed balance is tx 2's and tx 3's outputs (tx 1's was
/// spent at 5); what tx 4 funds and tx 5 spends is the unconfirmed delta.
#[test]
fn balance_above_the_pin_is_unconfirmed() {
    let (state, _dir) = electrum_state(100);
    assert_eq!(
        scripthash_get_balance(&state, params(), &pin_at(5)).unwrap(),
        json!({"confirmed": 5_000, "unconfirmed": 7_000})
    );
    assert_eq!(
        scripthash_get_balance(&state, params(), &pin_at(9)).unwrap(),
        json!({"confirmed": 12_000, "unconfirmed": 0})
    );
}

/// tx 4's outputs, created at 8, were unconfirmed as of 5 and are listed
/// after the confirmed one.
#[test]
fn utxos_created_above_the_pin_are_unconfirmed() {
    let (state, _dir) = electrum_state(100);
    assert_eq!(
        scripthash_listunspent(&state, params(), &pin_at(5)).unwrap(),
        json!([
            {"height": 5, "tx_hash": hex(3), "tx_pos": 1, "value": 3_000},
            {"height": 0, "tx_hash": hex(4), "tx_pos": 0, "value": 4_000},
            {"height": 0, "tx_hash": hex(4), "tx_pos": 1, "value": 5_000},
        ])
    );
}

/// Connect one more block on the fixture chain; its coinbase is the
/// transaction the transaction methods look up. Returns the coinbase's txid
/// and the block's height.
fn chain_with_block_above(state: &ElectrumState) -> (bitcoin::Txid, u32) {
    let block = extend_tip_with(&state.chain, 1_000, Vec::new());
    (block.txdata[0].compute_txid(), TIP_HEIGHT + 1)
}

/// A transaction confirmed above the pin has no block as of it: no
/// confirmation in `transaction.get`, no proof from `get_merkle`, and no
/// position in its block from `id_from_pos`.
#[test]
fn transaction_methods_see_nothing_above_the_pin() {
    let (state, _dir) = electrum_state(100);
    let (txid, height) = chain_with_block_above(&state);
    let below = pin_at(height - 1);
    let at = Pin {
        hash: state.chain.tip_hash(),
        height,
        mempool: true,
    };

    let verbose = json!([txid.to_string(), true]);
    let got = transaction_get(&state, verbose.clone(), &below).unwrap();
    assert!(got.get("blockhash").is_none(), "{got}");
    assert!(got.get("confirmations").is_none(), "{got}");
    let got = transaction_get(&state, verbose, &at).unwrap();
    assert_eq!(got["blockhash"], at.hash.to_string());
    assert_eq!(got["confirmations"], 1);

    let merkle = json!([txid.to_string()]);
    assert!(transaction_get_merkle(&state, merkle.clone(), &below).is_err());
    assert_eq!(
        transaction_get_merkle(&state, merkle, &at).unwrap()["block_height"],
        height
    );

    let pos = json!([height, 0]);
    assert!(transaction_id_from_pos(&state, pos.clone(), &below).is_err());
    assert_eq!(
        transaction_id_from_pos(&state, pos, &at).unwrap(),
        json!(txid.to_string())
    );
}

/// `confirmations` counts to the pin, not to the live tip.
#[test]
fn confirmations_count_to_the_pin() {
    let (state, _dir) = electrum_state(100);
    let (txid, height) = chain_with_block_above(&state);
    for salt in 0..3 {
        crate::test_support::extend_tip(&state.chain, 2_000 + salt);
    }
    let got = transaction_get(&state, json!([txid.to_string(), true]), &pin_at(height + 1)).unwrap();
    assert_eq!(got["confirmations"], 2);
}

fn version(protocol: Value) -> Request {
    Request {
        jsonrpc: Some("2.0".into()),
        id: Some(json!(0)),
        method: "server.version".into(),
        params: Some(json!(["test", protocol])),
    }
}

/// Every stamped answer names the block it was read at, whatever the
/// connection negotiated, as on rbitcoin; errors and other methods carry no
/// stamp. `server.version` accepts rbitcoin's `1.4.2-asof` and answers with
/// it, at either end of a range too.
#[tokio::test]
async fn stamped_answers_name_the_pinned_tip_on_every_connection() {
    let (state, _dir) = electrum_state(100);
    let call = |subs: &mut Subscriptions, req: Request| {
        dispatch_with_subscriptions(
            &state,
            subs,
            state.chain.as_ref(),
            state.electrum_extras.clone(),
            req,
        )
    };
    let (tx, _rx) = mpsc::channel(8);
    let mut subs = Subscriptions::new(tx, 10);
    let (tip, height) = state.chain.tip_snapshot();

    for protocol in [json!("1.4"), json!("1.4.2-asof")] {
        let answered = result(call(&mut subs, version(protocol.clone())));
        assert_eq!(answered[1], protocol);
        for method in [
            "blockchain.scripthash.get_history",
            "blockchain.scripthash.get_balance",
            "blockchain.scripthash.listunspent",
        ] {
            let wire = serde_json::to_value(call(&mut subs, request(method))).unwrap();
            assert_eq!(wire["chain_tip"], tip.to_string(), "{method}");
            assert_eq!(wire["chain_tip_height"], height, "{method}");
        }
    }
    assert_eq!(
        result(call(&mut subs, version(json!(["1.4", "1.4.2-asof"]))))[1],
        "1.4.2-asof"
    );

    // Unstamped methods, and errors, carry no stamp.
    let wire = serde_json::to_value(call(&mut subs, request("blockchain.scripthash.get_mempool")))
        .unwrap();
    assert!(wire.get("chain_tip").is_none(), "{wire}");
    let mut bad = request("blockchain.scripthash.get_balance");
    bad.params = Some(json!(["not a scripthash"]));
    let wire = serde_json::to_value(call(&mut subs, bad)).unwrap();
    assert!(wire.get("error").is_some() && wire.get("chain_tip").is_none(), "{wire}");
}

fn spend(prev: bitcoin::OutPoint, value: u64) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: prev,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: crate::test_support::anyone_can_spend_witness(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: crate::test_support::anyone_can_spend(),
        }],
    }
}

/// A late transaction is height `-1` when it spends one that was also
/// unconfirmed as of the pin, `0` when its parents were confirmed, and
/// carries the fee its parents' outputs give it.
#[test]
fn a_late_transaction_has_its_mempool_height_and_fee() {
    let (state, _dir) = electrum_state(100);
    // Mature the fixture chain's first coinbase.
    let first = state
        .electrum_extras
        .txid_at_pos(1, 0)
        .expect("block 1's coinbase");
    for salt in 0..100 {
        crate::test_support::extend_tip(&state.chain, 3_000 + salt);
    }
    let pin = pin_at(state.chain.tip_height());
    let a = spend(bitcoin::OutPoint { txid: first, vout: 0 }, 5_000_000_000 - 1_000);
    let b = spend(
        bitcoin::OutPoint {
            txid: a.compute_txid(),
            vout: 0,
        },
        5_000_000_000 - 3_000,
    );
    extend_tip_with(&state.chain, 4_000, vec![a.clone()]);
    extend_tip_with(&state.chain, 4_001, vec![b.clone()]);

    assert_eq!(
        super::LateFacts::new(&state, &pin).of(&a.compute_txid()),
        (0, Some(1_000))
    );
    assert_eq!(
        super::LateFacts::new(&state, &pin).of(&b.compute_txid()),
        (-1, Some(2_000))
    );
}

/// A late transaction whose parent sits in an OP_RETURN-stripped block still
/// carries its fee: the parent is read from its stored form, found by its
/// recorded txid, and its output values are the original's.
#[test]
fn a_late_transaction_with_a_parent_in_a_stripped_block_keeps_its_fee() {
    let (state, _dir) = electrum_state(100);
    let first = state
        .electrum_extras
        .txid_at_pos(1, 0)
        .expect("block 1's coinbase");
    for salt in 0..100 {
        crate::test_support::extend_tip(&state.chain, 5_000 + salt);
    }
    let mut parent = spend(bitcoin::OutPoint { txid: first, vout: 0 }, 5_000_000_000 - 1_000);
    let mut data = vec![0x6a, 0x4d, 0x84, 0x13];
    data.resize(5_000, 0x5a);
    parent.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(data),
    });
    // `regtest_block` adds the salt to the time: a salt that dates the block
    // now takes the tip out of initial block download, where strips wait.
    let now_salt = |height: u32| {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
        now - 1_708_000_000 - 600 * height
    };
    let parent_height = state.chain.tip_height() + 1;
    let parent_block = extend_tip_with(&state.chain, now_salt(parent_height), vec![parent.clone()]);
    let stripped = state.chain.strip_block(&parent_block.block_hash(), 4_096).expect("strip");
    assert!(
        matches!(stripped, node::chain::state::StripOutcome::Stripped(_)),
        "premise: the parent's block is stripped: {stripped:?}"
    );
    let pin = pin_at(state.chain.tip_height());
    let child = spend(
        bitcoin::OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        5_000_000_000 - 3_000,
    );
    extend_tip_with(&state.chain, now_salt(parent_height + 1) + 1, vec![child.clone()]);

    assert_eq!(
        super::LateFacts::new(&state, &pin).of(&child.compute_txid()),
        (0, Some(2_000))
    );
}

mod races {
    //! Reads that a block connecting mid-request splits.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use bitcoin::{OutPoint, Txid};
    use node_index::{
        AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, StatusUpdate,
        SubscribeError, Utxo,
    };
    use tokio::sync::broadcast;

    use super::super::historycap_tests::FixedIndex;
    use super::*;

    /// [`FixedIndex`], except that the first `balance` read is the one taken
    /// before tx 4 and tx 5's blocks connected: tx 2's and tx 3's outputs.
    #[derive(Default)]
    struct StaleFirstBalance {
        inner: FixedIndex,
        balance_reads: AtomicUsize,
    }

    impl AddressIndex for StaleFirstBalance {
        fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            self.inner.confirmed_history(sh)
        }
        fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            self.inner.mempool_history(sh)
        }
        fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            if self.balance_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok((5_000, 0));
            }
            self.inner.balance(sh)
        }
        fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            self.inner.utxos(sh)
        }
        fn subscribe(&self, sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            self.inner.subscribe(sh)
        }
    }

    /// A balance read before a block connected, paired with a history read
    /// after, describes no moment: the pair is read again until the history's
    /// confirmed balance is the balance's.
    #[test]
    fn a_balance_split_by_a_block_is_read_again() {
        let (mut state, _dir) = electrum_state(100);
        let index = Arc::new(StaleFirstBalance::default());
        state.address_index = index.clone();
        assert_eq!(
            scripthash_get_balance(&state, params(), &pin_at(5)).unwrap(),
            json!({"confirmed": 5_000, "unconfirmed": 7_000})
        );
        assert_eq!(index.balance_reads.load(Ordering::SeqCst), 2);
    }

    /// [`FixedIndex`], except that every `balance` read is a stale one.
    #[derive(Default)]
    struct AlwaysStaleBalance(FixedIndex);

    impl AddressIndex for AlwaysStaleBalance {
        fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            self.0.confirmed_history(sh)
        }
        fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            self.0.mempool_history(sh)
        }
        fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            Ok((5_000, 0))
        }
        fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            self.0.utxos(sh)
        }
        fn subscribe(&self, sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            self.0.subscribe(sh)
        }
    }

    /// A balance that never matches its history is refused like a chain view
    /// that never settles, not answered from a split pair.
    #[test]
    fn a_balance_split_on_every_read_is_refused() {
        let (mut state, _dir) = electrum_state(100);
        state.address_index = Arc::new(AlwaysStaleBalance::default());
        let err = scripthash_get_balance(&state, params(), &pin_at(5)).unwrap_err();
        assert_eq!(err.message, node::chain::pin::CHAIN_VIEW_MOVED);
    }

    /// [`FixedIndex`] plus `tx`, which is in the mempool until the index's
    /// first read of either part, and confirmed at 10 for every read after.
    struct ConfirmsOnFirstRead {
        inner: FixedIndex,
        tx: Txid,
        confirmed: AtomicBool,
    }

    impl AddressIndex for ConfirmsOnFirstRead {
        fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            self.inner.confirmed_history(sh)
        }
        fn confirmed_txs_in_chain_order(
            &self,
            sh: &Scripthash,
            limit: usize,
        ) -> Result<Vec<(u32, Txid)>, IndexError> {
            let mut rows = self.inner.confirmed_txs_in_chain_order(sh, limit)?;
            if self.confirmed.swap(true, Ordering::SeqCst) {
                rows.push((10, self.tx));
            }
            Ok(rows)
        }
        fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            if self.confirmed.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![MempoolHistoryEntry { txid: self.tx }]
            }
        }
        fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            self.inner.balance(sh)
        }
        fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            let mut utxos = self.inner.utxos(sh)?;
            if self.confirmed.swap(true, Ordering::SeqCst) {
                utxos.push(Utxo {
                    txid: self.tx,
                    vout: 0,
                    height: 10,
                    amount_sat: 5_000_000_000 - 1_000,
                });
            }
            Ok(utxos)
        }
        fn subscribe(&self, sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            self.inner.subscribe(sh)
        }
    }

    /// The fixture chain grown past coinbase maturity, with a spend of block
    /// 1's coinbase (paying [`crate::test_support::anyone_can_spend`]) in
    /// the mempool, behind a [`ConfirmsOnFirstRead`] index for it.
    fn confirming_mid_read() -> (ElectrumState, tempfile::TempDir, Txid) {
        let (mut state, dir) = electrum_state(100);
        let first = state.electrum_extras.txid_at_pos(1, 0).unwrap();
        for salt in 0..100 {
            crate::test_support::extend_tip(&state.chain, 5_000 + salt);
        }
        let tx = spend(OutPoint { txid: first, vout: 0 }, 5_000_000_000 - 1_000);
        let txid = state
            .mempool
            .accept_transaction(
                tx,
                &state.chain,
                &node::validation::script::NoopVerifier,
                node::mempool::pool::TxSource::Rpc,
                false,
            )
            .expect("into the mempool");
        state.address_index = Arc::new(ConfirmsOnFirstRead {
            inner: FixedIndex::default(),
            tx: txid,
            confirmed: AtomicBool::new(false),
        });
        (state, dir, txid)
    }

    /// An output whose transaction confirms between `listunspent`'s two
    /// reads is listed once, as the unconfirmed output it was at the pin.
    #[test]
    fn an_output_confirming_mid_listunspent_is_listed_once() {
        let (state, _dir, txid) = confirming_mid_read();
        let sh = node_index::scripthash_of(&crate::test_support::anyone_can_spend());
        let got = scripthash_listunspent(
            &state,
            json!([scripthash_to_wire_hex(&sh)]),
            &pin_at(9),
        )
        .unwrap();
        assert_eq!(
            got,
            json!([{"height": 0, "tx_hash": txid.to_string(), "tx_pos": 0, "value": 5_000_000_000u64 - 1_000}])
        );
    }

    /// [`FixedIndex`] plus `tx` in the mempool part, for every script.
    struct InMempool {
        inner: FixedIndex,
        tx: Txid,
    }

    impl AddressIndex for InMempool {
        fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            self.inner.confirmed_history(sh)
        }
        fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            vec![MempoolHistoryEntry { txid: self.tx }]
        }
        fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            self.inner.balance(sh)
        }
        fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            self.inner.utxos(sh)
        }
        fn subscribe(&self, sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            self.inner.subscribe(sh)
        }
    }

    /// A mempool transaction whose parent confirmed above the pin spent an
    /// unconfirmed parent as of the pin: `-1`, in `get_history` and in
    /// `listunspent`, as a late transaction's child would be. Pinned at or
    /// above the parent's block, it is `0`.
    #[test]
    fn a_mempool_child_of_a_late_parent_is_minus_one() {
        let (mut state, _dir) = electrum_state(100);
        let first = state.electrum_extras.txid_at_pos(1, 0).unwrap();
        for salt in 0..100 {
            crate::test_support::extend_tip(&state.chain, 6_000 + salt);
        }
        let pin = pin_at(state.chain.tip_height());
        let parent = spend(OutPoint { txid: first, vout: 0 }, 5_000_000_000 - 1_000);
        extend_tip_with(&state.chain, 6_500, vec![parent.clone()]);
        let child = spend(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            5_000_000_000 - 2_000,
        );
        let txid = state
            .mempool
            .accept_transaction(
                child,
                &state.chain,
                &node::validation::script::NoopVerifier,
                node::mempool::pool::TxSource::Rpc,
                false,
            )
            .expect("into the mempool");
        state.address_index = Arc::new(InMempool {
            inner: FixedIndex::default(),
            tx: txid,
        });
        let sh = json!([scripthash_to_wire_hex(&node_index::scripthash_of(
            &crate::test_support::anyone_can_spend()
        ))]);

        let history = scripthash_get_history(&state, sh.clone(), &pin).unwrap();
        assert_eq!(history, json!([{"height": -1, "tx_hash": txid.to_string(), "fee": 1_000}]));
        let utxos = scripthash_listunspent(&state, sh.clone(), &pin).unwrap();
        assert_eq!(utxos[0]["height"], -1, "{utxos}");

        let now = pin_at(state.chain.tip_height());
        let history = scripthash_get_history(&state, sh.clone(), &now).unwrap();
        assert_eq!(history[0]["height"], 0, "{history}");
        let utxos = scripthash_listunspent(&state, sh, &now).unwrap();
        assert_eq!(utxos[0]["height"], 0, "{utxos}");
    }

    /// A transaction that confirms between the history's two reads is in at
    /// least one of them, and listed once, as the unconfirmed transaction it
    /// was at the pin.
    #[test]
    fn a_transaction_confirming_mid_history_is_listed_once() {
        let (state, _dir, txid) = confirming_mid_read();
        let rows = scripthash_get_history(&state, params(), &pin_at(9)).unwrap();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 6, "{rows:?}");
        assert_eq!(rows[5], json!({"height": 0, "tx_hash": txid.to_string(), "fee": 1_000}));
    }
}

fn asof(height: u32) -> Pin {
    Pin {
        mempool: false,
        ..pin_at(height)
    }
}

/// As of 5: the rows at or below it, the balance funded and unspent by it,
/// and the outputs unspent by it, read from the history. tx 2's output,
/// spent at 9, is unspent as of 5; tx 1's, spent at 5, is not.
#[test]
fn asof_answers_from_the_history_at_the_block() {
    let (state, _dir) = electrum_state(100);
    assert_eq!(
        scripthash_get_history(&state, params(), &asof(5)).unwrap(),
        json!([
            {"height": 3, "tx_hash": hex(1)},
            {"height": 5, "tx_hash": hex(2)},
            {"height": 5, "tx_hash": hex(3)},
        ])
    );
    assert_eq!(
        scripthash_get_balance(&state, params(), &asof(5)).unwrap(),
        json!({"confirmed": 5_000, "unconfirmed": 0})
    );
    assert_eq!(
        scripthash_listunspent(&state, params(), &asof(5)).unwrap(),
        json!([
            {"height": 5, "tx_hash": hex(2), "tx_pos": 0, "value": 2_000},
            {"height": 5, "tx_hash": hex(3), "tx_pos": 1, "value": 3_000},
        ])
    );
    assert_eq!(
        scripthash_listunspent(&state, params(), &asof(2)).unwrap(),
        json!([])
    );
}

/// As of a block, a transaction confirmed after it is not found.
#[test]
fn asof_transaction_get_needs_a_confirmation_by_the_block() {
    let (state, _dir) = electrum_state(100);
    let (txid, height) = chain_with_block_above(&state);
    let req = json!([txid.to_string()]);
    assert!(transaction_get(&state, req.clone(), &asof(height - 1)).is_err());
    assert!(transaction_get(&state, req, &asof(height)).is_ok());
}

fn with_params(method: &str, params: Value) -> Request {
    Request {
        params: Some(params),
        ..request(method)
    }
}

fn dispatched(state: &ElectrumState, req: Request) -> Value {
    serde_json::to_value(crate::dispatch::dispatch(state, req)).unwrap()
}

/// The trailing `asof:` argument through dispatch: pins the answer to a
/// best-chain block and stamps it, without any negotiation; keeps the
/// method's own optional arguments; and is an error on a hash not on the
/// best chain, on a malformed hash, and on a method that does not take it.
#[tokio::test]
async fn trailing_asof_pins_stamps_and_is_refused_where_it_does_not_apply() {
    let (state, _dir) = electrum_state(100);
    let five = state.chain.get_block_hash_by_height(5).unwrap();
    let tag = format!("asof:{five}");
    let sh = scripthash_to_wire_hex(&SH);

    let wire = dispatched(&state, with_params("blockchain.scripthash.get_balance", json!([sh, tag])));
    assert_eq!(wire["result"], json!({"confirmed": 5_000, "unconfirmed": 0}), "{wire}");
    assert_eq!(wire["chain_tip"], five.to_string());
    assert_eq!(wire["chain_tip_height"], 5);

    // The optional argument before it is still read: verbose, here.
    let coinbase = state.electrum_extras.txid_at_pos(5, 0).unwrap();
    let wire = dispatched(
        &state,
        with_params("blockchain.transaction.get", json!([coinbase.to_string(), true, tag])),
    );
    assert_eq!(wire["result"]["confirmations"], 1, "{wire}");

    let error = |wire: &Value| wire["error"]["message"].as_str().unwrap_or_default().to_string();
    let unknown = format!("asof:{}", BlockHash::all_zeros());
    let wire = dispatched(&state, with_params("blockchain.scripthash.get_balance", json!([sh, unknown])));
    assert_eq!(error(&wire), "asof not on chain", "{wire}");
    assert!(wire.get("chain_tip").is_none());

    let wire = dispatched(&state, with_params("blockchain.scripthash.get_balance", json!([sh, "asof:xyz"])));
    assert_eq!(error(&wire), "asof must be asof:<blockhash>", "{wire}");

    let wire = dispatched(&state, with_params("blockchain.scripthash.get_mempool", json!([sh, tag])));
    assert_eq!(error(&wire), "asof is not supported by blockchain.scripthash.get_mempool");

    let (tx, _rx) = mpsc::channel(8);
    let mut subs = Subscriptions::new(tx, 10);
    let resp = dispatch_with_subscriptions(
        &state,
        &mut subs,
        state.chain.as_ref(),
        state.electrum_extras.clone(),
        with_params("blockchain.scripthash.subscribe", json!([sh, tag])),
    );
    assert_eq!(
        error(&serde_json::to_value(resp).unwrap()),
        "asof is not supported by blockchain.scripthash.subscribe"
    );
    assert_eq!(subs.scripthash_count(), 0);
}
