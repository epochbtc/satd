//! Core's opportunistic 1-parent-1-child package relay
//! (`TxDownloadManagerImpl::Find1P1CPackage`, `ProcessPackageResult`): a
//! parent refused on its fee alone is tried again as a package with a child
//! of it the same peer sent, whichever of the two arrives first.

use super::txrequest_tests::add_peer;
use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::net::recent_rejects::{package_hash, Rejection};
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

fn p2wpkh(tag: u8) -> ScriptBuf {
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[tag; 20]);
    ScriptBuf::from_bytes(spk)
}

fn coin_at(tag: u8) -> OutPoint {
    OutPoint { txid: bitcoin::Txid::from_byte_array([tag; 32]), vout: 0 }
}

const COIN: u64 = 100_000;

/// One input, one P2WPKH output paying `fee`, with a witness so its wtxid
/// differs from its txid.
fn spend(prev: OutPoint, value: u64, fee: u64, tag: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![tag; 72], vec![0x02; 33]]),
        }],
        output: vec![TxOut { value: Amount::from_sat(value - fee), script_pubkey: p2wpkh(tag) }],
    }
}

/// A manager out of IBD over a chain holding one coin per tag, with a relay
/// floor of 1000 sat/kvB, and two peers.
fn pm_with_coins(tags: &[u8]) -> (Arc<PeerManager>, std::path::PathBuf) {
    let coins: Vec<(OutPoint, Coin)> = tags
        .iter()
        .map(|t| {
            let coin = Coin {
                amount: COIN,
                script_pubkey: p2wpkh(0x11),
                height: 1,
                coinbase: false,
                txseq: node_index::TXSEQ_UNKNOWN,
            };
            (coin_at(*t), coin)
        })
        .collect();
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    mp.reload_policy(crate::mempool::pool::MempoolConfig { max_size_bytes: 1_000_000, min_fee_rate: 1_000, ..Default::default() });
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(_shutdown_tx);
    let pm = PeerManager::new(
        Arc::new(cs),
        Arc::new(mp),
        Arc::new(FeeEstimator::new()),
        Network::Regtest,
        shutdown_rx,
    );
    let tip = pm.chain_state.tip_hash();
    let block = crate::chain::state::tests::build_test_block(tip, 1, crate::time::now_secs() as u32);
    pm.chain_state.accept_block(&block).expect("block connects");
    std::mem::forget(add_peer(&pm, 1, Direction::Outbound));
    std::mem::forget(add_peer(&pm, 2, Direction::Outbound));
    (pm, dir)
}

/// A parent below the relay floor and a child paying for both.
fn cpfp_pair(tag: u8) -> (Transaction, Transaction) {
    let parent = spend(coin_at(tag), COIN, 50, tag);
    let child = spend(OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 50, 5_000, tag.wrapping_add(1));
    (parent, child)
}

fn in_pool(pm: &PeerManager, tx: &Transaction) -> bool {
    pm.mempool.get(&tx.compute_txid()).is_some()
}

/// The child first: it waits in the orphanage, and the parent, refused on
/// its fee, is tried with it.
#[test]
fn a_child_in_the_orphanage_pays_for_a_parent_that_arrives_after_it() {
    let (pm, _dir) = pm_with_coins(&[1]);
    let (parent, child) = cpfp_pair(1);
    pm.handle_tx(1, child.clone());
    assert!(pm.orphanage.contains(&child.compute_txid()));

    pm.handle_tx(1, parent.clone());
    assert!(in_pool(&pm, &parent) && in_pool(&pm, &child), "accepted as a package");
    assert!(!pm.orphanage.contains(&child.compute_txid()));
}

/// The parent first: refused on its fee, it is fetched again once its
/// orphan child names it, and the second copy is tried with the child
/// rather than turned away as recently rejected.
#[test]
fn a_parent_refused_on_its_fee_is_tried_again_with_its_child() {
    let (pm, _dir) = pm_with_coins(&[2]);
    let (parent, child) = cpfp_pair(2);
    pm.handle_tx(1, parent.clone());
    assert!(!in_pool(&pm, &parent));
    assert!(pm.recently_rejected(parent.compute_wtxid().as_byte_array()), "a reconsiderable refusal");

    pm.handle_tx(1, child.clone());
    assert!(pm.orphanage.contains(&child.compute_txid()), "an orphan whose parent may still enter");

    pm.handle_tx(1, parent.clone());
    assert!(in_pool(&pm, &parent) && in_pool(&pm, &child));
}

/// Only the sender's own children are looked at: a child another peer sent
/// is not paired with this peer's parent.
#[test]
fn a_child_from_another_peer_is_not_paired() {
    let (pm, _dir) = pm_with_coins(&[3]);
    let (parent, child) = cpfp_pair(3);
    pm.handle_tx(2, child.clone());
    pm.handle_tx(1, parent.clone());
    assert!(!in_pool(&pm, &parent) && !in_pool(&pm, &child));
    assert!(pm.orphanage.contains(&child.compute_txid()));
}

/// A package that fails is remembered by its hash, so the pairing is not
/// tried again, and its child leaves the orphanage.
#[test]
fn a_refused_package_is_remembered_and_its_child_dropped() {
    let (pm, _dir) = pm_with_coins(&[4]);
    let parent = spend(coin_at(4), COIN, 50, 4);
    // Too little for both.
    let child = spend(OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 50, 60, 5);
    pm.handle_tx(1, child.clone());
    pm.handle_tx(1, parent.clone());
    assert!(!in_pool(&pm, &parent) && !in_pool(&pm, &child));
    assert!(!pm.orphanage.contains(&child.compute_txid()));
    let hash = package_hash(&[parent.compute_wtxid(), child.compute_wtxid()]);
    let tip = pm.chain_state.tip_hash();
    assert!(pm.recent_rejects.lock().contains_reconsiderable(tip, &hash));
    assert!(pm.find_1p1c_package(&parent, 1).is_none());
}

/// A child of two parents refused on their fee alone is not kept: one
/// parent can enter with it as a package, two cannot.
#[test]
fn an_orphan_of_two_fee_refused_parents_is_rejected() {
    let (pm, _dir) = pm_with_coins(&[6]);
    let a = bitcoin::Txid::from_byte_array([0x61; 32]);
    let b = bitcoin::Txid::from_byte_array([0x62; 32]);
    let mut child = spend(OutPoint { txid: a, vout: 0 }, COIN, 5_000, 6);
    child.input.push(TxIn { previous_output: OutPoint { txid: b, vout: 0 }, ..child.input[0].clone() });
    pm.note_rejected(a.as_byte_array(), Rejection::Reconsiderable);
    pm.note_rejected(b.as_byte_array(), Rejection::Reconsiderable);
    pm.handle_tx(1, child.clone());
    assert!(!pm.orphanage.contains(&child.compute_txid()));
    assert!(pm.recently_rejected(child.compute_wtxid().as_byte_array()));

    // One such parent is tolerated.
    let lone = spend(OutPoint { txid: a, vout: 1 }, COIN, 5_000, 7);
    pm.handle_tx(1, lone.clone());
    assert!(pm.orphanage.contains(&lone.compute_txid()));
}

/// A member refused outright inside its package is recorded as one refused
/// on its own would be (Core's `ProcessInvalidTx` from
/// `ProcessPackageResult`): such a child goes to the
/// main filter and leaves the orphanage, so it is not fetched again, while
/// the parent stays refused on its fee alone. Here the child pays a fee and
/// carries a dust output, which only a zero-fee transaction may.
#[test]
fn a_child_refused_outright_in_its_package_is_rejected_on_its_own() {
    let (pm, _dir) = pm_with_coins(&[8]);
    let parent = spend(coin_at(8), COIN, 50, 8);
    let mut child = spend(OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 50, 5_000, 9);
    child.output.push(TxOut { value: Amount::from_sat(1), script_pubkey: p2wpkh(9) });
    child.output[0].value = Amount::from_sat(child.output[0].value.to_sat() - 1);
    pm.handle_tx(1, child.clone());
    assert!(pm.orphanage.contains(&child.compute_txid()));

    pm.handle_tx(1, parent.clone());
    assert!(!in_pool(&pm, &parent) && !in_pool(&pm, &child));
    assert!(!pm.orphanage.contains(&child.compute_txid()));
    assert!(pm.recently_rejected_outright(child.compute_wtxid().as_byte_array()), "the child is refused outright");
    assert!(!pm.recently_rejected_outright(parent.compute_wtxid().as_byte_array()));
    assert!(pm.recently_rejected(parent.compute_wtxid().as_byte_array()), "the parent only on its fee");
}

