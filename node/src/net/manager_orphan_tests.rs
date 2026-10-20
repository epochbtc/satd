//! Every peer that announces an orphan is one of its announcers, as in
//! Core's orphanage (`AddAnnouncer`, `EraseForPeer`): the peer is asked for
//! the missing parents, may pair the orphan with a parent it sends, and the
//! orphan stays while any announcer is connected.

use super::p1c_tests::{coin_at, cpfp_pair, in_pool, pm_with_coins, spend, COIN};
use super::*;

fn announcers(pm: &PeerManager, tx: &bitcoin::Transaction) -> Vec<PeerId> {
    let txid = tx.compute_txid();
    pm.orphanage
        .orphans()
        .into_iter()
        .find(|(t, _)| t.compute_txid() == txid)
        .map(|(_, from)| from)
        .unwrap_or_default()
}

/// Core's `AddTxAnnouncement`: a peer announcing a held orphan by wtxid
/// becomes an announcer and is asked for the missing parent.
#[test]
fn a_peer_announcing_a_held_orphan_becomes_an_announcer() {
    let (pm, _dir) = pm_with_coins(&[1]);
    let (parent, child) = cpfp_pair(1);
    pm.handle_tx(1, child.clone());
    assert_eq!(announcers(&pm, &child), vec![1]);

    pm.handle_inv(2, vec![Inventory::WTx(child.compute_wtxid())]);
    assert_eq!(announcers(&pm, &child), vec![1, 2]);
    let asked = pm.tx_requests.lock().candidate_peers(&parent.compute_txid().to_byte_array());
    assert!(asked.contains(&2), "peer 2 is asked for the parent: {asked:?}");
    assert_eq!(
        pm.tx_requests.lock().candidate_peers(&child.compute_wtxid().to_byte_array()),
        Vec::<PeerId>::new(),
        "the orphan itself is not fetched again"
    );

    pm.handle_inv(2, vec![Inventory::WTx(child.compute_wtxid())]);
    assert_eq!(announcers(&pm, &child), vec![1, 2], "recorded once");
}

/// A parent refused on its fee pairs with an orphan child of it any of the
/// child's announcers sent or announced, not only the first.
#[test]
fn a_second_announcer_of_the_child_pairs_it_with_the_parent() {
    let (pm, _dir) = pm_with_coins(&[2]);
    let (parent, child) = cpfp_pair(2);
    pm.handle_tx(1, child.clone());
    pm.handle_inv(2, vec![Inventory::WTx(child.compute_wtxid())]);

    pm.handle_tx(2, parent.clone());
    assert!(in_pool(&pm, &parent) && in_pool(&pm, &child), "accepted as a package");
}

/// Core's `EraseForPeer`: a departing peer's orphans go, except those
/// another peer announced too.
#[test]
fn a_departing_peer_takes_only_the_orphans_no_one_else_announced() {
    let (pm, _dir) = pm_with_coins(&[3, 4]);
    let (_, shared) = cpfp_pair(3);
    let (_, own) = cpfp_pair(4);
    pm.handle_tx(1, shared.clone());
    pm.handle_tx(1, own.clone());
    pm.handle_inv(2, vec![Inventory::WTx(shared.compute_wtxid())]);

    pm.handle_peer_disconnected(1);
    assert!(!pm.orphanage.contains(&own.compute_txid()));
    assert_eq!(announcers(&pm, &shared), vec![2]);
}

/// [`spend`] without a witness, so its wtxid is its txid.
fn spend_bare(prev: bitcoin::OutPoint, value: u64, fee: u64, tag: u8) -> bitcoin::Transaction {
    let mut tx = spend(prev, value, fee, tag);
    tx.input[0].witness = bitcoin::Witness::new();
    tx
}

/// Core's `AlreadyHaveTx` counts the orphanage: an announcer of a child is
/// not asked for a parent already held as an orphan, so with nothing else
/// missing it is not made an announcer.
#[test]
fn an_announcer_is_not_asked_for_a_parent_held_as_an_orphan() {
    let (pm, _dir) = pm_with_coins(&[7]);
    let unknown = bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([0xee; 32]), vout: 0 };
    let middle = spend_bare(unknown, COIN, 1_000, 7);
    let child = spend(bitcoin::OutPoint { txid: middle.compute_txid(), vout: 0 }, COIN - 1_000, 1_000, 8);
    pm.handle_tx(1, middle.clone());
    pm.handle_tx(1, child.clone());
    assert!(pm.orphanage.contains(&middle.compute_txid()) && pm.orphanage.contains(&child.compute_txid()));

    pm.handle_inv(2, vec![Inventory::WTx(child.compute_wtxid())]);
    assert_eq!(announcers(&pm, &child), vec![1]);
    let asked = pm.tx_requests.lock().candidate_peers(&middle.compute_txid().to_byte_array());
    assert!(!asked.contains(&2), "peer 2 is not asked for the held orphan: {asked:?}");
}

/// An orphan without a witness announced by txid, from a peer that does
/// not relay by wtxid, is held already and not fetched.
#[test]
fn a_txid_announcement_of_a_held_orphan_is_not_fetched() {
    let (pm, _dir) = pm_with_coins(&[9]);
    std::mem::forget(super::txrequest_tests::add_peer_with(&pm, 3, Direction::Outbound, |i| i.wtxid_relay = false));
    let unknown = bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([0xef; 32]), vout: 0 };
    let orphan = spend_bare(unknown, COIN, 1_000, 9);
    pm.handle_tx(1, orphan.clone());
    assert!(pm.orphanage.contains(&orphan.compute_txid()));

    pm.handle_inv(3, vec![Inventory::Transaction(orphan.compute_txid())]);
    let asked = pm.tx_requests.lock().candidate_peers(&orphan.compute_txid().to_byte_array());
    assert!(asked.is_empty(), "not fetched again: {asked:?}");
}

/// A held orphan sent again is dropped before validation, as Core's
/// `ReceivedTx` drops it: once its parent is refused outright, validating
/// it again would refuse it too, but it is not looked at.
#[test]
fn a_held_orphan_is_not_validated_again() {
    let (pm, _dir) = pm_with_coins(&[10]);
    let mut parent = spend(coin_at(10), COIN, 1_000, 10);
    parent.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let child = spend(bitcoin::OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 1_000, 1_000, 11);
    pm.handle_tx(1, child.clone());
    pm.handle_tx(1, parent.clone());
    assert!(!in_pool(&pm, &parent), "a non-standard output");
    assert!(pm.orphanage.contains(&child.compute_txid()));

    pm.handle_tx(2, child.clone());
    assert!(!pm.recently_rejected(child.compute_wtxid().as_byte_array()), "not judged again");
    assert!(pm.orphanage.contains(&child.compute_txid()));
}
