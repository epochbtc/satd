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

/// Core's `ReceivedTx`: an orphan already held is not validated again when
/// another peer sends it, so that peer does not become an announcer by
/// sending it.
#[test]
fn a_held_orphan_sent_again_is_dropped() {
    let (pm, _dir) = pm_with_coins(&[5]);
    let parent = spend(coin_at(5), COIN, 1_000, 5);
    let child = spend(bitcoin::OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 1_000, 1_000, 6);
    pm.handle_tx(1, child.clone());
    pm.handle_tx(2, child.clone());
    assert_eq!(announcers(&pm, &child), vec![1]);
}
