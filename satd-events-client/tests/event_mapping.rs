//! Wire → typed [`Event`] conversion. These pin the mapping decisions that are
//! easy to get subtly wrong: `has_amount` → `Option`, the evict-reason enum,
//! prefix nesting, and the empty-body / unrecognized-arm fallback.

use satd_events_client::{proto as pb, Event, EvictReason};

fn node_event(body: pb::node_event::Body) -> pb::NodeEvent {
    pb::NodeEvent { schema_version: 1, stamp: None, cursor: None, body: Some(body) }
}

#[test]
fn block_connected_maps() {
    let ev = node_event(pb::node_event::Body::Chain(pb::ChainEvent {
        body: Some(pb::chain_event::Body::BlockConnected(pb::BlockConnected {
            hash: vec![0xab; 32],
            height: 42,
        })),
    }));
    assert_eq!(
        Event::from(ev),
        Event::BlockConnected { hash: vec![0xab; 32], height: 42 }
    );
}

#[test]
fn evict_reason_maps() {
    let ev = node_event(pb::node_event::Body::Mempool(pb::MempoolEvent {
        body: Some(pb::mempool_event::Body::LeaveEvicted(pb::MempoolLeaveEvicted {
            txid: vec![1; 32],
            reason: pb::EvictReason::FullPool as i32,
        })),
    }));
    match Event::from(ev) {
        Event::MempoolLeaveEvicted { reason, .. } => assert_eq!(reason, EvictReason::FullPool),
        other => panic!("expected evicted, got {other:?}"),
    }
}

#[test]
fn spent_prevout_has_amount_becomes_option() {
    let prefix = pb::ScriptPrefix { prefix: vec![0xff], bits: 8 };
    let retained = pb::SpentPrevout {
        outpoint_txid: vec![2; 32],
        outpoint_vout: 1,
        script_pubkey: vec![0x51],
        amount: 1000,
        has_amount: true,
    };
    // A genuine 0-value prevout: has_amount=true, amount=0 → Some(0).
    let zero = pb::SpentPrevout {
        outpoint_txid: vec![3; 32],
        outpoint_vout: 0,
        script_pubkey: vec![],
        amount: 0,
        has_amount: true,
    };
    // Not retained: has_amount=false → None (regardless of the amount field).
    let absent = pb::SpentPrevout {
        outpoint_txid: vec![4; 32],
        outpoint_vout: 2,
        script_pubkey: vec![],
        amount: 0,
        has_amount: false,
    };
    let ev = node_event(pb::node_event::Body::PrefixMatched(pb::PrefixMatched {
        prefix: Some(prefix),
        raw_tx: vec![0xde, 0xad],
        confirmed: true,
        height: 7,
        matched_prevouts: vec![retained, zero, absent],
    }));
    match Event::from(ev) {
        Event::PrefixMatched(p) => {
            assert_eq!(p.prefix.bits, 8);
            assert_eq!(p.raw_tx, vec![0xde, 0xad]);
            assert!(p.confirmed);
            assert_eq!(p.matched_prevouts[0].amount, Some(1000));
            assert_eq!(p.matched_prevouts[0].script_pubkey, vec![0x51]);
            assert_eq!(p.matched_prevouts[1].amount, Some(0)); // genuine 0, not absent
            assert_eq!(p.matched_prevouts[2].amount, None); // not retained
        }
        other => panic!("expected prefix match, got {other:?}"),
    }
}

#[test]
fn lagged_carries_resume_cursor() {
    let cursor = pb::Cursor { height: 100, tx_index: 0, mempool_seq: 5, instance_id: 9 };
    let ev = node_event(pb::node_event::Body::Lagged(pb::Lagged {
        dropped_count: 12,
        resume_cursor: Some(cursor),
    }));
    match Event::from(ev) {
        Event::Lagged { dropped_count, resume_cursor } => {
            assert_eq!(dropped_count, 12);
            assert_eq!(resume_cursor, Some(cursor));
        }
        other => panic!("expected lagged, got {other:?}"),
    }
}

#[test]
fn empty_body_is_unknown() {
    let ev = pb::NodeEvent { schema_version: 1, stamp: None, cursor: None, body: None };
    assert_eq!(Event::from(ev), Event::Unknown);
}
