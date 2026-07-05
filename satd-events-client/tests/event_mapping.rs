//! Wire → typed [`Event`] conversion. These pin the mapping decisions that are
//! easy to get subtly wrong: `has_amount` → `Option`, the evict-reason enum,
//! prefix nesting, and the empty-body / unrecognized-arm fallback.

use satd_events_client::{proto as pb, CursorRejectReason, DescriptorMatch, Event, EvictReason};

fn node_event(body: pb::node_event::Body) -> pb::NodeEvent {
    pb::NodeEvent { schema_version: 1, stamp: None, cursor: None, body: Some(body) }
}

#[test]
fn script_matched_carries_descriptor_attribution() {
    let ev = node_event(pb::node_event::Body::ScriptMatched(pb::ScriptMatched {
        scripthash: vec![0x11; 32],
        txid: vec![0x22; 32],
        is_output: true,
        index: 0,
        confirmed: true,
        descriptor_matches: vec![pb::DescriptorMatch {
            descriptor: "wpkh(xpub...)".into(),
            branch: 1,
            derivation_index: 42,
        }],
        amount: 50_000,
        has_amount: true,
        raw_tx: vec![0xde, 0xad, 0xbe, 0xef],
    }));
    match Event::from(ev) {
        Event::ScriptMatched { descriptors, is_output, amount, raw_tx, .. } => {
            assert!(is_output);
            assert_eq!(amount, Some(50_000), "in-band matched value (#456)");
            assert_eq!(raw_tx, Some(vec![0xde, 0xad, 0xbe, 0xef]), "opt-in raw_tx (#456)");
            assert_eq!(
                descriptors,
                vec![DescriptorMatch {
                    descriptor: "wpkh(xpub...)".into(),
                    branch: 1,
                    derivation_index: 42,
                }]
            );
        }
        other => panic!("expected ScriptMatched, got {other:?}"),
    }
}

#[test]
fn script_matched_without_descriptor_is_empty_attribution() {
    let ev = node_event(pb::node_event::Body::ScriptMatched(pb::ScriptMatched {
        scripthash: vec![0x11; 32],
        txid: vec![0x22; 32],
        is_output: false,
        index: 1,
        confirmed: false,
        descriptor_matches: vec![],
        // hash tier: no value retained → has_amount=false decodes to None.
        amount: 0,
        has_amount: false,
        // no opt-in → empty raw_tx decodes to None.
        raw_tx: vec![],
    }));
    match Event::from(ev) {
        Event::ScriptMatched { descriptors, amount, raw_tx, .. } => {
            assert!(descriptors.is_empty());
            assert_eq!(amount, None, "has_amount=false → None (not a real 0-value)");
            assert_eq!(raw_tx, None, "empty raw_tx → None");
        }
        other => panic!("expected ScriptMatched, got {other:?}"),
    }
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

#[test]
fn set_cursor_accepted_maps() {
    let cursor = pb::Cursor { height: 50, tx_index: 0, mempool_seq: 0, instance_id: 7 };
    let ev = node_event(pb::node_event::Body::SetCursorResult(pb::SetCursorResult {
        outcome: Some(pb::set_cursor_result::Outcome::Accepted(pb::CursorAccepted {
            from: Some(cursor),
            clamped: true,
            earliest_replayed: 41,
        })),
    }));
    assert_eq!(
        Event::from(ev),
        Event::CursorAccepted { from: Some(cursor), clamped: true, earliest_replayed: 41 }
    );
}

#[test]
fn set_cursor_rejected_maps_reason() {
    let head = pb::Cursor { height: 99, tx_index: 0, mempool_seq: 3, instance_id: 1 };
    let ev = node_event(pb::node_event::Body::SetCursorResult(pb::SetCursorResult {
        outcome: Some(pb::set_cursor_result::Outcome::Rejected(pb::CursorRejected {
            reason: pb::cursor_rejected::Reason::ConcurrentReanchor as i32,
            current_head: Some(head),
        })),
    }));
    assert_eq!(
        Event::from(ev),
        Event::CursorRejected {
            reason: CursorRejectReason::ConcurrentReanchor,
            current_head: Some(head),
        }
    );
}

#[test]
fn set_cursor_rejected_unknown_reason_is_unknown_variant() {
    // A reason code from a newer server maps to the catch-all, not a panic.
    let ev = node_event(pb::node_event::Body::SetCursorResult(pb::SetCursorResult {
        outcome: Some(pb::set_cursor_result::Outcome::Rejected(pb::CursorRejected {
            reason: 9999,
            current_head: None,
        })),
    }));
    assert_eq!(
        Event::from(ev),
        Event::CursorRejected { reason: CursorRejectReason::Unknown, current_head: None }
    );
}

#[test]
fn set_cursor_result_without_outcome_is_unknown() {
    let ev = node_event(pb::node_event::Body::SetCursorResult(pb::SetCursorResult {
        outcome: None,
    }));
    assert_eq!(Event::from(ev), Event::Unknown);
}
