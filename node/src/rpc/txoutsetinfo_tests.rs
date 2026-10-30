//! `gettxoutsetinfo` refuses what it cannot honour (#896). satd keeps no
//! per-height UTXO stats and no UTXO-set hash, so a `hash_or_height` naming
//! a block other than the tip, and an explicit `muhash` or
//! `hash_serialized_3`, are refused by name instead of answered with the
//! tip's stats. The errors Core raises itself are Core's
//! (`src/rpc/blockchain.cpp`: `gettxoutsetinfo`, `ParseHashType`,
//! `ParseHashOrHeight`).

use bitcoin::Network;
use serde_json::{json, Value};

use crate::chain::state::tests::{build_test_block, make_chain_state};
use crate::chain::state::ChainState;
use crate::rpc::blockchain::{get_tx_out_set_info_with, TxOutSetInfoArgs};

fn chain(n: u32) -> (ChainState, std::path::PathBuf) {
    let (cs, dir) = make_chain_state();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for h in 1..=n {
        let b = build_test_block(parent, h, 1_300_000_000 + 600 * h);
        cs.accept_block(&b).expect("the test block connects");
        parent = b.block_hash();
    }
    (cs, dir)
}

fn call(
    cs: &ChainState,
    hash_type: Option<&str>,
    hash_or_height: Option<Value>,
    use_index: Option<bool>,
) -> Result<Value, (i32, String)> {
    let args = TxOutSetInfoArgs { hash_type: hash_type.map(str::to_string), hash_or_height, use_index };
    get_tx_out_set_info_with(cs, &args)
}

const NEEDS_INDEX: &str = "Querying specific block heights requires coinstatsindex";

/// What callers get today keeps working: no arguments, `"none"`, and the
/// tip named by height or hash.
#[test]
fn the_tip_and_hash_type_none_are_answered() {
    let (cs, dir) = chain(5);
    let tip = cs.tip_hash().to_string();
    for (hash_type, hoh) in [
        (None, None),
        (Some("none"), None),
        (Some("none"), Some(json!(5))),
        (None, Some(json!(tip.clone()))),
        (Some("none"), Some(json!(tip.clone()))),
    ] {
        let r = call(&cs, hash_type, hoh.clone(), None)
            .unwrap_or_else(|e| panic!("{hash_type:?} {hoh:?}: {e:?}"));
        assert_eq!(r["height"], 5);
        assert_eq!(r["bestblock"], json!(tip));
    }
    // `use_index` alone asks nothing satd cannot answer.
    assert!(call(&cs, None, None, Some(false)).is_ok());
    assert!(call(&cs, None, None, Some(true)).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fails without the fix: each call returned the tip's stats, height 5.
#[test]
fn a_block_other_than_the_tip_is_refused() {
    let (cs, dir) = chain(5);
    let at3 = cs.get_block_hash_by_height(3).unwrap().to_string();
    for hoh in [json!(0), json!(3), json!(4), json!(at3)] {
        assert_eq!(
            call(&cs, Some("none"), Some(hoh.clone()), None),
            Err((-8, NEEDS_INDEX.to_string())),
            "{hoh}"
        );
        assert_eq!(call(&cs, None, Some(hoh.clone()), None), Err((-8, NEEDS_INDEX.to_string())), "{hoh}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fails without the fix: both returned the tip's stats with no hash.
#[test]
fn an_explicit_utxo_set_hash_is_refused_by_name() {
    let (cs, dir) = chain(2);
    for t in ["muhash", "hash_serialized_3"] {
        let (code, msg) = call(&cs, Some(t), None, None).expect_err(t);
        assert_eq!(code, -8);
        assert!(msg.contains(t) && msg.contains("not supported"), "{msg}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core's own errors, in Core's order.
#[test]
fn cores_argument_errors_are_cores() {
    let (cs, dir) = chain(5);
    let tip = cs.tip_hash().to_string();
    let err = |t: Option<&str>, h: Option<Value>, u: Option<bool>| call(&cs, t, h, u).unwrap_err();

    assert_eq!(err(Some("sha256"), None, None), (-8, "'sha256' is not a valid hash_type".into()));
    // `ParseHashType` runs before anything looks at the height.
    assert_eq!(err(Some("sha256"), Some(json!(3)), None), (-8, "'sha256' is not a valid hash_type".into()));
    assert_eq!(err(None, Some(json!(-1)), None), (-8, "Target block height -1 is negative".into()));
    assert_eq!(err(None, Some(json!(6)), None), (-8, "Target block height 6 after current tip 5".into()));
    assert_eq!(err(None, Some(json!(1.5)), None), (-1, "JSON integer out of range".into()));
    assert_eq!(
        err(None, Some(json!("abc")), None),
        (-8, "hash_or_height must be of length 64 (not 3, for 'abc')".into())
    );
    assert_eq!(err(None, Some(json!("00".repeat(32))), None), (-5, "Block not found".into()));
    assert_eq!(
        err(None, Some(json!(true)), None),
        (-1, "JSON value of type bool is not of expected type string".into())
    );
    // The two checks Core makes for a named block apply to the tip too.
    assert_eq!(
        err(Some("hash_serialized_3"), Some(json!(tip.clone())), None),
        (-8, "hash_serialized_3 hash type cannot be queried for a specific block".into())
    );
    assert_eq!(
        err(Some("none"), Some(json!(5)), Some(false)),
        (-8, "Cannot set use_index to false when querying for a specific block".into())
    );
    // Without coinstatsindex Core refuses a named block before either.
    assert_eq!(err(Some("hash_serialized_3"), Some(json!(3)), None), (-8, NEEDS_INDEX.into()));
    assert_eq!(err(None, Some(json!(3)), Some(false)), (-8, NEEDS_INDEX.into()));
    let _ = std::fs::remove_dir_all(&dir);
}
