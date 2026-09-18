//! The property this crate exists for: a PSBT that parses re-serialises to
//! the bytes it came from, field order and all.

mod common;

use satd_psbt::raw::{PsbtVersion, RawMap, RawPair, RawPsbt};
use satd_psbt::{PsbtError, version_of_bytes};

/// Every BIP 375 vector — valid and invalid alike, since even a
/// structurally wrong PSBT must survive being read and written — plus every
/// BIP 370 vector that parses at all.
#[test]
fn roundtrip_is_byte_exact() {
    let mut checked = 0usize;
    for v in common::bip375_all() {
        let raw = RawPsbt::parse(&v.psbt)
            .unwrap_or_else(|e| panic!("{}: parse failed: {e}", v.description));
        assert_eq!(
            raw.serialize(),
            v.psbt,
            "{}: re-serialising changed the bytes",
            v.description
        );
        assert_eq!(raw.to_base64(), v.base64, "{}: base64 differs", v.description);
        checked += 1;
    }
    assert_eq!(checked, 42, "all 42 BIP 375 vectors should round trip");

    for v in common::bip370_valid()
        .into_iter()
        .chain(common::bip370_locktime())
        .chain(common::bip370_invalid())
    {
        if let Ok(raw) = RawPsbt::parse(&v.psbt) {
            assert_eq!(
                raw.serialize(),
                v.psbt,
                "{}: re-serialising changed the bytes",
                v.description
            );
        }
    }
}

/// Version 0 PSBTs go through `bitcoin::Psbt` in production, but the codec
/// must still carry them losslessly: `combinepsbt` and friends compare
/// versions before they do anything else, and a v0 PSBT with unknown pairs is
/// the shape an older wallet sends.
#[test]
fn roundtrip_is_byte_exact_for_v0() {
    for (name, bytes) in v0_fixtures() {
        let raw = RawPsbt::parse(&bytes).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"));
        assert_eq!(raw.version().unwrap(), PsbtVersion::V0, "{name}");
        assert_eq!(raw.serialize(), bytes, "{name}: re-serialising changed the bytes");
    }
}

/// Perturbation for `roundtrip_is_byte_exact`: a codec that sorts each map on
/// the way out looks correct by every other measure and loses the property
/// this crate is for. The `psbt-v2` crate re-orders 32 of the 35 vectors it
/// can parse, which is how that was found.
#[test]
fn sorting_a_map_on_write_breaks_byte_identity() {
    let mut reordered = 0usize;
    for v in common::bip375_all() {
        let raw = RawPsbt::parse(&v.psbt).expect("parses");
        if serialize_sorted(&raw) != v.psbt {
            reordered += 1;
        }
    }
    assert!(
        reordered > 0,
        "sorting each map should change at least one vector's bytes; if it does not, \
         roundtrip_is_byte_exact is not testing what it claims"
    );
}

fn serialize_sorted(raw: &RawPsbt) -> Vec<u8> {
    let sort = |map: &RawMap| -> RawMap {
        let mut pairs: Vec<RawPair> = map.pairs().to_vec();
        pairs.sort_by(|a, b| (a.key_type, &a.key_data).cmp(&(b.key_type, &b.key_data)));
        pairs.into_iter().collect()
    };
    RawPsbt {
        global: sort(&raw.global),
        inputs: raw.inputs.iter().map(sort).collect(),
        outputs: raw.outputs.iter().map(sort).collect(),
    }
    .serialize()
}

/// BIP 375 lets a silent payment output have no `PSBT_OUT_SCRIPT` while the
/// script has not been computed. A codec that models the script as a plain
/// byte string turns "absent" into "present and empty", which reads as a
/// finished output paying nothing. Three of the in-progress vectors grow by
/// three bytes under `psbt-v2` for exactly this reason.
#[test]
fn absent_script_stays_absent() {
    use satd_psbt::keys;
    let mut in_progress = 0usize;
    for v in common::bip375_valid() {
        let raw = RawPsbt::parse(&v.psbt).expect("parses");
        let absent = raw
            .outputs
            .iter()
            .filter(|o| !o.contains_type(keys::output::SCRIPT))
            .count();
        if absent == 0 {
            continue;
        }
        in_progress += 1;
        assert_eq!(
            raw.serialize(),
            v.psbt,
            "{}: an absent PSBT_OUT_SCRIPT did not survive",
            v.description
        );
        // And the field really is gone, not empty.
        for out in &raw.outputs {
            if !out.contains_type(keys::output::SCRIPT) {
                assert!(out.get_single(keys::output::SCRIPT).is_none());
            }
        }
    }
    assert!(
        in_progress >= 3,
        "expected at least three in-progress vectors with an absent output script, got {in_progress}"
    );
}

/// Perturbation for `absent_script_stays_absent`.
#[test]
fn writing_an_empty_script_for_an_absent_one_is_detectable() {
    use satd_psbt::keys;
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("in progress: one P2TR input / one sp output"))
        .expect("the in-progress vector is in the file");
    let mut raw = RawPsbt::parse(&v.psbt).expect("parses");
    let mut touched = false;
    for out in &mut raw.outputs {
        if !out.contains_type(keys::output::SCRIPT) {
            out.set(RawPair::new(keys::output::SCRIPT, Vec::new(), Vec::new()));
            touched = true;
        }
    }
    assert!(touched, "the vector should have an output with no script");
    assert_ne!(
        raw.serialize(),
        v.psbt,
        "inventing an empty PSBT_OUT_SCRIPT must change the bytes"
    );
    assert_eq!(raw.serialize().len(), v.psbt.len() + 3);
}

#[test]
fn version_is_sniffed_from_the_global_map_alone() {
    for v in common::bip375_all() {
        assert_eq!(
            version_of_bytes(&v.psbt).expect("the global map parses"),
            PsbtVersion::V2,
            "{}",
            v.description
        );
    }
    for (name, bytes) in v0_fixtures() {
        assert_eq!(version_of_bytes(&bytes).unwrap(), PsbtVersion::V0, "{name}");
    }
    // Garbage after the global map must not stop the sniff: a version 0 PSBT
    // has to keep reaching the v0 parser and getting the v0 error message.
    let (_, mut bytes) = v0_fixtures().remove(0);
    bytes.extend_from_slice(&[0xff; 8]);
    assert_eq!(version_of_bytes(&bytes).unwrap(), PsbtVersion::V0);
    assert!(RawPsbt::parse(&bytes).is_err());
}

#[test]
fn unsupported_versions_are_named() {
    let mut raw = RawPsbt::parse(&common::bip375_valid()[1].psbt).expect("parses");
    raw.global.set(RawPair::new(
        satd_psbt::keys::global::VERSION,
        Vec::new(),
        3u32.to_le_bytes().to_vec(),
    ));
    let bytes = raw.serialize();
    match version_of_bytes(&bytes) {
        Err(PsbtError::UnsupportedVersion(3)) => {}
        other => panic!("expected UnsupportedVersion(3), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

/// Truncating a PSBT at every byte offset must produce an error, never a
/// panic. `decodepsbt` is a read-only method, so this is attacker-controlled
/// input on a listener that may be exposed more widely than the wallet one.
#[test]
fn truncation_at_every_offset_errors_rather_than_panics() {
    let v = &common::bip375_valid()[19]; // the large nine-input vector
    for cut in 0..v.psbt.len() {
        let slice = &v.psbt[..cut];
        assert!(
            RawPsbt::parse(slice).is_err(),
            "a PSBT truncated to {cut} bytes must not parse"
        );
        let _ = version_of_bytes(slice);
    }
    assert!(RawPsbt::parse(&v.psbt).is_ok());
}

#[test]
fn a_huge_declared_length_is_refused_before_allocating() {
    // magic, then a key of length 2 (type 0x00) whose value claims 2^32 bytes.
    let mut bytes = satd_psbt::keys::MAGIC.to_vec();
    bytes.extend_from_slice(&[0x01, 0x00]); // key len 1, key type 0
    bytes.push(0xfe);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    match RawPsbt::parse(&bytes) {
        Err(PsbtError::LengthOverrun { declared, .. }) => {
            assert_eq!(declared, u32::MAX as u64)
        }
        other => panic!("expected LengthOverrun, got {other:?}"),
    }
}

#[test]
fn an_implausible_input_count_is_refused_before_allocating() {
    let v = &common::bip375_valid()[1];
    let mut raw = RawPsbt::parse(&v.psbt).expect("parses");
    let mut count = Vec::new();
    // 1_000_000_000 as a compact size.
    count.push(0xfe);
    count.extend_from_slice(&1_000_000_000u32.to_le_bytes());
    raw.global.set(RawPair::new(
        satd_psbt::keys::global::INPUT_COUNT,
        Vec::new(),
        count,
    ));
    match RawPsbt::parse(&raw.serialize()) {
        Err(PsbtError::ImplausibleCount { declared, .. }) => {
            assert!(declared >= 1_000_000_000)
        }
        other => panic!("expected ImplausibleCount, got {other:?}"),
    }
}

#[test]
fn a_duplicate_key_is_refused() {
    // Two PSBT_GLOBAL_VERSION pairs in one map.
    let v = &common::bip375_valid()[1];
    let mut bytes = RawPsbt::parse(&v.psbt).expect("parses").serialize();
    let version_pair = [0x01u8, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00];
    let at = bytes
        .windows(version_pair.len())
        .position(|w| w == version_pair)
        .expect("the version pair is in the bytes");
    bytes.splice(at..at, version_pair.iter().copied());
    match RawPsbt::parse(&bytes) {
        Err(PsbtError::DuplicateKey { key_type, .. }) => assert_eq!(key_type, 0xfb),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

#[test]
fn a_non_minimal_compact_size_is_refused() {
    // The same global version pair, but with its key length written as 0xfd
    // 0x0001 instead of 0x01.
    let mut bytes = satd_psbt::keys::MAGIC.to_vec();
    bytes.extend_from_slice(&[0xfd, 0x01, 0x00]); // non-minimal key length of 1
    bytes.push(0xfb);
    bytes.extend_from_slice(&[0x04, 0x02, 0x00, 0x00, 0x00]);
    bytes.push(0x00);
    assert!(matches!(
        RawPsbt::parse(&bytes),
        Err(PsbtError::NonMinimalCompactSize)
    ));
}

#[test]
fn trailing_data_after_the_last_map_is_refused() {
    let v = &common::bip375_valid()[1];
    let mut bytes = v.psbt.clone();
    bytes.push(0x00);
    assert!(matches!(
        RawPsbt::parse(&bytes),
        Err(PsbtError::TrailingData(1))
    ));
}

#[test]
fn an_unterminated_map_is_refused() {
    let v = &common::bip375_valid()[1];
    let mut bytes = v.psbt.clone();
    // Drop the final separator.
    bytes.pop();
    assert!(matches!(
        RawPsbt::parse(&bytes),
        Err(PsbtError::UnterminatedMap(_))
    ));
}

#[test]
fn bad_magic_is_refused() {
    assert!(matches!(RawPsbt::parse(b""), Err(PsbtError::BadMagic)));
    assert!(matches!(RawPsbt::parse(b"psbt"), Err(PsbtError::BadMagic)));
    assert!(matches!(
        RawPsbt::parse(b"psbt\x00\x00"),
        Err(PsbtError::BadMagic)
    ));
}

// ---------------------------------------------------------------------------
// Map mutation keeps everything else in place
// ---------------------------------------------------------------------------

#[test]
fn set_replaces_in_place_and_leaves_the_rest_alone() {
    let v = &common::bip375_valid()[1];
    let before = RawPsbt::parse(&v.psbt).expect("parses");
    let mut after = before.clone();
    let ty = satd_psbt::keys::global::TX_VERSION;
    after
        .global
        .set(RawPair::new(ty, Vec::new(), 3u32.to_le_bytes().to_vec()));

    assert_eq!(after.global.len(), before.global.len());
    for (a, b) in after.global.pairs().iter().zip(before.global.pairs()) {
        assert_eq!(a.key_type, b.key_type);
        assert_eq!(a.key_data, b.key_data);
        if a.key_type != ty {
            assert_eq!(a.value, b.value, "an unrelated pair moved or changed");
        }
    }
}

#[test]
fn insert_refuses_a_duplicate_and_set_does_not() {
    let mut map = RawMap::new();
    map.insert(RawPair::new(0x01u64, vec![0xaa], vec![1])).unwrap();
    assert!(map.insert(RawPair::new(0x01u64, vec![0xaa], vec![2])).is_err());
    assert!(map.insert(RawPair::new(0x01u64, vec![0xbb], vec![2])).is_ok());
    map.set(RawPair::new(0x01u64, vec![0xaa], vec![9]));
    assert_eq!(map.get(0x01, &[0xaa]), Some(&[9u8][..]));
    assert_eq!(map.len(), 2);
    assert_eq!(map.remove_type(0x01), 2);
    assert!(map.is_empty());
}

// ---------------------------------------------------------------------------
// Version 0 fixtures, built here rather than vendored
// ---------------------------------------------------------------------------

/// Version 0 PSBTs covering the shapes the codec has to carry: a bare
/// unsigned transaction, one with per-input material, and one with unknown
/// pairs in all three kinds of map.
fn v0_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::raw::{Key, Pair};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime, transaction::Version,
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7u8; 32]),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from_hex("0014c430f64c4756da310dbd1a085572ef299926272c")
                .unwrap(),
        }],
    };

    let bare = bitcoin::Psbt::from_unsigned_tx(tx).expect("an unsigned tx makes a psbt");

    let mut updated = bare.clone();
    updated.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_hex("00142269acb34a645bd3496bbbf50bbb81c9063f4f94").unwrap(),
    });
    updated.inputs[0].sighash_type = Some(bitcoin::EcdsaSighashType::All.into());

    let mut with_unknowns = updated.clone();
    let unknown = |ty: u8, data: &[u8], value: &[u8]| Pair {
        key: Key {
            type_value: ty,
            key: data.to_vec(),
        },
        value: value.to_vec(),
    };
    with_unknowns
        .unknown
        .insert(unknown(0x42, b"g", b"global").key, b"global".to_vec());
    with_unknowns.inputs[0]
        .unknown
        .insert(unknown(0x43, b"i", b"input").key, b"input".to_vec());
    with_unknowns.outputs[0]
        .unknown
        .insert(unknown(0x44, b"o", b"output").key, b"output".to_vec());

    vec![
        ("bare", bare.serialize()),
        ("updated", updated.serialize()),
        ("with unknown pairs", with_unknowns.serialize()),
    ]
}
