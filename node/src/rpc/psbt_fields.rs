//! The `decodepsbt` fields both PSBT versions share with Bitcoin Core's
//! `DecodePSBT` (src/rpc/rawtransaction.cpp, v32.1), rendered from the raw
//! key-value maps.
//!
//! Core keeps each field as the bytes it read and prints them back with
//! `HexStr`, so the bytes are the truth here too. The order of every array is
//! the order of the `std::map` or `std::set` Core keeps the field in (a
//! public key, a hash and a script compare byte for byte), which is not
//! always the order of the PSBT's own keys.
//!
//! A pair that does not have the shape Core reads stays in `unknown`, where
//! its bytes are still shown: Core refuses such a PSBT outright, and satd
//! would rather show the operator what is wrong with it.

use std::collections::{BTreeMap, BTreeSet};

use satd_psbt::raw::{RawMap, RawPair};
use satd_psbt::keys;
use serde_json::{Map, Value, json};

/// The key types of each map that Core reads; every other pair is Core's
/// `unknown`. The silent payment fields (BIP 375) are among the others, as
/// they are in Core.
const CORE_GLOBAL: &[u64] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xfb, 0xfc];
const CORE_INPUT: &[u64] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x1a, 0x1b, 0x1c, 0xfc,
];
const CORE_OUTPUT: &[u64] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xfc];

/// Sort keys for the arrays Core keeps in a `std::map`: an xpub's
/// (fingerprint, path length, path) origin then (key, chain code); a
/// taproot leaf's (script, leaf version); a MuSig2 row's (aggregate key,
/// leaf hash, participant).
type XpubOrder = (([u8; 4], usize, Vec<u32>), (Vec<u8>, Vec<u8>));
type LeafKey = (Vec<u8>, u8);
type MusigKey = (Vec<u8>, [u8; 32], Vec<u8>);

const MUSIG2_PARTICIPANTS_IN: u64 = 0x1a;
const MUSIG2_PUB_NONCE: u64 = 0x1b;
const MUSIG2_PARTIAL_SIG: u64 = 0x1c;
const MUSIG2_PARTICIPANTS_OUT: u64 = 0x08;

/// Core's `SighashToStr` (src/core_io.cpp): the six standard values by
/// name, anything else (`DEFAULT` included) as an empty string.
pub(crate) fn sighash_to_str(sighash: u32) -> &'static str {
    match sighash {
        0x01 => "ALL",
        0x81 => "ALL|ANYONECANPAY",
        0x02 => "NONE",
        0x82 => "NONE|ANYONECANPAY",
        0x03 => "SINGLE",
        0x83 => "SINGLE|ANYONECANPAY",
        _ => "",
    }
}

/// Core's `WriteHDKeypath`: `m`, then each index, hardened ones with `h`.
fn keypath(path: &[u32]) -> String {
    let mut s = String::from("m");
    for i in path {
        s.push_str(&format!("/{}", i & 0x7fff_ffff));
        if i >> 31 == 1 {
            s.push('h');
        }
    }
    s
}

/// A `KeyOriginInfo` value: a 4-byte fingerprint and little-endian indices.
fn key_origin(value: &[u8]) -> Option<([u8; 4], Vec<u32>)> {
    if value.len() < 4 || !(value.len() - 4).is_multiple_of(4) {
        return None;
    }
    let fingerprint = value[..4].try_into().ok()?;
    let path = value[4..].chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    Some((fingerprint, path))
}

/// A BIP 32 derivation object: Core prints the fingerprint as `%08x` of its
/// big-endian read, which is its bytes in order.
fn origin_json(pubkey: &[u8], fingerprint: [u8; 4], path: &[u32]) -> Value {
    json!({
        "pubkey": hex::encode(pubkey),
        "master_fingerprint": hex::encode(fingerprint),
        "path": keypath(path),
    })
}

fn read_compact(b: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = b.split_first()?;
    let (n, len) = match first {
        0xfd => (u64::from(u16::from_le_bytes(rest.get(..2)?.try_into().ok()?)), 2),
        0xfe => (u64::from(u32::from_le_bytes(rest.get(..4)?.try_into().ok()?)), 4),
        0xff => (u64::from_le_bytes(rest.get(..8)?.try_into().ok()?), 8),
        n => (u64::from(n), 0),
    };
    Some((n, &rest[len..]))
}

fn full_key(pair: &RawPair) -> Vec<u8> {
    let mut key = Vec::new();
    satd_psbt::raw::write_compact_size(&mut key, pair.key_type);
    key.extend_from_slice(&pair.key_data);
    key
}

fn is_pubkey(b: &[u8]) -> bool {
    bitcoin::secp256k1::PublicKey::from_slice(b).is_ok()
}

/// Core's `PSBTProprietary`: `identifier`, `subtype`, the whole key and the
/// value, the set ordered by the whole key.
fn proprietary_json(map: &RawMap, key_type: u64, used: &mut BTreeSet<Vec<u8>>) -> Vec<Value> {
    let mut rows: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == key_type) {
        let Some((len, rest)) = read_compact(&pair.key_data) else { continue };
        let Some(identifier) = usize::try_from(len).ok().and_then(|l| rest.get(..l)) else { continue };
        let Some((subtype, _)) = read_compact(&rest[identifier.len()..]) else { continue };
        let key = full_key(pair);
        used.insert(key.clone());
        rows.insert(
            key.clone(),
            json!({
                "identifier": hex::encode(identifier),
                "subtype": subtype,
                "key": hex::encode(&key),
                "value": hex::encode(&pair.value),
            }),
        );
    }
    rows.into_values().collect()
}

/// Core's `unknown`: every pair of a type Core does not read, every pair
/// of a type this module renders that did not have the shape to be
/// rendered, and every pair of a type the caller renders (`theirs`, by
/// the field it writes) that the caller did not render: one with key data,
/// or one whose field the caller left out because its value did not parse.
fn unknown_json(
    map: &RawMap,
    known: &[u64],
    mine: &[u64],
    used: &BTreeSet<Vec<u8>>,
    theirs: &[(u64, &str)],
    out: &Value,
) -> Map<String, Value> {
    let mut obj = Map::new();
    for pair in map.pairs() {
        let key = full_key(pair);
        let shown = if mine.contains(&pair.key_type) {
            used.contains(&key)
        } else if let Some((_, field)) = theirs.iter().find(|(t, _)| *t == pair.key_type) {
            // Every one of these is keyless, and the callers read only the
            // keyless pair; one with key data is not the one rendered.
            pair.key_data.is_empty() && out.get(*field).is_some()
        } else {
            known.contains(&pair.key_type)
        };
        if !shown {
            obj.insert(hex::encode(&key), json!(hex::encode(&pair.value)));
        }
    }
    obj
}

/// The fields the callers write for Core's other known input and output
/// types, by key type. A version 2 caller leaves a field out when its value
/// does not parse.
const THEIRS_INPUT: &[(u64, &str)] = &[
    (0x01, "witness_utxo"),
    (0x04, "redeem_script"),
    (0x05, "witness_script"),
    (0x07, "final_scriptSig"),
    (0x08, "final_scriptwitness"),
    (0x0e, "previous_txid"),
    (0x0f, "previous_vout"),
    (0x10, "sequence"),
    (0x11, "required_time_locktime"),
    (0x12, "required_height_locktime"),
];
const THEIRS_OUTPUT: &[(u64, &str)] =
    &[(0x00, "redeem_script"), (0x01, "witness_script"), (0x03, "amount"), (0x04, "script")];

/// The key types this module renders, in each map. Core's other known
/// types are the callers'.
const MINE_GLOBAL: &[u64] = &[0x01, 0xfc];
const MINE_INPUT: &[u64] =
    &[0x00, 0x02, 0x03, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x1a, 0x1b, 0x1c, 0xfc];
const MINE_OUTPUT: &[u64] = &[0x02, 0x05, 0x06, 0x07, 0x08, 0xfc];

/// The top-level fields of Core's `decodepsbt` that come from the global
/// map: `global_xpubs`, `proprietary` and `unknown`, all three always
/// present.
pub(crate) fn global_fields(map: &RawMap, out: &mut Value) {
    let mut used = BTreeSet::new();
    // `std::map<KeyOriginInfo, std::set<CExtPubKey>>`: by fingerprint, then
    // path length, then path; then by the key and its chain code.
    let mut xpubs: Vec<(XpubOrder, Value)> = Vec::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == keys::global::XPUB) {
        let Some((fingerprint, path)) = key_origin(&pair.value) else { continue };
        if pair.key_data.len() != 78 || !is_pubkey(&pair.key_data[45..]) {
            continue;
        }
        used.insert(full_key(pair));
        let (chaincode, pubkey) = (pair.key_data[13..45].to_vec(), pair.key_data[45..].to_vec());
        // `std::set<CExtPubKey>` compares the key and chain code only, so a
        // second encoding of the same key under the same origin is one
        // entry, the first read.
        let order = ((fingerprint, path.len(), path.clone()), (pubkey.clone(), chaincode.clone()));
        if xpubs.iter().any(|(o, _)| *o == order) {
            continue;
        }
        let row = json!({
            "xpub": bitcoin::base58::encode_check(&pair.key_data),
            "master_fingerprint": hex::encode(fingerprint),
            "path": keypath(&path),
        });
        xpubs.push((order, row));
    }
    xpubs.sort_by(|a, b| a.0.cmp(&b.0));
    out["global_xpubs"] = Value::Array(xpubs.into_iter().map(|(_, row)| row).collect());
    out["proprietary"] = Value::Array(proprietary_json(map, keys::global::PROPRIETARY, &mut used));
    let unknown = unknown_json(map, CORE_GLOBAL, MINE_GLOBAL, &used, &[], out);
    out["unknown"] = Value::Object(unknown);
}

/// The input fields of Core's `decodepsbt` beyond the scripts and UTXOs
/// the callers write: `non_witness_utxo` (with `tx_univ`), the signatures,
/// `sighash`, derivations, preimages, the taproot and MuSig2 fields,
/// `proprietary` and `unknown`. Each is set only when the PSBT has it, as
/// in Core.
pub(crate) fn input_fields(map: &RawMap, out: &mut Value, network: bitcoin::Network) {
    let mut used = BTreeSet::new();
    let mark = |used: &mut BTreeSet<Vec<u8>>, pair: &RawPair| {
        used.insert(full_key(pair));
    };
    let pairs = |ty: u64| map.pairs().iter().filter(move |p| p.key_type == ty);

    if let Some(pair) = pairs(keys::input::NON_WITNESS_UTXO).find(|p| p.key_data.is_empty())
        && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&pair.value)
    {
        mark(&mut used, pair);
        out["non_witness_utxo"] = crate::rpc::psbt::tx_univ(&tx, network);
    }

    // `partial_sigs` is keyed by key id; the JSON object by the key's hex.
    let mut sigs = Map::new();
    for pair in pairs(keys::input::PARTIAL_SIG).filter(|p| is_pubkey(&p.key_data)) {
        mark(&mut used, pair);
        sigs.insert(hex::encode(&pair.key_data), json!(hex::encode(&pair.value)));
    }
    if !sigs.is_empty() {
        out["partial_signatures"] = Value::Object(sigs);
    }

    if let Some(pair) = pairs(keys::input::SIGHASH_TYPE).find(|p| p.key_data.is_empty() && p.value.len() == 4) {
        mark(&mut used, pair);
        let v = u32::from_le_bytes(pair.value[..4].try_into().expect("four bytes"));
        out["sighash"] = json!(sighash_to_str(v));
    }

    let derivs = bip32_derivs(map, keys::input::BIP32_DERIVATION, &mut used);
    if !derivs.is_empty() {
        out["bip32_derivs"] = Value::Array(derivs);
    }

    for (ty, name, len) in [
        (keys::input::RIPEMD160, "ripemd160_preimages", 20),
        (keys::input::SHA256, "sha256_preimages", 32),
        (keys::input::HASH160, "hash160_preimages", 20),
        (keys::input::HASH256, "hash256_preimages", 32),
    ] {
        let mut obj = Map::new();
        for pair in pairs(ty).filter(|p| p.key_data.len() == len) {
            mark(&mut used, pair);
            obj.insert(hex::encode(&pair.key_data), json!(hex::encode(&pair.value)));
        }
        if !obj.is_empty() {
            out[name] = Value::Object(obj);
        }
    }

    if let Some(pair) = pairs(keys::input::TAP_KEY_SIG).find(|p| p.key_data.is_empty()) {
        mark(&mut used, pair);
        out["taproot_key_path_sig"] = json!(hex::encode(&pair.value));
    }

    // `std::map<std::pair<XOnlyPubKey, uint256>, ...>`: by key, then leaf
    // hash, which is the order of the key bytes.
    let mut script_sigs: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for pair in pairs(keys::input::TAP_SCRIPT_SIG).filter(|p| p.key_data.len() == 64) {
        mark(&mut used, pair);
        script_sigs.insert(
            pair.key_data.clone(),
            json!({
                "pubkey": hex::encode(&pair.key_data[..32]),
                "leaf_hash": hex::encode(&pair.key_data[32..]),
                "sig": hex::encode(&pair.value),
            }),
        );
    }
    if !script_sigs.is_empty() {
        out["taproot_script_path_sigs"] = Value::Array(script_sigs.into_values().collect());
    }

    // `std::map<std::pair<script, leaf version>, std::set<control block,
    // ShortestVectorFirstComparator>>`: one row per script, its control
    // blocks shortest first.
    let mut leaves: BTreeMap<LeafKey, BTreeSet<(usize, Vec<u8>)>> = BTreeMap::new();
    for pair in pairs(keys::input::TAP_LEAF_SCRIPT) {
        let Some((&leaf_ver, script)) = pair.value.split_last() else { continue };
        mark(&mut used, pair);
        leaves
            .entry((script.to_vec(), leaf_ver))
            .or_default()
            .insert((pair.key_data.len(), pair.key_data.clone()));
    }
    if !leaves.is_empty() {
        let rows = leaves
            .into_iter()
            .map(|((script, leaf_ver), blocks)| {
                json!({
                    "script": hex::encode(script),
                    "leaf_ver": leaf_ver,
                    "control_blocks": blocks.into_iter().map(|(_, b)| hex::encode(b)).collect::<Vec<_>>(),
                })
            })
            .collect();
        out["taproot_scripts"] = Value::Array(rows);
    }

    let tap_derivs = tap_bip32_derivs(map, keys::input::TAP_BIP32_DERIVATION, &mut used);
    if !tap_derivs.is_empty() {
        out["taproot_bip32_derivs"] = Value::Array(tap_derivs);
    }
    if let Some(pair) = pairs(keys::input::TAP_INTERNAL_KEY).find(|p| p.key_data.is_empty()) {
        mark(&mut used, pair);
        out["taproot_internal_key"] = json!(hex::encode(&pair.value));
    }
    if let Some(pair) = pairs(keys::input::TAP_MERKLE_ROOT).find(|p| p.key_data.is_empty()) {
        mark(&mut used, pair);
        out["taproot_merkle_root"] = json!(hex::encode(&pair.value));
    }

    let participants = musig2_participants(map, MUSIG2_PARTICIPANTS_IN, &mut used);
    if !participants.is_empty() {
        out["musig2_participant_pubkeys"] = Value::Array(participants);
    }
    for (ty, name, field, len) in [
        (MUSIG2_PUB_NONCE, "musig2_pubnonces", "pubnonce", 66),
        (MUSIG2_PARTIAL_SIG, "musig2_partial_sigs", "partial_sig", 32),
    ] {
        let rows = musig2_per_participant(map, ty, field, len, &mut used);
        if !rows.is_empty() {
            out[name] = Value::Array(rows);
        }
    }

    let prop = proprietary_json(map, keys::input::PROPRIETARY, &mut used);
    if !prop.is_empty() {
        out["proprietary"] = Value::Array(prop);
    }
    let unknown = unknown_json(map, CORE_INPUT, MINE_INPUT, &used, THEIRS_INPUT, out);
    if !unknown.is_empty() {
        out["unknown"] = Value::Object(unknown);
    }
}

/// The output fields of Core's `decodepsbt` beyond the scripts and the
/// version 2 amount and script: `bip32_derivs`, the taproot and MuSig2
/// fields, `proprietary` and `unknown`, each only when set.
pub(crate) fn output_fields(map: &RawMap, out: &mut Value) {
    let mut used = BTreeSet::new();
    let derivs = bip32_derivs(map, keys::output::BIP32_DERIVATION, &mut used);
    if !derivs.is_empty() {
        out["bip32_derivs"] = Value::Array(derivs);
    }
    if let Some(pair) = map.pairs().iter().find(|p| p.key_type == keys::output::TAP_INTERNAL_KEY && p.key_data.is_empty()) {
        used.insert(full_key(pair));
        out["taproot_internal_key"] = json!(hex::encode(&pair.value));
    }
    if let Some(pair) = map.pairs().iter().find(|p| p.key_type == keys::output::TAP_TREE && p.key_data.is_empty())
        && let Some(tree) = tap_tree(&pair.value)
    {
        used.insert(full_key(pair));
        out["taproot_tree"] = Value::Array(tree);
    }
    let tap_derivs = tap_bip32_derivs(map, keys::output::TAP_BIP32_DERIVATION, &mut used);
    if !tap_derivs.is_empty() {
        out["taproot_bip32_derivs"] = Value::Array(tap_derivs);
    }
    let participants = musig2_participants(map, MUSIG2_PARTICIPANTS_OUT, &mut used);
    if !participants.is_empty() {
        out["musig2_participant_pubkeys"] = Value::Array(participants);
    }
    let prop = proprietary_json(map, keys::output::PROPRIETARY, &mut used);
    if !prop.is_empty() {
        out["proprietary"] = Value::Array(prop);
    }
    let unknown = unknown_json(map, CORE_OUTPUT, MINE_OUTPUT, &used, THEIRS_OUTPUT, out);
    if !unknown.is_empty() {
        out["unknown"] = Value::Object(unknown);
    }
}

/// `std::map<CPubKey, KeyOriginInfo>`, in key byte order.
fn bip32_derivs(map: &RawMap, key_type: u64, used: &mut BTreeSet<Vec<u8>>) -> Vec<Value> {
    let mut rows: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == key_type && is_pubkey(&p.key_data)) {
        let Some((fingerprint, path)) = key_origin(&pair.value) else { continue };
        used.insert(full_key(pair));
        rows.insert(pair.key_data.clone(), origin_json(&pair.key_data, fingerprint, &path));
    }
    rows.into_values().collect()
}

/// `std::map<XOnlyPubKey, std::pair<std::set<uint256>, KeyOriginInfo>>`:
/// by key, the leaf hashes in byte order.
fn tap_bip32_derivs(map: &RawMap, key_type: u64, used: &mut BTreeSet<Vec<u8>>) -> Vec<Value> {
    let mut rows: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == key_type && p.key_data.len() == 32) {
        let Some((n, rest)) = read_compact(&pair.value) else { continue };
        let Some(hashes_len) = usize::try_from(n).ok().and_then(|n| n.checked_mul(32)) else { continue };
        if rest.len() < hashes_len {
            continue;
        }
        let Some((fingerprint, path)) = key_origin(&rest[hashes_len..]) else { continue };
        let hashes: BTreeSet<&[u8]> = rest[..hashes_len].chunks(32).collect();
        used.insert(full_key(pair));
        let mut row = origin_json(&pair.key_data, fingerprint, &path);
        row["leaf_hashes"] = json!(hashes.into_iter().map(hex::encode).collect::<Vec<_>>());
        rows.insert(pair.key_data.clone(), row);
    }
    rows.into_values().collect()
}

/// `PSBT_OUT_TAP_TREE`: (depth, leaf version, script) tuples in order.
fn tap_tree(value: &[u8]) -> Option<Vec<Value>> {
    let mut rest = value;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (&depth, r) = rest.split_first()?;
        let (&leaf_ver, r) = r.split_first()?;
        let (len, r) = read_compact(r)?;
        let len = usize::try_from(len).ok()?;
        let script = r.get(..len)?;
        out.push(json!({ "depth": depth, "leaf_ver": leaf_ver, "script": hex::encode(script) }));
        rest = &r[len..];
    }
    (!out.is_empty()).then_some(out)
}

/// `std::map<CPubKey, std::vector<CPubKey>>`: aggregate key to its
/// participants, in the order the PSBT lists them.
fn musig2_participants(map: &RawMap, key_type: u64, used: &mut BTreeSet<Vec<u8>>) -> Vec<Value> {
    let mut rows: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == key_type && p.key_data.len() == 33) {
        if pair.value.is_empty() || pair.value.len() % 33 != 0 {
            continue;
        }
        used.insert(full_key(pair));
        rows.insert(
            pair.key_data.clone(),
            json!({
                "aggregate_pubkey": hex::encode(&pair.key_data),
                "participant_pubkeys": pair.value.chunks(33).map(hex::encode).collect::<Vec<_>>(),
            }),
        );
    }
    rows.into_values().collect()
}

/// MuSig2 nonces and partial signatures, keyed `participant || aggregate
/// [|| leaf hash]`. Core keeps them as `map<pair<aggregate, leaf hash>,
/// map<participant, value>>`, so the rows go by aggregate key, then leaf
/// hash (none sorts first, as a null `uint256`), then participant, and a
/// row has `leaf_hash` only when one is set.
fn musig2_per_participant(
    map: &RawMap,
    key_type: u64,
    field: &str,
    value_len: usize,
    used: &mut BTreeSet<Vec<u8>>,
) -> Vec<Value> {
    let mut rows: BTreeMap<MusigKey, Value> = BTreeMap::new();
    for pair in map.pairs().iter().filter(|p| p.key_type == key_type) {
        let k = &pair.key_data;
        if (k.len() != 66 && k.len() != 98) || pair.value.len() != value_len {
            continue;
        }
        let (part, agg) = (&k[..33], &k[33..66]);
        let leaf: [u8; 32] = if k.len() == 98 { k[66..].try_into().expect("32 bytes") } else { [0; 32] };
        used.insert(full_key(pair));
        let mut row = json!({
            "participant_pubkey": hex::encode(part),
            "aggregate_pubkey": hex::encode(agg),
        });
        if leaf != [0; 32] {
            row["leaf_hash"] = json!(hex::encode(leaf));
        }
        row[field] = json!(hex::encode(&pair.value));
        rows.insert((agg.to_vec(), leaf, part.to_vec()), row);
    }
    rows.into_values().collect()
}
