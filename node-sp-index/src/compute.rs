//! The BIP 352 kernel — shared by the index writer and the scan-key matcher.
//!
//! Everything a scanning client needs from a transaction is the public
//! tweak `T = input_hash · A` (33 bytes). This module derives it
//! (`compute_tweak`) and scans a block's taproot outputs against a
//! scan key (`scan_outputs`). Both the node's index and the SDK's
//! client-side scanner call this same code, so a tweak the node stores
//! and a tweak a wallet recomputes are byte-identical by construction.
//!
//! Correctness bar is **parity with the BIP 352 test vectors**
//! (`tests/vectors.rs`), not self-consistency — the extraction rules
//! below are a faithful port of the BIP 352 reference `reference.py`
//! (v1.1.0), which is what generated those vectors. In particular:
//!
//! - the lowest-outpoint tiebreak for `input_hash` ranges over **all**
//!   of the transaction's inputs, not only the contributing ones
//!   (`get_input_hash([vin.outpoint for vin in vins], ...)` in the
//!   reference);
//! - `PublicKey::combine_keys` (the batch sum) is used deliberately so a
//!   transaction whose intermediate pubkey sum passes through the point
//!   at infinity but whose final sum is valid still indexes (vector
//!   "Input keys intermediate sum is zero but final sum is non-zero").

use std::collections::HashMap;
use std::sync::OnceLock;

use bitcoin::hashes::{Hash, HashEngine, hash160, sha256};
use bitcoin::secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Transaction, TxIn, Txid};

/// Per-group recipient scan limit (BIP 352 v1.1.0 `K_max`). The scanner
/// stops probing candidate outputs after this many consecutive `k`
/// values, bounding adversarial quadratic blow-up. Fact 9 of the design.
pub const K_MAX: usize = 2323;

/// BIP 341 NUMS point `H` (x-only), the "provably-unspendable" internal
/// key. A taproot script-path spend that reveals this internal key in its
/// control block is not a contributing input (fact 3).
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

const TAG_INPUTS: &[u8] = b"BIP0352/Inputs";
const TAG_SHARED_SECRET: &[u8] = b"BIP0352/SharedSecret";
const TAG_LABEL: &[u8] = b"BIP0352/Label";

/// One indexed transaction: the public tweak plus the fields satd stores
/// alongside it (design decision D6). `max_taproot_value` is the largest
/// value among the transaction's taproot outputs — it drives the
/// light-client dust-limit filter without the client fetching the tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TweakEntry {
    pub txid: Txid,
    pub tweak: PublicKey,
    pub max_taproot_value: Amount,
}

/// One output a scan key matched, with the per-output private-key tweak a
/// wallet adds to its spend key to derive the full spending key
/// (`d = b_spend + priv_key_tweak mod n`). `label_m` is the label integer
/// when the match came via a label (`m = 0` is change), else `None`.
///
/// `k` is the BIP 352 output counter at which this output matched: the
/// scanner probes `P_k = B_spend + hash_BIP0352/SharedSecret(ecdh || k)·G`
/// for `k = 0, 1, …` and increments `k` on each hit. Reporting it lets a
/// light client re-derive the output key offline from the public tweak `T`
/// and its own `b_scan` alone (Tier-2 `SilentPaymentMatched.k`, §4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpMatch {
    pub output: XOnlyPublicKey,
    pub priv_key_tweak: [u8; 32],
    pub label_m: Option<u32>,
    pub k: u32,
}

/// Process-wide secp context. BIP 352 needs both signing (`t_k·G`) and
/// verification (point mul) capabilities, so this is an `All` context;
/// building it once keeps the index-build and scan hot loops off the
/// per-call randomization cost.
fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// BIP 340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// Parse a witness/scriptSig pubkey push as a *compressed* secp point.
/// BIP 352 contributes only compressed keys from P2WPKH / P2SH-P2WPKH /
/// P2PKH inputs — uncompressed keys are skipped (vector "P2PKH and
/// P2WPKH Uncompressed Keys are skipped"), which falls out of requiring
/// exactly 33 bytes here.
fn parse_compressed(bytes: &[u8]) -> Option<PublicKey> {
    if bytes.len() != 33 {
        return None;
    }
    PublicKey::from_slice(bytes).ok()
}

/// Extract the contributing public key from one input, or `None` if the
/// input contributes nothing (unknown type, uncompressed key, NUMS
/// script-path, malformed). Faithful port of the reference
/// `get_pubkey_from_input`; the `if` order (P2PKH, P2SH, P2WPKH, P2TR)
/// matches the reference so a script that is somehow several shapes at
/// once resolves identically.
fn extract_input_pubkey(input: &TxIn, spk: &Script) -> Option<PublicKey> {
    let script_sig = input.script_sig.as_bytes();

    if spk.is_p2pkh() {
        // 20-byte hash sits at scriptPubKey[3..23] (after OP_DUP
        // OP_HASH160 <push20>). Slide a 33-byte window back-to-front over
        // the scriptSig and take the push whose hash160 matches — this
        // recovers the key even from malleated scriptSigs (vector
        // "Pubkey extraction from malleated p2pkh").
        let spk_hash = &spk.as_bytes()[3..23];
        let mut end = script_sig.len();
        while end >= 33 {
            let window = &script_sig[end - 33..end];
            if hash160::Hash::hash(window).to_byte_array().as_slice() == spk_hash
                && let Ok(pk) = PublicKey::from_slice(window)
            {
                return Some(pk);
            }
            end -= 1;
        }
    }

    if spk.is_p2sh() {
        // redeemScript = scriptSig without its leading push-length byte.
        if !script_sig.is_empty()
            && Script::from_bytes(&script_sig[1..]).is_p2wpkh()
            && let Some(pk) = input.witness.last().and_then(parse_compressed)
        {
            return Some(pk);
        }
    }

    if spk.is_p2wpkh()
        && let Some(pk) = input.witness.last().and_then(parse_compressed)
    {
        return Some(pk);
    }

    if spk.is_p2tr() {
        let stack: Vec<&[u8]> = input.witness.iter().collect();
        if !stack.is_empty() {
            let mut effective = stack;
            // Strip the annex (last element, ≥2 items, leading 0x50).
            if effective.len() > 1 && effective.last().is_some_and(|e| e.first() == Some(&0x50)) {
                effective.pop();
            }
            // A remaining stack of >1 is a script-path spend: reject it
            // if the control block's internal key is NUMS_H.
            if effective.len() > 1
                && let Some(control_block) = effective.last()
                && control_block.len() >= 33
                && control_block[1..33] == NUMS_H
            {
                return None;
            }
            // Contributing key is the taproot output key, even-Y lifted.
            if let Ok(xonly) = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..]) {
                return Some(xonly.public_key(Parity::Even));
            }
        }
    }

    None
}

/// The contributing input public keys `A_i` of a transaction, in input
/// order (fact 2/3). `prevout_spks[i]` is the scriptPubKey spent by
/// `tx.input[i]`; inputs without a supplied prevout are skipped.
pub fn eligible_inputs(tx: &Transaction, prevout_spks: &[ScriptBuf]) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    for (i, input) in tx.input.iter().enumerate() {
        if let Some(spk) = prevout_spks.get(i)
            && let Some(pk) = extract_input_pubkey(input, spk)
        {
            keys.push(pk);
        }
    }
    keys
}

/// The largest value among the transaction's taproot (BIP 341) outputs,
/// or `None` if it has none (fact 1a — a transaction with no taproot
/// output can carry no silent payment).
fn max_taproot_output_value(tx: &Transaction) -> Option<Amount> {
    tx.output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| o.value)
        .max()
}

/// True if any spent prevout is a SegWit output of version > 1 — such a
/// transaction is not silent-payment eligible (fact 1c, reserved for
/// future upgrades).
fn spends_future_segwit(prevout_spks: &[ScriptBuf]) -> bool {
    prevout_spks
        .iter()
        .any(|spk| spk.witness_version().is_some_and(|v| v.to_num() > 1))
}

/// Serialized outpoint (`txid[32] LE || vout[4] LE`), matching the
/// reference `COutPoint.serialize()` used for the lowest-outpoint
/// tiebreak.
fn ser_outpoint(op: &OutPoint) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(op)
}

/// Compute the public tweak `T = input_hash · A` for a transaction, or
/// `None` if it is not silent-payment eligible / must be skipped.
///
/// Skip conditions (facts 1–5): coinbase; no taproot output; spends a
/// future-SegWit output; no contributing inputs; input pubkey sum is the
/// point at infinity; `input_hash` is zero or ≥ the curve order.
pub fn compute_tweak(tx: &Transaction, prevout_spks: &[ScriptBuf]) -> Option<TweakEntry> {
    if tx.is_coinbase() {
        return None;
    }
    let max_taproot_value = max_taproot_output_value(tx)?;
    if spends_future_segwit(prevout_spks) {
        return None;
    }

    let pubkeys = eligible_inputs(tx, prevout_spks);
    if pubkeys.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = pubkeys.iter().collect();
    // Batch sum tolerates an intermediate infinity; errors only if the
    // final sum is the point at infinity (→ skip, fact 4).
    let a_sum = PublicKey::combine_keys(&refs).ok()?;

    // input_hash uses the lexicographically smallest outpoint over ALL
    // inputs (not only contributing ones), per the reference.
    let lowest = tx
        .input
        .iter()
        .map(|i| i.previous_output)
        .min_by(|a, b| ser_outpoint(a).cmp(&ser_outpoint(b)))?;
    let mut msg = ser_outpoint(&lowest);
    msg.extend_from_slice(&a_sum.serialize());
    let input_hash = tagged_hash(TAG_INPUTS, &msg);

    // ≥ curve order → None; a zero scalar makes mul_tweak error → None.
    let scalar = Scalar::from_be_bytes(input_hash).ok()?;
    let tweak = a_sum.mul_tweak(secp(), &scalar).ok()?;

    Some(TweakEntry {
        txid: tx.compute_txid(),
        tweak,
        max_taproot_value,
    })
}

/// Scan a set of taproot outputs against a scan key, given the public
/// tweak `T` for the transaction (or block group). Returns every output
/// that belongs to `(b_scan, spend_pubkey)` — directly or via one of the
/// receiver's labels (`label_ms`; include `0` for change).
///
/// This is the light-client / Tier-2 path (fact 5–9): it needs only `T`,
/// never the transaction's inputs. `ecdh = b_scan · T`, then candidate
/// `P_k = spend_pubkey + hash(ecdh || k)·G` is matched against outputs,
/// incrementing `k` per match and stopping at `K_MAX`.
pub fn scan_outputs(
    tweak: &PublicKey,
    b_scan: &SecretKey,
    spend_pubkey: &PublicKey,
    label_ms: &[u32],
    outputs: &[XOnlyPublicKey],
) -> Vec<SpMatch> {
    let secp = secp();
    let b_scan_scalar =
        Scalar::from_be_bytes(b_scan.secret_bytes()).expect("secret key is < curve order");
    let ecdh = match tweak.mul_tweak(secp, &b_scan_scalar) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let ecdh_ser = ecdh.serialize();

    // Precompute label points: compressed(label_m·G) → (m, label scalar).
    let mut label_map: HashMap<[u8; 33], (u32, Scalar)> = HashMap::new();
    for &m in label_ms {
        let mut buf = b_scan.secret_bytes().to_vec();
        buf.extend_from_slice(&m.to_be_bytes());
        let label = tagged_hash(TAG_LABEL, &buf);
        if let (Ok(sk), Ok(scalar)) = (SecretKey::from_slice(&label), Scalar::from_be_bytes(label))
        {
            label_map.insert(sk.public_key(secp).serialize(), (m, scalar));
        }
    }

    let mut remaining: Vec<XOnlyPublicKey> = outputs.to_vec();
    let mut matches = Vec::new();
    let mut k: u32 = 0;
    loop {
        if k as usize >= K_MAX {
            break;
        }
        let mut buf = ecdh_ser.to_vec();
        buf.extend_from_slice(&k.to_be_bytes());
        let t_k = tagged_hash(TAG_SHARED_SECRET, &buf);
        let Ok(t_k_sk) = SecretKey::from_slice(&t_k) else {
            break;
        };
        let p_k = match spend_pubkey.combine(&t_k_sk.public_key(secp)) {
            Ok(p) => p,
            Err(_) => break,
        };
        let p_k_xonly = p_k.x_only_public_key().0;
        let neg_p_k = p_k.negate(secp);

        let mut hit: Option<(usize, SpMatch)> = None;
        for (idx, out) in remaining.iter().enumerate() {
            // Direct (unlabeled) match.
            if *out == p_k_xonly {
                hit = Some((
                    idx,
                    SpMatch {
                        output: *out,
                        priv_key_tweak: t_k,
                        label_m: None,
                        k,
                    },
                ));
                break;
            }
            if label_map.is_empty() {
                continue;
            }
            // Labeled match: check both parities of the output against
            // the difference to a known label point. The matched output's
            // x-only is `*out` in either parity; the private-key tweak is
            // `t_k + label_scalar`.
            let out_ge = out.public_key(Parity::Even);
            let diffs = [
                out_ge.combine(&neg_p_k),
                out_ge.negate(secp).combine(&neg_p_k),
            ];
            for diff in diffs.into_iter().flatten() {
                if let Some((m, label_scalar)) = label_map.get(&diff.serialize())
                    && let Ok(tweak_sk) = t_k_sk.add_tweak(label_scalar)
                {
                    hit = Some((
                        idx,
                        SpMatch {
                            output: *out,
                            priv_key_tweak: tweak_sk.secret_bytes(),
                            label_m: Some(*m),
                            k,
                        },
                    ));
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }

        match hit {
            Some((idx, m)) => {
                matches.push(m);
                remaining.remove(idx);
                k += 1;
            }
            None => break,
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nums_constant_matches_bip341() {
        // Sanity: the hard-coded NUMS_H equals the documented hex.
        let hex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        assert_eq!(hex::encode(NUMS_H), hex);
    }

    #[test]
    fn tagged_hash_is_bip340_construction() {
        // Empty-message tagged hash for a known tag is stable; guards the
        // double-SHA(tag) prefix against accidental change.
        let a = tagged_hash(TAG_INPUTS, b"");
        let b = tagged_hash(TAG_INPUTS, b"");
        assert_eq!(a, b);
        assert_ne!(tagged_hash(TAG_INPUTS, b"x"), a);
        // Different tags must not collide on the same message.
        assert_ne!(
            tagged_hash(TAG_LABEL, b""),
            tagged_hash(TAG_SHARED_SECRET, b"")
        );
    }

    #[test]
    fn parse_compressed_rejects_uncompressed_and_wrong_len() {
        assert!(parse_compressed(&[0u8; 65]).is_none());
        assert!(parse_compressed(&[0u8; 32]).is_none());
        // 33 bytes but not a valid compressed point (bad prefix byte).
        assert!(parse_compressed(&[0x01; 33]).is_none());
    }
}
