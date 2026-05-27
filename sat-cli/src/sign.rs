//! Client-side PSBT signing.
//!
//! This module signs a PSBT entirely locally so a private key never travels
//! over JSON-RPC to the daemon. All prevout data needed to compute sighashes
//! (`witness_utxo` / `non_witness_utxo`) already lives in the PSBT, so signing
//! is a pure function over the PSBT and needs only the `bitcoin` crate — no
//! chainstate, no node dependency.
//!
//! The WIF path mirrors the node's `sign_raw_transaction_with_key`
//! (`node/src/rpc/rawtx.rs`) for the four common script types, but writes
//! `partial_sigs` / `tap_key_sig` instead of assembling final witnesses. That
//! is exactly what the node's `finalizepsbt` consumes.
//!
//! An xpriv is handled two ways. First it is expanded into standard-path child
//! keys (BIP 44/49/84/86, account 0, receive + change, over a bounded gap)
//! which feed the same script-matching pass — so an xpriv can sign PSBTs that
//! carry no derivation metadata, including satd's own `createpsbt` output.
//! Second, `Psbt::sign` is still run so PSBTs that *do* carry
//! `bip32_derivation` / `tap_key_origins` (e.g. from another wallet) sign on
//! their declared paths even when those fall outside the standard scan.
//!
//! Key erasure is best-effort. `secp256k1` deliberately does not implement
//! `Zeroize` (the compiler may copy/move secrets freely, so it can't be
//! guaranteed); instead it exposes `SecretKey::non_secure_erase`, a volatile
//! overwrite plus compiler fence — the same primitive the `zeroize` crate
//! uses. We call it on every key copy we hold, but copies made inside the C
//! signing path or spilled to the stack are unreachable.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{PublicKey, ScriptBuf, TxOut};

/// Outcome of attempting to sign a single PSBT input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    /// Signed during this run (a `partial_sig` / `tap_key_sig` was added).
    Signed,
    /// The input carried a final scriptSig/witness before we touched it.
    AlreadyFinal,
    /// A supported script, but none of the provided keys matched it.
    NoMatchingKey,
    /// No `witness_utxo` / `non_witness_utxo`, so the sighash can't be computed.
    MissingUtxo,
    /// The prevout script type is not supported by this signer.
    Unsupported,
}

impl InputOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            InputOutcome::Signed => "signed",
            InputOutcome::AlreadyFinal => "already final",
            InputOutcome::NoMatchingKey => "no matching key",
            InputOutcome::MissingUtxo => "missing witness_utxo",
            InputOutcome::Unsupported => "unsupported script",
        }
    }
}

/// Per-input results of a signing run.
#[derive(Debug, Clone)]
pub struct SignSummary {
    pub per_input: Vec<InputOutcome>,
}

impl SignSummary {
    /// True when every input is signed (now or already).
    pub fn complete(&self) -> bool {
        self.per_input
            .iter()
            .all(|o| matches!(o, InputOutcome::Signed | InputOutcome::AlreadyFinal))
    }
}

pub fn psbt_from_base64(b64: &str) -> Result<Psbt, String> {
    let raw = BASE64
        .decode(b64.trim())
        .map_err(|e| format!("PSBT base64 decode failed: {e}"))?;
    Psbt::deserialize(&raw).map_err(|e| format!("PSBT decode failed: {e}"))
}

pub fn psbt_to_base64(psbt: &Psbt) -> String {
    BASE64.encode(psbt.serialize())
}

/// Sign `psbt` in place with the given WIF keys and/or xprivs. Never finalizes
/// inputs — that is `finalizepsbt`'s job on the node.
pub fn sign_psbt(
    psbt: &mut Psbt,
    wif_keys: &[bitcoin::PrivateKey],
    xprivs: &[bitcoin::bip32::Xpriv],
    gap: u32,
) -> SignSummary {
    let secp = Secp256k1::new();

    // Snapshot which inputs were already finalized before we start so we can
    // distinguish "AlreadyFinal" from "Signed" afterwards.
    let was_final: Vec<bool> = psbt
        .inputs
        .iter()
        .map(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some())
        .collect();

    // Candidate keys: explicit WIF keys plus standard-path children expanded
    // from each xpriv, so an xpriv signs PSBTs that carry no derivation
    // metadata (e.g. satd's own `createpsbt` output).
    let mut derived: Vec<bitcoin::PrivateKey> = Vec::new();
    for xpriv in xprivs {
        derived.extend(expand_xpriv(&secp, xpriv, gap));
    }
    let mut key_map: HashMap<PublicKey, SecretKey> = HashMap::new();
    let mut xonly_key_map: HashMap<XOnlyPublicKey, SecretKey> = HashMap::new();
    for pk in wif_keys.iter().chain(derived.iter()) {
        let pubkey = pk.public_key(&secp);
        let (xonly, _parity) = pubkey.inner.x_only_public_key();
        key_map.insert(pubkey, pk.inner);
        xonly_key_map.insert(xonly, pk.inner);
    }

    // WIF pass. Clone the unsigned tx once so SighashCache can borrow it while
    // we mutate psbt.inputs[i].
    let tx = psbt.unsigned_tx.clone();
    let prevouts: Vec<Option<TxOut>> = (0..psbt.inputs.len())
        .map(|i| input_prevout(psbt, i))
        .collect();
    // Taproot key-spend (SIGHASH_DEFAULT) commits to EVERY input's amount and
    // script via Prevouts::All, so we can only sign a taproot input when all
    // prevouts are known. We must never fabricate placeholder prevouts — that
    // would yield a signature over the wrong data while still marking the input
    // signed. The real vector is built only when complete; otherwise taproot
    // inputs are left unsigned and reported (see the per-input outcome below).
    let all_prevouts_known = prevouts.iter().all(Option::is_some);
    let all_prevouts: Vec<TxOut> = if all_prevouts_known {
        prevouts.iter().map(|p| p.clone().unwrap()).collect()
    } else {
        Vec::new()
    };

    let mut cache = SighashCache::new(&tx);
    for i in 0..psbt.inputs.len() {
        if was_final[i] {
            continue;
        }
        let Some(prevout) = prevouts[i].clone() else {
            continue;
        };
        sign_input_wif(
            &secp,
            &mut cache,
            i,
            &prevout,
            &all_prevouts,
            all_prevouts_known,
            &key_map,
            &xonly_key_map,
            &mut psbt.inputs[i],
        );
    }

    // xpriv pass: rust-bitcoin signs every input whose bip32_derivation /
    // tap_key_origins matches the xpriv. Errors are per-key and non-fatal —
    // the final per-input outcome is read from PSBT state below.
    for xpriv in xprivs {
        let _ = psbt.sign(xpriv, &secp);
    }

    // Best-effort wipe of the secret-key copies we hold. `SecretKey` is
    // `Copy`, so this only erases the bindings in these maps — copies made by
    // the compiler or inside secp256k1's C signing path are unreachable. See
    // the module docs for the honest limitation.
    for sk in key_map.values_mut() {
        sk.non_secure_erase();
    }
    for sk in xonly_key_map.values_mut() {
        sk.non_secure_erase();
    }
    for pk in &mut derived {
        pk.inner.non_secure_erase();
    }

    // Derive outcomes from the resulting PSBT state.
    summarize(psbt)
}

/// Classify each input of a PSBT by its current signing state. Used both as the
/// return of [`sign_psbt`] and by the external-signer path to report on a PSBT
/// returned by the signer — so both share identical reporting and exit codes.
pub fn summarize(psbt: &Psbt) -> SignSummary {
    // Taproot key-spend needs every input's prevout; if any is missing, no
    // taproot input is signable, so report those as MissingUtxo rather than
    // NoMatchingKey.
    let all_prevouts_known = (0..psbt.inputs.len()).all(|i| input_prevout(psbt, i).is_some());
    let per_input = (0..psbt.inputs.len())
        .map(|i| {
            let input = &psbt.inputs[i];
            if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
                return InputOutcome::AlreadyFinal;
            }
            if !input.partial_sigs.is_empty() || input.tap_key_sig.is_some() {
                return InputOutcome::Signed;
            }
            match input_prevout(psbt, i) {
                None => InputOutcome::MissingUtxo,
                Some(prevout) if !is_supported_script(&prevout.script_pubkey) => {
                    InputOutcome::Unsupported
                }
                Some(prevout) if prevout.script_pubkey.is_p2tr() && !all_prevouts_known => {
                    InputOutcome::MissingUtxo
                }
                Some(_) => InputOutcome::NoMatchingKey,
            }
        })
        .collect();
    SignSummary { per_input }
}

/// Resolve an input's prevout `TxOut` from `witness_utxo`, falling back to the
/// relevant output of `non_witness_utxo`.
fn input_prevout(psbt: &Psbt, i: usize) -> Option<TxOut> {
    let input = &psbt.inputs[i];
    if let Some(utxo) = &input.witness_utxo {
        return Some(utxo.clone());
    }
    if let Some(prev_tx) = &input.non_witness_utxo {
        let vout = psbt.unsigned_tx.input[i].previous_output.vout as usize;
        return prev_tx.output.get(vout).cloned();
    }
    None
}

fn is_supported_script(script: &bitcoin::Script) -> bool {
    script.is_p2pkh() || script.is_p2wpkh() || script.is_p2sh() || script.is_p2tr()
}

/// Expand an xpriv into candidate signing keys over the standard derivation
/// paths, so script-matching can find the key for a PSBT that carries no
/// derivation metadata. Covers BIP 44/49/84/86 (account 0, receive + change)
/// when given a master key, plus the bare key and a receive/change leaf scan
/// for account-level keys — each over `0..gap`. The coin type follows the
/// key's network (0' mainnet, 1' otherwise).
fn expand_xpriv(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    xpriv: &bitcoin::bip32::Xpriv,
    gap: u32,
) -> Vec<bitcoin::PrivateKey> {
    use bitcoin::bip32::ChildNumber;
    let h = |i| ChildNumber::from_hardened_idx(i).expect("valid hardened index");
    let n = |i| ChildNumber::from_normal_idx(i).expect("valid normal index");
    let coin = match xpriv.network {
        bitcoin::NetworkKind::Main => 0u32,
        bitcoin::NetworkKind::Test => 1u32,
    };

    let mut out = Vec::new();
    // The key itself (e.g. a leaf xpriv).
    out.push(xpriv.to_priv());

    // Treat as an account-level key: scan receive/change leaves.
    for change in [0u32, 1] {
        for i in 0..gap {
            if let Ok(child) = xpriv.derive_priv(secp, &[n(change), n(i)]) {
                out.push(child.to_priv());
            }
        }
    }

    // Treat as a master key: descend the four standard BIP purposes, account 0.
    if xpriv.depth == 0 {
        for purpose in [44u32, 49, 84, 86] {
            for change in [0u32, 1] {
                for i in 0..gap {
                    let path = [h(purpose), h(coin), h(0), n(change), n(i)];
                    if let Ok(child) = xpriv.derive_priv(secp, &path) {
                        out.push(child.to_priv());
                    }
                }
            }
        }
    }
    out
}

/// Try to add a signature to one input using the WIF key maps. Writes
/// `partial_sigs` (ecdsa) or `tap_key_sig` (taproot key-path), plus
/// `redeem_script` for p2sh-wrapped-p2wpkh so the node can finalize it.
#[allow(clippy::too_many_arguments)]
fn sign_input_wif(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    cache: &mut SighashCache<&bitcoin::Transaction>,
    i: usize,
    prevout: &TxOut,
    all_prevouts: &[TxOut],
    all_prevouts_known: bool,
    key_map: &HashMap<PublicKey, SecretKey>,
    xonly_key_map: &HashMap<XOnlyPublicKey, SecretKey>,
    input: &mut bitcoin::psbt::Input,
) {
    let script = &prevout.script_pubkey;

    if script.is_p2pkh() {
        let Ok(sighash) = cache.legacy_signature_hash(i, script, EcdsaSighashType::All.to_u32())
        else {
            return;
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        for (pubkey, secret) in key_map {
            if ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()).as_bytes() == script.as_bytes() {
                let sig = secp.sign_ecdsa(&msg, secret);
                input
                    .partial_sigs
                    .insert(*pubkey, bitcoin::ecdsa::Signature::sighash_all(sig));
                return;
            }
        }
    } else if script.is_p2wpkh() {
        for (pubkey, secret) in key_map {
            let Ok(wpkh) = pubkey.wpubkey_hash() else {
                continue;
            };
            if ScriptBuf::new_p2wpkh(&wpkh).as_bytes() != script.as_bytes() {
                continue;
            }
            let Ok(sighash) =
                cache.p2wpkh_signature_hash(i, script, prevout.value, EcdsaSighashType::All)
            else {
                return;
            };
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg, secret);
            input
                .partial_sigs
                .insert(*pubkey, bitcoin::ecdsa::Signature::sighash_all(sig));
            return;
        }
    } else if script.is_p2sh() {
        for (pubkey, secret) in key_map {
            let Ok(wpkh) = pubkey.wpubkey_hash() else {
                continue;
            };
            let redeem = ScriptBuf::new_p2wpkh(&wpkh);
            if ScriptBuf::new_p2sh(&redeem.script_hash()).as_bytes() != script.as_bytes() {
                continue;
            }
            let Ok(sighash) =
                cache.p2wpkh_signature_hash(i, &redeem, prevout.value, EcdsaSighashType::All)
            else {
                return;
            };
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg, secret);
            input
                .partial_sigs
                .insert(*pubkey, bitcoin::ecdsa::Signature::sighash_all(sig));
            // The finalizer needs the redeem script to assemble the scriptSig.
            input.redeem_script = Some(redeem);
            return;
        }
    } else if script.is_p2tr() {
        // Refuse to sign a taproot key-spend unless every prevout is known —
        // the sighash commits to all of them, so a missing sibling would make
        // any signature we produce invalid.
        if !all_prevouts_known {
            return;
        }
        let Ok(sighash) = cache.taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(all_prevouts),
            TapSighashType::Default,
        ) else {
            return;
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        for (xonly, secret) in xonly_key_map {
            if ScriptBuf::new_p2tr(secp, *xonly, None).as_bytes() != script.as_bytes() {
                continue;
            }
            let keypair = Keypair::from_secret_key(secp, secret);
            let tweaked = keypair.tap_tweak(secp, None);
            let sig = secp.sign_schnorr(&msg, &tweaked.to_keypair());
            input.tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Address, Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
    };

    fn key(byte: u8) -> (bitcoin::PrivateKey, Secp256k1<bitcoin::secp256k1::All>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = bitcoin::PrivateKey::new(sk, Network::Regtest);
        (pk, secp)
    }

    fn psbt_spending(spk: ScriptBuf, value: u64) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_slice(&[7u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value - 1000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        });
        psbt
    }

    #[test]
    fn signs_p2wpkh_input() {
        let (pk, secp) = key(0x42);
        let cpk = CompressedPublicKey::from_slice(&pk.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 50 * 100_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert!(summary.complete());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn taproot_not_signed_when_sibling_prevout_missing() {
        // SIGHASH_DEFAULT commits to every input's prevout. If a sibling input
        // lacks its witness_utxo, our taproot input must NOT be signed (a
        // fabricated placeholder would yield an invalid signature marked
        // "signed"). It must be reported MissingUtxo instead.
        let (pk, secp) = key(0x66);
        let (xonly, _) = pk.public_key(&secp).inner.x_only_public_key();
        let spk = ScriptBuf::new_p2tr(&secp, xonly, None);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_slice(&[7u8; 32]).unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_slice(&[8u8; 32]).unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk,
        });
        // input 1 intentionally has no witness_utxo (sibling prevout unknown).

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "must not fabricate a taproot signature over a missing sibling prevout"
        );
        assert_eq!(summary.per_input[0], InputOutcome::MissingUtxo);
        assert_eq!(summary.per_input[1], InputOutcome::MissingUtxo);
        assert!(!summary.complete());
    }

    #[test]
    fn signs_p2pkh_input() {
        let (pk, secp) = key(0x43);
        let spk = Address::p2pkh(pk.public_key(&secp), Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn signs_p2sh_p2wpkh_and_sets_redeem_script() {
        let (pk, secp) = key(0x44);
        let cpk = CompressedPublicKey::from_slice(&pk.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2shwpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert!(
            psbt.inputs[0].redeem_script.is_some(),
            "p2sh-p2wpkh must carry redeem_script for the finalizer"
        );
    }

    #[test]
    fn signs_p2tr_keypath_input() {
        let (pk, secp) = key(0x45);
        let (xonly, _) = pk.public_key(&secp).inner.x_only_public_key();
        let spk = ScriptBuf::new_p2tr(&secp, xonly, None);
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert!(psbt.inputs[0].tap_key_sig.is_some());
    }

    #[test]
    fn missing_utxo_is_reported_not_skipped() {
        let (pk, secp) = key(0x46);
        let cpk = CompressedPublicKey::from_slice(&pk.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);
        psbt.inputs[0].witness_utxo = None; // strip the prevout

        let summary = sign_psbt(&mut psbt, &[pk], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::MissingUtxo]);
        assert!(!summary.complete());
    }

    #[test]
    fn no_matching_key_is_reported() {
        let (signing_key, secp) = key(0x47);
        // Address belongs to a different key than the one we sign with.
        let (other, _) = key(0x48);
        let cpk = CompressedPublicKey::from_slice(&other.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[signing_key], &[], 0);
        assert_eq!(summary.per_input, vec![InputOutcome::NoMatchingKey]);
    }

    fn h(i: u32) -> bitcoin::bip32::ChildNumber {
        bitcoin::bip32::ChildNumber::from_hardened_idx(i).unwrap()
    }
    fn nn(i: u32) -> bitcoin::bip32::ChildNumber {
        bitcoin::bip32::ChildNumber::from_normal_idx(i).unwrap()
    }

    #[test]
    fn signs_via_master_xpriv_standard_path() {
        // A bare PSBT (no derivation metadata) spending an address on the
        // standard BIP84 path must sign from the master xpriv alone.
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Regtest, &[0x11u8; 32]).unwrap();
        let child = master
            .derive_priv(&secp, &[h(84), h(1), h(0), nn(0), nn(0)])
            .unwrap();
        let cpk =
            CompressedPublicKey::from_slice(&child.to_priv().public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[], &[master], 5);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn signs_via_account_level_xpriv() {
        // Wallets export account-level xprivs (depth 3); the receive/change
        // leaf scan must find m/.../0/0 from such a key.
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Regtest, &[0x22u8; 32]).unwrap();
        let account = master.derive_priv(&secp, &[h(84), h(1), h(0)]).unwrap();
        let leaf = account.derive_priv(&secp, &[nn(0), nn(0)]).unwrap();
        let cpk =
            CompressedPublicKey::from_slice(&leaf.to_priv().public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[], &[account], 5);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
    }

    #[test]
    fn signs_taproot_via_master_xpriv() {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Regtest, &[0x33u8; 32]).unwrap();
        let child = master
            .derive_priv(&secp, &[h(86), h(1), h(0), nn(0), nn(0)])
            .unwrap();
        let (xonly, _) = child.to_priv().public_key(&secp).inner.x_only_public_key();
        let spk = ScriptBuf::new_p2tr(&secp, xonly, None);
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[], &[master], 5);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert!(psbt.inputs[0].tap_key_sig.is_some());
    }

    #[test]
    fn xpriv_outside_gap_is_not_found() {
        // An address beyond the scanned gap stays unsigned (fail-closed).
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Regtest, &[0x44u8; 32]).unwrap();
        let child = master
            .derive_priv(&secp, &[h(84), h(1), h(0), nn(0), nn(50)])
            .unwrap();
        let cpk =
            CompressedPublicKey::from_slice(&child.to_priv().public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[], &[master], 5);
        assert_eq!(summary.per_input, vec![InputOutcome::NoMatchingKey]);
    }

    #[test]
    fn base64_round_trip() {
        let (pk, secp) = key(0x49);
        let cpk = CompressedPublicKey::from_slice(&pk.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2wpkh(&cpk, Network::Regtest).script_pubkey();
        let psbt = psbt_spending(spk, 10_000_000);
        let b64 = psbt_to_base64(&psbt);
        let back = psbt_from_base64(&b64).unwrap();
        assert_eq!(back.unsigned_tx, psbt.unsigned_tx);
    }
}
