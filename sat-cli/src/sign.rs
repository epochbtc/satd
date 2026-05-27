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
//! is exactly what the node's `finalizepsbt` consumes. The xpriv path defers to
//! rust-bitcoin's `Psbt::sign`, which keys off the PSBT's `bip32_derivation` /
//! `tap_key_origins`.
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
) -> SignSummary {
    let secp = Secp256k1::new();

    // Snapshot which inputs were already finalized before we start so we can
    // distinguish "AlreadyFinal" from "Signed" afterwards.
    let was_final: Vec<bool> = psbt
        .inputs
        .iter()
        .map(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some())
        .collect();

    // Build pubkey -> secret lookups for the WIF path.
    let mut key_map: HashMap<PublicKey, SecretKey> = HashMap::new();
    let mut xonly_key_map: HashMap<XOnlyPublicKey, SecretKey> = HashMap::new();
    for pk in wif_keys {
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
    // Placeholder-filled prevout vector for taproot's Prevouts::All.
    let all_prevouts: Vec<TxOut> = prevouts
        .iter()
        .map(|p| {
            p.clone().unwrap_or(TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            })
        })
        .collect();

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

    // Derive outcomes from the resulting PSBT state.
    let per_input = (0..psbt.inputs.len())
        .map(|i| {
            if was_final[i] {
                return InputOutcome::AlreadyFinal;
            }
            let input = &psbt.inputs[i];
            if !input.partial_sigs.is_empty() || input.tap_key_sig.is_some() {
                return InputOutcome::Signed;
            }
            if prevouts[i].is_none() {
                return InputOutcome::MissingUtxo;
            }
            let script = &prevouts[i].as_ref().unwrap().script_pubkey;
            if is_supported_script(script) {
                InputOutcome::NoMatchingKey
            } else {
                InputOutcome::Unsupported
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

        let summary = sign_psbt(&mut psbt, &[pk], &[]);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert!(summary.complete());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn signs_p2pkh_input() {
        let (pk, secp) = key(0x43);
        let spk = Address::p2pkh(pk.public_key(&secp), Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[]);
        assert_eq!(summary.per_input, vec![InputOutcome::Signed]);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn signs_p2sh_p2wpkh_and_sets_redeem_script() {
        let (pk, secp) = key(0x44);
        let cpk = CompressedPublicKey::from_slice(&pk.public_key(&secp).to_bytes()).unwrap();
        let spk = Address::p2shwpkh(&cpk, Network::Regtest).script_pubkey();
        let mut psbt = psbt_spending(spk, 10_000_000);

        let summary = sign_psbt(&mut psbt, &[pk], &[]);
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

        let summary = sign_psbt(&mut psbt, &[pk], &[]);
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

        let summary = sign_psbt(&mut psbt, &[pk], &[]);
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

        let summary = sign_psbt(&mut psbt, &[signing_key], &[]);
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
