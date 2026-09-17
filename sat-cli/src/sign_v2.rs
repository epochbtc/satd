//! `sat-cli` as a BIP 375 Signer.
//!
//! A silent payment cannot be assembled without a private key. The output
//! script is derived from `a·B_scan`, where `a` is the input's own secret, so
//! the only party that can compute it is the one holding that secret — which
//! is why this lives in the client and not in the node. satd stays keyless;
//! nothing here crosses the JSON-RPC boundary.
//!
//! The Signer's duties, in BIP 375's order, and the order this module does
//! them in — because the order is the safety property:
//!
//! 1. Refuse a transaction that cannot carry a silent payment at all.
//! 2. Compute an ECDH share for every eligible input this signer holds, with a
//!    BIP 374 proof so anyone can check it without the secret.
//! 3. Once every eligible input is covered, compute each output's script and
//!    clear `PSBT_GLOBAL_TX_MODIFIABLE`.
//! 4. Only then sign. **Never sign while an output has no script**: a
//!    signature commits to the outputs, so signing first would commit to a
//!    transaction that is still going to change.
//!
//! Step 4 is why a partial run is a normal outcome rather than an error. A
//! signer that holds some of the inputs writes its shares, says which inputs
//! still owe theirs, and stops — the PSBT goes round again.

use std::collections::HashMap;

use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{All, Keypair, PublicKey, Scalar, Secp256k1, SecretKey};
use satd_psbt::raw::{RawPair, RawPsbt};
use satd_psbt::sp::{self, OutputStatus, ScriptState};
use satd_psbt::{V2View, keys};

use crate::sign::SignSummary;

/// What a version 2 signing run did.
#[derive(Debug, Clone)]
pub struct SignV2Summary {
    /// Per-input signing state, the same vocabulary the version 0 path uses.
    pub inner: SignSummary,
    /// Eligible inputs that still owe an ECDH share. Non-empty means another
    /// signer has to see this PSBT before anything can be signed.
    pub owing_shares: Vec<usize>,
    /// Whether every silent payment output now carries the script it derives
    /// to. Until this is true, no input may be signed.
    pub outputs_complete: bool,
}

impl SignV2Summary {
    /// Whether this run finished the job: every output computed and every
    /// input signed.
    pub fn complete(&self) -> bool {
        self.outputs_complete && self.owing_shares.is_empty() && self.inner.complete()
    }
}

/// An input this signer holds the key for.
struct Held {
    index: usize,
    /// The secret whose public key is the one the verifier bound to this
    /// input's previous output — negated where the even-Y lift required it.
    secret: SecretKey,
}

/// Sign a version 2 PSBT, doing the BIP 375 Signer's work first.
pub fn sign_psbt_v2(
    raw: &mut RawPsbt,
    wif_keys: &[bitcoin::PrivateKey],
    xprivs: &[bitcoin::bip32::Xpriv],
    gap: u32,
) -> Result<SignV2Summary, String> {
    let secp = Secp256k1::new();

    {
        let view = V2View::new(raw).map_err(|e| e.to_string())?;
        // BIP 375's transaction-wide rules. A segwit v2+ input cannot
        // contribute a public key, and a signature that is not SIGHASH_ALL
        // leaves the outputs free to change after the shared secret was
        // computed from them.
        if view.has_sp_outputs()
            && let Some(why) = sp::check_input_constraints(&view).map_err(|e| e.to_string())?
        {
            return Err(why);
        }
    }

    // The keys this signer can offer: the explicit ones, plus the standard
    // BIP 44/49/84/86 children of each xpriv, exactly as the version 0 path
    // expands them.
    let mut derived: Vec<bitcoin::PrivateKey> = Vec::new();
    for xpriv in xprivs {
        derived.extend(crate::sign::expand_xpriv(&secp, xpriv, gap));
    }
    let mut key_map: HashMap<PublicKey, SecretKey> = HashMap::new();
    let mut xonly_key_map: HashMap<XOnlyPublicKey, SecretKey> = HashMap::new();
    for pk in wif_keys.iter().chain(derived.iter()) {
        let pubkey = pk.public_key(&secp);
        key_map.insert(pubkey.inner, pk.inner);
        xonly_key_map.insert(pubkey.inner.x_only_public_key().0, pk.inner);
    }

    // Record the public key of every input this signer holds, before anything
    // reads the PSBT. Without it nobody — not the node, not the next signer,
    // not the recipient's own wallet — can tell whose key an ECDH share
    // belongs to, so the whole thing is unverifiable. satd's `createpsbt` has
    // no wallet and cannot write these, which makes it the Signer's job.
    declare_held_keys(&secp, raw, &key_map, &xonly_key_map)?;

    let mut owing_shares = Vec::new();
    let has_sp = V2View::new(raw)
        .map(|v| v.has_sp_outputs())
        .unwrap_or(false);
    if has_sp {
        owing_shares = fill_silent_payments(&secp, raw, &key_map, &xonly_key_map)?;
    }

    // A signature commits to the outputs, so an output with no script yet is
    // a hard stop rather than a thing to work around.
    let outputs_complete = {
        let view = V2View::new(raw).map_err(|e| e.to_string())?;
        view.outputs()
            .all(|o| matches!(o.script(), Ok(Some(s)) if !s.is_empty()))
    };

    let inner = if outputs_complete {
        sign_inputs(&secp, raw, wif_keys, xprivs, gap)?
    } else {
        crate::sign::summarize_v2(raw)?
    };

    // Best-effort wipe, as in the version 0 path. `SecretKey` is `Copy`, so
    // this erases the bindings here and not whatever the compiler or
    // secp256k1's C path may have copied.
    for sk in key_map.values_mut() {
        sk.non_secure_erase();
    }
    for sk in xonly_key_map.values_mut() {
        sk.non_secure_erase();
    }
    for pk in &mut derived {
        pk.inner.non_secure_erase();
    }

    Ok(SignV2Summary {
        inner,
        owing_shares,
        outputs_complete,
    })
}

/// Write a `PSBT_IN_BIP32_DERIVATION` for each input whose previous output
/// this signer's keys unlock.
///
/// This is the only field in a PSBT that carries an input's public key, and a
/// verifier needs it: the taproot case reads the key out of the script, but a
/// P2WPKH, P2PKH or nested P2WPKH output commits only to a hash. A key is
/// written only when it actually hashes to the script it claims, so the entry
/// is a fact about the transaction rather than an assertion to be trusted —
/// which is exactly what the node re-checks before it believes any share.
///
/// A key given as WIF has no derivation, so the entry carries a zero master
/// fingerprint and an empty path. BIP 174 allows that, and the path is not
/// what anyone reads here: the key is.
fn declare_held_keys(
    secp: &Secp256k1<All>,
    raw: &mut RawPsbt,
    key_map: &HashMap<PublicKey, SecretKey>,
    xonly_key_map: &HashMap<XOnlyPublicKey, SecretKey>,
) -> Result<(), String> {
    use bitcoin::hashes::{Hash, hash160};

    let prevouts: Vec<Option<bitcoin::TxOut>> = {
        let view = V2View::new(raw).map_err(|e| e.to_string())?;
        view.inputs().map(|i| i.prevout().ok().flatten()).collect()
    };

    for (index, prevout) in prevouts.iter().enumerate() {
        let Some(prevout) = prevout else { continue };
        let script = &prevout.script_pubkey;
        // A taproot input's key is in its own script; there is nothing to say.
        if script.is_p2tr() {
            let _ = xonly_key_map;
            continue;
        }

        let hash: Vec<u8> = if script.is_p2wpkh() {
            script.as_bytes()[2..22].to_vec()
        } else if script.is_p2pkh() {
            script.as_bytes()[3..23].to_vec()
        } else if script.is_p2sh() {
            // The nested case: the key hashes to the redeem script, which
            // hashes to the output. Only a key producing both is the right one.
            let mut found = None;
            for pubkey in key_map.keys() {
                let compressed = bitcoin::PublicKey::new(*pubkey);
                let Ok(wpkh) = compressed.wpubkey_hash() else {
                    continue;
                };
                let redeem = bitcoin::ScriptBuf::new_p2wpkh(&wpkh);
                if bitcoin::ScriptBuf::new_p2sh(&redeem.script_hash()).as_bytes()
                    == script.as_bytes()
                {
                    found = Some((*pubkey, redeem));
                    break;
                }
            }
            let Some((pubkey, redeem)) = found else {
                continue;
            };
            if !raw.inputs[index].contains_type(keys::input::REDEEM_SCRIPT) {
                raw.inputs[index].set(RawPair::new(
                    keys::input::REDEEM_SCRIPT,
                    Vec::new(),
                    redeem.to_bytes(),
                ));
            }
            declare_key(&mut raw.inputs[index], &pubkey);
            continue;
        } else {
            continue;
        };

        for pubkey in key_map.keys() {
            if hash160::Hash::hash(&pubkey.serialize()).to_byte_array()[..] == hash[..] {
                declare_key(&mut raw.inputs[index], pubkey);
                break;
            }
        }
    }
    let _ = secp;
    Ok(())
}

fn declare_key(map: &mut satd_psbt::raw::RawMap, pubkey: &PublicKey) {
    if map
        .get(keys::input::BIP32_DERIVATION, &pubkey.serialize())
        .is_some()
    {
        return;
    }
    map.set(RawPair::new(
        keys::input::BIP32_DERIVATION,
        pubkey.serialize().to_vec(),
        // A zero master fingerprint and no path: this key came from a WIF,
        // not from a seed.
        vec![0u8; 4],
    ));
}

/// Write the ECDH shares and proofs this signer can produce, and — once every
/// eligible input is covered — the output scripts and the frozen
/// `TX_MODIFIABLE`. Returns the eligible inputs that still owe a share.
fn fill_silent_payments(
    secp: &Secp256k1<All>,
    raw: &mut RawPsbt,
    key_map: &HashMap<PublicKey, SecretKey>,
    xonly_key_map: &HashMap<XOnlyPublicKey, SecretKey>,
) -> Result<Vec<usize>, String> {
    let (held, scan_keys, eligible) = {
        let view = V2View::new(raw).map_err(|e| e.to_string())?;
        let report = sp::verify(&view, None).map_err(|e| e.to_string())?;
        let held = held_inputs(secp, &view, &report, key_map, xonly_key_map)?;
        (
            held,
            view.sp_scan_keys().map_err(|e| e.to_string())?,
            report.eligible_inputs(),
        )
    };

    // A signer that holds none of the eligible inputs has nothing to
    // contribute. That is a normal state, not an error: it reports what is
    // still owed and the PSBT goes to whoever holds the rest.
    let holds_every_eligible =
        !held.is_empty() && eligible.iter().all(|i| held.iter().any(|h| h.index == *i));

    for scan_key in &scan_keys {
        if held.is_empty() {
            break;
        }
        // A global share stands for the whole eligible set at once, so it can
        // only be written by a signer that holds the whole eligible set.
        // Otherwise each input gets its own, which is what lets two signers
        // between them cover a transaction neither could alone.
        if holds_every_eligible && !any_input_share(raw, scan_key) {
            if raw
                .global
                .get(keys::global::SP_ECDH_SHARE, &scan_key.serialize())
                .is_some()
            {
                continue;
            }
            // BIP 352 sums the contributing secrets, and an intermediate
            // sum of zero is legal while a final one is not — a transaction
            // whose input keys cancel cannot carry a silent payment at all.
            let secret_sum = sp::sum_secret_keys(held.iter().map(|h| h.secret))
                .ok_or("the input secrets sum to zero, so this transaction cannot carry a \
                        silent payment")?;
            let (share, proof) = share_and_proof(secp, &secret_sum, scan_key)?;
            raw.global.set(RawPair::new(
                keys::global::SP_ECDH_SHARE,
                scan_key.serialize().to_vec(),
                share,
            ));
            raw.global.set(RawPair::new(
                keys::global::SP_DLEQ,
                scan_key.serialize().to_vec(),
                proof,
            ));
        } else {
            for input in &held {
                if raw.inputs[input.index]
                    .get(keys::input::SP_ECDH_SHARE, &scan_key.serialize())
                    .is_some()
                {
                    continue;
                }
                let (share, proof) = share_and_proof(secp, &input.secret, scan_key)?;
                raw.inputs[input.index].set(RawPair::new(
                    keys::input::SP_ECDH_SHARE,
                    scan_key.serialize().to_vec(),
                    share,
                ));
                raw.inputs[input.index].set(RawPair::new(
                    keys::input::SP_DLEQ,
                    scan_key.serialize().to_vec(),
                    proof,
                ));
            }
        }
    }

    // Now check the whole thing, this signer's own contributions included.
    // Verifying what we just wrote is not circular: the shares came from
    // secrets and the check runs on the proofs, so a mistake in either shows
    // up here rather than on chain.
    let view = V2View::new(raw).map_err(|e| e.to_string())?;
    let report = sp::verify(&view, None).map_err(|e| e.to_string())?;

    let mut owing: Vec<usize> = Vec::new();
    for output in &report.outputs {
        match output.status {
            OutputStatus::Ready | OutputStatus::MissingShares => {}
            status => {
                return Err(format!(
                    "output {} cannot be completed: {}{}",
                    output.index,
                    status.as_str(),
                    output
                        .reason
                        .as_ref()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                ));
            }
        }
        for index in &output.missing_inputs {
            if !owing.contains(index) {
                owing.push(*index);
            }
        }
    }
    if !owing.is_empty() {
        owing.sort_unstable();
        return Ok(owing);
    }

    // Every eligible input is covered, so the transaction is determined and
    // the scripts can be written. Writing them is what freezes it, which is
    // why `TX_MODIFIABLE` goes to zero in the same breath.
    let scripts: Vec<(usize, Vec<u8>)> = report
        .outputs
        .iter()
        .filter_map(|o| {
            o.derived_script
                .as_ref()
                .map(|s| (o.index, s.to_bytes()))
        })
        .collect();
    if scripts.len() != report.outputs.len() {
        return Err("a silent payment output script could not be derived".to_string());
    }
    for (index, script) in scripts {
        raw.outputs[index].set(RawPair::new(keys::output::SCRIPT, Vec::new(), script));
    }
    raw.global.set(RawPair::new(
        keys::global::TX_MODIFIABLE,
        Vec::new(),
        vec![0u8],
    ));

    // And the finished article has to pass the same check the node will run.
    let view = V2View::new(raw).map_err(|e| e.to_string())?;
    let report = sp::verify(&view, None).map_err(|e| e.to_string())?;
    if let Some(problem) = report.first_problem() {
        return Err(format!(
            "this signer produced a PSBT its own verifier rejects: output {} is {} with script {}",
            problem.index,
            problem.status.as_str(),
            problem.script_state.as_str()
        ));
    }
    debug_assert!(report.outputs.iter().all(|o| o.script_state == ScriptState::Matches));
    Ok(Vec::new())
}

/// `a·B_scan` and a BIP 374 proof of it.
///
/// The auxiliary randomness is 32 fresh bytes from the operating system for
/// every proof. BIP 374 takes the same line as BIP 340: reusing it across two
/// proofs for the same key and different messages can leak the secret.
fn share_and_proof(
    secp: &Secp256k1<All>,
    secret: &SecretKey,
    scan_key: &PublicKey,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut aux = [0u8; 32];
    bitcoin::secp256k1::rand::rngs::OsRng.fill_bytes(&mut aux);

    let share = scan_key
        .mul_tweak(
            secp,
            &Scalar::from_be_bytes(secret.secret_bytes())
                .map_err(|_| "the input secret is not a scalar".to_string())?,
        )
        .map_err(|_| "a·B_scan is not a point".to_string())?;
    let proof = satd_psbt::dleq::generate_proof(secret, scan_key, &aux, None)
        .map_err(|e| format!("could not prove the ECDH share: {e}"))?;
    aux.fill(0);
    Ok((share.serialize().to_vec(), proof.to_vec()))
}

/// Whether any input already carries a per-input share for this scan key.
///
/// If one does, another signer has chosen the per-input form, and a global
/// share on top would claim to cover inputs this signer does not hold.
fn any_input_share(raw: &RawPsbt, scan_key: &PublicKey) -> bool {
    raw.inputs
        .iter()
        .any(|m| m.get(keys::input::SP_ECDH_SHARE, &scan_key.serialize()).is_some())
}

/// The eligible inputs this signer holds a key for, with the secret that
/// contributes to the shared secret.
///
/// For a taproot input BIP 352 contributes the **output** key, and the
/// receiver assumes its even-Y lift, so the secret is negated when the key has
/// odd Y. Getting that backwards produces outputs the recipient never finds
/// and nothing on chain looks wrong.
fn held_inputs(
    secp: &Secp256k1<All>,
    view: &V2View<'_>,
    report: &sp::SpReport,
    key_map: &HashMap<PublicKey, SecretKey>,
    xonly_key_map: &HashMap<XOnlyPublicKey, SecretKey>,
) -> Result<Vec<Held>, String> {
    let mut out = Vec::new();
    for input in &report.inputs {
        if !input.eligible() {
            continue;
        }
        let Some(public_key) = input.public_key else {
            continue;
        };
        let Some(prevout) = &input.prevout else {
            continue;
        };
        let _ = view;

        let secret = if prevout.script_pubkey.is_p2tr() {
            let output_key = public_key.x_only_public_key().0;
            // Two readings, in the order the version 0 signer tries them: a
            // BIP 341/86 internal key with the taproot tweak applied, then the
            // output key itself, which is the shape a silent payment output
            // spent onwards has.
            let mut found = None;
            for (xonly, secret) in xonly_key_map {
                let keypair = Keypair::from_secret_key(secp, secret);
                let tweaked = keypair.tap_tweak(secp, None);
                if tweaked.to_keypair().x_only_public_key().0 == output_key {
                    found = Some(tweaked.to_keypair().secret_key());
                    break;
                }
                if *xonly == output_key {
                    found = Some(*secret);
                    break;
                }
            }
            match found {
                Some(secret) => secret,
                None => continue,
            }
        } else {
            match key_map.get(&public_key) {
                Some(secret) => *secret,
                None => continue,
            }
        };

        // The contributing key is `public_key`, which the verifier bound to
        // the previous output. Make the secret agree with it.
        let secret = if secret.public_key(secp) == public_key {
            secret
        } else {
            secret.negate()
        };
        if secret.public_key(secp) != public_key {
            return Err(format!(
                "input {}: the key this signer holds does not match the one bound to the \
                 previous output",
                input.index
            ));
        }

        out.push(Held {
            index: input.index,
            secret,
        });
    }
    Ok(out)
}

/// Sign every input, through the version 0 signer.
///
/// A version 2 PSBT whose outputs all have scripts describes exactly one
/// transaction, so the sighashes are the version 0 ones and there is no reason
/// for a second signing implementation. The signatures are written back into
/// the raw maps, leaving everything else where it was.
fn sign_inputs(
    secp: &Secp256k1<All>,
    raw: &mut RawPsbt,
    wif_keys: &[bitcoin::PrivateKey],
    xprivs: &[bitcoin::bip32::Xpriv],
    gap: u32,
) -> Result<SignSummary, String> {
    let _ = secp;
    let mut v0 = {
        let view = V2View::new(raw).map_err(|e| e.to_string())?;
        view.to_v0().map_err(|e| e.to_string())?
    };
    crate::sign::sign_psbt(&mut v0, wif_keys, xprivs, gap);

    for (index, input) in v0.inputs.iter().enumerate() {
        for (pubkey, sig) in &input.partial_sigs {
            raw.inputs[index].set(RawPair::new(
                keys::input::PARTIAL_SIG,
                pubkey.to_bytes(),
                sig.serialize().to_vec(),
            ));
        }
        if let Some(sig) = &input.tap_key_sig {
            raw.inputs[index].set(RawPair::new(
                keys::input::TAP_KEY_SIG,
                Vec::new(),
                sig.serialize().to_vec(),
            ));
        }
        // The finalizer needs the redeem script to assemble a nested spend's
        // scriptSig, and the version 0 signer writes it when it signs one.
        if let Some(redeem) = &input.redeem_script
            && !raw.inputs[index].contains_type(keys::input::REDEEM_SCRIPT)
        {
            raw.inputs[index].set(RawPair::new(
                keys::input::REDEEM_SCRIPT,
                Vec::new(),
                redeem.to_bytes(),
            ));
        }
    }

    crate::sign::summarize_v2(raw)
}

/// Report a version 2 signing run the way the version 0 path reports its own,
/// with the silent payment state appended.
pub fn describe(summary: &SignV2Summary) -> Vec<String> {
    let mut lines: Vec<String> = summary
        .inner
        .per_input
        .iter()
        .enumerate()
        .map(|(i, outcome)| format!("input {i}: {}", outcome.as_str()))
        .collect();
    if !summary.owing_shares.is_empty() {
        lines.push(format!(
            "silent payments: inputs {:?} still owe an ECDH share; the PSBT needs another \
             signer before any input can be signed",
            summary.owing_shares
        ));
    } else if !summary.outputs_complete {
        lines.push(
            "silent payments: an output script is still missing, so nothing was signed"
                .to_string(),
        );
    } else {
        lines.push("silent payments: every output script computed and verified".to_string());
    }
    lines
}
