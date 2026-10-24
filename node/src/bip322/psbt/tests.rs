//! The PSBT creator and finalizer. Test signers fill in partial signatures
//! as a hardware signer would: each signs its own copy, and the copies are
//! combined before finalizing, as a coordinator does.

use bitcoin::hashes::Hash as _;
use bitcoin::key::{Keypair, TapTweak as _};
use bitcoin::opcodes::all::*;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PublicKey, ScriptBuf, Sequence, TxIn, TxOut, Witness,
};

use super::*;
use crate::bip322::{Proof, Verification, verify};

const MESSAGE: &[u8] = b"NAP attestation v1\nkey: k\nvalue: v";

fn secret(n: u8) -> SecretKey {
    SecretKey::from_slice(&[n; 32]).unwrap()
}

fn public(n: u8) -> PublicKey {
    PublicKey::new(secret(n).public_key(&Secp256k1::new()))
}

fn ecdsa(sighash: [u8; 32], n: u8) -> bitcoin::ecdsa::Signature {
    let signature = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash), &secret(n));
    bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All }
}

fn schnorr(sighash: [u8; 32], keypair: &Keypair) -> bitcoin::taproot::Signature {
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(sighash), keypair);
    bitcoin::taproot::Signature { signature, sighash_type: TapSighashType::Default }
}

fn keypair(n: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &secret(n))
}

fn serialize(psbt: &Psbt) -> Vec<u8> {
    psbt.serialize()
}

/// Finalize `psbt` and check that the proof verifies for `challenge`.
fn finalize_valid(psbt: &Psbt, challenge: &ScriptBuf) -> Proof {
    let done = finalize(&serialize(psbt)).unwrap();
    assert_eq!(done.message, MESSAGE);
    assert_eq!(&done.challenge, challenge);
    let verdict = verify(challenge, MESSAGE, &done.proof);
    assert!(matches!(verdict, Verification::Valid { .. }), "{verdict:?}");
    done.proof
}

fn p2wsh_2_of_3() -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_key(&public(11))
        .push_key(&public(12))
        .push_key(&public(13))
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

/// `n`'s partial signature for a P2WSH input under `ws`.
fn sign_p2wsh(psbt: &Psbt, ws: &ScriptBuf, n: u8) -> Psbt {
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wsh_signature_hash(0, ws, Amount::ZERO, EcdsaSighashType::All)
        .unwrap()
        .to_byte_array();
    let mut signed = psbt.clone();
    signed.inputs[0].partial_sigs.insert(public(n), ecdsa(sighash, n));
    signed
}

/// A P2WSH 2-of-3 PSBT, with the witness script the coordinator adds.
fn p2wsh_psbt() -> (Psbt, ScriptBuf, ScriptBuf) {
    let ws = p2wsh_2_of_3();
    let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let mut psbt = create(&spk, MESSAGE);
    psbt.inputs[0].witness_script = Some(ws.clone());
    (psbt, spk, ws)
}

#[test]
fn create_sets_the_fields_the_bip_names() {
    let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public(1).inner).wpubkey_hash());
    let psbt = create(&spk, MESSAGE);
    let spend = to_spend(&spk, MESSAGE);
    assert_eq!(psbt.version, 0);
    assert_eq!(psbt.unsigned_tx, to_sign(spend.compute_txid(), Witness::new()));
    assert_eq!(psbt.inputs[0].witness_utxo.as_ref(), Some(&spend.output[0]));
    assert_eq!(psbt.inputs[0].non_witness_utxo.as_ref(), Some(&spend));
    let key = raw::Key { type_value: 0x09, key: vec![] };
    assert_eq!(psbt.unknown.get(&key).map(Vec::as_slice), Some(MESSAGE));

    // The field survives serialization, as a signer returns it.
    let bytes = serialize(&psbt);
    assert!(is_psbt(&bytes));
    assert_eq!(Psbt::deserialize(&bytes).unwrap().unknown.get(&key).map(Vec::as_slice), Some(MESSAGE));
}

#[test]
fn p2wsh_2_of_3_signed_by_two_signers_finalizes_to_simple() {
    let (psbt, spk, ws) = p2wsh_psbt();
    let mut combined = sign_p2wsh(&psbt, &ws, 11);
    combined.combine(sign_p2wsh(&psbt, &ws, 13)).unwrap();
    let proof = finalize_valid(&combined, &spk);
    assert!(matches!(&proof, Proof::Simple(w) if w.len() == 4), "{proof:?}");
}

#[test]
fn one_signature_of_two_is_incomplete() {
    let (psbt, _, ws) = p2wsh_psbt();
    let err = finalize(&serialize(&sign_p2wsh(&psbt, &ws, 12))).unwrap_err();
    assert!(matches!(err, PsbtError::Incomplete(_)), "{err}");
}

#[test]
fn multisig_without_the_witness_script_is_incomplete() {
    let (psbt, _, ws) = p2wsh_psbt();
    let mut combined = sign_p2wsh(&psbt, &ws, 11);
    combined.combine(sign_p2wsh(&psbt, &ws, 12)).unwrap();
    combined.inputs[0].witness_script = None;
    let err = finalize(&serialize(&combined)).unwrap_err();
    assert!(matches!(err, PsbtError::Incomplete(_)), "{err}");
}

#[test]
fn tapscript_leaf_signed_by_two_signers_finalizes_to_simple() {
    let secp = Secp256k1::new();
    let (a, b) = (keypair(21), keypair(22));
    // multi_a(2, A, B)
    let leaf = Builder::new()
        .push_x_only_key(&a.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&b.x_only_public_key().0)
        .push_opcode(OP_CHECKSIGADD)
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_NUMEQUAL)
        .into_script();
    let internal = keypair(23).x_only_public_key().0;
    let info = TaprootBuilder::new().add_leaf(0, leaf.clone()).unwrap().finalize(&secp, internal).unwrap();
    let control = info.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());

    let mut psbt = create(&spk, MESSAGE);
    psbt.inputs[0].tap_internal_key = Some(internal);
    psbt.inputs[0].tap_merkle_root = info.merkle_root();
    psbt.inputs[0].tap_scripts.insert(control, (leaf.clone(), LeafVersion::TapScript));
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::Default)
        .unwrap()
        .to_byte_array();
    let sign = |k: &Keypair| {
        let mut signed = psbt.clone();
        signed.inputs[0].tap_script_sigs.insert((k.x_only_public_key().0, leaf_hash), schnorr(sighash, k));
        signed
    };
    let mut combined = sign(&a);
    combined.combine(sign(&b)).unwrap();
    let proof = finalize_valid(&combined, &spk);
    assert!(matches!(&proof, Proof::Simple(w) if w.len() == 4), "{proof:?}");

    let err = finalize(&serialize(&sign(&a))).unwrap_err();
    assert!(matches!(err, PsbtError::Incomplete(_)), "{err}");
}

#[test]
fn p2wpkh_finalizes_to_simple() {
    let pk = CompressedPublicKey(public(1).inner);
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let mut psbt = create(&spk, MESSAGE);
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wpkh_signature_hash(0, &spk, Amount::ZERO, EcdsaSighashType::All)
        .unwrap()
        .to_byte_array();
    psbt.inputs[0].partial_sigs.insert(public(1), ecdsa(sighash, 1));
    assert!(matches!(finalize_valid(&psbt, &spk), Proof::Simple(_)));
}

#[test]
fn p2tr_key_path_finalizes_to_simple() {
    let secp = Secp256k1::new();
    let key = keypair(2);
    let spk = ScriptBuf::new_p2tr(&secp, key.x_only_public_key().0, None);
    let mut psbt = create(&spk, MESSAGE);
    let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap()
        .to_byte_array();
    let tweaked = key.tap_tweak(&secp, None).to_keypair();
    psbt.inputs[0].tap_key_sig = Some(schnorr(sighash, &tweaked));
    assert!(matches!(finalize_valid(&psbt, &spk), Proof::Simple(_)));
}

#[test]
fn p2sh_p2wpkh_and_p2pkh_finalize_to_full() {
    let pk = CompressedPublicKey(public(3).inner);
    let redeem = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
    let mut psbt = create(&spk, MESSAGE);
    psbt.inputs[0].redeem_script = Some(redeem.clone());
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wpkh_signature_hash(0, &redeem, Amount::ZERO, EcdsaSighashType::All)
        .unwrap()
        .to_byte_array();
    psbt.inputs[0].partial_sigs.insert(public(3), ecdsa(sighash, 3));
    assert!(matches!(finalize_valid(&psbt, &spk), Proof::Full(_)));

    let spk = ScriptBuf::new_p2pkh(&public(4).pubkey_hash());
    let mut psbt = create(&spk, MESSAGE);
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .legacy_signature_hash(0, &spk, EcdsaSighashType::All.to_u32())
        .unwrap()
        .to_byte_array();
    psbt.inputs[0].partial_sigs.insert(public(4), ecdsa(sighash, 4));
    assert!(matches!(finalize_valid(&psbt, &spk), Proof::Full(_)));
}

/// A coordinator that sets `to_sign`'s version, locktime or sequence makes
/// a full proof: a simple one stands for the default `to_sign`.
#[test]
fn a_non_default_to_sign_finalizes_to_full() {
    let (template, spk, ws) = p2wsh_psbt();
    let mut tx = template.unsigned_tx.clone();
    tx.version = Version::TWO;
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs = template.inputs.clone();
    psbt.unknown = template.unknown.clone();
    let mut combined = sign_p2wsh(&psbt, &ws, 11);
    combined.combine(sign_p2wsh(&psbt, &ws, 12)).unwrap();
    assert!(matches!(finalize_valid(&combined, &spk), Proof::Full(tx) if tx.version == Version::TWO));
}

#[test]
fn a_psbt_without_the_message_field_is_refused() {
    let (mut psbt, _, _) = p2wsh_psbt();
    psbt.unknown.clear();
    assert_eq!(finalize(&serialize(&psbt)), Err(PsbtError::NoMessage));
}

#[test]
fn a_psbt_whose_output_is_not_the_op_return_is_refused() {
    let (template, _, _) = p2wsh_psbt();
    let other = ScriptBuf::new_p2wsh(&p2wsh_2_of_3().wscript_hash());
    for output in [
        vec![TxOut { value: Amount::ZERO, script_pubkey: other }],
        vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new_op_return([]) }],
        vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return([1]) }],
        vec![template.unsigned_tx.output[0].clone(); 2],
    ] {
        let mut tx = template.unsigned_tx.clone();
        tx.output = output;
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs = template.inputs.clone();
        psbt.unknown = template.unknown.clone();
        assert_eq!(finalize(&serialize(&psbt)), Err(PsbtError::NotOpReturn));
    }
}

#[test]
fn a_proof_of_funds_psbt_is_refused() {
    let (template, _, _) = p2wsh_psbt();
    let mut tx = template.unsigned_tx.clone();
    tx.input.push(TxIn {
        previous_output: OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 7 },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0),
        witness: Witness::new(),
    });
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0] = template.inputs[0].clone();
    psbt.unknown = template.unknown.clone();
    assert_eq!(finalize(&serialize(&psbt)), Err(PsbtError::ExtraInputs(2)));
}

#[test]
fn input_fields_must_be_to_spends() {
    let (template, _, _) = p2wsh_psbt();

    // Another message's to_spend.
    let mut psbt = template.clone();
    psbt.unknown.insert(raw::Key { type_value: 0x09, key: vec![] }, b"another message".to_vec());
    assert!(matches!(finalize(&serialize(&psbt)), Err(PsbtError::NotToSpend(_))));

    // A witness_utxo with an amount: segwit signatures commit to it.
    let mut psbt = template.clone();
    psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
    psbt.inputs[0].non_witness_utxo = None;
    assert!(matches!(finalize(&serialize(&psbt)), Err(PsbtError::NotToSpend(_))));

    // A non_witness_utxo that is not to_spend.
    let mut psbt = template.clone();
    psbt.inputs[0].non_witness_utxo.as_mut().unwrap().lock_time = bitcoin::absolute::LockTime::from_consensus(1);
    assert!(matches!(finalize(&serialize(&psbt)), Err(PsbtError::NotToSpend(_))));

    // The right UTXO fields, but the input spends another output.
    let mut tx = template.unsigned_tx.clone();
    tx.input[0].previous_output.vout = 1;
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs = template.inputs.clone();
    psbt.unknown = template.unknown.clone();
    assert_eq!(finalize(&serialize(&psbt)), Err(PsbtError::NotToSpend("its prevout is not to_spend:0")));

    let mut psbt = template.clone();
    psbt.inputs[0].witness_utxo = None;
    psbt.inputs[0].non_witness_utxo = None;
    assert_eq!(finalize(&serialize(&psbt)), Err(PsbtError::NoUtxo));
}

/// With only `non_witness_utxo`, as the BIP allows, the challenge is
/// `to_spend`'s output.
#[test]
fn non_witness_utxo_alone_names_the_challenge() {
    let (psbt, spk, ws) = p2wsh_psbt();
    let mut combined = sign_p2wsh(&psbt, &ws, 11);
    combined.combine(sign_p2wsh(&psbt, &ws, 12)).unwrap();
    combined.inputs[0].witness_utxo = None;
    finalize_valid(&combined, &spk);
}

#[test]
fn garbage_is_not_a_psbt() {
    assert!(!is_psbt(b"\x02\x47\x30"));
    assert!(matches!(finalize(b"psbt\xff\x00"), Err(PsbtError::Decode(_))));
}

mod descriptors {
    use std::str::FromStr as _;

    use bitcoin::NetworkKind;
    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};

    use super::*;

    /// A test signer holding a master key, as a hardware signer does: it
    /// finds its keys through the PSBT's BIP 32 origins and nothing else.
    struct HwSigner {
        master: Xpriv,
    }

    impl HwSigner {
        fn new(seed: u8) -> Self {
            HwSigner { master: Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap() }
        }

        fn fingerprint(&self) -> Fingerprint {
            self.master.fingerprint(&Secp256k1::new())
        }

        /// `[fp/path]tpub` for the account at `path`.
        fn origin_xpub(&self, path: &str) -> String {
            let secp = Secp256k1::new();
            let account = self.master.derive_priv(&secp, &DerivationPath::from_str(path).unwrap()).unwrap();
            let xpub = Xpub::from_priv(&secp, &account);
            format!("[{}/{}]{xpub}", self.fingerprint(), path.trim_start_matches("m/"))
        }

        /// Sign every P2WSH key of ours the origins name.
        fn sign_p2wsh(&self, psbt: &mut Psbt) -> usize {
            let secp = Secp256k1::new();
            let ws = psbt.inputs[0].witness_script.clone().expect("the descriptor added the witness script");
            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .p2wsh_signature_hash(0, &ws, Amount::ZERO, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array();
            let mine: Vec<_> = psbt.inputs[0]
                .bip32_derivation
                .iter()
                .filter(|(_, (fp, _))| *fp == self.fingerprint())
                .map(|(pk, (_, path))| (*pk, path.clone()))
                .collect();
            for (pk, path) in &mine {
                let sk = self.master.derive_priv(&secp, path).unwrap().private_key;
                assert_eq!(sk.public_key(&secp), *pk);
                let signature = secp.sign_ecdsa(&Message::from_digest(sighash), &sk);
                psbt.inputs[0].partial_sigs.insert(
                    PublicKey::new(*pk),
                    bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All },
                );
            }
            mine.len()
        }

        /// Sign every tapscript key of ours the origins name.
        fn sign_tapscript(&self, psbt: &mut Psbt) -> usize {
            let secp = Secp256k1::new();
            let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
            let mine: Vec<_> = psbt.inputs[0]
                .tap_key_origins
                .iter()
                .filter(|(_, (_, (fp, _)))| *fp == self.fingerprint())
                .flat_map(|(xonly, (leaves, (_, path)))| leaves.iter().map(move |l| (*xonly, *l, path.clone())))
                .collect();
            for (xonly, leaf, path) in &mine {
                let sk = self.master.derive_priv(&secp, path).unwrap().private_key;
                let key = Keypair::from_secret_key(&secp, &sk);
                assert_eq!(key.x_only_public_key().0, *xonly);
                let sighash = SighashCache::new(&psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), *leaf, TapSighashType::Default)
                    .unwrap()
                    .to_byte_array();
                psbt.inputs[0].tap_script_sigs.insert((*xonly, *leaf), schnorr(sighash, &key));
            }
            mine.len()
        }
    }

    fn spk_of(descriptor: &str, index: u32) -> ScriptBuf {
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(descriptor)
            .unwrap()
            .at_derivation_index(index)
            .unwrap()
            .script_pubkey()
    }

    const ACCOUNT: &str = "m/48h/1h/0h/2h";

    fn multisig(signers: &[HwSigner], branch: &str) -> String {
        let keys: Vec<String> =
            signers.iter().map(|s| format!("{}/{branch}/*", s.origin_xpub(ACCOUNT))).collect();
        format!("wsh(sortedmulti(2,{}))", keys.join(","))
    }

    /// The case the hints are for: a 2-of-3 whose signers know nothing but
    /// their master keys. The coin is at index 3 of the receive branch.
    #[test]
    fn a_ranged_multisig_descriptor_lets_hardware_signers_sign() {
        let signers = [HwSigner::new(31), HwSigner::new(32), HwSigner::new(33)];
        let descriptor = multisig(&signers, "0");
        let spk = spk_of(&descriptor, 3);
        let mut psbt = create(&spk, MESSAGE);
        assert!(psbt.inputs[0].bip32_derivation.is_empty() && psbt.inputs[0].witness_script.is_none());

        add_descriptor(&mut psbt, &descriptor).unwrap();
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 3);
        let mut a = psbt.clone();
        let mut c = psbt.clone();
        assert_eq!(signers[0].sign_p2wsh(&mut a), 1);
        assert_eq!(signers[2].sign_p2wsh(&mut c), 1);
        a.combine(c).unwrap();
        assert!(matches!(finalize_valid(&a, &spk), Proof::Simple(_)));
    }

    /// A BIP 389 multipath descriptor, as wallets export it: the coin is on
    /// the change branch.
    #[test]
    fn each_branch_of_a_multipath_descriptor_is_searched() {
        let signers = [HwSigner::new(41), HwSigner::new(42)];
        let descriptor = multisig(&signers, "<0;1>");
        let change = multisig(&signers, "1");
        let spk = spk_of(&change, 7);
        let mut psbt = create(&spk, MESSAGE);
        add_descriptor(&mut psbt, &descriptor).unwrap();
        let mut a = psbt.clone();
        let mut b = psbt.clone();
        assert_eq!(signers[0].sign_p2wsh(&mut a) + signers[1].sign_p2wsh(&mut b), 2);
        a.combine(b).unwrap();
        finalize_valid(&a, &spk);

        let three = multisig(&signers, "<0;1;2>");
        assert_eq!(add_descriptor(&mut psbt, &three), Err(DescriptorError::TooManyBranches(3)));
    }

    #[test]
    fn a_taproot_descriptor_adds_the_leaves_and_origins() {
        let signers = [HwSigner::new(51), HwSigner::new(52)];
        let internal = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let descriptor = format!(
            "tr({internal},multi_a(2,{}/0/*,{}/0/*))",
            signers[0].origin_xpub(ACCOUNT),
            signers[1].origin_xpub(ACCOUNT)
        );
        let spk = spk_of(&descriptor, 0);
        let mut psbt = create(&spk, MESSAGE);
        add_descriptor(&mut psbt, &descriptor).unwrap();
        assert_eq!(psbt.inputs[0].tap_scripts.len(), 1);
        let mut a = psbt.clone();
        let mut b = psbt.clone();
        assert_eq!(signers[0].sign_tapscript(&mut a) + signers[1].sign_tapscript(&mut b), 2);
        a.combine(b).unwrap();
        assert!(matches!(finalize_valid(&a, &spk), Proof::Simple(_)));
    }

    #[test]
    fn a_fixed_single_key_descriptor_adds_its_origin() {
        let pk = public(1);
        let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk.inner).wpubkey_hash());
        let mut psbt = create(&spk, MESSAGE);
        add_descriptor(&mut psbt, &format!("wpkh([deadbeef/84h/1h/0h/0/5]{pk})")).unwrap();
        let (fp, path) = &psbt.inputs[0].bip32_derivation[&pk.inner];
        assert_eq!(fp.to_string(), "deadbeef");
        assert_eq!(path.to_string(), "84'/1'/0'/0/5");
    }

    #[test]
    fn unusable_descriptors_are_refused() {
        let signers = [HwSigner::new(61), HwSigner::new(62)];
        let spk = spk_of(&multisig(&signers, "0"), 0);
        let mut psbt = create(&spk, MESSAGE);
        let before = psbt.clone();

        // Another wallet's: nothing in range derives the coin.
        let other = multisig(&[HwSigner::new(63), HwSigner::new(64)], "0");
        assert_eq!(add_descriptor(&mut psbt, &other), Err(DescriptorError::NoMatch));
        // Beyond the search range.
        let far = spk_of(&multisig(&signers, "0"), DESCRIPTOR_SEARCH_RANGE);
        let mut far_psbt = create(&far, MESSAGE);
        assert_eq!(add_descriptor(&mut far_psbt, &multisig(&signers, "0")), Err(DescriptorError::NoMatch));

        // A public key cannot derive a hardened child, wherever the step is;
        // miniscript panics deriving one, so each is refused first.
        let xpub = signers[0].origin_xpub(ACCOUNT);
        for hardened in [
            format!("wpkh({xpub}/0/*h)"),
            format!("wpkh({xpub}/0h/*)"),
            format!("wpkh({xpub}/1h)"),
            format!("wpkh({xpub}/<0h;1>/*)"),
            format!("wsh(multi(1,{}/0/*,{xpub}/2h/*))", signers[1].origin_xpub(ACCOUNT)),
        ] {
            assert_eq!(add_descriptor(&mut psbt, &hardened), Err(DescriptorError::HardenedDerivation), "{hardened}");
        }

        // The node takes public descriptors only.
        let xprv = HwSigner::new(65).master.to_string();
        assert!(matches!(add_descriptor(&mut psbt, &format!("wpkh({xprv}/0/*)")), Err(DescriptorError::Parse(_))));
        assert!(matches!(add_descriptor(&mut psbt, "wsh(nonsense)"), Err(DescriptorError::Parse(_))));
        assert_eq!(psbt, before, "a refusal changes nothing");

        // Not a created PSBT: no input, or an input with no UTXO.
        let descriptor = multisig(&signers, "0");
        let mut empty = Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .unwrap();
        assert_eq!(add_descriptor(&mut empty, &descriptor), Err(DescriptorError::NoUtxo));
        let mut bare = create(&spk, MESSAGE);
        bare.inputs[0].witness_utxo = None;
        bare.inputs[0].non_witness_utxo.as_mut().unwrap().output.clear();
        assert_eq!(add_descriptor(&mut bare, &descriptor), Err(DescriptorError::NoUtxo));
        bare.inputs[0].non_witness_utxo = None;
        assert_eq!(add_descriptor(&mut bare, &descriptor), Err(DescriptorError::NoUtxo));
    }
}
