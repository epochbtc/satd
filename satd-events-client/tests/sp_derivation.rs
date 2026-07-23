//! BIP 352 receiver-derivation round-trip.
//!
//! The `sp_wallet.rs` / `sp_light_scan.rs` examples are the reference a wallet
//! developer copies to turn a `SilentPaymentMatched` (or a tweak) into a
//! *spendable* key. A wrong formula there silently yields unspendable outputs,
//! so this test independently plays the **sender** side of BIP 352 to build the
//! output, then reproduces the **receiver** derivation the examples use and
//! asserts the derived private key actually controls that output — for both an
//! unlabelled output and a labelled (change, `m = 0`) output, the case the
//! CRITICAL review finding was about.
//!
//! Sender and receiver are genuinely different computations (the sender never
//! knows `b_scan`; it pays the receiver's published `B_spend [+ label·G]`), so
//! their agreement is a real check, not a tautology.

#![cfg(feature = "bitcoin")]

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// BIP 340 tagged hash — identical to the helper both examples use.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine, sha256};
    let th = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(th.as_ref());
    eng.input(th.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// The receiver derivation the examples perform: `d = b_spend + t_k [+ label_m]`.
fn receiver_spend_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    b_scan: &SecretKey,
    b_spend: &SecretKey,
    tweak_t: &PublicKey,
    k: u32,
    label: Option<u32>,
) -> SecretKey {
    let ecdh = tweak_t
        .mul_tweak(secp, &Scalar::from_be_bytes(b_scan.secret_bytes()).unwrap())
        .unwrap();
    let mut msg = ecdh.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = tagged_hash(b"BIP0352/SharedSecret", &msg);
    let mut d = b_spend.add_tweak(&Scalar::from_be_bytes(t_k).unwrap()).unwrap();
    if let Some(m) = label {
        let mut lbuf = b_scan.secret_bytes().to_vec();
        lbuf.extend_from_slice(&m.to_be_bytes());
        let label_m = tagged_hash(b"BIP0352/Label", &lbuf);
        d = d.add_tweak(&Scalar::from_be_bytes(label_m).unwrap()).unwrap();
    }
    d
}

/// Play the sender: given the public tweak `T` the node emits and the receiver's
/// published spend point `B_pub` (which already folds in the label point for a
/// labelled address), the output key is `P = B_pub + t_k·G`. The sender computes
/// `t_k` from its own ECDH `e·B_scan`, which must equal the receiver's `b_scan·T`.
fn sender_output_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    e: &SecretKey,       // ephemeral input scalar; T = e·G
    b_scan_pub: &PublicKey,
    b_pub: &PublicKey,   // receiver's B_spend (+ label·G for a labelled address)
    k: u32,
) -> [u8; 32] {
    let ecdh = b_scan_pub
        .mul_tweak(secp, &Scalar::from_be_bytes(e.secret_bytes()).unwrap())
        .unwrap();
    let mut msg = ecdh.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = Scalar::from_be_bytes(tagged_hash(b"BIP0352/SharedSecret", &msg)).unwrap();
    let p = b_pub.add_exp_tweak(secp, &t_k).unwrap();
    p.x_only_public_key().0.serialize()
}

fn xonly(secp: &Secp256k1<bitcoin::secp256k1::All>, sk: &SecretKey) -> [u8; 32] {
    PublicKey::from_secret_key(secp, sk).x_only_public_key().0.serialize()
}

#[test]
fn unlabelled_output_round_trips() {
    let secp = Secp256k1::new();
    let b_scan = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let b_spend = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let e = SecretKey::from_slice(&[0x33; 32]).unwrap();

    let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
    let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);
    // The public tweak the node would emit for this transaction: T = e·G.
    let tweak_t = PublicKey::from_secret_key(&secp, &e);

    for k in 0..3u32 {
        let output = sender_output_key(&secp, &e, &b_scan_pub, &b_spend_pub, k);
        let d = receiver_spend_key(&secp, &b_scan, &b_spend, &tweak_t, k, None);
        assert_eq!(xonly(&secp, &d), output, "unlabelled derived key must control the output (k={k})");
    }
}

#[test]
fn labelled_change_output_round_trips() {
    // The CRITICAL case: a labelled (m = 0, change) address. The receiver
    // publishes B_m = B_spend + label_m·G; the derived spend key must fold the
    // label tweak back in, or the change is unspendable.
    let secp = Secp256k1::new();
    let b_scan = SecretKey::from_slice(&[0xAB; 32]).unwrap();
    let b_spend = SecretKey::from_slice(&[0xCD; 32]).unwrap();
    let e = SecretKey::from_slice(&[0xEF; 32]).unwrap();
    let m = 0u32;

    let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
    let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);
    let tweak_t = PublicKey::from_secret_key(&secp, &e);

    // Receiver's published labelled spend point B_m = B_spend + label_m·G.
    let mut lbuf = b_scan.secret_bytes().to_vec();
    lbuf.extend_from_slice(&m.to_be_bytes());
    let label_m = Scalar::from_be_bytes(tagged_hash(b"BIP0352/Label", &lbuf)).unwrap();
    let b_m = b_spend_pub.add_exp_tweak(&secp, &label_m).unwrap();

    for k in 0..3u32 {
        let output = sender_output_key(&secp, &e, &b_scan_pub, &b_m, k);
        let d = receiver_spend_key(&secp, &b_scan, &b_spend, &tweak_t, k, Some(m));
        assert_eq!(
            xonly(&secp, &d),
            output,
            "labelled derived key must control the change output (k={k})",
        );

        // And the omission that caused the finding must FAIL: deriving without
        // the label tweak yields a key that does not control the labelled output.
        let d_no_label = receiver_spend_key(&secp, &b_scan, &b_spend, &tweak_t, k, None);
        assert_ne!(
            xonly(&secp, &d_no_label),
            output,
            "omitting the label tweak must NOT control a labelled output (k={k})",
        );
    }
}
