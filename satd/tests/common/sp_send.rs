//! A BIP 352 **sender**, for tests only.
//!
//! satd has no silent-payment send support and is not getting any before the
//! BIP 375 work; the node only ever *scans*. That left a hole: `node-sp-index`
//! is covered against the BIP 352 vectors on the receiving side, and both SDKs
//! implement scanning, but nothing anywhere constructs a real silent-payment
//! payment. The live path — node index → watch matcher → SDK decode — had
//! therefore never run end to end, and no test produced a genuine
//! `SilentPaymentMatched`.
//!
//! This is the missing half. It derives the taproot output keys that pay a set
//! of silent-payment recipients, so an E2E test can build, sign, and broadcast a
//! transaction the node's scanner is supposed to match.
//!
//! # Why this does not reuse `node-sp-index`
//!
//! Every primitive here — the tagged hash, the outpoint serialization, the
//! shared-secret derivation — is reimplemented rather than borrowed. That is
//! deliberate. `node-sp-index`'s helpers are private, but more to the point, a
//! sender built from the receiver's own internals proves only that the two agree
//! with each other. The referee is [`bip352_sending_vectors`], which checks this
//! code against the vendored BIP 352 `send_and_receive_test_vectors.json`
//! **sending** cases. Agreement with the spec is the bar; agreement with our
//! receiver is what the E2E test then goes on to demonstrate.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::OutPoint;

const TAG_INPUTS: &[u8] = b"BIP0352/Inputs";
const TAG_SHARED_SECRET: &[u8] = b"BIP0352/SharedSecret";

/// BIP 340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag).to_byte_array();
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&t);
    buf.extend_from_slice(&t);
    buf.extend_from_slice(msg);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// `txid[32] LE || vout[4] LE`, matching the reference `COutPoint.serialize()`.
fn ser_outpoint(op: &OutPoint) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(op)
}

/// The secp256k1 group order `n`, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn to_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for (i, limb) in l.iter_mut().enumerate() {
        *limb = u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    l
}

fn from_limbs(l: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in l.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// `(a + b) mod n` over 32-byte big-endian scalars.
///
/// Summing input private keys cannot go through `SecretKey::add_tweak`: that
/// rejects an intermediate sum of zero, and BIP 352 only cares whether the
/// **final** sum is zero. A vector with three inputs whose first two cancel is
/// legal and must still send — `PublicKey::combine_keys` tolerates exactly this
/// on the receiving side, and the sender has to match.
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (x, y) = (to_limbs(a), to_limbs(b));
    let mut sum = [0u64; 4];
    let mut carry = 0u128;
    for i in (0..4).rev() {
        let t = x[i] as u128 + y[i] as u128 + carry;
        sum[i] = t as u64;
        carry = t >> 64;
    }
    // Reduce if the sum overflowed 256 bits or landed at/above n.
    let n = to_limbs(&CURVE_ORDER);
    let ge_n = carry > 0 || {
        let mut ge = true;
        for i in 0..4 {
            if sum[i] != n[i] {
                ge = sum[i] > n[i];
                break;
            }
        }
        ge
    };
    if ge_n {
        let mut borrow = 0i128;
        for i in (0..4).rev() {
            let t = sum[i] as i128 - n[i] as i128 - borrow;
            if t < 0 {
                sum[i] = (t + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                sum[i] = t as u64;
                borrow = 0;
            }
        }
    }
    from_limbs(&sum)
}

/// `scalar_add_mod_n`, exposed for its own edge-case test. Not part of the
/// sender's interface — the sending vectors exercise it only incidentally, and
/// hand-rolled modular arithmetic deserves its wrap-around pinned directly.
pub fn scalar_add_mod_n_for_test(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    scalar_add_mod_n(a, b)
}

/// One silent-payment recipient, as the two public keys its address encodes.
///
/// The address form (`sp1...`, bech32m) is deliberately not handled: the watch
/// API keys on `(scan, spend)` directly, and adding an address codec here would
/// be a second thing to get wrong for no test coverage gained.
#[derive(Debug, Clone, Copy)]
pub struct SpRecipient {
    /// `B_scan` — the recipient's scan public key.
    pub scan_pubkey: PublicKey,
    /// `B_spend` — the recipient's spend public key.
    pub spend_pubkey: PublicKey,
}

/// One input the sender controls: the outpoint it spends and the private key
/// that authorizes it.
#[derive(Debug, Clone, Copy)]
pub struct SpInput {
    /// The outpoint being spent.
    pub outpoint: OutPoint,
    /// The private key for this input's prevout.
    pub secret: SecretKey,
    /// Whether the prevout is P2TR. BIP 352 requires the *even-Y* private key
    /// for taproot inputs, so an odd-parity key is negated before summing;
    /// getting this wrong silently produces outputs the recipient never finds.
    pub is_taproot: bool,
}

/// Derive the taproot output keys paying `recipients`.
///
/// `inputs` must list **every** input of the transaction that contributes a key
/// (the eligible set), and `all_outpoints` **every** input's outpoint including
/// ineligible ones — `input_hash` is keyed on the lexicographically smallest
/// outpoint over all of them, per the reference implementation. Passing only the
/// eligible outpoints produces a valid-looking but unmatchable output whenever
/// the smallest outpoint belongs to an ineligible input.
///
/// Recipients sharing a `scan_pubkey` are numbered `k = 0, 1, ...` within that
/// group, so paying one recipient twice yields two distinct outputs. The result
/// is in `recipients` order.
///
/// Returns `None` when the transaction cannot carry a silent payment at all —
/// the input private keys sum to zero (the point at infinity), or `input_hash`
/// is not a usable scalar. BIP 352 says such a transaction sends nothing, and
/// the receiver's [`compute_tweak`](node_sp_index::compute_tweak) returns `None`
/// on the same conditions. Panicking here instead would turn a legitimate
/// "cannot send" into a test crash.
pub fn sp_outputs(
    secp: &Secp256k1<All>,
    inputs: &[SpInput],
    all_outpoints: &[OutPoint],
    recipients: &[SpRecipient],
) -> Option<Vec<XOnlyPublicKey>> {
    assert!(!inputs.is_empty(), "silent payments need at least one contributing input");
    assert!(
        !all_outpoints.is_empty(),
        "all_outpoints must list every input's outpoint, not just the eligible ones"
    );

    // a_sum: the sum of the (parity-corrected) input private keys, accumulated
    // mod n so an intermediate zero is not mistaken for "cannot send".
    let mut acc = [0u8; 32];
    for inp in inputs {
        let sk = if inp.is_taproot
            && inp.secret.public_key(secp).x_only_public_key().1
                == bitcoin::secp256k1::Parity::Odd
        {
            inp.secret.negate()
        } else {
            inp.secret
        };
        acc = scalar_add_mod_n(&acc, &sk.secret_bytes());
    }
    // A zero final sum IS the point-at-infinity case: this transaction sends
    // nothing (BIP 352 fact 4), and `SecretKey::from_slice` rejects it for us.
    let a_sum = SecretKey::from_slice(&acc).ok()?;
    let a_sum_pub = a_sum.public_key(secp);

    // input_hash = tagged_hash("BIP0352/Inputs", outpoint_L || A_sum)
    let lowest = all_outpoints
        .iter()
        .min_by(|a, b| ser_outpoint(a).cmp(&ser_outpoint(b)))
        .expect("non-empty");
    let mut msg = ser_outpoint(lowest);
    msg.extend_from_slice(&a_sum_pub.serialize());
    let input_hash = tagged_hash(TAG_INPUTS, &msg);

    // The scalar the recipient's scan key is multiplied by: input_hash · a_sum.
    let shared_scalar =
        a_sum.mul_tweak(&Scalar::from_be_bytes(input_hash).ok()?).ok()?;

    // k counts per scan key, not globally.
    let mut k_by_scan: std::collections::HashMap<[u8; 33], u32> = Default::default();
    let mut out = Vec::with_capacity(recipients.len());
    for r in recipients {
        let ecdh = r
            .scan_pubkey
            .mul_tweak(secp, &Scalar::from_be_bytes(shared_scalar.secret_bytes()).ok()?)
            .ok()?;

        let k = k_by_scan.entry(r.scan_pubkey.serialize()).or_insert(0);
        let mut buf = ecdh.serialize().to_vec();
        buf.extend_from_slice(&k.to_be_bytes());
        *k += 1;

        let t_k = tagged_hash(TAG_SHARED_SECRET, &buf);
        let t_k_sk = SecretKey::from_slice(&t_k).ok()?;
        let p_k = r.spend_pubkey.combine(&t_k_sk.public_key(secp)).ok()?;
        out.push(p_k.x_only_public_key().0);
    }
    Some(out)
}

/// `scan_secret` → the `B_scan` the watch API is registered with.
pub fn scan_pubkey_of(secp: &Secp256k1<All>, scan_secret: &SecretKey) -> PublicKey {
    scan_secret.public_key(secp)
}
