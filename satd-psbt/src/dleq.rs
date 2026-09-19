//! BIP 374: discrete logarithm equality proofs.
//!
//! A silent payment sender publishes `C = a·B_scan` for an input whose public
//! key is `A = a·G`, and must prove that both came from the same `a` without
//! revealing it. That proof is what lets satd — or a hardware wallet's host,
//! or any third party — check that an ECDH share in a PSBT really belongs to
//! the input it claims, rather than being a number that sends the recipient's
//! money somewhere they cannot spend it.
//!
//! The verifier is the part the node runs. `generate_proof` exists because
//! half the BIP's vectors are generation vectors, and because the tamper tests
//! need fresh proofs; the node never calls it.
//!
//! Two details of the specification are easy to get subtly wrong, and both
//! have a test of their own:
//!
//! - **`e` is not range-checked.** The BIP says `e = int(proof[0:32])` with no
//!   bound, and compares it against a hash output that is likewise unbounded.
//!   So `e` is reduced modulo the group order for the multiplication, and the
//!   *unreduced* 32 bytes are what the final comparison uses. Rejecting
//!   `e >= n` outright would be a deviation no honest prover ever triggers,
//!   which is exactly the kind that hides.
//! - **Infinity is a value, not an error.** `s = 0` makes `s·G` the point at
//!   infinity, and `e ≡ 0 (mod n)` does the same for `e·A`. The secp256k1 API
//!   reports both as errors because it has no infinity representation, so they
//!   are handled here as the `None` case rather than allowed to fail a proof
//!   that the specification accepts.

use std::sync::OnceLock;

use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};

/// The order of the secp256k1 group, big-endian.
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The secp256k1 generator, compressed.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn secp() -> &'static Secp256k1<All> {
    static CTX: OnceLock<Secp256k1<All>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::new)
}

/// The secp256k1 generator as a public key.
pub fn generator() -> PublicKey {
    static G: OnceLock<PublicKey> = OnceLock::new();
    *G.get_or_init(|| PublicKey::from_slice(&GENERATOR).expect("the generator is a valid point"))
}

/// Why a proof could not be generated. Verification has no error type: a proof
/// either verifies or it does not, and the distinction between "malformed" and
/// "wrong" is not one a verifier should act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DleqError {
    #[error("the secret is zero or not below the group order")]
    BadSecret,
    #[error("the nonce derived from the auxiliary randomness is zero")]
    ZeroNonce,
    #[error("the generated proof does not verify")]
    SelfCheckFailed,
}

/// BIP 374 `VerifyProof`, with the secp256k1 generator.
///
/// `a` is the public key of the secret used, `b` the public key it was
/// multiplied by, and `c` the claimed product. Returns whether the proof shows
/// that `a` and `c` came from the same scalar.
pub fn verify_proof(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &[u8; 64],
    message: Option<&[u8; 32]>,
) -> bool {
    verify_proof_with_generator(&generator(), a, b, c, proof, message)
}

/// BIP 374 `VerifyProof` over an arbitrary generator.
///
/// The generator is an input in BIP 374 so the algorithm can be used on other
/// curves; silent payments always use secp256k1's. The BIP's vectors exercise
/// other generators, which is the only reason this is public.
pub fn verify_proof_with_generator(
    g: &PublicKey,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &[u8; 64],
    message: Option<&[u8; 32]>,
) -> bool {
    let mut e_raw = [0u8; 32];
    e_raw.copy_from_slice(&proof[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&proof[32..]);

    // The BIP bounds `s` and does not bound `e`.
    if !is_below_order(&s) {
        return false;
    }
    let e = reduce(&e_raw);

    let Some(r1) = subtract(mul(g, &s), mul(a, &e)) else {
        return false;
    };
    let Some(r2) = subtract(mul(b, &s), mul(c, &e)) else {
        return false;
    };

    let expected = challenge(a, b, c, g, &r1, &r2, message);
    // Constant time is not a requirement here: everything compared is public.
    expected == e_raw
}

/// BIP 374 `GenerateProof`, with the secp256k1 generator.
///
/// Only tests and the client-side signer call this. The node holds no secrets
/// and so never proves anything; it only checks.
pub fn generate_proof(
    a: &SecretKey,
    b: &PublicKey,
    aux: &[u8; 32],
    message: Option<&[u8; 32]>,
) -> Result<[u8; 64], DleqError> {
    generate_proof_with_generator(&generator(), a, b, aux, message)
}

/// BIP 374 `GenerateProof` over an arbitrary generator.
pub fn generate_proof_with_generator(
    g: &PublicKey,
    a: &SecretKey,
    b: &PublicKey,
    aux: &[u8; 32],
    message: Option<&[u8; 32]>,
) -> Result<[u8; 64], DleqError> {
    let secp = secp();
    let a_scalar = Scalar::from_be_bytes(a.secret_bytes()).map_err(|_| DleqError::BadSecret)?;
    let big_a = g.mul_tweak(secp, &a_scalar).map_err(|_| DleqError::BadSecret)?;
    let big_c = b.mul_tweak(secp, &a_scalar).map_err(|_| DleqError::BadSecret)?;

    // t = bytes(32, a) XOR hash_BIP0374/aux(r), so that a proof built with
    // all-zero auxiliary randomness still differs between messages.
    let aux_hash = tagged_hash("BIP0374/aux", &[aux]);
    let mut t = a.secret_bytes();
    for (byte, mask) in t.iter_mut().zip(aux_hash.iter()) {
        *byte ^= mask;
    }

    let empty = [];
    let m: &[u8] = message.map(|m| &m[..]).unwrap_or(&empty);
    let rand = tagged_hash(
        "BIP0374/nonce",
        &[&t, &big_a.serialize(), &big_c.serialize(), m],
    );
    // Best-effort wipe of the value derived from the secret.
    t.fill(0);

    let k = reduce(&rand);
    if k == [0u8; 32] {
        return Err(DleqError::ZeroNonce);
    }
    let k_secret = SecretKey::from_slice(&k).map_err(|_| DleqError::ZeroNonce)?;
    let k_scalar = Scalar::from_be_bytes(k).map_err(|_| DleqError::ZeroNonce)?;
    let r1 = g.mul_tweak(secp, &k_scalar).map_err(|_| DleqError::ZeroNonce)?;
    let r2 = b.mul_tweak(secp, &k_scalar).map_err(|_| DleqError::ZeroNonce)?;

    let e = challenge(&big_a, b, &big_c, g, &r1, &r2, message);

    // s = (k + e·a) mod n. Done through the reduced `e` so that the
    // astronomically unlikely cases the specification permits — e ≡ 0, or a
    // sum of zero — produce the value the specification says rather than an
    // error the API happens to have.
    let e_reduced = reduce(&e);
    let s = if e_reduced == [0u8; 32] {
        k
    } else {
        let e_scalar = Scalar::from_be_bytes(e_reduced).map_err(|_| DleqError::BadSecret)?;
        // `mul_tweak` fails only on a zero product, impossible for a nonzero
        // secret and a nonzero scalar over a prime-order group.
        let ea = a.mul_tweak(&e_scalar).map_err(|_| DleqError::BadSecret)?;
        let ea_scalar =
            Scalar::from_be_bytes(ea.secret_bytes()).map_err(|_| DleqError::BadSecret)?;
        match k_secret.add_tweak(&ea_scalar) {
            Ok(sum) => sum.secret_bytes(),
            // The only way a sum of two valid scalars is rejected is that it
            // is zero modulo n, which the specification allows.
            Err(_) => [0u8; 32],
        }
    };

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&e);
    proof[32..].copy_from_slice(&s);

    // The BIP requires the prover to verify its own proof before returning it.
    if !verify_proof_with_generator(g, &big_a, b, &big_c, &proof, message) {
        return Err(DleqError::SelfCheckFailed);
    }
    Ok(proof)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn challenge(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
    message: Option<&[u8; 32]>,
) -> [u8; 32] {
    let empty = [];
    let m: &[u8] = message.map(|m| &m[..]).unwrap_or(&empty);
    tagged_hash(
        "BIP0374/challenge",
        &[
            &a.serialize(),
            &b.serialize(),
            &c.serialize(),
            &g.serialize(),
            &r1.serialize(),
            &r2.serialize(),
            m,
        ],
    )
}

/// `scalar · point`, with the point at infinity as `None`.
///
/// `scalar` must already be below the group order. A zero scalar gives
/// infinity, which the secp256k1 API cannot represent and so reports as an
/// error; here it is a value.
fn mul(point: &PublicKey, scalar: &[u8; 32]) -> Option<PublicKey> {
    if *scalar == [0u8; 32] {
        return None;
    }
    let tweak = Scalar::from_be_bytes(*scalar).ok()?;
    point.mul_tweak(secp(), &tweak).ok()
}

/// `a - b`, on points that may be at infinity. `None` out means infinity,
/// which every caller treats as a failed proof.
fn subtract(a: Option<PublicKey>, b: Option<PublicKey>) -> Option<PublicKey> {
    match (a, b) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b.negate(secp())),
        // `combine` reports the infinity case as an error; it has no other.
        (Some(a), Some(b)) => a.combine(&b.negate(secp())).ok(),
    }
}

/// Whether a big-endian 256-bit integer is strictly below the group order.
fn is_below_order(value: &[u8; 32]) -> bool {
    value[..] < GROUP_ORDER[..]
}

/// A big-endian 256-bit integer modulo the group order.
///
/// Any 256-bit value is below `2n`, so one conditional subtraction suffices.
fn reduce(value: &[u8; 32]) -> [u8; 32] {
    if is_below_order(value) {
        return *value;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = value[i] as i16 - GROUP_ORDER[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// BIP 340's tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub(crate) fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_is_a_single_conditional_subtraction() {
        assert_eq!(reduce(&[0u8; 32]), [0u8; 32]);
        let one = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        assert_eq!(reduce(&one), one);
        // n reduces to zero.
        assert_eq!(reduce(&GROUP_ORDER), [0u8; 32]);
        // n + 1 reduces to 1.
        let mut n_plus_one = GROUP_ORDER;
        n_plus_one[31] += 1;
        assert_eq!(reduce(&n_plus_one), one);
        // The largest 256-bit value reduces to 2^256 - n - 1.
        let max = [0xffu8; 32];
        assert!(is_below_order(&reduce(&max)));
    }

    #[test]
    fn the_generator_matches_the_bip() {
        assert_eq!(
            hex_of(&generator().serialize()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
