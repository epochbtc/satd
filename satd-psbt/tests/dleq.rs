//! BIP 374, refereed against the BIP's own vectors in both directions.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use satd_psbt::dleq;

const VERIFY_CSV: &str = include_str!("vectors/bip374_verify_proof.csv");
const GENERATE_CSV: &str = include_str!("vectors/bip374_generate_proof.csv");

fn rows(csv: &str) -> Vec<Vec<String>> {
    csv.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(|f| f.trim().to_string()).collect())
        .collect()
}

fn point(hex: &str) -> Option<PublicKey> {
    PublicKey::from_slice(&hex_bytes(hex)?).ok()
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn array32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex_bytes(hex)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn array64(hex: &str) -> Option<[u8; 64]> {
    let bytes = hex_bytes(hex)?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Every row of `test_vectors_verify_proof.csv`, the eight failures included.
/// Seven of those are point swaps and one is a tampered proof; a verifier that
/// forgot to bind one of the four points to the challenge passes the swaps.
#[test]
fn bip374_verify_proof_vectors() {
    let mut passed = 0usize;
    let mut failed = 0usize;
    for row in rows(VERIFY_CSV) {
        let (g, a, b, c) = (
            point(&row[1]).expect("G parses"),
            point(&row[2]).expect("A parses"),
            point(&row[3]).expect("B parses"),
            point(&row[4]).expect("C parses"),
        );
        let proof = array64(&row[5]).expect("a 64-byte proof");
        let message = array32(&row[6]);
        let expected = row[7] == "TRUE";
        let comment = &row[8];

        let got = dleq::verify_proof_with_generator(&g, &a, &b, &c, &proof, message.as_ref());
        assert_eq!(got, expected, "row {}: {comment}", row[0]);
        if expected {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    assert_eq!(passed, 8, "the file has eight success rows");
    assert_eq!(failed, 7, "the file has seven failure rows");
}

/// And `test_vectors_generate_proof.csv`, byte for byte: a proof is
/// deterministic given the auxiliary randomness, so the whole 64 bytes are
/// comparable rather than only their validity.
#[test]
fn bip374_generate_proof_vectors() {
    let mut produced = 0usize;
    let mut refused = 0usize;
    for row in rows(GENERATE_CSV) {
        let g = point(&row[1]).expect("G parses");
        let secret = array32(&row[2]).and_then(|b| SecretKey::from_slice(&b).ok());
        let b = point(&row[3]);
        let aux = array32(&row[4]).expect("32 bytes of auxiliary randomness");
        let message = array32(&row[5]);
        let expected = &row[6];
        let comment = &row[7];

        // A secret of zero or of the group order has no `SecretKey`, and the
        // point at infinity has no `PublicKey`. The BIP fails on all three,
        // and so does the type system.
        let (Some(secret), Some(b)) = (secret, b) else {
            assert_eq!(expected, "INVALID", "row {}: {comment}", row[0]);
            refused += 1;
            continue;
        };

        match dleq::generate_proof_with_generator(&g, &secret, &b, &aux, message.as_ref()) {
            Ok(proof) => {
                assert_eq!(hex(&proof), *expected, "row {}: {comment}", row[0]);
                produced += 1;
            }
            Err(e) => {
                assert_eq!(expected, "INVALID", "row {}: {comment}: {e}", row[0]);
                refused += 1;
            }
        }
    }
    assert_eq!(produced, 8, "the file has eight success rows");
    assert_eq!(refused, 3, "the file has three failure rows");
}

/// satd's own negatives, on top of the BIP's: flip one bit in each of `e`,
/// `s`, `A`, `B` and `C` for every row that passes, and require failure. A
/// proof that survives a single-bit change is not a proof.
#[test]
fn a_single_flipped_bit_breaks_every_passing_proof() {
    let mut checked = 0usize;
    for row in rows(VERIFY_CSV) {
        if row[7] != "TRUE" {
            continue;
        }
        let (g, a, b, c) = (
            point(&row[1]).unwrap(),
            point(&row[2]).unwrap(),
            point(&row[3]).unwrap(),
            point(&row[4]).unwrap(),
        );
        let proof = array64(&row[5]).unwrap();
        let message = array32(&row[6]);
        assert!(dleq::verify_proof_with_generator(
            &g,
            &a,
            &b,
            &c,
            &proof,
            message.as_ref()
        ));

        // Every byte of the proof: `e` in the first half, `s` in the second.
        for i in 0..64 {
            let mut tampered = proof;
            tampered[i] ^= 0x01;
            assert!(
                !dleq::verify_proof_with_generator(&g, &a, &b, &c, &tampered, message.as_ref()),
                "row {}: flipping proof byte {i} should break it",
                row[0]
            );
            checked += 1;
        }

        // And each of the three points, by flipping a byte of the x
        // coordinate until the result is still a valid point.
        for (name, original) in [("A", &a), ("B", &b), ("C", &c)] {
            let Some(other) = nudge(original) else {
                continue;
            };
            let (ta, tb, tc) = match name {
                "A" => (other, b, c),
                "B" => (a, other, c),
                _ => (a, b, other),
            };
            assert!(
                !dleq::verify_proof_with_generator(&g, &ta, &tb, &tc, &proof, message.as_ref()),
                "row {}: changing {name} should break it",
                row[0]
            );
            checked += 1;
        }

        // A message that was there and is not, or the other way round.
        let swapped = match message {
            Some(_) => None,
            None => Some([0u8; 32]),
        };
        assert!(
            !dleq::verify_proof_with_generator(&g, &a, &b, &c, &proof, swapped.as_ref()),
            "row {}: changing the message should break it",
            row[0]
        );
        checked += 1;
    }
    assert!(checked > 400, "expected a few hundred negatives, got {checked}");
}

/// The BIP does not bound `e`, and the specification's comparison is against
/// an equally unbounded hash output. So `e` is reduced modulo the group order
/// for the multiplication and compared unreduced, rather than rejected.
///
/// What that branch protects against is not something anyone will meet: a
/// challenge hash lands at or above the group order with probability about
/// 2^-128, so no honest proof will ever take it. It is here because the
/// alternative — rejecting `e >= n` outright — is a silent deviation from the
/// specification, and a deviation nobody can trigger is a deviation nobody
/// will find. What is testable is that such a proof is handled rather than
/// panicked on: a verifier that fed `e` straight to `Scalar::from_be_bytes`
/// and unwrapped would abort here, on a read-capability RPC method.
#[test]
fn an_out_of_range_or_zero_challenge_is_handled_rather_than_panicked_on() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let a = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
    let b = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x33u8; 32]).unwrap());
    let big_a = PublicKey::from_secret_key(&secp, &a);
    let big_c = b
        .mul_tweak(
            &secp,
            &bitcoin::secp256k1::Scalar::from_be_bytes(a.secret_bytes()).unwrap(),
        )
        .unwrap();

    let order =
        array32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let valid = dleq::generate_proof(&a, &b, &[0x11u8; 32], None).expect("a proof");
    let mut s_half = [0u8; 32];
    s_half.copy_from_slice(&valid[32..]);

    for (name, e) in [
        ("all ones", [0xffu8; 32]),
        ("exactly the group order", order),
        ("zero", [0u8; 32]),
    ] {
        let mut proof = [0u8; 64];
        proof[..32].copy_from_slice(&e);
        proof[32..].copy_from_slice(&s_half);
        assert!(
            !dleq::verify_proof(&big_a, &b, &big_c, &proof, None),
            "a challenge of {name} is not a valid proof"
        );
    }

    // And `s` at or above the group order is the one bound the BIP does state.
    let mut proof = valid;
    proof[32..].copy_from_slice(&order);
    assert!(!dleq::verify_proof(&big_a, &b, &big_c, &proof, None));

    // `s = 0` makes `s·G` the point at infinity, which the secp256k1 API
    // reports as an error and which the specification treats as a value.
    let mut proof = valid;
    proof[32..].copy_from_slice(&[0u8; 32]);
    assert!(!dleq::verify_proof(&big_a, &b, &big_c, &proof, None));
}

/// A proof generated here verifies here, over a range of shapes. Round-tripping
/// alone proves little — the vectors are the referee — but it catches a pair of
/// mistakes that cancel out only if they are made consistently.
#[test]
fn generated_proofs_verify() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    for i in 1u8..20 {
        let a = SecretKey::from_slice(&[i; 32]).unwrap();
        let b_secret = SecretKey::from_slice(&[i.wrapping_add(7).max(1); 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_secret);
        let big_a = PublicKey::from_secret_key(&secp, &a);
        let big_c = b
            .mul_tweak(
                &secp,
                &bitcoin::secp256k1::Scalar::from_be_bytes(a.secret_bytes()).unwrap(),
            )
            .unwrap();

        for message in [None, Some([i; 32])] {
            let proof = dleq::generate_proof(&a, &b, &[i ^ 0x5a; 32], message.as_ref())
                .expect("a proof");
            assert!(dleq::verify_proof(&big_a, &b, &big_c, &proof, message.as_ref()));
            // The same proof against the wrong C must fail.
            let wrong_c = PublicKey::from_secret_key(&secp, &b_secret);
            assert!(!dleq::verify_proof(&big_a, &b, &wrong_c, &proof, message.as_ref()));
        }
    }
}

/// Change a point to a different valid point, deterministically.
fn nudge(point: &PublicKey) -> Option<PublicKey> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let two = bitcoin::secp256k1::Scalar::from_be_bytes({
        let mut v = [0u8; 32];
        v[31] = 2;
        v
    })
    .ok()?;
    point.mul_tweak(&secp, &two).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
