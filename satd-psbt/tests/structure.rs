//! BIP 375's structural check, refereed by the BIP's own vectors.

mod common;

use satd_psbt::raw::RawPsbt;
use satd_psbt::validate_structure;

/// The six vectors the BIP files under "psbt structure" must fail, and every
/// valid vector the reference runner applies the structure check to must pass.
#[test]
fn structure_vectors() {
    let mut structural = 0usize;
    for v in common::bip375_invalid() {
        if !v.description.starts_with("psbt structure:") {
            continue;
        }
        structural += 1;
        let raw = RawPsbt::parse(&v.psbt).expect("the vector parses");
        assert!(
            validate_structure(&raw).is_err(),
            "{}: should fail the structure check",
            v.description
        );
    }
    assert_eq!(structural, 6, "the BIP files six structural vectors");

    for v in common::bip375_valid() {
        if !v.runs("psbt_structure") {
            continue;
        }
        let raw = RawPsbt::parse(&v.psbt).expect("the vector parses");
        validate_structure(&raw)
            .unwrap_or_else(|e| panic!("{}: should pass the structure check: {e}", v.description));
    }
}

/// Everything BIP 370 files as invalid must be refused, whether by the parser
/// (a version 2 PSBT with no input count cannot even be cut into maps) or by
/// the structure check.
#[test]
fn bip370_invalid_vectors_are_refused() {
    for v in common::bip370_invalid() {
        let verdict = RawPsbt::parse(&v.psbt).and_then(|raw| validate_structure(&raw));
        assert!(
            verdict.is_err(),
            "{}: should be refused, and was not",
            v.description
        );
    }
}

/// And everything it files as valid must be accepted.
#[test]
fn bip370_valid_vectors_are_accepted() {
    for v in common::bip370_valid() {
        let raw = RawPsbt::parse(&v.psbt)
            .unwrap_or_else(|e| panic!("{}: should parse: {e}", v.description));
        validate_structure(&raw)
            .unwrap_or_else(|e| panic!("{}: should be accepted: {e}", v.description));
    }
}

/// The structure check must notice a silent payment output whose script has
/// been computed while the transaction is still declared modifiable: adding
/// one more input would change the shared secret and the script with it.
#[test]
fn a_computed_sp_script_requires_a_frozen_transaction() {
    use satd_psbt::keys;
    use satd_psbt::raw::RawPair;

    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("can finalize: one P2PKH input"))
        .expect("the vector is in the file");
    let mut raw = RawPsbt::parse(&v.psbt).expect("parses");
    validate_structure(&raw).expect("the untouched vector is structurally sound");

    raw.global.set(RawPair::new(
        keys::global::TX_MODIFIABLE,
        Vec::new(),
        vec![keys::modifiable::INPUTS],
    ));
    let err = validate_structure(&raw).expect_err("a modifiable flag must be refused");
    assert!(
        err.to_string().contains("PSBT_GLOBAL_TX_MODIFIABLE"),
        "the message should name the field, got: {err}"
    );
}

/// A share with no proof is an unverifiable claim about where money is going.
#[test]
fn a_share_without_a_proof_is_refused() {
    use satd_psbt::keys;

    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("can finalize: two inputs single-signer using global"))
        .expect("the vector is in the file");
    let mut raw = RawPsbt::parse(&v.psbt).expect("parses");
    validate_structure(&raw).expect("the untouched vector is structurally sound");

    assert_eq!(raw.global.remove_type(keys::global::SP_DLEQ), 1);
    let err = validate_structure(&raw).expect_err("a share with no proof must be refused");
    assert!(err.to_string().contains("DLEQ"), "got: {err}");
}
