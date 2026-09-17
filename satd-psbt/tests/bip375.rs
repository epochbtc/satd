//! BIP 375's 42 vectors, through satd's full validator.
//!
//! The BIP runs four checks in sequence and lets a vector override which of
//! them apply. This mirrors that: `validate_structure` is the first check,
//! `sp::check_input_constraints` the third, and `sp::verify` covers the
//! second and fourth together, since the ECDH coverage and the output scripts
//! are two readings of one derivation.

mod common;

use satd_psbt::raw::RawPsbt;
use satd_psbt::sp::{self, OutputStatus, ScriptState};
use satd_psbt::{V2View, validate_structure};

/// satd's verdict on a vector, in the BIP's own terms: `Err` where the BIP
/// says invalid.
fn verdict(raw: &RawPsbt, checks: &Option<Vec<String>>) -> Result<(), String> {
    let runs = |name: &str| match checks {
        None => true,
        Some(list) => list.iter().any(|c| c == name),
    };

    if runs("psbt_structure") {
        validate_structure(raw).map_err(|e| format!("structure: {e}"))?;
    }
    let view = V2View::new(raw).map_err(|e| e.to_string())?;
    if runs("input_eligibility")
        && let Some(why) = sp::check_input_constraints(&view).map_err(|e| e.to_string())?
    {
        return Err(format!("input eligibility: {why}"));
    }
    if !runs("ecdh_coverage") && !runs("output_scripts") {
        return Ok(());
    }

    // The BIP's vectors do not bind an input's public key to its previous
    // output — 46 of their 49 non-taproot inputs carry a key that does not
    // hash to their own `witness_utxo` — so refereeing the derivation against
    // them means reading the key the way the reference validator does. The
    // node never does; `a_rebound_key_is_not_ready` is the test of that.
    let report = sp::verify_with_binding(&view, None, sp::KeyBinding::Declared)
        .map_err(|e| e.to_string())?;
    for output in &report.outputs {
        match output.status {
            // A missing share is only a fault once the script has been
            // computed from it. Before that it is the normal state of a PSBT
            // that is still going round.
            OutputStatus::MissingShares if !output.script_present => {}
            OutputStatus::Ready => {}
            status => {
                return Err(format!(
                    "output {}: {}{}",
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
    }
    Ok(())
}

/// Everything the BIP files as invalid must be refused, and everything it
/// files as valid must be accepted.
#[test]
fn bip375_vectors() {
    let mut refused = 0usize;
    for v in common::bip375_invalid() {
        let raw = RawPsbt::parse(&v.psbt).expect("the vector parses");
        let got = verdict(&raw, &v.checks);
        assert!(
            got.is_err(),
            "{}: should have been refused, and was not",
            v.description
        );
        refused += 1;
    }
    assert_eq!(refused, 22);

    let mut accepted = 0usize;
    for v in common::bip375_valid() {
        let raw = RawPsbt::parse(&v.psbt).expect("the vector parses");
        verdict(&raw, &v.checks)
            .unwrap_or_else(|e| panic!("{}: should have been accepted: {e}", v.description));
        accepted += 1;
    }
    assert_eq!(accepted, 20);
}

/// The vector that settles how `k` is assigned.
///
/// BIP 375's prose says to sort the codes sharing a scan key lexicographically
/// to decide their `k` values. Valid vector 9 has two outputs under one scan
/// key whose spend keys *descend* with output index, and its stored scripts
/// reproduce only under `k = position in output order`. The reference
/// validator agrees with the vector, not the prose. Following the prose would
/// mean rejecting a PSBT the BIP publishes as valid, so satd follows the
/// vector — and this is the test that pins which.
#[test]
fn k_follows_output_index_not_spend_key() {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("can finalize: two sp outputs - output 0 uses label=3"))
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    let report = sp::verify_with_binding(&view, None, sp::KeyBinding::Declared).expect("verifies");

    assert_eq!(report.outputs.len(), 2);
    assert_eq!(report.outputs[0].scan_key, report.outputs[1].scan_key);
    // The premise: the spend keys descend with output index.
    assert!(
        report.outputs[0].spend_key.serialize() > report.outputs[1].spend_key.serialize(),
        "this vector only discriminates while its spend keys descend with index"
    );
    // The conclusion: k follows the index anyway, and both scripts match.
    assert_eq!(report.outputs[0].k, 0);
    assert_eq!(report.outputs[1].k, 1);
    for output in &report.outputs {
        assert_eq!(output.status, OutputStatus::Ready, "{output:?}");
        assert_eq!(output.script_state, ScriptState::Matches);
    }

    // And the other rule really would fail: swapping the two derived scripts
    // is what sorting by spend key would have produced.
    assert_ne!(
        report.outputs[0].derived_script,
        report.outputs[1].derived_script
    );
}

/// Outputs under different scan keys each start at `k = 0`.
#[test]
fn k_counts_per_scan_key() {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("can finalize: three sp outputs (different scan keys)"))
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    let report = sp::verify_with_binding(&view, None, sp::KeyBinding::Declared).expect("verifies");
    assert_eq!(report.outputs.len(), 3);
    for output in &report.outputs {
        assert_eq!(output.k, 0, "output {} is alone under its scan key", output.index);
        assert_eq!(output.status, OutputStatus::Ready);
    }
}

/// And outputs sharing one scan key get distinct `k` values even when other
/// outputs sit between them.
#[test]
fn k_ignores_the_outputs_in_between() {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| {
            v.description
                .starts_with("can finalize: three sp outputs (same scan key) / two regular outputs")
        })
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    let report = sp::verify_with_binding(&view, None, sp::KeyBinding::Declared).expect("verifies");
    let ks: Vec<u32> = report.outputs.iter().map(|o| o.k).collect();
    assert_eq!(ks, vec![0, 1, 2]);
    // The silent payment outputs are not adjacent.
    let indices: Vec<usize> = report.outputs.iter().map(|o| o.index).collect();
    assert_eq!(indices, vec![0, 2, 4]);
}
