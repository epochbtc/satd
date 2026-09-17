//! Fuzz the PSBT raw codec against arbitrary bytes.
//!
//! `decodepsbt` and `analyzepsbt` are read-capability methods, so this parser
//! sees attacker-controlled bytes on a listener an operator may expose more
//! widely than the wallet one. Two properties are asserted:
//!
//! 1. Nothing panics — not the parser, not the structure check, not the
//!    typed accessors. libfuzzer catches a panic for us.
//! 2. Anything that parses re-serialises to exactly the bytes it came from.
//!    That is the property the BIP 375 passthrough guarantees rest on, and
//!    the vectors only cover the shapes the BIP authors thought of.
//!
//! Run: `cargo +nightly fuzz run psbt_raw` (needs a nightly + sanitizer
//! toolchain; this crate is a standalone workspace excluded from the main
//! build).

#![no_main]

use libfuzzer_sys::fuzz_target;
use satd_psbt::raw::{PsbtVersion, RawPsbt};
use satd_psbt::{V2View, validate_structure, version_of_bytes};

fuzz_target!(|data: &[u8]| {
    // The cheap sniff the RPC layer dispatches on must never panic either.
    let _ = version_of_bytes(data);

    let raw = match RawPsbt::parse(data) {
        Ok(raw) => raw,
        Err(_) => return,
    };

    let reserialized = raw.serialize();
    assert!(
        reserialized == data,
        "a parsed PSBT did not re-serialise to its own bytes"
    );

    // Reparsing what we wrote must give the same structure back.
    let again = RawPsbt::parse(&reserialized).expect("our own output must parse");
    assert!(again == raw, "reparsing changed the structure");

    let _ = validate_structure(&raw);

    if raw.version() == Ok(PsbtVersion::V2) {
        let view = V2View::new(&raw).expect("version 2 makes a view");
        let _ = view.tx_version();
        let _ = view.fallback_locktime();
        let _ = view.tx_modifiable();
        let _ = view.sp_ecdh_shares();
        let _ = view.sp_dleq_proofs();
        let _ = view.sp_scan_keys();
        let _ = view.lock_time();
        let _ = view.unsigned_tx();
        let _ = view.unique_id();
        let _ = view.to_v0();
        for input in view.inputs() {
            let _ = input.outpoint();
            let _ = input.sequence();
            let _ = input.prevout();
            let _ = input.sighash_type();
            let _ = input.tap_internal_key();
            let _ = input.sp_ecdh_shares();
            let _ = input.sp_dleq_proofs();
        }
        for output in view.outputs() {
            let _ = output.amount();
            let _ = output.script();
            let _ = output.sp_v0_info();
            let _ = output.sp_v0_label();
        }
    }
});
