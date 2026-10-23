//! Fuzz the NAP P2P message decoders. `getnapatt` reaches every publisher
//! from any peer, and `napatt` reaches every aggregator, so every byte is
//! attacker-controlled. Asserts that whatever decodes re-encodes to a prefix
//! of the input: the fields decode strictly, and only bytes after them (a
//! later version's fields) are ignored.
//!
//! Run: `cargo +nightly fuzz run nap_p2p_decode` (needs a nightly +
//! sanitizer toolchain; this crate is a standalone workspace excluded from
//! the main build).

#![no_main]

use libfuzzer_sys::fuzz_target;
use node::nap::p2p::{GetNapAtt, MAX_GETNAPATT_KEYS, MAX_NAPATT_SIZE, NapAtt};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = GetNapAtt::from_bytes(data) {
        assert!(req.keys.len() <= MAX_GETNAPATT_KEYS);
        assert!(data.starts_with(&req.to_bytes()));
    }
    if let Ok(page) = NapAtt::from_bytes(data) {
        assert!(data.len() <= MAX_NAPATT_SIZE);
        assert!(data.starts_with(&page.to_bytes()));
    }
});
