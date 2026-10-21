//! Fuzz the NAP message-text parser. Asserts there is one text per
//! attestation: whatever parses renders back to the same text.
//!
//! Run: `cargo +nightly fuzz run nap_message_parse` (needs a nightly +
//! sanitizer toolchain; this crate is a standalone workspace excluded from
//! the main build).

#![no_main]

use libfuzzer_sys::fuzz_target;
use node::nap::message;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(m) = message::parse(text) {
        let rendered = message::render(&m.outpoint, &m.key, &m.value, m.anchor_height, &m.anchor_hash);
        assert_eq!(rendered, text);
    }
});
