//! satd's PSBT codec.
//!
//! The `bitcoin` crate refuses any PSBT whose `PSBT_GLOBAL_VERSION` is above
//! zero, so a BIP 375 silent payment PSBT — which is version 2 by definition —
//! cannot reach satd through it at all. This crate carries version 2 instead,
//! as a lossless map of raw key-value pairs with a typed read-only view on
//! top. Version 0 keeps going through `bitcoin::Psbt` exactly as before.
//!
//! The layers, bottom up:
//!
//! - [`raw`] parses and re-serialises a PSBT byte-for-byte. Unknown fields,
//!   field order and encoding all survive a round trip.
//! - [`v2`] reads BIP 370 and BIP 375 fields out of a raw PSBT, and converts
//!   one to a `bitcoin::Psbt` so that version 0 code can finish the job.
//! - [`structure`] is BIP 375's structural check.
//!
//! Nothing in this crate holds key material or signs anything.

#![forbid(unsafe_code)]

pub mod error;
pub mod keys;
pub mod raw;
pub mod structure;
pub mod v2;

pub use error::{MapId, PsbtError};
pub use raw::{PsbtVersion, RawMap, RawPair, RawPsbt, sniff_version, version_of_bytes};
pub use structure::validate_structure;
pub use v2::{InputView, OutputView, SpProof, SpShare, SpV0Info, V2View};

/// A hook the test suite flips to prove the passthrough tests can fail.
///
/// A test that asserts "nothing was lost" is worth only as much as the proof
/// that it would notice a loss. `serialize_lossy` drops unknown and BIP 375
/// pairs on the way out; one meta-test flips it on and requires every
/// passthrough checker to report a loss. It is `cfg(test)`-adjacent by
/// convention rather than by `cfg`, because the surface tests that use it
/// live in other crates.
#[doc(hidden)]
pub mod testing {
    /// The vendored BIP 375 vectors, for crates that test their own PSBT
    /// surfaces. See `satd-psbt/tests/vectors/README.md` for provenance.
    #[cfg(feature = "test-vectors")]
    pub const BIP375_VECTORS: &str = include_str!("../tests/vectors/bip375_test_vectors.json");

    /// The vendored BIP 370 vectors.
    #[cfg(feature = "test-vectors")]
    pub const BIP370_VECTORS: &str = include_str!("../tests/vectors/bip370_test_vectors.json");

    use crate::keys;
    use crate::raw::{RawMap, RawPsbt};

    /// Serialise a PSBT with every unknown and BIP 375 pair dropped. Used only
    /// to prove a passthrough checker notices.
    pub fn serialize_lossy(raw: &RawPsbt) -> Vec<u8> {
        let known_global = [
            keys::global::UNSIGNED_TX,
            keys::global::XPUB,
            keys::global::TX_VERSION,
            keys::global::FALLBACK_LOCKTIME,
            keys::global::INPUT_COUNT,
            keys::global::OUTPUT_COUNT,
            keys::global::TX_MODIFIABLE,
            keys::global::VERSION,
        ];
        let known_input: Vec<u64> = (0x00..=0x18).chain([0xfc]).collect();
        let known_output: Vec<u64> = (0x00..=0x07).chain([0xfc]).collect();

        let keep = |map: &RawMap, known: &[u64]| -> RawMap {
            map.pairs()
                .iter()
                .filter(|p| known.contains(&p.key_type))
                .cloned()
                .collect()
        };

        let stripped = RawPsbt {
            global: keep(&raw.global, &known_global),
            inputs: raw.inputs.iter().map(|m| keep(m, &known_input)).collect(),
            outputs: raw.outputs.iter().map(|m| keep(m, &known_output)).collect(),
        };
        stripped.serialize()
    }
}
