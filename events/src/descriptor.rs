//! Descriptor convenience layer for the streaming watch API.
//!
//! Address-watching is outpoint-watching with a derivation rule on top.
//! This module expands a (possibly ranged) output descriptor into the
//! scripthashes a client wants to watch, via `rust-miniscript` — so a
//! client can send a single descriptor instead of enumerating addresses.
//! The expanded scripthashes are registered with the
//! [`WatchRegistry`](node::events::WatchRegistry) like any other script
//! watch-set; matches come back as `ScriptMatched`.
//!
//! Pure library, no consensus path. The gap-limit semantics: a client
//! watches `gap_limit` unused indices ahead; the server emits
//! `DescriptorNeedsAddresses` (a later enhancement) when the window should
//! advance.

use bitcoin::hashes::{Hash, sha256};
use miniscript::descriptor::Wildcard;
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use std::str::FromStr;

/// `sha256(scriptPubKey)` — the same convention as `node_index::keys`.
pub type Scripthash = [u8; 32];

/// Upper bound on the number of derivation indices a single `AddDescriptor`
/// may expand. `gap_limit`/`count` is attacker-controlled over the wire; an
/// unbounded value would drive a huge `Vec` pre-allocation plus that many EC
/// derivations on the runtime. Bitcoin Core's default gap limit is 20, so a
/// 1000-entry window is generous for legitimate clients.
pub const MAX_DESCRIPTOR_WINDOW: u32 = 1000;

/// Errors expanding a descriptor.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("invalid descriptor: {0}")]
    Parse(String),
    #[error("descriptor window too large: requested {requested}, max {max}")]
    WindowTooLarge { requested: u32, max: u32 },
    #[error("hardened-wildcard descriptors cannot be derived from a public key")]
    HardenedWildcard,
    #[error("descriptor derivation failed at index {0}: {1}")]
    Derive(u32, String),
}

/// Expand a descriptor into `(index, scripthash)` pairs for derivation
/// indices `[start, start + count)`.
///
/// - A **ranged** descriptor (one with a `/*` wildcard) yields up to
///   `count` entries, one per index.
/// - A **fixed** descriptor (no wildcard) yields a single entry at `start`
///   (it resolves to the same script at every index), with `count` ignored
///   beyond the first.
///
/// Only public descriptors are accepted (xpub / pubkey based) — the node is
/// keyless. Keylessness is enforced by the `Descriptor::<DescriptorPublicKey>`
/// type parameter below: a descriptor embedding a private key (`xprv`/`tprv`/
/// WIF) fails to parse here, because the private-key form is the separate
/// `parse_descriptor`, which we never call. A secret can therefore never reach
/// derivation.
pub fn expand_descriptor(
    desc: &str,
    start: u32,
    count: u32,
) -> Result<Vec<(u32, Scripthash)>, DescriptorError> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .map_err(|e| DescriptorError::Parse(e.to_string()))?;
    // Reject a hardened wildcard up front: such a descriptor parses, but
    // `at_derivation_index` PANICS on it (a hardened child cannot be derived
    // from an xpub), so a hardened-wildcard descriptor over the wire would be
    // a remotely reachable panic unless caught here.
    if has_hardened_wildcard(&descriptor) {
        return Err(DescriptorError::HardenedWildcard);
    }
    let ranged = descriptor.has_wildcard();
    // Bound the derivation window BEFORE allocating or deriving: `count`
    // (the wire `gap_limit`) is attacker-controlled. A fixed (non-wildcard)
    // descriptor always yields exactly one script.
    if ranged && count > MAX_DESCRIPTOR_WINDOW {
        return Err(DescriptorError::WindowTooLarge {
            requested: count,
            max: MAX_DESCRIPTOR_WINDOW,
        });
    }
    let n = if ranged { count.max(1) } else { 1 };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let idx = start.saturating_add(i);
        let definite = descriptor
            .at_derivation_index(idx)
            .map_err(|e| DescriptorError::Derive(idx, e.to_string()))?;
        let spk = definite.script_pubkey();
        let sh = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
        out.push((idx, sh));
    }
    Ok(out)
}

/// True if any key in the descriptor is an xpub with a HARDENED wildcard
/// (`/*h` or `/*'`). Such a descriptor parses but cannot be derived from a
/// public key, and `at_derivation_index` panics on it, so it must be rejected
/// before derivation.
fn has_hardened_wildcard(desc: &Descriptor<DescriptorPublicKey>) -> bool {
    desc.for_any_key(|k| match k {
        DescriptorPublicKey::XPub(x) => x.wildcard == Wildcard::Hardened,
        DescriptorPublicKey::MultiXPub(x) => x.wildcard == Wildcard::Hardened,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A well-known BIP84 test xpub (the standard test vector account 0
    // external chain): wpkh(.../84'/0'/0'/0/*).
    const RANGED_WPKH: &str = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*)";

    #[test]
    fn expands_ranged_descriptor_to_distinct_scripthashes() {
        let out = expand_descriptor(RANGED_WPKH, 0, 5).expect("expand");
        assert_eq!(out.len(), 5);
        // Indices are sequential from start.
        for (i, (idx, _)) in out.iter().enumerate() {
            assert_eq!(*idx, i as u32);
        }
        // Each derived script is distinct.
        let mut hashes: Vec<_> = out.iter().map(|(_, sh)| *sh).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 5, "derived scripthashes must be distinct");
    }

    #[test]
    fn ranged_expansion_is_deterministic_and_windowed() {
        let a = expand_descriptor(RANGED_WPKH, 0, 3).unwrap();
        let b = expand_descriptor(RANGED_WPKH, 0, 3).unwrap();
        assert_eq!(a, b, "same descriptor + window → same scripthashes");
        // A shifted window starts where asked.
        let shifted = expand_descriptor(RANGED_WPKH, 10, 2).unwrap();
        assert_eq!(shifted[0].0, 10);
        assert_eq!(shifted[1].0, 11);
        // Index 0 in window-from-0 differs from index 10.
        assert_ne!(a[0].1, shifted[0].1);
    }

    #[test]
    fn fixed_descriptor_yields_single_entry() {
        // A non-wildcard key descriptor (fixed final index) resolves to one
        // script regardless of the requested window size.
        let fixed = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/0)";
        let out = expand_descriptor(fixed, 0, 20).expect("expand fixed");
        assert_eq!(out.len(), 1, "fixed descriptor yields a single script");
    }

    #[test]
    fn rejects_malformed_descriptor() {
        assert!(matches!(
            expand_descriptor("not a descriptor", 0, 1),
            Err(DescriptorError::Parse(_))
        ));
    }

    #[test]
    fn rejects_oversized_window() {
        // A ranged descriptor with a window beyond the cap is rejected BEFORE
        // any allocation/derivation (DoS bound), not clamped silently.
        let err = expand_descriptor(RANGED_WPKH, 0, MAX_DESCRIPTOR_WINDOW + 1);
        assert!(matches!(
            err,
            Err(DescriptorError::WindowTooLarge { requested, max })
                if requested == MAX_DESCRIPTOR_WINDOW + 1 && max == MAX_DESCRIPTOR_WINDOW
        ));
        // Exactly at the cap is allowed (but we only check it does not error).
        assert!(expand_descriptor(RANGED_WPKH, 0, MAX_DESCRIPTOR_WINDOW).is_ok());
    }

    #[test]
    fn rejects_hardened_wildcard_without_panicking() {
        // `/*h` parses but cannot be derived from an xpub; `at_derivation_index`
        // would panic. expand_descriptor must return an error, not panic.
        let hardened = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*h)";
        assert!(matches!(
            expand_descriptor(hardened, 0, 4),
            Err(DescriptorError::HardenedWildcard)
        ));
    }

    #[test]
    fn rejects_secret_bearing_descriptors() {
        // The keyless invariant: a descriptor carrying a private key must fail
        // to parse (it never reaches derivation). tprv (testnet xprv) and a
        // WIF key are both rejected at parse — the `xprv` substring check the
        // old code used would have missed tprv entirely.
        let tprv = "wpkh(tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16/0/*)";
        assert!(matches!(
            expand_descriptor(tprv, 0, 1),
            Err(DescriptorError::Parse(_))
        ));
        let wif = "wpkh(cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy)";
        assert!(matches!(
            expand_descriptor(wif, 0, 1),
            Err(DescriptorError::Parse(_))
        ));
    }
}
