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
use miniscript::{Descriptor, DescriptorPublicKey};
use std::str::FromStr;

/// `sha256(scriptPubKey)` — the same convention as `node_index::keys`.
pub type Scripthash = [u8; 32];

/// Errors expanding a descriptor.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("invalid descriptor: {0}")]
    Parse(String),
    #[error("descriptor requires a private key or is not address-deriving")]
    NotDeriving,
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
/// keyless, so a descriptor carrying a private key is rejected.
pub fn expand_descriptor(
    desc: &str,
    start: u32,
    count: u32,
) -> Result<Vec<(u32, Scripthash)>, DescriptorError> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .map_err(|e| DescriptorError::Parse(e.to_string()))?;
    // The node never holds secrets; refuse a descriptor that embeds one.
    if descriptor.to_string().contains("xprv") {
        return Err(DescriptorError::NotDeriving);
    }
    let ranged = descriptor.has_wildcard();
    let n = if ranged { count.max(1) } else { 1 };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let idx = start.saturating_add(i);
        let definite = descriptor
            .at_derivation_index(idx)
            .map_err(|e| DescriptorError::Derive(idx, e.to_string()))?;
        let spk = definite
            .script_pubkey();
        let sh = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
        out.push((idx, sh));
    }
    Ok(out)
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
}
