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
//! Pure library, no consensus path. Gap-limit tracking is a **client**
//! concern: the server expands the fixed window `[start, start + gap_limit)`
//! it is asked for and stays stateless. The client advances `start` (and
//! removes the trailing scripts) to slide the window as its addresses are
//! used; the server never tracks derivation progress and never emits a
//! side-channel (no gap-limit nudge from the server — that derivation-progress
//! design was dropped, and its retired wire field is reserved in NodeEvent).

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

/// Upper bound on the number of branches a BIP-389 multipath descriptor may
/// expand to. A multipath step `<a;b;…>` yields one branch per element, and
/// each branch derives a full `[start, start + count)` window — so without a
/// branch bound a `<0;1;…;N>` descriptor would multiply the per-branch
/// derivation work past [`MAX_DESCRIPTOR_WINDOW`] (DoS amplification). Real
/// wallets — and Bitcoin Core itself — use exactly two branches (external
/// `<0>` + change `<1>`), so two is the right cap.
pub const MAX_DESCRIPTOR_BRANCHES: usize = 2;

/// Errors expanding a descriptor.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("invalid descriptor: {0}")]
    Parse(String),
    #[error("descriptor window too large: requested {requested}, max {max}")]
    WindowTooLarge { requested: u32, max: u32 },
    #[error("multipath descriptor has too many branches: {branches}, max {max}")]
    TooManyBranches { branches: usize, max: usize },
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
///
/// A **BIP-389 multipath** descriptor (e.g. `wpkh(.../<0;1>/*)`, the canonical
/// form modern wallets export to cover external + change in one string) is
/// split into its single-path branches and each branch expanded over the same
/// `[start, start + count)` window; the results are concatenated. Without this
/// split miniscript's `at_derivation_index` rejects the descriptor outright
/// ("multiple existing keys") and the watch silently installs nothing.
pub fn expand_descriptor(
    desc: &str,
    start: u32,
    count: u32,
) -> Result<Vec<(u32, Scripthash)>, DescriptorError> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .map_err(|e| DescriptorError::Parse(e.to_string()))?;
    // BIP-389: a multipath descriptor packs N single-path branches into one
    // string. `at_derivation_index` can't derive it directly, so split it
    // first and expand each branch independently. A non-multipath descriptor
    // is its own single branch.
    let branches = if descriptor.is_multipath() {
        let single = descriptor
            .into_single_descriptors()
            .map_err(|e| DescriptorError::Parse(format!("multipath split: {e}")))?;
        if single.len() > MAX_DESCRIPTOR_BRANCHES {
            return Err(DescriptorError::TooManyBranches {
                branches: single.len(),
                max: MAX_DESCRIPTOR_BRANCHES,
            });
        }
        single
    } else {
        vec![descriptor]
    };
    let mut out = Vec::new();
    for branch in &branches {
        expand_single(branch, start, count, &mut out)?;
    }
    Ok(out)
}

/// Expand one single-path (non-multipath) descriptor over `[start, start+count)`,
/// appending `(index, scripthash)` pairs to `out`.
fn expand_single(
    descriptor: &Descriptor<DescriptorPublicKey>,
    start: u32,
    count: u32,
    out: &mut Vec<(u32, Scripthash)>,
) -> Result<(), DescriptorError> {
    // Reject a hardened wildcard up front: such a descriptor parses, but
    // `at_derivation_index` PANICS on it (a hardened child cannot be derived
    // from an xpub), so a hardened-wildcard descriptor over the wire would be
    // a remotely reachable panic unless caught here.
    if has_hardened_wildcard(descriptor) {
        return Err(DescriptorError::HardenedWildcard);
    }
    let ranged = descriptor.has_wildcard();
    // Bound the derivation window BEFORE allocating or deriving: `count`
    // (the wire `gap_limit`) is attacker-controlled. A fixed (non-wildcard)
    // descriptor always yields exactly one script. The window is bounded
    // per branch; the branch count itself is bounded in `expand_descriptor`,
    // so the total work stays within `MAX_DESCRIPTOR_WINDOW * MAX_DESCRIPTOR_BRANCHES`.
    if ranged && count > MAX_DESCRIPTOR_WINDOW {
        return Err(DescriptorError::WindowTooLarge {
            requested: count,
            max: MAX_DESCRIPTOR_WINDOW,
        });
    }
    let n = if ranged { count.max(1) } else { 1 };
    out.reserve(n as usize);
    for i in 0..n {
        let idx = start.saturating_add(i);
        let definite = descriptor
            .at_derivation_index(idx)
            .map_err(|e| DescriptorError::Derive(idx, e.to_string()))?;
        let spk = definite.script_pubkey();
        let sh = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
        out.push((idx, sh));
    }
    Ok(())
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
    fn sliding_window_overlap_shares_scripthashes() {
        // The client-managed sliding window (B3): advancing `start` while the
        // windows overlap must re-derive the SAME scripthashes for the shared
        // indices — that overlap is what makes "advance start, Remove the
        // trailing scripts" correct, since the kept scripts are byte-identical.
        let w0 = expand_descriptor(RANGED_WPKH, 0, 5).unwrap(); // indices 0..5
        let w1 = expand_descriptor(RANGED_WPKH, 3, 5).unwrap(); // indices 3..8
        // Indices 3 and 4 are in both windows → identical (idx, scripthash).
        assert_eq!(w0[3], w1[0], "index 3 derives identically in both windows");
        assert_eq!(w0[4], w1[1], "index 4 derives identically in both windows");
    }

    #[test]
    fn huge_start_does_not_panic() {
        // A start near u32::MAX pushes derivation indices past the non-hardened
        // range (>= 2^31). `expand_descriptor` must return an error (handled by
        // the caller as "ignore"), never panic or overflow.
        let r = expand_descriptor(RANGED_WPKH, u32::MAX - 1, 3);
        assert!(matches!(r, Err(DescriptorError::Derive(_, _))), "got: {r:?}");
    }

    #[test]
    fn fixed_descriptor_yields_single_entry() {
        // A non-wildcard key descriptor (fixed final index) resolves to one
        // script regardless of the requested window size.
        let fixed = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/0)";
        let out = expand_descriptor(fixed, 0, 20).expect("expand fixed");
        assert_eq!(out.len(), 1, "fixed descriptor yields a single script");
    }

    // BIP-389 multipath form of `RANGED_WPKH`: external `<0>` + change `<1>`
    // packed into one string. This is what Core/Sparrow/BDK wallets export.
    const MULTIPATH_WPKH: &str = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1>/*)";

    #[test]
    fn expands_multipath_to_both_branches() {
        // A multipath descriptor must expand to one window per branch,
        // concatenated — not fail outright (#445). Here: 2 branches × 5.
        let out = expand_descriptor(MULTIPATH_WPKH, 0, 5).expect("expand multipath");
        assert_eq!(out.len(), 10, "2 branches × window of 5");

        // The first branch (`/0/*`) must match the equivalent single-path
        // descriptor byte-for-byte; the second branch (`/1/*`) is distinct.
        let single0 = expand_descriptor(RANGED_WPKH, 0, 5).unwrap();
        assert_eq!(&out[..5], &single0[..], "first branch == /0/* single-path");
        assert_ne!(
            &out[..5],
            &out[5..],
            "external and change branches derive distinct scripts"
        );

        // All ten scripthashes are distinct (no branch/index collision).
        let mut hashes: Vec<_> = out.iter().map(|(_, sh)| *sh).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 10, "all derived scripthashes distinct");
    }

    #[test]
    fn multipath_window_cap_is_per_branch() {
        // The window cap applies per branch, so a 2-branch descriptor at the
        // cap is accepted and yields 2× the cap. One past the cap still errors.
        assert!(expand_descriptor(MULTIPATH_WPKH, 0, MAX_DESCRIPTOR_WINDOW).is_ok());
        assert!(matches!(
            expand_descriptor(MULTIPATH_WPKH, 0, MAX_DESCRIPTOR_WINDOW + 1),
            Err(DescriptorError::WindowTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_too_many_multipath_branches() {
        // A multipath descriptor with more branches than the cap is rejected
        // before any derivation — it would otherwise amplify the per-branch
        // window past the DoS bound (and is incompatible with Core anyway).
        let three = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1;2>/*)";
        assert!(matches!(
            expand_descriptor(three, 0, 5),
            Err(DescriptorError::TooManyBranches { branches: 3, max: 2 })
        ));
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
