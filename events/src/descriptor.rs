//! Descriptor convenience layer for the streaming watch API.
//!
//! Address-watching is outpoint-watching with a derivation rule on top.
//! This module expands a (possibly ranged) output descriptor into the
//! scripthashes a client wants to watch, via `rust-miniscript` — so a
//! client can send a single descriptor instead of enumerating addresses.
//! A BIP-389 multipath descriptor (`.../<0;1>/*`) splits into its branches
//! and expands each over the same window — so one such descriptor yields up
//! to `branches × window` scripts (and the client must remove all branches
//! when sliding the window; see below).
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
//! Removal is by explicit scripthash (there is no `RemoveDescriptor`), so for a
//! multipath descriptor the client must re-derive and remove **every branch's**
//! scripthash for each slid index — a trailing index sheds `branches` scripts,
//! not one. A client that removes only one branch per index leaks the others'
//! quota as the window advances.

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

/// Expand a descriptor into `(branch, index, scripthash)` tuples for derivation
/// indices `[start, start + count)`. `branch` is the 0-based BIP-389 multipath
/// branch (`<0;1>` → external = 0, change = 1; always 0 for a single-path
/// descriptor); `index` is the absolute derivation index. Together they are the
/// exact coordinate the match path attributes back to the client — no positional
/// arithmetic, correct for fixed and multipath descriptors alike.
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
) -> Result<Vec<(u32, u32, Scripthash)>, DescriptorError> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .map_err(|e| DescriptorError::Parse(e.to_string()))?;
    // BIP-389: a multipath descriptor packs N single-path branches into one
    // string. `at_derivation_index` can't derive it directly, so split it
    // first and expand each branch independently. A non-multipath descriptor
    // is its own single branch.
    //
    // Bound the branch count BEFORE splitting. The `<a;b;…>` element count is
    // unbounded at parse time, and `into_single_descriptors` clones the whole
    // descriptor once per branch — O(branches²) time and space — so capping
    // after the split would let a single `<0;1;…;N>` message (N limited only by
    // the ~MB ingress size) drive a multi-GB, quadratic-time blowup on the
    // events runtime. `multipath_branch_count` reads the element count in O(keys)
    // without cloning, so the split only ever runs for an already-bounded count.
    let branches = multipath_branch_count(&descriptor);
    if branches > MAX_DESCRIPTOR_BRANCHES {
        return Err(DescriptorError::TooManyBranches {
            branches,
            max: MAX_DESCRIPTOR_BRANCHES,
        });
    }
    let single = if descriptor.is_multipath() {
        descriptor
            .into_single_descriptors()
            .map_err(|e| DescriptorError::Parse(format!("multipath split: {e}")))?
    } else {
        vec![descriptor]
    };
    let mut out = Vec::new();
    for (branch, branch_desc) in single.iter().enumerate() {
        expand_single(branch_desc, branch as u32, start, count, &mut out)?;
    }
    Ok(out)
}

/// Number of branches a descriptor would split into: the length of its BIP-389
/// multipath list (`<a;b;…>`), or 1 for a single-path descriptor. Computed by
/// reading each key's derivation-path count — no cloning, no splitting — so it
/// can bound the branch count before paying the O(branches²) cost of
/// [`Descriptor::into_single_descriptors`]. Takes the max over keys: BIP-389
/// requires every multipath key in a descriptor to share one length, but a
/// malformed descriptor with mismatched lengths still gets bounded by its
/// largest, and `into_single_descriptors` rejects the mismatch later.
fn multipath_branch_count(desc: &Descriptor<DescriptorPublicKey>) -> usize {
    let mut max = 1usize;
    desc.for_each_key(|k| {
        if let DescriptorPublicKey::MultiXPub(x) = k {
            max = max.max(x.derivation_paths.paths().len());
        }
        true
    });
    max
}

/// Expand one single-path (non-multipath) descriptor over `[start, start+count)`,
/// appending `(branch, index, scripthash)` tuples to `out`. `branch` is the
/// caller-assigned multipath branch position this single descriptor came from.
fn expand_single(
    descriptor: &Descriptor<DescriptorPublicKey>,
    branch: u32,
    start: u32,
    count: u32,
    out: &mut Vec<(u32, u32, Scripthash)>,
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
        out.push((branch, idx, sh));
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
        // A single-path descriptor is all branch 0; indices are sequential.
        for (i, (branch, idx, _)) in out.iter().enumerate() {
            assert_eq!(*branch, 0);
            assert_eq!(*idx, i as u32);
        }
        // Each derived script is distinct.
        let mut hashes: Vec<_> = out.iter().map(|(_, _, sh)| *sh).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 5, "derived scripthashes must be distinct");
    }

    #[test]
    fn ranged_expansion_is_deterministic_and_windowed() {
        let a = expand_descriptor(RANGED_WPKH, 0, 3).unwrap();
        let b = expand_descriptor(RANGED_WPKH, 0, 3).unwrap();
        assert_eq!(a, b, "same descriptor + window → same scripthashes");
        // A shifted window starts where asked (tuple is (branch, index, sh)).
        let shifted = expand_descriptor(RANGED_WPKH, 10, 2).unwrap();
        assert_eq!(shifted[0].1, 10);
        assert_eq!(shifted[1].1, 11);
        // Index 0 in window-from-0 differs from index 10.
        assert_ne!(a[0].2, shifted[0].2);
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

        // Branch order is load-bearing for the sliding window: branch[0] must
        // be `/0/*` (external) and branch[1] `/1/*` (change), each byte-identical
        // to its equivalent single-path descriptor. This pins the order
        // `into_single_descriptors` yields.
        let single0 = expand_descriptor(RANGED_WPKH, 0, 5).unwrap();
        let single1 = expand_descriptor(
            "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/1/*)",
            0,
            5,
        )
        .unwrap();
        // Compare (index, scripthash) — the single-path expansions are branch 0,
        // while `out`'s branches are 0 and 1 (that branch tag is the whole point).
        let ix = |v: &[(u32, u32, Scripthash)]| -> Vec<(u32, Scripthash)> {
            v.iter().map(|(_, i, s)| (*i, *s)).collect()
        };
        assert_eq!(ix(&out[..5]), ix(&single0), "first branch == /0/* single-path");
        assert_eq!(ix(&out[5..]), ix(&single1), "second branch == /1/* single-path");
        assert!(out[..5].iter().all(|(b, _, _)| *b == 0), "first 5 are branch 0");
        assert!(out[5..].iter().all(|(b, _, _)| *b == 1), "last 5 are branch 1");
        assert_ne!(
            ix(&out[..5]),
            ix(&out[5..]),
            "external and change branches derive distinct scripts"
        );

        // All ten scripthashes are distinct (no branch/index collision).
        let mut hashes: Vec<_> = out.iter().map(|(_, _, sh)| *sh).collect();
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
    fn over_cap_multipath_rejected_before_split() {
        // A large multipath list must be counted and rejected via
        // `multipath_branch_count` WITHOUT calling `into_single_descriptors`
        // (which is O(branches²) and the unbounded element count is the DoS
        // vector). We can't time it here, but assert the count is read directly
        // off the parsed key and surfaced exactly, for any list length.
        let big = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1;2;3;4;5;6;7>/*)";
        assert!(matches!(
            expand_descriptor(big, 0, 5),
            Err(DescriptorError::TooManyBranches { branches: 8, max: 2 })
        ));
        // And the cheap counter agrees with the parsed descriptor.
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(big).unwrap();
        assert_eq!(multipath_branch_count(&parsed), 8);
        let single = Descriptor::<DescriptorPublicKey>::from_str(RANGED_WPKH).unwrap();
        assert_eq!(multipath_branch_count(&single), 1, "single-path counts as 1");
    }

    #[test]
    fn multipath_fixed_yields_one_entry_per_branch() {
        // A multipath descriptor with no wildcard resolves to one script per
        // branch (count ignored beyond the first), i.e. exactly 2 entries.
        let fixed = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1>/0)";
        let out = expand_descriptor(fixed, 0, 20).expect("expand fixed multipath");
        assert_eq!(out.len(), 2, "one script per branch, count ignored");
        // The branch tag is explicit — the exact case the old positional
        // window_offset formula (offset/gap_limit) got wrong.
        assert_eq!((out[0].0, out[0].1), (0, 0), "branch 0 at index 0");
        assert_eq!((out[1].0, out[1].1), (1, 0), "branch 1 at index 0");
        assert_ne!(out[0].2, out[1].2, "the two branches derive distinct scripts");
    }

    #[test]
    fn multipath_taproot_expands_both_branches() {
        // Splitting must work across descriptor types, not just wpkh: a tr()
        // multipath exercises a different script_pubkey/derivation path.
        let tr = "tr(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1>/*)";
        let out = expand_descriptor(tr, 0, 4).expect("expand tr multipath");
        assert_eq!(out.len(), 8, "2 branches × window of 4");
        let mut hashes: Vec<_> = out.iter().map(|(_, _, sh)| *sh).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 8, "all taproot scripthashes distinct");
    }

    #[test]
    fn multipath_huge_start_aborts_whole_install() {
        // The partial-install guard under the per-branch loop: a `start` past
        // the non-hardened range makes derivation error; `expand_descriptor`
        // must return Err for the whole descriptor (nothing half-installed),
        // exactly like the single-path `huge_start_does_not_panic` case.
        let r = expand_descriptor(MULTIPATH_WPKH, u32::MAX - 1, 3);
        assert!(matches!(r, Err(DescriptorError::Derive(_, _))), "got: {r:?}");
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
