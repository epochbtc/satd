//! AssumeUTXO snapshot anchor table.
//!
//! Each [`AssumeUtxoData`] entry is a hardcoded `(height, blockhash,
//! nchaintx, hash_serialized_3)` tuple that satd trusts as a known-good
//! UTXO snapshot. The table is copied verbatim from Bitcoin Core's
//! `src/kernel/chainparams.cpp m_assumeutxo_data` so users who download
//! Core's published snapshot files can load them into satd via
//! `loadtxoutset` (PR 5/5) without satd hosting anything.
//!
//! ## What `hash_serialized_3` actually is
//!
//! It is **NOT** the SHA-256 of the snapshot file. Running
//! `sha256sum utxo-840000.dat` does **not** produce this value.
//!
//! It is Core's `HASH_SERIALIZED_3` UTXO-set hash: a single SHA-256
//! over a concatenation of `TxOutSer(outpoint, coin)` for every coin
//! in the UTXO set (in `(txid, vout)` ascending key order). The
//! per-coin contribution is:
//!
//! - `outpoint` (36 bytes: 32-byte txid + 4-byte vout LE)
//! - `uint32 LE: (height << 1) | coinbase` — fixed-width, NOT a varint
//! - `int64 LE` amount + `CompactSize(script.len())` + raw script
//!
//! See `bitcoin/bitcoin@HEAD:src/kernel/coinstats.cpp:TxOutSer` and
//! the satd implementation in
//! [`crate::storage::compressed_coin::write_txout_ser`].
//!
//! Both Core's `dumptxoutset` RPC and satd's `dumptxoutset` RPC return
//! this value under the field name `txoutset_hash`. The same value is
//! what Core's `loadtxoutset` (and satd's PR 5/5) computes during
//! snapshot load and compares against this table to validate that the
//! loaded snapshot matches a known-good anchor.
//!
//! ## Hex byte order
//!
//! Both `blockhash` and `hash_serialized_3` are quoted in Core's source
//! in the form that displays "naturally" to humans:
//!
//! - `blockhash`: rust-bitcoin's `BlockHash: FromStr` parses the
//!   reversed (display) hex order — same as `bitcoin-cli` output —
//!   which is what Core's source quotes.
//! - `hash_serialized_3`: stored byte-for-byte in natural order. The
//!   internal SHA-256 finalization produces these bytes directly.
//!
//! ## Relationship to checkpoints
//!
//! Conceptually distinct from [`super::checkpoints`]: checkpoints
//! reject headers at known-bad heights; AssumeUTXO anchors authorize
//! snapshot loads. Different semantics, different consumer, kept in a
//! separate module to avoid misreads.

use bitcoin::{BlockHash, Network};

/// Hardcoded snapshot anchor. See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssumeUtxoData {
    /// Height of the snapshot's "base block".
    pub height: u32,
    /// Block hash at `height`. Used to validate that satd's header
    /// chain agrees with the snapshot's claimed base before loading.
    pub blockhash: BlockHash,
    /// Cumulative transaction count through (and including) the base
    /// block. Seeds `getchaintxstats` for AssumeUTXO-bootstrapped
    /// nodes that don't yet have the pre-snapshot block index walked.
    pub nchaintx: u64,
    /// Bitcoin Core's `hash_serialized_3` over the snapshot's UTXO
    /// set (single SHA-256 over the `TxOutSer` stream from
    /// `kernel/coinstats.cpp`). See module docs.
    ///
    /// **This is NOT `sha256sum` of the snapshot file.** PR 5/5's
    /// `loadtxoutset` recomputes this hash from the loaded UTXO set
    /// and refuses to activate if it doesn't match. Operators do not
    /// hash the file directly — the file SHA-256 is unrelated.
    pub hash_serialized_3: [u8; 32],
}

/// Per-network anchor table. Entries are sorted by `height` ascending.
/// Networks without anchors (signet, regtest, testnet) return empty.
/// Computed once per call — the inner data lives in static memory.
pub fn assumeutxo_for_network(network: Network) -> Vec<AssumeUtxoData> {
    match network {
        Network::Bitcoin => mainnet_anchors(),
        _ => Vec::new(),
    }
}

/// Look up an anchor by block hash. Returns `None` if `blockhash` is
/// not a recognized AssumeUTXO base for `network`.
pub fn lookup_by_blockhash(network: Network, blockhash: &BlockHash) -> Option<AssumeUtxoData> {
    assumeutxo_for_network(network)
        .into_iter()
        .find(|d| &d.blockhash == blockhash)
}

/// Look up an anchor by height. Useful for "do we have a snapshot
/// available at height N?" queries from operator tooling.
pub fn lookup_by_height(network: Network, height: u32) -> Option<AssumeUtxoData> {
    assumeutxo_for_network(network)
        .into_iter()
        .find(|d| d.height == height)
}

fn decode_sha256(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hash_serialized_3 hex literal");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn decode_blockhash(hex_str: &str) -> BlockHash {
    hex_str
        .parse()
        .expect("invalid AssumeUTXO blockhash hex literal")
}

// ---------------------------------------------------------------------------
// Mainnet — copied verbatim from Bitcoin Core master at the time of writing.
// Reference: `bitcoin/bitcoin@HEAD:src/kernel/chainparams.cpp` —
// `CMainParams::m_assumeutxo_data`. Keep in sync with Core's master at PR
// review time; values must match byte-for-byte.
// ---------------------------------------------------------------------------

fn mainnet_anchors() -> Vec<AssumeUtxoData> {
    vec![
        AssumeUtxoData {
            height: 840_000,
            blockhash: decode_blockhash(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
            ),
            nchaintx: 991_032_194,
            hash_serialized_3: decode_sha256(
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
            ),
        },
        AssumeUtxoData {
            height: 880_000,
            blockhash: decode_blockhash(
                "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
            ),
            nchaintx: 1_145_604_538,
            hash_serialized_3: decode_sha256(
                "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
            ),
        },
        AssumeUtxoData {
            height: 910_000,
            blockhash: decode_blockhash(
                "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
            ),
            nchaintx: 1_226_586_151,
            hash_serialized_3: decode_sha256(
                "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
            ),
        },
        AssumeUtxoData {
            height: 935_000,
            blockhash: decode_blockhash(
                "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
            ),
            nchaintx: 1_305_397_408,
            hash_serialized_3: decode_sha256(
                "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_has_at_least_one_anchor() {
        let anchors = assumeutxo_for_network(Network::Bitcoin);
        assert!(!anchors.is_empty(), "mainnet should ship with anchors");
    }

    #[test]
    fn anchors_sorted_by_height_ascending() {
        let anchors = assumeutxo_for_network(Network::Bitcoin);
        let heights: Vec<u32> = anchors.iter().map(|a| a.height).collect();
        let mut sorted = heights.clone();
        sorted.sort_unstable();
        assert_eq!(heights, sorted, "anchors must be height-sorted");
    }

    #[test]
    fn heights_are_unique() {
        let anchors = assumeutxo_for_network(Network::Bitcoin);
        let heights: std::collections::HashSet<u32> =
            anchors.iter().map(|a| a.height).collect();
        assert_eq!(heights.len(), anchors.len());
    }

    #[test]
    fn anchor_blockhashes_are_unique() {
        let anchors = assumeutxo_for_network(Network::Bitcoin);
        let hashes: std::collections::HashSet<BlockHash> =
            anchors.iter().map(|a| a.blockhash).collect();
        assert_eq!(hashes.len(), anchors.len(), "duplicate anchor blockhash");
    }

    /// Pin EVERY mainnet anchor's full content against Bitcoin Core
    /// master verbatim. A typo in any of the hex literals would
    /// previously panic only on the first runtime lookup; this test
    /// catches the typo in CI before the binary ships.
    #[test]
    fn all_mainnet_anchors_match_core_master() {
        let anchors = assumeutxo_for_network(Network::Bitcoin);
        let expected: &[(u32, &str, u64, &str)] = &[
            (
                840_000,
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
                991_032_194,
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
            ),
            (
                880_000,
                "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
                1_145_604_538,
                "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
            ),
            (
                910_000,
                "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
                1_226_586_151,
                "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
            ),
            (
                935_000,
                "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
                1_305_397_408,
                "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
            ),
        ];
        assert_eq!(
            anchors.len(),
            expected.len(),
            "anchor count drift between satd and Core"
        );
        for (i, (h, bh, n, hs)) in expected.iter().enumerate() {
            assert_eq!(anchors[i].height, *h, "anchor #{i} height");
            assert_eq!(
                anchors[i].blockhash.to_string(),
                *bh,
                "anchor #{i} ({h}) blockhash"
            );
            assert_eq!(anchors[i].nchaintx, *n, "anchor #{i} ({h}) nchaintx");
            assert_eq!(
                hex::encode(anchors[i].hash_serialized_3),
                *hs,
                "anchor #{i} ({h}) hash_serialized_3"
            );
        }
    }

    #[test]
    fn lookup_by_blockhash_finds_known_anchor() {
        let hash: BlockHash =
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                .parse()
                .unwrap();
        let a = lookup_by_blockhash(Network::Bitcoin, &hash).expect("found");
        assert_eq!(a.height, 840_000);
    }

    #[test]
    fn lookup_by_blockhash_finds_each_anchor() {
        // Defense-in-depth: every anchor must be reachable via its
        // blockhash. Catches a copy-paste error where two AssumeUtxoData
        // entries share the same hash (also caught by
        // `anchor_blockhashes_are_unique`, but having a positive lookup
        // test in addition to the negative-uniqueness one is cheap).
        for anchor in assumeutxo_for_network(Network::Bitcoin) {
            let found = lookup_by_blockhash(Network::Bitcoin, &anchor.blockhash)
                .expect("lookup_by_blockhash must find every anchor");
            assert_eq!(found.height, anchor.height);
        }
    }

    #[test]
    fn lookup_by_blockhash_returns_none_for_unknown() {
        let hash: BlockHash =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        assert!(lookup_by_blockhash(Network::Bitcoin, &hash).is_none());
    }

    #[test]
    fn non_mainnet_networks_have_no_anchors() {
        for net in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert!(
                assumeutxo_for_network(net).is_empty(),
                "{net:?} should have no AssumeUTXO anchors"
            );
        }
    }
}
