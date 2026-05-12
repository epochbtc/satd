//! AssumeUTXO snapshot anchor table.
//!
//! Each [`AssumeUtxoData`] entry is a hardcoded `(height, blockhash,
//! nchaintx, utxo_set_sha256)` tuple that satd trusts as a known-good
//! UTXO snapshot. The table is copied verbatim from Bitcoin Core's
//! `src/kernel/chainparams.cpp m_assumeutxo_data` so users who download
//! Core's published snapshot files can load them into satd via
//! `loadtxoutset` (PR 5/5) without satd hosting anything.
//!
//! When updating: copy values directly from Core's master branch at
//! `kernel/chainparams.cpp` and verify the hex strings byte-by-byte.
//! Both `blockhash` and `utxo_set_sha256` are stored in natural hex
//! order in Core's source; `BlockHash: FromStr` parses block hashes
//! in **display** order (which is what Core's source quotes), and
//! `assumeutxo_hash` is the SHA-256 of the snapshot file in natural
//! byte order (matches `sha256sum`).
//!
//! Conceptually distinct from [`super::checkpoints`]: checkpoints
//! reject headers at known-bad heights; AssumeUTXO anchors authorize
//! snapshot loads. They share no semantics or merge logic.

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
    /// SHA-256 of the snapshot file (matches `sha256sum`). Operators
    /// verify this before calling `loadtxoutset`.
    pub utxo_set_sha256: [u8; 32],
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
    let bytes = hex::decode(hex_str).expect("invalid assumeutxo_hash hex literal");
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
            utxo_set_sha256: decode_sha256(
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
            ),
        },
        AssumeUtxoData {
            height: 880_000,
            blockhash: decode_blockhash(
                "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
            ),
            nchaintx: 1_145_604_538,
            utxo_set_sha256: decode_sha256(
                "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
            ),
        },
        AssumeUtxoData {
            height: 910_000,
            blockhash: decode_blockhash(
                "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
            ),
            nchaintx: 1_226_586_151,
            utxo_set_sha256: decode_sha256(
                "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
            ),
        },
        AssumeUtxoData {
            height: 935_000,
            blockhash: decode_blockhash(
                "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
            ),
            nchaintx: 1_305_397_408,
            utxo_set_sha256: decode_sha256(
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

    #[test]
    fn mainnet_840000_anchor_matches_core() {
        // Sentinel: if a typo creeps in, `cargo test` catches it before
        // the binary ships. Hex strings copied verbatim from Bitcoin
        // Core's master `kernel/chainparams.cpp`.
        let a = lookup_by_height(Network::Bitcoin, 840_000)
            .expect("840000 anchor must be present");
        assert_eq!(a.nchaintx, 991_032_194);
        assert_eq!(
            a.blockhash.to_string(),
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
        );
        assert_eq!(
            hex::encode(a.utxo_set_sha256),
            "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
        );
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
