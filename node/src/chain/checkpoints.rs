use bitcoin::BlockHash;
use bitcoin::Network;

/// A checkpoint: a known-good block hash at a specific height.
/// During IBD, if a block at a checkpoint height has a different hash,
/// it is rejected. This prevents long-range attacks.
pub struct Checkpoint {
    pub height: u32,
    pub hash: BlockHash,
}

/// Return hardcoded checkpoints for the given network.
pub fn checkpoints_for_network(network: Network) -> Vec<Checkpoint> {
    match network {
        Network::Signet => signet_checkpoints(),
        Network::Bitcoin => mainnet_checkpoints(),
        _ => Vec::new(),
    }
}

fn signet_checkpoints() -> Vec<Checkpoint> {
    // Signet checkpoints verified from mempool.space and blockstream.info APIs.
    parse_checkpoints(&[
        (0, "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
        (50_000, "000000f43b569ea4bdce85a92e8140e90049d6efbffd95c1b6e80de4e397cb01"),
        (100_000, "0000008753108390007b3f5c26e5d924191567e147876b84489b0c0cf133a0bf"),
        (150_000, "0000013d778ba3f914530f11f6b69869c9fab54acff85acd7b8201d111f19b7f"),
        (200_000, "0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c"),
    ])
}

fn mainnet_checkpoints() -> Vec<Checkpoint> {
    // From Bitcoin Core's chainparams.cpp — well-known mainnet checkpoints.
    parse_checkpoints(&[
        (0, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        (11111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
        (33333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
        (74000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
        (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
        (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
        (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
        (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
        (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
        (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
        (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
        (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
        (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
        (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"),
    ])
}

fn parse_checkpoints(data: &[(u32, &str)]) -> Vec<Checkpoint> {
    data.iter()
        .filter_map(|(height, hash_hex)| {
            let hash: BlockHash = hash_hex.parse().ok()?;
            Some(Checkpoint {
                height: *height,
                hash,
            })
        })
        .collect()
}

/// Check if a block at the given height violates any checkpoint.
/// Returns `true` if the block is valid (no checkpoint mismatch).
/// Returns `false` if the block's hash doesn't match the checkpoint at that height.
pub fn check_against_checkpoints(
    height: u32,
    hash: &BlockHash,
    checkpoints: &[Checkpoint],
) -> bool {
    for cp in checkpoints {
        if cp.height == height {
            return *hash == cp.hash;
        }
    }
    // No checkpoint at this height — block is acceptable
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_checkpoint() {
        let cps = checkpoints_for_network(Network::Bitcoin);
        assert!(!cps.is_empty());
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        assert!(check_against_checkpoints(0, &genesis.block_hash(), &cps));
    }

    #[test]
    fn test_signet_genesis_checkpoint() {
        let cps = checkpoints_for_network(Network::Signet);
        assert!(!cps.is_empty());
        let genesis = bitcoin::constants::genesis_block(Network::Signet);
        assert!(check_against_checkpoints(0, &genesis.block_hash(), &cps));
    }

    #[test]
    fn test_wrong_hash_rejected() {
        let cps = checkpoints_for_network(Network::Bitcoin);
        let fake_hash: BlockHash =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        assert!(!check_against_checkpoints(0, &fake_hash, &cps));
    }

    #[test]
    fn test_non_checkpoint_height_passes() {
        let cps = checkpoints_for_network(Network::Bitcoin);
        let any_hash: BlockHash =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        // Height 42 has no checkpoint, so any hash is fine
        assert!(check_against_checkpoints(42, &any_hash, &cps));
    }

    #[test]
    fn test_regtest_no_checkpoints() {
        let cps = checkpoints_for_network(Network::Regtest);
        assert!(cps.is_empty());
    }
}
