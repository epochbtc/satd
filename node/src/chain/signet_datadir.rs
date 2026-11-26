//! Which signet an old `signet/` directory holds (#1271).
//!
//! A custom signet (`-signetchallenge`) has a data directory of its own,
//! `signet_<message start>`, as in Bitcoin Core's `GetSignetDataDir`
//! (bitcoin/bitcoin#34566). Before that, satd kept every signet in
//! `signet/`. When a custom signet's directory does not exist yet, startup
//! looks in `signet/` to see whether it holds this signet's chain, so the
//! node can refuse and say how to move it instead of syncing again from
//! genesis. Core does not look: its release note asks custom-signet users to
//! rename the directory themselves.
//!
//! Nothing here writes. The chainstate is opened read-only and the tip
//! block is read straight from its block file.

use std::path::{Path, PathBuf};

use bitcoin::{Block, BlockHash, Network};

use crate::storage::flatfile::{FlatFilePos, read_record_read_only};
use crate::storage::rocksdb_store::read_tip_read_only;
use crate::validation::signet::{DEFAULT_SIGNET_CHALLENGE, check_signet_block_solution};

/// What an old `signet/` directory holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignetDirContents {
    /// No tip, or the tip is genesis, which every signet shares.
    Genesis,
    /// The default signet: the tip's solution satisfies the default
    /// challenge.
    DefaultSignet,
    /// This custom signet: the tip's solution fails the default challenge
    /// and satisfies the configured one. `blocks_dir` is the candidate that
    /// held the tip block.
    ThisSignet {
        height: u32,
        hash: BlockHash,
        blocks_dir: PathBuf,
    },
    /// Some other signet: the tip's solution satisfies neither challenge.
    OtherSignet,
    /// The chainstate or the tip block could not be read.
    Unreadable(String),
}

/// Read the tip of the chainstate in `chainstate_dir` and check its signet
/// solution against the default challenge and `challenge`. The tip block is
/// looked for in each of `blocks_dirs` in turn: where the blocks were
/// depends on the `-blocksdir` the old directory ran with, which need not be
/// this start's.
pub fn inspect(
    chainstate_dir: &Path,
    blocks_dirs: &[PathBuf],
    challenge: &[u8],
) -> SignetDirContents {
    let (hash, entry) = match read_tip_read_only(chainstate_dir) {
        Ok(Some(tip)) => tip,
        Ok(None) => return SignetDirContents::Genesis,
        Err(e) => return SignetDirContents::Unreadable(format!("chainstate: {e}")),
    };
    if entry.height == 0 {
        return SignetDirContents::Genesis;
    }
    let pos = FlatFilePos {
        file_number: entry.file_number,
        data_pos: entry.data_pos,
    };
    let mut errors = Vec::new();
    let mut found = None;
    for dir in blocks_dirs {
        let block: Result<Block, String> = read_record_read_only(dir, &pos)
            .map_err(|e| e.to_string())
            .and_then(|raw| bitcoin::consensus::deserialize(&raw).map_err(|e| e.to_string()));
        match block {
            Ok(b) if b.block_hash() == hash => {
                found = Some((b, dir.clone()));
                break;
            }
            Ok(b) => errors.push(format!("{}: holds block {}", dir.display(), b.block_hash())),
            Err(e) => errors.push(format!("{}: {e}", dir.display())),
        }
    }
    let Some((block, blocks_dir)) = found else {
        return SignetDirContents::Unreadable(format!(
            "tip block {hash} not found ({})",
            errors.join("; ")
        ));
    };
    let genesis = bitcoin::constants::genesis_block(Network::Signet).block_hash();
    if check_signet_block_solution(&block, &DEFAULT_SIGNET_CHALLENGE, genesis).is_ok() {
        SignetDirContents::DefaultSignet
    } else if check_signet_block_solution(&block, challenge, genesis).is_ok() {
        SignetDirContents::ThisSignet {
            height: entry.height,
            hash,
            blocks_dir,
        }
    } else {
        SignetDirContents::OtherSignet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::flatfile::FlatFileManager;
    use crate::storage::profile::StorageTuning;
    use crate::storage::rocksdb_store::RocksDbStore;
    use crate::storage::{Store, StoreBatch};
    use crate::validation::signet::fixtures::default_signet_block;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::consensus::serialize;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
        absolute, block, transaction,
    };

    /// A signet-shaped block whose coinbase has a witness commitment and no
    /// signet solution: an `OP_TRUE` challenge accepts it, the default one
    /// does not.
    fn op_true_signet_block() -> Block {
        let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment.extend([0u8; 32]);
        let coinbase = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(1).push_int(0).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment),
            }],
        };
        Block {
            header: block::Header {
                version: block::Version::from_consensus(0x20000000),
                prev_blockhash: bitcoin::constants::genesis_block(Network::Signet).block_hash(),
                merkle_root: TxMerkleNode::from_raw_hash(coinbase.compute_txid().to_raw_hash()),
                time: 1_700_000_000,
                bits: bitcoin::CompactTarget::from_consensus(0x1e0377ae),
                nonce: 0,
            },
            txdata: vec![coinbase],
        }
    }

    /// A chainstate whose tip is `block` at `height`, its record in
    /// `<dir>/blocks`. `None` writes no tip.
    fn signet_dir(block: Option<(&Block, u32)>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open_at(
            &dir.path().join("chainstate"),
            false,
            16,
            false,
            64,
            StorageTuning::default(),
        )
        .unwrap();
        if let Some((block, height)) = block {
            let mut flat = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
            let pos = flat
                .write_block(&serialize(block), [0x0a, 0x03, 0xcf, 0x40], height)
                .unwrap();
            flat.sync_all().unwrap();
            let mut batch = StoreBatch::default();
            batch.block_index_puts.push((
                block.block_hash(),
                BlockIndexEntry {
                    header: block.header,
                    height,
                    status: BlockStatus::Valid,
                    num_tx: block.txdata.len() as u32,
                    file_number: pos.file_number,
                    data_pos: pos.data_pos,
                    chainwork: [0u8; 32],
                },
            ));
            batch.tip = Some(block.block_hash());
            store.write_batch(batch).unwrap();
        }
        drop(store);
        dir
    }

    fn look(dir: &tempfile::TempDir, challenge: &[u8]) -> SignetDirContents {
        inspect(
            &dir.path().join("chainstate"),
            &[dir.path().join("blocks")],
            challenge,
        )
    }

    /// #1271: the tip's solution tells which signet an old `signet/` holds.
    ///
    /// The default signet's solutions are scriptSig pushes, which `OP_TRUE`
    /// accepts too, so the default challenge has to be checked first.
    ///
    /// Perturbation: drop the default-challenge check and the default
    /// signet's directory reads as `ThisSignet`.
    #[test]
    fn the_tip_solution_tells_which_signet_a_directory_holds() {
        let op_true = [0x51];
        let custom = op_true_signet_block();
        let dir = signet_dir(Some((&custom, 1)));
        assert_eq!(
            look(&dir, &op_true),
            SignetDirContents::ThisSignet {
                height: 1,
                hash: custom.block_hash(),
                blocks_dir: dir.path().join("blocks"),
            }
        );
        // The blocks are found wherever they are among the candidates: a
        // `-blocksdir` added or dropped since the old directory ran.
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(matches!(
            inspect(
                &dir.path().join("chainstate"),
                &[elsewhere.path().to_path_buf(), dir.path().join("blocks")],
                &op_true
            ),
            SignetDirContents::ThisSignet { blocks_dir, .. } if blocks_dir == dir.path().join("blocks")
        ));
        // OP_FALSE accepts nothing: some other signet's chain.
        assert_eq!(look(&dir, &[0x00]), SignetDirContents::OtherSignet);

        let default = signet_dir(Some((&default_signet_block(2), 2)));
        assert_eq!(look(&default, &op_true), SignetDirContents::DefaultSignet);

        let genesis = bitcoin::constants::genesis_block(Network::Signet);
        assert_eq!(
            look(&signet_dir(Some((&genesis, 0))), &op_true),
            SignetDirContents::Genesis
        );
        assert_eq!(
            look(&signet_dir(None), &op_true),
            SignetDirContents::Genesis
        );

        // The tip's block file is gone: unreadable, never a guess.
        std::fs::remove_dir_all(dir.path().join("blocks")).unwrap();
        assert!(matches!(
            look(&dir, &op_true),
            SignetDirContents::Unreadable(_)
        ));
    }

    /// The look is read-only: nothing in the directory changes.
    #[test]
    fn inspecting_writes_nothing() {
        let dir = signet_dir(Some((&op_true_signet_block(), 1)));
        let listing = |p: &Path| {
            let mut v: Vec<_> = walk(p);
            v.sort();
            v
        };
        let before = listing(dir.path());
        let _ = look(&dir, &[0x51]);
        assert_eq!(listing(dir.path()), before);
    }

    fn walk(p: &Path) -> Vec<(std::path::PathBuf, u64, Option<std::time::SystemTime>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            let md = e.metadata().unwrap();
            if md.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push((path, md.len(), md.modified().ok()));
            }
        }
        out
    }
}
