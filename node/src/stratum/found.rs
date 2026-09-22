//! A durable copy of every block a miner finds, written before it is
//! submitted.
//!
//! A block with valid proof of work is the one thing a solo miner cannot make
//! again. If this node refuses it — a consensus divergence, a panic in block
//! acceptance, a disk error part way through connecting — the block is still
//! worth submitting to another node, but only if something kept it. The
//! submission path holds it in memory alone, so it is saved first:
//! `<dir>/<height>-<hash>.hex`, the consensus serialization as one line of hex,
//! which is exactly what `submitblock` takes.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bitcoin::Block;

/// The file a found block at `height` is saved to under `dir`.
pub fn found_block_path(dir: &Path, height: u32, block: &Block) -> PathBuf {
    dir.join(format!("{height}-{}.hex", block.block_hash()))
}

/// Save `block` under `dir`, creating the directory if needed.
///
/// Written to a temporary file, synced, renamed into place and the directory
/// synced, so the file either holds the whole block or does not exist.
pub fn save_found_block(dir: &Path, height: u32, block: &Block) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = found_block_path(dir, height, block);
    let tmp = path.with_extension("hex.tmp");
    {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        f.write_all(hex::encode(bitcoin::consensus::serialize(block)).as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    // The rename is durable only once the directory entry is.
    File::open(dir)?.sync_all()?;
    Ok(path)
}

/// Save `block` (when `dir` is set), then hand it to `submit`.
///
/// Saving comes first so that a submission that fails, or panics, still
/// leaves the block on disk. A save that fails is logged and does not stop
/// the submission: the chance to connect the block matters more than the
/// copy. Returns where the block was saved alongside `submit`'s result.
pub fn save_then_submit<T>(
    dir: Option<&Path>,
    height: u32,
    block: &Block,
    submit: impl FnOnce(&Block) -> T,
) -> (Option<PathBuf>, T) {
    let saved = dir.and_then(|dir| match save_found_block(dir, height, block) {
        Ok(path) => {
            tracing::info!(
                target: "node::stratum",
                height,
                hash = %block.block_hash(),
                path = %path.display(),
                "Stratum found block saved; submitting it"
            );
            Some(path)
        }
        Err(e) => {
            tracing::error!(
                target: "node::stratum",
                height,
                hash = %block.block_hash(),
                dir = %dir.display(),
                error = %e,
                "could not save the found block; submitting it anyway"
            );
            None
        }
    });
    (saved, submit(block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Witness,
    };

    fn block(nonce: u32) -> Block {
        let coinbase = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x02, 0x03]),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[0u8; 32]]),
            }],
            output: vec![TxOut { value: Amount::from_sat(50), script_pubkey: ScriptBuf::new() }],
        };
        Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce,
            },
            txdata: vec![coinbase],
        }
    }

    fn read_back(path: &Path) -> Block {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.ends_with('\n'), "one line, as submitblock -stdin reads it");
        bitcoin::consensus::deserialize(&hex::decode(text.trim_end()).unwrap()).unwrap()
    }

    /// The case the copy exists for: the node refuses the block. It must be on
    /// disk, whole, and saved before the submitter ran.
    #[test]
    fn a_refused_block_is_still_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let found = dir.path().join("stratum").join("found");
        let b = block(7);
        let (saved, outcome) = save_then_submit(Some(&found), 968_181, &b, |blk| {
            let path = found_block_path(&found, 968_181, blk);
            assert!(path.exists(), "saved before submission");
            Err::<bool, _>("bad-cb-amount".to_string())
        });
        assert!(outcome.is_err());
        let path = saved.expect("saved");
        assert_eq!(path, found.join(format!("968181-{}.hex", b.block_hash())));
        assert_eq!(read_back(&path), b);
        assert!(!path.with_extension("hex.tmp").exists(), "no temporary file left behind");
    }

    /// A panic in block acceptance loses nothing either.
    #[test]
    fn a_submission_that_panics_leaves_the_block_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let b = block(8);
        let result = std::panic::catch_unwind(|| {
            save_then_submit(Some(dir.path()), 5, &b, |_| -> bool { panic!("accept_block panicked") })
        });
        assert!(result.is_err());
        assert_eq!(read_back(&found_block_path(dir.path(), 5, &b)), b);
    }

    #[test]
    fn an_accepted_block_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let b = block(9);
        let (saved, outcome) = save_then_submit(Some(dir.path()), 6, &b, |_| Ok::<bool, String>(true));
        assert_eq!(outcome, Ok(true));
        assert_eq!(read_back(&saved.unwrap()), b);
    }

    /// A directory that cannot be written costs the copy, not the block.
    #[test]
    fn a_failed_save_still_submits() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"").unwrap();
        let b = block(10);
        let mut submitted = false;
        let (saved, ()) = save_then_submit(Some(&blocker.join("found")), 7, &b, |_| submitted = true);
        assert!(saved.is_none());
        assert!(submitted, "the block was submitted although it could not be saved");
    }

    #[test]
    fn no_directory_submits_without_saving() {
        let b = block(11);
        let (saved, outcome) = save_then_submit(None, 8, &b, |_| 42);
        assert!(saved.is_none());
        assert_eq!(outcome, 42);
    }
}
