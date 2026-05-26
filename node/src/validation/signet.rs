//! Signet block-solution validation (BIP 325).
//!
//! Signet replaces proof-of-work difficulty with a block signature: each
//! block carries a "signet solution" in its coinbase that must satisfy a
//! network-wide *challenge* script. This module implements Bitcoin Core's
//! `CheckSignetBlockSolution` so satd can run a custom/private signet
//! specified with `-signetchallenge`.
//!
//! The solution is verified by reconstructing the two virtual
//! transactions BIP 325 defines — `to_spend` (whose single output is the
//! challenge) and `to_sign` (which spends it using the solution's
//! scriptSig + witness) — and running the script interpreter over them.
//! The message that is signed commits to the block's version, previous
//! hash, *modified* merkle root (the solution stripped from the coinbase
//! commitment), and time.

use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::{Builder, Instruction};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::Magic;
use bitcoin::{
    absolute, transaction, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::validation::ValidationError;

/// The 4-byte tag that marks the signet solution pushdata inside the
/// coinbase witness-commitment output (BIP 325).
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// BIP 141 witness-commitment header: `OP_RETURN OP_PUSHBYTES_36 <aa21a9ed…>`.
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Script flags Core applies when checking a signet block solution.
/// Must match Core's `BLOCK_SCRIPT_VERIFY_FLAGS` exactly, or satd could
/// accept a solution Core rejects (consensus divergence on a custom
/// signet): `P2SH | WITNESS | DERSIG | NULLDUMMY`.
fn block_script_verify_flags() -> u32 {
    bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_DERSIG
        | bitcoinconsensus::VERIFY_NULLDUMMY
}

/// Derive the P2P network magic for a signet from its challenge, the way
/// Bitcoin Core does: the first four bytes of `SHA256(challenge)`. For
/// the default signet challenge this reproduces the well-known
/// `0x0a03cf40` magic (asserted in tests).
pub fn signet_magic(challenge: &[u8]) -> Magic {
    // Core hashes the *serialized* challenge (a compact-size length prefix
    // followed by the bytes) with double-SHA256 (`CHashWriter << bin`),
    // then takes the first four bytes.
    let preimage = bitcoin::consensus::serialize(&challenge.to_vec());
    let bytes = sha256d::Hash::hash(&preimage).to_byte_array();
    Magic::from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Locate the witness-commitment output (last coinbase output whose
/// script starts with the BIP 141 header). Returns its index.
fn witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    coinbase
        .output
        .iter()
        .enumerate()
        .rev()
        .find(|(_, o)| {
            let s = o.script_pubkey.as_bytes();
            s.len() >= 38 && s[..6] == WITNESS_COMMITMENT_HEADER
        })
        .map(|(i, _)| i)
}

/// Scan `script` for the signet pushdata (a push whose first bytes are
/// [`SIGNET_HEADER`] and which carries data beyond the header). On the
/// first match, return `(rebuilt_script, solution)` where `solution` is
/// the bytes after the header and `rebuilt_script` is the script with
/// that push truncated to just the header — exactly Core's
/// `FetchAndClearCommitmentSection`. Returns `None` if no signet push is
/// present (Core allows this, e.g. an `OP_TRUE` trivial challenge).
fn fetch_and_clear_signet_section(script: &ScriptBuf) -> Option<(ScriptBuf, Vec<u8>)> {
    let mut builder = Builder::new();
    let mut solution: Option<Vec<u8>> = None;

    for instr in script.instructions() {
        // A malformed script can't carry a valid solution.
        let instr = instr.ok()?;
        match instr {
            Instruction::Op(op) => {
                builder = builder.push_opcode(op);
            }
            Instruction::PushBytes(push) => {
                let bytes = push.as_bytes();
                if solution.is_none()
                    && bytes.len() > SIGNET_HEADER.len()
                    && bytes[..SIGNET_HEADER.len()] == SIGNET_HEADER
                {
                    solution = Some(bytes[SIGNET_HEADER.len()..].to_vec());
                    // Keep only the header in the rebuilt script.
                    builder = builder.push_slice(SIGNET_HEADER);
                } else {
                    // push.as_bytes() is a valid pushable slice.
                    let pb: &bitcoin::script::PushBytes = push;
                    builder = builder.push_slice(pb);
                }
            }
        }
    }

    solution.map(|s| (builder.into_script(), s))
}

/// Double-SHA256 merkle root over `txids` (Bitcoin's odd-node-duplicates
/// rule). Operates on raw 32-byte leaves in internal byte order.
fn merkle_root(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    if layer.is_empty() {
        return [0u8; 32];
    }
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d::Hash::hash(&buf).to_byte_array());
        }
        layer = next;
    }
    layer[0]
}

/// The two virtual transactions of BIP 325.
struct SignetTxs {
    to_spend: Transaction,
    to_sign: Transaction,
}

impl SignetTxs {
    /// Reconstruct the `to_spend`/`to_sign` pair for `block` under
    /// `challenge`. Returns `None` for any structural problem Core treats
    /// as an invalid solution (missing witness commitment, malformed
    /// solution encoding, trailing bytes).
    fn create(block: &Block, challenge: &ScriptBuf) -> Option<SignetTxs> {
        let coinbase = block.txdata.first()?;
        let cidx = witness_commitment_index(coinbase)?;

        // Strip the signet solution out of a modified copy of the coinbase
        // so the signed merkle root commits to everything *except* the
        // signature itself.
        let mut modified_cb = coinbase.clone();
        let mut script_sig = ScriptBuf::new();
        let mut witness = Witness::new();
        if let Some((cleared, solution)) =
            fetch_and_clear_signet_section(&modified_cb.output[cidx].script_pubkey)
        {
            modified_cb.output[cidx].script_pubkey = cleared;
            let mut cursor = solution.as_slice();
            script_sig = ScriptBuf::consensus_decode(&mut cursor).ok()?;
            witness = Witness::consensus_decode(&mut cursor).ok()?;
            // Extraneous trailing data is rejected, like Core.
            if !cursor.is_empty() {
                return None;
            }
        }

        // Modified merkle root: txids, with the coinbase's solution stripped.
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
        leaves.push(modified_cb.compute_txid().to_raw_hash().to_byte_array());
        for tx in &block.txdata[1..] {
            leaves.push(tx.compute_txid().to_raw_hash().to_byte_array());
        }
        let signet_merkle = merkle_root(leaves);

        // The signed message: version || prev || modified-merkle || time.
        let mut block_data = Vec::with_capacity(72);
        block_data.extend_from_slice(&block.header.version.to_consensus().to_le_bytes());
        block_data
            .extend_from_slice(&block.header.prev_blockhash.to_raw_hash().to_byte_array());
        block_data.extend_from_slice(&signet_merkle);
        block_data.extend_from_slice(&block.header.time.to_le_bytes());

        let to_spend = Transaction {
            version: transaction::Version(0),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new()
                    .push_slice::<&bitcoin::script::PushBytes>(
                        block_data.as_slice().try_into().ok()?,
                    )
                    .into_script(),
                sequence: Sequence(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: challenge.clone(),
            }],
        };

        let to_sign = Transaction {
            version: transaction::Version(0),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: to_spend.compute_txid(),
                    vout: 0,
                },
                script_sig,
                sequence: Sequence(0),
                witness,
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            }],
        };

        Some(SignetTxs { to_spend, to_sign })
    }
}

/// Validate a block's signet solution against `challenge` (BIP 325).
///
/// The genesis block is exempt (Core skips it). Any structural or
/// signature failure maps to [`ValidationError::BadSignetSolution`]; the
/// specific reason is logged at debug level.
pub fn check_signet_block_solution(
    block: &Block,
    challenge: &[u8],
    genesis_hash: bitcoin::BlockHash,
) -> Result<(), ValidationError> {
    if block.block_hash() == genesis_hash {
        return Ok(());
    }

    let challenge_script = ScriptBuf::from_bytes(challenge.to_vec());
    let txs = match SignetTxs::create(block, &challenge_script) {
        Some(t) => t,
        None => {
            tracing::debug!("signet: could not reconstruct solution txs");
            return Err(ValidationError::BadSignetSolution);
        }
    };

    let spent = &txs.to_spend.output[0];
    let to_sign_bytes = bitcoin::consensus::serialize(&txs.to_sign);
    let spk = spent.script_pubkey.as_bytes();
    let utxo = bitcoinconsensus::Utxo {
        script_pubkey: spk.as_ptr(),
        script_pubkey_len: spk.len() as u32,
        value: 0,
    };

    match bitcoinconsensus::verify_with_flags(
        spk,
        0,
        &to_sign_bytes,
        Some(&[utxo]),
        0,
        block_script_verify_flags(),
    ) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::debug!(error = ?e, "signet: block solution script verification failed");
            Err(ValidationError::BadSignetSolution)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// The standard public signet challenge (BIP 325 appendix).
    const DEFAULT_SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

    #[test]
    fn default_signet_magic_matches_bitcoin_crate() {
        // Self-check on the magic derivation: SHA256(default challenge)[..4]
        // must equal the well-known default signet magic (0x0a03cf40).
        let challenge =
            <Vec<u8> as bitcoin::hashes::hex::FromHex>::from_hex(DEFAULT_SIGNET_CHALLENGE).unwrap();
        let derived: Vec<u8> = signet_magic(&challenge).to_bytes().to_vec();
        let crate_magic: Vec<u8> = Magic::from(Network::Signet).to_bytes().to_vec();
        assert_eq!(derived, crate_magic, "derived signet magic must match bitcoin crate");
    }

    use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
    use bitcoin::script::PushBytes;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{block, BlockHash, CompactTarget, TxMerkleNode};

    fn push(b: Builder, data: &[u8]) -> Builder {
        let pb: &PushBytes = data.try_into().unwrap();
        b.push_slice(pb)
    }

    /// Build a coinbase whose witness-commitment output optionally carries
    /// an appended signet section (`SIGNET_HEADER || solution`).
    fn coinbase_with_commitment(signet_section: Option<&[u8]>) -> Transaction {
        let mut commit = vec![0xaa, 0x21, 0xa9, 0xed];
        commit.extend_from_slice(&[0u8; 32]); // dummy witness commitment value
        let mut b = push(Builder::new().push_opcode(OP_RETURN), &commit);
        if let Some(sol) = signet_section {
            let mut s = SIGNET_HEADER.to_vec();
            s.extend_from_slice(sol);
            b = push(b, &s);
        }
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(42).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: b.into_script(),
            }],
        }
    }

    fn block_from_coinbase(coinbase: Transaction) -> Block {
        let merkle = TxMerkleNode::from_raw_hash(coinbase.compute_txid().to_raw_hash());
        Block {
            header: block::Header {
                version: block::Version::from_consensus(0x20000000),
                prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
                merkle_root: merkle,
                time: 1_600_000_000,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 0,
            },
            txdata: vec![coinbase],
        }
    }

    fn dummy_genesis() -> BlockHash {
        bitcoin::constants::genesis_block(Network::Signet).block_hash()
    }

    #[test]
    fn op_true_trivial_challenge_accepts_empty_solution() {
        // OP_TRUE challenge: a block with a witness commitment but no
        // signet section validates trivially (Core's documented allowance).
        let challenge = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
        let block = block_from_coinbase(coinbase_with_commitment(None));
        assert!(
            check_signet_block_solution(&block, challenge.as_bytes(), dummy_genesis()).is_ok()
        );
    }

    #[test]
    fn missing_witness_commitment_is_rejected() {
        // No witness commitment output → no place for a solution → invalid.
        let challenge = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
        let coinbase = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(42).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            }],
        };
        let block = block_from_coinbase(coinbase);
        assert!(
            check_signet_block_solution(&block, challenge.as_bytes(), dummy_genesis()).is_err()
        );
    }

    /// End-to-end signature test: build a P2WPKH challenge, sign the BIP 325
    /// message ourselves, embed the solution, and verify. This exercises the
    /// full block_data serialization + modified-merkle path — a bug there
    /// would change the sighash and break verification.
    #[test]
    fn p2wpkh_challenge_round_trips_and_rejects_tampering() {
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk = bitcoin::CompressedPublicKey(sk.public_key(&secp));
        let wpkh = pk.wpubkey_hash();
        let challenge = ScriptBuf::new_p2wpkh(&wpkh);

        // Step 1: block carrying a 4-byte signet-header *placeholder* (no
        // solution bytes). This is what gets signed: Core's
        // FetchAndClearCommitmentSection truncates the final solution push
        // back to exactly this header, so the modified merkle — and hence
        // the signed message — must include the bare header push. (segwit
        // sighash ignores the input's own witness, so the empty-witness
        // to_sign here has the same sighash as the final block.)
        let block_v0 = block_from_coinbase(coinbase_with_commitment(Some(&[])));
        let txs = SignetTxs::create(&block_v0, &challenge).expect("create v0");

        let sighash = SighashCache::new(&txs.to_sign)
            .p2wpkh_signature_hash(0, &challenge, Amount::ZERO, EcdsaSighashType::All)
            .expect("sighash");
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_ser = sig.serialize_der().to_vec();
        sig_ser.push(EcdsaSighashType::All as u8);
        let witness = Witness::from_slice(&[sig_ser, pk.to_bytes().to_vec()]);

        // Solution = serialize(empty scriptSig) || serialize(witness stack).
        let mut solution = bitcoin::consensus::serialize(&ScriptBuf::new());
        solution.extend_from_slice(&bitcoin::consensus::serialize(&witness));

        // Step 2: rebuild the block with the signet section embedded.
        let block = block_from_coinbase(coinbase_with_commitment(Some(&solution)));
        assert!(
            check_signet_block_solution(&block, challenge.as_bytes(), dummy_genesis()).is_ok(),
            "valid signet solution must verify"
        );

        // Tamper: changing the block time changes the signed message, so
        // the existing signature must no longer verify.
        let mut tampered = block.clone();
        tampered.header.time += 1;
        assert!(
            check_signet_block_solution(&tampered, challenge.as_bytes(), dummy_genesis())
                .is_err(),
            "tampering with the signed block data must invalidate the solution"
        );
    }

    #[test]
    fn genesis_block_is_exempt() {
        // The genesis hash is never solution-checked.
        let challenge = Builder::new().push_opcode(OP_RETURN).into_script(); // unsatisfiable
        let genesis = bitcoin::constants::genesis_block(Network::Signet);
        assert!(
            check_signet_block_solution(&genesis, challenge.as_bytes(), genesis.block_hash())
                .is_ok()
        );
    }

    #[test]
    fn verify_flags_match_core() {
        // Core's BLOCK_SCRIPT_VERIFY_FLAGS = P2SH | WITNESS | DERSIG |
        // NULLDUMMY. Pin the mask so a future edit can't silently drop a
        // flag and make satd accept solutions Core rejects.
        let expected = bitcoinconsensus::VERIFY_P2SH
            | bitcoinconsensus::VERIFY_WITNESS
            | bitcoinconsensus::VERIFY_DERSIG
            | bitcoinconsensus::VERIFY_NULLDUMMY;
        assert_eq!(block_script_verify_flags(), expected);
    }
}
