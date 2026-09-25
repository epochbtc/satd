//! Signet block-solution validation (BIP 325).
//!
//! Signet replaces proof-of-work difficulty with a block signature: each
//! block carries a "signet solution" in its coinbase that must satisfy a
//! network-wide *challenge* script. This module implements Bitcoin Core's
//! `CheckSignetBlockSolution`. satd verifies every block on every signet:
//! against `-signetchallenge` on a custom signet, against
//! [`DEFAULT_SIGNET_CHALLENGE`] on the default one.
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

/// The default signet's challenge, a 1-of-2 multisig (Core's
/// `CChainParams::SigNet` with no `-signetchallenge`).
pub const DEFAULT_SIGNET_CHALLENGE: [u8; 71] = hex_literal_challenge();

const fn hex_literal_challenge() -> [u8; 71] {
    const HEX: &[u8] = b"512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }
    let mut out = [0u8; 71];
    let mut i = 0;
    while i < 71 {
        out[i] = (nib(HEX[2 * i]) << 4) | nib(HEX[2 * i + 1]);
        i += 1;
    }
    out
}

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
                // BIP 325 / Core `signet.cpp`: `OP_0 PUSH72[block_data]`.
                // The `OP_0` is part of the txid `to_sign` spends, so
                // without it no solution signed by Core's tooling verifies.
                script_sig: Builder::new()
                    .push_opcode(bitcoin::opcodes::OP_0)
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

/// Real default-signet blocks, for tests anywhere in the crate.
#[cfg(test)]
pub(crate) mod fixtures {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::Block;

    /// Blocks 1 to 10 of the public default signet, one hex block per line,
    /// as Bitcoin Core's `test/functional/feature_signet.py` carries them.
    /// The network's signers produced their solutions with Core's tooling,
    /// so these prove satd's verifier agrees with Core's rather than merely
    /// with satd's own signer.
    const BLOCKS_1_TO_10: &str = include_str!("testdata/default_signet_blocks_1_to_10.hex");

    /// Block 2 with one byte inside its signet signature flipped, its
    /// merkle root recomputed for the altered coinbase, and its nonce
    /// reground to meet signet's target. It passes every check but the
    /// solution; `the_bad_solution_fixture_differs_from_block_2_only_in_its_signature`
    /// proves that.
    const BLOCK_2_BAD_SOLUTION: &str =
        include_str!("testdata/default_signet_block_2_bad_solution.hex");

    fn parse(hex: &str) -> Block {
        deserialize(&Vec::<u8>::from_hex(hex.trim()).expect("fixture hex")).expect("fixture block")
    }

    /// Default-signet block at `height` (1 to 10).
    pub(crate) fn default_signet_block(height: usize) -> Block {
        assert!((1..=10).contains(&height), "fixtures cover heights 1 to 10");
        parse(BLOCKS_1_TO_10.lines().nth(height - 1).expect("fixture line"))
    }

    /// Default-signet block 2 carrying an invalid solution (see
    /// `BLOCK_2_BAD_SOLUTION`).
    pub(crate) fn default_signet_block_2_with_a_bad_solution() -> Block {
        parse(BLOCK_2_BAD_SOLUTION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn default_signet_magic_matches_bitcoin_crate() {
        // Self-check on the magic derivation: SHA256(default challenge)[..4]
        // must equal the well-known default signet magic (0x0a03cf40). This
        // also pins `DEFAULT_SIGNET_CHALLENGE`'s bytes: one wrong byte
        // changes the magic.
        let derived: Vec<u8> = signet_magic(&DEFAULT_SIGNET_CHALLENGE).to_bytes().to_vec();
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

    // ---- Real default-signet blocks (signed with Bitcoin Core's tooling) ----

    use super::fixtures::{default_signet_block, default_signet_block_2_with_a_bad_solution};

    /// The default signet's 2-of-2 variant: the same two keys, both required.
    /// Core's `feature_signet.py` runs a node on it to show the real blocks,
    /// signed by one key, fail there.
    const DEFAULT_KEYS_AS_2_OF_2: &str = "522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

    #[test]
    fn the_default_signet_chain_verifies_against_the_default_challenge() {
        let genesis = dummy_genesis();
        for height in 1..=10 {
            let block = default_signet_block(height);
            check_signet_block_solution(&block, &DEFAULT_SIGNET_CHALLENGE, genesis).unwrap_or_else(
                |e| panic!("default signet block {height} ({}) rejected: {e:?}", block.block_hash()),
            );
        }
    }

    #[test]
    fn a_real_signet_block_signed_for_another_challenge_is_rejected() {
        let challenge =
            <Vec<u8> as bitcoin::hashes::hex::FromHex>::from_hex(DEFAULT_KEYS_AS_2_OF_2).unwrap();
        for height in 1..=10 {
            let block = default_signet_block(height);
            assert!(
                matches!(
                    check_signet_block_solution(&block, &challenge, dummy_genesis()),
                    Err(ValidationError::BadSignetSolution)
                ),
                "block {height} carries one signature, so the 2-of-2 must refuse it"
            );
        }
    }

    #[test]
    fn a_real_signet_block_with_a_tampered_solution_is_rejected() {
        assert!(matches!(
            check_signet_block_solution(
                &default_signet_block_2_with_a_bad_solution(),
                &DEFAULT_SIGNET_CHALLENGE,
                dummy_genesis()
            ),
            Err(ValidationError::BadSignetSolution)
        ));
    }

    /// The negative fixture must fail for its signature and nothing else, or
    /// the tests that refuse it prove nothing about solution checking.
    #[test]
    fn the_bad_solution_fixture_differs_from_block_2_only_in_its_signature() {
        let real = default_signet_block(2);
        let bad = default_signet_block_2_with_a_bad_solution();

        // Header: only the merkle root and the nonce moved.
        assert_eq!(bad.header.version, real.header.version);
        assert_eq!(bad.header.prev_blockhash, real.header.prev_blockhash);
        assert_eq!(bad.header.time, real.header.time);
        assert_eq!(bad.header.bits, real.header.bits);
        assert_ne!(bad.header.nonce, real.header.nonce);

        // Still a valid block: merkle root, witness commitment and signet PoW.
        assert!(bad.check_merkle_root(), "merkle root must match the altered coinbase");
        assert!(bad.check_witness_commitment());
        bad.header
            .validate_pow(bad.header.target())
            .expect("the reground nonce must meet the header's target");
        assert_eq!(bad.header.bits, real.header.bits, "same (signet) target as the real block");

        // The coinbase differs in exactly one byte, inside the signet section.
        let (a, b) = (
            bitcoin::consensus::serialize(&real.txdata[0]),
            bitcoin::consensus::serialize(&bad.txdata[0]),
        );
        assert_eq!(a.len(), b.len());
        let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        assert_eq!(diffs.len(), 1, "exactly one coinbase byte differs");
        let header_at = a.windows(4).position(|w| w == SIGNET_HEADER).expect("signet section");
        assert!(diffs[0] > header_at + SIGNET_HEADER.len(), "the flipped byte is in the solution");

        // And the stripped message is the real block's, so only the
        // signature is wrong.
        let real_txs = SignetTxs::create(&real, &ScriptBuf::from_bytes(DEFAULT_SIGNET_CHALLENGE.to_vec())).unwrap();
        let bad_txs = SignetTxs::create(&bad, &ScriptBuf::from_bytes(DEFAULT_SIGNET_CHALLENGE.to_vec())).unwrap();
        assert_eq!(real_txs.to_spend, bad_txs.to_spend, "same signed message");
        assert_ne!(real_txs.to_sign.input[0].script_sig, bad_txs.to_sign.input[0].script_sig);
    }

    /// BIP 325: `to_spend`'s scriptSig is `OP_0 PUSH72[block_data]`
    /// (Core `signet.cpp`). Without the `OP_0` the txid differs, so no
    /// solution signed by Core's tooling verifies.
    #[test]
    fn to_spend_carries_op_0_before_the_block_data() {
        let challenge = ScriptBuf::from_bytes(DEFAULT_SIGNET_CHALLENGE.to_vec());
        let txs = SignetTxs::create(&default_signet_block(1), &challenge).unwrap();
        let ins: Vec<Instruction> = txs.to_spend.input[0]
            .script_sig
            .instructions()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ins.len(), 2, "exactly OP_0 then the block data");
        assert!(
            matches!(ins[0], Instruction::PushBytes(b) if b.is_empty()),
            "first instruction must be OP_0, got {:?}",
            ins[0]
        );
        assert!(matches!(ins[1], Instruction::PushBytes(b) if b.len() == 72));
    }
}
