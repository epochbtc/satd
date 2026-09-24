//! The winning-block path, end to end in one process: a share whose header
//! meets the block target, judged by the same [`validate_share`] the sessions
//! call, reconstructed, saved and submitted through [`submit_block`], on a
//! real chain with the real script verifier.
//!
//! A block a solo miner finds cannot be found again. Every property here is
//! one whose failure would lose it: the header the node rebuilds must be the
//! header the miner hashed, and the block around it must be one Bitcoin Core
//! accepts.

use std::sync::Arc;

use bitcoin::block::{Header, Version};
use bitcoin::hashes::{Hash, HashEngine, sha256d};
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::{
    Address, Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::chain::state::{AssumeValid, ChainState};
use crate::mempool::pool::Mempool;
use crate::mining::template::{COINBASE_WEIGHT_RESERVE, TemplateTx, create_template};
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;
use crate::stratum::config::resolve_payout;
use crate::stratum::found::{found_block_path, save_found_block};
use crate::stratum::server::submit_block;
use crate::stratum::share::{ShareResult, validate_share};
use crate::stratum::template::{ActiveTemplate, Work};
use crate::validation::script::RustVerifier;

/// The version bits a miner may roll (BIP 310, the mask the server grants).
const ROLLING_MASK: u32 = 0x1fff_e000;

/// Bitcoin Core's `CScript() << nHeight`, hand-encoded from `script.h`:
/// `push_int64` writes `OP_1`..`OP_16` for 1..16, otherwise a direct push of
/// `CScriptNum::serialize` — little-endian, shortest form, and a `0x00` byte
/// when the top bit of the last byte is set. BIP 34 compares the coinbase
/// scriptSig's first bytes with exactly this (`validation.cpp`,
/// `ContextualCheckBlock`, `bad-cb-height`).
fn core_height_push(height: u32) -> Vec<u8> {
    if (1..=16).contains(&height) {
        return vec![0x50 + height as u8];
    }
    let mut num = height.to_le_bytes().to_vec();
    while num.last() == Some(&0) {
        num.pop();
    }
    if num.last().is_some_and(|b| b & 0x80 != 0) {
        num.push(0);
    }
    let mut push = vec![num.len() as u8];
    push.extend(num);
    push
}

#[test]
fn core_height_push_matches_cores_serialization_at_each_boundary() {
    let cases: &[(u32, &[u8])] = &[
        (1, &[0x51]),
        (16, &[0x60]),
        (17, &[0x01, 0x11]),
        (127, &[0x01, 0x7f]),
        (128, &[0x02, 0x80, 0x00]),
        (255, &[0x02, 0xff, 0x00]),
        (256, &[0x02, 0x00, 0x01]),
        (32_767, &[0x02, 0xff, 0x7f]),
        (32_768, &[0x03, 0x00, 0x80, 0x00]),
        (65_535, &[0x03, 0xff, 0xff, 0x00]),
        (65_536, &[0x03, 0x00, 0x00, 0x01]),
        (8_388_607, &[0x03, 0xff, 0xff, 0x7f]),
        (8_388_608, &[0x04, 0x00, 0x00, 0x80, 0x00]),
        (968_181, &[0x03, 0xf5, 0xc5, 0x0e]),
    ];
    for (height, expected) in cases {
        assert_eq!(core_height_push(*height), *expected, "height {height}");
    }
}

/// Every payout the server can put in a coinbase: each standard address
/// type a username can name, and the `--stratumaddress` fallback for one
/// that names none.
fn payouts(secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Vec<(&'static str, ScriptBuf)> {
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).unwrap();
    let (xonly, _) = sk.x_only_public_key(secp);
    let witness_script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
    let n = Network::Regtest;
    let named = [
        ("p2pkh", Address::p2pkh(pk, n)),
        ("p2sh", Address::p2sh(&witness_script, n).unwrap()),
        ("p2wpkh", Address::p2wpkh(&cpk, n)),
        ("p2wsh", Address::p2wsh(&witness_script, n)),
        ("p2tr", Address::p2tr(secp, xonly, None, n)),
    ];
    let mut out: Vec<(&'static str, ScriptBuf)> = named
        .into_iter()
        .map(|(kind, addr)| {
            let payout = resolve_payout(&format!("{addr}.rig"), n, None).expect("a regtest address");
            assert_eq!(payout.script, addr.script_pubkey(), "{kind}");
            (kind, payout.script)
        })
        .collect();
    let fallback = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
    let payout = resolve_payout("not-an-address.rig", n, Some(&fallback)).expect("the fallback pays");
    assert_eq!(payout.address, None);
    out.push(("fallback", payout.script));
    out
}

/// A regtest chain with the real script verifier, so a spend in a found block
/// is judged the way the network judges it.
fn chain() -> (ChainState, Mempool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let chain = ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(RustVerifier::new(Network::Regtest)),
        AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    (chain, Mempool::new(1_000_000, 0), dir)
}

/// The P2WSH output every early coinbase pays, spendable by revealing the
/// witness script `OP_TRUE`: a real segwit spend, no signature needed.
fn anyone_can_spend() -> (ScriptBuf, ScriptBuf) {
    let witness_script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
    (ScriptBuf::new_p2wsh(&witness_script.wscript_hash()), witness_script)
}

/// Spend `coin` (worth `value`) into `outputs` equal outputs back to the
/// anyone-can-spend script, leaving `fee`.
fn spend(coin: OutPoint, value: u64, outputs: u64, fee: u64) -> Transaction {
    let (spk, witness_script) = anyone_can_spend();
    let each = (value - fee) / outputs;
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: coin,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[witness_script.as_bytes()]),
        }],
        output: (0..outputs).map(|_| TxOut { value: Amount::from_sat(each), script_pubkey: spk.clone() }).collect(),
    }
}

/// The merkle root a miner computes from the job it was sent: the coinbase
/// halves around its extranonce, hashed, then folded with each branch hash.
/// Written out here, apart from the server's code, so the two are compared.
fn miner_merkle_root(job: &ActiveTemplate, extranonce: &[u8]) -> TxMerkleNode {
    let mut engine = sha256d::Hash::engine();
    engine.input(&job.coinbase_prefix);
    engine.input(extranonce);
    engine.input(&job.coinbase_suffix);
    let mut root = sha256d::Hash::from_engine(engine).to_byte_array();
    for sibling in &job.work.merkle_branch {
        let mut buf = root.to_vec();
        buf.extend_from_slice(sibling);
        root = sha256d::Hash::hash(&buf).to_byte_array();
    }
    TxMerkleNode::from_byte_array(root)
}

/// Grind a nonce for the header a miner would hash, until it meets the block
/// target (regtest makes that about every other try).
fn grind(job: &ActiveTemplate, extranonce: &[u8], ntime: u32, version: i32) -> (Header, u32) {
    let mut header = Header {
        version: Version::from_consensus(version),
        prev_blockhash: job.work.prev_hash,
        merkle_root: miner_merkle_root(job, extranonce),
        time: ntime,
        bits: job.work.bits,
        nonce: 0,
    };
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    (header, header.nonce)
}

/// One found block, checked against every property the network enforces and
/// every one the miner relies on.
fn check_found(block: &Block, miner_header: &Header, job: &ActiveTemplate, payout: &ScriptBuf, what: &str) {
    let height = job.work.height;
    assert_eq!(block.header, *miner_header, "{what}: the node rebuilt a different header than the miner hashed");
    assert_eq!(block.block_hash(), miner_header.block_hash(), "{what}");
    let coinbase = &block.txdata[0];
    let script_sig = coinbase.input[0].script_sig.as_bytes();
    assert!(
        script_sig.starts_with(&core_height_push(height)),
        "{what}: scriptSig {} does not start with Core's height push {}",
        hex::encode(script_sig),
        hex::encode(core_height_push(height))
    );
    assert!((2..=100).contains(&script_sig.len()), "{what}: scriptSig length {}", script_sig.len());
    assert_eq!(coinbase.output[0].script_pubkey, *payout, "{what}: the coinbase pays the miner");
    let paid: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(
        paid,
        crate::chain::connect::block_subsidy(Network::Regtest, height) + job.work.fees,
        "{what}: coinbase value is the subsidy plus the fees"
    );
    assert!(
        coinbase.weight().to_wu() as usize <= COINBASE_WEIGHT_RESERVE,
        "{what}: coinbase weight {} exceeds the {COINBASE_WEIGHT_RESERVE} WU the template reserved for it",
        coinbase.weight().to_wu()
    );
    assert!(block.check_merkle_root(), "{what}: merkle root");
    assert!(block.check_witness_commitment(), "{what}: witness commitment");
    crate::validation::block::check_block(block, Network::Regtest, height)
        .unwrap_or_else(|e| panic!("{what}: check_block: {e}"));
}

/// Heights across every place the BIP 34 push changes shape that a test can
/// reach by mining: `OP_1`..`OP_16`, the first data push (17), the sign byte
/// (128), and the second byte (256). At each one, every payout type is judged
/// by proposal mode (full validation, scripts included, minus proof of work),
/// and one is submitted and must connect.
#[test]
fn a_found_block_connects_at_every_bip34_encoding_boundary_for_every_payout() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let payouts = payouts(&secp);
    let (chain, mempool, dir) = chain();
    let found_dir = dir.path().join("found");
    let (anyone, _) = anyone_can_spend();
    let mut rng = StdRng::seed_from_u64(0x5a7d_b1c0);
    // Coinbases paying the anyone-can-spend script, oldest first; one is spent
    // in each found block past maturity, so the witness commitment commits to
    // a real witness and the fees are real.
    let mut spendable: std::collections::VecDeque<(u32, OutPoint, u64)> = Default::default();
    let mut submitted = 0;

    let wanted: Vec<u32> = (1..=18).chain(126..=130).chain(254..=258).collect();
    for height in wanted {
        // Mine up to the block before, paying the anyone-can-spend script.
        while chain.tip_height() + 1 < height {
            crate::mining::miner::mine_blocks_to_script(&chain, &mempool, anyone.clone(), 1, u64::MAX).unwrap();
            let tip = chain.tip_height();
            let block = chain.get_block(&chain.tip_hash()).unwrap();
            spendable.push_back((
                tip,
                OutPoint::new(block.txdata[0].compute_txid(), 0),
                crate::chain::connect::block_subsidy(Network::Regtest, tip),
            ));
        }
        assert_eq!(chain.tip_height() + 1, height);

        // The template for the next block, plus spends of the oldest mature
        // coinbase: a fan-out and a child of it, so the block carries a
        // transaction chain and a multi-output transaction.
        let mut template = create_template(&chain, &mempool);
        assert_eq!(template.height, height);
        // A coinbase can be spent 100 blocks after its own.
        let mature = spendable.front().is_some_and(|(mined, _, _)| mined + 100 <= height);
        if mature {
            let (_, coin, value) = spendable.pop_front().unwrap();
            let parent = spend(coin, value, 5, 1_000);
            let child = spend(OutPoint::new(parent.compute_txid(), 2), parent.output[2].value.to_sat(), 2, 5_000);
            for (tx, fee) in [(parent, 1_000u64), (child, 5_000)] {
                template.coinbase_value += fee;
                let weight = tx.weight().to_wu() as usize;
                template.transactions.push(TemplateTx { tx, fee, weight, sigop_cost: 0 });
            }
        }
        let prev_time = chain.get_block(&chain.tip_hash()).unwrap().header.time;
        let work = Arc::new(Work::new(template, Network::Regtest, prev_time));

        let mut to_submit = None;
        for (i, (kind, payout)) in payouts.iter().enumerate() {
            // V1 is an 8-byte hole (4 from the server, 4 from the miner);
            // Stratum V2 extended channels reach 32.
            let extranonce_len = [8, 12, 16, 32][i % 4];
            let job = ActiveTemplate::build(work.clone(), i as u32, payout.clone(), extranonce_len).unwrap();
            let extranonce: Vec<u8> = (0..extranonce_len).map(|_| rng.r#gen()).collect();
            let rolled = rng.r#gen::<u32>() & ROLLING_MASK;
            let version = ((work.version as u32 & !ROLLING_MASK) | rolled) as i32;
            let ntime = work.cur_time + rng.gen_range(0..600);
            let (miner_header, nonce) = grind(&job, &extranonce, ntime, version);
            let what = format!("height {height}, {kind}, {extranonce_len}-byte extranonce, version {version:#x}");
            let easiest = [0xff; 32];
            let result = validate_share(&job, &extranonce, ntime, nonce, version, &easiest, u64::from(ntime))
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            let ShareResult::Block(block) = result else {
                panic!("{what}: a header meeting the block target was not judged a block");
            };
            check_found(&block, &miner_header, &job, payout, &what);
            if mature {
                assert_eq!(block.txdata.len(), 3, "{what}");
            }
            assert_eq!(
                chain.test_block_validity(&block).unwrap(),
                None,
                "{what}: proposal mode refused the block"
            );
            if i == height as usize % payouts.len() {
                to_submit = Some((*block, what));
            }
        }

        // Save it and submit it, as a winning share is.
        let (block, what) = to_submit.unwrap();
        let path = save_found_block(&found_dir, height, &block).unwrap();
        assert_eq!(path, found_block_path(&found_dir, height, &block));
        let saved: Block = bitcoin::consensus::deserialize(
            &hex::decode(std::fs::read_to_string(&path).unwrap().trim_end()).unwrap(),
        )
        .unwrap();
        assert_eq!(saved, block, "{what}: the saved copy is the block");
        assert_eq!(submit_block(&chain, &mempool, &block), Ok(true), "{what}: submission");
        assert_eq!(chain.tip_hash(), block.block_hash(), "{what}: the block is the tip");
        submitted += 1;
    }
    assert_eq!(submitted, 28);
}

/// The coinbase for heights a test cannot mine to — up to the last height a
/// four-byte push can hold before the sign byte, and today's mainnet — built
/// and judged without a chain: the height push is Core's, and the block passes
/// the context-free checks.
#[test]
fn a_found_blocks_coinbase_commits_to_heights_no_test_chain_reaches() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let payouts = payouts(&secp);
    let mut rng = StdRng::seed_from_u64(0x00b1_7c01);
    for height in [32_767u32, 32_768, 65_535, 65_536, 8_388_607, 8_388_608, 968_181] {
        let template = crate::mining::template::BlockTemplate {
            version: 0x2000_0000,
            prev_hash: BlockHash::from_byte_array([7; 32]),
            height,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            cur_time: 1_700_000_000,
            min_time: 1_699_999_000,
            transactions: Vec::new(),
            coinbase_value: crate::chain::connect::block_subsidy(Network::Regtest, height),
        };
        let work = Arc::new(Work::new(template, Network::Regtest, 1_699_999_900));
        for (i, (kind, payout)) in payouts.iter().enumerate() {
            let extranonce_len = [8, 12, 16, 32][i % 4];
            let job = ActiveTemplate::build(work.clone(), 1, payout.clone(), extranonce_len).unwrap();
            let extranonce: Vec<u8> = (0..extranonce_len).map(|_| rng.r#gen()).collect();
            let version = (0x2000_0000u32 | (rng.r#gen::<u32>() & ROLLING_MASK)) as i32;
            let (miner_header, nonce) = grind(&job, &extranonce, work.cur_time, version);
            let result =
                validate_share(&job, &extranonce, work.cur_time, nonce, version, &[0xff; 32], u64::from(work.cur_time))
                    .unwrap();
            let ShareResult::Block(block) = result else { panic!("height {height}, {kind}: not a block") };
            check_found(&block, &miner_header, &job, payout, &format!("height {height}, {kind}"));
        }
    }
}

/// Random solutions against random jobs: the block the node reconstructs is
/// always the block the miner's parts describe, assembled independently from
/// the job's halves with the bitcoin crate.
#[test]
fn a_reconstructed_block_is_the_block_the_miners_parts_describe() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let payouts = payouts(&secp);
    let mut rng = StdRng::seed_from_u64(0x00de_c0de);
    for round in 0..500 {
        let n_txs = rng.gen_range(0..12);
        let transactions = (0..n_txs)
            .map(|i| {
                let coin = OutPoint::new(bitcoin::Txid::from_byte_array(rng.r#gen()), rng.gen_range(0..4));
                let tx = spend(coin, 100_000 + i, rng.gen_range(1..4), 500);
                TemplateTx { weight: tx.weight().to_wu() as usize, tx, fee: 500, sigop_cost: 0 }
            })
            .collect::<Vec<_>>();
        let height = rng.gen_range(1..2_000_000);
        let template = crate::mining::template::BlockTemplate {
            version: 0x2000_0000,
            prev_hash: BlockHash::from_byte_array(rng.r#gen()),
            height,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            cur_time: 1_700_000_000,
            min_time: 1_699_999_000,
            coinbase_value: 5_000_000_000 + 500 * n_txs,
            transactions,
        };
        let work = Arc::new(Work::new(template, Network::Regtest, 1_699_999_900));
        let (_, payout) = &payouts[round % payouts.len()];
        let extranonce_len = rng.gen_range(1..=32);
        let job = ActiveTemplate::build(work.clone(), 1, payout.clone(), extranonce_len).unwrap();
        let extranonce: Vec<u8> = (0..extranonce_len).map(|_| rng.r#gen()).collect();
        let ntime = work.cur_time + rng.gen_range(0..7_200);
        let nonce: u32 = rng.r#gen();
        let version = (0x2000_0000u32 | (rng.r#gen::<u32>() & ROLLING_MASK)) as i32;

        let block = job.reconstruct_block(&extranonce, ntime, nonce, version);

        // Independently: the coinbase is the job's halves around the
        // extranonce, decoded, with the 32-byte zero witness reserved value.
        let mut bytes = job.coinbase_prefix.clone();
        bytes.extend_from_slice(&extranonce);
        bytes.extend_from_slice(&job.coinbase_suffix);
        let mut coinbase: Transaction = bitcoin::consensus::deserialize(&bytes).expect("the halves are a transaction");
        coinbase.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
        let mut txdata = vec![coinbase];
        txdata.extend(work.txdata.iter().cloned());
        let mut expected = Block {
            header: Header {
                version: Version::from_consensus(version),
                prev_blockhash: work.prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: ntime,
                bits: work.bits,
                nonce,
            },
            txdata,
        };
        expected.header.merkle_root = expected.compute_merkle_root().unwrap();
        assert_eq!(block, expected, "round {round}");
        assert_eq!(block.header.merkle_root, miner_merkle_root(&job, &extranonce), "round {round}");
        assert!(block.check_witness_commitment(), "round {round}");
        assert!(block.txdata[0].input[0].script_sig.as_bytes().starts_with(&core_height_push(height)), "round {round}");
    }
}
