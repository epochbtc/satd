//! `validation::decode` against Bitcoin Core's `UnserializeTransaction`.
//! Expected values were taken from a Core v32.1 regtest node.

use super::*;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Txid};

/// `version | 00 00 | lock_time`: Core's ten-byte transaction with no inputs
/// and no outputs.
const EMPTY: &str = "02000000000000000000";
/// Core's `decoderawtransaction` txid (and `testmempoolaccept` wtxid) for it.
const EMPTY_TXID: &str = "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a";

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn spend(witness: &[&[u8]]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(7),
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 1 },
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut { value: Amount::from_sat(5000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
    }
}

#[test]
fn the_ten_byte_empty_transaction_reads_as_core_reads_it() {
    let raw = bytes(EMPTY);
    assert!(deserialize::<Transaction>(&raw).is_err(), "rust-bitcoin refuses it; the reason this module exists");
    let tx = deserialize_transaction(&raw).expect("Core reads it");
    assert_eq!(tx.version, transaction::Version::TWO);
    assert!(tx.input.is_empty() && tx.output.is_empty());
    assert_eq!(tx.lock_time.to_consensus_u32(), 0);
    assert_eq!(tx.compute_txid().to_string(), EMPTY_TXID);
    assert_eq!(wtxid(&tx).to_string(), EMPTY_TXID, "Core's wtxid is the txid");
    assert_ne!(tx.compute_wtxid().to_string(), EMPTY_TXID, "rust-bitcoin hashes its extended form");
    assert_eq!(
        crate::validation::tx::check_transaction(&tx).unwrap_err().to_string(),
        "bad-txns-vin-empty"
    );
}

#[test]
fn a_witness_flag_with_no_inputs_is_refused_as_core_refuses_it() {
    // version | 00 01 | no inputs | no outputs | lock_time: what rust-bitcoin
    // writes for a transaction with no inputs.
    let raw = bytes("020000000001000000000000");
    assert!(deserialize::<Transaction>(&raw).is_ok(), "rust-bitcoin reads it");
    assert_eq!(
        deserialize_transaction(&raw).unwrap_err().to_string(),
        encode::Error::ParseFailed("Superfluous witness record").to_string()
    );
}

#[test]
fn a_witness_flag_with_no_witnesses_is_refused() {
    let mut raw = bytes("02000000");
    raw.extend_from_slice(&[0x00, 0x01]);
    let legacy = serialize(&spend(&[]));
    raw.extend_from_slice(&legacy[4..legacy.len() - 4]); // inputs and outputs
    raw.push(0x00); // the input's empty witness
    raw.extend_from_slice(&7u32.to_le_bytes());
    assert!(deserialize::<Transaction>(&raw).is_err());
    assert!(deserialize_transaction(&raw).is_err());
}

#[test]
fn unknown_flags_are_refused() {
    for flags in [0x02u8, 0x03, 0x80] {
        let mut raw = bytes("02000000");
        raw.extend_from_slice(&[0x00, flags]);
        let legacy = serialize(&spend(&[]));
        raw.extend_from_slice(&legacy[4..legacy.len() - 4]);
        if flags & 1 != 0 {
            raw.extend_from_slice(&[0x01, 0x01, 0xaa]); // one witness item
        }
        raw.extend_from_slice(&7u32.to_le_bytes());
        assert!(deserialize_transaction(&raw).is_err(), "flags {flags:#04x}");
    }
}

#[test]
fn transactions_with_inputs_read_as_rust_bitcoin_reads_them() {
    let coinbase = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).txdata[0].clone();
    for tx in [spend(&[]), spend(&[b"sig", b"key"]), coinbase] {
        let raw = serialize(&tx);
        assert_eq!(deserialize_transaction(&raw).unwrap(), tx);
        assert_eq!(wtxid(&tx), tx.compute_wtxid());
        let mut extra = raw.clone();
        extra.push(0);
        assert!(deserialize_transaction(&extra).is_err(), "bytes left over are refused");
        assert!(deserialize_transaction(&raw[..raw.len() - 1]).is_err(), "a short read is refused");
    }
}

/// A block holding Core's empty transaction decodes, so `check_block` and
/// `check_transaction` get to refuse it, where rust-bitcoin refuses the bytes.
#[test]
fn a_block_holding_the_empty_transaction_decodes() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let raw = serialize(&genesis);
    assert_eq!(deserialize_block(&raw).unwrap(), genesis);

    let mut raw = serialize(&genesis.header);
    raw.push(2);
    raw.extend(serialize(&genesis.txdata[0]));
    raw.extend(bytes(EMPTY));
    assert!(deserialize::<Block>(&raw).is_err());
    let block = deserialize_block(&raw).expect("Core reads it");
    assert_eq!(block.txdata.len(), 2);
    assert!(block.txdata[1].input.is_empty());
}

#[test]
fn compact_block_messages_read_their_transactions_as_core_reads_them() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let cmpct = HeaderAndShortIds {
        header: genesis.header,
        nonce: 9,
        short_ids: vec![ShortId::from([1, 2, 3, 4, 5, 6])],
        prefilled_txs: vec![
            PrefilledTransaction { idx: 0, tx: genesis.txdata[0].clone() },
            PrefilledTransaction { idx: 1, tx: spend(&[b"w"]) },
        ],
    };
    let raw = serialize(&cmpct);
    assert_eq!(read_header_and_short_ids(&mut raw.as_slice()).unwrap(), cmpct);

    let txn = BlockTransactions { block_hash: genesis.block_hash(), transactions: vec![spend(&[]), spend(&[b"w"])] };
    let raw = serialize(&txn);
    assert_eq!(read_block_transactions(&mut raw.as_slice()).unwrap(), txn);

    // The empty transaction, prefilled and as a `blocktxn` member.
    let mut raw = serialize(&genesis.header);
    raw.extend_from_slice(&9u64.to_le_bytes());
    raw.extend_from_slice(&[0x00, 0x01, 0x00]);
    raw.extend(bytes(EMPTY));
    assert!(deserialize::<HeaderAndShortIds>(&raw).is_err());
    let read = read_header_and_short_ids(&mut raw.as_slice()).unwrap();
    assert!(read.prefilled_txs[0].tx.input.is_empty());

    let mut raw = serialize(&genesis.block_hash());
    raw.push(0x01);
    raw.extend(bytes(EMPTY));
    assert!(deserialize::<BlockTransactions>(&raw).is_err());
    assert!(read_block_transactions(&mut raw.as_slice()).unwrap().transactions[0].input.is_empty());
}
