//! Transactions, and the messages that carry them, read the way Bitcoin Core
//! reads them.
//!
//! rust-bitcoin's transaction decoder parts from Core's
//! `UnserializeTransaction` (`src/primitives/transaction.h`, v32.1) in two
//! places, both where the input vector reads as empty and Core goes on to
//! read a flags byte:
//!
//! - **Flags `0x00`.** Core ends the transaction there, with no inputs and no
//!   outputs, and reads the lock time: `version | 00 00 | lock_time` is a
//!   ten-byte transaction that `CheckTransaction` refuses as
//!   `bad-txns-vin-empty`. rust-bitcoin refuses the bytes as an unsupported
//!   segwit flag, so the transaction never reached `check_transaction` and a
//!   block holding one failed to decode as a whole (#1242).
//! - **Flags `0x01` and an empty inner input vector.** Core refuses it:
//!   witnesses were announced and no input carries one ("Superfluous witness
//!   record"). rust-bitcoin accepts it, because that is how it writes a
//!   transaction with no inputs.
//!
//! Neither shape can be valid (every valid transaction has an input), so this
//! changes which stage refuses such bytes and with what reason, never whether
//! they are refused. Inputs, outputs, witnesses and compact sizes are read by
//! rust-bitcoin's decoders exactly as before.
//!
//! Because of the second point, bytes rust-bitcoin wrote for a transaction
//! with no inputs do not read back here. Core writes such a transaction
//! without the marker and flag (`SerializeTransaction` writes them only when
//! an input carries a witness), and measures and hashes it in that form:
//! [`serialize_transaction`], [`total_size`], [`weight`], [`vsize`] and
//! [`wtxid`] do the same, for every RPC that prints or writes one.

use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds, PrefilledTransaction, ShortId};
use bitcoin::consensus::encode::{self, Decodable, VarInt, MAX_VEC_SIZE};
use bitcoin::io::Read;
use bitcoin::{absolute, block, transaction, Block, BlockHash, Transaction, TxIn, TxOut, Witness, Wtxid};

/// Core's `UnserializeTransaction` with witnesses allowed.
pub fn read_transaction<R: Read + ?Sized>(r: &mut R) -> Result<Transaction, encode::Error> {
    let version = transaction::Version::consensus_decode_from_finite_reader(r)?;
    let mut input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
    let mut output = Vec::<TxOut>::new();
    let mut flags = 0u8;
    if input.is_empty() {
        // An empty input vector, or the extended format's marker byte.
        flags = u8::consensus_decode_from_finite_reader(r)?;
        if flags != 0 {
            input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
            output = Vec::<TxOut>::consensus_decode_from_finite_reader(r)?;
        }
    } else {
        output = Vec::<TxOut>::consensus_decode_from_finite_reader(r)?;
    }
    if flags & 1 != 0 {
        flags ^= 1;
        for txin in input.iter_mut() {
            txin.witness = Witness::consensus_decode_from_finite_reader(r)?;
        }
        // Core's `!tx.HasWitness()`, which also holds for no inputs at all.
        if input.iter().all(|txin| txin.witness.is_empty()) {
            return Err(encode::Error::ParseFailed("Superfluous witness record"));
        }
    }
    if flags != 0 {
        return Err(encode::Error::ParseFailed("Unknown transaction optional data"));
    }
    let lock_time = absolute::LockTime::consensus_decode_from_finite_reader(r)?;
    Ok(Transaction { version, lock_time, input, output })
}

/// A compact-size count of transactions, each read by [`read_transaction`].
/// The up-front allocation is capped as rust-bitcoin caps it for a `Vec`.
fn read_transactions<R: Read + ?Sized>(r: &mut R) -> Result<Vec<Transaction>, encode::Error> {
    let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
    let max_capacity = MAX_VEC_SIZE / 4 / std::mem::size_of::<Transaction>();
    let mut txs = Vec::with_capacity((len as usize).min(max_capacity));
    for _ in 0..len {
        txs.push(read_transaction(r)?);
    }
    Ok(txs)
}

/// A block: its header, then its transactions read by [`read_transaction`].
pub fn read_block<R: Read + ?Sized>(r: &mut R) -> Result<Block, encode::Error> {
    let header = block::Header::consensus_decode_from_finite_reader(r)?;
    let txdata = read_transactions(r)?;
    Ok(Block { header, txdata })
}

/// A `cmpctblock` payload, its prefilled transactions read by
/// [`read_transaction`] (Core reads them `TX_WITH_WITNESS`).
pub fn read_header_and_short_ids<R: Read + ?Sized>(r: &mut R) -> Result<HeaderAndShortIds, encode::Error> {
    let header = block::Header::consensus_decode_from_finite_reader(r)?;
    let nonce = u64::consensus_decode_from_finite_reader(r)?;
    let short_ids = Vec::<ShortId>::consensus_decode_from_finite_reader(r)?;
    let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
    let max_capacity = MAX_VEC_SIZE / 4 / std::mem::size_of::<PrefilledTransaction>();
    let mut prefilled_txs = Vec::with_capacity((len as usize).min(max_capacity));
    for _ in 0..len {
        let idx = VarInt::consensus_decode_from_finite_reader(r)?.0;
        let idx = u16::try_from(idx)
            .map_err(|_| encode::Error::ParseFailed("BIP152 prefilled tx index out of bounds"))?;
        prefilled_txs.push(PrefilledTransaction { idx, tx: read_transaction(r)? });
    }
    Ok(HeaderAndShortIds { header, nonce, short_ids, prefilled_txs })
}

/// A `blocktxn` payload, its transactions read by [`read_transaction`].
pub fn read_block_transactions<R: Read + ?Sized>(r: &mut R) -> Result<BlockTransactions, encode::Error> {
    let block_hash = BlockHash::consensus_decode_from_finite_reader(r)?;
    let transactions = read_transactions(r)?;
    Ok(BlockTransactions { block_hash, transactions })
}

/// [`read_transaction`] over the whole of `bytes`, refusing any left over,
/// as `bitcoin::consensus::deserialize` refuses them.
pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, encode::Error> {
    whole(bytes, |r| read_transaction(r))
}

/// [`read_block`] over the whole of `bytes`, refusing any left over.
pub fn deserialize_block(bytes: &[u8]) -> Result<Block, encode::Error> {
    whole(bytes, |r| read_block(r))
}

fn whole<T>(
    bytes: &[u8],
    read: impl FnOnce(&mut &[u8]) -> Result<T, encode::Error>,
) -> Result<T, encode::Error> {
    let mut r = bytes;
    let value = read(&mut r)?;
    if !r.is_empty() {
        return Err(encode::Error::ParseFailed("data not consumed entirely when explicitly deserializing"));
    }
    Ok(value)
}

/// A transaction's wtxid as Core computes it (`ComputeWitnessHash`): the txid
/// when no input carries a witness.
///
/// rust-bitcoin agrees for every transaction with an input. For one with no
/// inputs it hashes the extended form it writes (marker and flag included),
/// which Core never produces; [`read_transaction`] yields such a transaction
/// from Core's ten-byte form. A block's witness commitment has to see Core's
/// value for it, or a block Core refuses as `bad-txns-vin-empty` is judged
/// mutated instead.
pub fn wtxid(tx: &Transaction) -> Wtxid {
    if tx.input.is_empty() {
        Wtxid::from_raw_hash(tx.compute_txid().to_raw_hash())
    } else {
        tx.compute_wtxid()
    }
}

/// A transaction written as Core writes it with witnesses allowed
/// (`SerializeTransaction`, `TX_WITH_WITNESS`): the marker and flag only when
/// an input carries a witness.
///
/// rust-bitcoin writes the same bytes for every transaction with an input.
/// For one with no inputs it writes `version 00 01 ...`, which neither Core
/// nor [`read_transaction`] reads back; Core writes `version 00 <outputs>
/// lock_time`, what `createrawtransaction` with no inputs returns.
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    if !tx.input.is_empty() {
        return encode::serialize(tx);
    }
    let mut out = Vec::with_capacity(tx.base_size());
    encode::Encodable::consensus_encode(&tx.version, &mut out).expect("vec");
    encode::Encodable::consensus_encode(&tx.input, &mut out).expect("vec");
    encode::Encodable::consensus_encode(&tx.output, &mut out).expect("vec");
    encode::Encodable::consensus_encode(&tx.lock_time, &mut out).expect("vec");
    out
}

/// The length of [`serialize_transaction`]'s bytes (Core's
/// `GetSerializeSize(TX_WITH_WITNESS(tx))`, `size` in `decoderawtransaction`).
pub fn total_size(tx: &Transaction) -> usize {
    if tx.input.is_empty() { tx.base_size() } else { tx.total_size() }
}

/// Core's `GetTransactionWeight`: three times the size without witnesses plus
/// [`total_size`]. For a transaction with no inputs it is four times its
/// size; rust-bitcoin counts the marker and flag in it.
pub fn weight(tx: &Transaction) -> bitcoin::Weight {
    if tx.input.is_empty() {
        bitcoin::Weight::from_wu_usize(tx.base_size() * 4)
    } else {
        tx.weight()
    }
}

/// [`weight`] in virtual bytes, rounded up (Core's `GetVirtualTransactionSize`
/// with no sigops).
pub fn vsize(tx: &Transaction) -> usize {
    (weight(tx).to_wu() as usize).div_ceil(4)
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
