use super::*;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use proptest::prelude::*;

fn op_return(len: usize) -> ScriptBuf {
    assert!(len >= 1);
    let mut v = vec![0x6a];
    v.extend((1..len).map(|i| (i % 251) as u8 + 1));
    ScriptBuf::from_bytes(v)
}

fn tx(n_in: usize, witness: bool, outputs: Vec<ScriptBuf>, salt: u32) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::from_consensus(salt),
        input: (0..n_in)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([salt as u8; 32]),
                    vout: i as u32,
                },
                script_sig: ScriptBuf::from_bytes(vec![0x51; i]),
                sequence: Sequence::MAX,
                witness: if witness {
                    Witness::from_slice(&[vec![0xab; 3 + i], vec![]])
                } else {
                    Witness::new()
                },
            })
            .collect(),
        output: outputs
            .into_iter()
            .enumerate()
            .map(|(i, s)| TxOut {
                value: Amount::from_sat(1_000 + i as u64),
                script_pubkey: s,
            })
            .collect(),
    }
}

fn coinbase(extra: Vec<ScriptBuf>) -> Transaction {
    let mut cb = tx(1, false, vec![ScriptBuf::new()], 0);
    cb.input[0].previous_output = OutPoint::null();
    cb.output.extend(extra.into_iter().map(|s| TxOut {
        value: Amount::ZERO,
        script_pubkey: s,
    }));
    cb
}

fn block(txdata: Vec<Transaction>) -> Block {
    let mut b = Block {
        header: bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header,
        txdata,
    };
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    b
}

/// Every parsed span holds exactly the script the decoder produced, and
/// the transaction spans tile the block after the header and count.
fn assert_spans_match(bytes: &[u8], block: &Block) {
    let spans = tx_spans(bytes).expect("a decodable block parses");
    assert_eq!(spans.len(), block.txdata.len());
    for (i, (s, tx)) in spans.iter().zip(&block.txdata).enumerate() {
        assert_eq!(&bytes[s.offset..s.offset + s.len], serialize(tx).as_slice(), "tx {i}");
        assert_eq!(s.outputs.len(), tx.output.len(), "tx {i}");
        for (v, (o, out)) in s.outputs.iter().zip(&tx.output).enumerate() {
            assert_eq!(
                &bytes[o.script_offset..o.script_offset + o.script_len],
                out.script_pubkey.as_bytes(),
                "tx {i} vout {v}"
            );
        }
    }
    for w in spans.windows(2) {
        assert_eq!(w[0].offset + w[0].len, w[1].offset);
    }
    let last = spans.last().unwrap();
    assert_eq!(last.offset + last.len, bytes.len());
}

// --- span parser ---------------------------------------------------------

/// Script lengths around every CompactSize boundary.
const BOUNDARY_LENS: [usize; 9] = [1, 2, 252, 253, 254, 65535, 65536, 65537, 100_000];

#[test]
fn spans_match_the_decoder_at_compact_size_boundaries() {
    for (n, len) in BOUNDARY_LENS.into_iter().enumerate() {
        for witness in [false, true] {
            let b = block(vec![
                coinbase(vec![]),
                tx(2, witness, vec![ScriptBuf::new(), op_return(len)], n as u32 + 1),
            ]);
            assert_spans_match(&serialize(&b), &b);
        }
    }
}

#[test]
fn spans_match_the_decoder_on_real_blocks() {
    for network in [bitcoin::Network::Bitcoin, bitcoin::Network::Testnet, bitcoin::Network::Signet] {
        let b = bitcoin::constants::genesis_block(network);
        assert_spans_match(&serialize(&b), &b);
    }
    for h in 1..=10 {
        let b = crate::validation::signet::fixtures::default_signet_block(h);
        assert_spans_match(&serialize(&b), &b);
    }
}

fn arb_script() -> impl Strategy<Value = ScriptBuf> {
    prop_oneof![
        Just(ScriptBuf::new()),
        (0usize..40).prop_map(|n| ScriptBuf::from_bytes(vec![0x51; n])),
        prop::sample::select(BOUNDARY_LENS.to_vec()).prop_map(op_return),
        (1usize..600).prop_map(op_return),
    ]
}

fn arb_tx() -> impl Strategy<Value = Transaction> {
    (1usize..4, any::<bool>(), prop::collection::vec(arb_script(), 0..5), any::<u32>())
        .prop_map(|(n_in, w, outs, salt)| tx(n_in, w, outs, salt))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn spans_match_the_decoder_on_random_blocks(txs in prop::collection::vec(arb_tx(), 0..6)) {
        let mut txdata = vec![coinbase(vec![op_return(38)])];
        txdata.extend(txs);
        let b = block(txdata);
        let bytes = serialize(&b);
        assert_spans_match(&bytes, &b);
        // The parser refuses what the decoder refuses: any truncation.
        prop_assert!(tx_spans(&bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn the_parser_refuses_what_the_decoder_refuses() {
    let b = block(vec![coinbase(vec![]), tx(1, true, vec![op_return(10)], 1)]);
    let good = serialize(&b);
    let spans = tx_spans(&good).unwrap();

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(tx_spans(&trailing), Err(SpanError::TrailingBytes(1)));
    assert!(deserialize::<Block>(&trailing).is_err());

    // The segwit flag of tx 1 sits after its version and the 0x00 marker.
    let flag_at = spans[1].offset + 5;
    let mut bad_flag = good.clone();
    bad_flag[flag_at] = 2;
    assert!(matches!(tx_spans(&bad_flag), Err(SpanError::UnsupportedSegwitFlag { flag: 2, .. })));
    assert!(deserialize::<Block>(&bad_flag).is_err());

    // The tx count as a non-minimal 0xfd prefix.
    let mut non_minimal = good[..80].to_vec();
    non_minimal.extend_from_slice(&[0xfd, 0x02, 0x00]);
    non_minimal.extend_from_slice(&good[81..]);
    assert_eq!(tx_spans(&non_minimal), Err(SpanError::NonMinimalCompactSize(80)));
    assert!(deserialize::<Block>(&non_minimal).is_err());

    // The segwit marker and flag with every witness stack empty: a legacy
    // tx re-encoded by hand with the marker, flag and a zero item count.
    let mut raw = serialize(&tx(1, false, vec![op_return(10)], 1));
    raw.splice(4..4, [0x00, 0x01]);
    let lock_at = raw.len() - 4;
    raw.insert(lock_at, 0x00);
    let mut empty_witness = good[..81].to_vec();
    empty_witness.extend_from_slice(&serialize(&b.txdata[0]));
    empty_witness.extend_from_slice(&raw);
    assert!(matches!(tx_spans(&empty_witness), Err(SpanError::EmptyWitness(_))));
    assert!(deserialize::<Block>(&empty_witness).is_err());

    // A count far past the remaining bytes is refused before allocating.
    let mut huge = good[..80].to_vec();
    huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert!(matches!(tx_spans(&huge), Err(SpanError::CountTooLarge { .. })));
}

// --- eligibility ---------------------------------------------------------

#[test]
fn eligibility_takes_op_returns_at_or_above_the_threshold_and_never_the_coinbase() {
    let b = block(vec![
        coinbase(vec![op_return(5000)]),
        tx(1, false, vec![op_return(100), op_return(99), ScriptBuf::from_bytes(vec![0x51; 200])], 1),
        tx(1, false, vec![ScriptBuf::new()], 2),
        tx(1, false, vec![op_return(1)], 3),
    ]);
    assert_eq!(eligible_outputs(&b, 100), vec![(1, vec![0])], "len == threshold is stripped");
    assert_eq!(eligible_outputs(&b, 101), vec![]);
    assert_eq!(eligible_outputs(&b, 99), vec![(1, vec![0, 1])]);
    assert_eq!(
        eligible_outputs(&b, 0),
        vec![(1, vec![0, 1]), (3, vec![0])],
        "0 takes every OP_RETURN except the coinbase's; never a non-OP_RETURN script"
    );
    assert!(!output_is_eligible(0, &op_return(5000), 0), "the coinbase is never eligible");
    assert!(!output_is_eligible(1, &ScriptBuf::new(), 0));
}

// --- record codec --------------------------------------------------------

fn sample_record() -> StripRecord {
    StripRecord {
        filled_sha256: [7; 32],
        txs: vec![
            StrippedTx {
                tx_index: 1,
                txid: Txid::from_byte_array([1; 32]),
                wtxid: None,
                outputs: vec![StrippedOutput { vout: 0, script_len: 100_000 }],
            },
            StrippedTx {
                tx_index: 300,
                txid: Txid::from_byte_array([2; 32]),
                wtxid: Some(Wtxid::from_byte_array([3; 32])),
                outputs: vec![
                    StrippedOutput { vout: 1, script_len: 83 },
                    StrippedOutput { vout: 7, script_len: 4096 },
                ],
            },
        ],
    }
}

#[test]
fn record_round_trips() {
    let r = sample_record();
    let enc = r.encode();
    assert_eq!(StripRecord::decode(&enc), Ok(r.clone()));
    assert_eq!(enc[0], RECORD_VERSION);
    assert!(r.tx(300).is_some() && r.tx(2).is_none());
}

#[test]
fn record_decode_is_strict() {
    let good = sample_record().encode();
    let decode = |b: &[u8]| StripRecord::decode(b);

    assert_eq!(decode(&[]), Err(RecordDecodeError::Empty));
    let mut v = good.clone();
    v[0] = 2;
    assert_eq!(decode(&v), Err(RecordDecodeError::UnsupportedVersion(2)));

    let mut v = good.clone();
    v.push(0);
    assert_eq!(decode(&v), Err(RecordDecodeError::TrailingBytes(1)));

    for cut in 1..good.len() {
        assert!(decode(&good[..cut]).is_err(), "truncated at {cut} must not decode");
    }

    let mut base = vec![RECORD_VERSION];
    base.extend_from_slice(&[7; 32]);
    let with = |tail: &[u8]| {
        let mut v = base.clone();
        v.extend_from_slice(tail);
        v
    };
    let txid = [1u8; 32];
    let one_tx = |idx: u8, flags: u8, outs: &[u8]| {
        let mut t = vec![1, idx];
        t.extend_from_slice(&txid);
        t.push(flags);
        if flags & 1 != 0 {
            t.extend_from_slice(&[9; 32]);
        }
        t.extend_from_slice(outs);
        t
    };
    assert_eq!(decode(&with(&[0])), Err(RecordDecodeError::ZeroCount("n_txs")));
    assert_eq!(decode(&with(&one_tx(0, 0, &[1, 0, 5]))), Err(RecordDecodeError::Coinbase));
    assert_eq!(decode(&with(&one_tx(1, 2, &[1, 0, 5]))), Err(RecordDecodeError::UnknownFlags(2)));
    assert_eq!(decode(&with(&one_tx(1, 0, &[0]))), Err(RecordDecodeError::ZeroCount("n_outputs")));
    assert_eq!(
        decode(&with(&one_tx(1, 0, &[2, 3, 5, 3, 5]))),
        Err(RecordDecodeError::NotAscending("vout"))
    );
    assert!(decode(&with(&one_tx(1, 0, &[1, 0, 5]))).is_ok());

    // Two txs out of order.
    let mut two = vec![2, 5];
    two.extend_from_slice(&txid);
    two.extend_from_slice(&[0, 1, 0, 5, 5]);
    two.extend_from_slice(&txid);
    two.extend_from_slice(&[0, 1, 0, 5]);
    assert_eq!(decode(&with(&two)), Err(RecordDecodeError::NotAscending("tx_index")));

    // A non-minimal varint (5 as 0x85 0x00).
    assert_eq!(
        decode(&with(&one_tx(1, 0, &[1, 0, 0x85, 0x00]))),
        Err(RecordDecodeError::NonMinimalVarint("script_len"))
    );

    // A huge count is refused without allocating.
    let mut huge = base.clone();
    encode_varint(u64::MAX >> 1, &mut huge);
    assert_eq!(decode(&huge), Err(RecordDecodeError::Truncated("n_txs")));
}

// --- fill, StoredBlock ---------------------------------------------------

/// A block with a large OP_RETURN in a witness tx, a small one in a legacy
/// tx, a coinbase OP_RETURN that must never be touched, and a tx paying a
/// 25-byte non-OP_RETURN script.
fn stripped_fixture() -> (Block, Vec<u8>) {
    let b = block(vec![
        coinbase(vec![op_return(38)]),
        tx(1, true, vec![ScriptBuf::new(), op_return(10_000)], 1),
        tx(2, false, vec![op_return(300), ScriptBuf::new()], 2),
        tx(1, false, vec![ScriptBuf::from_bytes(vec![0x51; 25])], 3),
    ]);
    let bytes = serialize(&b);
    (b, bytes)
}

#[test]
fn build_then_read_back_gives_the_original_identity() {
    let (b, bytes) = stripped_fixture();
    let (record, filled) = StripRecord::build(&bytes, &b, 300).unwrap().expect("two txs eligible");
    assert_eq!(record.txs.len(), 2);
    assert!(record.txs[0].wtxid.is_some(), "tx 1 has a witness");
    assert!(record.txs[1].wtxid.is_none(), "tx 2 does not");
    assert_eq!(filled.len(), bytes.len(), "no length changes");

    let spans = tx_spans(&bytes).unwrap();
    for (i, v) in [(1usize, 1usize), (2, 0)] {
        let o = spans[i].outputs[v];
        assert_eq!(filled[o.script_offset], 0x6a, "the opcode stays");
        assert!(filled[o.strip_range()].iter().all(|x| *x == 0));
    }
    let cb = spans[0].outputs[1];
    assert_eq!(&filled[cb.script_offset..cb.script_offset + cb.script_len], op_return(38).as_bytes());

    // The disk may hold anything in the spans: the original bytes (crash
    // before the punch), or zeros.
    for disk in [bytes.clone(), filled.clone()] {
        let sb = StoredBlock::from_bytes(disk, Some(record.clone()), &b.block_hash()).expect("reads back");
        assert!(sb.is_stripped());
        assert!(sb.tx_is_stripped(1) && sb.tx_is_stripped(2) && !sb.tx_is_stripped(3));
        assert_eq!(sb.txids(), b.txdata.iter().map(|t| t.compute_txid()).collect::<Vec<_>>());
        assert_eq!(sb.wtxids(), b.txdata.iter().map(|t| t.compute_wtxid()).collect::<Vec<_>>());
        assert_eq!(sb.stripped_outputs(1), vec![(1, 10_000)]);
        assert_eq!(sb.stripped_outputs(3), vec![]);
        assert_ne!(sb.block.txdata[1].compute_txid(), b.txdata[1].compute_txid(), "bytes are zeroed");
        assert_eq!(sb.block.total_size(), b.total_size());
        assert!(sb.verify_merkle());
        assert!(sb.clone().into_intact().is_none());
    }

    let intact = StoredBlock::from_bytes(bytes, None, &b.block_hash()).unwrap();
    assert!(!intact.is_stripped());
    assert_eq!(intact.into_intact(), Some(b));
}

#[test]
fn nothing_eligible_builds_no_record() {
    let (b, bytes) = stripped_fixture();
    assert!(StripRecord::build(&bytes, &b, 10_001).unwrap().is_none());
}

#[test]
fn a_flipped_byte_outside_the_spans_is_caught_by_the_filled_hash() {
    let (b, bytes) = stripped_fixture();
    let (record, filled) = StripRecord::build(&bytes, &b, 300).unwrap().unwrap();
    let spans = tx_spans(&bytes).unwrap();
    // tx 3's output value: inside the block, outside every span.
    let at = spans[3].outputs[0].script_offset - 1 - 8;
    let mut bad = filled.clone();
    bad[at] ^= 1;
    assert_eq!(
        StoredBlock::from_bytes(bad, Some(record.clone()), &b.block_hash()).unwrap_err(),
        StoredBlockError::FilledHashMismatch
    );
    // A byte inside a span is overwritten by the fill, so it does not matter.
    let mut in_span = filled;
    let o = spans[1].outputs[1];
    in_span[o.script_offset + 5] = 0xee;
    assert!(StoredBlock::from_bytes(in_span, Some(record), &b.block_hash()).is_ok());
}

#[test]
fn a_swapped_txid_is_caught_by_the_merkle_check() {
    let (b, bytes) = stripped_fixture();
    let (mut record, filled) = StripRecord::build(&bytes, &b, 300).unwrap().unwrap();
    record.txs[1].txid = b.txdata[3].compute_txid();
    let sb = StoredBlock::from_bytes(filled.clone(), None, &b.block_hash()).unwrap();
    let swapped = StoredBlock {
        block: sb.block,
        strip: Some(record.clone()),
    };
    assert!(!swapped.verify_merkle());
    assert_eq!(
        StoredBlock::from_bytes(filled, Some(record), &b.block_hash()).unwrap_err(),
        StoredBlockError::MerkleMismatch
    );
}

#[test]
fn a_record_that_does_not_fit_the_bytes_is_refused() {
    let (b, bytes) = stripped_fixture();
    let (record, _) = StripRecord::build(&bytes, &b, 300).unwrap().unwrap();
    let hash = b.block_hash();
    let read = |r: StripRecord| StoredBlock::from_bytes(bytes.clone(), Some(r), &hash).unwrap_err();

    let mut r = record.clone();
    r.txs[1].outputs[0].script_len = 301;
    assert!(matches!(read(r), StoredBlockError::Fill(FillError::LengthMismatch { .. })));

    let mut r = record.clone();
    r.txs[1].outputs[0].vout = 1;
    r.txs[1].outputs[0].script_len = 0;
    assert!(matches!(read(r), StoredBlockError::Fill(FillError::NotOpReturn { .. })));

    // The right length, but a script that is not an OP_RETURN.
    let mut r = record.clone();
    r.txs[1].tx_index = 3;
    r.txs[1].outputs[0].script_len = 25;
    assert!(
        matches!(read(r), StoredBlockError::Fill(FillError::NotOpReturn { tx_index: 3, vout: 0 })),
        "a record naming a non-OP_RETURN output must not zero it"
    );

    let mut r = record.clone();
    r.txs[1].outputs[0].vout = 9;
    assert!(matches!(read(r), StoredBlockError::Fill(FillError::NoSuchOutput { .. })));

    let mut r = record.clone();
    r.txs[1].tx_index = 40;
    assert!(matches!(read(r), StoredBlockError::Fill(FillError::NoSuchTx(40))));

    let other = BlockHash::from_byte_array([5; 32]);
    assert!(matches!(
        StoredBlock::from_bytes(bytes.clone(), Some(record), &other).unwrap_err(),
        StoredBlockError::WrongHash { .. }
    ));
}
