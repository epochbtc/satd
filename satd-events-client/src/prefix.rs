//! Privacy-preserving prefix-watch local re-filter (the `bitcoin` feature).
//!
//! A prefix watch trades precision for privacy: the consumer registers a
//! `bits`-bit prefix of `sha256(scriptPubKey)`, and the server delivers **every**
//! transaction whose output or spent prevout falls in that `2^-bits` bucket. The
//! server thus learns only the bucket, never the exact script — but the firehose
//! now carries decoys the consumer must filter out locally.
//!
//! [`PrefixWatcher`] is that filter. It holds the consumer's *real*
//! scriptPubKeys (as their scripthashes), and given a
//! [`PrefixMatch`](crate::PrefixMatch) it decodes the inline `raw_tx`,
//! recomputes `sha256(scriptPubKey)` for every output **and** every retained
//! spent prevout, and reports only the true hits — with no precise follow-up
//! fetch that would re-leak the exact script.
//!
//! The decode and hashing need `bitcoin` types, so this lives behind the
//! default-on `bitcoin` feature; disable it for a minimal build and filter the
//! raw bytes yourself.

use std::collections::HashSet;

use bitcoin::consensus;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Script, ScriptBuf, Transaction, Txid};

use crate::error::StreamError;
use crate::event::{Outpoint, PrefixMatch};

/// `sha256(scriptPubKey)` — the 32-byte scripthash the server keys watches on
/// (the prefix bucket is its top `ceil(bits/8)` bytes, big-endian).
pub fn scripthash_of(script_pubkey: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(script_pubkey).to_byte_array()
}

/// Derive the `(prefix, bits)` registration tuple for a scriptPubKey: the top
/// `ceil(bits/8)` bytes of its scripthash. `bits` is clamped to `1..=256`
/// (its valid range); [`WatchHandle::add_script_prefixes`](crate::WatchHandle::add_script_prefixes)
/// re-validates before the wire.
pub fn prefix_of(script_pubkey: &[u8], bits: u32) -> (Vec<u8>, u32) {
    let bits = bits.clamp(1, 256);
    let sh = scripthash_of(script_pubkey);
    let n = (bits as usize).div_ceil(8).min(32);
    (sh[..n].to_vec(), bits)
}

/// An output (funding side) of a delivered tx that pays a watched script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingHit {
    /// Output index within the transaction.
    pub vout: u32,
    /// The matched `sha256(scriptPubKey)`.
    pub scripthash: [u8; 32],
    /// Output value in satoshis.
    pub value: u64,
    /// The output's scriptPubKey.
    pub script_pubkey: ScriptBuf,
}

/// A spent prevout (spending side) of a delivered tx that consumed a watched
/// script. Only produced for prevouts the server **retained** the script for;
/// unretained ones surface in [`PrefixHits::unresolved`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingHit {
    /// The input index that spends the prevout, if it was located in the decoded
    /// tx (it always should be; `None` only on a malformed/mismatched payload).
    pub vin: Option<u32>,
    /// The consumed outpoint.
    pub outpoint: Outpoint,
    /// The matched `sha256(scriptPubKey)`.
    pub scripthash: [u8; 32],
    /// The prevout's scriptPubKey.
    pub script_pubkey: ScriptBuf,
    /// The prevout value in satoshis. `None` when the server retained the script
    /// but not the value (distinct from a genuine 0-sat prevout, `Some(0)`).
    pub amount: Option<u64>,
}

/// The result of re-filtering one [`PrefixMatch`] against the watched set: the
/// outputs and spent prevouts that are genuine matches, plus any spend-side
/// prevouts the server did not retain and so could not be filtered locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixHits {
    /// The delivered transaction's id (recomputed from `raw_tx`).
    pub txid: Txid,
    /// `false` = mempool, `true` = connected block.
    pub confirmed: bool,
    /// Block height when confirmed; 0 in the mempool.
    pub height: u32,
    /// Outputs paying a watched script.
    pub funding: Vec<FundingHit>,
    /// Spent prevouts of a watched script (script retained by the server).
    pub spending: Vec<SpendingHit>,
    /// Spend-side prevouts the server did not retain (a mempool spend below the
    /// `full` retention tier): the bucket fired but the script is absent, so the
    /// match cannot be confirmed locally. Resolve these outpoints yourself to
    /// complete the filter — never treat them as non-matches.
    pub unresolved: Vec<Outpoint>,
}

impl PrefixHits {
    /// Whether any genuine output or spend match was found.
    pub fn is_match(&self) -> bool {
        !self.funding.is_empty() || !self.spending.is_empty()
    }

    /// Whether any spend-side prevout could not be filtered locally (script not
    /// retained); the caller must resolve [`unresolved`](Self::unresolved) to be
    /// sure this tx is a true non-match.
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }
}

/// Holds the consumer's real scriptPubKeys and re-filters coarse prefix-bucket
/// deliveries down to true matches.
#[derive(Debug, Clone, Default)]
pub struct PrefixWatcher {
    /// `sha256(scriptPubKey)` of every watched script.
    watched: HashSet<[u8; 32]>,
}

impl PrefixWatcher {
    /// An empty watcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a watcher over `scripts`.
    pub fn with_scripts<'a>(scripts: impl IntoIterator<Item = &'a Script>) -> Self {
        let mut w = Self::new();
        for s in scripts {
            w.watch_script(s);
        }
        w
    }

    /// Watch a scriptPubKey; returns its scripthash (the value the server keys
    /// on). Idempotent.
    pub fn watch_script(&mut self, script_pubkey: &Script) -> [u8; 32] {
        self.watch_script_bytes(script_pubkey.as_bytes())
    }

    /// Watch a scriptPubKey by raw bytes; returns its scripthash.
    pub fn watch_script_bytes(&mut self, script_pubkey: &[u8]) -> [u8; 32] {
        let sh = scripthash_of(script_pubkey);
        self.watched.insert(sh);
        sh
    }

    /// Stop watching a scriptPubKey. Returns whether it had been watched.
    pub fn unwatch_script(&mut self, script_pubkey: &Script) -> bool {
        self.watched.remove(&scripthash_of(script_pubkey.as_bytes()))
    }

    /// Whether `scripthash` is in the watched set.
    pub fn is_watched(&self, scripthash: &[u8; 32]) -> bool {
        self.watched.contains(scripthash)
    }

    /// Number of watched scripts.
    pub fn len(&self) -> usize {
        self.watched.len()
    }

    /// Whether the watcher holds no scripts.
    pub fn is_empty(&self) -> bool {
        self.watched.is_empty()
    }

    /// The deduplicated set of `(prefix, bits)` buckets that cover every watched
    /// script at width `bits` — pass straight to
    /// [`WatchHandle::add_script_prefixes`](crate::WatchHandle::add_script_prefixes).
    /// Distinct scripts that share a bucket collapse to one registration.
    pub fn prefixes(&self, bits: u32) -> Vec<(Vec<u8>, u32)> {
        let bits = bits.clamp(1, 256);
        let n = (bits as usize).div_ceil(8).min(32);
        let buckets: HashSet<Vec<u8>> = self.watched.iter().map(|sh| sh[..n].to_vec()).collect();
        buckets.into_iter().map(|p| (p, bits)).collect()
    }

    /// Re-filter a [`PrefixMatch`] against the watched set. Decodes `raw_tx`,
    /// recomputes `sha256(scriptPubKey)` for each output and each retained spent
    /// prevout, and returns the true hits. Returns [`StreamError::Decode`] if
    /// `raw_tx` is not a valid consensus-serialized transaction.
    pub fn filter(&self, m: &PrefixMatch) -> Result<PrefixHits, StreamError> {
        let tx: Transaction = consensus::deserialize(&m.raw_tx)
            .map_err(|e| StreamError::Decode(format!("prefix raw_tx decode: {e}")))?;
        let txid = tx.compute_txid();

        let mut funding = Vec::new();
        for (vout, out) in tx.output.iter().enumerate() {
            let sh = scripthash_of(out.script_pubkey.as_bytes());
            if self.watched.contains(&sh) {
                funding.push(FundingHit {
                    vout: vout as u32,
                    scripthash: sh,
                    value: out.value.to_sat(),
                    script_pubkey: out.script_pubkey.clone(),
                });
            }
        }

        let mut spending = Vec::new();
        let mut unresolved = Vec::new();
        for sp in &m.matched_prevouts {
            if sp.script_pubkey.is_empty() {
                // Script not retained — cannot hash it; the caller resolves it.
                unresolved.push(sp.outpoint.clone());
                continue;
            }
            let sh = scripthash_of(&sp.script_pubkey);
            if self.watched.contains(&sh) {
                spending.push(SpendingHit {
                    vin: find_vin(&tx, &sp.outpoint),
                    outpoint: sp.outpoint.clone(),
                    scripthash: sh,
                    script_pubkey: ScriptBuf::from_bytes(sp.script_pubkey.clone()),
                    amount: sp.amount,
                });
            }
        }

        Ok(PrefixHits { txid, confirmed: m.confirmed, height: m.height, funding, spending, unresolved })
    }
}

/// Locate the input index that spends `outpoint` in `tx`, comparing the raw
/// (internal byte order) txid and vout the wire carries.
fn find_vin(tx: &Transaction, outpoint: &Outpoint) -> Option<u32> {
    tx.input.iter().position(|i| {
        i.previous_output.vout == outpoint.vout
            && i.previous_output.txid.to_byte_array().as_slice() == outpoint.txid.as_slice()
    }).map(|p| p as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ScriptPrefix, SpentPrevout};
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    fn spk(tag: u8) -> ScriptBuf {
        // A distinct, valid-enough scriptPubKey per tag (OP_RETURN <tag>).
        ScriptBuf::from_bytes(vec![0x6a, 0x01, tag])
    }

    fn dummy_outpoint(byte: u8, vout: u32) -> (OutPoint, Outpoint) {
        let txid = Txid::from_byte_array([byte; 32]);
        (
            OutPoint { txid, vout },
            Outpoint { txid: txid.to_byte_array().to_vec(), vout },
        )
    }

    fn tx_with(outputs: Vec<TxOut>, inputs: Vec<TxIn>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    fn prefix_match(tx: &Transaction, prevouts: Vec<SpentPrevout>) -> PrefixMatch {
        PrefixMatch {
            prefix: ScriptPrefix { prefix: vec![0u8, 0u8], bits: 16 },
            raw_tx: consensus::serialize(tx),
            confirmed: true,
            height: 800_000,
            matched_prevouts: prevouts,
        }
    }

    #[test]
    fn scripthash_matches_single_sha256_of_spk() {
        // Mirrors the server's `scripthash_of`: a plain sha256 of the spk bytes.
        let s = spk(1);
        let expect = sha256::Hash::hash(s.as_bytes()).to_byte_array();
        assert_eq!(scripthash_of(s.as_bytes()), expect);
    }

    #[test]
    fn prefix_of_takes_top_bytes_of_scripthash() {
        let s = spk(7);
        let sh = scripthash_of(s.as_bytes());
        assert_eq!(prefix_of(s.as_bytes(), 16), (sh[..2].to_vec(), 16));
        assert_eq!(prefix_of(s.as_bytes(), 12), (sh[..2].to_vec(), 12)); // ceil(12/8)=2
        assert_eq!(prefix_of(s.as_bytes(), 8), (sh[..1].to_vec(), 8));
        assert_eq!(prefix_of(s.as_bytes(), 256).0.len(), 32);
    }

    #[test]
    fn funding_match_only_for_watched_output() {
        let watched = spk(1);
        let decoy = spk(2);
        let mut w = PrefixWatcher::new();
        w.watch_script(&watched);

        let tx = tx_with(
            vec![
                TxOut { value: Amount::from_sat(500), script_pubkey: decoy },
                TxOut { value: Amount::from_sat(1234), script_pubkey: watched.clone() },
            ],
            vec![],
        );
        let hits = w.filter(&prefix_match(&tx, vec![])).unwrap();
        assert!(hits.is_match());
        assert_eq!(hits.funding.len(), 1);
        assert_eq!(hits.funding[0].vout, 1);
        assert_eq!(hits.funding[0].value, 1234);
        assert_eq!(hits.funding[0].script_pubkey, watched);
        assert!(hits.spending.is_empty());
        assert!(!hits.has_unresolved());
    }

    #[test]
    fn decoy_only_tx_is_no_match() {
        let mut w = PrefixWatcher::new();
        w.watch_script(&spk(1));
        let tx = tx_with(
            vec![TxOut { value: Amount::from_sat(9), script_pubkey: spk(99) }],
            vec![],
        );
        let hits = w.filter(&prefix_match(&tx, vec![])).unwrap();
        assert!(!hits.is_match());
        assert!(!hits.has_unresolved());
    }

    #[test]
    fn spend_match_locates_vin_and_amount() {
        let watched = spk(5);
        let mut w = PrefixWatcher::new();
        w.watch_script(&watched);

        let (op_btc, op_wire) = dummy_outpoint(0xaa, 3);
        let tx = tx_with(
            vec![TxOut { value: Amount::from_sat(10), script_pubkey: spk(42) }],
            vec![
                TxIn {
                    previous_output: dummy_outpoint(0xbb, 0).0,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op_btc,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
        );
        let prevout = SpentPrevout {
            outpoint: op_wire.clone(),
            script_pubkey: watched.as_bytes().to_vec(),
            amount: Some(7777),
        };
        let hits = w.filter(&prefix_match(&tx, vec![prevout])).unwrap();
        assert_eq!(hits.spending.len(), 1);
        assert_eq!(hits.spending[0].vin, Some(1)); // second input spends it
        assert_eq!(hits.spending[0].amount, Some(7777));
        assert_eq!(hits.spending[0].outpoint, op_wire);
    }

    #[test]
    fn unretained_prevout_surfaces_as_unresolved() {
        let mut w = PrefixWatcher::new();
        w.watch_script(&spk(5));
        let (_op_btc, op_wire) = dummy_outpoint(0xcc, 1);
        let tx = tx_with(
            vec![TxOut { value: Amount::from_sat(10), script_pubkey: spk(42) }],
            vec![],
        );
        // Empty script_pubkey = server did not retain it.
        let prevout = SpentPrevout { outpoint: op_wire.clone(), script_pubkey: vec![], amount: None };
        let hits = w.filter(&prefix_match(&tx, vec![prevout])).unwrap();
        assert!(!hits.is_match()); // no confirmable hit
        assert!(hits.has_unresolved());
        assert_eq!(hits.unresolved, vec![op_wire]);
    }

    #[test]
    fn prefixes_dedup_shared_bucket() {
        let mut w = PrefixWatcher::new();
        w.watch_script(&spk(1));
        w.watch_script(&spk(2));
        // At 1 bit, both scripts almost certainly collapse to <= 2 buckets; at
        // 256 bits each script is its own bucket.
        assert_eq!(w.prefixes(256).len(), 2);
        assert!(w.prefixes(1).len() <= 2);
        for (p, bits) in w.prefixes(16) {
            assert_eq!(bits, 16);
            assert_eq!(p.len(), 2);
        }
    }

    #[test]
    fn garbage_raw_tx_is_decode_error() {
        let w = PrefixWatcher::new();
        let m = PrefixMatch {
            prefix: ScriptPrefix { prefix: vec![0, 0], bits: 16 },
            raw_tx: vec![0xff, 0x00, 0x01],
            confirmed: false,
            height: 0,
            matched_prevouts: vec![],
        };
        assert!(matches!(w.filter(&m), Err(StreamError::Decode(_))));
    }
}
