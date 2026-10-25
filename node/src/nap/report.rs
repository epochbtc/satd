//! Reports and snapshots.
//!
//! A report is computed from an attestation set at one tip: for each
//! `(outpoint, key)`, the attestation that counts is the newest valid one
//! (Supersession), and it counts with its coin's value. The set is either
//! the aggregator's own or a snapshot another aggregator exported; given the
//! same set and the same tip, the report is the same, byte for byte. Every
//! number in it is an integer: weights in satoshis, shares in parts per
//! million rounded down, so no implementation's float formatting enters it.
//!
//! A snapshot holds every attestation the set holds, the superseded ones
//! kept for reorgs included, in ascending id order. Its digest is SHA256
//! over each attestation's wire form prefixed with its length as a compact
//! size, in that order. The file:
//!
//! ```text
//! magic     "NAPS"
//! version   u32 LE    // 1
//! height    u32 LE    // the tip it was exported at
//! hash      [32]
//! count     u32 LE
//! entries   count × { length compact size, attestation }
//! checksum  [32]      // SHA256 of everything before it
//! ```
//!
//! The digest is over the entries alone, so it names the set whatever tip
//! the file was exported at.

use std::collections::BTreeMap;

use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{Amount, BlockHash, OutPoint, Script};
use serde_json::{Value, json};

use super::validity::{Timelocks, check_chain, check_timelocks};
use super::{Attestation, ChainView, Coin, MAX_ATTESTATION_SIZE, supersedes};

const MAGIC: &[u8; 4] = b"NAPS";
/// The snapshot file format version.
pub const SNAPSHOT_VERSION: u32 = 1;
const HEADER_LEN: usize = 4 + 4 + 4 + 32 + 4;
const CHECKSUM_LEN: usize = 32;

/// Value tiers, by coin value in satoshis: each is below its bound, the
/// last unbounded.
const VALUE_TIERS: [(&str, u64); 4] =
    [("<0.01", 1_000_000), ("0.01-1", 100_000_000), ("1-100", 10_000_000_000), (">=100", u64::MAX)];
/// Anchor-age buckets in blocks (tip height − anchor height): about two
/// weeks, three months, and the freshness window, which no valid
/// attestation reaches.
const ANCHOR_AGES: [(&str, u32); 3] = [("<2016", 2_016), ("<13104", 13_104), ("<26208", 26_208)];
/// Coin-age buckets in blocks at the tip (tip height − coin height): about
/// three months, one, two and five years, and older.
const COIN_AGES: [(&str, u32); 5] =
    [("<13104", 13_104), ("<52416", 52_416), ("<104832", 104_832), ("<262080", 262_080), (">=262080", u32::MAX)];
/// Script types, by the coin's scriptPubKey.
const SCRIPT_TYPES: [&str; 6] = ["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr", "other"];
/// The largest outpoints whose share of a value's weight a report gives.
const CONCENTRATION: [usize; 2] = [10, 100];

/// An exported attestation set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The tip it was exported at. Informational: a report is computed at
    /// the reader's tip.
    pub height: u32,
    pub hash: BlockHash,
    /// Ascending by id, each once.
    pub attestations: Vec<Attestation>,
}

/// `atts` in snapshot order: ascending by id, each once.
pub fn canonical(atts: impl IntoIterator<Item = Attestation>) -> Vec<Attestation> {
    let mut keyed: Vec<(sha256::Hash, Attestation)> = atts.into_iter().map(|a| (a.id(), a)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    keyed.into_iter().map(|(_, a)| a).collect()
}

/// The entries' bytes: each attestation's wire form prefixed by its length.
fn entries(atts: &[Attestation]) -> Vec<u8> {
    let mut buf = Vec::new();
    for att in atts {
        let bytes = att.to_bytes();
        encode::VarInt(bytes.len() as u64).consensus_encode(&mut buf).expect("a Vec does not fail");
        buf.extend_from_slice(&bytes);
    }
    buf
}

/// The digest of `atts`, which are in snapshot order ([`canonical`]).
pub fn digest(atts: &[Attestation]) -> sha256::Hash {
    sha256::Hash::hash(&entries(atts))
}

/// The snapshot file's bytes. `atts` are in snapshot order.
pub fn encode_snapshot(height: u32, hash: BlockHash, atts: &[Attestation]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(hash.as_byte_array());
    buf.extend_from_slice(&(atts.len() as u32).to_le_bytes());
    buf.extend_from_slice(&entries(atts));
    let checksum = sha256::Hash::hash(&buf);
    buf.extend_from_slice(checksum.as_byte_array());
    buf
}

/// Parse a snapshot file: exactly what [`encode_snapshot`] writes, holding
/// at most `max` attestations (0 is no limit), or an error. Entries out of
/// order or repeated are refused, so a snapshot has one form and one digest.
pub fn decode_snapshot(bytes: &[u8], max: usize) -> Result<Snapshot, String> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN {
        return Err("the file is truncated".into());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if &body[..4] != MAGIC {
        return Err("the file is not a NAP snapshot".into());
    }
    if sha256::Hash::hash(body).as_byte_array() != checksum {
        return Err("the checksum does not match".into());
    }
    let u32_at = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().expect("4 bytes"));
    let version = u32_at(4);
    if version != SNAPSHOT_VERSION {
        return Err(format!("unsupported snapshot version {version}"));
    }
    let height = u32_at(8);
    let hash = BlockHash::from_byte_array(body[12..44].try_into().expect("32 bytes"));
    let count = u32_at(44) as usize;
    if max != 0 && count > max {
        return Err(format!("the snapshot holds {count} attestations, more than the {max} this node takes"));
    }
    let mut rest = &body[HEADER_LEN..];
    let mut out: Vec<Attestation> = Vec::with_capacity(count.min(rest.len()));
    let mut last: Option<sha256::Hash> = None;
    for i in 0..count {
        let len = encode::VarInt::consensus_decode(&mut rest).map_err(|e| format!("entry {i}: {e}"))?.0;
        if len > MAX_ATTESTATION_SIZE as u64 || rest.len() < len as usize {
            return Err(format!("entry {i}: bad length {len}"));
        }
        let (bytes, tail) = rest.split_at(len as usize);
        rest = tail;
        let att = Attestation::from_bytes(bytes).map_err(|e| format!("entry {i}: {e}"))?;
        let id = att.id();
        if last.is_some_and(|l| l >= id) {
            return Err(format!("entry {i}: not in ascending id order"));
        }
        last = Some(id);
        out.push(att);
    }
    if !rest.is_empty() {
        return Err(format!("{} bytes follow the last entry", rest.len()));
    }
    Ok(Snapshot { height, hash, attestations: out })
}

/// An attestation that counts, with its coin.
#[derive(Debug, Clone)]
pub struct Counted {
    pub attestation: Attestation,
    pub coin: Coin,
}

/// The chain state a report states: the tip and the UTXO set's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    pub height: u32,
    pub hash: BlockHash,
    pub utxo_total: Amount,
}

/// Judge `held`, attestations whose signatures verified with the timelocks
/// they left, at `v`'s tip, and return the tip and, for each
/// `(outpoint, key)`, the newest valid one: the attestations that count.
/// Ordered by outpoint and key.
pub fn counting_at(held: &[(Attestation, Timelocks)], v: &dyn ChainView) -> (Tip, Vec<Counted>) {
    let mut best: BTreeMap<(OutPoint, &str), Counted> = BTreeMap::new();
    for (att, locks) in held {
        let Ok(coin) = check_chain(att, v) else { continue };
        if check_timelocks(v, &coin, locks).is_err() {
            continue;
        }
        best.entry((att.outpoint(), att.key()))
            .and_modify(|cur| {
                if supersedes(att, &cur.attestation) {
                    *cur = Counted { attestation: att.clone(), coin: coin.clone() };
                }
            })
            .or_insert_with(|| Counted { attestation: att.clone(), coin: coin.clone() });
    }
    let height = v.tip_height();
    let tip = Tip {
        height,
        hash: v.block_hash(height).expect("the active chain holds its tip"),
        utxo_total: v.utxo_total(),
    };
    (tip, best.into_values().collect())
}

/// `part` of `whole` in parts per million, rounded down; 0 of nothing.
fn ppm(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    (u128::from(part) * 1_000_000 / u128::from(whole)) as u64
}

/// The script type a report files `script` under.
fn script_type(script: &Script) -> &'static str {
    if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2tr() {
        "p2tr"
    } else {
        "other"
    }
}

/// Weight and outpoints.
#[derive(Debug, Clone, Copy, Default)]
struct Sum {
    weight: u64,
    outpoints: u64,
}

impl Sum {
    fn add(&mut self, sat: u64) {
        self.weight += sat;
        self.outpoints += 1;
    }

    fn json(&self) -> Value {
        json!({ "weight_sat": self.weight, "outpoints": self.outpoints })
    }
}

/// `labels` with each one's sum, in order, the empty ones included.
fn buckets<'a>(labels: impl IntoIterator<Item = &'a str>, sums: &[Sum], name: &str) -> Value {
    Value::Array(
        labels
            .into_iter()
            .zip(sums)
            .map(|(label, s)| {
                let mut v = s.json();
                v[name] = json!(label);
                v
            })
            .collect(),
    )
}

/// The first bucket `x` is below.
fn bucket<T: PartialOrd>(x: T, bounds: impl IntoIterator<Item = T>) -> usize {
    bounds.into_iter().position(|b| x < b).expect("the last bucket is unbounded")
}

/// One value of one key.
#[derive(Default)]
struct ValueTally {
    total: Sum,
    tiers: [Sum; VALUE_TIERS.len()],
    anchor_ages: [Sum; ANCHOR_AGES.len()],
    coin_ages: [Sum; COIN_AGES.len()],
    scripts: [Sum; SCRIPT_TYPES.len()],
    /// Each outpoint's weight, for concentration.
    weights: Vec<u64>,
}

impl ValueTally {
    fn add(&mut self, c: &Counted, tip: u32) {
        let sat = c.coin.value.to_sat();
        self.total.add(sat);
        self.tiers[bucket(sat, VALUE_TIERS.map(|(_, b)| b))].add(sat);
        let anchor_age = tip.saturating_sub(c.attestation.anchor_height());
        // The freshness rule keeps every counted anchor inside the last
        // bucket; the clamp only spares a panic.
        let at = ANCHOR_AGES.iter().position(|(_, b)| anchor_age < *b).unwrap_or(ANCHOR_AGES.len() - 1);
        self.anchor_ages[at].add(sat);
        self.coin_ages[bucket(tip.saturating_sub(c.coin.height), COIN_AGES.map(|(_, b)| b))].add(sat);
        let script = script_type(&c.coin.script_pubkey);
        self.scripts[SCRIPT_TYPES.iter().position(|t| *t == script).expect("listed")].add(sat);
        self.weights.push(sat);
    }
}

/// The report on `counting`, the attestations that count at `tip`, from a
/// set of `held` attestations with `digest`. `invalid` is how many in the
/// set failed their signature check (always 0 for the aggregator's own,
/// which holds only verified ones).
pub fn report(tip: Tip, digest: sha256::Hash, held: usize, invalid: usize, counting: &[Counted]) -> Value {
    let mut keys: BTreeMap<&str, (Sum, BTreeMap<&str, ValueTally>)> = BTreeMap::new();
    for c in counting {
        let att = &c.attestation;
        let (withdrawn, values) = keys.entry(att.key()).or_default();
        if att.is_withdrawal() {
            withdrawn.add(c.coin.value.to_sat());
        } else {
            values.entry(att.value()).or_default().add(c, tip.height);
        }
    }
    let total = tip.utxo_total.to_sat();
    let keys: Vec<Value> = keys
        .into_iter()
        .map(|(key, (withdrawn, values))| {
            let participating = values.values().fold(Sum::default(), |mut s, v| {
                s.weight += v.total.weight;
                s.outpoints += v.total.outpoints;
                s
            });
            let mut values: Vec<(&str, ValueTally)> = values.into_iter().collect();
            // Heaviest first; equal weights by value, so the order is fixed.
            values.sort_by(|a, b| b.1.total.weight.cmp(&a.1.total.weight).then(a.0.cmp(b.0)));
            let values: Vec<Value> = values
                .into_iter()
                .map(|(value, mut t)| {
                    t.weights.sort_unstable_by(|a, b| b.cmp(a));
                    let concentration: serde_json::Map<String, Value> = CONCENTRATION
                        .iter()
                        .map(|&n| {
                            let top: u64 = t.weights.iter().take(n).sum();
                            (format!("top{n}_ppm"), json!(ppm(top, t.total.weight)))
                        })
                        .collect();
                    json!({
                        "value": value,
                        "weight_sat": t.total.weight,
                        "outpoints": t.total.outpoints,
                        "share_ppm": ppm(t.total.weight, participating.weight),
                        "coverage_ppm": ppm(t.total.weight, total),
                        "value_tiers": buckets(VALUE_TIERS.map(|(l, _)| l), &t.tiers, "tier"),
                        "anchor_age": buckets(ANCHOR_AGES.map(|(l, _)| l), &t.anchor_ages, "blocks"),
                        "coin_age": buckets(COIN_AGES.map(|(l, _)| l), &t.coin_ages, "blocks"),
                        "script_types": buckets(SCRIPT_TYPES, &t.scripts, "type"),
                        "concentration": concentration,
                    })
                })
                .collect();
            json!({
                "key": key,
                "weight_sat": participating.weight,
                "outpoints": participating.outpoints,
                "coverage_ppm": ppm(participating.weight, total),
                "withdrawn": withdrawn.json(),
                "values": values,
            })
        })
        .collect();
    json!({
        "height": tip.height,
        "hash": tip.hash.to_string(),
        "utxo_total_sat": total,
        "digest": digest.to_string(),
        "attestations": held,
        "invalid": invalid,
        "counting": counting.len(),
        "keys": keys,
    })
}
