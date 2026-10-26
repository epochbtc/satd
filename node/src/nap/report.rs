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
//!
//! Work over the whole set is split between threads where its items are
//! independent ([`par`]): ids for sorting, entries' bytes (hashed and
//! written in order), the chain rules for each attestation, and a replay's
//! signatures. What depends on order, the hashing and the choice of the
//! attestation that counts, runs in order as before, so nothing a report
//! or a snapshot holds depends on how the work was split.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read as _, Write};
use std::path::Path;

use bitcoin::consensus::encode::{self, Decodable};
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
use bitcoin::{Amount, BlockHash, OutPoint, Script};
use serde_json::{Value, json};

use super::par;
use super::publisher::ChainSource;
use super::validity::{Timelocks, check_chain, check_timelocks, verify_signature};
use super::{Attestation, ChainView, Coin, MAX_ATTESTATION_SIZE, supersedes};

const MAGIC: &[u8; 4] = b"NAPS";
/// The snapshot file format version.
pub const SNAPSHOT_VERSION: u32 = 1;
const HEADER_LEN: usize = 4 + 4 + 4 + 32 + 4;
const CHECKSUM_LEN: usize = 32;
/// The fewest bytes an entry takes: its length and the smallest
/// attestation (version, outpoint, a one-byte key, an empty value, the
/// anchor, the format and an empty signature), well over this.
pub(super) const MIN_ENTRY_LEN: usize = 64;

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

/// `atts` in snapshot order: ascending by id, each once. Owned
/// attestations or references to them, so a set can be ordered without
/// copying it.
pub fn canonical<A: Borrow<Attestation> + Send + Sync>(atts: impl IntoIterator<Item = A>) -> Vec<A> {
    let atts: Vec<A> = atts.into_iter().collect();
    let ids = par::map(&atts, |a| a.borrow().id());
    let mut keyed: Vec<(sha256::Hash, A)> = ids.into_iter().zip(atts).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    keyed.into_iter().map(|(_, a)| a).collect()
}

/// How many entries are serialized at a time, between threads, before
/// they are written in order: the most of the set held in memory at once.
pub(super) const ENTRY_BATCH: usize = 4_096;

/// Write the entries to `w` in order: each attestation's wire form
/// prefixed by its length. They are serialized [`ENTRY_BATCH`] at a time,
/// so the whole set is never in one buffer.
fn write_entries<'a>(w: &mut dyn Write, atts: impl IntoIterator<Item = &'a Attestation>) -> std::io::Result<()> {
    let mut atts = atts.into_iter();
    let mut batch: Vec<&Attestation> = Vec::with_capacity(ENTRY_BATCH);
    loop {
        batch.clear();
        batch.extend(atts.by_ref().take(ENTRY_BATCH));
        if batch.is_empty() {
            return Ok(());
        }
        for entry in par::map(&batch, |att| entry(att)) {
            w.write_all(&entry)?;
        }
    }
}

/// One entry: `att`'s wire form prefixed by its length.
fn entry(att: &Attestation) -> Vec<u8> {
    let bytes = att.to_bytes();
    let mut out = encode::serialize(&encode::VarInt(bytes.len() as u64));
    out.extend_from_slice(&bytes);
    out
}

/// A writer that hashes what passes through it.
struct Hashing<'w> {
    inner: &'w mut dyn Write,
    engine: sha256::HashEngine,
}

impl Write for Hashing<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.engine.input(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The digest of `atts`, which are in snapshot order ([`canonical`]),
/// hashed an entry at a time.
pub fn digest<'a>(atts: impl IntoIterator<Item = &'a Attestation>) -> sha256::Hash {
    let mut sink = std::io::sink();
    let mut hashing = Hashing { inner: &mut sink, engine: sha256::Hash::engine() };
    write_entries(&mut hashing, atts).expect("a sink does not fail");
    sha256::Hash::from_engine(hashing.engine)
}

/// Write the snapshot file to `w`, the checksum computed as it goes, so
/// the file is never held whole in memory, and return the set's digest,
/// computed from the same bytes. `atts` are in snapshot order.
pub fn write_snapshot(
    w: &mut dyn Write,
    height: u32,
    hash: BlockHash,
    atts: &[Attestation],
) -> std::io::Result<sha256::Hash> {
    let mut hashing = Hashing { inner: w, engine: sha256::Hash::engine() };
    hashing.write_all(MAGIC)?;
    hashing.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
    hashing.write_all(&height.to_le_bytes())?;
    hashing.write_all(hash.as_byte_array())?;
    hashing.write_all(&(atts.len() as u32).to_le_bytes())?;
    let mut entries = Hashing { inner: &mut hashing, engine: sha256::Hash::engine() };
    write_entries(&mut entries, atts)?;
    let digest = sha256::Hash::from_engine(entries.engine);
    let checksum = sha256::Hash::from_engine(hashing.engine);
    hashing.inner.write_all(checksum.as_byte_array())?;
    Ok(digest)
}

/// The snapshot file's bytes, as [`write_snapshot`] writes them.
pub fn encode_snapshot(height: u32, hash: BlockHash, atts: &[Attestation]) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write_snapshot(&mut buf, height, hash, atts).expect("a Vec does not fail");
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
    let mut out: Vec<Attestation> = Vec::with_capacity(room_for(count, rest.len()));
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

/// The longest snapshot file holding at most `max` attestations (0 is no
/// limit): the header, the checksum, and `max` entries at the largest size,
/// whose length prefix is three bytes.
fn max_snapshot_len(max: usize) -> Option<u64> {
    (max != 0).then(|| {
        ((max as u64).saturating_mul((3 + MAX_ATTESTATION_SIZE) as u64)).saturating_add((HEADER_LEN + CHECKSUM_LEN) as u64)
    })
}

/// How many entries to reserve room for: those the file states, at most
/// as many as `bytes` can hold. The count is the file's word, so with no
/// limit a large one would otherwise reserve far more than the bytes fill.
pub(super) fn room_for(count: usize, bytes: usize) -> usize {
    count.min(bytes / MIN_ENTRY_LEN)
}

/// Read and parse the snapshot file at `path`, holding at most `max`
/// attestations (0 is no limit). A file longer than `max` attestations can
/// be is refused before it is read in full.
pub fn read_snapshot(path: &Path, max: usize) -> Result<Snapshot, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    match max_snapshot_len(max) {
        Some(limit) => {
            file.take(limit.saturating_add(1)).read_to_end(&mut bytes).map_err(|e| format!("reading {}: {e}", path.display()))?;
            if bytes.len() as u64 > limit {
                return Err(format!(
                    "{}: the file is longer than a snapshot of {max} attestations can be",
                    path.display()
                ));
            }
        }
        None => {
            let mut file = file;
            file.read_to_end(&mut bytes).map_err(|e| format!("reading {}: {e}", path.display()))?;
        }
    }
    decode_snapshot(&bytes, max).map_err(|e| format!("{}: {e}", path.display()))
}

/// Write `bytes` to `path`, which must not exist. They go to a temporary
/// file of this writer's own, synced, which is then linked to `path`: the
/// link fails if `path` exists, so a file made meanwhile is never replaced,
/// and `path` appears only whole, so a crash leaves at most a stray
/// temporary, never a partial file that blocks the next export. On a
/// filesystem without hard links the bytes are written to `path` directly,
/// created only if it does not exist: never replacing a file, though a
/// crash then can leave a partial one. The directory is synced, so the name
/// outlives a power loss.
pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_new_with(path, |w| w.write_all(bytes))
}

/// [`write_new`], the contents written by `write`, which may run twice (the
/// second time to `path` directly, on a filesystem without hard links). Its
/// writes are buffered on their way to the file, so it can stream.
pub fn write_new_with(path: &Path, write: impl Fn(&mut dyn Write) -> std::io::Result<()>) -> std::io::Result<()> {
    write_new_linking(path, write, |from, to| std::fs::hard_link(from, to))
}

/// [`write_new_with`], with the link step given: tests stand in a
/// filesystem without hard links.
pub(super) fn write_new_linking(
    path: &Path,
    write: impl Fn(&mut dyn Write) -> std::io::Result<()>,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().ok_or_else(|| std::io::Error::other("the path names no file"))?;
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{}.{}.{seq}.tmp", name.to_string_lossy(), std::process::id()));
    let linked = write_synced(&tmp, &write).and_then(|()| link(&tmp, path));
    let _ = std::fs::remove_file(&tmp);
    match linked {
        // `link(2)` fails with EPERM (PermissionDenied) on a filesystem
        // without hard links, such as FAT and exFAT. A real permission
        // problem fails the direct write the same way.
        Err(e) if matches!(e.kind(), std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied) => {
            write_synced(path, &write)?
        }
        other => other?,
    }
    // Directories cannot be opened for syncing on every platform; the file
    // itself is already synced.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Create `path`, which must not exist, with what `write` writes, buffered
/// and synced. A failed write removes the file it created; a file it did
/// not create is never touched.
fn write_synced(path: &Path, write: &dyn Fn(&mut dyn Write) -> std::io::Result<()>) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    let written = (|| {
        let mut buffered = std::io::BufWriter::new(file);
        write(&mut buffered)?;
        buffered.into_inner().map_err(|e| e.into_error())?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(path);
    }
    written
}

/// How many times [`replay`] reads the chain again when it moved between
/// reading the coins and judging the set.
const REPLAY_ATTEMPTS: usize = 3;

/// A snapshot judged at a tip.
#[derive(Debug, Clone)]
pub struct Replay {
    pub tip: Tip,
    pub counting: Vec<Counted>,
    /// Attestations whose coin is in the UTXO set and whose signature fails.
    pub invalid: usize,
}

/// Verify `atts`, a snapshot's attestations, against their coins and judge
/// them at `chain`'s tip. The signatures are verified outside any chain
/// read, so the coins are read first and the set judged after; if the tip
/// moved in between, a coin read at one tip could be judged at another, so
/// both reads are made again until they agree. A signature's result is
/// kept across attempts: an outpoint's scriptPubKey never changes. `None`
/// when the chain would not hold still.
pub fn replay(chain: &impl ChainSource, atts: &[Attestation]) -> Option<Replay> {
    let ids = par::map(atts, Attestation::id);
    let mut verified: HashMap<sha256::Hash, Option<Timelocks>> = HashMap::new();
    for _ in 0..REPLAY_ATTEMPTS {
        let (read_at, scripts) = chain.read(&|v| {
            let h = v.tip_height();
            let scripts = par::map(atts, |a| v.coin(&a.outpoint()).map(|c| c.script_pubkey));
            ((h, v.block_hash(h)), scripts)
        })?;
        // A coin not in the UTXO set cannot count; it is not verified. The
        // rest not verified on an earlier attempt are, between threads.
        let todo: Vec<(&sha256::Hash, &Attestation, &bitcoin::ScriptBuf)> = ids
            .iter()
            .zip(atts)
            .zip(&scripts)
            .filter_map(|((id, att), script)| Some((id, att, script.as_ref()?)))
            .filter(|(id, _, _)| !verified.contains_key(*id))
            .collect();
        let results = par::map(&todo, |(_, att, script)| verify_signature(att, script).ok());
        for ((id, _, _), result) in todo.iter().zip(results) {
            verified.insert(**id, result);
        }
        let mut held = Vec::with_capacity(atts.len());
        let mut invalid = 0;
        for ((att, id), script) in atts.iter().zip(&ids).zip(&scripts) {
            if script.is_none() {
                continue;
            }
            match verified[id] {
                Some(locks) => held.push((att.clone(), locks)),
                None => invalid += 1,
            }
        }
        let (tip, counting) = chain.read(&|v| counting_at(&held, v))?;
        if read_at == (tip.height, Some(tip.hash)) {
            return Some(Replay { tip, counting, invalid });
        }
    }
    None
}

/// The last report on a live set: computed at most once per tip and set,
/// however often it is asked for. While collection keeps changing the set,
/// a report on the same tip is served again for [`REPORT_REUSE`] even so:
/// it names the set it was computed from by its digest. Callers that ask
/// while it is computed wait for it rather than computing it again.
#[derive(Default)]
pub struct Cache(parking_lot::Mutex<Option<Cached>>);

/// How long a report on the current tip is served again although the set
/// changed since. A new tip is always reported on afresh.
pub const REPORT_REUSE: std::time::Duration = std::time::Duration::from_secs(30);

struct Cached {
    tip: BlockHash,
    changes: u64,
    at: std::time::Instant,
    report: Value,
}

impl Cache {
    /// The report at `tip` on the set as of `changes`
    /// ([`Aggregate::changes`](super::aggregate::Aggregate::changes)): the
    /// cached one if it was computed at `tip` and for `changes`, or at `tip`
    /// less than [`REPORT_REUSE`] before `now`; otherwise `compute`'s, which
    /// returns the tip it judged at and is cached under it. An error is not
    /// cached.
    pub fn get_or<E>(
        &self,
        tip: BlockHash,
        changes: u64,
        now: std::time::Instant,
        compute: impl FnOnce() -> Result<(BlockHash, Value), E>,
    ) -> Result<Value, E> {
        let mut cached = self.0.lock();
        let fresh = |c: &&Cached| {
            c.tip == tip && (c.changes == changes || now.saturating_duration_since(c.at) < REPORT_REUSE)
        };
        if let Some(c) = cached.as_ref().filter(fresh) {
            return Ok(c.report.clone());
        }
        let (judged_at, report) = compute()?;
        *cached = Some(Cached { tip: judged_at, changes, at: now, report: report.clone() });
        Ok(report)
    }
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
///
/// The rules are checked between threads; the attestation that counts is
/// chosen in `held`'s order, as it would be on one.
pub fn counting_at(held: &[(Attestation, Timelocks)], v: &(dyn ChainView + Sync)) -> (Tip, Vec<Counted>) {
    let coins = par::map(held, |(att, locks)| {
        let coin = check_chain(att, v).ok()?;
        check_timelocks(v, &coin, locks).ok().map(|_| coin)
    });
    let mut best: BTreeMap<(OutPoint, &str), Counted> = BTreeMap::new();
    for ((att, _), coin) in held.iter().zip(coins) {
        let Some(coin) = coin else { continue };
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
