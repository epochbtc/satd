//! The aggregator's attestation set, `<datadir>/nap/aggregate/aggregate.dat`.
//!
//! For each `(outpoint, key)` the set holds the attestations whose
//! signatures verified, newest first in supersession order: the one that
//! counts, and the ones it superseded while they may still be needed. A
//! superseded attestation is kept until the attestation that superseded it
//! is valid and its anchor [`REORG_DEPTH`] blocks deep, so that if a reorg
//! takes the newer anchor first, the older one counts again (Supersession).
//! Every generation is kept this way, up to [`MAX_GENERATIONS`]. An
//! outpoint holds at most [`MAX_KEYS_PER_OUTPOINT`] keys, the first seen
//! (design D3, amended 2026-10-23): a key new to a full outpoint is refused,
//! while the keys already held keep taking newer attestations.
//!
//! An attestation loaded from the file is judged once the chain can judge
//! it: while the node is behind its anchor (initial block download, a
//! reindex) its coin may not be in the UTXO set yet, so it waits, and is
//! saved again, until the chain reaches the anchor.
//!
//! [`Aggregate::on_tip`] judges every attestation at a new tip, with the
//! signature results already known, and drops those that can no longer
//! count: a spent coin, a stale anchor, or a chain-state failure whose
//! anchor is too deep for a reorg to undo. Nothing else is ever dropped.
//!
//! The file:
//!
//! ```text
//! magic     "SNAG"
//! version   u32 LE    // 1
//! count     u32 LE
//! entries   count × { attestation, source varstr }
//! checksum  [32]      // SHA256 of everything before it
//! ```

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{Amount, OutPoint};
use parking_lot::Mutex;

use super::publisher::ChainSource;
use super::validity::{Timelocks, check_chain, check_timelocks, verify_signature};
use super::{Attestation, ChainView, Rejection, store, supersedes};

/// How deep the anchor of a superseding attestation must be before the one
/// it superseded is dropped, and how deep the anchor of an attestation that
/// fails on chain state must be before it is dropped: past this depth a
/// reorg is not a practical concern.
pub const REORG_DEPTH: u32 = 144;
/// The most attestations kept for one `(outpoint, key)`. A holder can sign
/// any number within [`REORG_DEPTH`] blocks; this bounds what they cost.
pub const MAX_GENERATIONS: usize = 8;
/// The most keys kept for one outpoint: eight times what a publisher
/// serves ([`super::MAX_KEYS_PER_OUTPOINT`]), so that a holder publishing
/// through several publishers is not cut short, while one old coin cannot
/// make the set grow without bound (D3, amended 2026-10-23).
pub const MAX_KEYS_PER_OUTPOINT: usize = 256;
/// The most attestations the set holds by default (`-napaggregatormax`).
/// The per-outpoint bound does not bound the total, which many small old
/// coins would multiply; this does.
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_000_000;

const MAGIC: &[u8; 4] = b"SNAG";
/// The file format version.
pub const FILE_VERSION: u32 = 1;
const HEADER_LEN: usize = 12;
const CHECKSUM_LEN: usize = 32;
/// The longest source name stored.
const MAX_SOURCE_LEN: usize = 256;

type Key = (OutPoint, String);
type Status = Result<Amount, Rejection>;

/// An attestation in the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub attestation: Attestation,
    /// What its verified signature leaves for the chain to judge.
    pub locks: Timelocks,
    /// The peer it was first collected from.
    pub source: String,
    /// Its validity at the tip it was last judged at, with the coin's value
    /// when valid.
    pub status: Status,
}

/// What [`Aggregate::insert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inserted {
    /// The attestation is new to the set.
    Added,
    /// The set already holds it.
    Duplicate,
    /// [`MAX_GENERATIONS`] newer attestations for its `(outpoint, key)` are
    /// held, so it would be dropped at once.
    TooOld,
    /// Its key is new to an outpoint that already has
    /// [`MAX_KEYS_PER_OUTPOINT`].
    KeyLimit,
    /// It would add an `(outpoint, key)` to a set that already holds its
    /// most attestations.
    Full,
}

#[derive(Default)]
struct State {
    /// Each key's generations, newest first.
    entries: BTreeMap<Key, Vec<Held>>,
    ids: HashMap<sha256::Hash, Key>,
    /// Loaded from the file but not yet judged: the chain did not reach the
    /// coin when they were read.
    pending: Vec<(Attestation, String)>,
    /// Changed since the last save.
    dirty: bool,
}

impl State {
    fn remove_where(&mut self, key: &Key, drop: impl Fn(usize, &Held) -> bool) -> usize {
        let State { entries, ids, dirty, .. } = self;
        let Some(gens) = entries.get_mut(key) else { return 0 };
        let before = gens.len();
        let mut i = 0;
        gens.retain(|h| {
            let gone = drop(i, h);
            i += 1;
            if gone {
                ids.remove(&h.attestation.id());
            }
            !gone
        });
        let removed = before - gens.len();
        if gens.is_empty() {
            entries.remove(key);
        }
        if removed > 0 {
            *dirty = true;
        }
        removed
    }
}

pub struct Aggregate {
    path: PathBuf,
    state: Mutex<State>,
    /// The most attestations held before new `(outpoint, key)` pairs are
    /// refused. Pairs already held still take newer attestations, at most
    /// [`MAX_GENERATIONS`] each.
    max_attestations: usize,
}

impl Aggregate {
    /// Load the set at `path` (a missing file is an empty set), verify every
    /// signature in it again, and judge it at `chain`'s tip. The file is the
    /// node's own, but a signature that no longer verifies is dropped rather
    /// than trusted.
    pub fn open(path: PathBuf, chain: &impl ChainSource) -> Result<Self, String> {
        Self::open_with_max(path, chain, DEFAULT_MAX_ATTESTATIONS)
    }

    /// [`Self::open`], holding at most `max_attestations` (see
    /// [`Inserted::Full`]); 0 is no limit, as for the publisher. A file
    /// holding more, from a higher limit, keeps what fits and is rewritten
    /// without the rest.
    pub fn open_with_max(path: PathBuf, chain: &impl ChainSource, max_attestations: usize) -> Result<Self, String> {
        let loaded = load(&path)?;
        let agg = Aggregate { path, state: Mutex::new(State::default()), max_attestations };
        agg.state.lock().pending = loaded;
        // What loaded is what the file holds, unless some was dropped.
        let dropped = agg.judge_pending(chain);
        agg.state.lock().dirty = dropped;
        agg.on_tip(chain);
        Ok(agg)
    }

    /// Verify and insert the attestations loaded but not yet judged, those
    /// the chain can judge now. One whose coin is gone on a chain that holds
    /// its anchor was spent while the node was stopped, and is dropped, as
    /// is one whose signature no longer verifies. The rest wait. Returns
    /// whether any was dropped.
    fn judge_pending(&self, chain: &impl ChainSource) -> bool {
        // Left in place while judged, so a save meanwhile still writes them.
        let pending = self.state.lock().pending.clone();
        if pending.is_empty() {
            return false;
        }
        let mut dropped = false;
        let mut decided = std::collections::HashSet::new();
        for (att, source) in pending {
            // The coin first, the signature outside the read (a read may run
            // more than once), then the chain rules at the tip.
            let read = chain.read(&|v| {
                let anchored = v.block_hash(att.anchor_height()) == Some(att.anchor_hash());
                match v.coin(&att.outpoint()) {
                    Some(coin) => Ok(coin.script_pubkey),
                    // Spent while the node was stopped.
                    None if anchored => Err(Pending::Spent),
                    // Off the chain for good: past any reorg.
                    None if v.tip_height() >= att.anchor_height().saturating_add(REORG_DEPTH) => {
                        Err(Pending::Spent)
                    }
                    None => Err(Pending::Wait),
                }
            });
            let outcome = match read.unwrap_or(Err(Pending::Wait)) {
                Err(p) => p,
                Ok(script) => match verify_signature(&att, &script) {
                    Err(r) => Pending::Bad(r),
                    // Verified; if the tip will not hold still for the
                    // judging, it is held unjudged and the tip pass judges it.
                    Ok(locks) => match chain.read(&|v| (judge(&att, &locks, v), v.tip_height())) {
                        // One the tip pass would drop at once takes no place
                        // in the set, which a cap may have to share.
                        Some((status, tip)) if doomed(&status, att.anchor_height(), tip) => Pending::Spent,
                        Some((status, _)) => Pending::Verified(locks, status),
                        None => Pending::Verified(locks, Err(Rejection::NotYetValid("not judged yet"))),
                    },
                },
            };
            if !matches!(outcome, Pending::Wait) {
                decided.insert(att.id());
            }
            match outcome {
                // Still in `pending`, and in the file.
                Pending::Wait => {}
                Pending::Spent => dropped = true,
                Pending::Verified(locks, status) => {
                    // A refusal (already held, too old, or a full outpoint, as
                    // a file written under other limits can hold) leaves it
                    // out of the file too.
                    if self.insert(att, locks, source, status) != Inserted::Added {
                        dropped = true;
                    }
                }
                Pending::Bad(r) => {
                    dropped = true;
                    tracing::warn!(
                        target: "nap",
                        outpoint = %att.outpoint(),
                        key = att.key(),
                        "NAP: dropping an aggregated attestation whose signature no longer verifies: {r}"
                    );
                }
            }
        }
        let mut st = self.state.lock();
        st.pending.retain(|(a, _)| !decided.contains(&a.id()));
        st.dirty |= dropped;
        dropped
    }

    /// Whether the set holds the attestation with this id.
    pub fn contains(&self, id: &sha256::Hash) -> bool {
        self.state.lock().ids.contains_key(id)
    }

    /// Add an attestation whose signature verified, with its status at the
    /// tip it was judged at.
    pub fn insert(&self, att: Attestation, locks: Timelocks, source: String, status: Status) -> Inserted {
        let source = truncated(source, MAX_SOURCE_LEN);
        let key = (att.outpoint(), att.key().to_owned());
        let id = att.id();
        let mut st = self.state.lock();
        if st.ids.contains_key(&id) {
            return Inserted::Duplicate;
        }
        if !st.entries.contains_key(&key) && keys_for(&st.entries, att.outpoint()) >= MAX_KEYS_PER_OUTPOINT {
            return Inserted::KeyLimit;
        }
        if self.max_attestations != 0 && !st.entries.contains_key(&key) && st.ids.len() >= self.max_attestations {
            return Inserted::Full;
        }
        let gens = st.entries.entry(key.clone()).or_default();
        let at = gens.iter().position(|h| supersedes(&att, &h.attestation)).unwrap_or(gens.len());
        if at >= MAX_GENERATIONS {
            if gens.is_empty() {
                st.entries.remove(&key);
            }
            return Inserted::TooOld;
        }
        gens.insert(at, Held { attestation: att, locks, source, status });
        let dropped: Vec<sha256::Hash> =
            gens.drain(MAX_GENERATIONS.min(gens.len())..).map(|h| h.attestation.id()).collect();
        for d in dropped {
            st.ids.remove(&d);
        }
        st.ids.insert(id, key);
        st.dirty = true;
        Inserted::Added
    }

    /// Judge every attestation at `chain`'s tip and drop those that can no
    /// longer count (see the module docs). Returns how many were dropped.
    pub fn on_tip(&self, chain: &impl ChainSource) -> usize {
        let _ = self.judge_pending(chain);
        let snapshot: Vec<(Key, sha256::Hash, Attestation, Timelocks)> = {
            let st = self.state.lock();
            st.entries
                .iter()
                .flat_map(|(k, gens)| {
                    gens.iter().map(move |h| (k.clone(), h.attestation.id(), h.attestation.clone(), h.locks))
                })
                .collect()
        };
        let mut judged: HashMap<sha256::Hash, (Judged, u32)> = HashMap::with_capacity(snapshot.len());
        let mut keys: Vec<Key> = Vec::new();
        for (key, id, att, locks) in snapshot {
            let Some(j) = chain.read(&|v| (assess(&att, &locks, v), v.tip_height())) else { continue };
            judged.insert(id, j);
            if keys.last() != Some(&key) {
                keys.push(key);
            }
        }
        let mut st = self.state.lock();
        let mut dropped = 0;
        for key in keys {
            // Apply the statuses first; an attestation inserted while the
            // pass ran was not judged here and is left for the next tip.
            let mut drops = vec![false; st.entries.get(&key).map_or(0, Vec::len)];
            if let Some(gens) = st.entries.get_mut(&key) {
                let mut newer_settled = false;
                for (i, h) in gens.iter_mut().enumerate() {
                    let Some((j, tip)) = judged.get(&h.attestation.id()) else { continue };
                    let anchor_depth = tip.saturating_sub(h.attestation.anchor_height());
                    let deep = *tip >= h.attestation.anchor_height() && anchor_depth >= REORG_DEPTH;
                    match j {
                        Judged::Spent => drops[i] = true,
                        Judged::Status(status) => {
                            h.status = status.clone();
                            drops[i] = newer_settled || doomed(status, h.attestation.anchor_height(), *tip);
                            // A valid attestation this deep will not be
                            // reorganised out: those it superseded are done.
                            if status.is_ok() && deep {
                                newer_settled = true;
                            }
                        }
                    }
                }
            }
            dropped += st.remove_where(&key, |i, _| drops.get(i).copied().unwrap_or(false));
        }
        dropped
    }

    /// For each `(outpoint, key)`, the attestation that counts at the tip
    /// last judged: the newest valid one. Ordered by outpoint and key.
    pub fn counting(&self) -> Vec<Held> {
        self.state
            .lock()
            .entries
            .values()
            .filter_map(|gens| gens.iter().find(|h| h.status.is_ok()).cloned())
            .collect()
    }

    /// Every attestation held, ordered by outpoint and key, newest first
    /// within each.
    pub fn all(&self) -> Vec<Held> {
        self.state.lock().entries.values().flatten().cloned().collect()
    }

    /// The most attestations the set holds (0 is no limit).
    pub fn max_attestations(&self) -> usize {
        self.max_attestations
    }

    /// How many attestations the set holds.
    pub fn len(&self) -> usize {
        self.state.lock().ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the set if it changed since the last save.
    pub fn save_if_dirty(&self) -> Result<bool, String> {
        let bytes = {
            let mut st = self.state.lock();
            if !st.dirty {
                return Ok(false);
            }
            st.dirty = false;
            let held = st.entries.values().flatten().map(|h| (&h.attestation, h.source.as_str()));
            // A pending entry collected again meanwhile is saved once.
            let pending = st.pending.iter().filter(|(a, _)| !st.ids.contains_key(&a.id()));
            encode(held.chain(pending.map(|(a, s)| (a, s.as_str()))))
        };
        if let Err(e) = store::save(&self.path, &bytes) {
            self.state.lock().dirty = true;
            return Err(e);
        }
        Ok(true)
    }
}

/// Whether an attestation with `status` at `tip` can no longer count: stale,
/// or failing on chain state with its anchor too deep for a reorg to undo.
/// One not yet valid may become valid without a reorg, and is kept.
fn doomed(status: &Status, anchor_height: u32, tip: u32) -> bool {
    let deep = tip >= anchor_height && tip - anchor_height >= REORG_DEPTH;
    match status {
        Ok(_) | Err(Rejection::NotYetValid(_)) => false,
        Err(Rejection::Stale { .. }) => true,
        Err(_) => deep,
    }
}

/// How many keys `outpoint` has in `entries`.
fn keys_for(entries: &BTreeMap<Key, Vec<Held>>, outpoint: OutPoint) -> usize {
    entries.range((outpoint, String::new())..).take_while(|((op, _), _)| *op == outpoint).count()
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn truncated(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
    s
}

/// Attestations loaded but waiting for the chain to judge them.
#[cfg(test)]
pub(super) fn pending_len(agg: &Aggregate) -> usize {
    agg.state.lock().pending.len()
}

/// What the chain makes of an attestation loaded from the file.
enum Pending {
    /// The chain cannot judge it yet.
    Wait,
    /// Its coin is gone for good.
    Spent,
    /// Its signature verified; with its status at the tip.
    Verified(Timelocks, Status),
    /// Its signature does not verify.
    Bad(Rejection),
}

/// One attestation judged at one tip.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Judged {
    /// The chain holds the anchor and the coin is gone.
    Spent,
    Status(Status),
}

/// Judge `att`, whose signature left `locks`, at `v`'s tip.
fn assess(att: &Attestation, locks: &Timelocks, v: &dyn ChainView) -> Judged {
    // As the publisher's `assess`: a missing coin is a spent one only on a
    // chain that holds the anchor.
    if v.block_hash(att.anchor_height()) == Some(att.anchor_hash()) && v.coin(&att.outpoint()).is_none() {
        return Judged::Spent;
    }
    Judged::Status(judge(att, locks, v))
}

/// Rules 1–4 and 6 at `v`'s tip, for an attestation whose signature left
/// `locks`.
pub(super) fn judge(att: &Attestation, locks: &Timelocks, v: &dyn ChainView) -> Status {
    let coin = check_chain(att, v)?;
    check_timelocks(v, &coin, locks)?;
    Ok(coin.value)
}

/// The file's bytes for `entries`.
fn encode<'a>(entries: impl Iterator<Item = (&'a Attestation, &'a str)>) -> Vec<u8> {
    let entries: Vec<_> = entries.collect();
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (att, source) in entries {
        buf.extend_from_slice(&att.to_bytes());
        source.as_bytes().to_vec().consensus_encode(&mut buf).expect("a Vec does not fail");
    }
    let checksum = sha256::Hash::hash(&buf);
    buf.extend_from_slice(checksum.as_byte_array());
    buf
}

/// Parse the file's bytes: exactly what [`encode`] writes, or an error.
fn decode(bytes: &[u8]) -> Result<Vec<(Attestation, String)>, String> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN {
        return Err("the file is truncated".into());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if sha256::Hash::hash(body).as_byte_array() != checksum {
        return Err("the checksum does not match".into());
    }
    if &body[..4] != MAGIC {
        return Err("the file is not a NAP aggregate".into());
    }
    let version = u32::from_le_bytes(body[4..8].try_into().expect("4 bytes"));
    if version != FILE_VERSION {
        return Err(format!("unsupported file version {version}"));
    }
    let count = u32::from_le_bytes(body[8..12].try_into().expect("4 bytes"));
    let mut rest = &body[HEADER_LEN..];
    let mut out = Vec::with_capacity((count as usize).min(rest.len()));
    for i in 0..count {
        let att = Attestation::decode_from(&mut rest).map_err(|e| format!("entry {i}: {e}"))?;
        let len = encode::VarInt::consensus_decode(&mut rest).map_err(|e| format!("entry {i}: {e}"))?.0;
        if len > MAX_SOURCE_LEN as u64 || rest.len() < len as usize {
            return Err(format!("entry {i}: bad source length {len}"));
        }
        let (source, tail) = rest.split_at(len as usize);
        rest = tail;
        let source = String::from_utf8(source.to_vec()).map_err(|_| format!("entry {i}: source is not UTF-8"))?;
        out.push((att, source));
    }
    if !rest.is_empty() {
        return Err(format!("{} bytes follow the last entry", rest.len()));
    }
    Ok(out)
}

/// Read the file at `path`. A missing file is an empty set.
fn load(path: &Path) -> Result<Vec<(Attestation, String)>, String> {
    match std::fs::read(path) {
        Ok(bytes) => decode(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

#[cfg(test)]
pub(super) fn encode_for_test(entries: &[(Attestation, String)]) -> Vec<u8> {
    encode(entries.iter().map(|(a, s)| (a, s.as_str())))
}
