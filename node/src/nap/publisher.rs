//! The publisher: the attestations this node stores and will serve.
//!
//! Holders submit signed attestations through the RPCs; the publisher
//! checks each against the chain, keeps at most one per `(outpoint, key)`
//! and at most [`MAX_KEYS_PER_OUTPOINT`] keys per outpoint (D3), and writes
//! them to [`store`](super::store) on every change. At each new tip
//! ([`Publisher::on_tip`]) it drops the attestations whose coin was spent
//! and re-judges the rest; it serves only those valid at its own tip.
//!
//! A signature's result depends only on the coin's scriptPubKey, so each is
//! verified once and cached; a tip costs the chain checks and the timelocks.
//!
//! Chain reads can wait out a block commit, so none is made while holding the
//! entries' lock: readers (`list`, `serving`) take it only to copy or update.
//! A separate writer lock serializes the changes `submit`, `remove` and
//! `on_tip` make. `submit` holds it across its re-check of the stored entry;
//! `on_tip` judges without it and applies each result only to the entry it
//! judged, so a long pass never holds up the RPCs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bitcoin::hashes::sha256;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, BlockHash, OutPoint};
use parking_lot::Mutex;

use super::validity::{Timelocks, check_chain, check_coin_age, check_timelocks, verify_signature};
use super::{
    ANCHOR_DEPTH, Attestation, ChainView, Coin, FormatError, LEGACY_SIGNATURE_LEN,
    MAX_KEYS_PER_OUTPOINT, NapSignature, Rejection, message, store, supersedes,
};
use crate::bip322::{self, DecodeError, Proof, Signature};

/// The longest message a Coldcard signs (D16).
pub const COLDCARD_MESSAGE_LIMIT: usize = 330;

/// Chain state for the publisher to read.
pub trait ChainSource {
    /// Run `read` against one chain state that does not change during it.
    /// `read` may run more than once. `None` when the chain would not hold
    /// still, which callers report as "try again".
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T>;
}

/// Why the publisher refused a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// The request itself is malformed: the message text, the signature
    /// string, or a key or value.
    #[error("{0}")]
    Format(String),
    /// The attestation is not valid at this node's tip.
    #[error("{0}")]
    Rejected(Rejection),
    /// A valid attestation for the same `(outpoint, key)` already counts
    /// over this one.
    #[error("the attestation published for this key (anchor {anchor_height}) supersedes this one")]
    Superseded { anchor_height: u32 },
    /// The outpoint already has the most keys a publisher stores.
    #[error("this node already publishes {MAX_KEYS_PER_OUTPOINT} keys for this outpoint")]
    KeyLimit,
    /// The store holds the operator's limit (`-napmaxattestations`).
    #[error("this node already stores {max} attestations, its -napmaxattestations limit")]
    StoreFull { max: usize },
    #[error("the chain is shorter than the anchor depth ({ANCHOR_DEPTH} blocks)")]
    ChainTooShort,
    /// The chain kept moving during the request.
    #[error("the chain tip kept changing; try again")]
    Busy,
    #[error("no attestation is published for this outpoint and key")]
    NotFound,
    /// The store could not be written; nothing changed.
    #[error("{0}")]
    Io(String),
}

impl PublishError {
    /// The rule's stable name, as RPCs report it.
    pub fn rule(&self) -> &'static str {
        match self {
            PublishError::Format(_) => "format",
            PublishError::Rejected(r) => r.rule(),
            PublishError::Superseded { .. } => "superseded",
            PublishError::KeyLimit => "key-limit",
            PublishError::StoreFull { .. } => "store-full",
            PublishError::ChainTooShort => "chain-too-short",
            PublishError::Busy => "busy",
            PublishError::NotFound => "not-found",
            PublishError::Io(_) => "io",
        }
    }
}

impl From<FormatError> for PublishError {
    fn from(e: FormatError) -> Self {
        PublishError::Format(e.to_string())
    }
}

/// What `createnapattestation` hands the holder to sign.
#[derive(Debug, Clone)]
pub struct Draft {
    pub message: String,
    pub anchor_height: u32,
    pub anchor_hash: BlockHash,
    pub coin: Coin,
    /// BIP 322's `to_sign` PSBT for the message, for PSBT signers (D15).
    pub psbt: Psbt,
    pub warnings: Vec<String>,
}

/// A stored attestation.
#[derive(Debug, Clone)]
pub struct Published {
    pub attestation: Attestation,
    /// The attestation's validity at the tip it was last judged at, with
    /// the coin's value when valid. `None` if it has not been judged yet:
    /// the chain has not held still long enough since it was loaded.
    pub status: Option<Result<Amount, Rejection>>,
}

/// A stored attestation and what has been learned about it.
struct Entry {
    att: Attestation,
    /// The signature's result, once the coin has been seen.
    locks: Option<Result<Timelocks, Rejection>>,
    /// Validity at the last tip it was judged at; `None` before the first.
    status: Option<Result<Amount, Rejection>>,
}

/// One entry judged at one tip.
enum Assessed {
    /// The chain has reached the anchor and the coin is gone.
    Spent,
    Judged { status: Result<Amount, Rejection>, locks: Option<Result<Timelocks, Rejection>> },
}

type Key = (OutPoint, String);

pub struct Publisher {
    path: PathBuf,
    entries: Mutex<BTreeMap<Key, Entry>>,
    /// Held by every change to `entries`, for as long as the change takes.
    writer: Mutex<()>,
    /// The most attestations the store takes (`-napmaxattestations`); 0 is
    /// no limit.
    max_attestations: usize,
}

impl Publisher {
    /// Load the store at `path` (a missing file is an empty store) and judge
    /// every entry at `chain`'s tip.
    pub fn open(path: PathBuf, chain: &impl ChainSource) -> Result<Self, String> {
        let mut entries: BTreeMap<Key, Entry> = BTreeMap::new();
        for att in store::load(&path)? {
            let key = (att.outpoint(), att.key().to_owned());
            if entries.get(&key).is_some_and(|e| !supersedes(&att, &e.att)) {
                continue;
            }
            entries.insert(key, Entry { att, locks: None, status: None });
        }
        let publisher =
            Publisher { path, entries: Mutex::new(entries), writer: Mutex::new(()), max_attestations: 0 };
        publisher.on_tip(chain);
        Ok(publisher)
    }

    /// Refuse submissions that would take the store past `max` attestations
    /// (`-napmaxattestations`; 0, the default, is no limit). Replacing one
    /// of the stored attestations is always allowed. A store already larger,
    /// after the limit was lowered, is kept whole.
    pub fn with_max_attestations(mut self, max: usize) -> Self {
        self.max_attestations = max;
        self
    }

    fn full(&self, len: usize) -> bool {
        self.max_attestations != 0 && len >= self.max_attestations
    }

    /// [`Self::open`], but a store that does not read back is renamed to
    /// `<name>.bad-<unix seconds>` and the publisher starts empty
    /// (`-napstorerecover`). Returns the path the file was moved to, for the
    /// caller to report. Fails only if the file cannot be moved aside.
    pub fn open_recovering(
        path: PathBuf,
        chain: &impl ChainSource,
    ) -> Result<(Self, Option<(PathBuf, String)>), String> {
        let why = match store::load(&path) {
            Ok(_) => return Self::open(path, chain).map(|p| (p, None)),
            Err(why) => why,
        };
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut aside = path.clone().into_os_string();
        aside.push(format!(".bad-{secs}"));
        let aside = PathBuf::from(aside);
        std::fs::rename(&path, &aside)
            .map_err(|e| format!("{why}; moving it to {} failed: {e}", aside.display()))?;
        Ok((Self::open(path, chain)?, Some((aside, why))))
    }

    /// The message for `outpoint`, `key` and `value`, anchored
    /// [`ANCHOR_DEPTH`] blocks below the tip, after checking that the coin
    /// exists and is old enough at that anchor.
    pub fn create(
        &self,
        chain: &impl ChainSource,
        outpoint: OutPoint,
        key: &str,
        value: &str,
    ) -> Result<Draft, PublishError> {
        message::check_key(key.as_bytes())?;
        message::check_value(value.as_bytes())?;
        let read = chain
            .read(&|v| {
                let anchor_height = v.tip_height().checked_sub(ANCHOR_DEPTH)?;
                Some((anchor_height, v.block_hash(anchor_height), v.coin(&outpoint), v.network()))
            })
            .ok_or(PublishError::Busy)?;
        let (anchor_height, anchor_hash, coin, network) = read.ok_or(PublishError::ChainTooShort)?;
        let anchor_hash = anchor_hash.ok_or(PublishError::Busy)?;
        let coin = coin.ok_or(PublishError::Rejected(Rejection::CoinNotFound))?;
        check_coin_age(network, &coin, anchor_height).map_err(PublishError::Rejected)?;

        let text = message::render(&outpoint, key, value, anchor_height, &anchor_hash);
        let mut warnings = Vec::new();
        if text.len() > COLDCARD_MESSAGE_LIMIT {
            warnings.push(format!(
                "the message is {} characters; a Coldcard signs at most {COLDCARD_MESSAGE_LIMIT}",
                text.len()
            ));
        }
        let entries = self.entries.lock();
        if !entries.contains_key(&(outpoint, key.to_owned())) {
            if keys_for(&entries, outpoint) >= MAX_KEYS_PER_OUTPOINT {
                warnings.push(format!(
                    "this node already publishes {MAX_KEYS_PER_OUTPOINT} keys for this outpoint, \
                     so it will refuse this one"
                ));
            }
            if self.full(entries.len()) {
                warnings.push(format!(
                    "this node already stores {} attestations, its -napmaxattestations limit, \
                     so it will refuse this one",
                    self.max_attestations
                ));
            }
        }
        let psbt = bip322::psbt::create(&coin.script_pubkey, text.as_bytes());
        Ok(Draft { message: text, anchor_height, anchor_hash, coin, psbt, warnings })
    }

    /// Check a signed message and store it. Returns the stored attestation
    /// and the id of the one it replaced, if any. Submitting an attestation
    /// that is already stored changes nothing.
    pub fn submit(
        &self,
        chain: &impl ChainSource,
        text: &str,
        signature: &str,
    ) -> Result<(Published, Option<sha256::Hash>), PublishError> {
        let msg = message::parse(text)?;
        let coin = chain
            .read(&|v| v.coin(&msg.outpoint))
            .ok_or(PublishError::Busy)?
            .ok_or(PublishError::Rejected(Rejection::CoinNotFound))?;
        let signature = decode_signature(signature, &coin, text)?;
        let att = Attestation::new(
            msg.outpoint,
            msg.key,
            msg.value,
            msg.anchor_height,
            msg.anchor_hash,
            signature,
        )?;
        let (status, locks) = match chain.read(&|v| assess(&att, None, v)).ok_or(PublishError::Busy)? {
            Assessed::Judged { status, locks } => (status, locks),
            Assessed::Spent => (Err(Rejection::CoinNotFound), None),
        };
        let value = status.map_err(PublishError::Rejected)?;

        let key = (att.outpoint(), att.key().to_owned());
        let _writer = self.writer.lock();
        let (current, key_count, total) = {
            let entries = self.entries.lock();
            let current = entries.get(&key).map(|e| (e.att.clone(), e.locks.clone()));
            (current, keys_for(&entries, att.outpoint()), entries.len())
        };
        let replaced = match current {
            Some((cur, _)) if cur == att => {
                // Already stored: nothing to write, but the verdict just
                // reached is the current one, and decides serving. The
                // writer lock is held, so the entry is still this one.
                if let Some(e) = self.entries.lock().get_mut(&key) {
                    e.status = Some(Ok(value));
                    e.locks = locks;
                }
                return Ok((Published { attestation: att, status: Some(Ok(value)) }, None));
            }
            Some((cur, cur_locks)) => {
                let cur_valid = matches!(
                    chain.read(&|v| assess(&cur, cur_locks.clone(), v)).ok_or(PublishError::Busy)?,
                    Assessed::Judged { status: Ok(_), .. }
                );
                if cur_valid && !supersedes(&att, &cur) {
                    return Err(PublishError::Superseded { anchor_height: cur.anchor_height() });
                }
                Some(cur.id())
            }
            None if key_count >= MAX_KEYS_PER_OUTPOINT => {
                return Err(PublishError::KeyLimit);
            }
            None if self.full(total) => {
                return Err(PublishError::StoreFull { max: self.max_attestations });
            }
            None => None,
        };
        let mut entries = self.entries.lock();
        let entry = Entry { att: att.clone(), locks, status: Some(Ok(value)) };
        let previous = entries.insert(key.clone(), entry);
        if let Err(e) = self.save(&entries) {
            match previous {
                Some(p) => entries.insert(key, p),
                None => entries.remove(&key),
            };
            return Err(PublishError::Io(e));
        }
        tracing::info!(
            target: "nap",
            outpoint = %att.outpoint(),
            key = att.key(),
            anchor = att.anchor_height(),
            "NAP: publishing attestation"
        );
        Ok((Published { attestation: att, status: Some(Ok(value)) }, replaced))
    }

    /// Every stored attestation, judged at `chain`'s tip, ordered by
    /// outpoint and key. The serving status is left to [`Self::on_tip`],
    /// which reports what changed between tips.
    pub fn list(&self, chain: &impl ChainSource) -> Vec<Published> {
        let snapshot = self.snapshot();
        let mut out = Vec::with_capacity(snapshot.len());
        let mut learned = Vec::new();
        for (key, att, locks, status) in snapshot {
            let status = match chain.read(&|v| assess(&att, locks.clone(), v)) {
                Some(Assessed::Judged { status, locks: new }) => {
                    if new != locks {
                        learned.push((key, att.id(), new));
                    }
                    Some(status)
                }
                // Spent, and dropped at the next tip.
                Some(Assessed::Spent) => Some(Err(Rejection::CoinNotFound)),
                None => status,
            };
            out.push(Published { attestation: att, status });
        }
        // Keep what was learned about signatures, for entries not replaced
        // in the meantime.
        let mut entries = self.entries.lock();
        for (key, id, locks) in learned {
            if let Some(e) = entries.get_mut(&key).filter(|e| e.att.id() == id) {
                e.locks = locks;
            }
        }
        out
    }

    /// Each entry's key, attestation, cached signature result and status.
    #[allow(clippy::type_complexity)]
    fn snapshot(
        &self,
    ) -> Vec<(Key, Attestation, Option<Result<Timelocks, Rejection>>, Option<Result<Amount, Rejection>>)> {
        self.entries
            .lock()
            .iter()
            .map(|(k, e)| (k.clone(), e.att.clone(), e.locks.clone(), e.status.clone()))
            .collect()
    }

    /// Stop publishing the attestation for `outpoint` and `key`. Copies
    /// already collected stay valid; only signing an empty value withdraws.
    pub fn remove(&self, outpoint: OutPoint, key: &str) -> Result<Attestation, PublishError> {
        let k = (outpoint, key.to_owned());
        let _writer = self.writer.lock();
        let mut entries = self.entries.lock();
        let entry = entries.remove(&k).ok_or(PublishError::NotFound)?;
        if let Err(e) = self.save(&entries) {
            entries.insert(k, entry);
            return Err(PublishError::Io(e));
        }
        Ok(entry.att)
    }

    /// The attestations valid at the tip last judged, which are the ones
    /// this node serves.
    pub fn serving(&self) -> Vec<Attestation> {
        self.entries
            .lock()
            .values()
            .filter(|e| matches!(e.status, Some(Ok(_))))
            .map(|e| e.att.clone())
            .collect()
    }

    /// The page of the attestations this node serves that answers `req`
    /// (see [`super::p2p::page`]).
    pub fn page(&self, req: &super::p2p::GetNapAtt, max_size: usize) -> super::p2p::NapAtt {
        let entries = self.entries.lock();
        // Keys sort after the empty string, so a cursor starts the range at
        // its own outpoint, which `page` skips.
        let range = match req.cursor {
            Some(cursor) => entries.range((cursor, String::new())..),
            None => entries.range(..),
        };
        let serving = range.filter(|(_, e)| matches!(e.status, Some(Ok(_)))).map(|(_, e)| &e.att);
        super::p2p::page(serving, req, max_size)
    }

    /// Judge every entry at `chain`'s new tip: drop those whose coin was
    /// spent, and warn about each that lost its anchor to a reorg.
    pub fn on_tip(&self, chain: &impl ChainSource) {
        let judged: Vec<(Key, sha256::Hash, Assessed, u32)> = self
            .snapshot()
            .into_iter()
            .filter_map(|(key, att, locks, _)| {
                chain
                    .read(&|v| (assess(&att, locks.clone(), v), v.tip_height()))
                    .map(|(a, tip)| (key, att.id(), a, tip))
            })
            .collect();
        let _writer = self.writer.lock();
        let mut entries = self.entries.lock();
        let mut spent = Vec::new();
        for (key, id, assessed, tip) in judged {
            // An entry submitted or removed while the pass ran was not judged
            // here; the next tip judges it.
            let Some(e) = entries.get_mut(&key).filter(|e| e.att.id() == id) else { continue };
            let (status, locks) = match assessed {
                Assessed::Spent => {
                    spent.push(key);
                    continue;
                }
                Assessed::Judged { status, locks } => (status, locks),
            };
            let (next, said) = transition(e.status.as_ref(), status, tip, e.att.anchor_height());
            match said {
                Some(Report::LostAnchor) => tracing::warn!(
                    target: "nap",
                    outpoint = %e.att.outpoint(),
                    key = e.att.key(),
                    anchor = e.att.anchor_height(),
                    "NAP: a reorg removed the anchor block of a published attestation; \
                     it is not served until signed again"
                ),
                Some(Report::NoLongerValid(ref r)) => tracing::info!(
                    target: "nap",
                    outpoint = %e.att.outpoint(),
                    key = e.att.key(),
                    rule = r.rule(),
                    "NAP: attestation is no longer valid and is not served: {r}"
                ),
                None => {}
            }
            e.status = next;
            e.locks = locks;
        }
        if spent.is_empty() {
            return;
        }
        for key in &spent {
            entries.remove(key);
            tracing::info!(target: "nap", outpoint = %key.0, key = key.1, "NAP: coin spent; attestation dropped");
        }
        if let Err(e) = self.save(&entries) {
            tracing::error!(target: "nap", "NAP: could not write the attestation store: {e}");
        }
    }

    fn save(&self, entries: &BTreeMap<Key, Entry>) -> Result<(), String> {
        store::save(&self.path, &store::encode(entries.values().map(|e| &e.att)))
    }
}

/// What a tip pass tells the operator about one entry.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Report {
    /// A reorg replaced the anchor block.
    LostAnchor,
    NoLongerValid(Rejection),
}

type Status = Result<Amount, Rejection>;

/// One entry's status after a tip pass judged it `now` at `tip`, and what,
/// if anything, to tell the operator.
///
/// - An entry with no status (just loaded from the store) reports what
///   happened while the node was stopped.
/// - Below the anchor's height the node is behind (IBD, a reindex, or the
///   first half of a reorg), and a missing anchor proves nothing yet: the
///   entry is not served and goes back to having no status, so the first
///   pass at or above the anchor's height decides. There, a missing anchor
///   is one a reorg replaced.
pub(super) fn transition(before: Option<&Status>, now: Status, tip: u32, anchor_height: u32) -> (Option<Status>, Option<Report>) {
    if now == Err(Rejection::AnchorNotOnChain) && tip < anchor_height {
        let unjudged = before.is_none_or(|s| s.is_ok());
        let keep = if unjudged { None } else { before.cloned() };
        return (keep, None);
    }
    let was_served = before.is_none_or(|s| s.is_ok());
    let said = match &now {
        Err(Rejection::AnchorNotOnChain) if was_served => Some(Report::LostAnchor),
        Err(r) if was_served => Some(Report::NoLongerValid(r.clone())),
        _ => None,
    };
    (Some(now), said)
}

/// How many keys `outpoint` has in `entries`.
fn keys_for(entries: &BTreeMap<Key, Entry>, outpoint: OutPoint) -> usize {
    entries.range((outpoint, String::new())..).take_while(|((op, _), _)| *op == outpoint).count()
}

/// Judge `att` at `view`'s tip, verifying its signature unless `cached`
/// already holds the result.
fn assess(att: &Attestation, cached: Option<Result<Timelocks, Rejection>>, v: &dyn ChainView) -> Assessed {
    // A missing coin means a spent one only on a chain that holds the anchor:
    // the coin confirmed below the anchor, so on that
    // chain nothing else removes it. A node behind the anchor (a reindex,
    // say), or on a fork without it, may see the coin again; the attestation
    // is kept and judged `AnchorNotOnChain` meanwhile.
    if v.block_hash(att.anchor_height()) == Some(att.anchor_hash()) && v.coin(&att.outpoint()).is_none() {
        return Assessed::Spent;
    }
    let coin = match check_chain(att, v) {
        Ok(coin) => coin,
        Err(r) => return Assessed::Judged { status: Err(r), locks: cached },
    };
    let locks = cached.unwrap_or_else(|| verify_signature(att, &coin.script_pubkey));
    let status = match &locks {
        Ok(l) => check_timelocks(v, &coin, l).map(|()| coin.value),
        Err(r) => Err(r.clone()),
    };
    Assessed::Judged { status, locks: Some(locks) }
}

/// A signature string as the RPCs take it (D14), for `coin`: `smp`, `ful`,
/// or unprefixed (legacy for P2PKH, simple otherwise); a signed BIP 322
/// PSBT of `text` (D15), which is finalized into a simple or full proof; or
/// the signed `to_sign` transaction in hex, a full proof.
fn decode_signature(signature: &str, coin: &Coin, text: &str) -> Result<NapSignature, PublishError> {
    if let Some(bytes) = crate::rpc::signmessage::decode_base64(signature)
        && bip322::psbt::is_psbt(&bytes)
    {
        let format = |e: bip322::psbt::PsbtError| PublishError::Format(e.to_string());
        let signed = bip322::psbt::parse(&bytes).map_err(format)?;
        if signed.message != text.as_bytes() {
            return Err(PublishError::Format(
                "the PSBT signs a different message from the one submitted".into(),
            ));
        }
        if signed.challenge != coin.script_pubkey {
            return Err(PublishError::Format(
                "the PSBT signs for a different scriptPubKey from the outpoint's".into(),
            ));
        }
        return Ok(match signed.finalize().map_err(format)? {
            Proof::Simple(w) => NapSignature::Simple(w),
            Proof::Full(tx) => NapSignature::Full(tx),
        });
    }
    // A wallet that finalizes the PSBT itself (Sparrow) exports the signed
    // `to_sign` as a raw transaction in hex: the full proof, unencoded.
    let hex = raw_transaction(signature);
    if let Some(Ok(tx)) = hex {
        return Ok(NapSignature::Full(tx));
    }
    match bip322::decode(signature, &coin.script_pubkey) {
        Ok(Signature::Legacy(bytes)) => {
            let bytes: [u8; LEGACY_SIGNATURE_LEN] = bytes.try_into().map_err(|b: Vec<u8>| {
                PublishError::Format(format!(
                    "a legacy signature is {LEGACY_SIGNATURE_LEN} bytes, not {}",
                    b.len()
                ))
            })?;
            Ok(NapSignature::Legacy(bytes))
        }
        Ok(Signature::Bip322(Proof::Simple(w))) => Ok(NapSignature::Simple(w)),
        Ok(Signature::Bip322(Proof::Full(tx))) => Ok(NapSignature::Full(tx)),
        Err(DecodeError::ProofOfFunds) => Err(PublishError::Format(
            "proof-of-funds (pof) signatures are not accepted; sign without extra inputs".into(),
        )),
        Err(e) => Err(PublishError::Format(match hex {
            Some(Err(h)) => format!("neither a transaction in hex ({h}) nor a signature ({e})"),
            _ => e.to_string(),
        })),
    }
}

/// `s` as a transaction in hex, if it is written in hex digits at all.
fn raw_transaction(s: &str) -> Option<Result<bitcoin::Transaction, String>> {
    (!s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| bitcoin::consensus::encode::deserialize_hex(s).map_err(|e| e.to_string()))
}

/// A signature in the string form RPCs return: prefixed for BIP 322, as
/// Core's `signmessage` emits it for legacy.
pub fn encode_signature(signature: &NapSignature) -> String {
    use base64::Engine as _;
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    match signature {
        NapSignature::Simple(w) => format!("smp{}", b64(&bitcoin::consensus::serialize(w))),
        NapSignature::Full(tx) => format!("ful{}", b64(&bitcoin::consensus::serialize(tx))),
        NapSignature::Legacy(sig) => b64(sig),
    }
}
