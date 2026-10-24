//! The aggregator's intake: attestations collected from publishers, checked
//! in the design's cheapest-first order before they reach the
//! [`Aggregate`].
//!
//! 1. Size and form: already done, since an [`Attestation`] only decodes
//!    well formed.
//! 2. Already held: an attestation the set holds costs nothing more.
//! 3. The anchor, freshness, the coin and its age ([`check_chain`]). A
//!    failure here is chain state, not misbehaviour: the publisher's tip
//!    may differ. The attestation is passed over; a later pull brings it
//!    again.
//! 4. The signature, unless the verified-id cache already holds its result.
//!    Verifications are budgeted per pull ([`PULL_VERIFICATIONS`]) and
//!    across all pulls per hour ([`HOURLY_VERIFICATIONS`]). Work over
//!    either budget is deferred, not dropped, and runs when the hourly
//!    budget allows ([`Collector::drain_deferred`]). A signature that fails
//!    is misbehaviour by the peer that served it.
//! 5. The timelocks, which decide the status it is stored with.
//!
//! The deferred queue is bounded ([`MAX_DEFERRED_BYTES`]): the collector
//! asks for a page only while [`Collector::has_room`], so nothing that was
//! received is ever dropped for lack of budget.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use bitcoin::hashes::sha256;
use lru::LruCache;
use parking_lot::Mutex;

use super::aggregate::{Aggregate, Inserted, judge};
use super::p2p::MAX_NAPATT_SIZE;
use super::publisher::ChainSource;
use super::validity::{Timelocks, check_chain, verify_signature};
use super::{Attestation, Rejection};

/// Signature verifications one pull may spend.
pub const PULL_VERIFICATIONS: u32 = 5_000;
/// Signature verifications all pulls together may spend per
/// [`BUDGET_WINDOW`].
pub const HOURLY_VERIFICATIONS: u32 = 50_000;
/// The window [`HOURLY_VERIFICATIONS`] is counted over.
pub const BUDGET_WINDOW: Duration = Duration::from_secs(60 * 60);
/// Signature results remembered by attestation id.
pub const VERIFIED_CACHE_SIZE: usize = 100_000;
/// The most serialized bytes of attestations waiting for budget.
pub const MAX_DEFERRED_BYTES: usize = 16 * MAX_NAPATT_SIZE;

/// The budgets and bounds a [`Collector`] works within. The defaults are
/// the reference values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub pull_verifications: u32,
    pub hourly_verifications: u32,
    pub max_deferred_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            pull_verifications: PULL_VERIFICATIONS,
            hourly_verifications: HOURLY_VERIFICATIONS,
            max_deferred_bytes: MAX_DEFERRED_BYTES,
        }
    }
}

/// One pull's verification budget, from [`Collector::pull_budget`].
#[derive(Debug)]
pub struct PullBudget(u32);

impl PullBudget {
    pub fn remaining(&self) -> u32 {
        self.0
    }
}

/// What one page did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Intake {
    /// New to the set.
    pub added: usize,
    /// Already held, or older than every generation kept.
    pub known: usize,
    /// Passed over on chain state (step 3).
    pub chain_state: usize,
    /// Waiting for budget.
    pub deferred: usize,
    /// Refused: a key new to an outpoint that already has
    /// [`super::aggregate::MAX_KEYS_PER_OUTPOINT`].
    pub key_limit: usize,
    /// Refused: a new `(outpoint, key)` for a set already at its most
    /// attestations.
    pub full: usize,
    /// The signature that failed, if one did. The rest of the page was not
    /// looked at: the peer that served it is misbehaving.
    pub misbehaved: Option<Rejection>,
}

/// An attestation waiting for budget, and the peer that served it.
struct Deferred {
    att: Attestation,
    source: String,
    size: usize,
}

/// Verifications spent in a window that starts with the first one.
struct Window {
    start: Instant,
    used: u32,
}

struct Budget {
    window: Option<Window>,
}

impl Budget {
    fn take(&mut self, per_window: u32, now: Instant) -> bool {
        match &mut self.window {
            Some(w) if now.saturating_duration_since(w.start) < BUDGET_WINDOW => {
                if w.used >= per_window {
                    return false;
                }
                w.used += 1;
            }
            _ if per_window == 0 => return false,
            _ => self.window = Some(Window { start: now, used: 1 }),
        }
        true
    }
}

pub struct Collector {
    aggregate: Aggregate,
    limits: Limits,
    /// Signature results by attestation id. An id commits to the outpoint,
    /// whose scriptPubKey never changes, so a result holds for good.
    verified: Mutex<LruCache<sha256::Hash, Result<Timelocks, Rejection>>>,
    budget: Mutex<Budget>,
    deferred: Mutex<(VecDeque<Deferred>, usize)>,
}

/// What a signature check came to.
enum Checked {
    Verified(Result<Timelocks, Rejection>),
    OverBudget,
}

impl Collector {
    pub fn new(aggregate: Aggregate) -> Self {
        Self::with_limits(aggregate, Limits::default())
    }

    pub fn with_limits(aggregate: Aggregate, limits: Limits) -> Self {
        Collector {
            aggregate,
            limits,
            verified: Mutex::new(LruCache::new(NonZeroUsize::new(VERIFIED_CACHE_SIZE).expect("nonzero"))),
            budget: Mutex::new(Budget { window: None }),
            deferred: Mutex::new((VecDeque::new(), 0)),
        }
    }

    pub fn aggregate(&self) -> &Aggregate {
        &self.aggregate
    }

    /// A new pull's verification budget.
    pub fn pull_budget(&self) -> PullBudget {
        PullBudget(self.limits.pull_verifications)
    }

    /// Whether the deferred queue has room for a whole page, so that one
    /// more may be asked for.
    pub fn has_room(&self) -> bool {
        self.deferred.lock().1 + MAX_NAPATT_SIZE <= self.limits.max_deferred_bytes
    }

    /// Attestations waiting for budget.
    pub fn deferred_len(&self) -> usize {
        self.deferred.lock().0.len()
    }

    /// Take one page served by `source`, spending `pull`'s budget.
    pub fn intake(
        &self,
        chain: &impl ChainSource,
        source: &str,
        page: Vec<Attestation>,
        pull: &mut PullBudget,
        now: Instant,
    ) -> Intake {
        let mut out = Intake::default();
        for att in page {
            match self.take(chain, source, att, Some(pull), now) {
                Taken::Added => out.added += 1,
                Taken::Known => out.known += 1,
                Taken::ChainState => out.chain_state += 1,
                Taken::Deferred => out.deferred += 1,
                Taken::KeyLimit => out.key_limit += 1,
                Taken::Full => out.full += 1,
                Taken::Misbehaved(r) => {
                    out.misbehaved = Some(r);
                    break;
                }
            }
        }
        out
    }

    /// Verify deferred attestations, oldest first, while the hourly budget
    /// allows. Returns the peers whose deferred attestations failed their
    /// signature, with the failure, for the caller to discourage.
    pub fn drain_deferred(&self, chain: &impl ChainSource, now: Instant) -> Vec<(String, Rejection)> {
        let mut bad = Vec::new();
        loop {
            let next = {
                let mut q = self.deferred.lock();
                let next = q.0.pop_front();
                if let Some(d) = &next {
                    q.1 -= d.size;
                }
                next
            };
            let Some(d) = next else { break };
            match self.take(chain, &d.source, d.att.clone(), None, now) {
                Taken::Misbehaved(r) => bad.push((d.source, r)),
                Taken::Deferred => {
                    // `take` queued it again at the back; put it back in
                    // front and stop until the budget refills.
                    let mut q = self.deferred.lock();
                    if let Some(again) = q.0.pop_back() {
                        q.0.push_front(again);
                    }
                    break;
                }
                _ => {}
            }
        }
        bad
    }

    fn take(
        &self,
        chain: &impl ChainSource,
        source: &str,
        att: Attestation,
        pull: Option<&mut PullBudget>,
        now: Instant,
    ) -> Taken {
        let id = att.id();
        if self.aggregate.contains(&id) {
            return Taken::Known;
        }
        let coin = match chain.read(&|v| check_chain(&att, v)) {
            Some(Ok(coin)) => coin,
            Some(Err(_)) => return Taken::ChainState,
            // The chain would not hold still: try again with the budget.
            None => return self.defer(att, source),
        };
        let locks = match self.check_signature(&att, &id, &coin.script_pubkey, pull, now) {
            Checked::OverBudget => return self.defer(att, source),
            Checked::Verified(Ok(locks)) => locks,
            Checked::Verified(Err(r)) if r.is_chain_state() => return Taken::ChainState,
            Checked::Verified(Err(r)) => return Taken::Misbehaved(r),
        };
        let Some(status) = chain.read(&|v| judge(&att, &locks, v)) else {
            return self.defer(att, source);
        };
        match self.aggregate.insert(att, locks, source.to_owned(), status) {
            Inserted::Added => Taken::Added,
            Inserted::Duplicate | Inserted::TooOld => Taken::Known,
            Inserted::KeyLimit => Taken::KeyLimit,
            Inserted::Full => Taken::Full,
        }
    }

    fn check_signature(
        &self,
        att: &Attestation,
        id: &sha256::Hash,
        script: &bitcoin::ScriptBuf,
        pull: Option<&mut PullBudget>,
        now: Instant,
    ) -> Checked {
        if let Some(cached) = self.verified.lock().get(id) {
            return Checked::Verified(cached.clone());
        }
        if pull.as_ref().is_some_and(|p| p.0 == 0) {
            return Checked::OverBudget;
        }
        if !self.budget.lock().take(self.limits.hourly_verifications, now) {
            return Checked::OverBudget;
        }
        if let Some(p) = pull {
            p.0 -= 1;
        }
        let result = verify_signature(att, script);
        self.verified.lock().put(*id, result.clone());
        Checked::Verified(result)
    }

    fn defer(&self, att: Attestation, source: &str) -> Taken {
        let size = att.to_bytes().len();
        let mut q = self.deferred.lock();
        q.1 += size;
        q.0.push_back(Deferred { att, source: source.to_owned(), size });
        Taken::Deferred
    }
}

enum Taken {
    Added,
    Known,
    ChainState,
    Deferred,
    KeyLimit,
    Full,
    Misbehaved(Rejection),
}
