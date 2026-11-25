//! Alt-slots (`-altslots`): the manager's side. The rules, trust levels and
//! limits are [`crate::net::altslots`].
//!
//! `-altslots=N` sets aside N of the full-relay outbound slots. Ordinary
//! dials leave them alone ([`PeerManager::alt_slots_reserved`]); the
//! reconnect pass fills them instead with:
//!
//! - a **trial**: one dial at a time to an address whose survey record
//!   matches a rule (the survey's store with `-peersurvey`, otherwise the
//!   results of earlier trials, kept in memory), or else an address-book
//!   entry drawn as any automatic dial is, whose stored services can meet a
//!   rule. Once its fingerprint settles the peer is judged: it takes the
//!   slot under the first rule it matches, or is disconnected, after which
//!   the next trial waits [`ALT_TRIAL_INTERVAL`].
//! - a **fallback**: an ordinary peer for a slot left empty past
//!   `-altfillwait`, so the node keeps all its outbounds. A match that
//!   arrives later takes the slot and the fallback is disconnected; a
//!   fallback that turns out to match takes the slot itself.
//!
//! Every alt-slot dial obeys the same network-group rule as every other
//! automatic dial. Alt-slot peers are `outbound-full-relay` in every other
//! respect. With `-altslots=0` none of this runs and the outbound slots are
//! filled exactly as without it.

use super::*;
use crate::net::altslots::{ALT_TRIAL_INTERVAL, AltConfig, AltRole, Candidate, Trust};
use crate::net::survey::{SurveyRecord, SurveyStore};
use rand::seq::SliceRandom as _;

/// How many trial results are kept with the survey off: enough to skip the
/// addresses already found not to match. In memory only.
const ALT_RESULTS_KEPT: usize = 4_096;

/// How long an address whose trial did not take a slot is passed over by
/// later trials. Its record alone may not say why (a crawler or spy flag is
/// a judgement of the session, not part of the record).
const ALT_REJECT_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// How many such addresses are remembered; past it the oldest go first.
const ALT_REJECTS_KEPT: usize = 4_096;

/// The alt-slots' settings and fill state.
pub(super) struct AltSlots {
    config: RwLock<Arc<AltConfig>>,
    /// Never held while another lock is taken.
    pub(super) state: parking_lot::Mutex<AltState>,
}

impl Default for AltSlots {
    fn default() -> Self {
        AltSlots {
            config: RwLock::new(Arc::new(AltConfig::default())),
            state: parking_lot::Mutex::new(AltState {
                next_trial: None,
                empty_since: None,
                dials: Vec::new(),
                results: SurveyStore::with_limit(ALT_RESULTS_KEPT),
                rejected: HashMap::new(),
            }),
        }
    }
}

pub(super) struct AltState {
    /// No trial is dialled before this: set when one ends unmatched.
    next_trial: Option<Instant>,
    /// Since when an alt-slot has been neither matched nor held by a
    /// fallback.
    pub(super) empty_since: Option<Instant>,
    /// Alt-slot dials in flight, by address, with the role their peer
    /// takes; `spawn_peer` takes the entry.
    pub(super) dials: Vec<(PeerAddr, AltRole)>,
    /// Trial results with the survey off.
    pub(super) results: SurveyStore,
    /// Addresses whose trial did not take a slot, and when.
    pub(super) rejected: HashMap<PeerAddr, Instant>,
}

impl AltState {
    fn reject(&mut self, addr: PeerAddr, now: Instant) {
        self.rejected.retain(|_, at| now.saturating_duration_since(*at) < ALT_REJECT_FOR);
        if self.rejected.len() >= ALT_REJECTS_KEPT
            && let Some(oldest) = self.rejected.iter().min_by_key(|(_, at)| **at).map(|(a, _)| a.clone())
        {
            self.rejected.remove(&oldest);
        }
        self.rejected.insert(addr, now);
    }

    fn rejected_recently(&self, addr: &PeerAddr, now: Instant) -> bool {
        self.rejected.get(addr).is_some_and(|at| now.saturating_duration_since(*at) < ALT_REJECT_FOR)
    }
}

/// Takes an alt-slot dial's entry off [`AltState::dials`] when the dial
/// ends, however it ends: a later dial to the address must not inherit the
/// role.
pub(super) struct AltDialEntry {
    pm: Arc<PeerManager>,
    target: PeerAddr,
}

impl Drop for AltDialEntry {
    fn drop(&mut self) {
        self.pm.alt_slots.state.lock().dials.retain(|(a, _)| *a != self.target);
    }
}

/// The alt-slots' fill, as `getpeersurvey` and the metrics report it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AltSlotCounts {
    /// `-altslots`.
    pub configured: usize,
    /// Filled by a peer that matched a rule.
    pub matched: usize,
    /// Held by an ordinary fallback peer.
    pub fallback: usize,
    /// Neither.
    pub empty: usize,
}

/// A trial or fallback peer whose fingerprint has settled, as judged.
struct Settled {
    id: PeerId,
    role: AltRole,
    fingerprint: crate::net::fingerprint::Fingerprint,
    user_agent: String,
    services: u64,
    flags: crate::net::flags::FlagSet,
    record: Option<(PeerAddr, SurveyRecord)>,
}

impl PeerManager {
    /// Set the alt-slot settings, at startup and on a reload. The caller
    /// has checked them ([`crate::net::altslots::check_outbound_limits`]).
    ///
    /// Peers already in alt-slots are judged again under the new rules,
    /// oldest first: one that no longer matches, or past a lowered count,
    /// becomes an ordinary outbound peer and stays connected. Fallbacks go
    /// first when the count drops. A raised count fills on the next pass.
    pub fn set_alt_slots(&self, config: AltConfig) {
        let config = Arc::new(config);
        *self.alt_slots.config.write() = Arc::clone(&config);
        let n = config.slots.min(self.automatic_outbound_target());
        let mut peers = self.peers.write();
        let mut alt: Vec<PeerId> = peers.values().filter(|h| h.info.alt.is_some()).map(|h| h.info.id).collect();
        alt.sort_unstable();
        let mut used: HashMap<String, usize> = HashMap::new();
        let mut kept = 0usize;
        for id in &alt {
            let Some(h) = peers.get_mut(id) else { continue };
            if !matches!(h.info.alt, Some(AltRole::Matched { .. })) {
                continue;
            }
            let chosen = (kept < n)
                .then(|| {
                    let c = candidate_of(&h.info);
                    config.choose(&c, |r| used.get(&r.to_string()).copied().unwrap_or(0)).map(|r| (r.to_string(), c.trust()))
                })
                .flatten();
            match chosen {
                Some((rule, trust)) => {
                    *used.entry(rule.clone()).or_default() += 1;
                    kept += 1;
                    h.info.alt = Some(AltRole::Matched { rule, trust });
                }
                None => {
                    tracing::debug!("peer={id} leaves its alt-slot on reload, kept as an ordinary outbound");
                    h.info.alt = None;
                }
            }
        }
        for id in &alt {
            let Some(h) = peers.get_mut(id) else { continue };
            if h.info.alt != Some(AltRole::Fallback) {
                continue;
            }
            if kept < n {
                kept += 1;
            } else {
                tracing::debug!("alt-slot fallback peer={id} kept as an ordinary outbound on reload");
                h.info.alt = None;
            }
        }
        // The `-altfillwait` clock is left running: a reload that leaves a
        // slot empty does not restart its wait, and the next pass clears it
        // once every slot is held.
    }

    /// The alt-slot settings in effect.
    pub fn alt_slot_config(&self) -> Arc<AltConfig> {
        Arc::clone(&self.alt_slots.config.read())
    }

    /// The alt-slots the full-relay target holds: `-altslots`, at most the
    /// target.
    fn alt_slots_effective(&self) -> usize {
        let slots = self.alt_slots.config.read().slots;
        if slots == 0 { 0 } else { slots.min(self.automatic_outbound_target()) }
    }

    /// Outbound full-relay peers, connected or in the handshake, by role:
    /// (matched, fallback, trial).
    fn alt_peer_counts(&self) -> (usize, usize, usize) {
        let (mut m, mut f, mut t) = (0, 0, 0);
        for h in self.peers.read().values() {
            if h.info.conn_type != ConnType::OutboundFullRelay || h.info.state == PeerState::Disconnected {
                continue;
            }
            match h.info.alt {
                Some(AltRole::Matched { .. }) => m += 1,
                Some(AltRole::Fallback) => f += 1,
                Some(AltRole::Trial) => t += 1,
                None => {}
            }
        }
        (m, f, t)
    }

    /// The alt-slots no peer or dial holds yet: they count against the
    /// automatic target, so ordinary dials leave them to the alt-slot
    /// dials. Zero with `-altslots=0`, without reading the peers.
    pub(super) fn alt_slots_reserved(&self, in_flight: &DialsInFlight) -> usize {
        let n = self.alt_slots_effective();
        if n == 0 {
            return 0;
        }
        let (m, f, t) = self.alt_peer_counts();
        n.saturating_sub(m + f + t + in_flight.alt_trial + in_flight.alt_fallback)
    }

    /// Whether a trial may be dialled now: one at a time, dialled or being
    /// judged, and only while an alt-slot is not filled by a match. A
    /// fallback does not count as filling one.
    pub(super) fn check_alt_trial(&self, in_flight: &DialsInFlight) -> Result<(), String> {
        let n = self.alt_slots_effective();
        if n == 0 {
            return Err("no alt-slots".to_string());
        }
        if in_flight.alt_trial > 0 {
            return Err("an alt-slot trial is already being dialled".to_string());
        }
        // A trial may run one over the full-relay target while a fallback
        // holds its slot, but never past `-maxconnections`.
        if self.automatic_sockets_open(in_flight) >= self.max_connections.load(Ordering::Relaxed) {
            return Err("no connection left under -maxconnections".to_string());
        }
        let (m, _, t) = self.alt_peer_counts();
        if t > 0 {
            return Err("an alt-slot trial is being judged".to_string());
        }
        if m >= n {
            return Err("every alt-slot is filled".to_string());
        }
        Ok(())
    }

    /// The role an alt-slot dial to `addr` (or onion `onion_host`) gave its
    /// peer, taken off the list: for `spawn_peer`.
    pub(super) fn take_alt_dial(&self, addr: &SocketAddr, onion_host: Option<&str>) -> Option<AltRole> {
        let mut state = self.alt_slots.state.lock();
        if state.dials.is_empty() {
            return None;
        }
        let i = state.dials.iter().position(|(a, _)| match (a, onion_host) {
            (PeerAddr::Socket(sa), None) => sa == addr,
            (PeerAddr::Onion { host, .. }, Some(h)) => host == h,
            _ => false,
        })?;
        Some(state.dials.swap_remove(i).1)
    }

    /// A trial peer left without taking a slot, judged or not: the next
    /// trial waits [`ALT_TRIAL_INTERVAL`], and its address is passed over.
    /// Called with the peer table locked; takes only the alt-slot state.
    pub(super) fn note_alt_trial_ended(&self, info: &PeerInfo, now: Instant) {
        let mut state = self.alt_slots.state.lock();
        state.next_trial = Some(now + ALT_TRIAL_INTERVAL);
        if let Some(addr) = Self::dialled_book_addr(info) {
            state.reject(addr, now);
        }
    }

    /// The alt-slot half of a reconnect pass: a trial if one is due, then a
    /// fallback if a slot has been empty for `-altfillwait`. Returns the
    /// addresses dialled. Nothing with `-altslots=0` or under `-connect`.
    pub(super) fn open_alt_slot_peers(self: &Arc<Self>, now: Instant, dialled: &[PeerAddr]) -> Vec<PeerAddr> {
        let config = self.alt_slot_config();
        if config.slots == 0 || !self.automatic_outbound.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let n = self.alt_slots_effective();
        let (matched, fallback, _) = self.alt_peer_counts();
        let (trial_due, fallback_due) = {
            let mut state = self.alt_slots.state.lock();
            if matched + fallback < n {
                state.empty_since.get_or_insert(now);
            } else {
                state.empty_since = None;
            }
            (
                state.next_trial.is_none_or(|t| now >= t),
                state.empty_since.is_some_and(|t| now.saturating_duration_since(t) >= config.fill_wait),
            )
        };
        let mut out = Vec::new();
        if trial_due && let Ok(slot) = self.reserve_dial(DialBudget::AltTrial) {
            match self.pick_alt_trial(now, dialled, &config) {
                Some(target) => {
                    tracing::debug!(%target, "Making alt-slot trial connection");
                    self.spawn_alt_dial(target.clone(), AltRole::Trial, slot);
                    out.push(target);
                }
                // No candidate: look again after the trial interval, not
                // every pass.
                None => self.alt_slots.state.lock().next_trial = Some(now + ALT_TRIAL_INTERVAL),
            }
        }
        if fallback_due && let Ok(slot) = self.reserve_dial(DialBudget::AltFallback) {
            let mut taken = dialled.to_vec();
            taken.extend(out.iter().cloned());
            if let Some(target) = self.pick_automatic_dial(now, &taken, &mut rand::thread_rng(), |_| true) {
                tracing::debug!(%target, "Making alt-slot fallback connection");
                self.spawn_alt_dial(target.clone(), AltRole::Fallback, slot);
                out.push(target);
            }
        }
        out
    }

    /// Dial `target` for an alt-slot, holding `slot`; its peer takes `role`.
    fn spawn_alt_dial(self: &Arc<Self>, target: PeerAddr, role: AltRole, slot: DialSlot) {
        let entry = self.alt_dial_entry(target.clone(), role.clone());
        let pm = Arc::clone(self);
        tokio::spawn(async move {
            let _slot = slot;
            let _entry = entry;
            let connected = pm.dial_book_target(&target, None, AUTOMATIC_RECONNECT_MAX_BACKOFF).await;
            if !connected && role == AltRole::Trial {
                let now = Instant::now();
                let mut state = pm.alt_slots.state.lock();
                state.next_trial = Some(now + ALT_TRIAL_INTERVAL);
                state.reject(target.clone(), now);
            }
        });
    }

    /// List an alt-slot dial to `target`, whose peer takes `role`, until the
    /// returned entry drops.
    pub(super) fn alt_dial_entry(self: &Arc<Self>, target: PeerAddr, role: AltRole) -> AltDialEntry {
        self.alt_slots.state.lock().dials.push((target.clone(), role));
        AltDialEntry { pm: Arc::clone(self), target }
    }

    /// How many matched peers each rule (by its text) holds.
    fn alt_rule_usage(&self) -> HashMap<String, usize> {
        let mut used = HashMap::new();
        for h in self.peers.read().values() {
            if h.info.state != PeerState::Disconnected
                && let Some(AltRole::Matched { rule, .. }) = &h.info.alt
            {
                *used.entry(rule.clone()).or_default() += 1;
            }
        }
        used
    }

    /// Run `f` on the store trial results go to: the survey's with
    /// `-peersurvey`, the in-memory one otherwise.
    fn read_alt_results<R>(&self, f: impl FnOnce(&SurveyStore) -> R) -> R {
        let mut f = Some(f);
        if let Some(r) = self.read_survey_store(|s| (f.take().expect("once"))(s)) {
            return r;
        }
        (f.take().expect("once"))(&self.alt_slots.state.lock().results)
    }

    /// The address a trial is dialled at, or `None`. First an address in the
    /// book whose record matches a rule with a slot left, verified agents before
    /// unverified ones under `-altuatrust=consistent`, at random within
    /// each; then an address-book entry, drawn as any automatic dial is,
    /// whose stored services can meet such a rule and whose record (if any)
    /// does not rule it out. Every candidate passes the checks an automatic
    /// dial makes, the network-group rule among them.
    pub(super) fn pick_alt_trial(&self, now: Instant, dialled: &[PeerAddr], config: &AltConfig) -> Option<PeerAddr> {
        let used = self.alt_rule_usage();
        let open = config.open_rules(|r| used.get(&r.to_string()).copied().unwrap_or(0));
        if open.is_empty() {
            return None;
        }
        let matches_open = |c: &Candidate| open.iter().any(|r| r.matches(c, config.ua_trust));
        let (mut known, ruled_out): (Vec<(Trust, PeerAddr)>, HashSet<PeerAddr>) = self.read_alt_results(|store| {
            let mut known = Vec::new();
            let mut out = HashSet::new();
            for (addr, r) in store.rows() {
                let c = Candidate {
                    fingerprint: r.fingerprint,
                    user_agent: &r.user_agent,
                    services: r.services,
                    flags: Default::default(),
                };
                if matches_open(&c) {
                    known.push((c.trust(), addr.clone()));
                } else {
                    out.insert(addr.clone());
                }
            }
            (known, out)
        });
        let mut rng = rand::thread_rng();
        // The book iterates in no fixed order; sorted, the shuffle alone
        // decides, and the stable sort keeps it within each trust level.
        known.sort_unstable_by(|a, b| a.1.cmp(&b.1));
        known.shuffle(&mut rng);
        known.sort_by_key(|(trust, _)| *trust);
        let rejected: HashSet<PeerAddr> = {
            let state = self.alt_slots.state.lock();
            state.rejected.keys().filter(|a| state.rejected_recently(a, now)).cloned().collect()
        };
        let (tip_depth, restore_pending) = self.desirable_services_inputs();
        let mut groups = self.outbound_netgroups();
        groups.extend(dialled.iter().filter_map(|a| match a {
            PeerAddr::Socket(sa) => self.outbound_netgroup(sa.ip()),
            PeerAddr::Onion { .. } => None,
        }));
        let services_of = |addr: &PeerAddr| {
            self.read_alt_results(|store| store.get(addr).map(|r| r.services)).unwrap_or(0)
        };
        for (_, addr) in known {
            // Only an address still in the book: the book is where a failed
            // dial's backoff and attempts are kept, and an address it dropped
            // would otherwise be dialled again every trial.
            if dialled.contains(&addr) || rejected.contains(&addr) || !self.addrman.read().contains(&addr) {
                continue;
            }
            let c = DialCandidate { services: services_of(&addr), addr };
            if !self.automatic_dial_may_take(&c, 0, now, tip_depth, restore_pending) {
                continue;
            }
            if let PeerAddr::Socket(sa) = &c.addr
                && self.outbound_netgroup(sa.ip()).is_some_and(|g| groups.contains(&g))
            {
                continue;
            }
            return Some(c.addr);
        }
        self.pick_automatic_dial(now, dialled, &mut rng, |c| {
            !ruled_out.contains(&c.addr)
                && !rejected.contains(&c.addr)
                && open.iter().any(|r| r.services_may_match(c.services))
        })
    }

    /// Judge the trial and fallback peers whose fingerprints have settled,
    /// on what [`Self::evaluate_peer_flags`] just found: run with it.
    ///
    /// Each takes a slot under the first rule with room that it matches,
    /// while a slot is not filled by a match: one net line names the rule.
    /// A trial that matches none is disconnected; a fallback that matches
    /// none stays a fallback. A match past the slots a fallback holds
    /// disconnects the youngest fallback. Each judged trial's result goes
    /// to the store trials are drawn from.
    pub(crate) fn judge_alt_slot_peers(&self) {
        let pending: Vec<Settled> = {
            let peers = self.peers.read();
            let mut pending = Vec::new();
            for h in peers.values() {
                let info = &h.info;
                if info.state != PeerState::Connected || !info.flags.settled {
                    continue;
                }
                let role = match &info.alt {
                    Some(role @ (AltRole::Trial | AltRole::Fallback)) => role.clone(),
                    _ => continue,
                };
                let c = candidate_of(info);
                let record = (role == AltRole::Trial).then(|| self.alt_result_of(info)).flatten();
                pending.push(Settled {
                    id: info.id,
                    role,
                    fingerprint: c.fingerprint,
                    user_agent: c.user_agent.to_string(),
                    services: c.services,
                    flags: c.flags,
                    record,
                });
            }
            pending
        };
        if pending.is_empty() {
            return;
        }
        let config = self.alt_slot_config();
        let n = self.alt_slots_effective();
        let mut used = self.alt_rule_usage();
        let (mut matched, _, _) = self.alt_peer_counts();
        let mut fills = Vec::new();
        let mut unmatched = Vec::new();
        let mut no_room = Vec::new();
        let mut rejects = Vec::new();
        let mut results = Vec::new();
        let mut pending = pending;
        // Trials first, so a fallback that newly matches cannot take the
        // last slot from a trial judged in the same pass; the fallback is
        // the one dropped as surplus then.
        pending.sort_unstable_by_key(|p| (p.role != AltRole::Trial, p.id));
        for p in pending {
            let c = Candidate { fingerprint: p.fingerprint, user_agent: &p.user_agent, services: p.services, flags: p.flags };
            let room = matched < n;
            let chosen = if room {
                config.choose(&c, |r| used.get(&r.to_string()).copied().unwrap_or(0)).map(|r| r.to_string())
            } else {
                None
            };
            match chosen {
                Some(rule) => {
                    matched += 1;
                    *used.entry(rule.clone()).or_default() += 1;
                    fills.push((p.id, rule, c.trust(), p.fingerprint, p.role.clone()));
                }
                // Every slot is matched already: the trial goes, but its
                // address is not held against it.
                None if p.role == AltRole::Trial && !room => no_room.push(p.id),
                None if p.role == AltRole::Trial => {
                    unmatched.push(p.id);
                    if let Some((addr, _)) = &p.record {
                        rejects.push(addr.clone());
                    }
                }
                None => {}
            }
            if let Some(r) = p.record {
                results.push(r);
            }
        }
        {
            let mut peers = self.peers.write();
            for (id, rule, trust, fingerprint, was) in &fills {
                let Some(h) = peers.get_mut(id) else { continue };
                if h.info.alt.as_ref() != Some(was) {
                    continue;
                }
                tracing::debug!(
                    "alt-slot filled by peer={id} rule={rule} trust={} fingerprint={fingerprint}{}",
                    trust.name(),
                    if *was == AltRole::Fallback { " (was its fallback)" } else { "" }
                );
                h.info.alt = Some(AltRole::Matched { rule: rule.clone(), trust: *trust });
            }
            // No longer a trial, so leaving does not pass its address over.
            for id in &no_room {
                if let Some(h) = peers.get_mut(id) {
                    h.info.alt = None;
                }
            }
        }
        for id in no_room {
            self.disconnect_peer(id, "alt-slot-filled");
        }
        if !rejects.is_empty() {
            let now = Instant::now();
            let mut state = self.alt_slots.state.lock();
            for addr in rejects {
                state.reject(addr, now);
            }
        }
        for id in unmatched {
            self.disconnect_peer(id, "alt-slot-no-match");
        }
        // A match takes the slot a fallback held.
        let (matched, fallback, _) = self.alt_peer_counts();
        let excess = (matched + fallback).saturating_sub(n);
        if excess > 0 {
            let mut fallbacks: Vec<PeerId> = self
                .peers
                .read()
                .values()
                .filter(|h| h.info.alt == Some(AltRole::Fallback) && h.info.state != PeerState::Disconnected)
                .map(|h| h.info.id)
                .collect();
            fallbacks.sort_unstable_by(|a, b| b.cmp(a));
            for id in fallbacks.into_iter().take(excess) {
                self.disconnect_peer(id, "alt-slot-fallback-replaced");
            }
        }
        if !results.is_empty() {
            let now = crate::time::now_secs();
            for (addr, mut record) in results {
                // A trial runs no probes: keep those a survey connection
                // recorded for the address.
                if let Some(probes) = self.read_survey_store(|s| s.get(&addr).map(|r| r.probes)).flatten() {
                    record.probes = probes;
                }
                if !self.insert_survey_record(addr.clone(), record.clone(), now) {
                    self.alt_slots.state.lock().results.insert(addr, record, now);
                }
            }
        }
    }

    /// A trial's result, in the form a survey record takes; `None` for a
    /// peer the node reached by name rather than at a book address.
    fn alt_result_of(&self, info: &PeerInfo) -> Option<(PeerAddr, SurveyRecord)> {
        let addr = Self::dialled_book_addr(info)?;
        let version = info.behavior.version.as_ref()?;
        let now = crate::time::now_secs();
        let asn = match &addr {
            PeerAddr::Socket(sa) if crate::net::is_routable(sa.ip()) => {
                self.asmap.get().map(|m| m.lookup(sa.ip())).filter(|a| *a != 0)
            }
            _ => None,
        };
        Some((
            addr,
            SurveyRecord {
                fingerprint: info.flags.fingerprint,
                user_agent: version.user_agent.clone(),
                protocol_version: version.protocol_version,
                services: version.services,
                v2: info.transport.is_v2(),
                asn,
                first_seen: now,
                last_seen: now,
                probes: Default::default(),
                shape: info
                    .flags
                    .fingerprint
                    .observed()
                    .is_none()
                    .then(|| crate::net::survey::SurveyShape::of(&info.behavior.handshake, version.relay)),
                // A trial is a connected peer, judged as one: never fake or
                // closed early.
                verdict: Default::default(),
                retry: Default::default(),
            },
        ))
    }

    /// When the next trial may be dialled, for tests.
    #[cfg(test)]
    pub(super) fn alt_slots_next_trial(&self) -> Option<Instant> {
        self.alt_slots.state.lock().next_trial
    }

    /// The alt-slots' fill: configured, matched, fallback, empty.
    pub fn alt_slot_counts(&self) -> AltSlotCounts {
        let configured = self.alt_slot_config().slots;
        if configured == 0 {
            return AltSlotCounts::default();
        }
        let (matched, fallback, _) = self.alt_peer_counts();
        let empty = self.alt_slots_effective().saturating_sub(matched + fallback);
        AltSlotCounts { configured, matched, fallback, empty }
    }

    /// `getpeersurvey`'s `alt_slots`.
    pub(super) fn alt_slots_json(&self) -> serde_json::Value {
        let c = self.alt_slot_counts();
        serde_json::json!({
            "configured": c.configured,
            "matched": c.matched,
            "fallback": c.fallback,
            "empty": c.empty,
        })
    }
}

/// A connected peer as a rule judges it: its last fingerprint and flags,
/// the user agent and services from its `version`.
fn candidate_of(info: &PeerInfo) -> Candidate<'_> {
    let version = info.behavior.version.as_ref();
    Candidate {
        fingerprint: info.flags.fingerprint,
        user_agent: version.map_or("", |v| v.user_agent.as_str()),
        services: version.map_or(0, |v| v.services),
        flags: info.flags.set(),
    }
}
