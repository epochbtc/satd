//! The network survey's connections (`-peersurvey`): the scheduler that
//! opens one every `-peersurveyinterval`, the session each runs, and what
//! `getpeersurvey` and the metrics read. The records and their file are
//! [`crate::net::survey`].
//!
//! A survey connection is [`ConnType::Survey`]. It is outside every
//! connection budget: no outbound slot or grant, no place in the automatic
//! target, and it is left out of `getpeerinfo` and `getconnectioncount`. At
//! most one is open or being dialled at a time.
//!
//! It is dialled as any automatic connection is, so it obeys `-onlynet`,
//! `-proxy`, `-onion` and `-v2transport` (v2 first, v1 after a failed v2
//! handshake). It sends the `version`, `wtxidrelay`, `sendaddrv2`,
//! `verack` and `sendheaders` a full-relay outbound sends, then the
//! `sendcmpct` and `feefilter` one sends next. It sends no `getaddr`, no
//! `getheaders` and none of our addresses, and answers a `ping` with a
//! `pong`. It listens for up to [`PASSIVE_WAIT`], until the peer's
//! handshake transcript closes, then sends the probes
//! (`-peersurveyprobes`) and closes.
//!
//! The address book learns what a feeler would teach it (Core's `Good` on a
//! completed handshake, an attempt on a failed dial, the services the peer
//! states), and nothing else.

use super::*;
use crate::net::survey::{
    self, PASSIVE_WAIT, PROBE_REPLY_WAIT, Probe, ProbeContext, ProbeOutcome, ProbeResults, SurveyRecord,
    SurveyStore, UNKNOWN_PROBE_WAIT,
};
use rand::seq::SliceRandom as _;

/// `-peersurvey`'s settings.
#[derive(Debug, Clone)]
pub struct SurveyConfig {
    /// `-peersurveyinterval`.
    pub interval: Duration,
    /// `-peersurveyprobes`.
    pub probes: bool,
    /// Where the store is kept (`peersurvey.dat`); `None` keeps it in
    /// memory only.
    pub path: Option<std::path::PathBuf>,
}

/// The survey while it runs.
pub(super) struct SurveyRun {
    config: SurveyConfig,
    store: parking_lot::Mutex<SurveyStore>,
    /// A survey dial is under way. With a [`ConnType::Survey`] peer in the
    /// table, this makes the one connection at a time.
    dialing: AtomicBool,
    /// Survey connections that ran their session, and those that did not
    /// (a failed dial or handshake), this run.
    completed: AtomicU64,
    failed: AtomicU64,
    /// Probe outcomes this run, by [`Probe::ALL`] then answered, silent,
    /// disconnected.
    probe_outcomes: [[AtomicU64; 3]; 4],
    /// The probes every connection sends, in order, in place of a random
    /// draw: for tests.
    #[cfg(test)]
    pub(super) forced_probes: parking_lot::Mutex<Option<Vec<Probe>>>,
}

/// What the metrics read: counts only, no address.
#[derive(Debug, Clone, Default)]
pub struct SurveyMetrics {
    pub records: usize,
    pub completed: u64,
    pub failed: u64,
    /// Records by observed family, [`crate::net::fingerprint::Family::ALL`]'s
    /// order.
    pub families: [usize; crate::net::fingerprint::Family::ALL.len()],
    pub unknown: usize,
    pub mismatches: usize,
    pub v2: usize,
    /// By [`Probe::ALL`] then answered, silent, disconnected.
    pub probe_outcomes: [[u64; 3]; 4],
}

/// Clears [`SurveyRun::dialing`] when the dial ends, however it ends.
struct DialingGuard(Arc<PeerManager>);

impl Drop for DialingGuard {
    fn drop(&mut self) {
        if let Some(run) = self.0.survey.get() {
            run.dialing.store(false, Ordering::Relaxed);
        }
    }
}

fn outcome_slot(o: ProbeOutcome) -> usize {
    match o {
        ProbeOutcome::Answered(_) => 0,
        ProbeOutcome::Silent => 1,
        ProbeOutcome::Disconnected => 2,
    }
}

impl PeerManager {
    /// Turn the survey on: read the store from `config.path`. Call once, at
    /// startup, before [`Self::spawn_survey`]. A store that does not read is
    /// set aside with a warning and the survey starts empty.
    pub fn enable_survey(&self, config: SurveyConfig) {
        let now = crate::time::now_secs();
        let store = match &config.path {
            Some(path) => match SurveyStore::load(path, self.chain_state.p2p_magic().to_bytes(), now) {
                Ok(store) => {
                    tracing::info!(records = store.len(), "Loaded the network survey");
                    store
                }
                Err(e) => {
                    // Set aside rather than overwritten at the next save.
                    let aside = path.with_extension(format!("dat.bad-{now}"));
                    let _ = std::fs::rename(path, &aside);
                    tracing::warn!(
                        file = %path.display(),
                        moved_to = %aside.display(),
                        "Could not read the network survey, starting empty: {e}"
                    );
                    SurveyStore::default()
                }
            },
            None => SurveyStore::default(),
        };
        let run = SurveyRun {
            config,
            store: parking_lot::Mutex::new(store),
            dialing: AtomicBool::new(false),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            probe_outcomes: Default::default(),
            #[cfg(test)]
            forced_probes: Default::default(),
        };
        if self.survey.set(run).is_err() {
            tracing::warn!("the network survey was enabled twice; the second call is ignored");
        }
    }

    /// Whether the survey is on.
    pub fn survey_enabled(&self) -> bool {
        self.survey.get().is_some()
    }

    /// `-asmap`'s map, for the survey records' autonomous systems.
    pub fn set_asmap(&self, map: Arc<crate::net::asmap::AsMap>) {
        let _ = self.asmap.set(map);
    }

    /// Start the survey's loop: a survey connection every
    /// `-peersurveyinterval` while none is open, and the store written every
    /// [`survey::SAVE_INTERVAL`]. Ends at shutdown. Nothing without
    /// [`Self::enable_survey`].
    pub fn spawn_survey(self: &Arc<Self>) {
        let Some(run) = self.survey.get() else {
            return;
        };
        let interval = run.config.interval.max(Duration::from_secs(1));
        let pm = Arc::clone(self);
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick is immediate; the first survey waits a whole
            // interval, as the node is still finding its peers.
            tick.tick().await;
            let mut saved = Instant::now();
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = shutdown.changed() => {}
                }
                if *shutdown.borrow() {
                    return;
                }
                pm.survey_tick();
                if saved.elapsed() >= survey::SAVE_INTERVAL {
                    saved = Instant::now();
                    let pm = Arc::clone(&pm);
                    let _ = tokio::task::spawn_blocking(move || pm.dump_survey()).await;
                }
            }
        });
    }

    /// Write the survey's store to its file. A no-op with the survey off.
    pub fn dump_survey(&self) {
        let Some(run) = self.survey.get() else {
            return;
        };
        let Some(path) = &run.config.path else {
            return;
        };
        let magic = self.chain_state.p2p_magic().to_bytes();
        // Encoded under the lock, written outside it.
        let store = run.store.lock().clone();
        if let Err(e) = store.save(path, magic) {
            tracing::warn!(file = %path.display(), "Could not write the network survey: {e}");
        }
    }

    /// Whether a survey connection is open or being dialled.
    pub(super) fn survey_open(&self) -> bool {
        let dialing = self.survey.get().is_some_and(|run| run.dialing.load(Ordering::Relaxed));
        dialing || self.peers.read().values().any(|h| h.info.conn_type == ConnType::Survey)
    }

    /// One turn of the survey's loop: dial a survey connection unless one
    /// is open, networking is off, or the node makes no automatic
    /// connections (`-connect`). Returns the address dialled.
    pub(super) fn survey_tick(self: &Arc<Self>) -> Option<PeerAddr> {
        let run = self.survey.get()?;
        if !self.is_network_active() || !self.automatic_outbound.load(Ordering::Relaxed) || self.survey_open() {
            return None;
        }
        let target = self.draw_survey_target()?;
        run.dialing.store(true, Ordering::Relaxed);
        let guard = DialingGuard(Arc::clone(self));
        let pm = Arc::clone(self);
        let dialled = target.clone();
        tokio::spawn(async move {
            let _guard = guard;
            tracing::debug!(target = %dialled, "Making survey connection");
            if !pm.dial_book_target(&dialled, Some(ConnType::Survey), AUTOMATIC_RECONNECT_MAX_BACKOFF).await
                && let Some(run) = pm.survey.get()
            {
                run.failed.fetch_add(1, Ordering::Relaxed);
            }
        });
        Some(target)
    }

    /// The address a survey connection is dialled at: drawn uniformly from
    /// the whole address book, new and tried tables alike, with no weight
    /// for anything about the entry. Passed over, as an automatic dial
    /// passes them over: an address the operator named, one on a network
    /// the node does not reach (`-onlynet`, an onion without a proxy that
    /// reaches Tor or under `-onion=0`), a banned one, one connected,
    /// being dialled or backing off after failed dials, and a bad port.
    pub(super) fn draw_survey_target(&self) -> Option<PeerAddr> {
        let mut addrs: Vec<PeerAddr> = self.addrman.read().iter().map(|e| e.addr.clone()).collect();
        // The book iterates in no fixed order; sorted first, the shuffle
        // alone decides.
        addrs.sort_unstable();
        addrs.shuffle(&mut rand::thread_rng());
        let now = Instant::now();
        addrs.into_iter().find(|target| {
            !self.is_manual_target(target)
                && self.may_dial(target)
                && !self.is_peer_addr_banned(target)
                && !self.is_dial_in_flight(target)
                && self.redial_due(target, now)
                && !crate::net::is_bad_port(target.port())
        })
    }

    /// A survey connection from its transport on: the handshake, then
    /// [`Self::run_survey_session`]. Ends `Ok` either way, so a failed
    /// survey is a debug line rather than a warning; the caller then
    /// reports the peer gone.
    pub(super) async fn run_survey_connection(
        self: &Arc<Self>,
        id: PeerId,
        mut conn: Connection,
        connected_at: u64,
    ) -> Result<(), String> {
        let version = match self.perform_handshake(id, &mut conn, Direction::Outbound, connected_at).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("survey handshake failed: {e}, peer={id}");
                if let Some(run) = self.survey.get() {
                    run.failed.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(());
            }
        };
        self.run_survey_session(id, conn, version).await;
        Ok(())
    }

    /// The survey session past the handshake: the passive wait, the
    /// probes, the record, and the close.
    async fn run_survey_session(self: &Arc<Self>, id: PeerId, conn: Connection, version: VersionMessage) {
        let v2 = conn.transport_protocol().is_v2();
        let book_addr = self.peers.read().get(&id).and_then(|h| Self::dialled_book_addr(&h.info));
        // What a feeler teaches the address book: the peer answered. Core
        // marks every outbound peer good on its `version` (`Good`, v32.1
        // `src/net_processing.cpp`), a feeler's included.
        if let Some(addr) = &book_addr {
            self.addrman.write().mark_good(addr.clone(), now_unix_secs());
        }

        let (mut reader, mut writer) = conn.split();
        if let Some(stats) = self.peers.read().get(&id).map(|h| h.stats.clone()) {
            reader.set_counters(stats.clone());
            writer.set_counters(stats);
        }
        // The read side in a task of its own, as `peer_task` reads: a
        // `recv` cancelled mid-message would lose the bytes it had taken.
        let (read_tx, mut read_rx) = mpsc::channel::<NetworkMessage>(64);
        let read_task = tokio::spawn(async move {
            while let Ok(msg) = reader.recv().await {
                if read_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let closed = self.survey_listen(id, &mut writer, &mut read_rx).await;
        let mut probes = ProbeResults::default();
        let closed = closed
            || (self.survey.get().is_some_and(|run| run.config.probes)
                && self.survey_probe(id, &mut writer, &mut read_rx, &mut probes).await);
        read_task.abort();
        drop(writer);

        let Some(mut handle) = self.peers.write().remove(&id) else {
            // Gone already: shutdown, or `setnetworkactive false`.
            return;
        };
        let info = &mut handle.info;
        let fingerprint = crate::net::fingerprint::classify(false, &info.behavior.handshake, info.behavior.version.as_ref(), true);
        let reason = if closed { "survey-peer-closed" } else { "survey-done" };
        tracing::debug!(
            "survey connection done ({reason}), fingerprint={fingerprint} v2={v2} probes={}, disconnecting peer={id}",
            Probe::ALL
                .iter()
                .filter_map(|p| probes.get(*p).map(|o| format!("{}:{}", p.name(), o.name())))
                .collect::<Vec<_>>()
                .join(",")
        );
        self.retire_behavior(id, info, reason);
        let Some(run) = self.survey.get() else {
            return;
        };
        run.completed.fetch_add(1, Ordering::Relaxed);
        let Some(addr) = book_addr else {
            return;
        };
        let now = crate::time::now_secs();
        let asn = match &addr {
            PeerAddr::Socket(sa) if crate::net::is_routable(sa.ip()) => {
                self.asmap.get().map(|m| m.lookup(sa.ip())).filter(|a| *a != 0)
            }
            _ => None,
        };
        let record = SurveyRecord {
            fingerprint,
            user_agent: crate::net::limits::sanitize_string(&version.user_agent),
            protocol_version: version.version,
            services: version.services.to_u64(),
            v2,
            asn,
            first_seen: now,
            last_seen: now,
            probes,
        };
        run.store.lock().insert(addr, record, now);
    }

    /// The passive wait: send what a full-relay outbound sends after its
    /// `verack` (less `getaddr`, `getheaders` and our addresses), then take
    /// the peer's messages into its handshake transcript until it closes or
    /// [`PASSIVE_WAIT`] passes, answering a `ping`. Returns whether the
    /// peer closed the connection.
    async fn survey_listen(
        &self,
        id: PeerId,
        writer: &mut crate::net::connection::ConnectionWriter,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
    ) -> bool {
        // `peer_task`'s, in its order: compact blocks in low-bandwidth mode,
        // then the fee filter.
        let cmpct = NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
            send_compact: false,
            version: 2,
        });
        if writer.send(cmpct).await.is_err() {
            return true;
        }
        if let Some(rate) = self.fee_filter_for(id)
            && writer.send(NetworkMessage::FeeFilter(rate as i64)).await.is_err()
        {
            return true;
        }
        let deadline = tokio::time::Instant::now() + PASSIVE_WAIT;
        loop {
            let msg = match tokio::time::timeout_at(deadline, read_rx.recv()).await {
                Err(_) => return false,
                Ok(None) => return true,
                Ok(Some(msg)) => msg,
            };
            log_received(id, &msg);
            let open = self.capture_handshake(id, &msg);
            if let NetworkMessage::Ping(nonce) = msg
                && writer.send(NetworkMessage::Pong(nonce)).await.is_err()
            {
                return true;
            }
            if !open {
                return false;
            }
        }
    }

    /// The probes: a random subset of [`Probe::ALL`] in random order, each
    /// waiting for its answer. Records each outcome in `probes`; returns
    /// whether the peer closed the connection, after which no probe is
    /// sent.
    async fn survey_probe(
        &self,
        id: PeerId,
        writer: &mut crate::net::connection::ConnectionWriter,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
        probes: &mut ProbeResults,
    ) -> bool {
        #[cfg(test)]
        let chosen = self
            .survey
            .get()
            .and_then(|run| run.forced_probes.lock().clone())
            .unwrap_or_else(|| survey::choose_probes(&mut rand::thread_rng()));
        #[cfg(not(test))]
        let chosen = survey::choose_probes(&mut rand::thread_rng());
        let (locator, stop) = self.survey_locator();
        let wtxid_relay = self.peers.read().get(&id).is_some_and(|h| h.info.wtxid_relay);
        let ctx = ProbeContext::new(&mut rand::thread_rng(), locator, stop, wtxid_relay);
        let wanted = survey::probe_inventory(&ctx);
        for probe in chosen {
            let sent_at = Instant::now();
            let outcome = if writer.send(survey::probe_message(probe, &ctx)).await.is_err() {
                ProbeOutcome::Disconnected
            } else {
                let wait = if probe == Probe::Unknown { UNKNOWN_PROBE_WAIT } else { PROBE_REPLY_WAIT };
                let deadline = tokio::time::Instant::now() + wait;
                loop {
                    let msg = match tokio::time::timeout_at(deadline, read_rx.recv()).await {
                        Err(_) => break ProbeOutcome::Silent,
                        Ok(None) => break ProbeOutcome::Disconnected,
                        Ok(Some(msg)) => msg,
                    };
                    log_received(id, &msg);
                    match (probe, &msg) {
                        (Probe::Ping, NetworkMessage::Pong(n)) if *n == ctx.nonce => {
                            let ms = u32::try_from(sent_at.elapsed().as_millis()).unwrap_or(u32::MAX);
                            break ProbeOutcome::Answered(ms);
                        }
                        (Probe::GetHeaders, NetworkMessage::Headers(h)) => {
                            break ProbeOutcome::Answered(h.len() as u32);
                        }
                        (Probe::GetData, NetworkMessage::NotFound(inv)) if inv.contains(&wanted) => {
                            break ProbeOutcome::Answered(inv.iter().filter(|i| **i == wanted).count() as u32);
                        }
                        (_, NetworkMessage::Ping(n)) => {
                            if writer.send(NetworkMessage::Pong(*n)).await.is_err() {
                                break ProbeOutcome::Disconnected;
                            }
                        }
                        _ => {}
                    }
                }
            };
            probes.set(probe, outcome);
            if let Some(run) = self.survey.get() {
                let i = Probe::ALL.iter().position(|p| *p == probe).expect("in ALL");
                run.probe_outcomes[i][outcome_slot(outcome)].fetch_add(1, Ordering::Relaxed);
            }
            if outcome == ProbeOutcome::Disconnected {
                return true;
            }
        }
        false
    }

    /// The `getheaders` probe's locator and stop: our tip's parent and our
    /// tip, so a peer on our chain answers with one header. At genesis,
    /// genesis for both.
    fn survey_locator(&self) -> (bitcoin::BlockHash, bitcoin::BlockHash) {
        let tip = self.chain_state.tip_hash();
        let parent = self
            .chain_state
            .get_block_index(&tip)
            .filter(|e| e.height > 0)
            .map_or(tip, |e| e.header.prev_blockhash);
        (parent, tip)
    }

    /// `getpeersurvey`: the aggregate, and with `verbose` a row per
    /// address. With the survey off, `enabled` is false and the counts are
    /// zero.
    pub fn get_peer_survey(&self, verbose: bool) -> serde_json::Value {
        let Some(run) = self.survey.get() else {
            return survey::survey_json(&SurveyStore::default(), verbose, &serde_json::json!({ "enabled": false }));
        };
        let settings = serde_json::json!({
            "enabled": true,
            "probes": run.config.probes,
            "interval": run.config.interval.as_secs(),
            "connections": {
                "completed": run.completed.load(Ordering::Relaxed),
                "failed": run.failed.load(Ordering::Relaxed),
            },
        });
        let store = run.store.lock();
        survey::survey_json(&store, verbose, &settings)
    }

    /// The survey's counts for the metrics; `None` with the survey off.
    pub fn survey_metrics(&self) -> Option<SurveyMetrics> {
        let run = self.survey.get()?;
        let agg = run.store.lock().aggregate();
        let mut probe_outcomes = [[0u64; 3]; 4];
        for (row, counters) in probe_outcomes.iter_mut().zip(&run.probe_outcomes) {
            for (n, c) in row.iter_mut().zip(counters) {
                *n = c.load(Ordering::Relaxed);
            }
        }
        Some(SurveyMetrics {
            records: agg.addresses,
            completed: run.completed.load(Ordering::Relaxed),
            failed: run.failed.load(Ordering::Relaxed),
            families: agg.families,
            unknown: agg.unknown,
            mismatches: agg.mismatches,
            v2: agg.v2,
            probe_outcomes,
        })
    }

    /// The survey's store, for tests.
    #[cfg(test)]
    pub(super) fn survey_store(&self) -> Option<SurveyStore> {
        self.survey.get().map(|run| run.store.lock().clone())
    }
}
