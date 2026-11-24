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
    SurveyShape, SurveyStore, UNKNOWN_PROBE_WAIT,
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
    /// The store's aggregate as of its last change, for the metrics and
    /// `getpeersurvey` without `verbose`: neither walks the store.
    aggregate: parking_lot::Mutex<survey::Aggregate>,
    /// A survey dial is under way. With a [`ConnType::Survey`] peer in the
    /// table, this makes the one connection at a time.
    dialing: AtomicBool,
    /// Survey connections that ran their session, and those that did not
    /// (a failed dial or handshake), this run.
    completed: AtomicU64,
    failed: AtomicU64,
    /// The last survey connection to end: when (Unix seconds) and whether
    /// it completed. `None` until one ends.
    last: parking_lot::Mutex<Option<(u64, bool)>>,
    /// Probe outcomes this run, by [`Probe::ALL`] then answered, silent,
    /// disconnected.
    probe_outcomes: [[AtomicU64; 3]; 4],
    /// The probes every connection sends, in order, in place of a random
    /// draw: for tests.
    #[cfg(test)]
    pub(super) forced_probes: parking_lot::Mutex<Option<Vec<Probe>>>,
}

impl SurveyRun {
    /// Keep a survey connection that ended as the last one, and count it.
    /// The last one is set first, so a reader that sees the count sees it.
    fn note_connection(&self, completed: bool) {
        *self.last.lock() = Some((crate::time::now_secs(), completed));
        let counter = if completed { &self.completed } else { &self.failed };
        counter.fetch_add(1, Ordering::Relaxed);
    }
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
    /// Records no row matched, the claimed ones included.
    pub unknown: usize,
    /// The unknown records whose user agent names a family, per family:
    /// never counted in `families`.
    pub claimed: [usize; crate::net::fingerprint::Family::ALL.len()],
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

/// What a survey or crawl session's next read brought.
pub(super) enum Next {
    Msg(NetworkMessage),
    /// The wait ran out.
    Timeout,
    /// The peer closed the connection.
    Closed,
    /// The node closed it: `disconnectnode`, a ban, `setnetworkactive
    /// false` or shutdown signalled the peer's handle.
    Aborted,
}

/// The next message, the deadline, the peer's close or the node's,
/// whichever comes first.
pub(super) async fn next_message(
    read_rx: &mut mpsc::Receiver<NetworkMessage>,
    deadline: tokio::time::Instant,
    abort: &tokio::sync::Notify,
) -> Next {
    tokio::select! {
        r = tokio::time::timeout_at(deadline, read_rx.recv()) => match r {
            Err(_) => Next::Timeout,
            Ok(None) => Next::Closed,
            Ok(Some(msg)) => Next::Msg(msg),
        },
        _ = abort.notified() => Next::Aborted,
    }
}

/// How [`listen_passive`] ended.
pub(super) enum Listened {
    /// The wait ran out with the transcript still open.
    Timeout,
    /// The transcript closed.
    Settled,
    /// The connection closed, at the peer's end or the node's.
    Closed,
}

/// The passive wait of a survey or crawl session: take the peer's messages
/// until `observe` (which records each in the handshake transcript) says
/// the transcript has closed, or `deadline`, answering a `ping` with a
/// `pong`. Nothing else is sent.
pub(super) async fn listen_passive(
    id: PeerId,
    writer: &mut crate::net::connection::ConnectionWriter,
    read_rx: &mut mpsc::Receiver<NetworkMessage>,
    abort: &tokio::sync::Notify,
    deadline: tokio::time::Instant,
    mut observe: impl FnMut(&NetworkMessage) -> bool,
) -> Listened {
    loop {
        let msg = match next_message(read_rx, deadline, abort).await {
            Next::Msg(msg) => msg,
            Next::Timeout => return Listened::Timeout,
            Next::Closed | Next::Aborted => return Listened::Closed,
        };
        log_received(id, &msg);
        let open = observe(&msg);
        if let NetworkMessage::Ping(nonce) = msg
            && writer.send(NetworkMessage::Pong(nonce)).await.is_err()
        {
            return Listened::Closed;
        }
        if !open {
            return Listened::Settled;
        }
    }
}

/// Send the probes `chosen`, in order, each waiting for its answer:
/// `waits` is the wait of every probe but the unknown message's, then the
/// unknown message's. A `getheaders` probe is skipped without
/// `has_locator`. With `deadline`, no probe waits past it and none is sent
/// after it. Each outcome goes to `on_outcome`; with `headers`, the
/// `getheaders` probe's answer is kept there too. Returns whether the
/// connection closed, at the peer's end or the node's (`abort`), after
/// which no probe is sent. A `ping` from the peer is answered; anything
/// else is ignored.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_probes(
    id: PeerId,
    writer: &mut crate::net::connection::ConnectionWriter,
    read_rx: &mut mpsc::Receiver<NetworkMessage>,
    abort: &tokio::sync::Notify,
    chosen: Vec<Probe>,
    ctx: &ProbeContext,
    has_locator: bool,
    waits: (Duration, Duration),
    deadline: Option<tokio::time::Instant>,
    mut headers: Option<&mut Option<Vec<bitcoin::block::Header>>>,
    mut on_outcome: impl FnMut(Probe, ProbeOutcome),
) -> bool {
    let wanted = survey::probe_inventory(ctx);
    for probe in chosen {
        if probe == Probe::GetHeaders && !has_locator {
            continue;
        }
        let now = tokio::time::Instant::now();
        if deadline.is_some_and(|d| now >= d) {
            break;
        }
        let sent_at = Instant::now();
        let outcome = if writer.send(survey::probe_message(probe, ctx)).await.is_err() {
            ProbeOutcome::Disconnected
        } else {
            let wait = if probe == Probe::Unknown { waits.1 } else { waits.0 };
            let probe_deadline = deadline.map_or(now + wait, |d| d.min(now + wait));
            loop {
                let msg = match next_message(read_rx, probe_deadline, abort).await {
                    Next::Msg(msg) => msg,
                    Next::Timeout => break ProbeOutcome::Silent,
                    Next::Closed => break ProbeOutcome::Disconnected,
                    // Not the peer's doing: nothing to record.
                    Next::Aborted => return true,
                };
                log_received(id, &msg);
                match (probe, &msg) {
                    (Probe::Ping, NetworkMessage::Pong(n)) if *n == ctx.nonce => {
                        let ms = u32::try_from(sent_at.elapsed().as_millis()).unwrap_or(u32::MAX);
                        break ProbeOutcome::Answered(ms);
                    }
                    (Probe::GetHeaders, NetworkMessage::Headers(h)) => {
                        let n = h.len() as u32;
                        if let Some(keep) = headers.as_deref_mut() {
                            *keep = Some(h.clone());
                        }
                        break ProbeOutcome::Answered(n);
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
        on_outcome(probe, outcome);
        if outcome == ProbeOutcome::Disconnected {
            return true;
        }
    }
    false
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
                    if store.dropped_old_format() > 0 {
                        tracing::info!(
                            dropped = store.dropped_old_format(),
                            "The network survey file is in the old format; its records are dropped and the survey starts empty"
                        );
                    } else {
                        tracing::info!(records = store.len(), "Loaded the network survey");
                    }
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
            aggregate: parking_lot::Mutex::new(store.aggregate()),
            store: parking_lot::Mutex::new(store),
            dialing: AtomicBool::new(false),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last: parking_lot::Mutex::new(None),
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

    /// Whether the crawl (`-crawl`) has taken the survey's place: it
    /// measures everything the survey would, from more addresses, so the
    /// survey opens no connection while it is on. Its store is still read
    /// and reported.
    pub fn survey_superseded(&self) -> bool {
        self.crawl_enabled()
    }

    /// `-asmap`'s map, for the survey records' autonomous systems.
    pub fn set_asmap(&self, map: Arc<crate::net::asmap::AsMap>) {
        let _ = self.asmap.set(map);
    }

    /// Start the survey's loop: a survey connection every
    /// `-peersurveyinterval` while none is open, and the store written every
    /// [`survey::SAVE_INTERVAL`]. Ends at shutdown. Nothing without
    /// [`Self::enable_survey`], and nothing while the crawl supersedes it.
    pub fn spawn_survey(self: &Arc<Self>) {
        let Some(run) = self.survey.get() else {
            return;
        };
        if self.survey_superseded() {
            tracing::info!("The network survey is superseded by the crawl and opens no connection");
            return;
        }
        let interval = run.config.interval.max(Duration::from_secs(1));
        let pm = Arc::clone(self);
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick is immediate; the first survey waits a whole
            // interval, as the node is still finding its peers.
            tick.tick().await;
            // The store is written on a timer of its own, whatever the
            // survey's interval.
            let mut save = tokio::time::interval(survey::SAVE_INTERVAL);
            save.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            save.tick().await;
            loop {
                let dial = tokio::select! {
                    _ = tick.tick() => true,
                    _ = save.tick() => false,
                    _ = shutdown.changed() => false,
                };
                if *shutdown.borrow() {
                    return;
                }
                if dial {
                    pm.survey_tick();
                } else {
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
    /// is open, networking is off, the node makes no automatic connections
    /// (`-connect`), or the crawl supersedes the survey. Returns the
    /// address dialled.
    pub(super) fn survey_tick(self: &Arc<Self>) -> Option<PeerAddr> {
        let run = self.survey.get()?;
        if self.survey_superseded()
            || !self.is_network_active()
            || !self.automatic_outbound.load(Ordering::Relaxed)
            || self.survey_open()
        {
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
                run.note_connection(false);
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
                    run.note_connection(false);
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
        let Some((stats, abort)) = self.peers.read().get(&id).map(|h| (h.stats.clone(), h.disconnect.clone())) else {
            // Closed by the node already.
            return;
        };
        reader.set_counters(stats.clone());
        writer.set_counters(stats);
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

        let closed = self.survey_listen(id, &mut writer, &mut read_rx, &abort).await;
        let mut probes = ProbeResults::default();
        let closed = closed
            || (self.survey.get().is_some_and(|run| run.config.probes)
                && self.survey_probe(id, &mut writer, &mut read_rx, &abort, &mut probes).await);
        read_task.abort();
        drop(writer);

        let Some(mut handle) = self.peers.write().remove(&id) else {
            // Gone already: shutdown, or `setnetworkactive false`.
            return;
        };
        let info = &mut handle.info;
        let fingerprint = crate::net::fingerprint::classify(false, &info.behavior.handshake, info.behavior.version.as_ref(), true);
        let reason = if closed { "survey-peer-closed" } else { "survey-done" };
        // A shape no row matched keeps its raw features, in the record and
        // here, so the next round of unknown shapes can be told apart.
        let relay = info.behavior.version.as_ref().is_some_and(|v| v.relay);
        let shape = fingerprint.observed().is_none().then(|| SurveyShape::of(&info.behavior.handshake, relay));
        tracing::debug!(
            "survey connection done ({reason}), fingerprint={fingerprint} v2={v2} probes={}{}, disconnecting peer={id}",
            Probe::ALL
                .iter()
                .filter_map(|p| probes.get(*p).map(|o| format!("{}:{}", p.name(), o.name())))
                .collect::<Vec<_>>()
                .join(","),
            shape.as_ref().map_or_else(String::new, |s| format!(
                " handshake={} relay={} version={} services={:016x}",
                s.commands.join(","),
                s.relay,
                version.version,
                version.services.to_u64()
            ))
        );
        self.retire_behavior(id, info, reason);
        let Some(run) = self.survey.get() else {
            return;
        };
        run.note_connection(true);
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
            shape,
        };
        let aggregate = {
            let mut store = run.store.lock();
            store.insert(addr, record, now);
            store.aggregate()
        };
        *run.aggregate.lock() = aggregate;
    }

    /// The passive wait: send what a full-relay outbound sends after its
    /// `verack` (less `getaddr`, `getheaders` and our addresses), then take
    /// the peer's messages into its handshake transcript until it closes or
    /// [`PASSIVE_WAIT`] passes, answering a `ping`. Returns whether the
    /// connection closed, at the peer's end or the node's (`abort`).
    async fn survey_listen(
        &self,
        id: PeerId,
        writer: &mut crate::net::connection::ConnectionWriter,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
        abort: &tokio::sync::Notify,
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
        match listen_passive(id, writer, read_rx, abort, deadline, |msg| self.capture_handshake(id, msg)).await {
            Listened::Timeout => false,
            Listened::Closed => true,
            // A transcript reads as closed, too, once the node has dropped
            // the peer's handle.
            Listened::Settled => !self.peers.read().contains_key(&id),
        }
    }

    /// The probes: a random subset of [`Probe::ALL`] in random order, each
    /// waiting for its answer. Records each outcome in `probes`; returns
    /// whether the connection closed, at the peer's end or the node's
    /// (`abort`), after which no probe is sent.
    async fn survey_probe(
        &self,
        id: PeerId,
        writer: &mut crate::net::connection::ConnectionWriter,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
        abort: &tokio::sync::Notify,
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
        let locator = self.survey_locator();
        let zero = bitcoin::BlockHash::all_zeros();
        let (locator_top, stop) = locator.unwrap_or((zero, zero));
        let wtxid_relay = self.peers.read().get(&id).is_some_and(|h| h.info.wtxid_relay);
        let ctx = ProbeContext::new(&mut rand::thread_rng(), locator_top, stop, wtxid_relay);
        let waits = (PROBE_REPLY_WAIT, UNKNOWN_PROBE_WAIT);
        send_probes(id, writer, read_rx, abort, chosen, &ctx, locator.is_some(), waits, None, None, |probe, outcome| {
            probes.set(probe, outcome);
            if let Some(run) = self.survey.get() {
                let i = Probe::ALL.iter().position(|p| *p == probe).expect("in ALL");
                run.probe_outcomes[i][outcome_slot(outcome)].fetch_add(1, Ordering::Relaxed);
            }
        })
        .await
    }

    /// The `getheaders` probe's locator and stop: our tip's parent and our
    /// tip, so a peer on our chain answers with one header. `None` at
    /// genesis, where no stop hash lies past the locator and a peer would
    /// answer with a full batch of 2,000: the probe is not sent then.
    pub(super) fn survey_locator(&self) -> Option<(bitcoin::BlockHash, bitcoin::BlockHash)> {
        let tip = self.chain_state.tip_hash();
        let parent = self.chain_state.get_block_index(&tip).filter(|e| e.height > 0)?.header.prev_blockhash;
        Some((parent, tip))
    }

    /// `getpeersurvey`: the aggregate, and with `verbose` a row per
    /// address. With the survey off, `enabled` is false and the counts are
    /// zero.
    pub fn get_peer_survey(&self, verbose: bool) -> serde_json::Value {
        let Some(run) = self.survey.get() else {
            return survey::survey_json(
                &SurveyStore::default(),
                verbose,
                &serde_json::json!({
                    "enabled": false,
                    "superseded_by_crawl": self.survey_superseded(),
                    "alt_slots": self.alt_slots_json(),
                }),
            );
        };
        let settings = serde_json::json!({
            "enabled": !self.survey_superseded(),
            "superseded_by_crawl": self.survey_superseded(),
            "probes": run.config.probes,
            "interval": run.config.interval.as_secs(),
            "connections": {
                "completed": run.completed.load(Ordering::Relaxed),
                "failed": run.failed.load(Ordering::Relaxed),
                "last": run.last.lock().map(|(time, completed)| serde_json::json!({
                    "time": time,
                    "result": if completed { "completed" } else { "failed" },
                })),
            },
            "alt_slots": self.alt_slots_json(),
        });
        if verbose {
            // Copied under the lock, serialized outside it.
            let store = run.store.lock().clone();
            survey::survey_json(&store, true, &settings)
        } else {
            survey::aggregate_json(&run.aggregate.lock(), &settings)
        }
    }

    /// The survey's counts for the metrics; `None` with the survey off.
    pub fn survey_metrics(&self) -> Option<SurveyMetrics> {
        let run = self.survey.get()?;
        let agg = run.aggregate.lock().clone();
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
            claimed: agg.claimed,
            mismatches: agg.mismatches,
            v2: agg.v2,
            probe_outcomes,
        })
    }

    /// Run `f` on the survey's store; `None` with the survey off.
    pub(super) fn read_survey_store<R>(&self, f: impl FnOnce(&SurveyStore) -> R) -> Option<R> {
        self.survey.get().map(|run| f(&run.store.lock()))
    }

    /// Put a record in the survey's store, as a survey connection does, and
    /// refresh the aggregate. Returns false with the survey off.
    pub(super) fn insert_survey_record(&self, addr: PeerAddr, record: SurveyRecord, now: u64) -> bool {
        let Some(run) = self.survey.get() else {
            return false;
        };
        let aggregate = {
            let mut store = run.store.lock();
            store.insert(addr, record, now);
            store.aggregate()
        };
        *run.aggregate.lock() = aggregate;
        true
    }

    /// The survey's store, for tests.
    #[cfg(test)]
    pub(super) fn survey_store(&self) -> Option<SurveyStore> {
        self.survey.get().map(|run| run.store.lock().clone())
    }
}
