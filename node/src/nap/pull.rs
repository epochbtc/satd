//! The aggregator's pulls (`-napaggregator`): which publishers to ask, and
//! one pull per peer at a time, page by page, into the [`Collector`].
//!
//! A pull is a `getnapatt` without a cursor and the continuations that
//! follow it, one page at a time, each asked for only once the last was
//! taken. It ends when a page comes without a cursor, when the deferred
//! queue has no room for another page, when a page shows misbehaviour, or
//! when the publisher stops answering for [`PULL_TIMEOUT`]: a publisher
//! over its serving limits stays silent rather than refusing.
//!
//! A publisher is pulled over an existing connection when the node has one
//! (user, 2026-10-23): as soon as each connection to it opens, since a
//! publisher's limits are per connection, and then every
//! [`REPULL_INTERVAL`] while it stays up. A publisher the node is not
//! connected to is reached
//! with a short [`ConnType::NapPull`](crate::net::peer::ConnType::NapPull)
//! connection, at most [`MAX_PULL_CONNECTIONS`] at a time, and no more
//! often than [`REPULL_INTERVAL`] per address.
//!
//! [`Puller`] holds only the bookkeeping; the peer manager sends, dials and
//! punishes as it says.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::OutPoint;
use parking_lot::Mutex;

use super::collect::{Collector, Intake, PullBudget};
use super::p2p::{GetNapAtt, NapAtt};
use super::publisher::ChainSource;
use super::Rejection;

/// How long a publisher has to answer one request.
pub const PULL_TIMEOUT: Duration = Duration::from_secs(60);
/// How often one publisher is pulled. Above the publishers' one new pull
/// per connection per 10 minutes, so a pull over a long-lived connection is
/// never refused for that.
pub const REPULL_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// The most pull connections open at once.
pub const MAX_PULL_CONNECTIONS: usize = 2;
/// The most pulls in progress at once, over every kind of connection. Each
/// may add a page to the deferred queue past its room check, so this also
/// bounds how far the queue can run over.
pub const MAX_ACTIVE_PULLS: usize = 8;
/// The most pages one pull takes. A publisher serves one connection at most
/// 200 MB an hour, which is 200 full pages; a pull that runs longer is a
/// publisher streaming pages that cost nothing to pass over, and ends.
pub const MAX_PULL_PAGES: u32 = 200;
/// How long a pull connection's dial may take before it is given up.
pub const DIAL_TIMEOUT: Duration = PULL_TIMEOUT;
/// How long a dial is counted against [`MAX_PULL_CONNECTIONS`] at most: its
/// own timeout, the handshake's, and margin.
const DIALING_EXPIRY: Duration = Duration::from_secs(3 * 60);

/// How often the peer manager's collection tick runs.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// A peer's id, as the peer manager numbers connections.
pub type PeerId = u64;

/// One pull in progress.
struct Active {
    /// The publisher's address, which deferred work and the statistics name.
    source: String,
    /// Opened for this pull, and closed when it ends.
    pull_connection: bool,
    /// When the request now outstanding was sent.
    sent_at: Instant,
    budget: PullBudget,
    /// Pages taken so far.
    pages: u32,
    /// A page is being taken; the budget is out with it.
    taking: bool,
}

/// Collection counters, for `listnapaggregate`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Pulls that ended with a page without a cursor.
    pub pulls_completed: u64,
    /// Pulls that ended because the publisher stopped answering.
    pub pulls_timed_out: u64,
    /// Pages taken.
    pub pages: u64,
    /// Peers found misbehaving: a malformed `napatt`, or an attestation
    /// whose signature fails.
    pub misbehaving: u64,
    /// `napatt` messages nobody asked for, ignored.
    pub unsolicited: u64,
    /// Attestations refused because their outpoint had all its keys.
    pub key_limit: u64,
    /// Attestations refused because the set was at `-napaggregatormax`.
    pub full: u64,
}

/// What to do after a `napatt`.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// Not a reply to anything asked: ignore it.
    Unsolicited,
    /// Send this continuation.
    Continue(Vec<u8>),
    /// The pull is over; close the connection if it was opened for it.
    Done { close: bool },
    /// The peer misbehaved: punish it, and the pull is over.
    Misbehaved(String),
}

pub struct Puller {
    collector: Arc<Collector>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    active: HashMap<PeerId, Active>,
    /// When each publisher address was last pulled, or dialled for a pull.
    last_pull: HashMap<String, Instant>,
    /// Pull connections being opened, by address, since when. The dial is
    /// bounded by [`DIAL_TIMEOUT`] and the handshake by the node's peer
    /// timeout; one that ends neither way is forgotten after
    /// [`DIALING_EXPIRY`].
    dialing: HashMap<String, Instant>,
    stats: Stats,
}

impl Puller {
    pub fn new(collector: Arc<Collector>) -> Self {
        Puller { collector, state: Mutex::new(State::default()) }
    }

    pub fn collector(&self) -> &Arc<Collector> {
        &self.collector
    }

    pub fn stats(&self) -> Stats {
        self.state.lock().stats
    }

    /// Pulls in progress.
    pub fn active(&self) -> usize {
        self.state.lock().active.len()
    }

    /// Pull connections open, or being opened, for pulls in progress.
    pub fn pull_connections(&self) -> usize {
        let st = self.state.lock();
        st.active.values().filter(|a| a.pull_connection).count() + st.dialing.len()
    }

    /// A pull connection to `source` is being opened. It counts as one of
    /// [`MAX_PULL_CONNECTIONS`], and the address is not due again for
    /// [`REPULL_INTERVAL`] whether or not it answers.
    pub fn dial_started(&self, source: &str, now: Instant) {
        let mut st = self.state.lock();
        st.dialing.insert(source.to_owned(), now);
        st.last_pull.insert(source.to_owned(), now);
    }

    /// The pull connection to `source` connected, or failed.
    pub fn dial_ended(&self, source: &str) {
        self.state.lock().dialing.remove(source);
    }

    /// Whether `source` is due a pull at `now`.
    pub fn due(&self, source: &str, now: Instant) -> bool {
        self.state
            .lock()
            .last_pull
            .get(source)
            .is_none_or(|t| now.saturating_duration_since(*t) >= REPULL_INTERVAL)
    }

    /// Start a pull from `peer`, at `source`, if none is in progress with it
    /// and the deferred queue has room for a page: the `getnapatt` to send.
    /// `pull_connection` says the connection was opened for it.
    pub fn start(&self, peer: PeerId, source: &str, pull_connection: bool, now: Instant) -> Option<Vec<u8>> {
        if !self.collector.has_room() {
            return None;
        }
        let mut st = self.state.lock();
        if st.active.contains_key(&peer) || st.active.len() >= MAX_ACTIVE_PULLS {
            return None;
        }
        st.last_pull.insert(source.to_owned(), now);
        st.active.insert(
            peer,
            Active {
                source: source.to_owned(),
                pull_connection,
                sent_at: now,
                budget: self.collector.pull_budget(),
                pages: 0,
                taking: false,
            },
        );
        Some(request(None))
    }

    /// Take a `napatt` from `peer`. The intake runs here, verifying
    /// signatures, so the caller runs this off the network thread.
    pub fn on_napatt(&self, chain: &impl ChainSource, peer: PeerId, payload: &[u8], now: Instant) -> Next {
        // The pull stays in place, marked, while its page is taken, so that
        // a disconnect meanwhile ends it rather than being missed.
        let (source, mut budget) = {
            let mut st = self.state.lock();
            match st.active.get_mut(&peer) {
                Some(a) if !a.taking => {
                    a.taking = true;
                    (a.source.clone(), std::mem::replace(&mut a.budget, PullBudget::empty()))
                }
                _ => {
                    st.stats.unsolicited += 1;
                    return Next::Unsolicited;
                }
            }
        };
        let end = |st: &mut State| st.active.remove(&peer);
        // If the intake panics, the pull ends rather than holding its slot
        // marked as being taken for good.
        let _ends_on_panic = EndOnPanic { state: &self.state, peer };
        let page = match NapAtt::from_bytes(payload) {
            Ok(page) => page,
            Err(e) => {
                let mut st = self.state.lock();
                end(&mut st);
                st.stats.misbehaving += 1;
                return Next::Misbehaved(format!("malformed napatt: {e}"));
            }
        };
        let Intake { misbehaved, key_limit, full, .. } =
            self.collector.intake(chain, &source, page.attestations, &mut budget, now);
        let mut st = self.state.lock();
        st.stats.pages += 1;
        st.stats.key_limit += key_limit as u64;
        st.stats.full += full as u64;
        if let Some(r) = misbehaved {
            end(&mut st);
            st.stats.misbehaving += 1;
            return Next::Misbehaved(misbehaviour(&r));
        }
        let room = self.collector.has_room();
        let Some(active) = st.active.get_mut(&peer) else {
            // The peer went while its page was taken.
            return Next::Done { close: false };
        };
        active.pages += 1;
        match page.next_cursor {
            Some(cursor) if room && active.pages < MAX_PULL_PAGES => {
                active.taking = false;
                active.budget = budget;
                active.sent_at = now;
                Next::Continue(request(Some(cursor)))
            }
            Some(_) => {
                let close = active.pull_connection;
                end(&mut st);
                Next::Done { close }
            }
            None => {
                let close = active.pull_connection;
                end(&mut st);
                st.stats.pulls_completed += 1;
                Next::Done { close }
            }
        }
    }

    /// The pulls whose publisher has not answered within [`PULL_TIMEOUT`],
    /// ended, with whether to close each one's connection.
    pub fn expire(&self, now: Instant) -> Vec<(PeerId, bool)> {
        let mut st = self.state.lock();
        let late: Vec<(PeerId, bool)> = st
            .active
            .iter()
            // A page being taken has arrived; only its intake is running.
            .filter(|(_, a)| !a.taking && now.saturating_duration_since(a.sent_at) >= PULL_TIMEOUT)
            .map(|(id, a)| (*id, a.pull_connection))
            .collect();
        for (id, _) in &late {
            st.active.remove(id);
            st.stats.pulls_timed_out += 1;
        }
        st.dialing.retain(|_, since| now.saturating_duration_since(*since) < DIALING_EXPIRY);
        late
    }

    /// Note that `peer` disconnected: a pull with it is over.
    pub fn forget(&self, peer: PeerId) {
        self.state.lock().active.remove(&peer);
    }

    /// Record a peer found misbehaving outside a pull, such as by deferred
    /// work.
    pub fn note_misbehaving(&self) {
        self.state.lock().stats.misbehaving += 1;
    }
}

/// Ends `peer`'s pull if dropped while unwinding.
struct EndOnPanic<'a> {
    state: &'a Mutex<State>,
    peer: PeerId,
}

impl Drop for EndOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.state.lock().active.remove(&self.peer);
        }
    }
}

/// A `getnapatt` for every attestation, after `cursor`.
fn request(cursor: Option<OutPoint>) -> Vec<u8> {
    GetNapAtt { anchor_height_min: 0, keys: Vec::new(), cursor }.to_bytes()
}

/// The reason a misbehaving page gives.
pub fn misbehaviour(r: &Rejection) -> String {
    format!("napatt attestation fails {}: {r}", r.rule())
}
