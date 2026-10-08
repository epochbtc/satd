use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;
use parking_lot::{Condvar, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use base64::Engine;

use crate::chain::connect_phase::ConnectPhase;
use crate::chain::state::ChainState;
use crate::mempool::fee::FeeEstimator;
use crate::mempool::orphanage::{AddOutcome, OrphanReject, TxOrphanage};
use crate::mempool::pool::{Mempool, MempoolError};
use crate::net::bg_catchup::BgDownloader;
use crate::net::compact;
use crate::net::connection::{Connection, ConnectionWriter};
use crate::net::ibd::IbdScheduler;
use crate::net::peer::{default_p2p_port, ConnType, Direction, PeerAddr, PeerId, PeerInfo, PeerState};
use crate::net::proxy;
use crate::net::stats::{NetTotals, PeerStats};
use crate::net::sync;

const MAX_OUTBOUND: usize = 8;
const MAX_OUTBOUND_IBD: usize = 64;
/// Block-relay-only slots, counted separately from full-relay ones. Bitcoin
/// Core's `m_max_outbound_block_relay` (2 by default): these connections exist
/// so a tx-graph observer cannot learn the full topology, which only works if
/// they are not competing with full-relay peers for the same slots.
const MAX_OUTBOUND_BLOCK_RELAY: usize = 2;
/// How long an `addr-fetch` connection is kept if the peer never answers our
/// `getaddr`. Core's `SendMessages` drops one after `10 *
/// AVG_ADDRESS_BROADCAST_INTERVAL` (net_processing.cpp), i.e. 300 seconds
/// since the connection was made.
const ADDR_FETCH_TIMEOUT_SECS: u64 = 10 * 30;
const BAN_THRESHOLD: u32 = 100;
/// Keepalive cadence: how often each peer is sent a `ping` when none is
/// outstanding. Bitcoin Core's `PING_INTERVAL` (net_processing.h).
///
/// The pong that comes back is what proves the link is still alive in both
/// directions, and it is what populates `getpeerinfo`'s `pingtime`.
const PING_INTERVAL: Duration = Duration::from_secs(120);

/// How long a ping may go unanswered before the peer is disconnected.
/// Bitcoin Core's `TIMEOUT_INTERVAL` (net.h).
///
/// Core additionally gates its inactivity checks on the connection being
/// older than `-peertimeout` (60s). That gate is subsumed here: satd's first
/// ping goes out when the connection is set up, so a ping cannot have been
/// outstanding for twenty minutes unless the connection is at least that old.
const PING_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Minimum interval between announcement-triggered `getheaders` to a single
/// peer. Caps the header-discovery work a peer can make us do by spamming
/// invs / unconnectable headers (anti-DoS), while still reacting promptly to
/// an honest competing-chain announcement.
const GETHEADERS_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Cap on onion peer addresses discovered via `addrv2` gossip and kept in
/// `connect_peer_addrs` for the reconnect loop to dial. Unlike clearnet
/// addresses (persisted in the addrman / peers.dat), onion peers live only in
/// this in-memory list, so bound it to avoid unbounded growth from a gossipy
/// peer. The reconnect loop never opens more than the outbound target anyway.
const MAX_ONION_CONNECT_ADDRS: usize = 512;

/// Upper bound on onion dials the reconnect loop starts in a single 10s tick.
/// Onion dials each hold a Tor circuit through the one configured SOCKS proxy,
/// so a burst must be bounded even when many slots are open — otherwise a peer
/// that floods `connect_peer_addrs` via addrv2 gossip could make a single tick
/// spawn hundreds of concurrent circuits and saturate the proxy.
const MAX_ONION_DIALS_PER_TICK: usize = 16;

/// How long a resolved peer name that has lost its connection waits before
/// it is looked up again. Core resolves an added node on each attempt and
/// attempts once a minute (`ThreadOpenAddedConnections`).
const MANUAL_TARGET_RELOOKUP: Duration = Duration::from_secs(60);

/// A peer the operator named (`-addnode`, `addnode add`, or a `-connect`
/// host name), with the address it currently resolves to.
#[derive(Debug, Clone)]
struct ManualTarget {
    /// The string as the operator gave it.
    target: String,
    /// Registered for dialling; `None` while a name has not resolved.
    resolved: Option<PeerAddr>,
    /// An added node, reported by `getaddednodeinfo`; `false` for a
    /// `-connect` name.
    listed: bool,
    /// When a name is next looked up.
    next_lookup: Instant,
    /// Consecutive failed lookups, to log the first at `info`.
    lookups_failed: u32,
}
/// Ban score charged for a `headers` message whose parent we don't have. Small
/// enough that an honest peer announcing a better chain (one such message,
/// resolved by the getheaders we send back) stays far under [`BAN_THRESHOLD`],
/// but a peer streaming endless unconnectable headers still accrues to a ban.
/// Ban score charged when a peer relays a *consensus-invalid* transaction (bad
/// script/signature, or outputs exceeding inputs). Mirrors the `block rejected`
/// score: relaying an invalid tx is real misbehavior, but we deliberately avoid
/// an instant ban (the verifier could have an edge case), so a peer accrues to a
/// ban over several. Policy/standardness/resource rejections (fee floor, dust,
/// mempool-full, RBF, conflicts) are NOT misbehavior and carry no score — see
/// [`tx_rejection_ban_score`].
const INVALID_TX_BAN_SCORE: u32 = 10;
/// Hardcoded fallback when callers (tests, the no-config `new` constructor)
/// don't supply a value. Operator-facing path goes through
/// `Config::maxinboundperip` and the `-maxinboundperip` CLI flag.
const DEFAULT_MAX_INBOUND_PER_IP: usize = 3;
/// Default handshake timeout in milliseconds, matching Bitcoin Core's
/// `-timeout` default (5000ms).
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Core's `DEFAULT_PEER_CONNECT_TIMEOUT`: seconds a new connection has before
/// the inactivity check may drop it (`-peertimeout`).
pub const DEFAULT_PEER_CONNECT_TIMEOUT_SECS: i64 = 60;

/// Core's `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS`: a pruned peer is a
/// wanted outbound peer while our tip is within this many blocks of now.
const NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS: u64 = 144;
/// Default distinct-witness count before a local tx is considered
/// propagated and rebroadcast stops. 1 = "any peer fetched/echoed it."
const DEFAULT_BROADCAST_CONFIRM_PEERS: u64 = 1;
/// Bounds for the "auto" (interval = 0) rebroadcast cadence — Bitcoin Core's
/// 10–15 minute randomized window. Randomizing avoids a fleet re-announcing
/// in lockstep.
const REBROADCAST_AUTO_MIN_SECS: u64 = 600;
const REBROADCAST_AUTO_MAX_SECS: u64 = 900;
/// P2P protocol cap on inventory items per `inv` message (Core's
/// `MAX_INV_SZ`); peers disconnect senders that exceed it.
const MAX_INV_PER_MSG: usize = 50_000;

/// Maximum entries in a getheaders/getblocks locator. Core disconnects
/// peers that exceed this (net_processing.cpp `MAX_LOCATOR_SZ`).
const MAX_LOCATOR_SZ: usize = 101;
/// How long a `getblockfrompeer` request stays armed. A block arriving after
/// this window is treated as an ordinary unsolicited block rather than a
/// repair, so a peer that answers minutes late cannot divert a block the
/// normal paths were already handling. Generous relative to a single-block
/// round trip, short enough that the map self-drains.
const BLOCK_REFETCH_TTL: Duration = Duration::from_secs(600);

/// How long the connector waits on one re-fetch of a stored block whose
/// record it cannot read before asking another peer. A single-block round
/// trip is well under this; the IBD connector retries once a second, so
/// without a floor it would ask a peer on every retry.
const UNREADABLE_REFETCH_INTERVAL: Duration = Duration::from_secs(10);

/// How long a tip-following block request counts as in flight. A request is
/// re-sent every few seconds while the block is still missing, which
/// refreshes the stamp; an entry this old belongs to a request nobody is
/// making any more.
const BLOCK_IN_FLIGHT_TTL: Duration = Duration::from_secs(120);
/// How long a compact block being reconstructed suppresses an ordinary fetch
/// of the same block. Core marks a block it is reconstructing as in flight
/// and does not download it twice; satd's tip-following sweep would otherwise
/// fetch in full a block already arriving compactly, spending the bandwidth
/// compact relay saves. Short on purpose: the sweep is the safety net for a
/// reconstruction that never finishes, so it must not be held off for long.
const COMPACT_RECONSTRUCT_SUPPRESSION: Duration = Duration::from_secs(5);
/// How recent the tip must be for a block announced by headers to be fetched
/// as a `cmpctblock`: Bitcoin Core's `CanDirectFetch`, twenty block
/// intervals (`PowTargetSpacing() * 20`, ten minutes on every network). An
/// older tip means the node is catching up and its mempool has little to
/// reconstruct from.
const DIRECT_FETCH_MAX_TIP_AGE_SECS: u64 = 20 * 10 * 60;
/// The protocol version satd speaks (Core's `PROTOCOL_VERSION`).
const PROTOCOL_VERSION: u32 = 70016;
/// BIP 130's `sendheaders` is only sent to a peer whose common version with
/// us reaches this (Core's `SENDHEADERS_VERSION`).
const SENDHEADERS_VERSION: u32 = 70012;
/// BIP 339's `wtxidrelay` is sent to, and honoured from, a peer whose common
/// version with us reaches this (Core's `WTXID_RELAY_VERSION`).
const WTXID_RELAY_VERSION: u32 = 70016;
/// Most tip-following block requests recorded per peer. The records exist to
/// answer "did we ask this peer for this block?", and a peer can make us
/// record one per hash it announces: an `inv` may carry
/// [`MAX_INV_PER_MSG`] hashes, none of which has to be a block anyone mined.
/// Capping per peer bounds the table by the connection limit rather than by
/// what peers say. Comfortably above the 128 blocks
/// [`PeerManager::request_missing_blocks`] asks for in one round; past it a
/// request simply goes unrecorded, and a block that arrives for it is treated
/// as unsolicited.
const MAX_IN_FLIGHT_BLOCKS_PER_PEER: usize = 256;
/// Events the manager loop takes from the peer queue in one pass before
/// yielding. A fairness bound so a busy peer cannot starve the periodic
/// maintenance in the same loop — not a rate limit: a pass that fills it
/// comes straight back for more (see `run`).
const EVENTS_PER_DRAIN: usize = 64;

/// How often the manager loop runs its periodic maintenance: stall
/// detection and the release of stuck IBD heights, work for idle peers, fee
/// filters, expiries. Every cadence in that section counts these passes
/// ("every 4 ticks (2s)"), so the pass has to come round on time, however
/// busy the event queue is (#909).
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(500);

/// What the manager loop does after one drain of the peer event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterDrain {
    /// Maintenance is due: run it, then go on draining.
    Maintain,
    /// The queue was still full and maintenance is not due: go straight
    /// back to the queue.
    DrainAgain,
    /// The queue is drained and maintenance is not due: wait for the next
    /// interval tick or a parked pong.
    Wait,
}

/// The manager loop's choice after each drain (#909).
///
/// Maintenance is due on every interval tick, as before, and also once
/// `MAINTENANCE_INTERVAL` has passed since it last started, so a queue too
/// busy to wait for a tick still gets it. It runs after the drain in
/// progress, however full the queue is. A drain takes at most
/// `EVENTS_PER_DRAIN` events, so maintenance is late by at most one drain.
///
/// 0.6.0 tied maintenance to an interval wake instead, and let a full queue
/// put it off: a run of fast drains ended in a wait for the next tick, and
/// the pass after that tick found the queue full again. Under initial block
/// download the queue is full at every wake, and with an fsync for every
/// block stored a single drain can take most of a second, so stall detection
/// ran tens of seconds apart and a block held by one slow peer stayed with it
/// for up to a minute.
///
/// A wake from `drain_now`, for a pong parked behind the queue, is neither a
/// tick nor late, so it drains and waits (#776): maintenance never runs at
/// the rate pings arrive.
#[derive(Debug, Default)]
struct DrainPacer {
    /// When maintenance last started; `None` before the first pass.
    last_maintenance: Option<Instant>,
    /// An interval tick has woken the loop since maintenance last started.
    ticked: bool,
}

impl DrainPacer {
    /// Record that an interval tick woke the loop.
    fn ticked(&mut self) {
        self.ticked = true;
    }

    /// Decide what follows a drain that took `processed` events, at `now`.
    fn after_drain(&self, processed: usize, now: Instant) -> AfterDrain {
        let due = self.ticked
            || self
                .last_maintenance
                .is_none_or(|t| now.duration_since(t) >= MAINTENANCE_INTERVAL);
        if due {
            AfterDrain::Maintain
        } else if processed >= EVENTS_PER_DRAIN {
            AfterDrain::DrainAgain
        } else {
            AfterDrain::Wait
        }
    }

    /// Record that maintenance started at `at`.
    fn maintained(&mut self, at: Instant) {
        self.last_maintenance = Some(at);
        self.ticked = false;
    }
}

/// Token-bucket cap for the promotion-INV drain (§8): at most this many
/// reloaded-and-promoted transactions are announced per drain tick, so a
/// worst-case mass promotion spreads over minutes instead of bursting peers.
const PROMOTION_DRAIN_PER_TICK: usize = 200;
/// Interval between promotion-drain ticks. With [`PROMOTION_DRAIN_PER_TICK`],
/// a full-quarantine promotion of tens of thousands of txs drains over a few
/// minutes (e.g. 20k txs ≈ 100 ticks ≈ 3.3 min). Public so the satd binary's
/// drain task can pace itself by the same constant.
pub const PROMOTION_DRAIN_INTERVAL_SECS: u64 = 2;
/// Minimum spacing between BIP35 `mempool` dumps served to one peer. Each
/// dump is a full-mempool scan plus up to multi-MB of queued `inv`s, so a
/// permissioned-but-misbehaving peer must not be able to request it in a
/// tight loop ("whitelisted subnet" ≠ "trusted to behave for months").
const MEMPOOL_REQUEST_COOLDOWN_SECS: u64 = 30;
/// Minimum timeout for a SOCKS5 `.onion` dial, in milliseconds. A `.onion`
/// connect tunnels the proxy socket connect, the SOCKS5 handshake, and the
/// Tor rendezvous (HS descriptor fetch + intro/rendezvous circuit build) — the
/// last of which routinely takes well over the 5s clearnet socket-connect
/// budget, especially on the first connection to a freshly-published service.
/// Bitcoin Core gives the SOCKS5 exchange its own 20s `SOCKS5_RECV_TIMEOUT`
/// (netbase.cpp) for exactly this reason; we mirror that as a floor so a small
/// `-timeout` doesn't make onion peers effectively undialable. A larger
/// `-timeout` still wins (operators can extend, not shorten, the onion budget).
const ONION_DIAL_TIMEOUT_FLOOR_MS: u64 = 20_000;
/// How far above the background connect cursor the AssumeUTXO catch-up
/// downloader keeps historical blocks requested/on-disk. Bounds disk
/// read-ahead and outstanding `getdata` for the background range.
const BG_CATCHUP_WINDOW: u32 = 1024;
/// A background-range `getdata` older than this is assumed lost and
/// becomes eligible for re-request on the next download pass.
const BG_CATCHUP_STALE_SECS: u64 = 30;
/// Cap on the number of fresh background-range `getdata` heights issued
/// per peer per download pass, so the catch-up downloader does not flood
/// a single peer.
const BG_CATCHUP_PER_PEER_PER_PASS: usize = 16;
/// Flush the background coin cache to disk every N connected blocks so a
/// crash resumes from a recent private tip instead of redoing the whole
/// genesis→snapshot validation.
const BG_CATCHUP_FLUSH_EVERY: u64 = 2000;

/// How long the IBD connector waits on one height's block data before it
/// warns that it is stuck (#904). Blocks arrive out of order from many peers
/// and the connector takes them in height order, so it waits on some height
/// for a second or two all through a healthy sync. In the run that set this,
/// those waits were all under 5 s; the ones worth a warning had the block in
/// flight on a single peer for 23–60 s.
///
/// Above the 15 s after which the scheduler takes a block at the connect
/// cursor back from a peer and asks another (`release_stale_inflight`), with
/// room for the maintenance pass that does it: a wait that release ends is
/// the sync handling a slow peer, not a stuck connector.
const STUCK_WAIT_WARN_AFTER: Duration = Duration::from_secs(20);

/// How often the stuck-wait warning repeats while the wait goes on.
const STUCK_WAIT_WARN_EVERY: Duration = Duration::from_secs(60);

/// The IBD connector's current wait on one height's block data, for the
/// "Connector stuck waiting for block data" warning.
#[derive(Debug, Clone, Copy)]
struct StuckWait {
    height: u32,
    since: Instant,
    warned_at: Option<Instant>,
}

impl StuckWait {
    /// Record that the connector is waiting on `height` at `now`, and say
    /// whether to warn: once the wait passes `STUCK_WAIT_WARN_AFTER`, then
    /// every `STUCK_WAIT_WARN_EVERY` while it lasts. A wait on a different
    /// height starts over.
    fn should_warn(wait: &mut Option<StuckWait>, height: u32, now: Instant) -> bool {
        if wait.is_none_or(|w| w.height != height) {
            *wait = Some(StuckWait {
                height,
                since: now,
                warned_at: None,
            });
        }
        let Some(w) = wait.as_mut() else {
            return false;
        };
        if now.duration_since(w.since) < STUCK_WAIT_WARN_AFTER {
            return false;
        }
        if w
            .warned_at
            .is_some_and(|t| now.duration_since(t) < STUCK_WAIT_WARN_EVERY)
        {
            return false;
        }
        w.warned_at = Some(now);
        true
    }
}

/// Per-address reconnect backoff state.
struct ReconnectState {
    attempts: u32,
    next_attempt: Instant,
}

impl ReconnectState {
    fn new() -> Self {
        Self {
            attempts: 0,
            next_attempt: Instant::now(),
        }
    }

    /// Backoff delay: 10s, 20s, 40s, 80s, 160s, capped at 300s.
    fn backoff_duration(&self) -> Duration {
        let secs = 10u64.saturating_mul(1u64 << self.attempts.min(5));
        Duration::from_secs(secs.min(300))
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_attempt = Instant::now() + self.backoff_duration();
    }

    fn reset(&mut self) {
        self.attempts = 0;
        self.next_attempt = Instant::now();
    }
}

/// Event sent from peer tasks to the central manager loop.
pub enum NetEvent {
    PeerConnected {
        id: PeerId,
        addr: SocketAddr,
        version: VersionMessage,
    },
    PeerDisconnected {
        id: PeerId,
    },
    MessageReceived {
        id: PeerId,
        msg: NetworkMessage,
    },
    /// The peer's queue has drained back under the send buffer while some
    /// of its `getdata` entries are still unserved: serve more of them. Sent
    /// by the peer's write loop; see [`crate::net::send_queue`].
    GetDataResume {
        id: PeerId,
    },
}

/// A block handed to the block processor: the peer it came from, that peer's
/// counters, the block, its in-flight guard, and whether this node asked for
/// it. Only a block the node asked for may wait for a parent it does not
/// know yet (see [`crate::net::orphan_blocks`]).
type IncomingBlock =
    (PeerId, Option<Arc<PeerStats>>, bitcoin::Block, crate::net::flow::InFlight, bool);

/// BIP 152: at most this many peers are asked to announce blocks to us as
/// `cmpctblock`s (high-bandwidth mode).
const MAX_HB_PEERS: usize = 3;

/// One block asked of one peer outside the IBD scheduler: when, and in which
/// form. See `PeerManager::in_flight_blocks`.
#[derive(Clone, Copy, Debug)]
struct BlockRequest {
    at: Instant,
    /// Asked as `MSG_CMPCT_BLOCK`. The answer is a `cmpctblock`, not a
    /// `block`, so a compact path that gives up on it must ask for the full
    /// block itself: nothing else is coming from this peer. A later full
    /// request for the same block replaces the record.
    compact: bool,
}

/// See `PeerManager::most_recent_block`.
struct RecentBlock {
    hash: bitcoin::BlockHash,
    height: u32,
    block: Arc<bitcoin::Block>,
    compact: Arc<bitcoin::bip152::HeaderAndShortIds>,
}

/// Handle for sending messages to a specific peer.
struct PeerHandle {
    info: PeerInfo,
    /// The peer's outbound queue. It counts the bytes queued, which Core's
    /// send-buffer limit is measured in; see [`crate::net::send_queue`].
    msg_tx: crate::net::send_queue::PeerSender,
    /// Last time we sent this peer a `getheaders`, for rate-limiting
    /// announcement-triggered header discovery (anti-DoS). `None` until the
    /// first send.
    last_getheaders_sent: Option<Instant>,
    /// Last time we served this peer a BIP35 `mempool` dump, for
    /// rate-limiting: each dump is a full mempool scan plus up to multi-MB
    /// of queued `inv` allocations, so even a *permissioned* peer must not
    /// be able to spam it in a tight loop. `None` until the first serve.
    last_mempool_served: Option<Instant>,
    /// The BIP 133 `feefilter` value last sent to this peer, sat/kvB. `None`
    /// until one is sent; some peers are never sent one.
    fee_filter_sent: Option<u64>,
    /// Signals the peer's write loop to end, shared with that task.
    ///
    /// Dropping this handle closes `msg_rx`, which the write loop already
    /// treats as "the manager dropped us" -- but only once the *last* sender
    /// is gone, and `handle_get_cfilters` clones one into a task that may hold
    /// it for up to 1000 awaited sends. Without an explicit signal a
    /// `disconnectnode` issued mid-`getcfilters` reports success while the
    /// socket stays open and the peer keeps feeding the node.
    disconnect: Arc<tokio::sync::Notify>,
    /// Per-peer wire counters (bytes + last activity), shared with the peer's
    /// I/O tasks. Read by `getpeerinfo`; rolls up into the global
    /// [`NetTotals`].
    stats: Arc<PeerStats>,
    /// How many of this peer's messages the node has taken in and not yet
    /// finished with. Core processes a connection's messages one at a time,
    /// so a pong answers for everything ahead of it; satd spreads the work
    /// across tasks, and this is what lets the pong wait for it. See
    /// [`crate::net::flow`].
    flow: Arc<crate::net::flow::PeerFlow>,
}

/// A message's type as Core names it in a log line. A type satd does not
/// know is the peer's own text, sanitized as Core's `SanitizeString(msg_type)`
/// does, so it cannot break a log line.
fn handshake_msg_type(msg: &NetworkMessage) -> String {
    match msg {
        NetworkMessage::Unknown { command, .. } => crate::net::limits::sanitize_string(command.as_ref()),
        m => m.cmd().to_string(),
    }
}

/// Core's `ProcessMessage` line, written as the message comes off the wire
/// so it lands in the order the peer sent. The payload size needs a
/// re-encode, so it is only paid for when the line will be written.
fn log_received(id: PeerId, msg: &NetworkMessage) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let cmd = handshake_msg_type(msg);
    let raw = bitcoin::p2p::message::RawNetworkMessage::new(bitcoin::p2p::Magic::REGTEST, msg.clone());
    let payload = bitcoin::consensus::serialize(&raw).len().saturating_sub(24);
    tracing::debug!("received: {cmd} ({payload} bytes) peer={id}");
}

#[cfg(test)]
#[path = "manager_p2pbounds_tests.rs"]
mod p2pbounds_tests;

/// How a transaction is announced to a peer: `MSG_WTX` carrying the wtxid
/// to a peer that negotiated BIP 339 wtxid relay, the txid to the rest.
fn tx_announcement(wtxid_relay: bool, txid: bitcoin::Txid, wtxid: bitcoin::Wtxid) -> Inventory {
    if wtxid_relay {
        Inventory::WTx(wtxid)
    } else {
        Inventory::WitnessTransaction(txid)
    }
}

/// Core's `CInv::ToString`: the inventory type's name and the hash.
fn inv_to_string(inv: &Inventory) -> String {
    match inv {
        Inventory::Transaction(txid) => format!("tx {txid}"),
        Inventory::WitnessTransaction(txid) => format!("witness-tx {txid}"),
        Inventory::WTx(wtxid) => format!("wtx {wtxid}"),
        Inventory::Block(hash) => format!("block {hash}"),
        Inventory::WitnessBlock(hash) => format!("witness-block {hash}"),
        Inventory::CompactBlock(hash) => format!("cmpctblock {hash}"),
        Inventory::Error => "error".to_string(),
        Inventory::Unknown { inv_type, hash } => format!("type={inv_type} {}", hex::encode(hash)),
    }
}

/// Core's `MAX_MONEY`, the `feefilter` a node in initial block download sends
/// before rounding.
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;

/// Core's `FeeFilterRounder::round`: the buckets are 0 and
/// `max(1, incremental / 2) * 1.1^n` up to 10,000,000 sat/kvB; `fee` goes to
/// the first bucket at or above it, stepped one bucket down two times in
/// three (or always, past the last bucket), so the filter a peer sees carries
/// less information about the mempool.
fn fee_filter_round(fee: u64, incremental_relay_fee: u64, random: u32) -> u64 {
    const MAX_FILTER_FEERATE: f64 = 10_000_000.0;
    const FEE_FILTER_SPACING: f64 = 1.1;
    let mut buckets = vec![0.0f64];
    let mut boundary = ((incremental_relay_fee / 2).max(1)) as f64;
    while boundary <= MAX_FILTER_FEERATE {
        buckets.push(boundary);
        boundary *= FEE_FILTER_SPACING;
    }
    let fee = fee as f64;
    let mut i = buckets.partition_point(|b| *b < fee);
    if i == buckets.len() || (i != 0 && !random.is_multiple_of(3)) {
        i -= 1;
    }
    buckets[i] as u64
}

/// How a peer task receives its transport.
///
/// Inbound connections are handed the raw socket and negotiate v1/v2 in
/// the spawned task (so the accept loop never blocks on a handshake).
/// Outbound connections establish their transport in the connect path —
/// where re-dialing for a v1 downgrade is possible — and hand over an
/// already-built [`Connection`].
enum IncomingTransport {
    Raw(TcpStream),
    Established(Box<Connection>),
}

/// How to (re-)dial an outbound peer, so a v2 handshake failure can fall
/// back to a fresh v1 connection to the same destination.
enum OutboundDial {
    Direct(SocketAddr),
    Onion(String, u16),
}

/// Holds a per-type outbound slot from the moment the capacity check passes
/// until the peer is registered (or the dial fails), so two concurrent callers
/// cannot both be granted the same free slot.
struct TypedDialGuard<'a> {
    set: &'a RwLock<Vec<ConnType>>,
    conn_type: ConnType,
}

impl Drop for TypedDialGuard<'_> {
    fn drop(&mut self) {
        let mut set = self.set.write();
        if let Some(i) = set.iter().position(|t| *t == self.conn_type) {
            set.swap_remove(i);
        }
    }
}

/// [`TypedDialGuard`] for a reservation that outlives the call that took it —
/// `add_connection` reserves the slot synchronously and releases it from the
/// spawned dial, so the guard cannot borrow the manager.
struct OwnedTypedDialGuard {
    pm: Arc<PeerManager>,
    conn_type: ConnType,
}

impl Drop for OwnedTypedDialGuard {
    fn drop(&mut self) {
        let mut set = self.pm.pending_typed_dials.write();
        if let Some(i) = set.iter().position(|t| *t == self.conn_type) {
            set.swap_remove(i);
        }
    }
}

/// See [`PeerManager::peer_summary`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerSummary {
    pub inbound: usize,
    pub outbound: usize,
    /// Connected peers per user agent (BIP 14 subversion), as the peer sent
    /// it. Unescaped: it is peer-controlled text.
    pub clients: std::collections::BTreeMap<String, usize>,
}

/// BIP 152 compact block counters, exported as `satd_net_compact_block_*`.
#[derive(Debug, Default)]
pub struct CompactBlockStats {
    /// Reconstructed from the `cmpctblock` alone.
    pub direct: AtomicU64,
    /// Reconstructed after a `getblocktxn` round trip.
    pub round_trip: AtomicU64,
    /// Abandoned for a full block: merkle mismatch or timeout.
    pub fallback: AtomicU64,
    /// Refused as malformed: a bad `cmpctblock` shape or a `blocktxn` that
    /// does not answer the request.
    pub invalid: AtomicU64,
    /// Transaction bytes received in `blocktxn` messages that completed a block.
    pub fetched_bytes: AtomicU64,
    pub txs_prefilled: AtomicU64,
    pub txs_mempool: AtomicU64,
    pub txs_extra: AtomicU64,
    pub txs_requested: AtomicU64,
    /// `cmpctblock` messages sent as announcements.
    pub sent_announce: AtomicU64,
    /// `cmpctblock` messages sent in answer to a `MSG_CMPCT_BLOCK` getdata.
    pub sent_getdata: AtomicU64,
}

impl CompactBlockStats {
    fn record(&self, stats: &compact::ReconstructStats, round_trip: bool) {
        let o = Ordering::Relaxed;
        if round_trip {
            self.round_trip.fetch_add(1, o);
        } else {
            self.direct.fetch_add(1, o);
        }
        self.fetched_bytes.fetch_add(stats.requested_bytes, o);
        self.txs_prefilled.fetch_add(stats.prefilled, o);
        self.txs_mempool.fetch_add(stats.mempool, o);
        self.txs_extra.fetch_add(stats.extra, o);
        self.txs_requested.fetch_add(stats.requested, o);
    }
}

/// Why a compact block reconstruction was given up, for its log line.
#[derive(Debug, Clone, Copy)]
enum CompactAbandon {
    /// The filled block failed its merkle check; the full block was requested.
    Merkle,
    /// No `blocktxn` came within [`compact::COMPACT_PENDING_TIMEOUT`].
    Timeout,
    /// The message was malformed.
    Invalid,
}

impl CompactAbandon {
    fn as_str(self) -> &'static str {
        match self {
            Self::Merkle => "merkle",
            Self::Timeout => "timeout",
            Self::Invalid => "invalid",
        }
    }
}

/// Manages all peer connections and routes messages.
pub struct PeerManager {
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
    next_id: AtomicU64,
    event_tx: mpsc::Sender<NetEvent>,
    event_rx: tokio::sync::Mutex<mpsc::Receiver<NetEvent>>,
    /// Track the highest header height we've stored.
    headers_tip: AtomicU64,
    /// Blocks we asked a peer for outside the IBD scheduler (a `getdata`
    /// sent while following the tip): peer → the hashes asked of it, when,
    /// and whether as a `cmpctblock`. Core's `mapBlocksInFlight`, as far as
    /// the compact block path needs it: "did we request this block from this
    /// peer?" decides whether an out-of-range `cmpctblock` still earns a full
    /// `getdata`, and whether a peer that is not high-bandwidth may send one
    /// at all; "is anything else in flight?" decides whether an announced
    /// block may be fetched compactly. Cleared when the block arrives, by
    /// either route, when the peer disconnects, and after
    /// [`BLOCK_IN_FLIGHT_TTL`].
    ///
    /// Keyed by peer first so the peer that fills it is the peer it is
    /// charged to: each map is capped at
    /// [`MAX_IN_FLIGHT_BLOCKS_PER_PEER`], which bounds the whole table by the
    /// connection limit no matter what peers announce.
    in_flight_blocks: RwLock<HashMap<PeerId, HashMap<bitcoin::BlockHash, BlockRequest>>>,
    /// Blocks on their way in as a `cmpctblock`: hash → when we asked for
    /// one or, for a pushed or answered `cmpctblock`, when reconstruction
    /// started. Dropped when the block arrives by any route, when its
    /// reconstruction is abandoned, and after
    /// [`COMPACT_RECONSTRUCT_SUPPRESSION`]. While an entry is here the
    /// tip-following sweep leaves the block alone rather than fetching it in
    /// full — Core's `mapBlocksInFlight`, which covers a block being
    /// reconstructed as much as one being downloaded. (An `inv` for it needs
    /// no such guard: its header is accepted before reconstruction starts,
    /// and `handle_inv` only fetches blocks it has no index entry for.)
    compact_in_progress: RwLock<HashMap<bitcoin::BlockHash, Instant>>,
    /// Blocks explicitly requested for repair (`getblockfrompeer`, and the
    /// connector's re-fetch of an unreadable stored block): (hash, a peer we
    /// asked) → when we asked. A block arriving from a peer we asked for it is
    /// routed to `ChainState::repair_block_data` instead of the normal accept
    /// path — the normal path rejects it as a duplicate, which is precisely
    /// the case a repair needs to handle.
    ///
    /// The peer is part of the key on purpose. Matching on hash alone would
    /// let any connected peer consume the operator's registration, so a
    /// hostile peer could both supply the copy and burn the request (the
    /// honest peer's later reply then falls through as an ordinary duplicate
    /// and is dropped) — silently defeating the operator's choice of who to
    /// trust for these bytes. Every peer asked is registered, not only the
    /// latest: the connector asks another peer each interval, and an earlier
    /// one's reply is as good as the latest's. Entries expire so an
    /// unanswered request cannot pin memory or divert a much later arrival.
    block_refetch: RwLock<HashMap<(bitcoin::BlockHash, PeerId), Instant>>,
    /// When the connector last asked a peer for each unreadable stored block
    /// ([`Self::refetch_unreadable_block`]). Separate from `block_refetch`,
    /// which drops a registration whose `getdata` could not be sent: an
    /// attempt counts toward the interval whether or not it reached a peer.
    unreadable_refetch_at: parking_lot::Mutex<HashMap<bitcoin::BlockHash, Instant>>,
    /// Addresses the node learned for itself: `addr`/`addrv2` gossip, the
    /// address book at startup, DNS seeds. The reconnect loop dials them only
    /// while `automatic_outbound` is on, as `outbound-full-relay`
    /// connections. Only addresses the address book would take get here
    /// (`AddrMan::admits`).
    ///
    /// Kept apart from `manual_addrs`. This list used to hold both, and
    /// `spawn_peer` called any peer on it `manual`, so every peer reached
    /// through gossip was reported, whitelisted and counted as one (#866).
    learned_addrs: RwLock<Vec<SocketAddr>>,
    /// Bitcoin Core's `m_use_addrman_outgoing`. False under `-connect`.
    automatic_outbound: std::sync::atomic::AtomicBool,
    /// The clearnet peers the operator named: `-connect`, `-addnode` /
    /// `addnode add` (the address a name resolved to), and `-seednode`. The
    /// reconnect loop dials them whatever `automatic_outbound` says, and a
    /// connection to one is `manual`. An `addnode onetry` is a manual
    /// connection too, but it is typed at its dial and never recorded here.
    manual_addrs: RwLock<HashSet<SocketAddr>>,
    /// The `.onion` hosts an operator named (`-connect` / `-addnode` /
    /// `-seednode`), as opposed to those learned from `addrv2` gossip. The
    /// clearnet equivalent is `manual_addrs`; onion peers need their own set
    /// because `connect_peer_addrs` holds both kinds and is keyed by host,
    /// not `SocketAddr`.
    manual_onion_hosts: RwLock<HashSet<String>>,
    /// Connection types whose dial has passed the capacity check but has not
    /// yet reached `spawn_peer`. Held for the duration of the dial and the
    /// transport handshake so the per-type limits are limits rather than
    /// suggestions; see `check_outbound_limit_for`.
    pending_typed_dials: RwLock<Vec<ConnType>>,
    /// The peers the operator named: every `-addnode` / `addnode add`
    /// entry, plus each `-connect` entry given as a host name. Keeps the
    /// string the operator typed (what `getaddednodeinfo` reports, matching
    /// Core's `m_added_node_params`) next to the address it currently
    /// resolves to, which is `None` while a name has not resolved yet.
    /// Names are looked up again by [`Self::refresh_manual_targets`].
    addnode_entries: RwLock<Vec<ManualTarget>>,
    /// Set while a [`Self::refresh_manual_targets`] pass is running, so a
    /// slow resolver cannot stack one pass per reconnect tick.
    refreshing_manual_targets: std::sync::atomic::AtomicBool,
    /// Test hook standing in for the system resolver in
    /// [`Self::resolve_target_classified`].
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    test_resolver: RwLock<
        Option<Arc<dyn Fn(&str) -> Result<PeerAddr, crate::net::dns::PeerTargetError> + Send + Sync>>,
    >,
    /// Operator-declared external addresses (Bitcoin Core's
    /// `-externalip`). Advertised in `getaddr` responses and used as the
    /// version message's `addr_from`. Set once at startup.
    external_addrs: RwLock<Vec<SocketAddr>>,
    /// Our own Tor v3 hidden-service address, when `-listenonion` created one.
    /// Advertised to addrv2-capable peers (proactively after handshake and in
    /// `getaddr` responses) so the network can discover and dial us inbound —
    /// without this the service exists but is reachable only by peers handed
    /// the address out of band. Set once at startup.
    advertised_onion: RwLock<Option<PeerAddr>>,
    /// `-whitelist` permission entries (by source subnet). Set once at
    /// startup; consulted on every peer connect to compute permissions.
    whitelist: RwLock<Vec<crate::net::permissions::WhitelistEntry>>,
    /// Persistent address manager (peers.dat): learned + tried peers,
    /// bucketed by network group. Fed by addr gossip and successful
    /// connects; persisted across restarts.
    addrman: RwLock<crate::net::addrman::AddrMan>,
    /// Wakes the manager loop's event drain before its next 500 ms tick.
    ///
    /// The drain cadence is deliberate everywhere else, but a peer whose
    /// pong is parked behind queued work would otherwise pay up to a full
    /// tick of it — and that lands in the round-trip time the *peer*
    /// measures. Notifying here collapses the wait to the actual processing
    /// time without speeding up the loop's periodic maintenance, which is
    /// still driven by the interval alone.
    drain_now: Arc<tokio::sync::Notify>,
    /// Channel to send received blocks to the processing thread.
    block_tx: mpsc::UnboundedSender<IncomingBlock>,
    /// Compact block reconstructions awaiting a `blocktxn`, at most one per
    /// peer. Bounded by the peer count, expired after
    /// [`compact::COMPACT_PENDING_TIMEOUT`], dropped when the peer disconnects
    /// or the block arrives by any route.
    pending_compact: RwLock<HashMap<PeerId, compact::PendingCompact>>,
    /// Recently seen transactions that are not in the mempool, for compact
    /// block reconstruction (Core's `vExtraTxnForCompact`). Shared with the
    /// mempool's replacement hook, which feeds it RBF-replaced transactions.
    extra_txns: Arc<parking_lot::Mutex<compact::ExtraTxnCache>>,
    /// Compact block relay counters, rendered by the metrics endpoint.
    compact_stats: CompactBlockStats,
    /// The peers we asked to announce blocks as `cmpctblock`s, least
    /// recently useful at the front. Core's `lNodesAnnouncingHeaderAndIDs`.
    hb_peers: parking_lot::Mutex<std::collections::VecDeque<PeerId>>,
    /// The newest block that extended our tip, with its `cmpctblock` form
    /// built once: every announcement and `MSG_CMPCT_BLOCK` answer for it
    /// uses the same nonce, and `getblocktxn` for it needs no disk read.
    /// Core's `m_most_recent_block` / `m_most_recent_compact_block`.
    most_recent_block: RwLock<Option<RecentBlock>>,
    /// `-cmpctblockprefill`: announce new blocks with the transactions this
    /// node lacked prefilled (Core #35558). Set once at startup.
    compact_prefill: std::sync::atomic::AtomicBool,
    /// `-cmpctblockprefillbytes`: the prefill's transaction-byte budget.
    compact_prefill_bytes: std::sync::atomic::AtomicUsize,
    /// The highest block announced before connecting it. Core's
    /// `m_highest_fast_announce`: a block at or below it is not announced
    /// early again.
    highest_fast_announce: std::sync::atomic::AtomicU32,
    /// Per-address reconnect backoff state.
    reconnect_backoff: RwLock<HashMap<SocketAddr, ReconnectState>>,
    /// Exponential backoff for `.onion` reconnect candidates, keyed by host
    /// string. `reconnect_backoff` is `SocketAddr`-keyed and can't hold onion
    /// peers, so without this a dead onion seed (or a failed gossip-discovered
    /// host) would be hot-dialed every 10s with no backoff.
    onion_reconnect_backoff: RwLock<HashMap<String, ReconnectState>>,
    /// Subnet-level ban list with wall-clock expiry times and JSON
    /// persistence. Replaces the old `HashMap<SocketAddr, Instant>`: bans
    /// are keyed by normalised subnet string, survive restarts, and respond
    /// to `setmocktime`.
    ban_list: RwLock<crate::net::ban::BanList>,
    /// Core's `DumpBanlist` `dump_mutex` (`src/banman.cpp`): serialises the
    /// whole snapshot-then-write, not just the snapshot.
    ///
    /// Without it two flushes race, and both outcomes lose data. `setban`
    /// runs on an RPC thread while the automatic-ban path runs on the manager
    /// event loop, so this is reachable, not theoretical:
    ///
    /// - **Lost update.** A slow flush snapshots `{A}`, is preempted, a fast
    ///   flush writes `{A, B}` and clears `dirty`, then the slow flush renames
    ///   `{A}` over it. `B` is gone from the file *and* `dirty` is false, so
    ///   nothing ever rewrites it — the exact silent-loss failure this whole
    ///   change exists to close.
    /// - **Torn file.** Both writes use one `banlist.json.tmp`; the second
    ///   `File::create` truncates the first's file while it still holds the
    ///   descriptor, so the bytes interleave and the renamed result is
    ///   invalid JSON.
    banlist_dump: parking_lot::Mutex<()>,
    /// Fee estimator fed from confirmed blocks (kept alive via Arc, used in block_processor).
    #[allow(dead_code)]
    fee_estimator: Arc<FeeEstimator>,
    /// Shutdown signal.
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// `-stopatheight`, and the sender on which reaching it asks for
    /// shutdown. See [`Self::stop_if_at_height`].
    stop_at_height: Option<(u32, tokio::sync::watch::Sender<bool>)>,
    /// Prune target in MB (0 = disabled).
    #[allow(dead_code)]
    prune_target_mb: u64,
    /// Maximum total connections (default: 125). Atomic so SIGHUP config
    /// reload can adjust it live (applies to new connections; existing peers
    /// above a lowered cap are not dropped).
    max_connections: AtomicUsize,
    /// Maximum simultaneous inbound peers from the same source IP
    /// (Core-style flood guard). Atomic for live SIGHUP reload.
    max_inbound_per_ip: AtomicUsize,
    /// Outbound `connect_outbound` calls that have started but haven't
    /// yet finished registering a peer. Used to dedup concurrent dial
    /// attempts against the same addr (e.g. an addr arriving from
    /// multiple peers' gossip).
    pending_connections: RwLock<HashSet<SocketAddr>>,
    /// In-flight `.onion` dials, keyed by Tor hostname. The clearnet
    /// `pending_connections` set can't dedupe onion dials because every
    /// onion peer shares the `0.0.0.0` placeholder socket; this is the
    /// onion equivalent, stopping the reconnect loop from opening a second
    /// connection to an onion peer it's already dialing/connected to.
    pending_onion_dials: RwLock<HashSet<String>>,
    /// Ban duration in seconds (default: 86400). Atomic for live SIGHUP
    /// reload (applies to bans created after the change).
    ban_duration_secs: AtomicU64,
    /// Per-message timeout for the version/verack handshake, in
    /// milliseconds (Bitcoin Core's `-timeout`, default 5000ms). A peer
    /// that doesn't make handshake progress within this window is
    /// dropped. Stored as an atomic so the satd binary can set it from
    /// config after construction (see [`set_connect_timeout_ms`]) without
    /// widening the already-large `with_config` argument list.
    connect_timeout_ms: AtomicU64,
    /// `-peertimeout`, seconds.
    peer_connect_timeout_secs: AtomicU64,
    /// Core's `-prune=1`: prune mode is on, but only `pruneblockchain`
    /// deletes. Separate from `prune_target_mb`, which is 0 in that mode.
    prune_manual: AtomicBool,
    /// Rebroadcast cadence for unbroadcast local txs, in seconds. `0` means
    /// "auto" — the spawner randomizes each interval in
    /// `[REBROADCAST_AUTO_MIN_SECS, REBROADCAST_AUTO_MAX_SECS]` (Core's
    /// 10–15 min). Set from config after construction (see
    /// [`set_rebroadcast_config`]). SIGHUP-reloadable; an interval change
    /// takes effect after the in-flight sleep completes.
    rebroadcast_interval_secs: AtomicU64,
    /// Distinct witnesses (peer IPs that fetched/echoed a local tx) before
    /// we consider it propagated and stop rebroadcasting. Clamped to ≥1 at
    /// use. SIGHUP-reloadable.
    broadcast_confirm_peers: AtomicU64,
    /// Bounded-drain queue of transactions promoted out of the quarantine class
    /// by a policy reload (§8). A mass promotion (worst case: a full-quarantine
    /// ruleset removed) can free tens of thousands of txs at once; announcing
    /// them all immediately would burst every peer. Instead they are enqueued
    /// here and the promotion-drain task ([`Self::drain_promotion_queue`]) INVs
    /// at most [`PROMOTION_DRAIN_PER_TICK`] per tick, so the burst spreads over
    /// minutes. In-memory only — anything lost to a restart is recovered by the
    /// startup re-placement pass (§9).
    promotion_queue: parking_lot::Mutex<std::collections::VecDeque<bitcoin::Txid>>,
    /// IBD scheduler for parallel block download (shared with connect thread).
    ibd: Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
    /// Signal to wake the connect thread when a block is stored.
    connect_signal: Arc<(parking_lot::Mutex<bool>, Condvar)>,
    /// AssumeUTXO background catch-up download tracker. Drives downloading
    /// historical block data (genesis→`snapshot_height`) for the
    /// background validator. Idle (empty) unless a snapshot is loaded.
    bg_downloader: RwLock<BgDownloader>,
    /// Wakes the background connect loop when a historical block is stored.
    bg_connect_signal: Arc<(parking_lot::Mutex<bool>, Condvar)>,
    /// The block processor and background catch-up threads, named. Both
    /// exit once shutdown is signalled; [`Self::join_connectors`] waits
    /// for them.
    connector_threads: parking_lot::Mutex<Vec<(&'static str, std::thread::JoinHandle<()>)>>,
    /// SOCKS5 proxy for all outbound connections (e.g. "127.0.0.1:9050").
    proxy: Option<String>,
    /// Separate SOCKS5 proxy for .onion connections (defaults to proxy).
    onion_proxy: Option<String>,
    /// Randomize SOCKS5 credentials per outbound dial so Tor isolates each
    /// peer onto its own circuit (Bitcoin Core's `-proxyrandomize`, default
    /// on). Set once at startup; only meaningful when a proxy is configured.
    proxy_randomize: std::sync::atomic::AtomicBool,
    /// `-dns`: whether name lookups are permitted at all. Default on.
    /// Read by `resolve_peer_target`, which is the only path that resolves
    /// an operator-supplied peer target.
    dns_enabled: std::sync::atomic::AtomicBool,
    /// Configured outbound .onion and hostname-based peer addresses for auto-reconnect.
    connect_peer_addrs: RwLock<Vec<PeerAddr>>,
    /// Max blocks downloaded ahead of connect cursor during IBD.
    max_ahead: u32,
    /// Latest ETA (seconds) from the weight-aware IBD estimator.
    /// Written by the connect loop, read by the RPC handler.
    ibd_eta_secs: Arc<AtomicU64>,
    /// Orphan transaction pool. Txs with missing parents (from P2P relay)
    /// are deferred here instead of triggering peer bans; reconsidered on
    /// new mempool admission and on block connect.
    orphanage: Arc<TxOrphanage>,
    /// BIP 158 filter index handle. Wired post-construction via
    /// `set_filter_index` (mirrors `ChainState::set_mempool` shape) so
    /// the existing constructor surface stays unchanged. The handler
    /// arms read it for `getcfilters` / `getcfheaders` / `getcfcheckpt`,
    /// and the version handshake ORs `COMPACT_FILTERS` into our
    /// services when both the runtime advertise flag and the index's
    /// `is_complete()` say yes.
    #[cfg(feature = "block-filter-index")]
    filter_index: std::sync::OnceLock<Arc<dyn node_filter_index::FilterIndex>>,
    /// Whether the operator opted into advertising and serving the BIP
    /// 157 P2P service (`--peerblockfilters=1`). Defaults to false; set
    /// alongside `set_filter_index` from the satd binary.
    #[cfg(feature = "block-filter-index")]
    peer_serve_filters: std::sync::atomic::AtomicBool,
    /// Bitcoin Core's `-blocksonly`: suppress transaction relay. When set,
    /// the node advertises `relay=false` in its version, ignores inbound
    /// `tx` messages from peers, and does not request advertised txs.
    /// Transactions submitted locally via RPC are still relayed. Defaults
    /// to false; set from the satd binary via `set_blocksonly`.
    blocksonly: std::sync::atomic::AtomicBool,
    /// Bitcoin Core's `-v2transport`: offer/accept the BIP 324 v2 encrypted
    /// transport. When set, inbound connections that do not begin with the
    /// network magic are treated as v2 and run through the v2 handshake;
    /// when unset, every connection is plaintext v1 (legacy behavior).
    /// Defaults to false here; the satd binary sets it from config via
    /// `set_v2transport` (default-on at that layer, matching Core).
    v2_transport: std::sync::atomic::AtomicBool,
    /// satd-specific `-v2only`: refuse peers that don't speak BIP 324 v2.
    /// Inbound v1 peers are dropped at detection; outbound v2 failures are
    /// not downgraded. Implies `v2_transport`. Defaults to false.
    v2_only: std::sync::atomic::AtomicBool,
    /// Outbound destinations whose v2 handshake failed this session, so we
    /// connect them straight as v1 instead of wasting a v2 round trip on
    /// every reconnect. Keyed by socket address (direct peers only).
    v2_downgraded: RwLock<HashSet<SocketAddr>>,
    /// Bitcoin Core's `-maxuploadtarget`: a soft cap, in bytes, on the
    /// volume of *historical* block data served in a rolling 24h window.
    /// 0 = unlimited. When the cap is exceeded, serving blocks older than
    /// a week is declined for peers without the `download`/`noban`
    /// permission; recent blocks and headers are always served.
    upload_target_bytes: AtomicU64,
    /// Bytes of block data served in the current 24h cycle.
    upload_bytes: AtomicU64,
    /// Unix-seconds start of the current 24h upload cycle.
    upload_cycle_start: AtomicU64,
    /// Process-global P2P byte totals (across all peers, past and present),
    /// feeding `getnettotals` and the Prometheus `satd_net_bytes_*` counters.
    /// Each peer's [`PeerStats`] holds a clone and rolls its activity up here.
    net_totals: Arc<NetTotals>,
    /// Bitcoin Core's `-networkactive` / `setnetworkactive`: when false, the
    /// node stops accepting inbound peers and stops initiating outbound dials
    /// (existing peers are disconnected when it is toggled off). Defaults to
    /// true. Read by the accept loop and the reconnect/dial paths.
    network_active: std::sync::atomic::AtomicBool,
}

impl PeerManager {
    pub fn new(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Arc<Self> {
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, 0, 125, DEFAULT_MAX_INBOUND_PER_IP, 86400, None, None, workers, 50_000, 0, None)
    }

    pub fn with_prune(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
        prune_target_mb: u64,
    ) -> Arc<Self> {
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, prune_target_mb, 125, DEFAULT_MAX_INBOUND_PER_IP, 86400, None, None, workers, 50_000, 0, None)
    }

    /// `stop_at_height` is `-stopatheight` and the sender on which reaching
    /// it asks for shutdown (see [`Self::stop_if_at_height`]). It is fixed
    /// here, before the connector threads start: on a restart with blocks
    /// already stored ahead of the tip, the IBD connector connects from the
    /// moment its thread does.
    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
        prune_target_mb: u64,
        max_connections: usize,
        max_inbound_per_ip: usize,
        ban_duration_secs: u64,
        proxy: Option<String>,
        onion_proxy: Option<String>,
        prefetch_workers: usize,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
        stop_at_height: Option<(u32, tokio::sync::watch::Sender<bool>)>,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        let connect_signal = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));
        let bg_connect_signal = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));
        // Both connect loops stop on shutdown, so that shutdown can join
        // them before it flushes (see `join_connectors`).
        let bg_shutdown = shutdown.clone();
        let connect_shutdown = shutdown.clone();

        // Check for IBD resume: if headers are ahead of tip, create scheduler
        let tip_height = chain_state.tip_height();
        let headers_tip_height = chain_state.headers_tip_height();
        let ibd_scheduler = if headers_tip_height > tip_height + 24 {
            let effective_max_ahead = Self::resolve_max_ahead(max_ahead, headers_tip_height, tip_height);
            let mut sched = IbdScheduler::new(headers_tip_height, tip_height, &chain_state, effective_max_ahead);
            // Scan for already-downloaded blocks (crash-resume)
            for h in (tip_height + 1)..=headers_tip_height {
                if let Some(hash) = chain_state.get_block_hash_by_height(h)
                    && chain_state.has_block_data(&hash)
                {
                    sched.mark_downloaded(h);
                }
            }
            let (dl, _inf, pend, _) = sched.progress();
            tracing::info!(
                target_height = headers_tip_height,
                already_downloaded = dl,
                pending = pend,
                "Resuming IBD with parallel scheduler"
            );
            Some(sched)
        } else {
            None
        };
        let ibd = Arc::new(parking_lot::RwLock::new(ibd_scheduler));

        let mgr = Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            next_id: AtomicU64::new(0),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            headers_tip: AtomicU64::new(headers_tip_height as u64),
            in_flight_blocks: RwLock::new(HashMap::new()),
            compact_in_progress: RwLock::new(HashMap::new()),
            block_refetch: RwLock::new(HashMap::new()),
            unreadable_refetch_at: parking_lot::Mutex::new(HashMap::new()),
            learned_addrs: RwLock::new(Vec::new()),
            automatic_outbound: std::sync::atomic::AtomicBool::new(true),
            dns_enabled: std::sync::atomic::AtomicBool::new(true),
            manual_addrs: RwLock::new(HashSet::new()),
            manual_onion_hosts: RwLock::new(HashSet::new()),
            pending_typed_dials: RwLock::new(Vec::new()),
            addnode_entries: RwLock::new(Vec::new()),
            refreshing_manual_targets: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_resolver: RwLock::new(None),
            external_addrs: RwLock::new(Vec::new()),
            advertised_onion: RwLock::new(None),
            whitelist: RwLock::new(Vec::new()),
            // Core's rule off regtest: routable addresses only. Regtest keeps
            // private ones, which lab networks run on.
            addrman: RwLock::new({
                let mut book = crate::net::addrman::AddrMan::new();
                book.set_admit_private(network == Network::Regtest);
                book
            }),
            drain_now: Arc::new(tokio::sync::Notify::new()),
            block_tx,
            pending_compact: RwLock::new(HashMap::new()),
            extra_txns: Arc::new(parking_lot::Mutex::new(compact::ExtraTxnCache::new(
                compact::DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN,
            ))),
            compact_stats: CompactBlockStats::default(),
            hb_peers: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            most_recent_block: RwLock::new(None),
            compact_prefill: std::sync::atomic::AtomicBool::new(false),
            compact_prefill_bytes: std::sync::atomic::AtomicUsize::new(compact::DEFAULT_CMPCTBLOCK_PREFILL_BYTES),
            highest_fast_announce: std::sync::atomic::AtomicU32::new(0),
            fee_estimator: fee_estimator.clone(),
            reconnect_backoff: RwLock::new(HashMap::new()),
            onion_reconnect_backoff: RwLock::new(HashMap::new()),
            ban_list: RwLock::new(crate::net::ban::BanList::default()),
            banlist_dump: parking_lot::Mutex::new(()),
            shutdown,
            stop_at_height,
            prune_target_mb,
            max_connections: AtomicUsize::new(max_connections),
            max_inbound_per_ip: AtomicUsize::new(max_inbound_per_ip),
            pending_connections: RwLock::new(HashSet::new()),
            pending_onion_dials: RwLock::new(HashSet::new()),
            ban_duration_secs: AtomicU64::new(ban_duration_secs),
            connect_timeout_ms: AtomicU64::new(DEFAULT_CONNECT_TIMEOUT_MS),
            peer_connect_timeout_secs: AtomicU64::new(DEFAULT_PEER_CONNECT_TIMEOUT_SECS as u64),
            prune_manual: AtomicBool::new(false),
            rebroadcast_interval_secs: AtomicU64::new(0),
            promotion_queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            broadcast_confirm_peers: AtomicU64::new(DEFAULT_BROADCAST_CONFIRM_PEERS),
            ibd: ibd.clone(),
            connect_signal: connect_signal.clone(),
            bg_downloader: RwLock::new(BgDownloader::new(
                BG_CATCHUP_WINDOW,
                Duration::from_secs(BG_CATCHUP_STALE_SECS),
            )),
            bg_connect_signal: bg_connect_signal.clone(),
            connector_threads: parking_lot::Mutex::new(Vec::new()),
            proxy,
            onion_proxy,
            proxy_randomize: std::sync::atomic::AtomicBool::new(true),
            connect_peer_addrs: RwLock::new(Vec::new()),
            max_ahead,
            ibd_eta_secs: Arc::new(AtomicU64::new(0)),
            orphanage: Arc::new(TxOrphanage::with_defaults()),
            #[cfg(feature = "block-filter-index")]
            filter_index: std::sync::OnceLock::new(),
            #[cfg(feature = "block-filter-index")]
            peer_serve_filters: std::sync::atomic::AtomicBool::new(false),
            blocksonly: std::sync::atomic::AtomicBool::new(false),
            v2_transport: std::sync::atomic::AtomicBool::new(false),
            v2_only: std::sync::atomic::AtomicBool::new(false),
            v2_downgraded: RwLock::new(HashSet::new()),
            upload_target_bytes: AtomicU64::new(0),
            upload_bytes: AtomicU64::new(0),
            upload_cycle_start: AtomicU64::new(now_unix_secs()),
            net_totals: NetTotals::new(),
            network_active: std::sync::atomic::AtomicBool::new(true),
        });

        // Transactions an RBF replacement pushes out of the mempool are the
        // ones most likely to turn up in a block mined by someone who never
        // saw the replacement; keep them for reconstruction.
        {
            let extra = mgr.extra_txns.clone();
            mgr.mempool.set_replaced_tx_sink(Box::new(move |replaced| {
                let mut cache = extra.lock();
                for tx in replaced {
                    cache.insert(tx);
                }
            }));
        }

        // Announce a block to high-bandwidth peers as soon as it has passed
        // everything short of connection, from whichever path it arrives on:
        // P2P, `submitblock`, or a miner on the Stratum server.
        {
            let pm = Arc::downgrade(&mgr);
            mgr.chain_state.set_pow_valid_block_hook(Box::new(move |block, height| {
                if let Some(pm) = pm.upgrade() {
                    pm.fast_announce(block, height);
                }
            }));
        }

        // Spawn block processing thread
        let cs = chain_state;
        let mp = mempool;
        let fe = fee_estimator;
        let prune_mb = prune_target_mb;
        let eta_secs = mgr.ibd_eta_secs.clone();
        let orph = mgr.orphanage.clone();
        let cs_for_block = cs.clone();
        let pm_for_block = Arc::downgrade(&mgr);
        let block_processor = std::thread::Builder::new()
            .name("block-processor".into())
            .spawn(move || {
                Self::block_processor(block_rx, cs_for_block, mp, fe, prune_mb, connect_signal, ibd, prefetch_workers, max_ahead, ibd_l0_pause_at, network, eta_secs, orph, pm_for_block, connect_shutdown);
            })
            .expect("failed to spawn the block processor thread");

        // Background AssumeUTXO catch-up connect loop. Long-lived: idles
        // (waiting on `bg_connect_signal`) until a snapshot is loaded and a
        // background chainstate is attached, then connects downloaded
        // historical blocks in order until handoff.
        let bg_catchup = std::thread::Builder::new()
            .name("bg-catchup".into())
            .spawn(move || {
                Self::bg_catchup_connect_loop(&cs, &bg_connect_signal, &bg_shutdown);
            })
            .expect("failed to spawn the background catch-up thread");
        *mgr.connector_threads.lock() =
            vec![("block-processor", block_processor), ("bg-catchup", bg_catchup)];

        mgr
    }

    /// `-stopatheight`: ask for shutdown if `height`, the height a connect
    /// has just taken the tip to, reaches the target. Returns whether it does.
    ///
    /// Core checks the target on every tip it connects
    /// (`KernelNotifications::blockTip`). Here a connect that emits
    /// `ChainEvent::BlockConnected` reaches the watcher in `main`; the IBD
    /// connector emits no event, so it calls this after each connect (#873).
    /// The stored-tail drain emits one (#900) and calls this too, because the
    /// watcher hears of it asynchronously. Asked for between one connect and
    /// the next, shutdown also stops a connector at the target rather than
    /// past it, because the connector checks for shutdown before it connects
    /// another block.
    fn stop_if_at_height(&self, height: u32) -> bool {
        let Some((target, shutdown)) = self.stop_at_height.as_ref() else {
            return false;
        };
        if height < *target {
            return false;
        }
        if shutdown.send_if_modified(|stop| !std::mem::replace(stop, true)) {
            tracing::info!(
                target = *target,
                tip = height,
                "-stopatheight reached; broadcasting shutdown"
            );
        }
        true
    }

    /// Wait up to `timeout` for the block connector threads to exit: the
    /// block processor, which also runs the IBD connect loop, and the
    /// background catch-up loop. They exit once shutdown has been signalled
    /// on the watch this manager was built with, each after finishing the
    /// block in hand; the caller signals it first.
    ///
    /// Shutdown waits for them before it flushes, so that no connect lands
    /// after the flush and the clean-shutdown marker names the tip the node
    /// stopped at (#868). Returns `false` if either is still running at
    /// `timeout`; it is kept, and a later call waits for it again.
    pub fn join_connectors(&self, timeout: Duration) -> bool {
        // Wake both loops out of their condvar waits rather than leaving
        // them to their timeouts.
        for signal in [&self.connect_signal, &self.bg_connect_signal] {
            let (lock, cvar) = &**signal;
            *lock.lock() = true;
            cvar.notify_all();
        }
        let mut threads = self.connector_threads.lock();
        let running = crate::shutdown::join_within(std::mem::take(&mut *threads), timeout);
        if running.is_empty() {
            return true;
        }
        let names: Vec<_> = running.iter().map(|(name, _)| *name).collect();
        tracing::warn!(threads = ?names, "block connector still running at its deadline");
        *threads = running;
        false
    }

    /// How long a connected peer may go without a useful message before it is
    /// dropped (Core's `-peertimeout`, seconds). Call once at startup. A value
    /// of 0 is clamped to 1s so a peer can never be held forever.
    pub fn set_peer_connect_timeout_secs(&self, secs: u64) {
        self.peer_connect_timeout_secs.store(secs.max(1), Ordering::Relaxed);
    }

    /// Whether `-prune=1` manual pruning is on. The node deletes nothing on
    /// its own in that mode, but it is still a pruned node to the network:
    /// it cannot promise `NODE_NETWORK` and must not be asked for a block
    /// below its floor.
    pub fn set_prune_manual(&self, manual: bool) {
        self.prune_manual.store(manual, Ordering::Relaxed);
    }

    /// Set the handshake timeout (Bitcoin Core's `-timeout`), in
    /// milliseconds. Call once at startup before peers connect. A value
    /// of 0 is clamped to 1ms so the handshake can never block forever.
    pub fn set_connect_timeout_ms(&self, ms: u64) {
        self.connect_timeout_ms.store(ms.max(1), Ordering::Relaxed);
    }

    /// Resolve a max_ahead config value to an effective count.
    /// Values > 1_000_000_000 encode a percentage: 1_000_000_000 + pct.
    fn resolve_max_ahead(max_ahead: u32, target_height: u32, tip_height: u32) -> u32 {
        if max_ahead > 1_000_000_000 {
            let pct = max_ahead - 1_000_000_000;
            let remaining = target_height.saturating_sub(tip_height);
            (remaining as u64 * pct as u64 / 100) as u32
        } else {
            max_ahead
        }
    }

    /// Expose the orphanage so the RPC layer can report diagnostics.
    pub fn orphanage(&self) -> Arc<TxOrphanage> {
        self.orphanage.clone()
    }

    /// Wire the BIP 158 filter index handle. Called once at startup
    /// after both `PeerManager` and `RocksFilterIndex` are constructed.
    /// Idempotent on duplicate calls (later sets are silently ignored).
    /// `peer_serve` is the operator-side advertisement flag
    /// (`--peerblockfilters=1`).
    #[cfg(feature = "block-filter-index")]
    pub fn set_filter_index(
        &self,
        index: Arc<dyn node_filter_index::FilterIndex>,
        peer_serve: bool,
    ) {
        let _ = self.filter_index.set(index);
        self.peer_serve_filters
            .store(peer_serve, std::sync::atomic::Ordering::Relaxed);
    }

    /// Toggle the BIP 157 `NODE_COMPACT_FILTERS` advertisement
    /// (`--peerblockfilters`) at runtime, independent of the (write-once)
    /// filter-index wiring. `peer_serve_filters_ready()` is re-evaluated per
    /// outgoing handshake, so a SIGHUP reload that flips `peerblockfilters`
    /// takes effect for new connections without a restart. No-op when the
    /// `block-filter-index` feature is compiled out (the flag has no backing
    /// field, and the service can't be served anyway).
    pub fn set_peer_serve_filters(&self, enabled: bool) {
        #[cfg(feature = "block-filter-index")]
        self.peer_serve_filters
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(feature = "block-filter-index"))]
        let _ = enabled;
    }

    /// Enable/disable `-blocksonly` transaction-relay suppression. Set
    /// once from the satd binary after construction.
    pub fn set_blocksonly(&self, enabled: bool) {
        self.blocksonly
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether transaction relay is suppressed (`-blocksonly`).
    pub fn blocksonly(&self) -> bool {
        self.blocksonly.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Enable/disable all P2P networking (`-networkactive` /
    /// `setnetworkactive`). Disabling stops new inbound accepts and outbound
    /// dials *and* disconnects every current peer via [`Self::drop_all_peers`]
    /// — each write loop is signalled and the handles dropped, tearing the
    /// sockets down even where another task still holds a sender clone.
    /// Re-enabling lets the reconnect loop redial. A no-op if already in the
    /// target state.
    pub fn set_network_active(&self, active: bool) {
        if active {
            let was = self
                .network_active
                .swap(true, std::sync::atomic::Ordering::Relaxed);
            if !was {
                // Core logs "SetNetworkActive: true" — test harness
                // `assert_debug_log` checks this exact string.
                tracing::info!("SetNetworkActive: true");
            }
        } else {
            // Flip the flag AND clear peers under the same `peers` write lock
            // that peer registration ([`register_peer`]) checks the flag under.
            // This makes "pause" atomic with respect to "register a new peer":
            // a dial that wins the lock first registers and is then cleared
            // here; one that loses sees the flag false and refuses to register.
            // Without this coupling, a dial finishing its handshake could insert
            // a live peer in the window after `clear()`, leaving a connection up
            // while networking is meant to be off.
            let mut peers = self.peers.write();
            let was = self
                .network_active
                .swap(false, std::sync::atomic::Ordering::Relaxed);
            if was {
                let n = peers.len();
                Self::drop_all_peers(&mut peers);
                // Core logs "SetNetworkActive: false\n" — test harness
                // `assert_debug_log` checks this exact substring including
                // the trailing newline, so no structured fields may follow
                // the message text on this line.
                tracing::info!("SetNetworkActive: false");
                tracing::debug!(disconnected = n, "paused P2P networking");
            }
        }
    }

    /// Whether P2P networking is active (`-networkactive`, default true).
    pub fn is_network_active(&self) -> bool {
        self.network_active
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Enable/disable BIP 324 v2 transport (`-v2transport`). Set from the
    /// satd binary at startup.
    pub fn set_v2transport(&self, enabled: bool) {
        self.v2_transport
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the BIP 324 v2 transport is enabled (`-v2transport`).
    pub fn v2_transport_enabled(&self) -> bool {
        self.v2_transport.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Enable/disable v2-only peering (`-v2only`). Set from the satd binary
    /// at startup; implies v2 transport is enabled.
    pub fn set_v2only(&self, enabled: bool) {
        self.v2_only
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether non-v2 peers are refused (`-v2only`).
    fn v2_only(&self) -> bool {
        self.v2_only.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Declare operator-supplied external addresses (`-externalip`). Set
    /// once from the satd binary after construction.
    pub fn set_external_addrs(&self, addrs: Vec<SocketAddr>) {
        *self.external_addrs.write() = addrs;
    }

    /// Register our own `-listenonion` v3 hidden-service address so it is
    /// advertised to peers. Validates that `host` is a well-formed v3 onion
    /// (the pubkey must be recoverable for the addrv2 encoding); a malformed
    /// address is logged and ignored rather than advertised as garbage.
    pub fn set_advertised_onion(&self, host: String, port: u16) {
        if crate::net::peer::onion_host_to_torv3_pubkey(&host).is_none() {
            tracing::warn!(onion = %host, "Not advertising malformed onion address");
            return;
        }
        tracing::info!(onion = %host, port, "Advertising hidden service to peers");
        *self.advertised_onion.write() = Some(PeerAddr::Onion { host, port });
    }

    /// Addresses this node advertises as its own, for `getnetworkinfo`'s
    /// `localaddresses`: operator `-externalip` entries plus our hidden
    /// service. `score` mirrors Bitcoin Core's notion of confidence; onion
    /// (operator-intent, manually configured) ranks above bare externals.
    pub fn local_addresses(&self) -> Vec<(String, u16, u32)> {
        let mut out: Vec<(String, u16, u32)> = self
            .external_addrs
            .read()
            .iter()
            .map(|a| (a.ip().to_string(), a.port(), 1))
            .collect();
        if let Some(PeerAddr::Onion { host, port }) = self.advertised_onion.read().as_ref() {
            out.push((host.clone(), *port, 4));
        }
        out
    }

    /// Whether onion peers are reachable, i.e. an onion-routing proxy is
    /// configured (`-proxy`/`-onion`). Drives `getnetworkinfo`'s onion
    /// `reachable` flag.
    pub fn onion_routing_available(&self) -> bool {
        self.proxy.is_some() || self.onion_proxy.is_some()
    }

    /// Enable/disable per-dial SOCKS credential randomization (`-proxyrandomize`).
    /// Set once at startup from config.
    pub fn set_proxy_randomize(&self, on: bool) {
        self.proxy_randomize.store(on, Ordering::Relaxed);
    }

    /// Whether per-dial SOCKS credential randomization is on. Drives
    /// `getnetworkinfo`'s `proxy_randomize_credentials`.
    pub fn proxy_randomize(&self) -> bool {
        self.proxy_randomize.load(Ordering::Relaxed)
    }

    /// `-dns`. Set once at startup (`-dns` is restart-required); the
    /// atomic keeps `PeerManager`'s constructor signature untouched.
    pub fn set_dns_enabled(&self, on: bool) {
        self.dns_enabled.store(on, Ordering::Relaxed);
    }

    /// Whether `-dns` permits name lookups.
    pub fn dns_enabled(&self) -> bool {
        self.dns_enabled.load(Ordering::Relaxed)
    }

    /// Resolve an operator-supplied peer target under this node's `-proxy`
    /// and `-dns` settings. See [`crate::net::dns::resolve_peer_target`].
    pub async fn resolve_peer_target(
        &self,
        s: &str,
        default_port: u16,
    ) -> Result<PeerAddr, String> {
        crate::net::dns::resolve_peer_target(
            s,
            default_port,
            self.proxy.as_deref(),
            self.dns_enabled(),
        )
        .await
    }

    /// [`Self::resolve_peer_target`], keeping a refusal apart from a failed
    /// lookup. See [`crate::net::dns::PeerTargetError`].
    pub async fn resolve_target_classified(
        &self,
        s: &str,
        default_port: u16,
    ) -> Result<PeerAddr, crate::net::dns::PeerTargetError> {
        #[cfg(test)]
        {
            let hook = self.test_resolver.read().clone();
            if let Some(hook) = hook {
                return hook(s);
            }
        }
        crate::net::dns::resolve_peer_target_classified(
            s,
            default_port,
            self.proxy.as_deref(),
            self.dns_enabled(),
        )
        .await
    }

    /// [`Self::resolve_target_classified`] short of the lookup: see
    /// [`crate::net::dns::classify_peer_target`].
    pub fn classify_target(
        &self,
        s: &str,
        default_port: u16,
    ) -> Result<Option<PeerAddr>, crate::net::dns::PeerTargetError> {
        crate::net::dns::classify_peer_target(s, default_port, self.proxy.as_deref(), self.dns_enabled())
    }

    /// The SOCKS proxy used for clearnet (ipv4/ipv6) outbound, if any.
    pub fn proxy_addr(&self) -> Option<String> {
        self.proxy.clone()
    }

    /// The SOCKS proxy used for `.onion` outbound (the dedicated onion proxy,
    /// else the general proxy), if any.
    pub fn onion_proxy_addr(&self) -> Option<String> {
        self.onion_proxy.clone().or_else(|| self.proxy.clone())
    }

    /// Whether this node is in prune mode — Core's `fPruneMode`, true for
    /// both `-prune=<MiB>` and `-prune=1`. A manual pruner has deleted
    /// nothing yet but is still a node that will, so it answers the same.
    pub fn is_pruning(&self) -> bool {
        self.prune_target_mb > 0 || self.prune_manual.load(Ordering::Relaxed)
    }

    /// A fresh random SOCKS5 credential pair for one outbound dial, or `None`
    /// when randomization is off. Tor uses the username/password as its
    /// stream-isolation key (`IsolateSOCKSAuth`), so a unique pair per dial
    /// forces a separate circuit per peer. Username and password are set to the
    /// same random token, matching Bitcoin Core.
    fn socks_cred(&self) -> Option<(String, String)> {
        if !self.proxy_randomize.load(Ordering::Relaxed) {
            return None;
        }
        let token = format!("{:016x}", rand::random::<u64>());
        Some((token.clone(), token))
    }

    /// Build the `AddrV2` self-advertisement (our hidden service as a BIP 155
    /// `TorV3` entry) for peer `id`, or `None` if we have no onion to advertise
    /// or the peer didn't opt into addrv2. The pubkey is recovered from the
    /// stored host; it was validated when the onion was registered, so this is
    /// infallible in practice.
    fn self_advertise_addrv2(&self, id: PeerId) -> Option<bitcoin::p2p::address::AddrV2Message> {
        if !self.peers.read().get(&id).is_some_and(|h| h.info.wants_addrv2) {
            return None;
        }
        let onion = self.advertised_onion.read().clone()?;
        let PeerAddr::Onion { host, port } = onion else {
            return None;
        };
        let pubkey = crate::net::peer::onion_host_to_torv3_pubkey(&host)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        Some(bitcoin::p2p::address::AddrV2Message {
            time: now,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: bitcoin::p2p::address::AddrV2::TorV3(pubkey),
            port,
        })
    }

    /// Install `-whitelist` permission entries. Set once at startup.
    pub fn set_whitelist(&self, entries: Vec<crate::net::permissions::WhitelistEntry>) {
        *self.whitelist.write() = entries;
    }

    /// Compute the net permissions an inbound/outbound peer at `ip` earns
    /// from the `-whitelist` subnets.
    fn whitelist_permissions(&self, ip: IpAddr) -> crate::net::permissions::NetPermissions {
        crate::net::permissions::permissions_for_ip(&self.whitelist.read(), ip)
    }

    /// `-whitelist` permissions for a peer reached in a given direction.
    /// See [`crate::net::permissions::permissions_for`] for Core's rule.
    fn whitelist_permissions_for(
        &self,
        ip: IpAddr,
        direction: crate::net::permissions::Direction,
    ) -> crate::net::permissions::NetPermissions {
        crate::net::permissions::permissions_for(&self.whitelist.read(), ip, direction)
    }

    /// Permissions currently held by peer `id` (empty if unknown).
    fn peer_permissions(&self, id: PeerId) -> crate::net::permissions::NetPermissions {
        self.peers
            .read()
            .get(&id)
            .map(|h| h.info.permissions)
            .unwrap_or(crate::net::permissions::NetPermissions::NONE)
    }

    /// Set the `-maxuploadtarget` cap in bytes (0 = unlimited).
    pub fn set_max_upload_target(&self, bytes: u64) {
        self.upload_target_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Set the `-maxconnections` cap. Applies to connections accepted/dialed
    /// after the change; peers already connected above a lowered cap are not
    /// disconnected. Used at startup and by SIGHUP config reload.
    pub fn set_max_connections(&self, n: usize) {
        self.max_connections.store(n, Ordering::Relaxed);
    }

    /// Set the `-maxinboundperip` flood-guard limit. Applies to new inbound
    /// connections. Used at startup and by SIGHUP config reload.
    pub fn set_max_inbound_per_ip(&self, n: usize) {
        self.max_inbound_per_ip.store(n, Ordering::Relaxed);
    }

    /// Set the `-bantime` duration in seconds. Applies to bans created after
    /// the change; already-active bans keep their original expiry. Used at
    /// startup and by SIGHUP config reload.
    pub fn set_ban_duration_secs(&self, secs: u64) {
        self.ban_duration_secs.store(secs, Ordering::Relaxed);
    }

    /// Current default ban duration in seconds (the `-bantime` setting).
    pub fn default_ban_duration_secs(&self) -> u64 {
        self.ban_duration_secs.load(Ordering::Relaxed)
    }

    /// Roll the 24h upload cycle over if it has elapsed.
    fn maybe_reset_upload_cycle(&self, now: u64) {
        let start = self.upload_cycle_start.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= 24 * 60 * 60 {
            self.upload_cycle_start.store(now, Ordering::Relaxed);
            self.upload_bytes.store(0, Ordering::Relaxed);
        }
    }

    /// Decide whether to serve `block` to peer `id` under the
    /// `-maxuploadtarget` budget. Recent blocks (< 1 week old) and peers
    /// with `download`/`noban` are always served; otherwise a historical
    /// block is declined once the cycle budget is spent.
    fn upload_permits_block(&self, id: PeerId, block: &bitcoin::Block) -> bool {
        let target = self.upload_target_bytes.load(Ordering::Relaxed);
        if target == 0 {
            return true; // unlimited
        }
        const ONE_WEEK: u64 = 7 * 24 * 60 * 60;
        let now = now_unix_secs();
        let historical = (block.header.time as u64).saturating_add(ONE_WEEK) < now;
        if !historical {
            return true;
        }
        let perms = self.peer_permissions(id);
        if perms.download || perms.noban {
            return true;
        }
        self.maybe_reset_upload_cycle(now);
        self.upload_bytes.load(Ordering::Relaxed) < target
    }

    /// Account `bytes` of served block data toward the upload budget.
    fn record_upload(&self, bytes: u64) {
        if self.upload_target_bytes.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.maybe_reset_upload_cycle(now_unix_secs());
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Predicate consulted by `handle_message` and the version
    /// handshake: serve filters only when the operator opted in
    /// (`--peerblockfilters=1`) AND the index is complete. Backfill
    /// in flight → false (prevents advertising a service we cannot
    /// faithfully provide).
    #[cfg(feature = "block-filter-index")]
    fn peer_serve_filters_ready(&self) -> bool {
        if !self
            .peer_serve_filters
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        match self.filter_index.get() {
            Some(idx) => idx.is_complete(),
            None => false,
        }
    }

    /// Record a gossiped address as a dial candidate, with the default
    /// service bits and as its own source.
    ///
    /// Deduped: addr/addrv2 gossip from multiple peers frequently announces
    /// the same socket address many times. Without dedup, the reconnect
    /// loop spawns one `connect_outbound` task per duplicate, and a remote
    /// peer's per-IP rate limit will FIN all but the first within a few
    /// hundred ms — surfacing as severe peer churn.
    pub fn add_learned_addr(&self, addr: SocketAddr) {
        self.add_learned_addr_from(
            addr,
            crate::net::addrman::DEFAULT_SERVICES,
            addr.ip(),
        );
    }

    /// [`add_learned_addr`](Self::add_learned_addr) for a gossiped address,
    /// recording the service bits it was announced with and the peer that
    /// announced it (Core's `nServices` and `source`, which `getnodeaddresses`
    /// and `getrawaddrman` report).
    pub fn add_learned_addr_from(&self, addr: SocketAddr, services: u64, source: IpAddr) {
        // Record in the persistent address book (peers.dat) as a *new*
        // address. This is the chokepoint for gossiped addresses, and the
        // book's rule decides what the node learns at all. An address it
        // refuses goes on the dial list no more than in the book: one that
        // names no host, like the `0.0.0.0` a peer relayed in #866, which on
        // Linux dials the local host, or, off regtest, one that is not
        // publicly routable. Core refuses both in `AddrManImpl::AddSingle`
        // (v31.1 `src/addrman.cpp:554`) and dials only from its book.
        {
            let mut book = self.addrman.write();
            if !book.admits(&addr) {
                tracing::debug!(%addr, "Ignoring a gossiped address the address book does not take");
                return;
            }
            book.add_from(addr, now_unix_secs(), services, source);
        }
        self.push_learned(addr);
    }

    /// Record a peer from a DNS seed or the compiled-in fixed seeds as a
    /// dial candidate. These are the node's own bootstrap sources, not peers
    /// the operator named: Core adds them to its address book and dials them
    /// as automatic connections, so they join the learned candidates rather
    /// than `manual_addrs`, under the same rule as gossip. An onion seed
    /// joins the onion candidates.
    pub fn add_learned_peer_addr(&self, addr: &PeerAddr) {
        match addr {
            PeerAddr::Socket(sa) => {
                if self.addrman.read().admits(sa) {
                    self.push_learned(*sa);
                }
            }
            PeerAddr::Onion { host, port } => self.add_onion_connect_addr(host.clone(), *port),
        }
    }

    /// Put an address the node learned on the reconnect loop's automatic
    /// dial list.
    fn push_learned(&self, addr: SocketAddr) {
        // Under `-connect` the node dials only the peers it was told to.
        // Core keeps learning addresses in that mode (they go to the addrman
        // above) but sets `m_use_addrman_outgoing = false`, so it never opens
        // a connection from them. Pushing them onto the dial list here would
        // quietly reconnect the node to the network the operator disconnected
        // it from.
        if !self.automatic_outbound.load(Ordering::Relaxed) {
            return;
        }
        let mut addrs = self.learned_addrs.write();
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    /// Bitcoin Core's `m_use_addrman_outgoing`: whether the node may dial
    /// peers it learned itself, as opposed to only those it was given.
    /// `-connect` (with or without addresses) turns this off.
    pub fn set_automatic_outbound(&self, enabled: bool) {
        self.automatic_outbound.store(enabled, Ordering::Relaxed);
    }

    /// Whether the reconnect loop may dial `addr`.
    ///
    /// The `push_learned` gate alone is not enough. `peers.dat` is loaded
    /// straight into `learned_addrs` at startup, long before `-connect` has
    /// been applied to the manager, so a node restarted with `-connect=0` and
    /// an existing address book still dialled everything it had learned --
    /// exactly the reconnect-to-the-network-you-disconnected-from this mode
    /// exists to prevent. Gating the dial rather than the bookkeeping is also
    /// order-independent: it holds however an address arrived.
    ///
    /// Explicit operator lists are unaffected: `-connect=<addr>`, `-addnode`
    /// and `-seednode` all register in `manual_addrs`, and Core dials those
    /// under `-connect` too.
    fn may_dial(&self, addr: &SocketAddr) -> bool {
        self.automatic_outbound.load(Ordering::Relaxed)
            || self.manual_addrs.read().contains(addr)
    }

    /// Record a `.onion` peer learned from `addrv2` gossip so the reconnect
    /// loop can dial it. The addrman is `SocketAddr`-keyed and can't hold
    /// onion peers, so they live in `connect_peer_addrs` (in-memory, bounded
    /// by `MAX_ONION_CONNECT_ADDRS`). Deduped against both the current
    /// connection and the existing candidate list. This is what lets a
    /// proxy-only node grow its peer set past the hardcoded onion seeds.
    fn add_onion_connect_addr(&self, host: String, port: u16) {
        // Under `-connect` the node dials only the peers it was told to; see
        // `may_dial`. Onion candidates are in-memory only, so refusing them
        // here is enough to keep them off the dial list.
        if !self.automatic_outbound.load(Ordering::Relaxed) {
            return;
        }
        if self.is_onion_connected(&host) {
            return;
        }
        let mut addrs = self.connect_peer_addrs.write();
        let already = addrs
            .iter()
            .any(|a| matches!(a, PeerAddr::Onion { host: h, .. } if *h == host));
        if already || addrs.len() >= MAX_ONION_CONNECT_ADDRS {
            return;
        }
        tracing::debug!(onion = %host, port, "Discovered onion peer via addrv2");
        addrs.push(PeerAddr::Onion { host, port });
    }

    /// Load the persistent address book from `path` (peers.dat), then
    /// seed the in-memory dial pool with up to `seed` of its addresses so
    /// learned peers survive a restart. No-op if the file is absent.
    pub fn load_addrman(&self, path: &std::path::Path, seed: usize) {
        let mut am = self.addrman.write();
        if let Err(e) = am.load(path) {
            tracing::warn!(path = %path.display(), "addrman load failed: {e}");
            return;
        }
        let picks = am.select_n(seed);
        drop(am);
        // Straight onto the list, not through `push_learned`: `-connect` has
        // not been applied yet, and `may_dial` holds these back under it.
        let mut addrs = self.learned_addrs.write();
        for a in picks {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
        tracing::info!(loaded = self.addrman.read().len(), "Loaded persistent address book");
    }

    /// Persist the address book to `path` (peers.dat).
    pub fn dump_addrman(&self, path: &std::path::Path) {
        if let Err(e) = self.addrman.read().dump(path) {
            tracing::warn!(path = %path.display(), "addrman dump failed: {e}");
        }
    }

    /// Whether the address book is empty (used to gate DNS seeding /
    /// fixed-seed fallback).
    pub fn addrman_is_empty(&self) -> bool {
        self.addrman.read().is_empty()
    }

    /// A copy of every address-book entry, for `getnodeaddresses`.
    pub fn addrman_snapshot(&self) -> Vec<crate::net::addrman::AddrEntry> {
        self.addrman.read().iter().cloned().collect()
    }

    /// Every address-book entry with its derived `bucket/position` slot, for
    /// `getrawaddrman`.
    pub fn addrman_positions(
        &self,
    ) -> Vec<(crate::net::addrman::AddrSlot, crate::net::addrman::AddrEntry)> {
        self.addrman
            .read()
            .positions()
            .into_iter()
            .map(|(slot, e)| (slot, e.clone()))
            .collect()
    }

    /// New/tried counts per network, for `getaddrmaninfo`.
    pub fn addrman_counts(
        &self,
    ) -> std::collections::BTreeMap<&'static str, crate::net::addrman::TableCounts> {
        self.addrman.read().counts_by_network()
    }

    /// Core's `addpeeraddress`: add an address to the book by hand. Errors
    /// are Core's strings (`failed-adding-to-new` / `failed-adding-to-tried`).
    ///
    /// The address only enters the book. It does not join the dial list, as
    /// in Core, where the RPC touches addrman and nothing else.
    pub fn addrman_add_manual(&self, addr: SocketAddr, tried: bool) -> Result<(), &'static str> {
        self.addrman
            .write()
            .add_manual(addr, tried, crate::time::now_secs())
    }

    /// The IP of peer `id`, as the `source` of the addresses it announces.
    /// `None` for an unknown peer and for an onion peer, whose socket is the
    /// unspecified placeholder: the address is then its own source, as for
    /// any address whose announcer the book cannot represent.
    fn peer_ip(&self, id: PeerId) -> Option<IpAddr> {
        let peers = self.peers.read();
        let ip = peers.get(&id)?.info.addr.ip();
        (!ip.is_unspecified()).then_some(ip)
    }

    /// Install a custom addrman network-group function (e.g. `-asmap`).
    pub fn set_addrman_group_fn(
        &self,
        f: Box<dyn Fn(IpAddr) -> Vec<u8> + Send + Sync>,
    ) {
        self.addrman.write().set_group_fn(f);
    }

    /// Register a peer the operator named (`-connect`, `-addnode`,
    /// `-seednode`) for auto-reconnect: the reconnect loop dials it even
    /// under `-connect`, and a connection to it is `manual`. Returns `true`
    /// if the address was newly registered, `false` if it already was.
    ///
    /// The address may also be one the node learned (`peers.dat` seeds
    /// `learned_addrs` at startup, long before `-connect` reaches the
    /// manager, and gossip adds to it continuously). That does not matter:
    /// the two lists are separate, and registering here is what makes it
    /// manual. When the two were one list, an already-present address was
    /// once left unmarked, so under `-connect` one failed dial stranded the
    /// node with no peers at all.
    pub fn add_peer_addr(&self, addr: PeerAddr) -> bool {
        match &addr {
            PeerAddr::Socket(sa) => self.manual_addrs.write().insert(*sa),
            PeerAddr::Onion { host, .. } => {
                self.manual_onion_hosts.write().insert(host.clone());
                let mut addrs = self.connect_peer_addrs.write();
                if addrs.contains(&addr) {
                    return false;
                }
                addrs.push(addr);
                true
            }
        }
    }

    /// Register an added node (`-addnode` or `addnode add`) that resolved to
    /// `addr`, tracking the operator's string for `getaddednodeinfo`.
    /// Returns `false`, changing nothing, if it is already an added node.
    pub fn addnode_add(&self, user_str: &str, addr: PeerAddr) -> bool {
        self.add_manual_target(user_str, Some(addr), true)
    }

    /// Register an added node whose name did not resolve. It is listed by
    /// `getaddednodeinfo` at once, as in Core, and dialled once
    /// [`Self::refresh_manual_targets`] resolves it. Returns `false` if it
    /// is already an added node.
    pub fn addnode_add_unresolved(&self, user_str: &str) -> bool {
        self.add_manual_target(user_str, None, true)
    }

    /// Register `-addnode` entries: all of them at startup, and those a
    /// config reload adds (#879). Called at startup before RPC serves, so
    /// `getaddednodeinfo` lists every entry from its first answer:
    /// registered only once its name had been looked up, an entry was
    /// missing from any answer given in the meantime (#876). Core sets its
    /// added-node list from `-addnode` during init, and RPC answers nothing
    /// but "warming up" until init is done.
    ///
    /// Nothing is looked up here. A literal or `.onion` target is added
    /// with its address, and a name unresolved, for
    /// [`Self::refresh_manual_targets`] to look up once the node is up. A
    /// target that can never resolve here (malformed, `-dns=0`, `-proxy`)
    /// is refused. Returns the addresses to dial.
    pub fn register_config_addnodes(&self, targets: &[String]) -> Vec<PeerAddr> {
        let default_port = default_p2p_port(self.chain_state.network);
        let mut dial = Vec::new();
        for target in targets {
            match self.classify_target(target, default_port) {
                Ok(Some(addr)) => {
                    if self.addnode_add(target, addr.clone()) {
                        dial.push(addr);
                    }
                }
                Ok(None) => {
                    self.addnode_add_unresolved(target);
                }
                Err(e) => {
                    tracing::warn!(addr = %target, "Invalid addnode address: {}", e);
                }
            }
        }
        dial
    }

    /// Register a `-connect` target, at startup or when a config reload adds
    /// it (#879), and return the address to dial if it has one yet. A name
    /// is looked up now and tracked, so that it is looked up again
    /// ([`Self::connect_name_add`]); one that does not resolve yet is kept,
    /// and dialled once [`Self::refresh_manual_targets`] resolves it. Only
    /// a target that can never resolve here (malformed, `-dns=0`, `-proxy`)
    /// is refused. Never listed by `getaddednodeinfo`.
    pub async fn register_connect_target(&self, target: &str) -> Option<PeerAddr> {
        use crate::net::dns::PeerTargetError;
        let default_port = default_p2p_port(self.chain_state.network);
        match self.resolve_target_classified(target, default_port).await {
            Ok(addr) => {
                self.add_peer_addr(addr.clone());
                if crate::net::dns::is_name_target(target) {
                    self.connect_name_add(target, Some(addr.clone()));
                }
                Some(addr)
            }
            Err(PeerTargetError::Lookup(e)) => {
                tracing::warn!(addr = target, "connect address does not resolve yet; will keep trying: {}", e);
                self.connect_name_add(target, None);
                None
            }
            Err(e) => {
                tracing::warn!(addr = target, "Invalid connect address: {}", e);
                None
            }
        }
    }

    /// Track a `-connect` host name so that it is looked up again: resolved
    /// now (`Some`), in case its address changes, or not yet (`None`), so
    /// it is dialled once it resolves. Never listed by `getaddednodeinfo`.
    pub fn connect_name_add(&self, name: &str, addr: Option<PeerAddr>) -> bool {
        self.add_manual_target(name, addr, false)
    }

    fn add_manual_target(&self, target: &str, addr: Option<PeerAddr>, listed: bool) -> bool {
        let default_port = default_p2p_port(self.chain_state.network);
        let mut entries = self.addnode_entries.write();
        // Core's `CConnman::AddNode`: the same string, or two spellings of
        // the same numeric address, are one entry. Names are never looked
        // up to compare. Whether the address is already a dial candidate
        // (gossip, `peers.dat`) does not matter: that is not an added node.
        let numeric = |t: &str| {
            (!crate::net::dns::is_name_target(t))
                .then(|| PeerAddr::parse_with_default_port(t, default_port).ok())
                .flatten()
        };
        let mine = numeric(target);
        if entries.iter().any(|e| {
            e.listed == listed
                && (e.target == target || (mine.is_some() && numeric(&e.target) == mine))
        }) {
            return false;
        }
        if let Some(a) = &addr {
            self.add_peer_addr(a.clone());
        }
        entries.push(ManualTarget {
            target: target.to_string(),
            resolved: addr,
            listed,
            next_lookup: Instant::now(),
            lookups_failed: 0,
        });
        true
    }

    /// Remove an added node. Matched first by the operator's string, as
    /// Core's `RemoveAddedNode` does, then by resolved address (the form
    /// satd has always accepted). Returns `true` if one was removed.
    pub fn addnode_remove_target(&self, user_str: &str, addr: Option<&PeerAddr>) -> bool {
        let mut entries = self.addnode_entries.write();
        let pos = entries
            .iter()
            .position(|e| e.listed && e.target == user_str)
            .or_else(|| {
                addr.and_then(|a| {
                    entries
                        .iter()
                        .position(|e| e.listed && e.resolved.as_ref() == Some(a))
                })
            });
        let Some(pos) = pos else {
            return false;
        };
        let removed = entries.remove(pos);
        if let Some(a) = removed.resolved
            && !entries.iter().any(|e| e.resolved.as_ref() == Some(&a))
        {
            self.remove_peer_addr(&a);
        }
        true
    }

    /// Remove a peer registered via addnode, by resolved address. Returns
    /// `true` if found and removed.
    pub fn addnode_remove(&self, addr: &PeerAddr) -> bool {
        self.addnode_remove_target(&addr.to_string(), Some(addr))
    }

    /// Whether any named target is due a lookup: a name that has not
    /// resolved yet, or one whose peer is gone and whose address may have
    /// moved since it was last looked up.
    fn manual_targets_due(&self, now: Instant) -> bool {
        self.addnode_entries
            .read()
            .iter()
            .any(|e| crate::net::dns::is_name_target(&e.target) && now >= e.next_lookup)
    }

    /// Look up again every named target that is due, and dial what changed.
    ///
    /// Core resolves an added node's name on every connection attempt
    /// (`ThreadOpenAddedConnections` passes the string to
    /// `OpenNetworkConnection`), and does the same for each `-connect`
    /// entry, so a name that did not resolve at startup is not lost and a
    /// peer whose address changed is found again. satd resolved each once,
    /// at startup, and dropped a name that failed: a node started alongside
    /// its peers never connected to them. This is that retry:
    ///
    /// * a name that has not resolved is looked up on every reconnect tick,
    ///   and dialled as soon as it resolves;
    /// * a resolved name whose peer is not connected is looked up again at
    ///   most every [`MANUAL_TARGET_RELOOKUP`], and if the address moved the
    ///   old one stops being dialled and the new one is.
    ///
    /// Run as its own task: lookups can take seconds and must not hold up
    /// the manager loop. Refusals (`-dns=0`, `-proxy`) never reach this
    /// list; they are reported where the target is configured.
    pub async fn refresh_manual_targets(self: Arc<Self>) {
        if self.refreshing_manual_targets.swap(true, Ordering::AcqRel) {
            return;
        }
        let now = Instant::now();
        let default_port = default_p2p_port(self.chain_state.network);
        let due: Vec<(String, bool, Option<PeerAddr>)> = self
            .addnode_entries
            .read()
            .iter()
            .filter(|e| crate::net::dns::is_name_target(&e.target) && now >= e.next_lookup)
            .map(|e| (e.target.clone(), e.listed, e.resolved.clone()))
            .collect();
        for (target, listed, old) in due {
            // A resolved name whose peer is up needs nothing; look again
            // once it is not.
            if let Some(a) = &old
                && self.is_peer_addr_connected(a)
            {
                if let Some(e) = self
                    .addnode_entries
                    .write()
                    .iter_mut()
                    .find(|e| e.target == target && e.listed == listed)
                {
                    e.next_lookup = Instant::now() + MANUAL_TARGET_RELOOKUP;
                }
                continue;
            }
            let result = self.resolve_target_classified(&target, default_port).await;
            let mut dial = None;
            {
                // Re-find the entry: `addnode remove` may have run while the
                // lookup was in flight, and a removed target must stay gone.
                let mut entries = self.addnode_entries.write();
                let Some(idx) = entries
                    .iter()
                    .position(|e| e.target == target && e.listed == listed)
                else {
                    continue;
                };
                match result {
                    Ok(new) => {
                        let prev = entries[idx].resolved.clone();
                        entries[idx].lookups_failed = 0;
                        entries[idx].next_lookup = Instant::now()
                            + if prev.is_some() { MANUAL_TARGET_RELOOKUP } else { Duration::ZERO };
                        if prev.as_ref() != Some(&new) {
                            if let Some(p) = &prev {
                                let shared = entries
                                    .iter()
                                    .enumerate()
                                    .any(|(i, e)| i != idx && e.resolved.as_ref() == Some(p));
                                if !shared {
                                    self.remove_peer_addr(p);
                                }
                                tracing::info!(target = %target, old = %p, new = %new, "Peer name now resolves to a different address");
                            } else {
                                tracing::info!(target = %target, addr = %new, "Peer name resolved; connecting");
                            }
                            entries[idx].resolved = Some(new.clone());
                            self.add_peer_addr(new.clone());
                            dial = Some(new);
                        }
                    }
                    Err(e) => {
                        let first = entries[idx].lookups_failed == 0;
                        entries[idx].lookups_failed += 1;
                        // Unresolved: try again next tick. Resolved: keep
                        // the address it had; look again later.
                        entries[idx].next_lookup = Instant::now()
                            + if entries[idx].resolved.is_some() { MANUAL_TARGET_RELOOKUP } else { Duration::ZERO };
                        if first && entries[idx].resolved.is_none() {
                            tracing::info!(target = %target, "Peer name does not resolve yet; will keep trying: {e}");
                        } else {
                            tracing::debug!(target = %target, "Peer name lookup failed: {e}");
                        }
                    }
                }
            }
            if let Some(addr) = dial
                && self.is_network_active()
            {
                let pm = Arc::clone(&self);
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::debug!(%addr, "Dial after peer name lookup failed: {e}");
                    }
                });
            }
        }
        self.refreshing_manual_targets.store(false, Ordering::Release);
    }

    /// Whether a connection to `addr` is up or being set up.
    fn is_peer_addr_connected(&self, addr: &PeerAddr) -> bool {
        match addr {
            PeerAddr::Socket(sa) => self.is_addr_connected(sa),
            PeerAddr::Onion { host, .. } => self.is_onion_connected(host),
        }
    }

    /// Drop a PeerAddr from the auto-reconnect set (the inverse of
    /// [`add_peer_addr`]). Used by `addnode <node> remove`. Like Bitcoin Core,
    /// this only stops future reconnect attempts; it does not force-disconnect
    /// an already-established peer. Returns `true` if the address was found
    /// and removed, `false` if it was not in the set.
    ///
    /// An address the node also learned for itself stays a learned
    /// candidate, as in Core, where removing an added node leaves its
    /// address book alone.
    pub fn remove_peer_addr(&self, addr: &PeerAddr) -> bool {
        // The manual registration has to go, not only the dial. A removed
        // `addnode` peer once stayed "manual" for the life of the process:
        // it kept being dialled as a manual connection and exempt from
        // `-connect` gating, so `addnode <peer> remove` on a
        // `-connect`-pinned node left the peer connectable when the whole
        // point of that flag is that it is not.
        match addr {
            PeerAddr::Socket(sa) => self.manual_addrs.write().remove(sa),
            PeerAddr::Onion { host, .. } => {
                self.manual_onion_hosts.write().remove(host);
                let mut addrs = self.connect_peer_addrs.write();
                let before = addrs.len();
                addrs.retain(|a| a != addr);
                addrs.len() < before
            }
        }
    }

    /// Count inbound peers, returning `(total_inbound, same_ip_inbound)`.
    /// Pulled out for unit-testing the per-IP cap without a real `TcpStream`.
    ///
    /// Includes both `Connecting` and `Connected` inbound peers — review
    /// F4 (PR #181): counting only `Connected` let concurrent handshake
    /// bursts from one IP exceed `maxinboundperip` for the duration of
    /// the handshake. Pending inbound peers consume a slot from the
    /// moment we accept the TCP stream until the peer task terminates
    /// (handshake success → `Connected`, or handshake failure → peer
    /// dropped from `self.peers`). Outbound peers and disconnected
    /// peers don't count.
    fn count_inbound(peers: &HashMap<PeerId, PeerHandle>, ip: IpAddr) -> (usize, usize) {
        let mut total = 0usize;
        let mut same_ip = 0usize;
        for h in peers.values() {
            if h.info.direction != Direction::Inbound
                || h.info.state == PeerState::Disconnected
            {
                continue;
            }
            total += 1;
            if h.info.addr.ip() == ip {
                same_ip += 1;
            }
        }
        (total, same_ip)
    }

    /// Get the number of connected outbound peers.
    pub fn outbound_count(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| {
                h.info.direction == Direction::Outbound
                    && h.info.state == PeerState::Connected
            })
            .count()
    }

    /// Number of inbound peers currently connected.
    pub fn inbound_count(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| {
                h.info.direction == Direction::Inbound
                    && h.info.state == PeerState::Connected
            })
            .count()
    }

    /// An addr-fetch connection exists to collect one batch of addresses and
    /// go. Core requires more than one entry before treating the answer as
    /// complete, so a peer that only announces itself does not end the
    /// connection before it has said anything useful (`net_processing.cpp`,
    /// "Require multiple addresses to avoid disconnecting on
    /// self-announcements").
    ///
    /// Core applies this in the handler both `addr` and `addrv2` share. satd
    /// sends `sendaddrv2` on every outbound connection, so every BIP155-capable
    /// peer -- Bitcoin Core 22 and later, and satd itself -- answers our
    /// `getaddr` with `addrv2`. Having the rule on the legacy arm alone meant
    /// the connection never completed against any modern peer and sat holding
    /// an outbound slot until the 300s expiry.
    fn note_addr_fetch_answered(&self, id: PeerId, count: usize) {
        if count > 1 && self.conn_type_of(id) == ConnType::AddrFetch {
            tracing::debug!(id, count, "addrfetch connection completed, disconnecting");
            self.disconnect_by_id(id);
        }
    }

    /// Bitcoin Core's per-type outbound capacity check
    /// (`CConnman::AddConnection`): full-relay and block-relay-only each have
    /// their own budget, and neither addr-fetch nor feeler has one -- they are
    /// short-lived by construction, and `-seednode` has no limit either.
    ///
    /// The error string is the one Core's `addconnection` turns into
    /// RPC_CLIENT_NODE_CAPACITY_REACHED, so the RPC does not have to re-derive
    /// which limit was hit.
    ///
    /// `pending` is the in-flight dial list, passed in rather than read here
    /// so the caller can hold it across the check *and* its own reservation:
    /// two acquisitions would leave the window this check exists to close.
    fn check_outbound_limit_for(
        &self,
        conn_type: ConnType,
        pending: &[ConnType],
    ) -> Result<(), String> {
        // `None` = no *individual* limit. Core leaves addr-fetch and feeler
        // uncapped per type deliberately, because `semOutbound` below holds
        // them; they must still take that grant, so they cannot return early
        // here.
        let max = match conn_type {
            ConnType::OutboundFullRelay => {
                Some(self.max_connections.load(Ordering::Relaxed).min(MAX_OUTBOUND))
            }
            ConnType::BlockRelay => Some(MAX_OUTBOUND_BLOCK_RELAY),
            ConnType::AddrFetch | ConnType::Feeler => None,
            // Core returns false rather than opening one of these.
            ConnType::Inbound | ConnType::Manual => {
                return Err(format!(
                    "cannot open a {} connection this way",
                    conn_type.as_str()
                ))
            }
        };
        // Count dials already in flight for this type alongside the peers
        // that completed. Counting only the map leaves a window between the
        // check and `spawn_peer` -- the dial and the whole transport
        // handshake -- in which concurrent callers all see the same free
        // slot: three concurrent `addconnection` calls at a limit of two
        // produced three peers. Core is protected by the `semOutbound`
        // counting semaphore, whose grant is taken before the dial.
        let peers = self.peers.read();
        if let Some(max) = max {
            let existing = peers
                .values()
                .filter(|h| h.info.conn_type == conn_type)
                .count()
                + pending.iter().filter(|t| **t == conn_type).count();
            if existing >= max {
                return Err(
                    "Error: Already at capacity for specified connection type.".to_string()
                );
            }
        }

        // Core takes a *second* grant after the per-type check: `semOutbound`
        // is a counting semaphore sized `min(m_max_automatic_outbound,
        // m_max_automatic_connections)`, and `AddConnection` fails when it
        // cannot be acquired (`net.cpp`). Without it the per-type limits are
        // the only bound, and the types that have none — addr-fetch and
        // feeler, which Core deliberately leaves uncapped *individually*
        // because the semaphore holds them — are unbounded: a caller could
        // open addr-fetch connections until the process ran out of sockets.
        let total_outbound = peers
            .values()
            .filter(|h| h.info.conn_type != ConnType::Inbound)
            // Core exempts MANUAL: `-addnode` peers have their own semaphore
            // (`semAddnode`) and do not consume an automatic slot.
            .filter(|h| h.info.conn_type != ConnType::Manual)
            .count()
            + pending.len();
        if total_outbound >= Self::max_automatic_outbound(&self.max_connections) {
            return Err("Error: Already at capacity for specified connection type.".to_string());
        }
        Ok(())
    }

    /// Core's `m_max_automatic_outbound`, capped by the connection budget:
    /// `min(full_relay + block_relay + feeler, max_connections)` (`net.h`).
    ///
    /// The IBD figure is deliberately *not* used here. It raises the
    /// full-relay target while the node catches up; the semaphore Core sizes
    /// this way is about how many automatic outbound sockets may exist at
    /// once, which does not change with sync state.
    fn max_automatic_outbound(max_connections: &std::sync::atomic::AtomicUsize) -> usize {
        // One feeler slot, as Core's `m_max_feeler`.
        const MAX_FEELER: usize = 1;
        (MAX_OUTBOUND + MAX_OUTBOUND_BLOCK_RELAY + MAX_FEELER)
            .min(max_connections.load(Ordering::Relaxed))
    }

    /// Check outbound connection limit.
    fn check_outbound_limit(&self) -> Result<(), String> {
        let max_outbound = if self.is_ibd() {
            MAX_OUTBOUND_IBD
        } else {
            self.max_connections.load(Ordering::Relaxed).min(MAX_OUTBOUND)
        };
        let outbound = self.outbound_count();
        if outbound >= max_outbound {
            return Err("max outbound connections reached".to_string());
        }
        Ok(())
    }

    /// Connect to an outbound peer with no caller-chosen type, as the
    /// reconnect loop does. `spawn_peer` classifies it: `manual` if the
    /// operator named the address, `outbound-full-relay` otherwise.
    pub async fn connect_outbound(self: &Arc<Self>, addr: SocketAddr) -> Result<(), String> {
        self.connect_outbound_as(addr, None, None).await
    }

    /// Connect to an outbound peer of a caller-chosen type.
    ///
    /// `conn_type` is `Some(Manual)` for a dial the operator asked for
    /// ([`Self::connect_peer_addr_with`]), and one of `addconnection`'s four
    /// types for that RPC. `None` is an automatic dial, classified by
    /// `spawn_peer`. A manual or automatic dial takes the historical single
    /// outbound cap; `addconnection`'s types take Core's per-type ones.
    pub async fn connect_outbound_as(
        self: &Arc<Self>,
        addr: SocketAddr,
        conn_type: Option<ConnType>,
        use_v2: Option<bool>,
    ) -> Result<(), String> {
        self.connect_outbound_inner(addr, conn_type, use_v2, true).await
    }

    /// Core's `CConnman::AddConnection`, behind `addconnection`.
    ///
    /// Returns as soon as the capacity check passes and the outbound slot is
    /// taken; the dial and the transport handshake run in a spawned task.
    /// Core answers the RPC the same way — `OpenNetworkConnection` returns
    /// once the socket is connected, never waiting for the peer's `version`
    /// — and the difference is not cosmetic: the functional-test framework
    /// binds a listener, calls `addconnection`, and only *then* accepts and
    /// speaks. Awaiting the handshake inside the RPC, as this used to,
    /// deadlocks against that order until the dial times out.
    ///
    /// The capacity check stays synchronous so a refusal still reaches the
    /// caller as `-34`, which is the one part of the outcome Core reports.
    ///
    /// The target is taken as the operator's string, as Core takes it:
    /// `AddConnection` hands it to `OpenNetworkConnection`, and the `Lookup`
    /// happens inside `ConnectNode` (v31.1 `src/net.cpp:406`), on the dial
    /// thread, after the RPC has answered. A name that does not resolve is
    /// therefore a dial that failed, which Core reports only in its log.
    /// Resolving here instead turned that into `-8 Invalid address`, an error
    /// Core has no way to produce for this call.
    pub fn add_connection(
        self: &Arc<Self>,
        target: &str,
        default_port: u16,
        conn_type: ConnType,
        use_v2: bool,
    ) -> Result<(), String> {
        if !self.is_network_active() {
            return Err("networking disabled (networkactive=false)".to_string());
        }
        // satd types a connection at `spawn_peer`, which is reached from the
        // socket dial path; the onion dial has its own path and no way to
        // carry a requested type through it yet. Refuse by name rather than
        // open an untyped connection the caller would then see reported as
        // something else. This is a satd limitation Core does not have, so it
        // stays a synchronous, named refusal instead of a line in the log —
        // and recognising an onion target needs no resolver.
        if crate::net::dns::is_onion_target(target) {
            let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
            return Err(format!(
                "addconnection cannot open a typed connection to an onion address ({host}) yet"
            ));
        }
        {
            let mut pending = self.pending_typed_dials.write();
            self.check_outbound_limit_for(conn_type, &pending)?;
            pending.push(conn_type);
        }
        let pm = self.clone();
        let target = target.to_string();
        tokio::spawn(async move {
            // Releases the reservation on every exit path, including a
            // resolver failure, a dial timeout, or a panic below.
            let _grant = OwnedTypedDialGuard { pm: pm.clone(), conn_type };
            let addr = match pm.resolve_peer_target(&target, default_port).await {
                Ok(PeerAddr::Socket(sa)) => sa,
                // Refused synchronously above; `resolve_peer_target` cannot
                // return this for a target that got past that check.
                Ok(PeerAddr::Onion { .. }) => return,
                Err(e) => {
                    tracing::debug!(
                        %target,
                        ?conn_type,
                        "addconnection: target did not resolve: {e}"
                    );
                    return;
                }
            };
            if let Err(e) = pm
                .connect_outbound_inner(addr, Some(conn_type), Some(use_v2), false)
                .await
            {
                tracing::debug!(%addr, ?conn_type, "addconnection dial failed: {e}");
            }
        });
        Ok(())
    }

    /// `connect_outbound_as`, with the per-type reservation optional:
    /// `add_connection` has already taken it and holds the grant across the
    /// spawned dial.
    async fn connect_outbound_inner(
        self: &Arc<Self>,
        addr: SocketAddr,
        conn_type: Option<ConnType>,
        use_v2: Option<bool>,
        reserve: bool,
    ) -> Result<(), String> {
        if !self.is_network_active() {
            return Err("networking disabled (networkactive=false)".to_string());
        }
        // Core's `ConnectNode` opens a socket only to an address that
        // `IsValid()` (v31.1 `src/net.cpp:443`), for a manual target as much
        // as a learned one. `0.0.0.0`, `255.255.255.255` and `::` name no
        // host, and on Linux a connect to `0.0.0.0` reaches the local host:
        // a gossiped `0.0.0.0:<our port>` had the node dial itself on every
        // reconnect tick (#866). The address book refuses such an address
        // on the way in, but this is the one place every socket dial passes
        // (the reconnect loop, `addnode`, `-connect`, `addconnection`), so it
        // holds however the address arrived.
        if !crate::net::is_valid(addr.ip()) {
            return Err(format!("{addr} is not a valid address to connect to"));
        }
        // Take the capacity check and the per-type reservation together, so
        // two callers cannot both pass the same free slot.
        let _typed_slot = match conn_type {
            // A manual dial is capped as an automatic one is, as it always
            // was; it has no per-type reservation to take.
            None | Some(ConnType::Manual) => {
                self.check_outbound_limit()?;
                None
            }
            Some(t) if reserve => {
                let mut pending = self.pending_typed_dials.write();
                self.check_outbound_limit_for(t, &pending)?;
                pending.push(t);
                drop(pending);
                Some(TypedDialGuard { set: &self.pending_typed_dials, conn_type: t })
            }
            Some(_) => None,
        };

        // Claim the dial slot before doing any network I/O. Without this,
        // the reconnect loop can spawn multiple concurrent `connect_outbound`
        // tasks for the same addr (nothing takes an address off the dial
        // lists while a dial to it is in flight), and a remote peer's per-IP
        // rate limit will FIN all but the first.
        {
            let mut pending = self.pending_connections.write();
            if pending.contains(&addr) {
                return Err(format!("connect already in flight to {}", addr));
            }
            if self.is_addr_connected(&addr) {
                return Err(format!("already connected to {}", addr));
            }
            pending.insert(addr);
        }
        // RAII guard so the slot is released on every exit path, including
        // panics from the await points below.
        struct PendingGuard<'a> {
            set: &'a RwLock<HashSet<SocketAddr>>,
            addr: SocketAddr,
        }
        impl<'a> Drop for PendingGuard<'a> {
            fn drop(&mut self) {
                self.set.write().remove(&self.addr);
            }
        }
        let _guard = PendingGuard {
            set: &self.pending_connections,
            addr,
        };

        // Bound the dial itself with Core's `-timeout` (the same value
        // that bounds the version/verack reads). Without this a
        // blackholed route or a stalled SOCKS/onion proxy hangs the dial
        // for the OS/proxy default rather than the configured value. The
        // `_guard` above releases the pending-connection slot on the
        // timeout early-return too.
        let stream = self.dial_direct(addr).await?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%addr, id, "Connecting to peer");

        // Establish the transport before spawning so a failed v2 handshake
        // can re-dial for v1. Peers that already failed v2 this session are
        // connected straight as v1 to avoid a wasted round trip.
        let (conn, id) = self
            .establish_outbound(id, stream, OutboundDial::Direct(addr), use_v2)
            .await?;

        // Re-check after the dial + handshake awaits: `setnetworkactive false`
        // (RPC or SIGHUP) may have run while we were connecting, clearing all
        // peers. Without this we'd register a live peer *after* the pause,
        // leaving an outbound connection up while networking is meant to be
        // off. Dropping `conn` here closes the socket.
        if !self.is_network_active() {
            return Err("networking disabled during connect (networkactive=false)".to_string());
        }

        self.spawn_peer(
            id,
            addr,
            IncomingTransport::Established(Box::new(conn)),
            Direction::Outbound,
            None,
            conn_type,
        );
        Ok(())
    }

    /// Connect to a .onion peer address via SOCKS5 proxy. `conn_type` is
    /// `Some(Manual)` for a dial the operator asked for and `None` for an
    /// automatic one, which `spawn_peer` classifies.
    pub async fn connect_outbound_onion(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        conn_type: Option<ConnType>,
    ) -> Result<(), String> {
        if !self.is_network_active() {
            return Err("networking disabled (networkactive=false)".to_string());
        }
        self.check_outbound_limit()?;

        // Dedupe by onion host BEFORE any network I/O. Onion peers all share
        // the `0.0.0.0` placeholder socket, so `is_addr_connected` /
        // `pending_connections` (both keyed on `SocketAddr`) can't tell them
        // apart. Without this guard the 10s reconnect loop re-dials onion
        // peers it's already connected to; the remote then drops the older
        // duplicate, which churned onion peers every ~2s and stalled IBD over
        // Tor (the live seed delivered one headers batch, got re-dialed, and
        // EOF'd before any blocks transferred).
        {
            let mut pending = self.pending_onion_dials.write();
            if pending.contains(host) {
                return Err(format!("onion dial already in flight to {host}"));
            }
            if self.is_onion_connected(host) {
                return Err(format!("already connected to {host}"));
            }
            pending.insert(host.to_string());
        }
        // RAII guard releases the in-flight slot on every exit path (including
        // a dial timeout or panic at the awaits below).
        struct OnionPendingGuard<'a> {
            set: &'a RwLock<HashSet<String>>,
            host: String,
        }
        impl Drop for OnionPendingGuard<'_> {
            fn drop(&mut self) {
                self.set.write().remove(&self.host);
            }
        }
        let _guard = OnionPendingGuard {
            set: &self.pending_onion_dials,
            host: host.to_string(),
        };

        let stream = self.dial_onion(host, port).await?;

        // Use a placeholder SocketAddr for .onion peers (the actual routing is via proxy)
        let placeholder_addr: SocketAddr = ([0, 0, 0, 0], port).into();

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(onion = host, id, "Connecting to .onion peer via proxy");

        let (conn, id) = self
            .establish_outbound(id, stream, OutboundDial::Onion(host.to_string(), port), None)
            .await?;

        // Re-check after the dial + handshake awaits (see connect_outbound):
        // networkactive may have been toggled off mid-connect. Dropping `conn`
        // closes the socket so no peer is registered while paused.
        if !self.is_network_active() {
            return Err("networking disabled during connect (networkactive=false)".to_string());
        }

        self.spawn_peer(
            id,
            placeholder_addr,
            IncomingTransport::Established(Box::new(conn)),
            Direction::Outbound,
            Some(host),
            conn_type,
        );
        Ok(())
    }

    /// Dial a peer the operator asked for (either socket or .onion), there
    /// and then: `-connect`, `-addnode` and `-seednode` at startup and on
    /// reload, `addnode add`, `addnode onetry`, and a named peer whose
    /// name resolved. The connection is `manual`.
    pub async fn connect_peer_addr(self: &Arc<Self>, addr: &PeerAddr) -> Result<(), String> {
        self.connect_peer_addr_with(addr, None).await
    }

    /// [`Self::connect_peer_addr`] with `addnode`'s `v2transport` choice for
    /// this dial; `None` follows `-v2transport`.
    pub async fn connect_peer_addr_with(
        self: &Arc<Self>,
        addr: &PeerAddr,
        use_v2: Option<bool>,
    ) -> Result<(), String> {
        // Typed at the dial rather than by registering the address. This
        // used to add it to `manual_addrs` for the dial and take it out
        // again afterwards unless it was a dial candidate, which every
        // gossip-learned address was: an `addnode <learned> onetry` left it
        // manual for good, dialled as one even under `-connect`.
        match addr {
            PeerAddr::Socket(sa) => {
                self.connect_outbound_as(*sa, Some(ConnType::Manual), use_v2).await
            }
            PeerAddr::Onion { host, port } => {
                self.connect_outbound_onion(host, *port, Some(ConnType::Manual)).await
            }
        }
    }

    /// Dial `addr` as one of the node's own automatic dials: the reconnect
    /// loop's, and a seed's. No type is chosen here; `spawn_peer` reports
    /// the connection `manual` if the operator named the peer and
    /// `outbound-full-relay` otherwise.
    pub async fn connect_peer_addr_automatic(self: &Arc<Self>, addr: &PeerAddr) -> Result<(), String> {
        match addr {
            PeerAddr::Socket(sa) => self.connect_outbound(*sa).await,
            PeerAddr::Onion { host, port } => self.connect_outbound_onion(host, *port, None).await,
        }
    }

    /// Accept an inbound connection.
    ///
    /// Cap-check and slot reservation happen atomically under one
    /// write lock so concurrent accepts cannot both observe a below-
    /// limit count and proceed. Without this, the earlier shape
    /// (read-lock for count, drop lock, write-lock for insert) left
    /// a TOCTOU window that, combined with counting only `Connected`
    /// peers, let handshake bursts bypass the per-IP cap. Review F4.
    pub fn accept_inbound(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        self.accept_inbound_with_perms(
            stream,
            addr,
            crate::net::permissions::NetPermissions::NONE,
            false,
        );
    }

    /// Accept an inbound connection, granting `bind_perms` on top of any
    /// `-whitelist` source-subnet permissions. `bind_perms` carries the
    /// permissions of a `-whitebind` listener; it is NONE for the normal
    /// `-bind` listener.
    pub fn accept_inbound_with_perms(
        self: &Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
        bind_perms: crate::net::permissions::NetPermissions,
        inbound_onion: bool,
    ) {
        // `-networkactive=0` / `setnetworkactive false`: refuse inbound. The
        // moved `stream` is dropped here, closing the socket.
        if !self.is_network_active() {
            tracing::debug!(%addr, "networkactive=false: refusing inbound connection");
            return;
        }
        let ip = addr.ip();
        // Core: `AddWhitelistPermissionFlags(permission_flags, inbound_onion ?
        // std::optional<CNetAddr>{} : addr, vWhitelistedRangeIncoming)`.
        //
        // Tor forwards a hidden-service connection to a local port, so every
        // inbound onion peer arrives with the loopback address of the socket
        // Tor dialled. Matching that against `-whitelist` hands an anonymous
        // remote peer whatever the operator granted their own machine — and
        // `-whitelist=127.0.0.1` is the ordinary way to whitelist a local
        // Electrum or BTCPay integration. `noban` alone makes such a peer
        // un-bannable for misbehaviour and exempt from both inbound caps.
        //
        // `-whitebind` permissions still apply: those are attached to the
        // listener the operator named, not inferred from the peer's address.
        let perms = if inbound_onion {
            bind_perms
        } else {
            self.whitelist_permissions(ip).union(bind_perms)
        };
        // A ban has to cover the inbound direction or it covers nothing: a
        // banned host simply dials us instead of waiting to be dialled, and
        // `setban` becomes advisory. Core drops the socket here too, before a
        // `CNode` exists (`src/net.cpp`: `if (!HasFlag(permission_flags,
        // NoBan) && banned) { ... return; }`), with the same NoBan exemption
        // so `-whitelist`/`-whitebind` peers stay reachable.
        if !perms.noban && self.is_addr_banned(&addr) {
            tracing::debug!("connection from {addr} dropped (banned)");
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg_rx = {
            let mut peers = self.peers.write();
            // Authoritative pause check under the peers lock (mirrors
            // spawn_peer / set_network_active). Closes the race where
            // `setnetworkactive false` runs between the top-of-function check
            // and here; returning drops `stream`, closing the socket.
            if !self.is_network_active() {
                tracing::debug!(%addr, "networkactive=false: refusing inbound connection (race)");
                return;
            }
            // NoBan peers are exempt from the inbound connection caps
            // (matches Bitcoin Core's manual-conn / whitelist handling).
            if !perms.noban {
                let (inbound_count, same_ip_count) = Self::count_inbound(&peers, ip);
                if inbound_count >= self.max_connections.load(Ordering::Relaxed).saturating_sub(MAX_OUTBOUND) {
                    tracing::warn!(%addr, "Max inbound connections reached, dropping connection");
                    return;
                }
                // The per-IP sub-cap is an anti-eclipse / anti-DoS guard
                // against a single *remote* source monopolizing inbound
                // slots. Loopback is the operator's own machine: local
                // integrations (NBXplorer/BTCPayServer, the Electrum and
                // Esplora-personality wallets, multiple local clients all
                // dialing 127.0.0.1) legitimately open several connections
                // from the one loopback address and would otherwise trip a
                // cap meant for hostile peers. Bitcoin Core does not
                // throttle localhost this way. The total `inbound_count`
                // cap above still bounds loopback, so this cannot exhaust
                // all slots.
                if !ip.is_loopback() && same_ip_count >= self.max_inbound_per_ip.load(Ordering::Relaxed) {
                    tracing::warn!(
                        %addr,
                        same_ip_count,
                        limit = self.max_inbound_per_ip.load(Ordering::Relaxed),
                        "Per-IP inbound limit reached, dropping connection",
                    );
                    return;
                }
            }
            // Reserve the slot under the same write lock so further
            // accepts on this thread (or another) see this peer in
            // count_inbound's tally before they themselves cap-check.
            let (msg_tx, msg_rx) = mpsc::channel::<NetworkMessage>(256);
            let mut info = PeerInfo::new(id, addr, Direction::Inbound);
            info.permissions = perms;
            // `getpeerinfo`'s `addrbind`: which of our listeners this peer
            // reached us on. Distinct from `-bind` config, since a node may
            // listen on several addresses.
            info.bind_addr = stream.local_addr().ok();
            // `detecting` until the first bytes show v1 or v2.
            if self.v2_transport_enabled() {
                info.transport = crate::net::peer::TransportProtocol::Detecting;
            }
            peers.insert(
                id,
                PeerHandle {
                    info,
                    msg_tx: msg_tx.into(),
                    disconnect: Arc::new(tokio::sync::Notify::new()),
                    flow: Arc::new(crate::net::flow::PeerFlow::new()),
                    last_getheaders_sent: None,
                    last_mempool_served: None,
                    fee_filter_sent: None,
                    stats: PeerStats::new(self.net_totals.clone()),
                },
            );
            msg_rx
        };
        tracing::info!(%addr, id, noban = perms.noban, "Accepted inbound peer");
        tracing::debug!("Added connection peer={id}");
        self.spawn_peer_task(
            id,
            addr,
            IncomingTransport::Raw(stream),
            Direction::Inbound,
            msg_rx,
        );
    }

    /// Bind the inbound P2P listener, returning the bound socket.
    ///
    /// Separated from the accept loop ([`Self::accept_loop`]) so the caller
    /// can treat a bind failure — port already in use (another satd instance),
    /// permission denied, bad address — as a *fatal* startup error rather than
    /// discovering it asynchronously after the daemon already reported a clean
    /// start. The accept loop never returns, so folding bind into it makes the
    /// only observable failure a log line on a detached task.
    pub async fn bind_listener(bind_addr: SocketAddr) -> Result<TcpListener, String> {
        TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("listen failed: {}", e))
    }

    /// Run the inbound accept loop on an already-bound listener, granting every
    /// peer accepted here `bind_perms` (Bitcoin Core's `-whitebind`). Never
    /// returns under normal operation.
    /// `inbound_onion` marks a listener that Tor forwards a hidden service
    /// to. Peers arriving there are remote and anonymous however local their
    /// socket address looks, so `-whitelist` must not match them.
    pub async fn accept_loop(
        self: &Arc<Self>,
        listener: TcpListener,
        bind_perms: crate::net::permissions::NetPermissions,
        inbound_onion: bool,
    ) {
        let bind_addr = listener.local_addr().ok();
        tracing::info!(?bind_addr, whitebind = bind_perms.any(), "P2P listening");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    self.accept_inbound_with_perms(stream, addr, bind_perms, inbound_onion);
                }
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                }
            }
        }
    }

    /// Bind and serve inbound connections in one call. Convenience wrapper over
    /// [`Self::bind_listener`] + [`Self::accept_loop`]; a bind failure surfaces
    /// as `Err` before the loop starts.
    pub async fn listen(self: &Arc<Self>, bind_addr: SocketAddr) -> Result<(), String> {
        self.listen_with_perms(bind_addr, crate::net::permissions::NetPermissions::NONE)
            .await
    }

    /// Bind and serve inbound connections, granting `bind_perms` to every peer
    /// accepted (Bitcoin Core's `-whitebind`). See [`Self::listen`].
    pub async fn listen_with_perms(
        self: &Arc<Self>,
        bind_addr: SocketAddr,
        bind_perms: crate::net::permissions::NetPermissions,
    ) -> Result<(), String> {
        let listener = Self::bind_listener(bind_addr).await?;
        self.accept_loop(listener, bind_perms, false).await;
        Ok(())
    }

    /// Disconnect a peer by address. Returns whether one matched.
    pub fn disconnect(&self, addr: &SocketAddr) -> bool {
        self.disconnect_by_addr(&addr.to_string())
    }

    /// Disconnect the peer whose address string matches `addr`, as Bitcoin
    /// Core's `DisconnectNode(std::string_view)` does.
    ///
    /// The comparison is against the string `getpeerinfo` reports, not a
    /// parsed socket address. That is what Core compares (`m_addr_name`), and
    /// it is the difference between an operator being able to feed
    /// `getpeerinfo`'s own output back in and not: an onion peer is reported
    /// as `<base32>.onion:port` while its socket is a placeholder, so parsing
    /// first made those peers impossible to name. Parsing also turned any
    /// unrecognised string into a parse error where Core simply finds no
    /// match.
    ///
    /// Core stops at the first match (`find_if`), so this does too; the
    /// disconnect-every-match overloads are the ones `setban` uses.
    pub fn disconnect_by_addr(&self, addr: &str) -> bool {
        let id = self
            .peers
            .read()
            .iter()
            .find(|(_, handle)| handle.info.addr_string() == addr)
            .map(|(id, _)| *id);
        match id {
            Some(id) => self.disconnect_by_id(id),
            None => false,
        }
    }

    /// Disconnect a peer by its `getpeerinfo` id. Returns whether one matched.
    ///
    /// Dropping the `PeerHandle` is what actually closes the connection: it
    /// closes the peer task's `msg_rx`, which the write loop treats as
    /// "manager dropped our handle" and returns on, aborting the reader task
    /// and closing the socket. The task then emits `PeerDisconnected`, which
    /// runs the rest of the teardown (IBD reassignment, background-range
    /// requeue) exactly as an organic disconnect would.
    pub fn disconnect_by_id(&self, id: PeerId) -> bool {
        let removed = self.peers.write().remove(&id);
        match removed {
            Some(handle) => {
                // Signal before the handle drops. Dropping it closes `msg_rx`
                // only when the last sender goes, and a `getcfilters` stream
                // task can be holding a clone -- in which case the RPC would
                // report success on a connection that is still open and still
                // relaying. The write loop selects on this, so the socket
                // closes now rather than whenever that task finishes.
                // `notify_one`, not `notify_waiters`: the write loop builds a
                // fresh `notified()` each pass, so a signal sent while it is
                // between iterations -- or parked in a `send` -- has to be
                // stored as a permit rather than dropped for want of a waiter.
                handle.disconnect.notify_one();
                tracing::info!(
                    id,
                    addr = %handle.info.addr_string(),
                    reason = "rpc_request",
                    "Disconnecting peer on request"
                );
                true
            }
            None => false,
        }
    }

    /// Drop every peer handle, signalling each write loop first.
    ///
    /// `clear()` alone closes a peer's `msg_rx` only when the last sender
    /// goes, and a `getcfilters` stream task can hold a clone of `msg_tx` --
    /// leaving the socket open, and the peer feeding the node, after the
    /// caller claimed to have disconnected everyone. Same reasoning as
    /// `disconnect_by_id`, applied to the disconnect-all paths (shutdown,
    /// `setnetworkactive false`).
    fn drop_all_peers(peers: &mut HashMap<PeerId, PeerHandle>) {
        for handle in peers.values() {
            handle.disconnect.notify_one();
        }
        peers.clear();
    }

    /// Get info about all peers — connected *or* still connecting — sorted by
    /// id ascending.
    ///
    /// Core's `getpeerinfo` calls `CConnman::GetNodeStats`, which walks every
    /// entry in `m_nodes` with no `fSuccessfullyConnected` filter, so a peer
    /// appears from the moment its TCP connection is accepted, before the
    /// version handshake completes. Filtering to handshaked peers hid exactly
    /// the window `feature_framework_startup_failures.py` inspects.
    ///
    /// The sort matters too: Core returns entries ordered by `CNode::GetId()`
    /// and its suite indexes `getpeerinfo()[0]` as the first-connected peer.
    /// A `HashMap` gives no ordering guarantee, so sort explicitly.
    pub fn get_peer_info(&self) -> Vec<serde_json::Value> {
        let peers = self.peers.read();
        let mut entries: Vec<_> = peers.iter().collect();
        entries.sort_by_key(|(id, _)| **id);
        // `inflight` was a hardcoded `[]`, which reads as "this peer owes us
        // nothing" — the opposite of the answer when the question is which
        // peer is stalling the download. Read once for the whole call so a
        // long peer list does not take the scheduler lock per peer.
        let ibd = self.ibd.read();
        entries
            .into_iter()
            .map(|(id, h)| {
                let inflight = ibd
                    .as_ref()
                    .map(|s| s.peer_inflight_heights(*id))
                    .unwrap_or_default();
                h.info.to_rpc_json_with_inflight(&h.stats, inflight)
            })
            .collect()
    }

    /// Process-global P2P byte totals (for `getnettotals` and metrics).
    pub fn net_totals(&self) -> &Arc<NetTotals> {
        &self.net_totals
    }

    /// Connected peers by direction, and how many run each client version,
    /// for the status page. One read of the peer table. Deliberately no
    /// addresses: the page may be served with no authentication in front of
    /// it, and who a node talks to is not something to publish.
    pub fn peer_summary(&self) -> PeerSummary {
        let peers = self.peers.read();
        let mut summary = PeerSummary::default();
        for h in peers.values() {
            if h.info.state != PeerState::Connected {
                continue;
            }
            match h.info.direction {
                Direction::Inbound => summary.inbound += 1,
                Direction::Outbound => summary.outbound += 1,
            }
            *summary.clients.entry(h.info.user_agent.clone()).or_default() += 1;
        }
        summary
    }

    /// The initial-block-download ETA, in seconds, while the download
    /// scheduler is running and has an estimate. The same figure
    /// `getibdprogress` reports as `eta_secs`, without building that call's
    /// block bitmap.
    pub fn ibd_eta_secs(&self) -> Option<u64> {
        if self.ibd.read().is_none() {
            return None;
        }
        match self.ibd_eta_secs.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            secs => Some(secs),
        }
    }

    /// Get connection count.
    pub fn connection_count(&self) -> usize {
        // Core walks one set for both `getconnectioncount` and
        // `getpeerinfo` (`m_nodes`), so the count and the list agree.
        // Filtering on `Connected` here while `get_peer_info` lists every
        // state made them disagree for as long as a handshake was in
        // flight — which is exactly when a caller polling both notices.
        self.peers.read().len()
    }

    /// Number of connected peers using the BIP 324 v2 encrypted transport.
    pub fn connection_count_v2(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| h.info.state == PeerState::Connected && h.info.transport.is_v2())
            .count()
    }

    /// Get IBD download progress for the TUI dashboard.
    pub fn get_ibd_progress(&self) -> Option<serde_json::Value> {
        let ibd = self.ibd.read();
        let scheduler = ibd.as_ref()?;
        let (downloaded, in_flight, pending, target) = scheduler.progress();
        let cursor = scheduler.connect_cursor();
        let (mut bitmap, bitmap_sampled) = scheduler.block_bitmap();
        let peer_stats = scheduler.peer_stats();
        drop(ibd); // Release scheduler lock before checking chain state

        // Fix display: blocks stored on disk but no longer tracked by the scheduler
        // (downloaded, connected, and removed from scheduler sets) show as state 0.
        // Upgrade them to state 3 (downloaded) if the block data exists.
        let bitmap_start = cursor + 1;
        let total = bitmap.len();
        if total > 0 {
            let step = if bitmap_sampled {
                let range = target.saturating_sub(bitmap_start) + 1;
                range as f64 / total as f64
            } else {
                1.0
            };
            for (i, state) in bitmap.iter_mut().enumerate() {
                if *state == 0 {
                    let h = bitmap_start + (i as f64 * step) as u32;
                    if let Some(hash) = self.chain_state.get_block_hash_by_height(h)
                        && self.chain_state.has_block_data(&hash)
                    {
                        *state = 3; // stored on disk
                    }
                }
            }
        }

        let bitmap_b64 = base64::engine::general_purpose::STANDARD.encode(&bitmap);

        let eta = self.ibd_eta_secs.load(std::sync::atomic::Ordering::Relaxed);

        Some(serde_json::json!({
            "active": true,
            "connect_cursor": cursor,
            "target_height": target,
            "downloaded": downloaded,
            "in_flight": in_flight,
            "pending": pending,
            "bitmap": bitmap_b64,
            "bitmap_start": cursor + 1,
            "bitmap_sampled": bitmap_sampled,
            "eta_secs": eta,
            "peer_download_stats": peer_stats.iter().map(|(id, recv, assigned)| {
                serde_json::json!({"peer_id": id, "blocks_received": recv, "assigned": assigned})
            }).collect::<Vec<_>>(),
        }))
    }

    /// Get the list of currently banned addresses with expiry times.
    pub fn list_banned(&self) -> Vec<serde_json::Value> {
        let now = crate::time::now_secs();
        let ban_list = self.ban_list.read();
        ban_list
            .list(now)
            .into_iter()
            .map(|entry| {
                serde_json::json!({
                    "address": entry.address,
                    "ban_created": entry.ban_created,
                    "banned_until": entry.banned_until,
                    "ban_duration": entry.ban_duration(),
                    "time_remaining": entry.time_remaining(now),
                    "ban_reason": "node misbehaving",
                })
            })
            .collect()
    }

    /// Ban or unban a subnet. Called from the `setban` RPC.
    ///
    /// On `add`, also disconnects every currently-connected peer whose IP
    /// falls within the banned subnet, matching Core's behaviour.
    pub fn set_ban_subnet(
        &self,
        target: &crate::net::ban::BanTarget,
        add: bool,
        ban_created: u64,
        banned_until: u64,
    ) -> Result<(), String> {
        if add {
            self.ban_list
                .write()
                .add(target, ban_created, banned_until)?;
            self.flush_banlist();
            // Disconnect any connected peer whose IP falls within the ban.
            self.disconnect_banned_peers(target);
        } else {
            self.ban_list.write().remove(target)?;
            self.flush_banlist();
        }
        Ok(())
    }

    /// Core's `setban add` duplicate pre-check. Separate from
    /// [`crate::net::ban::BanList::add`] because the automatic misbehaviour
    /// path must be able to re-arm and extend bans, while an operator asking
    /// twice gets `-23`.
    pub fn is_already_banned(&self, target: &crate::net::ban::BanTarget, is_subnet: bool) -> bool {
        self.ban_list
            .read()
            .already_banned(target, is_subnet, crate::time::now_secs())
    }

    /// Disconnect every peer whose IP falls within `target`.
    fn disconnect_banned_peers(&self, target: &crate::net::ban::BanTarget) {
        let ids_to_disconnect: Vec<u64> = {
            let peers = self.peers.read();
            peers
                .iter()
                .filter_map(|(id, handle)| {
                    if target.contains_addr(&handle.info.addr.ip()) {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect()
        };
        for id in ids_to_disconnect {
            self.disconnect_by_id(id);
        }
    }

    /// Clear all bans.
    pub fn clear_banned(&self) {
        self.ban_list.write().clear();
        self.flush_banlist();
    }

    /// Load the ban list from `banlist.json` in `dir`. Returns whether the
    /// database had to be recreated (caller logs Core's "Recreating the
    /// banlist database") and, if so, why.
    ///
    /// This cannot fail. Core's `BanMan` constructor is `LoadBanlist();
    /// DumpBanlist();` — an unreadable list is recreated, never a reason to
    /// stop persisting. The old signature returned `Result`, and the caller
    /// answered an `Err` by leaving the manager holding a default `BanList`
    /// with no path, so every subsequent `setban` vanished on restart with no
    /// error at any point.
    pub fn load_banlist(&self, dir: &std::path::Path) -> (bool, Option<String>) {
        let path = dir.join("banlist.json");
        let (mut list, recreated, why) = crate::net::ban::BanList::load(&path);
        // Prune expired bans from the loaded list using the current node
        // clock (which may be mocktime).
        let now = crate::time::now_secs();
        list.prune_expired(now);
        *self.ban_list.write() = list;
        // Core dumps immediately after loading, which is what writes the file
        // for a fresh datadir and rewrites a recreated one.
        self.flush_banlist();
        (recreated, why)
    }

    /// Core's `BanMan::DumpBanlist`: take the dump mutex, snapshot the list
    /// under the ban-list lock, release *that* lock, then write. On a failed
    /// write the list is marked dirty again so the next flush retries.
    ///
    /// Two locks, each doing one job. `banlist_dump` orders whole dumps
    /// against each other, so a snapshot can never be written out of order
    /// with respect to a newer one (see its declaration). `ban_list` is
    /// released before the write so a concurrent `is_addr_banned` — on the
    /// inbound-accept path — does not wait on a disk write.
    ///
    /// The write is still a blocking syscall on whichever thread calls this,
    /// which for the automatic-ban path is the manager event loop. That is
    /// unchanged by this split and is a separate problem.
    pub fn flush_banlist(&self) {
        let _dumping = self.banlist_dump.lock();
        let pending = self.ban_list.write().take_pending_dump();
        let Some((path, json)) = pending else {
            return;
        };
        if let Err(e) = crate::net::ban::write_banlist(&path, &json) {
            tracing::warn!("Failed to write banlist {}: {e}", path.display());
            self.ban_list.write().mark_dirty();
        }
    }

    /// Queue a message of any type to one fully connected peer: Core's hidden
    /// `sendmsgtopeer`. The caller has already bounded `msg_type` to the
    /// 12-byte header field. Returns false if the peer is not connected or its
    /// send queue is full.
    pub fn send_raw_message(&self, id: PeerId, msg_type: &str, payload: Vec<u8>) -> bool {
        let Ok(command) = bitcoin::p2p::message::CommandString::try_from(msg_type.to_string()) else {
            return false;
        };
        let peers = self.peers.read();
        match peers.get(&id) {
            Some(handle) if handle.info.state == PeerState::Connected => handle
                .msg_tx
                .try_send(NetworkMessage::Unknown { command, payload })
                .is_ok(),
            _ => false,
        }
    }

    /// Core's `RejectIncomingTxs`: whether a transaction or transaction inv
    /// from `id` is a protocol violation. A block-relay-only link never
    /// carries them; on a `-blocksonly` node only a peer with `relay`
    /// permission may send them.
    fn rejects_incoming_txs(&self, id: PeerId) -> bool {
        let (conn_type, permissions) = {
            let peers = self.peers.read();
            match peers.get(&id) {
                Some(h) => (h.info.conn_type, h.info.permissions),
                None => return false,
            }
        };
        if conn_type == ConnType::BlockRelay {
            return true;
        }
        if permissions.relays_txes() {
            return false;
        }
        self.blocksonly()
    }

    /// The `feefilter` to send `id` now, Core's `MaybeSendFeefilter`: none to
    /// a peer we take no transactions from (`-blocksonly`, a block-relay-only
    /// or feeler link) or one with `forcerelay`; while in initial block
    /// download the largest filter, so no peer sends transactions we would
    /// not validate; otherwise the relay floor, rounded to a coarse bucket so
    /// the value does not fingerprint the mempool.
    fn fee_filter_for(&self, id: PeerId) -> Option<u64> {
        if self.blocksonly() {
            return None;
        }
        let (conn_type, permissions) = {
            let peers = self.peers.read();
            let h = peers.get(&id)?;
            (h.info.conn_type, h.info.permissions)
        };
        if !conn_type.wants_tx_relay() || permissions.force_relay {
            return None;
        }
        let min_relay = self.mempool.min_fee_rate();
        // Core's `currentFilter = m_mempool.GetMinFee()`: a full pool that has
        // evicted its way to a higher floor tells its peers so, instead of
        // inviting transactions it is about to reject. The static relay floor
        // is applied below, after rounding, exactly as Core clamps
        // `filterToSend`.
        let current = if self.chain_state.is_initial_block_download() {
            MAX_MONEY_SATS
        } else {
            self.mempool.min_fee()
        };
        let rounded = fee_filter_round(
            current,
            self.mempool.policy().incremental_relay_fee,
            rand::random::<u32>(),
        );
        Some(rounded.max(min_relay))
    }

    /// Re-send `feefilter` where the value a peer holds is out of date: at
    /// once when the node leaves or re-enters initial block download, and
    /// when the floor has moved outside Core's 3/4..4/3 band.
    fn maybe_send_fee_filters(&self) {
        let ids: Vec<(PeerId, Option<u64>)> = self
            .peers
            .read()
            .iter()
            .filter(|(_, h)| h.info.state == PeerState::Connected && h.fee_filter_sent.is_some())
            .map(|(id, h)| (*id, h.fee_filter_sent))
            .collect();
        let ibd = self.chain_state.is_initial_block_download();
        let max_filter = fee_filter_round(MAX_MONEY_SATS, self.mempool.policy().incremental_relay_fee, 0);
        for (id, sent) in ids {
            let Some(sent) = sent else { continue };
            let stale = if ibd {
                sent != max_filter
            } else if sent == max_filter {
                true
            } else {
                let current = self.mempool.min_fee().max(self.mempool.min_fee_rate());
                current * 4 < sent * 3 || current * 3 > sent * 4
            };
            if !stale {
                continue;
            }
            if let Some(rate) = self.fee_filter_for(id)
                && self.send_to_peer(id, NetworkMessage::FeeFilter(rate as i64))
                && let Some(h) = self.peers.write().get_mut(&id)
            {
                h.fee_filter_sent = Some(rate);
            }
        }
    }

    /// Record a peer's BIP 133 `feefilter`.
    ///
    /// The message carries an `i64`; a negative value clamps to 0 (pass
    /// everything, Core's signed comparison) rather than wrapping through
    /// `as u64` into a filter that drops every announcement.
    fn set_peer_fee_filter(&self, id: PeerId, rate: i64) {
        if let Some(handle) = self.peers.write().get_mut(&id) {
            handle.info.fee_filter = rate.max(0) as u64;
            tracing::debug!(id, rate, "Peer set fee filter");
        }
    }

    /// Send a ping to all connected peers.
    ///
    /// Registered with the peer's counters exactly as a keepalive ping is, so
    /// the `ping` RPC populates `pingtime` -- in Core the RPC and the
    /// keepalive share one timer, and a pong that nothing is waiting for is
    /// discarded. A peer already awaiting a pong is left alone rather than
    /// handed a second nonce, which would reset its `pingwait` and hide the
    /// ping that actually went unanswered.
    pub fn ping_all(&self) {
        let peers = self.peers.read();
        for (_, handle) in peers.iter() {
            if handle.info.state == PeerState::Connected {
                // Best-effort skip; the authoritative accounting happens on
                // the peer's task. Recording `ping_sent` here — on the RPC
                // task — raced the write loop: the queued ping could be
                // transmitted and answered before this task stored its nonce,
                // and a pong that arrives before its ping is marked
                // outstanding is discarded. The nonce then stays outstanding
                // forever and the peer is dropped at PING_TIMEOUT for failing
                // to answer a ping it answered. The write loop records the
                // nonce when it actually transmits the message, on the same
                // task that matches the pong, so no ordering is left to
                // scheduling.
                if handle.stats.ping_outstanding() {
                    continue;
                }
                // Nonce 0 is the "nothing outstanding" sentinel; Core
                // likewise re-rolls until the nonce is non-zero. A full queue
                // drops the message, which is safe precisely because nothing
                // is recorded until the write loop transmits it.
                let nonce = rand::random::<u64>().max(1);
                let _ = handle.msg_tx.try_send(NetworkMessage::Ping(nonce));
            }
        }
    }

    /// Get the list of addnode-registered peers, matching Core's
    /// `getaddednodeinfo` output. Returns the original user-provided
    /// address string (without port normalisation) as `addednode`.
    pub fn get_added_node_info(&self) -> Vec<serde_json::Value> {
        let peers = self.peers.read();
        let entries = self.addnode_entries.read();

        let mut out: Vec<serde_json::Value> = Vec::new();

        for entry in entries.iter().filter(|e| e.listed) {
            let connected = match &entry.resolved {
                Some(PeerAddr::Socket(sa)) => peers.values().any(|h| {
                    h.info.addr == *sa && h.info.state == PeerState::Connected
                }),
                Some(PeerAddr::Onion { host, .. }) => peers.values().any(|h| {
                    h.info.onion_host.as_deref() == Some(host.as_str())
                        && h.info.state == PeerState::Connected
                }),
                None => false,
            };
            // Core (`rpc/net.cpp` getaddednodeinfo) lists an address only
            // for a connected node, and then the address it connected to,
            // so a name that has not resolved reads as not connected with
            // no addresses.
            let addresses = match (&entry.resolved, connected) {
                (Some(a), true) => serde_json::json!([{
                    "address": a.to_string(),
                    "connected": "outbound",
                }]),
                _ => serde_json::json!([]),
            };
            out.push(serde_json::json!({
                "addednode": entry.target,
                "connected": connected,
                "addresses": addresses,
            }));
        }

        out
    }

    /// Check if we are in Initial Block Download.
    /// True when our validated tip is more than 24 blocks behind the highest
    /// header height received from peers, or when no headers have been received.
    fn is_ibd(&self) -> bool {
        let tip = self.chain_state.tip_height();
        // The best header is at least our own tip. `headers_tip` only moves
        // when a peer sends headers, so a node that mined its own chain still
        // reads 0 there; taken alone, that node would count itself in IBD
        // forever and ignore every transaction a peer announces.
        let htip = (self.headers_tip.load(Ordering::Relaxed) as u32).max(tip);
        htip == 0 || tip + 24 < htip
    }

    /// Whether the node is actively catching up to a known headers tip.
    /// Unlike [`is_ibd`](Self::is_ibd), "no headers heard yet" (`htip == 0`)
    /// does NOT count: that's the state of an isolated node (fresh regtest,
    /// no peers yet) — exactly the node whose pending local broadcasts must
    /// still go out when a peer finally appears. Used to suppress the
    /// unbroadcast announce paths only while genuinely syncing (peers don't
    /// want tx invs mid-IBD, and the mempool can't validate then anyway).
    fn is_actively_syncing(&self) -> bool {
        let tip = self.chain_state.tip_height();
        let htip = self.headers_tip.load(Ordering::Relaxed) as u32;
        tip + 24 < htip
    }

    /// Check if we already have a connection to this address.
    fn is_addr_connected(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read();
        peers
            .values()
            .any(|h| h.info.addr == *addr && h.info.state != PeerState::Disconnected)
    }

    /// Whether we already hold (or are mid-handshake on) a connection to the
    /// given `.onion` host. The onion analogue of `is_addr_connected`, needed
    /// because all onion peers share the `0.0.0.0` placeholder socket.
    fn is_onion_connected(&self, host: &str) -> bool {
        Self::onion_connected_in(&self.peers.read(), host)
    }

    /// How many new onion dials the reconnect loop may start this tick: the
    /// open outbound slots (counting in-flight dials, which `outbound_count`
    /// excludes because they aren't `Connected` yet) capped by the per-tick
    /// burst limit. Without counting `in_flight`, a single tick could spawn a
    /// dial for every gossip-discovered onion at once.
    fn onion_dial_budget(target: usize, outbound: usize, in_flight: usize) -> usize {
        target
            .saturating_sub(outbound + in_flight)
            .min(MAX_ONION_DIALS_PER_TICK)
    }

    /// Pure predicate behind `is_onion_connected`, factored out for testing.
    fn onion_connected_in(peers: &HashMap<PeerId, PeerHandle>, host: &str) -> bool {
        peers.values().any(|h| {
            h.info.onion_host.as_deref() == Some(host)
                && h.info.state != PeerState::Disconnected
        })
    }

    /// Check if an address is currently banned.
    fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        let now = crate::time::now_secs();
        self.ban_list.read().is_banned(&addr.ip(), now)
    }

    /// Add ban score to a peer. If the score exceeds BAN_THRESHOLD, the peer
    /// is disconnected, removed, and its address is banned.
    fn add_ban_score(&self, id: PeerId, score: u32, reason: &str) {
        let mut peers = self.peers.write();
        let (should_ban, ban_addr) = if let Some(handle) = peers.get_mut(&id) {
            // NoBan peers (-whitelist/-whitebind) are never banned or
            // disconnected for misbehavior.
            if handle.info.permissions.noban {
                tracing::debug!(id, addr = %handle.info.addr, reason, "Skipping ban score for noban peer");
                return;
            }
            handle.info.ban_score += score;
            if handle.info.ban_score >= BAN_THRESHOLD {
                tracing::warn!(id, addr = %handle.info.addr, score = handle.info.ban_score, reason, "Banning peer");
                (true, Some(handle.info.addr.ip()))
            } else {
                tracing::debug!(id, score = handle.info.ban_score, reason, "Increased ban score");
                (false, None)
            }
        } else {
            (false, None)
        };
        if should_ban {
            // Signal, for the same reason `disconnect_by_id` does: dropping
            // the handle closes the peer task's `msg_rx` only when the last
            // sender goes, and a `getcfilters` stream task can hold a clone.
            // Without the signal a banned peer stayed connected -- and kept
            // feeding the node -- until that task drained.
            if let Some(handle) = peers.remove(&id) {
                handle.disconnect.notify_one();
            }
            if let Some(addr) = ban_addr {
                drop(peers); // release peers lock before acquiring ban_list lock
                let now = crate::time::now_secs();
                let duration = self.ban_duration_secs.load(Ordering::Relaxed);
                let target = crate::net::ban::BanTarget::Net(
                    ipnet::IpNet::from(addr),
                );
                // Best-effort: misbehaviour bans are fire-and-forget; if the
                // entry already exists (e.g. repeated misbehaviour) the add
                // fails silently.
                let _ = self.ban_list.write().add(&target, now, now + duration);
                self.flush_banlist();
            }
        }
    }

    /// Run the main event loop. Returns when shutdown signal is received.
    pub async fn run(self: &Arc<Self>) {
        let mut event_rx = self.event_rx.lock().await;
        let mut sync_interval = tokio::time::interval(MAINTENANCE_INTERVAL);
        // A busy queue skips the waits that consume ticks. When it quiets,
        // one late tick is enough: a burst of them would run maintenance back
        // to back.
        sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tip: u32 = 0;
        let mut ticks: u64 = 0;
        let shutdown = self.shutdown.clone();
        // Maintain, drain again, or wait: see `DrainPacer`.
        let mut pacer = DrainPacer::default();

        loop {
            // Manager-loop heartbeat: bumped on every iteration so the
            // stall watchdog has a "loop is alive" signal that is
            // independent of block arrivals. At mainnet tip the
            // connector heartbeat can be quiet for >10 min between
            // blocks, but this counter keeps ticking every ~500 ms as
            // long as the manager loop and tokio runtime are healthy.
            self.chain_state.bump_manager_heartbeat();

            // Check for shutdown
            if *shutdown.borrow() {
                tracing::info!("P2P manager shutting down");
                // Drop all peers to close connections
                Self::drop_all_peers(&mut self.peers.write());
                return;
            }
            // Process up to 64 events per iteration, then yield for sync
            let mut processed = 0;
            loop {
                if processed >= EVENTS_PER_DRAIN {
                    break;
                }
                match event_rx.try_recv() {
                    Ok(NetEvent::PeerConnected { id, addr: _, version }) => {
                        self.handle_peer_connected(id, version);
                    }
                    Ok(NetEvent::PeerDisconnected { id }) => {
                        self.handle_peer_disconnected(id);
                    }
                    Ok(NetEvent::GetDataResume { id }) => {
                        self.resume_getdata(id);
                    }
                    Ok(NetEvent::MessageReceived { id, msg }) => {
                        // The socket task counted this message in as it was
                        // handed over; the guard counts it out once the work
                        // is done, which is what a parked pong waits for.
                        let guard = crate::net::flow::InFlight::adopt(self.peer_flow(id));
                        self.handle_message(id, msg, guard);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return,
                }
                processed += 1;
            }

            // The cap above is a fairness yield, not a rate limit. Leaving a
            // full queue to wait out the 500 ms interval caps every inbound
            // path at `EVENTS_PER_DRAIN` messages per tick, which during
            // initial block download is the whole of the node's throughput: a
            // 999-block regtest sync from one peer ran at 16 blocks a second
            // on a loopback socket, the peer idle between bursts, and timed
            // out the 60-second wait in Core's `p2p_blockfilters`. So when the
            // queue was still full, come straight back to it.
            //
            // The maintenance below runs on time regardless, at most one
            // drain late, so stall detection, fee filters and the rest keep
            // their cadence under sustained load (#909).
            let now = Instant::now();
            match pacer.after_drain(processed, now) {
                AfterDrain::DrainAgain => {
                    tokio::task::yield_now().await;
                    continue;
                }
                AfterDrain::Wait => {
                    tokio::select! {
                        _ = sync_interval.tick() => pacer.ticked(),
                        _ = self.drain_now.notified() => {}
                    }
                    continue;
                }
                AfterDrain::Maintain => pacer.maintained(now),
            }

            // Check sync progress and request more blocks
            let tip = self.chain_state.tip_height();
            let _htip = self.headers_tip.load(Ordering::Relaxed) as u32;

            // When chain advances, immediately request more blocks (don't wait for timer)
            let tip_advanced = tip != last_tip;
            if tip_advanced {
                last_tip = tip;
                // Reset reconnect backoff on chain progress
                let mut backoff = self.reconnect_backoff.write();
                for state in backoff.values_mut() {
                    state.reset();
                }
            }

            // IBD scheduler maintenance
            let has_ibd = self.ibd.read().is_some();
            if has_ibd {
                // Every 4 ticks (2s): stall detection and reassignment
                if ticks.is_multiple_of(4) {
                    let (stalled, stale_heights, silent) = {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            let stalled = scheduler.detect_stalls(Duration::from_secs(15));
                            // Per-height timeout: catch heights stuck with an active peer
                            let stale = scheduler.release_stale_inflight(
                                Duration::from_secs(60),
                                Duration::from_secs(15),
                            );
                            // Silent peers are scanned AFTER releases so a
                            // peer that hit its third release on this pass
                            // gets dropped on the same tick.
                            let silent = scheduler.silent_peers(
                                crate::net::ibd::SILENT_PEER_FAILURE_THRESHOLD,
                            );
                            (stalled, stale, silent)
                        } else {
                            (Vec::new(), 0, Vec::new())
                        }
                    };
                    for peer_id in stalled {
                        tracing::debug!(peer_id, "IBD: peer stalled, reassigning blocks");
                    }
                    if stale_heights > 0 {
                        tracing::info!(stale_heights, "IBD: stale in-flight heights returned to pending");
                    }
                    for peer_id in silent {
                        let addr = self
                            .peers
                            .read()
                            .get(&peer_id)
                            .map(|h| h.info.addr.to_string())
                            .unwrap_or_else(|| "<gone>".to_string());
                        tracing::warn!(
                            peer_id,
                            addr = %addr,
                            "IBD: dropping silent peer — repeatedly failed to deliver assigned blocks"
                        );
                        // Reuse the normal disconnect flow so the scheduler
                        // gets its in-flight heights back via peer_disconnected.
                        self.handle_peer_disconnected(peer_id);
                    }
                    // A header accepted off the P2P path (`submitheader`)
                    // rewrites rows without passing through `handle_headers`.
                    self.apply_header_row_changes();
                    // Assign work to any idle peers
                    self.assign_all_peers();
                }

                // Every 20 ticks (10s): progress logging
                if ticks.is_multiple_of(20) {
                    let (cursor, target) = {
                        let ibd = self.ibd.read();
                        match ibd.as_ref() {
                            Some(s) => (s.connect_cursor(), s.target_height()),
                            None => (0, 0),
                        }
                    };
                    let (dl, inf, pend, _) = {
                        let ibd = self.ibd.read();
                        ibd.as_ref()
                            .map(|s| s.progress())
                            .unwrap_or((0, 0, 0, 0))
                    };
                    let peers_active = self.connection_count();
                    // "stored" is the count of blocks already connected,
                    // which is exactly `connect_cursor`. The prior formula
                    // `target - dl - inf - pend` (plus dl) underflowed when
                    // pending and downloaded overlapped: the priority-zone
                    // scan does not pop from pending, so an assigned and
                    // then delivered height can appear in both `downloaded`
                    // and `pending` simultaneously, making the subtraction
                    // wrap below zero. That panic crashed the sync loop and
                    // wedged IBD with the trailing blocks unrequested.
                    tracing::info!(
                        "IBD download: {}/{} stored, {} in-flight, {} pending, {} peers",
                        cursor,
                        target,
                        inf,
                        pend,
                        peers_active
                    );
                    let _ = dl; // retained for future per-tick stats
                }
            }

            // AssumeUTXO background catch-up: drive downloading historical
            // block data (genesis→snapshot_height) for the background
            // validator. Independent of forward IBD — the background range
            // is below the primary tip, which the forward scheduler never
            // requests. Runs every 4 ticks (2s) whenever a background
            // chainstate is attached; idles (and frees the tracker) once
            // handoff completes.
            if ticks.is_multiple_of(4) {
                self.drive_bg_catchup_download();
            }

            // Request blocks: immediately on tip advance, or every 10 ticks as fallback
            // Skip during IBD swarming — the scheduler handles block requests
            if !has_ibd && (tip_advanced || ticks.is_multiple_of(10)) {
                // First chance to re-arm bulk IBD without an inbound headers
                // message (issue #582): if the connector tore down short of
                // headers we already hold, re-create the scheduler here
                // instead of parking until a peer announces the next block.
                // When it fires, the scheduler owns block requests; the
                // per-peer fallback below is for the steady-state gap.
                if !self.maybe_start_ibd() {
                    let peer_ids: Vec<PeerId> = {
                        let peers = self.peers.read();
                        peers.iter()
                            .filter(|(_, h)| {
                                h.info.state == PeerState::Connected && h.info.serves_blocks()
                            })
                            .map(|(id, _)| *id)
                            .collect()
                    };
                    for pid in &peer_ids {
                        self.request_missing_blocks(*pid);
                    }
                }
            }

            // Request headers: during IBD, request every 4 ticks (2s) from a few peers.
            // Requesting from ALL peers floods them and triggers rate limits.
            if self.is_ibd() && ticks.is_multiple_of(4) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(_, h)| {
                            h.info.state == PeerState::Connected && h.info.serves_blocks()
                        })
                        .map(|(id, _)| *id)
                        .take(3)
                        .collect()
                };
                for pid in &peer_ids {
                    self.send_to_peer(*pid, sync::make_getheaders(&self.chain_state));
                }
            } else if !self.is_ibd() && ticks.is_multiple_of(20) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(_, h)| {
                            h.info.state == PeerState::Connected && h.info.serves_blocks()
                        })
                        .map(|(id, _)| *id)
                        .collect()
                };
                for pid in &peer_ids {
                    self.send_to_peer(*pid, sync::make_getheaders(&self.chain_state));
                }
            }

            ticks += 1;

            // Bring stale fee filters up to date every 4 ticks (2 seconds),
            // and on the tick the tip moves: that is when the node leaves
            // IBD, and a peer still holding the IBD maximum filters out every
            // transaction it would announce to us. Core sends that update at
            // once (`m_next_send_feefilter = 0` after `MAX_FILTER`).
            if tip_advanced || ticks.is_multiple_of(4) {
                self.maybe_send_fee_filters();
            }

            // Every 60 ticks (30 seconds), expire old mempool transactions
            // and sweep expired orphans.
            if ticks.is_multiple_of(60) {
                self.mempool.remove_expired();
                let expired = self.orphanage.expire(Instant::now());
                if !expired.is_empty() {
                    tracing::debug!(count = expired.len(), "Expired orphan transactions");
                }
            }

            // Every 20 ticks (10 seconds), reconnect if below outbound target.
            // Skipped entirely while networking is paused (`networkactive=0` /
            // `setnetworkactive false`): otherwise each tick would spawn dials
            // that immediately fail the gate, churning backoff state and logs.
            // Named peers are looked up again on the same tick, whatever the
            // outbound count: an added node is a manual connection, which
            // Core dials outside the outbound target.
            if ticks.is_multiple_of(20)
                && self.is_network_active()
                && self.manual_targets_due(Instant::now())
            {
                tokio::spawn(Arc::clone(self).refresh_manual_targets());
            }
            if ticks.is_multiple_of(20) && self.is_network_active() {
                let outbound = self.outbound_count();
                let target = if self.is_ibd() { MAX_OUTBOUND_IBD } else { MAX_OUTBOUND };
                let need_peers = outbound < target;
                if need_peers {
                    // The peers the operator named first, then those the node
                    // learned. An address on both lists is offered once, and
                    // `spawn_peer` makes it the manual connection it is: Core
                    // makes no automatic connection to an added node
                    // (`AddedNodesContain`, v31.1 `src/net.cpp:2883`).
                    let manual: HashSet<SocketAddr> = self.manual_addrs.read().clone();
                    let learned: Vec<SocketAddr> = self
                        .learned_addrs
                        .read()
                        .iter()
                        .filter(|a| !manual.contains(a))
                        .copied()
                        .collect();
                    let addrs: Vec<SocketAddr> = manual.into_iter().chain(learned).collect();

                    let now = Instant::now();

                    // Clean expired bans
                    {
                        let now_secs = crate::time::now_secs();
                        self.ban_list.write().prune_expired(now_secs);
                        self.flush_banlist();
                    }

                    for addr in addrs {
                        // Under `-connect`, only the peers the operator named.
                        if !self.may_dial(&addr) {
                            continue;
                        }
                        // Skip if already connected
                        if self.is_addr_connected(&addr) {
                            continue;
                        }
                        // Skip if banned
                        if self.is_addr_banned(&addr) {
                            continue;
                        }
                        // Check backoff timer
                        {
                            let backoff = self.reconnect_backoff.read();
                            if let Some(state) = backoff.get(&addr)
                                && now < state.next_attempt {
                                    continue;
                                }
                        }

                        // Don't exceed target
                        if self.check_outbound_limit().is_err() {
                            break;
                        }

                        let pm = Arc::clone(self);
                        tokio::spawn(async move {
                            match pm.connect_outbound(addr).await {
                                Ok(_) => {
                                    let mut backoff = pm.reconnect_backoff.write();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .reset();
                                }
                                Err(e) => {
                                    tracing::debug!(%addr, "Reconnect failed: {}", e);
                                    let mut backoff = pm.reconnect_backoff.write();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .record_failure();
                                }
                            }
                        });
                    }

                    // Also reconnect .onion peers — with the same discipline the
                    // clearnet loop above has. `connect_peer_addrs` is fillable
                    // from untrusted addrv2 gossip (up to MAX_ONION_CONNECT_ADDRS),
                    // so spawning a dial per entry with no cap would let one peer
                    // drive hundreds of concurrent SOCKS dials through the single
                    // proxy every tick. Bound new dials this tick by the open
                    // slot budget (counting in-flight dials, which
                    // `outbound_count()` excludes) and a per-tick burst cap; skip
                    // already-connected / in-flight hosts; and back off failures
                    // (onion-host-keyed, since `reconnect_backoff` is SocketAddr-
                    // keyed).
                    let onion_addrs = self.connect_peer_addrs.read().clone();
                    let mut budget = Self::onion_dial_budget(
                        target,
                        self.outbound_count(),
                        self.pending_onion_dials.read().len(),
                    );
                    for peer_addr in onion_addrs {
                        if budget == 0 {
                            break;
                        }
                        // Under `-connect`, only the peers the operator named.
                        let manual = match &peer_addr {
                            PeerAddr::Onion { host, .. } => {
                                self.manual_onion_hosts.read().contains(host)
                            }
                            PeerAddr::Socket(sa) => self.manual_addrs.read().contains(sa),
                        };
                        if !manual && !self.automatic_outbound.load(Ordering::Relaxed) {
                            continue;
                        }
                        let already = match &peer_addr {
                            PeerAddr::Onion { host, .. } => {
                                self.is_onion_connected(host)
                                    || self.pending_onion_dials.read().contains(host)
                            }
                            PeerAddr::Socket(sa) => self.is_addr_connected(sa),
                        };
                        if already {
                            continue;
                        }
                        let key = peer_addr.to_string();
                        {
                            let backoff = self.onion_reconnect_backoff.read();
                            if let Some(state) = backoff.get(&key)
                                && now < state.next_attempt
                            {
                                continue;
                            }
                        }
                        budget -= 1;
                        let pm = Arc::clone(self);
                        tokio::spawn(async move {
                            let key = peer_addr.to_string();
                            match pm.connect_peer_addr_automatic(&peer_addr).await {
                                Ok(_) => {
                                    pm.onion_reconnect_backoff
                                        .write()
                                        .entry(key)
                                        .or_insert_with(ReconnectState::new)
                                        .reset();
                                }
                                Err(e) => {
                                    tracing::debug!(%peer_addr, "Onion reconnect failed: {}", e);
                                    pm.onion_reconnect_backoff
                                        .write()
                                        .entry(key)
                                        .or_insert_with(ReconnectState::new)
                                        .record_failure();
                                }
                            }
                        });
                    }
                }
            }

            // Drop addr-fetch connections whose peer never sent a usable
            // `addr`. Read through the node clock, not the wall clock, so
            // `setmocktime` moves the deadline the way it does in Core.
            if ticks.is_multiple_of(2) {
                self.expire_addr_fetch_peers();
                self.expire_compact_state();
            }

            // Back to a queue the last drain left full. Otherwise yield to
            // the tokio runtime, waking early when a peer is waiting on the
            // drain above to answer a ping.
            if processed >= EVENTS_PER_DRAIN {
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    _ = sync_interval.tick() => pacer.ticked(),
                    _ = self.drain_now.notified() => {}
                }
            }
        }
    }

    fn handle_peer_connected(&self, id: PeerId, version: VersionMessage) {
        {
            let mut peers = self.peers.write();
            if let Some(handle) = peers.get_mut(&id) {
                handle.info.set_version(version);
                handle.info.state = PeerState::Connected;
                // Promote to the tried table in the persistent address book,
                // but only for outbound peers: their address is one we dialed
                // and can dial again. An inbound peer's address is its
                // ephemeral source port, which is not re-dialable and would
                // only pollute (and, unbounded, bloat) the table.
                // Onion peers carry the 0.0.0.0 placeholder socket, not a
                // re-dialable clearnet addr — marking it good would pollute the
                // addrman (and conflate every onion peer). Skip them.
                if handle.info.direction == Direction::Outbound && handle.info.onion_host.is_none() {
                    self.addrman.write().mark_good(handle.info.addr, now_unix_secs());
                }
                tracing::info!(
                    id,
                    addr = %handle.info.addr,
                    user_agent = %handle.info.user_agent,
                    height = handle.info.best_height,
                    "Peer connected"
                );
            }
        }
        // Assign IBD work to the new peer
        let has_ibd = self.ibd.read().is_some();
        if has_ibd {
            self.assign_peer_work(id);
        }

        // Re-announce any pending local broadcasts to the freshly-connected
        // peer, so a tx submitted while we had no (fee-permitting) peers
        // reaches the network as soon as one arrives. Suppressed while
        // actively syncing (peers don't want tx invs mid-IBD) — but NOT for
        // an isolated node that simply hasn't heard headers yet, which is
        // precisely the "first peer finally arrived" case this exists for.
        if !self.is_actively_syncing() {
            self.announce_unbroadcast_to_peer(id);
        }
    }

    fn handle_peer_disconnected(&self, id: PeerId) {
        let mut peers = self.peers.write();
        if let Some(handle) = peers.remove(&id) {
            tracing::info!(id, addr = %handle.info.addr, "Peer disconnected");
            tracing::debug!("Cleared nodestate for peer={id}");
        }
        drop(peers);
        // Notify IBD scheduler so in-flight blocks get reassigned
        let mut ibd = self.ibd.write();
        if let Some(scheduler) = ibd.as_mut() {
            scheduler.peer_disconnected(id);
        }
        drop(ibd);
        // Return the peer's background-range requests to the pool so they
        // re-request promptly rather than waiting out the stale timeout.
        self.bg_downloader.write().note_peer_gone(id);
        // A departed peer's partial compact block can never be completed,
        // and its requests will never be answered.
        self.pending_compact.write().remove(&id);
        self.hb_peers.lock().retain(|p| *p != id);
        self.in_flight_blocks.write().remove(&id);
    }

    /// `in_flight` is this message's place in the peer's queue: the socket
    /// task counted it in, and dropping the guard counts it out. Arms that
    /// finish their work here let it drop at the end of the call; the block
    /// path hands it down the pipeline so the count stays up until the block
    /// is connected, rejected, or dropped. See [`crate::net::flow`].
    fn handle_message(
        &self,
        id: PeerId,
        msg: NetworkMessage,
        in_flight: crate::net::flow::InFlight,
    ) {
        match msg {
            // Neither `Ping` nor `Pong` reaches here: the peer's write loop
            // answers the one and matches the other against that peer's
            // outstanding ping, on the peer's own task.
            NetworkMessage::Ping(_) => {}
            // `Pong` never reaches here: the peer's write loop matches it
            // against that peer's outstanding ping and does not forward it.
            NetworkMessage::Pong(_) => {}
            NetworkMessage::Inv(inventory) => {
                // Core's `MAX_INV_SZ` (`net_processing.cpp` INV).
                if inventory.len() > MAX_INV_PER_MSG {
                    self.add_ban_score(id, 100, &format!("inv message size = {}", inventory.len()));
                    return;
                }
                self.handle_inv(id, inventory);
            }
            NetworkMessage::Headers(headers) => {
                // Core's `MAX_HEADERS_RESULTS`, checked before any header in
                // the message is looked at.
                if headers.len() > crate::net::limits::MAX_HEADERS_RESULTS {
                    self.add_ban_score(id, 100, &format!("headers message size = {}", headers.len()));
                    return;
                }
                self.handle_headers(id, headers);
            }
            NetworkMessage::Block(block) => {
                // `last_block` is stamped where the block is *accepted*, not
                // here — see `block_processor` and `handle_block_ibd`.
                self.handle_block(id, block, in_flight);
            }
            NetworkMessage::Tx(tx) => {
                // `last_transaction` likewise: only a mempool accept counts.
                self.handle_tx(id, tx);
            }
            NetworkMessage::GetHeaders(msg) => {
                self.handle_getheaders(id, msg);
            }
            NetworkMessage::GetBlocks(msg) => {
                self.handle_getblocks(id, msg);
            }
            NetworkMessage::GetData(inv) => {
                self.handle_getdata(id, inv);
                // The write loop stopped reading this peer when it handed the
                // request over. Whatever is left unserved keeps it stopped;
                // see `serve_getdata`.
                if let Some(sender) = self.peer_sender(id) {
                    sender.queue().note_getdata_handled();
                }
            }
            NetworkMessage::SendCmpct(msg) => {
                // Only version 2 (witness) compact blocks are spoken; Core
                // ignores any other version outright. `send_compact` is the
                // high-bandwidth flag, not "supports compact blocks": a peer
                // sends `sendcmpct(0, 2)` to say it speaks v2 but wants
                // announcements as headers.
                if msg.version != 2 {
                    return;
                }
                let mut peers = self.peers.write();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.compact_blocks = true;
                    handle.info.hb_from = msg.send_compact;
                    tracing::debug!(id, high_bandwidth = msg.send_compact, "Peer supports compact blocks");
                }
            }
            NetworkMessage::CmpctBlock(msg) => {
                self.handle_compact_block(id, msg.compact_block);
            }
            NetworkMessage::GetBlockTxn(msg) => {
                self.handle_get_block_txn(id, msg.txs_request);
            }
            NetworkMessage::BlockTxn(msg) => {
                self.handle_block_txn(id, msg.transactions);
            }
            // Applied in the peer's read task, the moment it arrives.
            NetworkMessage::FeeFilter(_) => {}
            NetworkMessage::MemPool => {
                self.handle_mempool_request(id);
            }
            // BIP 111: satd never offers NODE_BLOOM, so a peer sending a BIP
            // 37 filter message is violating the protocol, and Core
            // disconnects it (`ProcessMessage`, "filterload received despite
            // not offering bloom services").
            NetworkMessage::FilterLoad(_) | NetworkMessage::FilterAdd(_) | NetworkMessage::FilterClear => {
                tracing::debug!(
                    id,
                    "{} received despite not offering bloom services, disconnecting peer={id}",
                    msg.cmd()
                );
                self.disconnect_by_id(id);
            }
            NetworkMessage::Addr(addrs) => {
                tracing::debug!(id, count = addrs.len(), "Received addr");
                // Address relay is off in *both* directions on a
                // block-relay-only link (Core's `SetupAddressRelay`), so
                // nothing this peer announces enters the address book.
                // Otherwise this is the message that latches the link's
                // addr relay on, inbound included.
                let relay_addrs = self.setup_address_relay(id);
                // Core's `ProcessAddrs`: past `MAX_ADDR_TO_SEND` entries the
                // message is misbehaviour and nothing in it is stored. A link
                // that relays no addresses ignores it whatever its size.
                if relay_addrs && addrs.len() > crate::net::limits::MAX_ADDR_TO_SEND {
                    self.add_ban_score(id, 100, &format!("addr message size = {}", addrs.len()));
                    return;
                }
                let source = self.peer_ip(id);
                for (_, addr) in &addrs {
                    if relay_addrs
                        && let Ok(sock_addr) = addr.socket_addr()
                        && !self.is_addr_connected(&sock_addr)
                        && !self.is_addr_banned(&sock_addr)
                    {
                        self.add_learned_addr_from(
                            sock_addr,
                            addr.services.to_u64(),
                            source.unwrap_or(sock_addr.ip()),
                        );
                    }
                }
                self.note_addr_fetch_answered(id, addrs.len());
            }
            NetworkMessage::GetAddr => {
                // Respond with our declared external addresses (-externalip)
                // followed by addresses of our connected peers.
                //
                // Not on a block-relay-only link: Core's `SetupAddressRelay`
                // refuses one outright, because answering is what lets an
                // adversary infer the link from its addr traffic.
                if !self.setup_address_relay(id) {
                    tracing::debug!(id, "ignoring getaddr on a block-relay-only connection");
                    return;
                }
                // Copy what we need and drop the guard before sending.
                // `send_to_peer` takes `peers.read()` itself, and
                // `parking_lot`'s read lock is not reentrant: a writer
                // arriving between the two acquisitions makes the second read
                // queue behind it while it waits on the first, deadlocking
                // the manager's event-drain task -- and with it the node's
                // whole P2P loop.
                struct AddrEntry {
                    addr: SocketAddr,
                    services: ServiceFlags,
                    onion_host: Option<String>,
                    conn_time: std::time::SystemTime,
                }
                let (wants_v2, addr_entries) = {
                    let peers = self.peers.read();
                    let wants_v2 = peers.get(&id).is_some_and(|h| h.info.wants_addrv2);
                    let entries: Vec<AddrEntry> = peers
                        .values()
                        .filter(|h| h.info.state == PeerState::Connected)
                        .map(|h| AddrEntry {
                            addr: h.info.addr,
                            services: h.info.services,
                            onion_host: h.info.onion_host.clone(),
                            conn_time: h.info.conn_time,
                        })
                        .collect();
                    (wants_v2, entries)
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                let our_services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                let externals = self.external_addrs.read().clone();

                let entry_time = |h: &AddrEntry| {
                    h.conn_time
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32
                };
                if wants_v2 {
                    // Map a routable socket to an addrv2 entry; the 0.0.0.0
                    // placeholder used for onion peers (and any unspecified
                    // address) is dropped rather than relayed as a bogus IPv4.
                    let to_v2 = |addr: SocketAddr, time: u32, services: ServiceFlags| {
                        if addr.ip().is_unspecified() {
                            return None;
                        }
                        let v2 = match addr.ip() {
                            std::net::IpAddr::V4(ip) => bitcoin::p2p::address::AddrV2::Ipv4(ip),
                            std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                                Some(ip4) => bitcoin::p2p::address::AddrV2::Ipv4(ip4),
                                None => bitcoin::p2p::address::AddrV2::Ipv6(ip),
                            },
                        };
                        Some(bitcoin::p2p::address::AddrV2Message { time, services, addr: v2, port: addr.port() })
                    };
                    let mut addrs: Vec<bitcoin::p2p::address::AddrV2Message> = externals
                        .iter()
                        .filter_map(|a| to_v2(*a, now, our_services))
                        .collect();
                    // Advertise our own hidden service.
                    if let Some(PeerAddr::Onion { host, port }) =
                        self.advertised_onion.read().as_ref()
                        && let Some(pubkey) = crate::net::peer::onion_host_to_torv3_pubkey(host)
                    {
                        addrs.push(bitcoin::p2p::address::AddrV2Message {
                            time: now,
                            services: our_services,
                            addr: bitcoin::p2p::address::AddrV2::TorV3(pubkey),
                            port: *port,
                        });
                    }
                    for h in &addr_entries {
                        let time = entry_time(h);
                        // A connected onion peer is relayed as a TorV3 entry
                        // (its socket is the 0.0.0.0 placeholder); everything
                        // else goes through the socket path.
                        if let Some(host) = h.onion_host.as_deref() {
                            if let Some(pubkey) = crate::net::peer::onion_host_to_torv3_pubkey(host) {
                                addrs.push(bitcoin::p2p::address::AddrV2Message {
                                    time,
                                    services: h.services,
                                    addr: bitcoin::p2p::address::AddrV2::TorV3(pubkey),
                                    port: h.addr.port(),
                                });
                            }
                        } else if let Some(msg) = to_v2(h.addr, time, h.services) {
                            addrs.push(msg);
                        }
                    }
                    if !addrs.is_empty() {
                        self.send_to_peer(id, NetworkMessage::AddrV2(addrs));
                    }
                } else {
                    // Legacy addr can't carry onion; skip onion peers and the
                    // unspecified placeholder rather than relay a bogus address.
                    let mut addrs: Vec<(u32, bitcoin::p2p::Address)> = externals
                        .iter()
                        .filter(|a| !a.ip().is_unspecified())
                        .map(|a| (now, bitcoin::p2p::Address::new(a, our_services)))
                        .collect();
                    for h in &addr_entries {
                        if h.onion_host.is_some() || h.addr.ip().is_unspecified() {
                            continue;
                        }
                        addrs.push((entry_time(h), bitcoin::p2p::Address::new(&h.addr, h.services)));
                    }
                    if !addrs.is_empty() {
                        self.send_to_peer(id, NetworkMessage::Addr(addrs));
                    }
                }
            }
            NetworkMessage::AddrV2(addrs) => {
                tracing::debug!(id, count = addrs.len(), "Received addrv2");
                // Onion peers are only reachable when an onion-routing proxy is
                // configured; without one there's no point recording them.
                let onion_routing = self.proxy.is_some() || self.onion_proxy.is_some();
                // As above: a block-relay-only link relays no addresses in
                // either direction, and anything else latches on.
                let relay_addrs = self.setup_address_relay(id);
                // As for `addr`.
                if relay_addrs && addrs.len() > crate::net::limits::MAX_ADDR_TO_SEND {
                    self.add_ban_score(id, 100, &format!("addrv2 message size = {}", addrs.len()));
                    return;
                }
                let source = self.peer_ip(id);
                for addr_msg in addrs.iter().filter(|_| relay_addrs) {
                    match &addr_msg.addr {
                        // BIP 155 TorV3: `socket_addr()` can't represent these,
                        // so derive the .onion host and queue it for dialing.
                        bitcoin::p2p::address::AddrV2::TorV3(pubkey)
                            if onion_routing && addr_msg.port != 0 =>
                        {
                            let host = crate::net::peer::torv3_to_onion_host(pubkey);
                            self.add_onion_connect_addr(host, addr_msg.port);
                        }
                        // IPv4 / IPv6 (and, under a proxy, anything else with a
                        // socket form) flow through the clearnet address book.
                        _ => {
                            if let Ok(sock_addr) = addr_msg.socket_addr()
                                && !self.is_addr_connected(&sock_addr)
                                && !self.is_addr_banned(&sock_addr)
                            {
                                self.add_learned_addr_from(
                                    sock_addr,
                                    addr_msg.services.to_u64(),
                                    source.unwrap_or(sock_addr.ip()),
                                );
                            }
                        }
                    }
                }
                self.note_addr_fetch_answered(id, addrs.len());
            }
            NetworkMessage::SendAddrV2 => {
                let mut peers = self.peers.write();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.wants_addrv2 = true;
                    tracing::debug!(id, "Peer supports addrv2");
                }
            }
            // BIP 339 negotiates wtxid relay between version and verack
            // (`perform_handshake`), so the two ends never disagree on how a
            // transaction is announced. Core disconnects a peer that sends
            // `wtxidrelay` after its verack.
            NetworkMessage::WtxidRelay => {
                tracing::debug!("wtxidrelay received after verack, disconnecting peer={id}");
                self.disconnect_by_id(id);
            }
            NetworkMessage::NotFound(inventory) => {
                // Core looks at a `notfound` only up to
                // `MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER`
                // entries, and ignores a longer one whole, without penalty.
                if inventory.len() > crate::net::limits::MAX_NOTFOUND_SZ {
                    tracing::debug!(id, count = inventory.len(), "ignoring an oversized notfound");
                    return;
                }
                // Authoritative "I don't have this" from the peer. Until
                // this commit we logged at debug and did nothing, so the
                // height stayed in_flight for the full 60s
                // `release_stale_inflight` window before any other peer
                // could be assigned. When ALL near-cursor peers respond
                // notfound (e.g. they're pruned or not synced past the
                // connect cursor's depth), the connector wedges
                // indefinitely. Release the heights now so the next
                // `assign_all_peers` tick can try a different peer.
                let mut block_hashes: Vec<bitcoin::BlockHash> = Vec::new();
                for inv in &inventory {
                    if let Inventory::Block(h) | Inventory::WitnessBlock(h) = inv {
                        block_hashes.push(*h);
                    }
                }
                if block_hashes.is_empty() {
                    tracing::debug!(id, count = inventory.len(), "Peer sent notfound (non-block)");
                } else {
                    let mut released_heights: Vec<u32> = Vec::new();
                    {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            for h in &block_hashes {
                                if let Some(entry) = self.chain_state.get_block_index(h)
                                    && scheduler.release_height(entry.height, id)
                                {
                                    released_heights.push(entry.height);
                                }
                            }
                        }
                    }
                    if released_heights.is_empty() {
                        tracing::debug!(
                            id,
                            count = block_hashes.len(),
                            "Peer sent notfound for blocks not currently in_flight to this peer"
                        );
                    } else {
                        tracing::info!(
                            peer_id = id,
                            count = released_heights.len(),
                            min_height = released_heights.iter().min().copied(),
                            max_height = released_heights.iter().max().copied(),
                            "Peer notfound: heights released for reassignment to a different peer"
                        );
                        // Trigger immediate reassignment instead of waiting
                        // for the next 2s scheduler tick.
                        self.assign_all_peers();
                    }
                }
            }
            NetworkMessage::SendHeaders => {
                tracing::debug!(id, "Peer prefers headers announcements");
                // BIP 130: remember the preference so new-tip blocks are
                // announced to this peer as `headers`, not `inv`.
                if let Some(handle) = self.peers.write().get_mut(&id) {
                    handle.info.prefers_headers = true;
                }
            }
            // Each request is checked as Core's `PrepareBlockFilterRequest`
            // does, including whether filters are served at all.
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFilters(req) => self.handle_get_cfilters(id, req),
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFHeaders(req) => self.handle_get_cfheaders(id, req),
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFCheckpt(req) => self.handle_get_cfcheckpt(id, req),
            // Built without filters: no filter type is served, and Core
            // disconnects a peer that asks for one it does not serve.
            #[cfg(not(feature = "block-filter-index"))]
            NetworkMessage::GetCFilters(_) | NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFCheckpt(_) => {
                tracing::debug!("peer requested unsupported block filter type, disconnecting peer={id}");
                self.disconnect_by_id(id);
            }
            _ => {}
        }
    }

    /// BIP35 `mempool`: a peer asks us to announce our full mempool.
    ///
    /// An unfiltered mempool dump is a privacy/DoS surface, which is why
    /// Bitcoin Core gates it behind `NODE_BLOOM`. satd does **not** support
    /// BIP37 / advertise `NODE_BLOOM` (intentionally — see `peerbloomfilters`),
    /// so the Core-equivalent gate here is the explicit `mempool` net
    /// permission — granted by `-whitelist=mempool@<subnet>`, by `all@`, or
    /// implicitly by a bare `-whitelist=<subnet>` entry (which carries Core's
    /// implicit permission set). It is NOT implied by `noban@`. Requests from
    /// peers without it are ignored without disconnecting; Bitcoin Core
    /// *disconnects* such peers unless they have `noban` — satd is
    /// deliberately softer to stay friendly to clients that probe. We
    /// respond, honoring the peer's fee filter, with `inv` message(s) of
    /// transaction inventory (by wtxid to a BIP 339 peer, by txid to the
    /// rest), batched to [`MAX_INV_PER_MSG`]; the peer then
    /// `getdata`s the ones it wants. Dumps to one peer are spaced at least
    /// [`MEMPOOL_REQUEST_COOLDOWN_SECS`] apart — each costs a full mempool
    /// scan and up to multi-MB of queued invs, and the permission grant is
    /// not a license to request in a loop.
    fn handle_mempool_request(&self, id: PeerId) {
        let permissions = self.peer_permissions(id);
        if !permissions.mempool {
            // Without NODE_BLOOM, which satd never offers, Core serves BIP 35
            // only to a peer with `mempool` permission and disconnects any
            // other that is not `noban`.
            if permissions.noban {
                tracing::debug!(id, "ignoring mempool request from peer without mempool permission");
            } else {
                tracing::debug!(id, "mempool request with bloom filters disabled, disconnecting peer={id}");
                self.disconnect_by_id(id);
            }
            return;
        }
        // Snapshot the peer's fee filter; confirm it's still connected,
        // participates in tx relay (a blocksonly peer asking for a mempool
        // dump gets nothing — Core has no tx-relay state for it either),
        // and is past the per-peer cooldown. The cooldown stamp is taken
        // under the same write lock that reads it, so concurrent requests
        // can't double-serve.
        let (fee_filter, wtxid_relay) = {
            let mut peers = self.peers.write();
            match peers.get_mut(&id) {
                Some(h) if h.info.state == PeerState::Connected && h.info.relays_txs() => {
                    let now = Instant::now();
                    if let Some(last) = h.last_mempool_served
                        && now.duration_since(last).as_secs() < MEMPOOL_REQUEST_COOLDOWN_SECS
                    {
                        tracing::debug!(id, "mempool request inside cooldown; ignoring");
                        return;
                    }
                    h.last_mempool_served = Some(now);
                    (h.info.fee_filter, h.info.wtxid_relay)
                }
                _ => return,
            }
        };
        let ids = self.mempool.relay_ids_above_feerate(fee_filter);
        if ids.is_empty() {
            return;
        }
        tracing::debug!(id, count = ids.len(), "serving BIP35 mempool request");
        for chunk in ids.chunks(MAX_INV_PER_MSG) {
            let inv = chunk
                .iter()
                .map(|(txid, wtxid)| tx_announcement(wtxid_relay, *txid, *wtxid))
                .collect::<Vec<_>>();
            if !self.send_to_peer(id, NetworkMessage::Inv(inv)) {
                // Channel full — the peer isn't draining its queue; the rest
                // of the dump would drop silently anyway (BIP35 makes no
                // completeness promise, but don't burn the allocations).
                tracing::debug!(id, "peer queue full mid mempool dump; truncating response");
                break;
            }
        }
    }

    fn handle_inv(&self, id: PeerId, inventory: Vec<Inventory>) {
        let mut blocks_to_get = Vec::new();
        let mut txs_to_get = Vec::new();
        let reject_tx_invs = self.rejects_incoming_txs(id);
        let wtxid_relay = self.peers.read().get(&id).is_some_and(|h| h.info.wtxid_relay);

        for inv in inventory {
            // BIP 339: a peer that negotiated wtxid relay announces by wtxid,
            // and one that did not announces by txid. Core skips an `inv` of
            // the other kind before looking at it any further, so it is not
            // a protocol violation either. Only `MSG_TX` is skipped on a
            // wtxid link, as in Core: `MSG_WITNESS_TX` is a getdata type.
            let mismatched = if wtxid_relay {
                matches!(inv, Inventory::Transaction(_))
            } else {
                matches!(inv, Inventory::WTx(_))
            };
            if mismatched {
                continue;
            }
            if reject_tx_invs {
                let tx_hash = match &inv {
                    Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                        Some(txid.to_string())
                    }
                    Inventory::WTx(wtxid) => Some(wtxid.to_string()),
                    _ => None,
                };
                if let Some(hash) = tx_hash {
                    tracing::debug!(
                        "transaction ({hash}) inv sent in violation of protocol, disconnecting peer={id}"
                    );
                    self.disconnect_by_id(id);
                    return;
                }
            }
            match inv {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    if self.chain_state.get_block_index(&hash).is_none() {
                        blocks_to_get.push(hash);
                    } else {
                        // Core's INV handler calls `UpdateBlockAvailability`
                        // for every block announced, known or not. A known
                        // one tells us how far the peer has got, which a peer
                        // that announces by `inv` shows no other way.
                        self.note_block_availability(id, &hash);
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    if self.mempool.get(&txid).is_some() {
                        // We already have it. If it's one of our pending local
                        // broadcasts, a peer announcing it back is a secondary
                        // sign it propagated — count it toward stopping
                        // rebroadcast (the primary signal is a peer fetching it
                        // from us via `getdata`; see `handle_getdata`).
                        self.note_broadcast_witness(id, txid);
                    } else if !self.is_ibd() && !self.blocksonly() {
                        // Don't request transactions during IBD — we can't
                        // validate them — nor under -blocksonly (no tx relay).
                        txs_to_get.push(Inventory::WitnessTransaction(txid));
                    }
                }
                // Fetched as announced, by wtxid: a resident transaction with
                // the same txid and another witness is not the one offered.
                Inventory::WTx(wtxid) => {
                    if let Some(txid) = self.mempool.txid_of_wtxid(&wtxid) {
                        self.note_broadcast_witness(id, txid);
                    } else if !self.is_ibd() && !self.blocksonly() {
                        txs_to_get.push(Inventory::WTx(wtxid));
                    }
                }
                _ => {}
            }
        }

        if !blocks_to_get.is_empty() {
            // Direct fetch (fast path when the block extends our tip)…
            if self.send_to_peer(id, sync::make_getdata_blocks(&blocks_to_get)) {
                self.note_blocks_requested(id, &blocks_to_get);
            }
            // …plus rate-limited headers-first discovery: if the announced
            // block builds on a competing chain we don't have, the direct block
            // arrives with an unknown parent and stalls in the buffer; asking
            // for headers lets us learn the connecting chain so
            // `request_missing_blocks` can pull its fork blocks and reorg. The
            // throttle stops a peer spamming block invs from making us emit a
            // getheaders per message.
            self.maybe_send_getheaders(id);
        }
        if !txs_to_get.is_empty() {
            self.send_to_peer(id, NetworkMessage::GetData(txs_to_get));
        }
    }

    /// Hand the IBD scheduler every height-index row above the tip that a
    /// best-header change rewrote, so the block it fetches for those heights
    /// is the one on the chain. Without this the scheduler keeps its
    /// creation-time hash for the height and asks for a block no peer has —
    /// which Bitcoin Core answers with silence, not `notfound`.
    fn apply_header_row_changes(&self) {
        let changes = self.chain_state.take_header_row_changes();
        if changes.is_empty() {
            return;
        }
        let best_height = self
            .chain_state
            .get_block_index(&self.chain_state.best_header_hash())
            .map(|e| e.height)
            .unwrap_or(0);
        let mut ibd = self.ibd.write();
        let Some(scheduler) = ibd.as_mut() else {
            return;
        };
        let (requeued, dropped) = scheduler.header_rows_changed(&changes, best_height);
        if requeued + dropped > 0 {
            tracing::info!(
                changed = changes.len(),
                requeued,
                dropped,
                "IBD: best-header chain moved above the tip; re-keyed the affected heights"
            );
        }
    }

    fn handle_headers(&self, id: PeerId, headers: Vec<bitcoin::block::Header>) {
        if headers.is_empty() {
            return;
        }

        let (accepted, err) = self.chain_state.accept_headers(&headers);
        // Whatever the batch did to the rows above the tip, the scheduler
        // must hear about it before its next assignment.
        self.apply_header_row_changes();
        // Core's `UpdateBlockAvailability`: the peer has at least the last
        // header it sent, already known or not.
        if let Some(last) = headers.last() {
            self.note_block_availability(id, &last.block_hash());
        }
        if let Some(e) = err {
            match e {
                crate::chain::state::ChainError::Duplicate => {}
                crate::chain::state::ChainError::PrevBlockNotFound
                | crate::chain::state::ChainError::BadPrevBlock => {
                    // The announced header builds on a chain we haven't seen —
                    // a competing/longer chain forking below our knowledge, or,
                    // far more often, a peer mining ahead of headers we have
                    // not caught up on yet. Ask for the connecting headers
                    // (headers-first discovery, rate-limited) so we can learn
                    // the chain; `request_missing_blocks` then pulls its blocks.
                    //
                    // No ban score. Core's `HandleUnconnectingHeaders` charges
                    // none: it sends the getheaders and records the peer as a
                    // source for what it announced. (It used to disconnect at
                    // `MAX_UNCONNECTING_HEADERS`; that was removed.) An
                    // unconnected batch costs us nothing — no header is stored
                    // — and the getheaders throttle already caps the work.
                    //
                    // satd charged a point per message on the theory that an
                    // honest peer sends one and stays far under the threshold.
                    // It does not: a node syncing 999 regtest blocks from a
                    // peer that is still mining answers each of our getheaders
                    // with a batch that no longer connects, and the exchange
                    // ran to 100 points — a ban — in half a second, leaving the
                    // node with no block source and its sync stopped dead.
                    self.maybe_send_getheaders(id);
                }
                other => {
                    self.add_ban_score(id, 20, &format!("Header rejected: {}", other));
                }
            }
        }

        if let Some(last) = headers.last() {
            self.note_peer_has_block(id, last.block_hash());
        }

        if accepted > 0 {
            // Update headers tip tracking from actual chain state
            let htip = self.chain_state.headers_tip_height() as u64;
            self.headers_tip.store(htip, Ordering::Relaxed);

            tracing::debug!(id, accepted, headers_tip = htip, "Headers accepted");

            // Request more headers if peer sent a full batch
            if headers.len() >= 2000 {
                self.send_to_peer(id, sync::make_getheaders(&self.chain_state));
                // During header download, request from other peers too for redundancy
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(pid, h)| **pid != id && h.info.state == PeerState::Connected)
                        .map(|(pid, _)| *pid)
                        .take(3)
                        .collect()
                };
                for pid in peer_ids {
                    self.send_to_peer(pid, sync::make_getheaders(&self.chain_state));
                }
            }

            // Start or extend IBD scheduler when headers are ahead of blocks.
            //
            // The +24 threshold only gates *creation* — once a scheduler
            // exists, extension must happen unconditionally on any new
            // headers past its target. Otherwise a late-arriving headers
            // batch (e.g. the last few blocks of a small chain) lands
            // while tip is already close to the prior target, the
            // `>tip+24` gate fails, the scheduler keeps its old target,
            // and the connector declares IBD complete with the new
            // headers' blocks unrequested. Observed on regtest
            // test_parallel_ibd: connector wedges at tip < headers tip
            // forever because request_missing_blocks (the non-IBD path)
            // only runs inside handle_headers and never sees another
            // batch trigger it.
            let headers_tip = htip as u32;
            if !self.maybe_start_ibd() {
                // Extension path. The write lock is scoped to this block —
                // holding it through the `self.ibd.read()` below deadlocked
                // handle_headers and wedged every test that depends on
                // block propagation (test_block_propagation,
                // test_block_sync_between_nodes, the p2p_orphan suite).
                let mut ibd = self.ibd.write();
                if let Some(scheduler) = ibd.as_mut()
                    && headers_tip > scheduler.target_height()
                {
                    scheduler.extend_target(headers_tip, &self.chain_state);
                    drop(ibd);
                    self.assign_all_peers();
                }
            }

            // Request blocks (legacy path for non-IBD or fallback)
            let has_ibd = self.ibd.read().is_some();
            if !has_ibd && let Some(last) = headers.last() {
                self.request_announced_blocks(id, last.block_hash());
            }
        }
    }

    /// (Re)create the parallel IBD scheduler if headers have run ahead of
    /// the tip by more than the creation threshold. Returns whether a
    /// scheduler was created.
    ///
    /// Called from two places: `handle_headers` (the event-driven path) and
    /// the run loop's periodic non-IBD fallback. The fallback call is what
    /// re-arms a node whose connector tore down short of the headers tip
    /// (issue #582): a fork-blocked handoff, or a headers batch accepted
    /// between the connector's completion check and its teardown, leaves
    /// `tip < headers_tip` with no scheduler — and with creation gated
    /// solely on inbound headers, the node parks until a peer happens to
    /// announce the next block, an interval that is unbounded on a chain
    /// with slow or irregular block production. Polling the same gate from
    /// the run loop bounds the parked interval at one fallback tick.
    fn maybe_start_ibd(&self) -> bool {
        let tip = self.chain_state.tip_height();
        let headers_tip = self.chain_state.headers_tip_height();
        // Don't (re)create the linear IBD scheduler while the connect
        // frontier is fork-blocked — it can't reorg and would re-wedge
        // on `bad-prevblk` (and, for a deep competing reorg arriving
        // mid-IBD, oscillate teardown↔re-create forever). Leave the
        // reorg-capable steady-state path to move the tip onto the
        // better chain first; once it does, the frontier links to the
        // new tip and bulk IBD resumes on the next gate evaluation.
        if headers_tip <= tip + 24 || !self.chain_state.frontier_connects_to_tip() {
            return false;
        }
        {
            let mut ibd = self.ibd.write();
            if ibd.is_some() {
                return false;
            }
            let effective_max_ahead = Self::resolve_max_ahead(self.max_ahead, headers_tip, tip);
            let sched = IbdScheduler::new(headers_tip, tip, &self.chain_state, effective_max_ahead);
            let (_, _, pending, target) = sched.progress();
            tracing::info!(
                target_height = target,
                blocks_to_download = pending,
                "Starting parallel block download"
            );
            *ibd = Some(sched);
        }
        // Wake the block processor thread so it enters IBD mode
        let (lock, cvar) = &*self.connect_signal;
        *lock.lock() = true;
        cvar.notify_one();
        // Assign work to all connected peers
        self.assign_all_peers();
        true
    }

    /// Assign download work to all connected peers during IBD.
    fn assign_all_peers(&self) {
        let peer_ids: Vec<PeerId> = {
            let peers = self.peers.read();
            peers.iter()
                .filter(|(_, h)| h.info.state == PeerState::Connected)
                .map(|(id, _)| *id)
                .collect()
        };
        for pid in peer_ids {
            self.assign_peer_work(pid);
        }
    }

    /// Bitcoin Core's `UpdateBlockAvailability`: record that `id` has the
    /// block it just announced, whatever route the announcement took.
    ///
    /// This is load-bearing for the download scheduler, not bookkeeping.
    /// [`Self::assign_peer_work`] will not give a peer heights above what we
    /// believe the peer holds, so an ingress that teaches us a header without
    /// recording availability wedges the download rather than slowing it: the
    /// target rises, the peer's believed height does not, and the scheduler
    /// returns having asked for nothing. Every path that accepts a header
    /// from a peer must come through here.
    fn note_block_availability(&self, id: PeerId, hash: &bitcoin::BlockHash) {
        if let Some(entry) = self.chain_state.get_block_index(hash) {
            self.note_peer_height(id, entry.height);
            self.maybe_send_sendheaders(id, &entry);
        }
    }

    /// Bitcoin Core's `MaybeSendSendHeaders` (v31.1 `net_processing.cpp:5607`):
    /// ask a peer to announce new blocks with `headers` (BIP 130) once its
    /// best known block has more work than the network's minimum chain work,
    /// if our common version is at least `SENDHEADERS_VERSION`. Core holds it
    /// back until then because announcements arriving mid headers-sync are no
    /// use to it. In practice this serves inbound peers: an outbound one was
    /// sent `sendheaders` in the handshake (`perform_handshake`).
    ///
    /// Core evaluates this on every `SendMessages` pass. The best known block
    /// only moves where availability is recorded, and it never loses work, so
    /// checking each block recorded there fires at the same point: the first
    /// time the peer shows a block past the minimum.
    fn maybe_send_sendheaders(&self, id: PeerId, shown: &crate::storage::blockindex::BlockIndexEntry) {
        if crate::chain::state::compare_u256(&shown.chainwork, &self.chain_state.minimum_chain_work()) <= 0 {
            return;
        }
        let mut peers = self.peers.write();
        let Some(handle) = peers.get_mut(&id) else {
            return;
        };
        let common_version = handle
            .info
            .version
            .as_ref()
            .map_or(0, |v| v.version.min(PROTOCOL_VERSION));
        if handle.info.sent_sendheaders || common_version < SENDHEADERS_VERSION {
            return;
        }
        // Marked only once queued: a full queue drops the message, and the
        // next block the peer shows tries again.
        if handle.msg_tx.try_send(NetworkMessage::SendHeaders).is_ok() {
            handle.info.sent_sendheaders = true;
            tracing::debug!(id, "sent sendheaders");
        }
    }

    /// Raise the height we believe `id` has reached. Never lowers it: a peer
    /// that announced a block still has it after announcing an older one.
    fn note_peer_height(&self, id: PeerId, height: u32) {
        if let Some(h) = self.peers.write().get_mut(&id) {
            h.info.best_known_height =
                Some(h.info.best_known_height.map_or(height, |b| b.max(height)));
        }
    }

    /// Assign IBD download work to a specific peer.
    ///
    /// Skips peers whose advertised best_height in the version message is
    /// more than 1000 blocks behind our target. The 2026-05-13 mainnet
    /// wedge showed inbound peers connecting with `height=0` (likely spam
    /// or pre-sync nodes) consuming priority-zone assignments they cannot
    /// fulfill, then holding them for the full stale-timeout window
    /// before any useful peer is tried.
    fn assign_peer_work(&self, peer_id: PeerId) {
        let target_height = match self.ibd.read().as_ref() {
            Some(s) => s.target_height(),
            None => return,
        };
        let peer_height = {
            let peers = self.peers.read();
            let Some(handle) = peers.get(&peer_id) else { return };
            // An addr-fetch connection exists to answer one `getaddr` and go;
            // Core excludes it from block download (`CanServeBlocks`), and
            // the sync loop's `getheaders` broadcasts already do. Registering
            // it as an IBD source assigns blocks to a peer about to hang up.
            if !handle.info.serves_blocks() {
                return;
            }
            // What the peer claimed at connect, or has announced since.
            (handle.info.best_height as i64).max(handle.info.best_known_height.map_or(-1, i64::from))
        };
        // i32::saturating_sub avoids underflow for early-IBD targets.
        if peer_height < (target_height as i64).saturating_sub(1000) {
            // Peer is not synced enough to be a useful IBD source. Skip.
            return;
        }
        // A peer that has neither claimed nor announced a block we still
        // need can serve none of them. Core only downloads from a peer up to
        // its `pindexBestKnownBlock`; asking the rest parks the heights on
        // them until the stall timeout.
        let Ok(max_height) = u32::try_from(peer_height) else { return };
        let mut ibd = self.ibd.write();
        if let Some(scheduler) = ibd.as_mut() {
            scheduler.register_peer(peer_id);
            if max_height <= scheduler.connect_cursor() {
                return;
            }
            let hashes = scheduler.assign_blocks_up_to(peer_id, max_height);
            if !hashes.is_empty() {
                drop(ibd);
                for chunk in hashes.chunks(128) {
                    self.send_to_peer(peer_id, sync::make_getdata_blocks(chunk));
                }
            }
        }
    }

    /// Core's `IsBlockMutated` gate. Returns true (and penalizes the peer) when
    /// the block is malleated — see [`crate::validation::block::is_block_mutated`]
    /// for the rules. Must be applied at EVERY block-ingress point before the
    /// block enters the processing channel, since blocks reach `block_tx` via
    /// several routes (direct `Block` messages and both compact-block
    /// reconstruction paths). The peer is penalized but the block is NOT marked
    /// permanently invalid: an honest block sharing the same hash must remain
    /// acceptable from another peer (avoids the CVE-2012-2459 index-poisoning
    /// DoS).
    fn reject_if_mutated(&self, id: PeerId, block: &bitcoin::Block) -> bool {
        // The witness half of the gate is segwit-gated, so it needs the block's
        // height, and the only way to know that before accepting the block is
        // its parent's index entry. Core does the same lookup and, when the
        // parent is unknown, **skips the gate entirely**:
        //
        //     const CBlockIndex* prev_block{...LookupBlockIndex(pblock->hashPrevBlock)};
        //     if (prev_block && IsBlockMutated(*pblock, DeploymentActiveAfter(prev_block, ...)))
        //
        // Skipping rather than falling back to a guessed activation state is
        // the safe direction: a block we cannot place cannot be connected
        // either, so it is rejected downstream on its own merits, whereas
        // guessing wrong here bans a peer at 100 points for an honest block.
        let Some(parent) = self
            .chain_state
            .get_block_index(&block.header.prev_blockhash)
        else {
            return false;
        };
        let segwit_active = crate::validation::block::segwit_active_at(
            self.chain_state.network,
            parent.height + 1,
        );
        if crate::validation::block::is_block_mutated(block, segwit_active) {
            tracing::warn!(hash = %block.block_hash(), id, "Rejecting mutated block");
            self.add_ban_score(id, 100, "mutated-block");
            return true;
        }
        false
    }

    /// Ask `peer_id` for a single block, routing the reply to the block-data
    /// repair path rather than the normal accept path.
    ///
    /// Backs the `getblockfrompeer` RPC. Returns an error string suitable for
    /// surfacing to the operator when the peer is unknown, not connected, or
    /// its send queue is full.
    pub fn request_block_from_peer(
        &self,
        hash: bitcoin::BlockHash,
        peer_id: PeerId,
    ) -> Result<(), String> {
        {
            let peers = self.peers.read();
            match peers.get(&peer_id) {
                None => return Err("Peer does not exist".to_string()),
                Some(h) if h.info.state != PeerState::Connected => {
                    return Err("Peer does not exist".to_string());
                }
                // The getdata we send asks for the witness serialization
                // (`Inventory::WitnessBlock`). A peer without NODE_WITNESS
                // answers with a stripped block, which the repair path
                // correctly rejects — and would then ban an honest peer for
                // doing the only thing it could. Refuse up front, as Core
                // does with "Pre-SegWit peer".
                Some(h) if !h.info.services.has(ServiceFlags::WITNESS) => {
                    return Err("Pre-SegWit peer".to_string());
                }
                Some(_) => {}
            }
        }

        // Register before sending: the reply can land on the peer thread
        // before `send_to_peer` even returns.
        {
            let mut pending = self.block_refetch.write();
            pending.retain(|_, at| at.elapsed() < BLOCK_REFETCH_TTL);
            pending.insert((hash, peer_id), Instant::now());
        }

        if !self.send_to_peer(peer_id, sync::make_getdata_blocks(&[hash])) {
            self.block_refetch.write().remove(&(hash, peer_id));
            return Err(format!("Failed to send getdata to peer {peer_id}"));
        }

        tracing::info!(%hash, peer_id, "Requested single block from peer for data repair");
        Ok(())
    }

    /// Fetch again a block the connector cannot read: stored per the index,
    /// but its record is gone (pruning deleted the file under it, #852) or
    /// is another block's. Nothing else would. The scheduler counts a stored
    /// block as downloaded, a re-sent copy dies as `Duplicate`, and the
    /// operator's remedy, `getblockfrompeer`, refuses a block above the tip
    /// in prune mode. The block goes through the repair route
    /// (`handle_refetched_block` → `repair_block_data`), which accepts a
    /// `DataStored` entry, authenticates the copy against the header, and
    /// repoints the entry, so the connector's next attempt reads it.
    ///
    /// At most one request per block per [`UNREADABLE_REFETCH_INTERVAL`],
    /// each to a peer picked at random, so a peer that never answers does
    /// not hold the block hostage.
    pub(crate) fn refetch_unreadable_block(&self, hash: bitcoin::BlockHash, height: u32) {
        use rand::seq::SliceRandom as _;
        {
            let mut last = self.unreadable_refetch_at.lock();
            last.retain(|_, at| at.elapsed() < UNREADABLE_REFETCH_INTERVAL);
            if last.contains_key(&hash) {
                return;
            }
            // Before the attempt, so a request that fails to send (a full
            // queue, a peer going away) still waits out the interval.
            last.insert(hash, Instant::now());
        }
        let peers = self.block_serving_peer_ids();
        let Some(&peer_id) = peers.choose(&mut rand::thread_rng()) else {
            tracing::warn!(
                height, %hash,
                "Stored block has no readable record and no connected peer can serve it"
            );
            return;
        };
        match self.request_block_from_peer(hash, peer_id) {
            Ok(()) => tracing::warn!(
                height, %hash, peer_id,
                "Stored block has no readable record; fetching it again from a peer"
            ),
            Err(e) => tracing::warn!(
                height, %hash, peer_id,
                "Stored block has no readable record; asking a peer for it failed: {e}"
            ),
        }
    }

    /// Peer ids eligible to serve a block re-fetch: connected, advertising
    /// `NODE_NETWORK` so they should hold historical blocks, and
    /// `NODE_WITNESS` so they can serve the witness serialization we ask for.
    pub fn block_serving_peer_ids(&self) -> Vec<PeerId> {
        let peers = self.peers.read();
        peers
            .iter()
            .filter(|(_, h)| {
                h.info.state == PeerState::Connected
                    && h.info.services.has(ServiceFlags::NETWORK)
                    && h.info.services.has(ServiceFlags::WITNESS)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Route a block that `getblockfrompeer` asked for into the repair path.
    /// Returns true when the block was consumed here.
    fn handle_refetched_block(&self, id: PeerId, block: &bitcoin::Block) -> bool {
        // Read-only fast path: this runs for every arriving block, including
        // all of IBD, and the map is empty except in the seconds after an
        // operator RPC. Don't take the write lock to sweep an empty map.
        if self.block_refetch.read().is_empty() {
            return false;
        }

        let hash = block.block_hash();
        {
            let mut pending = self.block_refetch.write();
            pending.retain(|_, at| at.elapsed() < BLOCK_REFETCH_TTL);
            // Only a peer we asked for this block. A peer we did not ask takes
            // the ordinary route, and the registrations of the peers we did
            // ask stay armed.
            if pending.remove(&(hash, id)).is_none() {
                return false;
            }
        }

        // Only an entry that claims to hold unreadable data is ours to repair.
        // A `HeaderOnly` block — Core's primary use case for this RPC — is a
        // block we simply never fetched, and `store_block` admits exactly that
        // status, so the normal path stores it *and* connects it, with the
        // checkpoint and signet checks `repair_block_data` deliberately does
        // not perform. Diverting it here would leave it stored and never
        // connected.
        if !self
            .chain_state
            .get_block_index(&hash)
            .is_some_and(|e| {
                matches!(
                    e.status,
                    crate::storage::blockindex::BlockStatus::DataStored
                        | crate::storage::blockindex::BlockStatus::Valid
                )
            })
        {
            tracing::debug!(
                %hash, id,
                "getblockfrompeer: not a data hole; handing to the normal block path"
            );
            return false;
        }

        let outcome = self.chain_state.repair_block_data(block);
        if outcome.is_ok() {
            // The block is readable now; other asked peers' replies are
            // ordinary duplicates.
            self.block_refetch.write().retain(|(h, _), _| *h != hash);
        }
        match outcome {
            Ok(crate::chain::state::BlockDataRepair::Repaired { height }) => {
                tracing::info!(
                    %hash, height, id,
                    "getblockfrompeer: block data repaired"
                );
            }
            Ok(crate::chain::state::BlockDataRepair::AlreadyPresent { height }) => {
                tracing::info!(
                    %hash, height, id,
                    "getblockfrompeer: block data was already readable; nothing written"
                );
            }
            // The block failed to authenticate against a header we already
            // accepted — the peer sent something it should not have. Same
            // penalty as a mutated block.
            Err(e @ crate::chain::state::ChainError::Validation(_)) => {
                tracing::warn!(
                    %hash, id, error = %e,
                    "getblockfrompeer: peer returned a block that does not match the header"
                );
                self.add_ban_score(id, 100, "bad-refetched-block");
            }
            // Everything else is ours, not the peer's: a storage or flat-file
            // failure, or the block having been pruned or invalidated in the
            // meantime. Penalizing the peer for our disk would be wrong.
            Err(e) => {
                tracing::warn!(%hash, id, error = %e, "getblockfrompeer: repair failed locally");
            }
        }
        true
    }

    /// The per-peer counters for `id`, if the peer is still connected.
    /// Used to carry a peer's stats along a channel that outlives the
    /// message dispatch, so the "last block" stamp lands on acceptance.
    fn peer_stats(&self, id: PeerId) -> Option<Arc<PeerStats>> {
        self.peers.read().get(&id).map(|h| h.stats.clone())
    }

    /// This peer's work-in-flight count, or `None` once it is gone — a
    /// departed peer has no pong to park.
    fn peer_flow(&self, id: PeerId) -> Option<Arc<crate::net::flow::PeerFlow>> {
        self.peers.read().get(&id).map(|h| h.flow.clone())
    }

    /// Whether this node has asked any peer for `hash` recently enough to
    /// still expect it: Core's `IsBlockRequested`.
    fn block_is_requested(&self, hash: &bitcoin::BlockHash) -> bool {
        self.in_flight_blocks
            .read()
            .values()
            .any(|asked| asked.get(hash).is_some_and(|r| r.at.elapsed() < BLOCK_IN_FLIGHT_TTL))
    }

    fn handle_block(
        &self,
        id: PeerId,
        block: bitcoin::Block,
        in_flight: crate::net::flow::InFlight,
    ) {
        if self.reject_if_mutated(id, &block) {
            return;
        }
        // Read before `note_block_arrived` clears the record. Core reads
        // `IsBlockRequested` at the same point (`net_processing.cpp:4800`);
        // here it decides whether the block may wait for an unknown parent.
        let requested = self.block_is_requested(&block.block_hash());
        self.note_block_arrived(&block.block_hash());
        self.note_peer_has_block(id, block.block_hash());
        // A peer that pushes a block has it, so the same availability rule
        // applies here as to the announcement paths. The block's own index
        // entry does not exist until it is accepted, and acceptance happens
        // off this thread, so the height comes from the parent: a block is
        // its parent's height plus one.
        //
        // Proof of work first. Core records availability only out of
        // `AcceptBlockHeader`, which has checked the header by then, and the
        // other two ingresses here inherit that: `handle_headers` records
        // after `accept_headers` and the compact path after
        // `accept_compact_header`. Without this a peer could raise the height
        // we believe it has reached for nothing, by pushing a well-formed
        // block whose header is garbage. (`reject_if_mutated` above does not
        // cover it — that gate is about witness and merkle malleation.)
        //
        // Bounded by the network's powLimit, which is Core's own
        // CheckProofOfWork. The hash against the header's *own* bits alone
        // bounds nothing: a header may claim `0x20ffffff`, a target near 2^256
        // that essentially any nonce meets. With the bound, the cheapest header
        // that passes costs a minimum-difficulty block. Whether its difficulty
        // is right for its place in the chain is still checked downstream,
        // when the block is accepted.
        //
        // Nothing observable rides on this one — a pushed block carries its
        // own data, so the scheduler has nothing to ask this peer for that it
        // is not already getting. It is here so the invariant holds at every
        // ingress rather than at the ones that happen to matter today.
        if crate::validation::pow::check_proof_of_work_bounded(&block.header, self.chain_state.network)
            .is_ok()
            && let Some(parent) = self.chain_state.get_block_index(&block.header.prev_blockhash)
        {
            self.note_peer_height(id, parent.height + 1);
        }

        // Operator-requested single-block re-fetch. Must come before every
        // other route: the normal paths reject a block we already have an
        // index entry for, which is the whole point of a repair.
        if self.handle_refetched_block(id, &block) {
            return;
        }

        // Forward IBD swarm: store every arriving block to disk; the
        // ibd_connect_loop connects them in order. Historical blocks the
        // background catch-up requested also land here and are stored — we
        // notify the background connector from the same path.
        if self.ibd.read().is_some() {
            self.handle_block_ibd(id, block);
            return;
        }
        // Forward IBD inactive. If a background catch-up is active and this
        // block falls in the historical range it validates (at or below
        // snapshot_height), store it for the background connector instead
        // of the normal connect path — accept_block would reject a
        // below-tip block as a stale side branch.
        if let Some(bg) = self.chain_state.background()
            && let Some(parent) = self.chain_state.get_block_index(&block.header.prev_blockhash)
            && parent.height < bg.snapshot_height()
        {
            let height = parent.height + 1;
            // Only the canonical block for this height may be stored — see
            // `historical_block_storable`. A valid non-canonical side block
            // here would overwrite the shared height→hash mapping the
            // background connector depends on and derail validation.
            if historical_block_storable(
                bg.snapshot_height(),
                height,
                self.chain_state.get_block_hash_by_height(height),
                block.block_hash(),
            ) {
                self.store_bg_block(id, block);
            } else {
                tracing::debug!(
                    height,
                    hash = %block.block_hash(),
                    "bg catch-up: dropping non-canonical historical block"
                );
            }
            return;
        }
        // Normal mode
        let _ = self.block_tx.send((id, self.peer_stats(id), block, in_flight, requested));
    }

    /// While an AssumeUTXO background validator is attached, refuse to
    /// store a block in the historical range (≤ snapshot_height) that is
    /// NOT the canonical block for its height. The headers for the whole
    /// genesis→snapshot range are canonical and fixed (a loadtxoutset
    /// precondition); a peer may still relay a valid non-canonical
    /// historical block extending a known ancestor, and storing it would
    /// overwrite the shared height→hash mapping the background connector
    /// reads — derailing validation or falsely rejecting the snapshot.
    /// Returns true when the block must be dropped before `store_block`.
    fn is_poisoning_historical_block(&self, block: &bitcoin::Block) -> bool {
        let bg = match self.chain_state.background() {
            Some(b) => b,
            None => return false,
        };
        let height = match self.chain_state.get_block_index(&block.header.prev_blockhash) {
            // Parent unknown — store_block rejects with BadPrevBlock and
            // never writes a height→hash mapping, so it cannot poison.
            None => return false,
            Some(p) => p.height + 1,
        };
        !historical_block_storable(
            bg.snapshot_height(),
            height,
            self.chain_state.get_block_hash_by_height(height),
            block.block_hash(),
        )
    }

    /// Block arrival during forward IBD swarm. Stores the block and
    /// advances the forward scheduler; if a background catch-up is also
    /// active, a stored historical block additionally wakes the background
    /// connector.
    fn handle_block_ibd(&self, id: PeerId, block: bitcoin::Block) {
        // A non-canonical historical block (≤ snapshot_height) can arrive
        // unsolicited even during forward IBD; storing it would poison the
        // shared height→hash mapping the background connector relies on.
        // Drop it before store_block. (No-op when no snapshot is loaded.)
        if self.is_poisoning_historical_block(&block) {
            tracing::debug!(
                hash = %block.block_hash(),
                "IBD: dropping non-canonical sub-snapshot block while a background validator is active"
            );
            return;
        }
        let hash = block.block_hash();
        match self.chain_state.store_block(&block) {
            Ok((_, height)) => {
                // Stored — Core's `new_block`. See `block_processor`.
                if let Some(h) = self.peers.read().get(&id) {
                    h.stats.record_block();
                }
                let needs_more = {
                    let mut ibd = self.ibd.write();
                    if let Some(scheduler) = ibd.as_mut() {
                        scheduler.block_received(id, height, hash)
                    } else {
                        false
                    }
                };
                // Wake connect thread
                let (lock, cvar) = &*self.connect_signal;
                *lock.lock() = true;
                cvar.notify_one();
                // Assign more work if peer has capacity
                if needs_more {
                    self.assign_peer_work(id);
                }
                // A historical block requested by the background catch-up
                // also lands here during forward IBD. Only poke the
                // background connector when a snapshot is actually loaded
                // (the common no-AssumeUTXO path skips this entirely).
                if self.chain_state.has_background() {
                    self.note_bg_block_stored(height);
                }
            }
            Err(crate::chain::state::ChainError::Duplicate) => {
                // Already have it, mark in scheduler anyway
                if let Some(entry) = self.chain_state.get_block_index(&hash) {
                    {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.block_received(id, entry.height, hash);
                        }
                    }
                    if self.chain_state.has_background() {
                        self.note_bg_block_stored(entry.height);
                    }
                }
            }
            Err(crate::chain::state::ChainError::PrevBlockNotFound)
            | Err(crate::chain::state::ChainError::BadPrevBlock) => {
                // Parent header not yet accepted — normal during swarm IBD.
                // Don't penalize the peer; the block may become valid later.
                tracing::debug!(%hash, "IBD block store: parent unknown, skipping");
            }
            Err(e) => {
                tracing::debug!(%hash, "IBD block store failed: {}", e);
                self.add_ban_score(id, 10, &format!("block rejected: {}", e));
            }
        }
    }

    /// Store a downloaded historical block for the background catch-up
    /// validator and wake the background connector. Runs only when forward
    /// IBD is inactive and the block is in the background's range.
    fn store_bg_block(&self, id: PeerId, block: bitcoin::Block) {
        let hash = block.block_hash();
        match self.chain_state.store_block(&block) {
            Ok((_, height)) => {
                if let Some(h) = self.peers.read().get(&id) {
                    h.stats.record_block();
                }
                self.note_bg_block_stored(height);
            }
            Err(crate::chain::state::ChainError::Duplicate) => {
                if let Some(entry) = self.chain_state.get_block_index(&hash) {
                    self.note_bg_block_stored(entry.height);
                }
            }
            Err(crate::chain::state::ChainError::PrevBlockNotFound)
            | Err(crate::chain::state::ChainError::BadPrevBlock) => {
                tracing::debug!(%hash, "bg catch-up block store: parent unknown, skipping");
            }
            Err(e) => {
                tracing::debug!(%hash, "bg catch-up block store failed: {}", e);
                // Smaller penalty than forward IBD: a malformed historical
                // block is suspicious but the catch-up download is best-
                // effort and will re-request from another peer.
                self.add_ban_score(id, 5, &format!("bg block rejected: {}", e));
            }
        }
    }

    /// A block's data was stored — clear it from the background download
    /// tracker (no-op for forward-range heights) and wake the background
    /// connect loop so it can attempt the next in-order connect.
    fn note_bg_block_stored(&self, height: u32) {
        self.bg_downloader.write().note_stored(height);
        let (lock, cvar) = &*self.bg_connect_signal;
        *lock.lock() = true;
        cvar.notify_one();
    }

    /// Drive the AssumeUTXO background catch-up download: request the next
    /// window of historical block data above the background connect cursor
    /// from connected peers. Frees the tracker once no background remains.
    fn drive_bg_catchup_download(&self) {
        let bg = match self.chain_state.background() {
            Some(b) => b,
            None => {
                // Background detached (handoff done or never attached) —
                // release any lingering request bookkeeping once.
                if self.bg_downloader.read().in_flight_len() > 0 {
                    self.bg_downloader.write().reset();
                }
                return;
            }
        };
        let snapshot_height = bg.snapshot_height();
        let cursor = bg.tip_height();
        if cursor >= snapshot_height {
            return;
        }

        let now = Instant::now();
        self.bg_downloader.write().release_stale(now);

        // Heights we still need data for, within the read-ahead window.
        let range = self.bg_downloader.read().wanted_range(cursor, snapshot_height);
        if range.is_empty() {
            return;
        }
        let mut needed: Vec<(u32, bitcoin::BlockHash)> = Vec::new();
        {
            let dl = self.bg_downloader.read();
            for h in range {
                if dl.is_in_flight(h) {
                    continue;
                }
                if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                    // Already on disk (downloaded earlier / crash-resume) —
                    // the connector will pick it up; no request needed.
                    if self.chain_state.has_block_data(&hash) {
                        continue;
                    }
                    needed.push((h, hash));
                }
            }
        }
        if needed.is_empty() {
            return;
        }

        let peer_ids: Vec<PeerId> = {
            let peers = self.peers.read();
            peers
                .iter()
                .filter(|(_, h)| h.info.state == PeerState::Connected)
                .map(|(id, _)| *id)
                .collect()
        };
        if peer_ids.is_empty() {
            return;
        }

        // Round-robin the needed heights across peers, capping how many we
        // assign to any one peer this pass.
        let mut assignments: HashMap<PeerId, Vec<bitcoin::BlockHash>> = HashMap::new();
        {
            let mut dl = self.bg_downloader.write();
            let mut next_peer = 0usize;
            let mut per_peer: HashMap<PeerId, usize> = HashMap::new();
            for (h, hash) in needed {
                // Find a peer under the per-pass cap.
                let mut placed = false;
                for _ in 0..peer_ids.len() {
                    let pid = peer_ids[next_peer % peer_ids.len()];
                    next_peer += 1;
                    let count = per_peer.entry(pid).or_insert(0);
                    if *count < BG_CATCHUP_PER_PEER_PER_PASS {
                        *count += 1;
                        dl.mark_in_flight(h, pid, now);
                        assignments.entry(pid).or_default().push(hash);
                        placed = true;
                        break;
                    }
                }
                if !placed {
                    // Every peer is at the per-pass cap; defer the rest.
                    break;
                }
            }
        }
        for (pid, hashes) in assignments {
            for chunk in hashes.chunks(128) {
                self.send_to_peer(pid, sync::make_getdata_blocks(chunk));
            }
        }
    }

    /// Long-lived background catch-up connect loop. Idles on
    /// `bg_connect_signal` until a snapshot is loaded and a background
    /// chainstate is attached, then connects downloaded historical blocks
    /// in strict order until handoff (which `background_connect_block`
    /// performs internally on reaching `snapshot_height`). Periodically
    /// flushes the background coin cache so a crash resumes from a recent
    /// private tip. Exits on shutdown.
    fn bg_catchup_connect_loop(
        chain_state: &Arc<ChainState>,
        bg_connect_signal: &Arc<(parking_lot::Mutex<bool>, Condvar)>,
        shutdown: &tokio::sync::watch::Receiver<bool>,
    ) {
        let mut since_flush: u64 = 0;
        /// How long the handoff must keep failing before the condition is
        /// escalated to a warning. Long enough that a brief disk hiccup
        /// resolves without paging anyone, short enough that a real stall is
        /// reported in well under a minute.
        ///
        /// Measured in elapsed time rather than in attempts, because an attempt
        /// count is not a clock here: the wait below is a 1s *timeout*, not a
        /// period, and `note_bg_block_stored` wakes it on every stored
        /// background block — including duplicates, which a peer can send at
        /// will. Counting attempts would let a peer turn a 200ms hiccup into a
        /// page by feeding us blocks we already have.
        const HANDOFF_RETRY_WARN_AFTER: Duration = Duration::from_secs(10);
        /// Floor between two handoff attempts, doubling up to a ceiling while
        /// the failure persists. Without it those same peer-driven wakeups spin
        /// `retry_background_handoff` as fast as blocks arrive — and that call
        /// flushes the coin cache and can rehash the whole background UTXO set,
        /// which is not something to run in a hot loop on a node that is
        /// already failing its I/O.
        const HANDOFF_RETRY_MIN_BACKOFF: Duration = Duration::from_secs(1);
        const HANDOFF_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(30);
        const HANDOFF_WARNING_ID: &str = "assumeutxo.handoff_failing";
        let mut handoff_retry_failures: u32 = 0;
        let mut handoff_first_failure: Option<Instant> = None;
        let mut handoff_last_attempt: Option<Instant> = None;
        let mut handoff_backoff = HANDOFF_RETRY_MIN_BACKOFF;
        let mut handoff_warned = false;
        let mut handoff_snapshot: Option<u32> = None;
        loop {
            if *shutdown.borrow() {
                return;
            }
            let bg = match chain_state.background() {
                Some(b) => b,
                None => {
                    // No snapshot loaded — sleep until woken (loadtxoutset /
                    // startup resume pokes the signal) or a 1s timeout.
                    let (lock, cvar) = &**bg_connect_signal;
                    let mut ready = lock.lock();
                    *ready = false;
                    let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                    continue;
                }
            };

            // A snapshot proven invalid at handoff stays attached with a
            // durable rejected marker; stop trying to advance it.
            if bg.is_rejected() {
                return;
            }

            let next_height = bg.tip_height() + 1;
            if next_height > bg.snapshot_height() {
                // At/past the snapshot but still attached: the handoff did not
                // complete. Actually re-attempt it rather than only sleeping.
                //
                // Waiting alone made this branch a permanent stall: the
                // handoff runs from `background_connect_block`, i.e. only
                // after a successful connect, and no further connect is
                // possible once the tip is at `snapshot_height`. So an I/O
                // failure inside the handoff — `verify_at_snapshot` flushes
                // coins and hashes the whole UTXO set, either of which can hit
                // ENOSPC — left the snapshot pending forever with nothing
                // retrying and nothing reported. That is issue #545's "halts
                // silently and permanently", reached without any connect ever
                // failing.
                // A `loadtxoutset` can replace the snapshot under us. Counting
                // the new one's failures on top of the old one's would report
                // the wrong total for the wrong height, so start clean.
                if handoff_snapshot != Some(bg.snapshot_height()) {
                    if handoff_warned {
                        chain_state.warnings().clear(HANDOFF_WARNING_ID);
                    }
                    handoff_snapshot = Some(bg.snapshot_height());
                    handoff_retry_failures = 0;
                    handoff_first_failure = None;
                    handoff_last_attempt = None;
                    handoff_backoff = HANDOFF_RETRY_MIN_BACKOFF;
                    handoff_warned = false;
                }

                let due = handoff_last_attempt.is_none_or(|at| at.elapsed() >= handoff_backoff);
                if due {
                    handoff_last_attempt = Some(Instant::now());
                    match chain_state.retry_background_handoff() {
                        Ok(_) => {
                            // The condition resolved: the snapshot is validated
                            // (or condemned), so the standing warning is now a
                            // false statement. Clearing it is what keeps
                            // `has_errors()` — and the TUI's blocking modal —
                            // from latching for the life of the process.
                            if handoff_warned {
                                tracing::info!(
                                    height = bg.snapshot_height(),
                                    attempts = handoff_retry_failures,
                                    "AssumeUTXO: handoff succeeded; clearing the standing warning"
                                );
                                chain_state.warnings().clear(HANDOFF_WARNING_ID);
                                handoff_warned = false;
                            }
                            handoff_retry_failures = 0;
                            handoff_first_failure = None;
                            handoff_backoff = HANDOFF_RETRY_MIN_BACKOFF;
                        }
                        Err(e) => {
                            // Transient by assumption (disk full, a failed
                            // flush), so keep retrying — but say so once it
                            // stops looking transient, because until the
                            // handoff completes the snapshot is unvalidated and
                            // `getchainstates` reports it as neither validated
                            // nor rejected.
                            handoff_retry_failures += 1;
                            let failing_since =
                                *handoff_first_failure.get_or_insert_with(Instant::now);
                            handoff_backoff =
                                (handoff_backoff * 2).min(HANDOFF_RETRY_MAX_BACKOFF);
                            if failing_since.elapsed() >= HANDOFF_RETRY_WARN_AFTER {
                                // Re-recorded on every failure, not only the
                                // first: `record` bumps `count` and refreshes
                                // `last_seen`, while `-alertnotify` still fires
                                // once. Recording once would leave an operator
                                // reading `count: 1` with an hours-old
                                // `last_seen` for a condition that is failing
                                // right now.
                                tracing::error!(
                                    height = bg.snapshot_height(),
                                    error = %e,
                                    attempts = handoff_retry_failures,
                                    "AssumeUTXO: handoff keeps failing; the snapshot stays unvalidated"
                                );
                                chain_state.warnings().record(
                                    HANDOFF_WARNING_ID,
                                    crate::warnings::Severity::Error,
                                    format!(
                                        "AssumeUTXO handoff at height {} has been failing for {}s \
                                         over {} attempts ({e}); the snapshot remains unvalidated \
                                         until it succeeds",
                                        bg.snapshot_height(),
                                        failing_since.elapsed().as_secs(),
                                        handoff_retry_failures
                                    ),
                                    serde_json::json!({
                                        "height": bg.snapshot_height(),
                                        "attempts": handoff_retry_failures,
                                        "failing_for_secs": failing_since.elapsed().as_secs(),
                                        "error": e.to_string(),
                                    }),
                                );
                                handoff_warned = true;
                            }
                        }
                    }
                }
                let (lock, cvar) = &**bg_connect_signal;
                let mut ready = lock.lock();
                *ready = false;
                let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                continue;
            }

            let hash = match chain_state.get_block_hash_by_height(next_height) {
                Some(h) => h,
                None => {
                    // Header missing for this height (shouldn't happen given
                    // loadtxoutset's headers precondition) — wait and retry.
                    let (lock, cvar) = &**bg_connect_signal;
                    let mut ready = lock.lock();
                    *ready = false;
                    let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                    continue;
                }
            };

            if !chain_state.has_block_data(&hash) {
                // Not downloaded yet — the run-loop downloader will request
                // it; wait to be woken when it's stored.
                let (lock, cvar) = &**bg_connect_signal;
                let mut ready = lock.lock();
                *ready = false;
                let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                continue;
            }

            let block = match chain_state.get_block(&hash) {
                Some(b) => b,
                None => {
                    // Index says DataStored but the read failed — back off
                    // briefly and retry rather than busy-looping.
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };

            match chain_state.background_connect_block(&block) {
                Ok(Some(outcome)) => {
                    since_flush += 1;
                    if outcome.reached_snapshot {
                        // Handoff ran inside background_connect_block. On a
                        // match the background is now detached; the next loop
                        // iteration idles. On a mismatch it returned Err
                        // (handled below), not here.
                        tracing::info!(
                            height = outcome.height,
                            "AssumeUTXO: background reached snapshot height; handoff complete"
                        );
                        since_flush = 0;
                        continue;
                    }
                    if since_flush >= BG_CATCHUP_FLUSH_EVERY {
                        if let Err(e) = bg.flush() {
                            tracing::warn!(error = %e, "AssumeUTXO: background flush failed");
                        }
                        since_flush = 0;
                    }
                }
                Ok(None) => {
                    // Background detached between the guard and here.
                    continue;
                }
                Err(e) => {
                    // Either a validation failure on a historical block or a
                    // handoff mismatch (which already marked the snapshot
                    // rejected). Either way we cannot make forward progress;
                    // log once and stop the loop. The operator must reindex
                    // or reload a valid snapshot.
                    tracing::error!(
                        height = next_height,
                        error = %e,
                        "AssumeUTXO: background catch-up halted — connect failed"
                    );
                    // Returning here ends the only thread that advances the
                    // background chainstate, permanently for this process.
                    // That has to reach the operator: without it the only
                    // trace is the log line above — a background tip frozen
                    // forever with no surfaced reason (#545).
                    //
                    // Two different failures arrive here, and they must not be
                    // described the same way. `background_connect_block` runs
                    // the handoff via `?`, so a *proven invalid* snapshot —
                    // hash mismatch at the snapshot height — lands in this arm
                    // having already been marked rejected and warned about
                    // upstream as `assumeutxo-validation-failed`. Telling that
                    // operator the snapshot "remains unvalidated" would be the
                    // weaker of two truths at the moment the stronger one
                    // applies, so the rejected case is left to the warning
                    // that already describes it exactly.
                    //
                    // Deliberately NOT `bg.mark_rejected()` here. That marker
                    // is a durable "this snapshot is invalid" verdict and only
                    // the handoff comparison proves it. What actually reaches
                    // this arm otherwise is storage and flat-file I/O failure
                    // — a full disk must not condemn a good snapshot. (A bad
                    // *block* cannot reach it: while a background is attached
                    // only the canonical block for a historical height is
                    // storable, `store_block` validates it before it lands,
                    // and `get_block` re-derives the hash and reports
                    // corruption rather than returning foreign bytes.)
                    if !bg.is_rejected() {
                        chain_state.warnings().record(
                            "assumeutxo.catchup_halted",
                            crate::warnings::Severity::Error,
                            format!(
                                "AssumeUTXO background validation stopped at height \
                                 {next_height} ({e}) and will not resume without a restart; \
                                 the snapshot remains unvalidated"
                            ),
                            serde_json::json!({
                                "height": next_height,
                                "error": e.to_string(),
                            }),
                        );
                    }
                    let _ = bg.flush();
                    return;
                }
            }
        }
    }

    /// Block processing runs on a dedicated OS thread (not tokio) to avoid
    /// blocking the async event loop during CPU-intensive validation.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn block_processor(
        mut rx: mpsc::UnboundedReceiver<IncomingBlock>,
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        prune_target_mb: u64,
        connect_signal: Arc<(parking_lot::Mutex<bool>, Condvar)>,
        ibd: Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
        prefetch_workers: usize,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
        network: Network,
        ibd_eta_secs: Arc<AtomicU64>,
        orphanage: Arc<TxOrphanage>,
        peer_manager: std::sync::Weak<PeerManager>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut last_log_height: u32 = 0;
        let mut last_prune_height: u32 = 0;

        // Compute keep_blocks from the prune target. `-prune` is in **MiB**,
        // as Core's is (`blockmanager_args.cpp`: `nPruneArg * 1024 * 1024`);
        // the 2 MiB divisor is an average-block-size assumption, not a unit.
        let keep_blocks: u32 = if prune_target_mb > 0 {
            ((prune_target_mb * 1024 * 1024 / (2 * 1024 * 1024)) as u32).max(288)
        } else {
            0
        };

        // IBD connect loop: walk from tip forward, connecting stored blocks
        if ibd.read().is_some() {
            Self::ibd_connect_loop(
                &chain_state,
                &fee_estimator,
                &connect_signal,
                &ibd,
                keep_blocks,
                prefetch_workers,
                &mut last_log_height,
                &mut last_prune_height,
                max_ahead,
                ibd_l0_pause_at,
                network,
                &ibd_eta_secs,
                &peer_manager,
                &shutdown,
            );
        }

        // Normal mode: process blocks from the channel.
        // Periodically check if the IBD scheduler was activated (header download completed
        // while we were in normal mode), and switch to the IBD connect loop if so.
        //
        // A block this node asked for whose parent it does not know yet waits
        // here, within the bounds `OrphanBlocks` enforces, and connects when
        // the parent becomes the tip. Its in-flight guard is not kept with it:
        // Core is done with such a block once it has refused it as
        // `prev-blk-not-found`, so a pong behind it is answered then, and not
        // after a parent that may never come.
        let mut orphan_blocks = crate::net::orphan_blocks::OrphanBlocks::new();
        loop {
            // Shutdown: stop connecting. `join_connectors` is waiting for
            // this thread to exit before the shutdown flush.
            if *shutdown.borrow() {
                tracing::info!(
                    height = chain_state.tip_height(),
                    "Block processor stopped for shutdown"
                );
                return;
            }
            // Check if IBD scheduler was activated
            if ibd.read().is_some() {
                Self::ibd_connect_loop(
                    &chain_state,
                    &fee_estimator,
                    &connect_signal,
                    &ibd,
                    keep_blocks,
                    prefetch_workers,
                    &mut last_log_height,
                    &mut last_prune_height,
                    max_ahead,
                    ibd_l0_pause_at,
                    network,
                    &ibd_eta_secs,
                    &peer_manager,
                    &shutdown,
                );
                continue;
            }

            // Wait for a block from the channel, but wake up periodically
            // to check for IBD scheduler activation
            let (lock, cvar) = &*connect_signal;
            let mut ready = lock.lock();
            *ready = false;
            // Wait up to 500ms — will be woken immediately if a block is stored
            let _ = cvar.wait_for(&mut ready, Duration::from_millis(500));
            // Release the signal mutex before doing any connect work. The
            // flag is edge-triggered with the 500ms timeout as backstop, so
            // holding the guard buys nothing — while every notifier blocks
            // on it: `maybe_start_ibd` runs on the tokio run loop, so
            // holding this across a long drain would freeze all P2P
            // maintenance (and park peer tasks in `handle_block_ibd`) for
            // the duration.
            drop(ready);
            orphan_blocks.expire(Instant::now());

            // Drain all available blocks from the channel. Each block's
            // in-flight guard is counted out at the end of its iteration.
            while let Ok((sender, sender_stats, block, _in_flight, requested)) = rx.try_recv() {
                let hash = block.block_hash();
                // A block whose parent has no index entry cannot connect yet,
                // and `accept_block` would refuse it as `PrevBlockNotFound`.
                // It skips that and the fee pass below, which looks up a coin
                // per input.
                if chain_state.get_block_index(&block.header.prev_blockhash).is_none() {
                    Self::hold_for_parent(&mut orphan_blocks, sender, block, requested, network, &peer_manager);
                    continue;
                }
                // Compute fees BEFORE accept_block — connect_block removes spent coins.
                let fees = Self::compute_block_fee_rates(&block, &chain_state);
                match chain_state.accept_block(&block) {
                    Ok(acceptance) => {
                        // Core sets `m_last_block_time` in `ProcessBlock`
                        // only when `ProcessNewBlock` reports `new_block` —
                        // i.e. the block was actually stored. `Ok` here is
                        // that same condition (a block we already had is
                        // `ChainError::Duplicate`). Stamping it on *receipt*
                        // instead, as this used to, let a peer refresh its
                        // own eviction protection for free by re-sending a
                        // block the node already had.
                        if let Some(stats) = &sender_stats {
                            stats.record_block();
                        }
                        chain_state.bump_connect_heartbeat();
                        // A successful steady-state connect disproves "the
                        // connector cannot make progress" no matter which
                        // path raised it — without this, a warning recorded
                        // by the (now torn-down) IBD connector would gate
                        // `/readyz` forever on a healthy node.
                        chain_state
                            .warnings()
                            .clear(crate::warnings::CONNECT_PERSISTENT_FAILURE);
                        // Everything below this point is "a block joined the
                        // active chain" bookkeeping, and `accept_block` also
                        // returns `Ok` for a block it stored WITHOUT connecting
                        // — a side chain whose work does not beat the tip, a
                        // block far ahead of the tip during IBD, a reorg
                        // declined below an AssumeUTXO snapshot. Running it
                        // then is not harmless: `remove_for_block` deletes
                        // every transaction in the block from the mempool as
                        // *confirmed* and emits `LeaveConfirmed` to every
                        // subscriber, so an ordinary stale sibling would purge
                        // live transactions this node would otherwise relay and
                        // mine, and tell clients they confirmed in a block
                        // `getblock` reports at `confirmations: -1`. The fee
                        // estimator would likewise sample a block that never
                        // confirmed.
                        if let Some(height) =
                            chain_state.connected_height(&acceptance)
                        {
                            fee_estimator.record_block(&fees);
                            mempool.remove_for_block(&block, height);
                            reconsider_orphans_on_block(&orphanage, &mempool, &chain_state, &block);
                            if chain_state.tip_hash() == hash
                                && let Some(pm) = peer_manager.upgrade()
                            {
                                pm.block_became_tip(sender, &block, height);
                            }
                        }
                        // Connect the blocks that were waiting for this one.
                        loop {
                            let tip = chain_state.tip_hash();
                            match orphan_blocks.take_child_of(&tip) {
                                Some(b) => {
                                    let b_fees = Self::compute_block_fee_rates(&b, &chain_state);
                                    match chain_state.accept_block(&b) {
                                        Ok(acc) => {
                                            chain_state.bump_connect_heartbeat();
                                            // Same rule as above: a buffered
                                            // block that stored without
                                            // connecting confirmed nothing, so
                                            // no purge or fee sample may run
                                            // for it -- and the unmoved tip
                                            // means this drain is done.
                                            let Some(h) = chain_state.connected_height(&acc) else {
                                                break;
                                            };
                                            fee_estimator.record_block(&b_fees);
                                            mempool.remove_for_block(&b, h);
                                            reconsider_orphans_on_block(&orphanage, &mempool, &chain_state, &b);
                                        }
                                        // Another block waiting on the same
                                        // parent may still connect. Each pass
                                        // takes one block out, so this ends.
                                        Err(_) => continue,
                                    }
                                }
                                None => break,
                            }
                        }
                        let height = chain_state.tip_height();
                        if height / 1000 > last_log_height / 1000 {
                            tracing::info!(height, buffered = orphan_blocks.len(), "IBD progress");
                            last_log_height = height;
                        }

                        // Flush UTXO cache immediately in normal mode (not IBD).
                        // This only happens once per ~10 min so has no performance impact.
                        let _ = chain_state.flush_coin_cache();

                        // Periodic pruning
                        if keep_blocks > 0 && height > keep_blocks
                            && height / 1000 > last_prune_height / 1000
                        {
                            let deleted = chain_state.prune_blocks(keep_blocks);
                            if deleted > 0 {
                                tracing::info!(height, deleted, "Pruned old block files");
                            }
                            last_prune_height = height;
                        }
                    }
                    Err(crate::chain::state::ChainError::Duplicate) => {}
                    Err(crate::chain::state::ChainError::PrevBlockNotFound) => {
                        Self::hold_for_parent(&mut orphan_blocks, sender, block, requested, network, &peer_manager);
                    }
                    // Core's `bad-prevblk`: nothing connects on a parent
                    // marked invalid until `reconsiderblock` clears it, so
                    // the block is not kept.
                    Err(crate::chain::state::ChainError::BadPrevBlock) => {
                        tracing::debug!(%hash, "Block builds on a block marked invalid; not kept");
                    }
                    Err(e) => {
                        tracing::warn!(%hash, "Block rejected: {}", e);
                    }
                }
            }

            // A competing branch whose blocks are all stored, with none left
            // to arrive and trigger the switch from `accept_block` (#856):
            // blocks the IBD scheduler fetched before handing off, a data
            // repair, a restart. The same situation as the tail below, for
            // a branch that forks below the tip. Keyed inside on what has
            // changed since the last attempt, so an idle wakeup is cheap and
            // a failing reorg is not retried every 500ms.
            if let Err(e) = chain_state.activate_best_stored_chain() {
                tracing::warn!(error = %e, "Could not activate the best stored chain");
            }

            // Drain any stored-but-unconnected tail on the best header chain
            // (issue #582). A torn-down IBD connector can leave blocks it
            // downloaded but never connected sitting on disk; nothing else
            // in steady state can reach them — `request_missing_blocks`
            // skips them (data present), and a re-sent copy dies in
            // `accept_block` as `Duplicate` (status is already DataStored),
            // so the channel above cannot carry them either.
            Self::connect_stored_tail(
                &chain_state,
                &fee_estimator,
                &mempool,
                &orphanage,
                &peer_manager,
            );
        }
    }

    /// A block whose parent has no index entry. Core refuses it as
    /// `prev-blk-not-found` (`validation.cpp:4216`) and keeps nothing. Here it
    /// waits for its parent, within the bounds of
    /// [`crate::net::orphan_blocks::OrphanBlocks`], only if this node asked
    /// for it. Either way the sender is asked for headers, which is how the
    /// node learns the parent, as Core does for headers that do not connect
    /// (`HandleUnconnectingHeaders`) and satd does for a `cmpctblock` on an
    /// unknown parent.
    fn hold_for_parent(
        orphan_blocks: &mut crate::net::orphan_blocks::OrphanBlocks,
        sender: PeerId,
        block: bitcoin::Block,
        requested: bool,
        network: Network,
        peer_manager: &std::sync::Weak<PeerManager>,
    ) {
        let hash = block.block_hash();
        if requested && orphan_blocks.insert(sender, block, network, Instant::now()) {
            tracing::debug!(
                %hash,
                peer = sender,
                waiting = orphan_blocks.len(),
                bytes = orphan_blocks.bytes(),
                "Block waits for its parent"
            );
        } else {
            tracing::debug!(%hash, peer = sender, requested, "Dropped a block whose parent is unknown");
        }
        if let Some(pm) = peer_manager.upgrade() {
            pm.maybe_send_getheaders(sender);
        }
    }

    /// Connect blocks that are already stored on disk and extend the tip,
    /// walking the best-header-chain frontier until data runs out, a
    /// block fails to connect, or the per-wakeup cap is hit. Returns the
    /// number of blocks connected.
    ///
    /// This is the steady-state counterpart of the IBD connect loop's
    /// stored-block walk: it exists so a tail downloaded by a scheduler
    /// that tore down before connecting it (issue #582) drains without a
    /// network event. Out-of-order delivery at the tip is the other
    /// producer of this state: a block whose parent has not arrived is
    /// stored and waits (`accept_block` activates only a chain whose every
    /// block has data), so it sits `DataStored` above the tip with nothing
    /// on the network path able to reach it — `request_missing_blocks`
    /// skips it (data present) and a re-sent copy dies as `Duplicate`.
    /// Once the late parent connects, this drain is what picks it up.
    ///
    /// Idle cost is one height-index lookup per wakeup — at the tip there
    /// is no row above the frontier and the loop exits immediately.
    ///
    /// The cap equals the scheduler-creation threshold on purpose: a
    /// stored tail longer than 24 coincides with `headers_tip > tip + 24`,
    /// so the run loop's `maybe_start_ibd` poll re-arms within one
    /// fallback tick and the IBD connect loop — which flushes on the
    /// dirty-cache threshold, prunes, and skips per-block fee recording —
    /// takes the bulk over. This drain only needs to cover what that gate
    /// can leave behind. The cap is also what bounds the caller's
    /// latency: the block processor must return to its loop top promptly
    /// to notice a newly-armed scheduler and to keep servicing the
    /// channel.
    fn connect_stored_tail(
        chain_state: &Arc<ChainState>,
        fee_estimator: &FeeEstimator,
        mempool: &Arc<Mempool>,
        orphanage: &Arc<TxOrphanage>,
        peer_manager: &std::sync::Weak<PeerManager>,
    ) -> u32 {
        const MAX_PER_WAKEUP: u32 = 24;
        let mut connected = 0u32;
        while connected < MAX_PER_WAKEUP {
            // Cost gates, not the guard — `connect_stored_block` re-checks
            // every fact under the accept lock. A post-handoff fork-blocked
            // frontier is a routine wait state for this loop's caller, and
            // without these two checks each 500ms wakeup would pay a full
            // block read plus a per-input fee computation (and admit
            // `next_block_to_connect`'s rate-limited full-index scan) just
            // to have the connect reject the row. The frontier check is
            // two point lookups and short-circuits all of that; the
            // DataStored check below catches the reorg-displaced `Valid`
            // row the frontier check cannot see.
            if !chain_state.frontier_connects_to_tip() {
                break;
            }
            let next_height = chain_state.tip_height() + 1;
            let Some(hash) = chain_state.next_block_to_connect(next_height) else {
                break;
            };
            if !chain_state.has_block_data(&hash) {
                break;
            }
            // The entry's height is the block's own (parent + 1), immutable
            // and tip-independent -- the purge below must report it, not a
            // tip re-read that a concurrent connect can already have moved.
            let block_height = match chain_state.get_block_index(&hash) {
                Some(entry)
                    if entry.status == crate::storage::blockindex::BlockStatus::DataStored
                        && entry.header.prev_blockhash == chain_state.tip_hash() =>
                {
                    entry.height
                }
                _ => break,
            };
            // The block bytes are needed regardless of outcome: fee rates
            // must be computed against the pre-connect UTXO view, and the
            // mempool/orphanage bookkeeping below needs the transactions.
            let Some(block) = chain_state.get_block(&hash) else {
                if let Some(pm) = peer_manager.upgrade() {
                    pm.refetch_unreadable_block(hash, block_height);
                }
                break;
            };
            let fees = Self::compute_block_fee_rates(&block, chain_state);
            // Connects and reports the block as `accept_block` does.
            // `-blocknotify`, block announcement, Electrum and Esplora
            // subscribers, the streaming API and ZMQ all learn of new blocks
            // from its `BlockConnected`, and without it every one of them
            // missed a block that reached the tip here (#900).
            match chain_state.connect_stored_block_and_report(&hash) {
                Ok(_) => {
                    chain_state.bump_connect_heartbeat();
                    chain_state
                        .warnings()
                        .clear(crate::warnings::CONNECT_PERSISTENT_FAILURE);
                    fee_estimator.record_block(&fees);
                    mempool.remove_for_block(&block, block_height);
                    reconsider_orphans_on_block(orphanage, mempool, chain_state, &block);
                    connected += 1;
                    // `-stopatheight`. The connect's event reaches the watcher
                    // in `main` as well, but only after this walk has gone
                    // on to its next block; checking here stops the walk
                    // at the target rather than past it (#873).
                    if peer_manager.upgrade().is_some_and(|pm| pm.stop_if_at_height(block_height)) {
                        break;
                    }
                }
                // Any failure parks the walk for this wakeup: `Duplicate`
                // means the tip moved under us, `BadPrevBlock` means the
                // frontier row is fork-blocked and the reorg-capable paths
                // own it. Either way the next wakeup re-evaluates.
                Err(_) => break,
            }
        }
        if connected > 0 {
            tracing::info!(
                connected,
                height = chain_state.tip_height(),
                "Drained stored-but-unconnected blocks at the tip"
            );
            let _ = chain_state.flush_coin_cache();
        }
        connected
    }

    /// IBD connect loop: sequentially connect stored blocks from tip forward.
    /// Uses a prefetch pipeline to read and pre-process upcoming blocks in
    /// background threads while the connect thread works on the current block.
    /// Sleeps (via condvar) when the next block isn't downloaded yet.
    ///
    /// Write-mode lifecycle: enters BulkLoad via `BulkLoadGuard::new`;
    /// restores Normal (and runs a best-effort durable flush) from the
    /// guard's `Drop` impl. That covers every exit path — clean success,
    /// persistent-failure break, scheduler-cleared break, and panic unwind
    /// — so BulkLoad semantics cannot leak into steady-state operation.
    #[allow(clippy::too_many_arguments)]
    fn ibd_connect_loop(
        chain_state: &ChainState,
        _fee_estimator: &FeeEstimator,
        connect_signal: &Arc<(parking_lot::Mutex<bool>, Condvar)>,
        ibd: &Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
        keep_blocks: u32,
        prefetch_workers: usize,
        last_log_height: &mut u32,
        last_prune_height: &mut u32,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
        network: Network,
        ibd_eta_secs: &Arc<AtomicU64>,
        peer_manager: &std::sync::Weak<PeerManager>,
        shutdown: &tokio::sync::watch::Receiver<bool>,
    ) {
        let mut connected_count = 0u64;
        let mut retry_count = 0u32;
        let start_time = Instant::now();
        let perf = std::sync::Arc::new(crate::perf::IbdPerf::new());

        // Weight-aware ETA estimator
        let target = ibd.read().as_ref().map(|s| s.target_height()).unwrap_or(0);
        let is_mainnet = network == Network::Bitcoin;
        let mut eta_estimator = crate::ibd_eta::IbdEtaEstimator::new(
            chain_state.tip_height(), target, is_mainnet,
        );

        // Start the prefetch pipeline
        let store: Arc<dyn crate::storage::Store + Send + Sync> =
            chain_state.store_ref().clone();
        let assumevalid_active = chain_state.is_assumevalid_active();
        let primary_engine = chain_state.primary_engine();
        tracing::info!(?primary_engine, "Prefetch speculative verifier engine");
        let prefetch_handle = crate::chain::prefetch::start_prefetcher(
            store,
            chain_state.blocks_dir().to_path_buf(),
            chain_state.blocks_xor_key(),
            // No replay plan on the IBD path: the height→hash index is
            // authoritative there — it is written forward as blocks connect,
            // and `connect_stored_block` refuses anything that does not extend
            // the tip.
            None,
            chain_state.tip_height() + 1,
            prefetch_workers,
            128, // lookahead blocks
            assumevalid_active,
            primary_engine,
            network,
        );

        // Enter BulkLoad mode via an RAII guard: subsequent RocksDB writes
        // skip the WAL for the duration of IBD. The guard's Drop impl runs
        // on *every* exit path from this function — normal break, panic,
        // early return — ensuring we never leak WAL-disabled semantics
        // into steady-state operation. We still call `flush_durable` every
        // 1000 blocks below so a crash during IBD replays at most ~1000
        // blocks of work.
        //
        // Small catch-ups keep the WAL. BulkLoad's WAL-less writes are
        // volatile until a memtable flush, and its throughput win only
        // matters on replays measured in tens of thousands of blocks. A
        // routine restart's catch-up gets no measurable speedup but
        // inherits the full data-loss exposure — mainnet block 952978's
        // connect delta was lost from exactly this window after a 64-block
        // catch-up.
        let blocks_behind = target.saturating_sub(chain_state.tip_height());
        let _bulk_guard = if use_bulkload_for_catchup(blocks_behind) {
            tracing::info!(
                blocks_behind,
                "IBD write mode: BulkLoad (WAL disabled, flush every 1000 blocks)"
            );
            Some(BulkLoadGuard::new(chain_state))
        } else {
            tracing::info!(
                blocks_behind,
                threshold = BULKLOAD_MIN_BLOCKS_BEHIND,
                "IBD write mode: Normal (catch-up below BulkLoad threshold; WAL stays on)"
            );
            None
        };

        // RocksDB compaction backpressure state. We log a single warn when
        // we first start pausing in a sustained-pressure window, and a
        // single info when we resume — without this throttling the
        // backpressure loop would spam every 500ms it stays paused.
        let mut backpressure_paused = false;
        let mut backpressure_pause_started: Option<Instant> = None;

        // The height the connector is waiting on for block data, and since
        // when, for the "stuck waiting for block data" warning. It fires
        // once a wait passes `STUCK_WAIT_WARN_AFTER`, then once a minute.
        let mut stuck_wait: Option<StuckWait> = None;

        'connect: loop {
            // Shutdown: stop between blocks. Left running, the loop went on
            // connecting past the shutdown flush and the clean-shutdown
            // marker, and was inside RocksDB when the process exited
            // (#868). The scheduler is left in place; the prefetch pipeline
            // and the BulkLoad guard wind down below, as on every exit.
            if *shutdown.borrow() {
                tracing::info!(
                    height = chain_state.tip_height(),
                    "IBD connector stopped for shutdown"
                );
                break;
            }
            // Backpressure: if RocksDB has accumulated too many L0 SST files,
            // the chainstate is on the path that wedged a 78-GB process
            // during a mainnet IBD (10k+ L0 SSTs, 4h cumulative write-stall).
            // Pause the connector here to give compaction a chance to drain
            // before we add another batch of writes. We cap the per-iteration
            // wait so a buggy or stuck compactor cannot deadlock the loop —
            // the periodic forced-compactor (a separate thread) is the
            // backstop for that case.
            if ibd_l0_pause_at > 0 {
                let mut waited = Duration::ZERO;
                let max_wait = Duration::from_secs(60);
                let poll = Duration::from_millis(500);
                loop {
                    if *shutdown.borrow() {
                        continue 'connect;
                    }
                    let l0 = chain_state.chainstate_l0_files();
                    if l0 < ibd_l0_pause_at as u64 {
                        if backpressure_paused {
                            let dur = backpressure_pause_started
                                .map(|t| t.elapsed())
                                .unwrap_or_default();
                            tracing::info!(
                                l0_files = l0,
                                paused_secs = dur.as_secs(),
                                "IBD: L0 below threshold, resuming connector"
                            );
                            backpressure_paused = false;
                            backpressure_pause_started = None;
                        }
                        break;
                    }
                    if !backpressure_paused {
                        let pending = chain_state.chainstate_pending_compaction_bytes();
                        tracing::warn!(
                            l0_files = l0,
                            threshold = ibd_l0_pause_at,
                            pending_compaction_bytes = pending,
                            "IBD: L0 above pause threshold, pausing connector for compaction"
                        );
                        backpressure_paused = true;
                        backpressure_pause_started = Some(Instant::now());
                    }
                    if waited >= max_wait {
                        tracing::warn!(
                            l0_files = l0,
                            threshold = ibd_l0_pause_at,
                            waited_secs = waited.as_secs(),
                            "IBD: backpressure max-wait exceeded, proceeding anyway"
                        );
                        break;
                    }
                    std::thread::sleep(poll);
                    waited += poll;
                }
            }

            let target_height = {
                let sched = ibd.read();
                match sched.as_ref() {
                    Some(s) => s.target_height(),
                    None => break, // Scheduler cleared
                }
            };

            let tip_height = chain_state.tip_height();
            let next_height = tip_height + 1;

            if next_height > target_height {
                // Check if more headers have arrived since we started
                let headers_tip = chain_state.headers_tip_height();
                if headers_tip > target_height + 24 {
                    // More headers available — create a new scheduler for the next batch
                    tracing::info!(
                        height = tip_height,
                        blocks = connected_count,
                        new_target = headers_tip,
                        elapsed_secs = start_time.elapsed().as_secs(),
                        "IBD batch complete, starting next batch"
                    );
                    let effective_max_ahead = Self::resolve_max_ahead(max_ahead, headers_tip, tip_height);
                    let new_sched = IbdScheduler::new(headers_tip, tip_height, chain_state, effective_max_ahead);
                    *ibd.write() = Some(new_sched);
                    connected_count = 0;
                    // Update prefetch cursor for the new batch
                    prefetch_handle.advance_cursor(tip_height + 1);
                    // The run() loop will detect has_ibd=true within 2s and assign peers
                    continue;
                }
                // Truly done — flush UTXO cache and force a durable
                // checkpoint before marking IBD complete. Fail-closed: if
                // either step errors, we loop back instead of claiming
                // completion, so subsequent retries can attempt to
                // checkpoint again. The BulkLoadGuard restores Normal
                // write mode on any actual exit path.
                chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                if let Err(e) = chain_state.flush_coin_cache() {
                    tracing::error!(
                        error = %e,
                        "IBD completion: flush_coin_cache failed; deferring completion"
                    );
                    chain_state.connect_phases().enter(ConnectPhase::Idle);
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                chain_state.connect_phases().enter(ConnectPhase::FlushDurable);
                if let Err(e) = chain_state.flush_durable() {
                    tracing::error!(
                        error = %e,
                        "IBD completion: flush_durable failed; deferring completion \
                         (will retry on next loop iteration)"
                    );
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                tracing::info!(
                    height = tip_height,
                    blocks = connected_count,
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "IBD complete"
                );
                *ibd.write() = None;
                break;
            }

            let hash = match chain_state.next_block_to_connect(next_height) {
                Some(h) => h,
                None => {
                    // No header for this height yet — wait
                    chain_state.connect_phases().enter(ConnectPhase::WaitingForHeader);
                    let (lock, cvar) = &**connect_signal;
                    let mut ready = lock.lock();
                    *ready = false;
                    let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                    chain_state.connect_phases().enter(ConnectPhase::Idle);
                    continue;
                }
            };

            if chain_state.has_block_data(&hash) {
                // Try to get a pre-processed block from the prefetcher
                let connect_start = Instant::now();
                let connect_result = match prefetch_handle.take_block(next_height) {
                    Some(pre) if pre.hash == hash => {
                        perf.prefetch_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let spec_count = pre.script_verified_txs.len() as u64;
                        if spec_count > 0 {
                            perf.spec_verify_skipped.fetch_add(spec_count, std::sync::atomic::Ordering::Relaxed);
                        }
                        chain_state.connect_preprocessed_block(pre)
                    }
                    _ => {
                        perf.prefetch_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        chain_state.connect_stored_block(&hash)
                    }
                };
                perf.connect_ns.fetch_add(connect_start.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                perf.connect_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                match connect_result {
                    Ok(_) => {
                        connected_count += 1;
                        retry_count = 0;
                        stuck_wait = None;
                        // Lock-free progress signal for the stall watchdog.
                        // Must run on every successful connect, before any
                        // subsequent step that takes a lock the watchdog
                        // would otherwise block on.
                        chain_state.bump_connect_heartbeat();
                        // Clear any prior connect-failure warnings now that
                        // we've made forward progress.
                        chain_state.warnings().clear(crate::warnings::CONNECT_PERSISTENT_FAILURE);
                        chain_state.warnings().clear("connect.retry");
                        // Update scheduler connect cursor
                        {
                            let mut sched = ibd.write();
                            if let Some(s) = sched.as_mut() {
                                s.connect_cursor_advanced(next_height);
                            }
                        }
                        // Tell the prefetcher we've advanced
                        prefetch_handle.advance_cursor(next_height + 1);

                        // `-stopatheight`. This connect emits no chain
                        // event, so the watcher in `main` never heard of
                        // it, and IBD ran straight past the target (#873).
                        // The shutdown asked for here also stops the loop
                        // at the target: its first check is for shutdown.
                        if let Some(pm) = peer_manager.upgrade() {
                            pm.stop_if_at_height(next_height);
                        }

                        // Skip fee recording during IBD — the coins are already
                        // spent so get_coin returns None for every input, and fee
                        // data from old blocks is useless for estimation anyway.

                        // Flush if dirty map is getting large (caps memory usage)
                        if chain_state.cache_dirty_count() > chain_state.flush_threshold() {
                            chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                            if let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush cache: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_coin_cache_failed",
                                    crate::warnings::Severity::Error,
                                    format!("UTXO cache flush failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_coin_cache_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::Idle);
                        }

                        // Log progress
                        if next_height / 1000 > *last_log_height / 1000 {
                            let elapsed = start_time.elapsed().as_secs().max(1);
                            let rate = connected_count / elapsed;
                            let (dl, inf, pend, _) = {
                                let sched = ibd.read();
                                sched.as_ref()
                                    .map(|s| s.progress())
                                    .unwrap_or((0, 0, 0, 0))
                            };
                            // Transfer cache perf counters and report
                            {
                                let store = chain_state.store_ref();
                                perf.cache_dirty_hits.fetch_add(
                                    store.perf_dirty_hits.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                perf.cache_clean_hits.fetch_add(
                                    store.perf_clean_hits.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                perf.cache_store_misses.fetch_add(
                                    store.perf_store_misses.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            perf.report(next_height);

                            // Feed the ETA estimator with this interval's wall-clock time
                            let interval_ms = perf.last_interval_ms.load(std::sync::atomic::Ordering::Relaxed);
                            eta_estimator.record_interval(next_height, interval_ms as f64 / 1000.0);
                            let eta_str = match eta_estimator.estimate_eta(next_height, target_height) {
                                Some(secs) => {
                                    ibd_eta_secs.store(secs, std::sync::atomic::Ordering::Relaxed);
                                    format!("ETA: {}", crate::ibd_eta::format_eta(secs))
                                }
                                None => {
                                    ibd_eta_secs.store(0, std::sync::atomic::Ordering::Relaxed);
                                    "ETA: --".to_string()
                                }
                            };

                            tracing::info!(
                                height = next_height,
                                "IBD: {}/{} connected, {} downloaded ahead, {} in-flight, {} pending ({} blk/s, {})",
                                next_height,
                                target_height,
                                dl,
                                inf,
                                pend,
                                rate,
                                eta_str,
                            );
                            *last_log_height = next_height;

                            // Flush UTXO cache to disk every 1000 blocks, then
                            // force a durable checkpoint. With BulkLoad mode
                            // (WAL disabled) this bounds crash-recovery replay
                            // work to the last ~1000 blocks.
                            chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                            if let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush UTXO cache: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_coin_cache_failed",
                                    crate::warnings::Severity::Error,
                                    format!("UTXO cache flush failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_coin_cache_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::FlushDurable);
                            if let Err(e) = chain_state.flush_durable() {
                                tracing::error!("Failed durable checkpoint: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_durable_failed",
                                    crate::warnings::Severity::Error,
                                    format!("durable checkpoint failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_durable_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::Idle);
                        }
                        // Periodic pruning
                        if keep_blocks > 0 && next_height > keep_blocks
                            && next_height / 1000 > *last_prune_height / 1000
                        {
                            let deleted = chain_state.prune_blocks(keep_blocks);
                            if deleted > 0 {
                                tracing::info!(height = next_height, deleted, "Pruned old block files");
                            }
                            *last_prune_height = next_height;
                        }
                        continue; // Immediately try next block
                    }
                    // An operator `loadtxoutset` is streaming and the
                    // chainstate is deliberately frozen. Park without burning
                    // the retry budget — this is not a failing block, and 30
                    // retries of it must not raise the persistent-failure
                    // warning (and fail `/readyz` recovery) while the node is
                    // doing exactly what it was told. The heartbeat keeps
                    // ticking via the manager loop, so the stall watchdog
                    // stays quiet too.
                    Err(crate::chain::state::ChainError::SnapshotLoadInProgress) => {
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                    // `Duplicate` deliberately falls through to the generic
                    // error arm rather than retrying immediately. It means the
                    // block offered at tip+1 is one this chainstate already
                    // connected, which `connect_stored_block` rejects before it
                    // does any work — so `continue` here re-offers the same
                    // block with no sleep and no retry counter, spinning a core
                    // for as long as the condition lasts. It is reachable
                    // whenever a height row names a `Valid` block: a reorg
                    // displaced it and `disconnect_block` writes no status, so
                    // the marker sticks. Counting it toward the retry limit
                    // lets the existing recovery run instead of spinning.
                    Err(e) => {
                        retry_count += 1;
                        if matches!(e, crate::chain::state::ChainError::BlockDataUnreadable(_))
                            && let Some(pm) = peer_manager.upgrade()
                        {
                            pm.refetch_unreadable_block(hash, next_height);
                        }
                        if retry_count >= 30 {
                            // The block at tip+1 can't connect because its
                            // parent isn't the active tip. If a competing
                            // higher-work header chain exists, this is a reorg
                            // the linear IBD connector cannot perform: it keeps
                            // requesting `tip+1` (a block on the other branch)
                            // while the height-indexed scheduler reports itself
                            // complete and never fetches the missing fork
                            // block. Tear down the stalled scheduler and hand
                            // off to the reorg-capable steady-state path, which
                            // pulls the fork (missing_blocks_for_best_header_
                            // chain) and runs ActivateBestChain — exactly what
                            // a restart would do, without the restart.
                            if matches!(e,
                                    crate::chain::state::ChainError::PrevBlockNotFound
                                    | crate::chain::state::ChainError::BadPrevBlock)
                                && chain_state.best_header_beats_active_tip()
                            {
                                // Gate on PrevBlockNotFound/BadPrevBlock specifically: best_header_
                                // beats_active_tip() is true for ~all of IBD, so
                                // without the variant check ANY persistent connect
                                // error (invalid block, I/O fault) would be masked
                                // as a fork-handoff instead of failing closed.
                                //
                                // Log (for diagnostics) but do NOT record a
                                // persistent node-warning: this is a self-healing
                                // transition, not an unresolved operator issue,
                                // so it must not linger in the active-warnings
                                // panel after the reorg succeeds.
                                tracing::warn!(
                                    height = next_height, %hash,
                                    "IBD connector stalled on a competing higher-work chain \
                                     ({e}); exiting IBD so the steady-state reorg path can pull \
                                     the fork and reorg"
                                );
                                // Resolve the retry warning — we are now
                                // handling this via the reorg path, not looping.
                                // And clear any standing persistent-failure
                                // warning for the same reason: its only other
                                // clear site is this connector's own success
                                // branch, and this branch tears the connector
                                // down. Left standing, the warning holds
                                // `/readyz` at 503 forever on a node the
                                // steady-state reorg path is about to heal —
                                // the IBD connector never runs again once the
                                // tip tracks the headers.
                                chain_state
                                    .warnings()
                                    .clear(crate::warnings::CONNECT_PERSISTENT_FAILURE);
                                chain_state.warnings().clear("connect.retry");
                                *ibd.write() = None;
                                break;
                            }
                            // "Giving up" is what this used to say, and it was
                            // not true. Breaking exits the connector loop, not
                            // the process; the run loop sees `has_ibd` and
                            // starts a fresh IBD within seconds, which fails
                            // at the same height and arrives back here. An
                            // operator watching a mainnet node read "giving
                            // up" every thirty seconds for five and a half
                            // hours while the node did anything but.
                            tracing::error!(
                                height = next_height, %hash, retries = retry_count,
                                "Persistent connect failure after {} retries; restarting IBD, \
                                 which will retry the same block: {}",
                                retry_count, e
                            );
                            chain_state.warnings().record(
                                crate::warnings::CONNECT_PERSISTENT_FAILURE,
                                crate::warnings::Severity::Error,
                                format!(
                                    "block {} ({}) failed to connect after {} retries: {}. \
                                     IBD will restart and retry the same block; this repeats \
                                     until the cause is fixed",
                                    next_height, hash, retry_count, e
                                ),
                                serde_json::json!({
                                    "height": next_height,
                                    "hash": hash.to_string(),
                                    "retries": retry_count,
                                    "error": e.to_string(),
                                }),
                            );
                            // Exit the connector loop. NOT the process: the run
                            // loop restarts IBD from scratch, which is the
                            // point (a fresh scheduler can pick different
                            // peers, and a transient cause clears). systemd is
                            // not involved — the comment here used to claim it
                            // was, which is why the log line above claimed to
                            // be giving up.
                            break;
                        }
                        if retry_count.is_multiple_of(10) {
                            tracing::warn!(
                                height = next_height, %hash, retries = retry_count,
                                "Connect stored block failed (retrying): {}", e
                            );
                            chain_state.warnings().record(
                                "connect.retry",
                                crate::warnings::Severity::Warn,
                                format!(
                                    "block {} ({}) connect retry {}: {}",
                                    next_height, hash, retry_count, e
                                ),
                                serde_json::json!({
                                    "height": next_height,
                                    "hash": hash.to_string(),
                                    "retries": retry_count,
                                    "error": e.to_string(),
                                }),
                            );
                        }
                        chain_state.connect_phases().enter(ConnectPhase::CondvarWait);
                        let (lock, cvar) = &**connect_signal;
                        let mut ready = lock.lock();
                        *ready = false;
                        let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                        chain_state.connect_phases().enter(ConnectPhase::Idle);
                        continue;
                    }
                }
            } else {
                // Next block not downloaded yet — wait for signal
                chain_state.connect_phases().enter(ConnectPhase::WaitingForBlockData);
                // Diagnostic for the wedge class where the connector spins
                // forever on a HeaderOnly entry whose data never arrives.
                // Once the wait on this height passes the threshold, log a
                // scheduler-state snapshot so we can see if the downloader
                // is even trying, and refresh it every 60s. A shorter wait is
                // out-of-order download working as intended, and warning on
                // it filled the log with one line per block (#904). Cheap:
                // the scheduler read is a single RwLock::read() and three
                // HashMap lookups.
                if StuckWait::should_warn(&mut stuck_wait, next_height, Instant::now()) {
                    let (
                        in_pending,
                        in_flight,
                        downloaded,
                        has_height_to_hash,
                        inflight_peer,
                        inflight_age,
                        peer_load,
                    ) = {
                        let sched = ibd.read();
                        match sched.as_ref() {
                            Some(s) => {
                                let p = s.inflight_peer(next_height);
                                (
                                    s.pending_contains(next_height),
                                    s.in_flight_contains(next_height),
                                    s.is_downloaded(next_height),
                                    s.height_to_hash_contains(next_height),
                                    p,
                                    s.inflight_age_secs(next_height),
                                    p.map(|pid| s.peer_inflight_count(pid)),
                                )
                            }
                            None => (false, false, false, false, None, None, None),
                        }
                    };
                    let inflight_peer_height = inflight_peer.and_then(|pid| {
                        // Note: we don't have a back-ref to `self` here
                        // (this is in block_processor), so look up via the
                        // ChainState-less PeerManager Arc would require
                        // passing it in. Leaving as None for now keeps
                        // this diagnostic single-purpose — the peer ID is
                        // enough to grep the journal for that peer's
                        // version log.
                        let _ = pid;
                        None::<i32>
                    });
                    let entry = chain_state.get_block_index(&hash);
                    let waited_secs = stuck_wait.map(|w| w.since.elapsed().as_secs());
                    tracing::warn!(
                        height = next_height,
                        %hash,
                        ?waited_secs,
                        in_pending,
                        in_flight,
                        downloaded,
                        has_height_to_hash,
                        ?inflight_peer,
                        ?inflight_age,
                        ?peer_load,
                        ?inflight_peer_height,
                        block_index_status = ?entry.as_ref().map(|e| e.status),
                        file_number = entry.as_ref().map(|e| e.file_number),
                        data_pos = entry.as_ref().map(|e| e.data_pos),
                        "Connector stuck waiting for block data; scheduler state for this height"
                    );
                }
                let (lock, cvar) = &**connect_signal;
                let mut ready = lock.lock();
                *ready = false;
                let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                chain_state.connect_phases().enter(ConnectPhase::Idle);
            }
        }

        // Stop the prefetch pipeline. For shutdown, without waiting for it:
        // a worker can be tens of seconds into one transaction's scripts,
        // and it holds nothing shutdown needs (#868).
        if *shutdown.borrow() {
            prefetch_handle.abandon();
        } else {
            prefetch_handle.stop();
        }
    }

    /// Extract fee rates from a connected block and feed them to the fee estimator.
    /// Compute per-tx fee rates (sat/kvB) for a block. Must be called BEFORE
    /// `accept_block`, since connect_block removes spent coins from the UTXO set.
    /// Intra-block spends are skipped (the prior tx's outputs are not yet in
    /// the UTXO set at this point).
    fn compute_block_fee_rates(block: &bitcoin::Block, chain_state: &ChainState) -> Vec<u64> {
        let mut fee_rates = Vec::new();
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            let weight = tx.weight().to_wu();
            if weight == 0 {
                continue;
            }
            let mut sum_inputs: u64 = 0;
            let mut inputs_found = true;
            for input in &tx.input {
                match chain_state.get_coin(&input.previous_output) {
                    Some(coin) => sum_inputs += coin.amount,
                    None => {
                        inputs_found = false;
                        break;
                    }
                }
            }
            if !inputs_found {
                continue;
            }
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            if sum_inputs >= sum_outputs {
                let fee = sum_inputs - sum_outputs;
                let fee_rate = crate::mempool::policy::fee_rate_sat_per_kvb(fee, weight); // sat/kvB
                fee_rates.push(fee_rate);
            }
        }
        fee_rates
    }

    /// Ban score for a mempool rejection of a peer-relayed transaction. Only
    /// *consensus-invalid* transactions are peer misbehavior; policy,
    /// standardness, resource and RBF rejections are not — the peer cannot know
    /// our local relay policy, and banning for them severs honest peers on
    /// low-fee networks (testnet4 is a sub-min-relay-fee tx soup, which used to
    /// ban our entire peer set one `+1` at a time). This mirrors Bitcoin Core,
    /// which DoS-scores only `TX_CONSENSUS` failures. `MissingInputs` never
    /// reaches here — it is handled as an orphan upstream.
    fn tx_rejection_ban_score(e: &MempoolError) -> u32 {
        match e {
            // Consensus-invalid: bad script/signature, or outputs > inputs.
            MempoolError::Script(..) | MempoolError::BadAmounts => INVALID_TX_BAN_SCORE,
            // Everything else is local policy / standardness / resource limits /
            // RBF / duplicates — not misbehavior.
            MempoolError::AlreadyExists
            | MempoolError::SameNonWitnessData
            | MempoolError::ConflictingSpend
            | MempoolError::MissingInputs
            | MempoolError::InsufficientFee(..)
            | MempoolError::MempoolFull
            | MempoolError::MempoolMinFeeNotMet(..)
            | MempoolError::Validation(_)
            | MempoolError::PrematureCoinbaseSpend
            | MempoolError::DecodeFailed
            | MempoolError::Dust
            | MempoolError::NonStandardOpReturn
            | MempoolError::InsufficientReplacementFee(..)
            | MempoolError::SpendsConflictingTx(..)
            | MempoolError::TooManyReplacements(..)
            | MempoolError::DoesNotImproveFeerateDiagram(..)
            | MempoolError::TooLongMempoolChain
            // Non-final for the *next* block is tip-relative, not misbehavior:
            // a peer one block behind (or ahead) legitimately relays these.
            // Core classes them TX_PREMATURE_SPEND, which it does not score.
            | MempoolError::NonFinal
            | MempoolError::NonBip68Final
            // Local-submission-only refusal (§6.1); P2P traffic never produces it
            // and it is never peer misbehavior.
            | MempoolError::Quarantined(_)
            // Ephemeral dust policy errors: local package submission only.
            | MempoolError::EphemeralDustFee
            | MempoolError::MissingEphemeralSpends(_) => 0,
        }
    }

    fn handle_tx(&self, id: PeerId, tx: bitcoin::Transaction) {
        // A peer told not to send transactions -- a block-relay-only link, or
        // any peer of a `-blocksonly` node unless it holds `relay` -- is
        // violating the protocol by sending one, and Core disconnects it.
        if self.rejects_incoming_txs(id) {
            tracing::debug!("transaction sent in violation of protocol, disconnecting peer={id}");
            self.disconnect_by_id(id);
            return;
        }
        // During IBD, ignore relayed transactions — our UTXO set is incomplete
        // so validation would produce false MissingInputs rejections.
        if self.is_ibd() {
            return;
        }

        let txid = tx.compute_txid();
        match self.mempool.accept_transaction(
            tx.clone(),
            &self.chain_state,
            self.chain_state.script_verifier(),
            crate::mempool::pool::TxSource::P2p,
            // Peer traffic quarantines as designed; the §6.1 refusal is local-only.
            false,
        ) {
            Ok(_) => {
                // Core stamps `m_last_tx_time` only on a VALID mempool
                // accept. Stamping it on receipt let a peer keep its
                // eviction protection alive with a stream of transactions
                // the node rejects.
                if let Some(h) = self.peers.read().get(&id) {
                    h.stats.record_transaction();
                }
                self.broadcast_inv(id, txid);
                // A new parent just entered the mempool — walk orphans
                // that were waiting on it and try to admit them.
                self.drain_orphans_for_parent(txid);
            }
            Err(MempoolError::MissingInputs) => {
                // Don't ban — peer may just be ahead of us. Defer to
                // orphanage and ask the same peer for the parents.
                let missing = self.collect_missing_parents(&tx);
                match self.orphanage.add(tx.clone(), id, missing.clone()) {
                    Ok(AddOutcome::Added) => {
                        // Core keeps a first-time orphan for reconstruction:
                        // its parents may well confirm alongside it.
                        self.keep_for_reconstruction(tx);
                        let want: Vec<bitcoin::Txid> = missing.into_iter().collect();
                        self.send_to_peer(id, sync::make_getdata_txs(&want));
                        tracing::debug!(%txid, peer = id, "Tx deferred to orphanage");
                    }
                    Ok(AddOutcome::Duplicate) => {
                        // Peer resent an orphan we already hold. Don't
                        // amplify their traffic by re-requesting the same
                        // parents; parents are already being awaited from
                        // the original sender (and natural propagation).
                        tracing::trace!(
                            %txid,
                            peer = id,
                            "Duplicate orphan, skipping parent re-request"
                        );
                    }
                    Err(OrphanReject::NoMissingParents) => {
                        // Race: parent entered mempool between accept and
                        // collect. Drop silently — the peer will re-relay
                        // the child via normal INV once we announce the
                        // parent, or another peer will redeliver.
                        tracing::debug!(
                            %txid,
                            peer = id,
                            "Orphan with no resolvable missing parents, dropping"
                        );
                    }
                    Err(OrphanReject::TooLarge) => {
                        self.add_ban_score(id, 1, "orphan too large");
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "{txid} (wtxid={}) from peer={id} was not accepted: {}",
                    tx.compute_wtxid(),
                    e.state_string()
                );
                // Only consensus-invalid transactions are misbehavior; policy
                // rejections (fee floor, dust, mempool limits, RBF, …) carry no
                // ban score so we don't sever honest peers on low-fee networks.
                let score = Self::tx_rejection_ban_score(&e);
                if score > 0 {
                    self.add_ban_score(id, score, &format!("Tx rejected: {}", e));
                } else if !matches!(e, MempoolError::AlreadyExists) {
                    // Refused by policy but well-formed: a miner with other
                    // policy may still include it. Core's first-time-reject
                    // insertion. A consensus-invalid transaction is not kept,
                    // and one we already hold is not a rejection.
                    self.keep_for_reconstruction(tx);
                }
            }
        }
    }

    /// Inspect `tx`'s inputs and return the set of parent txids whose
    /// outputs we can't resolve in either the confirmed UTXO set or the
    /// current mempool. Used to decide which parents to ask for after
    /// orphaning a tx.
    fn collect_missing_parents(
        &self,
        tx: &bitcoin::Transaction,
    ) -> std::collections::HashSet<bitcoin::Txid> {
        let mut missing = std::collections::HashSet::new();
        for input in &tx.input {
            let parent = input.previous_output.txid;
            if self.chain_state.get_coin(&input.previous_output).is_some() {
                continue;
            }
            if self.mempool.get(&parent).is_some() {
                continue;
            }
            missing.insert(parent);
        }
        missing
    }

    /// Announce a newly-connected best-tip block to peers. Peers that
    /// sent `sendheaders` (BIP 130) receive a `headers` message carrying
    /// the new header; the rest receive a legacy `inv` advertising the
    /// block hash. In both cases the peer pulls the full block with a
    /// follow-up `getdata`, which [`handle_getdata`] serves.
    ///
    /// Without this, satd connected blocks (whether self-mined via
    /// `generatetoaddress`/`submitblock` or relayed from another peer)
    /// but never told its peers, so any announcement-driven consumer —
    /// another node, or a Core-client backend like NBXplorer/BTCPayServer
    /// that indexes blocks over P2P — would learn the new height via
    /// polling yet never fetch the block, and sit permanently unsynced.
    ///
    /// Suppressed while bulk-syncing (`tip` far below the best known
    /// header): during IBD peers drive their own sync via `getheaders`,
    /// and announcing every connected block would be redundant spam. The
    /// guard mirrors [`Self::is_ibd`] but, unlike it, treats an unknown
    /// header tip (`htip == 0`, e.g. a regtest node whose peers have no
    /// chain) as "at the frontier" so self-mined blocks are still
    /// announced.
    pub fn announce_block(&self, hash: bitcoin::BlockHash) {
        let tip = self.chain_state.tip_height();
        let htip = self.headers_tip.load(Ordering::Relaxed) as u32;
        if htip != 0 && tip + 24 < htip {
            return;
        }
        let Some(entry) = self.chain_state.get_block_index(&hash) else {
            return;
        };
        let headers_msg = NetworkMessage::Headers(vec![entry.header]);
        let inv_msg = NetworkMessage::Inv(vec![Inventory::Block(hash)]);

        // A peer that asked for high-bandwidth relay gets the block itself as
        // a `cmpctblock` — but only the tip, one block at a time, as Core's
        // `SendMessages` does (a reorg's intermediate blocks go out as
        // headers). A peer that already has the block, because it sent it
        // to us or the pre-connect announcement already reached it, is
        // skipped.
        let is_tip = self.chain_state.tip_hash() == hash;
        let wants_compact = is_tip && {
            let peers = self.peers.read();
            peers.values().any(|h| {
                h.info.state == PeerState::Connected
                    && h.info.hb_from
                    && h.info.compact_blocks
                    && h.info.known_block != Some(hash)
            })
        };
        let compact = if wants_compact {
            self.cached_compact(&hash).or_else(|| {
                self.chain_state
                    .get_block(&hash)
                    .and_then(|block| self.compact_for(&block, entry.height, false))
            })
        } else {
            None
        };

        let mut announced = Vec::new();
        {
            let peers = self.peers.read();
            for (id, handle) in peers.iter() {
                if handle.info.state != PeerState::Connected || handle.info.known_block == Some(hash) {
                    continue;
                }
                let msg = match &compact {
                    Some(c) if handle.info.hb_from && handle.info.compact_blocks => {
                        NetworkMessage::CmpctBlock(bitcoin::p2p::message_compact_blocks::CmpctBlock {
                            compact_block: (**c).clone(),
                        })
                    }
                    _ if handle.info.prefers_headers => headers_msg.clone(),
                    _ => inv_msg.clone(),
                };
                let is_compact = matches!(msg, NetworkMessage::CmpctBlock(_));
                if handle.msg_tx.try_send(msg).is_ok() {
                    if is_compact {
                        self.compact_stats.sent_announce.fetch_add(1, Ordering::Relaxed);
                    }
                    announced.push(*id);
                }
            }
        }
        if !announced.is_empty() {
            let mut peers = self.peers.write();
            for id in announced {
                if let Some(h) = peers.get_mut(&id) {
                    h.info.known_block = Some(hash);
                }
            }
        }
    }

    /// Relay a newly-admitted tx to other peers whose fee filter allows it.
    /// Relay-quarantined txs are never INV'd: the node declines to gossip
    /// them (design §2.4/§6.1).
    fn broadcast_inv(&self, from: PeerId, txid: bitcoin::Txid) {
        self.announce_to_peers(txid, Some(from));
    }

    /// `inv` `txid` to every connected, tx-relaying peer whose fee filter it
    /// clears, other than `skip`: by wtxid to a peer that negotiated BIP 339
    /// wtxid relay, by txid to the rest. Nothing goes out while the tx is
    /// relay-quarantined.
    fn announce_to_peers(&self, txid: bitcoin::Txid, skip: Option<PeerId>) {
        let entry = self.mempool.get(&txid);
        if entry.as_ref().is_some_and(|e| !e.scope.assists_relay()) {
            return;
        }
        let entry_fee_rate = entry.as_ref().map_or(0, |e| e.fee_rate);
        let by_txid = NetworkMessage::Inv(vec![Inventory::WitnessTransaction(txid)]);
        // A tx that has already left the mempool has no wtxid to give, and
        // a `getdata` for it would only be answered `notfound`.
        let by_wtxid = entry.map(|e| NetworkMessage::Inv(vec![Inventory::WTx(e.tx.compute_wtxid())]));
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if Some(*peer_id) == skip
                || handle.info.state != PeerState::Connected
                || !handle.info.relays_txs()
                || entry_fee_rate < handle.info.fee_filter
            {
                continue;
            }
            let inv = if handle.info.wtxid_relay { by_wtxid.as_ref() } else { Some(&by_txid) };
            if let Some(inv) = inv {
                let _ = handle.msg_tx.try_send(inv.clone());
            }
        }
    }

    /// Announce a locally-originated transaction (submitted via the
    /// `sendrawtransaction` RPC) to all fee-permitting peers.
    ///
    /// Without this, an RPC-broadcast tx enters the mempool but is never
    /// announced to the network, so it never propagates — peers only
    /// learn of txs we received from *another* peer (via `broadcast_inv`
    /// on the relay path). This is the local-origin counterpart: there is
    /// no source peer to exclude, so it invs every connected peer whose
    /// fee filter the tx clears. It is called synchronously from the RPC
    /// handler (not via the lossy mempool event broadcast) so a
    /// successful `sendrawtransaction` reliably reaches the wire.
    ///
    /// Relay-quarantined txs are withheld from the wire even on the
    /// local-origin path. A relay-scoped local submission is normally refused
    /// outright (design §6.1), but with an `allowquarantined` override the tx
    /// is admitted to the quarantine class and must still not be announced.
    pub fn announce_tx(&self, txid: bitcoin::Txid) {
        self.announce_to_peers(txid, None);
    }

    /// Broadcast a locally-originated transaction: decode it, accept it
    /// into the mempool, then [`announce_tx`](Self::announce_tx) it to
    /// peers. Returns the txid (as a JSON string) on success, or the
    /// mempool error `(code, message)` on failure.
    ///
    /// This is the shared core behind every broadcast surface — the
    /// `sendrawtransaction` JSON-RPC method and the MCP `send_transaction`
    /// tool both route through it, so the announce step is part of the
    /// operation itself and cannot be omitted by an individual handler
    /// (the surfaces stay thin and only format the result/errors). A bare
    /// mempool accept does not put a local-origin tx on the wire — the
    /// peer-relay path only fires for txs received from another peer.
    pub fn broadcast_transaction(
        &self,
        hex_tx: &str,
        source: crate::mempool::pool::TxSource,
        allow_quarantined: bool,
    ) -> Result<serde_json::Value, (i32, String)> {
        let tx_bytes =
            hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|_| (-22, "TX decode failed".to_string()))?;
        let txid = self
            .submit_and_announce(tx, source, allow_quarantined)
            .map_err(|e| {
                // Core's taxonomy: -25 = RPC_VERIFY_ERROR (in practice only
                // missing inputs); -26 = RPC_VERIFY_REJECTED (every other
                // invalid-or-rejected verdict). `rpc_code` maps each variant
                // to the code Core returns for it, and
                // `sendrawtransaction_msg` supplies Core's reject-reason
                // string plus any RBF detail.
                (e.rpc_code(), e.sendrawtransaction_msg())
            })?;
        Ok(serde_json::Value::String(txid.to_string()))
    }

    /// Accept an already-decoded, locally-originated transaction into the
    /// mempool and [`announce_tx`](Self::announce_tx) it to peers, as one
    /// operation. Returns the txid.
    ///
    /// The pre-decoded twin of [`broadcast_transaction`](Self::broadcast_transaction):
    /// surfaces that decode the tx themselves with their own error shape
    /// (Esplora `POST /tx`, Electrum `transaction.broadcast` and
    /// `broadcast_package`) call this through the [`TxBroadcaster`] trait,
    /// so they cannot accept a tx into the mempool without also putting it
    /// on the wire.
    ///
    /// Resubmitting a tx that is already in the mempool is a success, not
    /// an error, and re-announces it — Core's `BroadcastTransaction`
    /// semantics. Wallets (Electrum, Sparrow, BDK) rely on resubmission to
    /// force re-relay of a stuck tx, including txs that entered the
    /// mempool from a peer or a `mempool.dat` reload rather than through
    /// a local submit.
    pub fn submit_and_announce(
        &self,
        tx: bitcoin::Transaction,
        source: crate::mempool::pool::TxSource,
        allow_quarantined: bool,
    ) -> Result<bitcoin::Txid, MempoolError> {
        let resubmit_txid = tx.compute_txid();
        let txid = match self.mempool.accept_transaction(
            tx,
            &self.chain_state,
            self.chain_state.script_verifier(),
            source,
            allow_quarantined,
        ) {
            Ok(txid) => txid,
            // The same txid with another witness counts too: Core's
            // `BroadcastTransaction` re-announces whichever witness the pool
            // holds, and `announce_tx` reads the wtxid from the pool.
            Err(MempoolError::AlreadyExists | MempoolError::SameNonWitnessData) => resubmit_txid,
            Err(e) => return Err(e),
        };
        // Mark on the resubmit path too — Core's BroadcastTransaction
        // re-adds an already-resident tx to m_unbroadcast, so an operator
        // resubmitting a stuck tx re-arms durable rebroadcast for it.
        self.mempool.mark_unbroadcast(txid);
        self.announce_tx(txid);
        Ok(txid)
    }

    /// Set the rebroadcast cadence (`interval_secs`, `0` = auto/randomized)
    /// and the distinct-witness count required to confirm propagation.
    /// Called from the satd binary after construction and on SIGHUP reload
    /// (both values are re-read from the atomics at each use, so a live
    /// change takes effect on the next pass / witness check).
    pub fn set_rebroadcast_config(&self, interval_secs: u64, confirm_peers: u64) {
        if interval_secs > 0 && interval_secs < 60 {
            // Allowed (useful on regtest), but on a real network this
            // re-invs every pending local tx to every peer each pass.
            tracing::warn!(
                interval_secs,
                "rebroadcastinterval under 60s re-announces aggressively; \
                 intended for test networks only"
            );
        }
        self.rebroadcast_interval_secs
            .store(interval_secs, Ordering::Relaxed);
        self.broadcast_confirm_peers
            .store(confirm_peers.max(1), Ordering::Relaxed);
    }

    /// Seconds to wait before the next rebroadcast pass. When configured to
    /// `0` (auto), returns a fresh random value in the Core-style 10–15 min
    /// window each call so a fleet doesn't re-announce in lockstep.
    pub fn next_rebroadcast_delay_secs(&self) -> u64 {
        use rand::Rng as _;
        match self.rebroadcast_interval_secs.load(Ordering::Relaxed) {
            0 => rand::thread_rng().gen_range(REBROADCAST_AUTO_MIN_SECS..=REBROADCAST_AUTO_MAX_SECS),
            n => n,
        }
    }

    /// Re-announce every still-resident unbroadcast local tx to all
    /// fee-permitting, tx-relaying peers. Run periodically by the
    /// rebroadcast task; the `unbroadcast_entries` call also prunes txids
    /// that have since left the mempool. A tx stops being rebroadcast once
    /// enough distinct witnesses accrue (see
    /// [`note_broadcast_witness`](Self::note_broadcast_witness)) or it is
    /// mined/evicted.
    ///
    /// The per-peer invs are coalesced into one batched `inv` message
    /// (chunked at the protocol cap): a repeated *isolated* single-txid inv
    /// is a much stronger "this is the node's own tx" fingerprint to a
    /// passive observer than a batch, and it's one message instead of N.
    /// Suppressed during IBD, which doesn't relay txs.
    pub fn rebroadcast_unbroadcast_txs(&self) {
        if self.is_actively_syncing() {
            return;
        }
        // (txid, wtxid, fee_rate) triples are snapshotted BEFORE taking the peers
        // lock: `mempool.get` can block behind a long `accept_transaction`
        // write hold (script verification), and stalling every P2P router
        // behind that while holding `peers.read()` would be self-inflicted.
        let pairs = self.mempool.unbroadcast_entries();
        if pairs.is_empty() {
            return;
        }
        tracing::debug!(count = pairs.len(), "rebroadcasting unbroadcast local txs");
        let peers = self.peers.read();
        for handle in peers.values() {
            if handle.info.state != PeerState::Connected || !handle.info.relays_txs() {
                continue;
            }
            let invs: Vec<Inventory> = pairs
                .iter()
                .filter(|(_, _, fee_rate)| *fee_rate >= handle.info.fee_filter)
                .map(|(txid, wtxid, _)| tx_announcement(handle.info.wtxid_relay, *txid, *wtxid))
                .collect();
            for chunk in invs.chunks(MAX_INV_PER_MSG) {
                let _ = handle.msg_tx.try_send(NetworkMessage::Inv(chunk.to_vec()));
            }
        }
    }

    /// Enqueue transactions promoted out of the quarantine class by a policy
    /// reload (§8) for bounded re-announcement. Called by the reload handler with
    /// the [`PolicyTransition::promoted`](crate::mempool::pool::PolicyTransition)
    /// set; the actual INVs go out on the drain task at a capped rate so a mass
    /// promotion never bursts peers. Cheap and non-blocking; deduped against the
    /// existing backlog so repeated reloads don't stack duplicate announcements.
    pub fn enqueue_promotions(&self, txids: impl IntoIterator<Item = bitcoin::Txid>) {
        let mut q = self.promotion_queue.lock();
        let existing: HashSet<bitcoin::Txid> = q.iter().copied().collect();
        for txid in txids {
            if !existing.contains(&txid) {
                q.push_back(txid);
            }
        }
    }

    /// Drain up to [`PROMOTION_DRAIN_PER_TICK`] promoted txs and announce each to
    /// fee-permitting peers (one drain tick). Returns the number announced.
    /// [`announce_tx`](Self::announce_tx) re-checks scope, so a tx demoted again
    /// before its turn (or already gone) is silently skipped. Suppressed during
    /// IBD, which doesn't relay txs.
    pub fn drain_promotion_queue(&self) -> usize {
        if self.is_actively_syncing() {
            return 0;
        }
        let batch: Vec<bitcoin::Txid> = {
            let mut q = self.promotion_queue.lock();
            let n = q.len().min(PROMOTION_DRAIN_PER_TICK);
            q.drain(..n).collect()
        };
        for txid in &batch {
            self.announce_tx(*txid);
        }
        batch.len()
    }

    /// Current depth of the promotion-INV backlog (metrics / tests).
    pub fn promotion_queue_len(&self) -> usize {
        self.promotion_queue.lock().len()
    }

    /// Announce the current unbroadcast local txs to a single freshly-
    /// connected peer (so a tx submitted while we had no peers reaches the
    /// network as soon as one arrives). Honors the peer's fee filter,
    /// `fRelay`, and Connected state, and batches into one `inv`.
    ///
    /// Outbound peers only: an unsolicited just-after-connect inv of
    /// exactly our pending local txs is a wallet fingerprint, and inbound
    /// connections are attacker-chosen — a sybil could connect repeatedly
    /// just to enumerate them. Outbound peers are ones *we* selected,
    /// which is the same trust distinction Core draws for address-relay
    /// and tx-relay decisions; the periodic rebroadcast pass still reaches
    /// inbound peers on the randomized timer alongside everyone else.
    fn announce_unbroadcast_to_peer(&self, id: PeerId) {
        // Snapshot before taking the peers lock (see rebroadcast pass).
        let pairs = self.mempool.unbroadcast_entries();
        if pairs.is_empty() {
            return;
        }
        let peers = self.peers.read();
        let Some(handle) = peers.get(&id) else { return };
        if handle.info.state != PeerState::Connected
            || handle.info.direction != Direction::Outbound
            || !handle.info.relays_txs()
        {
            return;
        }
        let invs: Vec<Inventory> = pairs
            .iter()
            .filter(|(_, _, fee_rate)| *fee_rate >= handle.info.fee_filter)
            .map(|(txid, wtxid, _)| tx_announcement(handle.info.wtxid_relay, *txid, *wtxid))
            .collect();
        for chunk in invs.chunks(MAX_INV_PER_MSG) {
            let _ = handle.msg_tx.try_send(NetworkMessage::Inv(chunk.to_vec()));
        }
    }

    /// Record that peer `id` has demonstrated knowledge of `txid` — either by
    /// fetching it from us via `getdata` (the primary, reliable signal: the
    /// peer pulled the tx, so we've handed it off) or by announcing it back to
    /// us via `inv`. If `txid` is a pending local broadcast, this is
    /// propagation evidence; once enough distinct witnesses (keyed by peer
    /// IP, so reconnects don't stack) have seen it the tx is dropped from
    /// the unbroadcast set and rebroadcast stops.
    ///
    /// `getdata` is the dominant signal for local txs: we announce a local tx
    /// to every fee-permitting peer, and standard relay dedup means none of
    /// them will `inv` it *back* to us (they know we have it) — but each that
    /// didn't already hold it will `getdata` it within seconds. This mirrors
    /// Bitcoin Core's `RemoveUnbroadcastTx`-on-`getdata`.
    ///
    /// Called from the hottest P2P paths (every tx inv / getdata for a tx we
    /// hold), so it must stay cheap when nothing is pending: the lock-free
    /// `has_unbroadcast` check skips the mempool write lock entirely in that
    /// ~always case, leaving the original read-only fast path untouched.
    fn note_broadcast_witness(&self, id: PeerId, txid: bitcoin::Txid) {
        if !self.mempool.has_unbroadcast() {
            return;
        }
        let Some(witness_ip) = self.peers.read().get(&id).map(|h| h.info.addr.ip()) else {
            return;
        };
        let threshold = self.broadcast_confirm_peers.load(Ordering::Relaxed) as usize;
        if self.mempool.record_broadcast_witness(&txid, witness_ip, threshold) {
            tracing::debug!(%txid, "local tx confirmed propagated; rebroadcast stopped");
        }
    }

    /// BFS-drain orphans that listed `parent` as a missing parent. Newly
    /// admitted children recursively trigger further drains. Orphans that
    /// still don't validate (other missing parents, or genuinely invalid)
    /// are re-orphaned or silently dropped.
    fn drain_orphans_for_parent(&self, parent: bitcoin::Txid) {
        use std::collections::VecDeque;
        let mut queue: VecDeque<bitcoin::Txid> =
            self.orphanage.children_of(&parent).into_iter().collect();
        while let Some(child_txid) = queue.pop_front() {
            let Some(child) = self.orphanage.remove(&child_txid) else {
                continue;
            };
            let result = self.mempool.accept_transaction(
                child.tx.clone(),
                &self.chain_state,
                self.chain_state.script_verifier(),
                crate::mempool::pool::TxSource::P2p,
                false,
            );
            match result {
                Ok(_) => {
                    self.broadcast_inv(child.from_peer, child_txid);
                    for grandchild in self.orphanage.children_of(&child_txid) {
                        queue.push_back(grandchild);
                    }
                }
                Err(MempoolError::MissingInputs) => {
                    // Other parents still missing — re-orphan. If
                    // `collect_missing_parents` now returns empty (race),
                    // `add` returns NoMissingParents and we drop silently.
                    let missing = self.collect_missing_parents(&child.tx);
                    let _ = self.orphanage.add(child.tx, child.from_peer, missing);
                }
                Err(e) => {
                    tracing::debug!(%child_txid, "Orphan re-evaluation failed: {}", e);
                }
            }
        }
    }

    /// Called after a block connects: reconsider orphans whose missing
    /// parent is now confirmed. Used from the block-processor thread via
    /// the free-standing [`reconsider_orphans_on_block`] helper below.
    /// Orphans admitted here are not relayed — peers will naturally
    /// re-announce, and the block-connect path has no peer context.
    pub fn reconsider_orphans_for_block(&self, block: &bitcoin::Block) {
        reconsider_orphans_on_block(
            &self.orphanage,
            &self.mempool,
            &self.chain_state,
            block,
        );
    }

    /// Core's `PrepareBlockFilterRequest`: the checks a BIP 157 request
    /// passes before it is served. Returns the stop block's height and the
    /// index to serve from.
    ///
    /// A request satd will not answer as asked disconnects the peer, as in
    /// Core (`fDisconnect`, no misbehaviour): a filter type it does not serve
    /// (any type, while it serves no filters), a stop hash it does not know
    /// or would not serve, a start above the stop, or a range of
    /// `max_height_diff` heights or more. satd used to ignore them all.
    ///
    /// A stop hash off the active chain that Core would still serve (a block
    /// its `BlockRequestAllowed` admits) is ignored without a disconnect:
    /// satd keeps filters for the active chain only, so it has nothing to
    /// send, but the request is not one Core would hold against the peer.
    #[cfg(feature = "block-filter-index")]
    fn prepare_block_filter_request(
        &self,
        id: PeerId,
        filter_type: u8,
        start_height: u32,
        stop_hash: bitcoin::BlockHash,
        max_height_diff: u32,
    ) -> Option<(u32, Arc<dyn node_filter_index::FilterIndex>)> {
        if filter_type != node_filter_index::FILTER_TYPE_BASIC || !self.peer_serve_filters_ready() {
            tracing::debug!(
                "peer requested unsupported block filter type: {filter_type}, disconnecting peer={id}"
            );
            self.disconnect_by_id(id);
            return None;
        }
        let stop_height = match self.chain_state.get_block_index(&stop_hash) {
            Some(e) if self.chain_state.active_chain_contains(&stop_hash, e.height) => e.height,
            Some(e) if self.stale_block_request_allowed(&e) => {
                tracing::debug!("no filters for block {stop_hash} off the active chain, peer={id}");
                return None;
            }
            _ => {
                tracing::debug!("peer requested invalid block hash: {stop_hash}, disconnecting peer={id}");
                self.disconnect_by_id(id);
                return None;
            }
        };
        if start_height > stop_height {
            tracing::debug!(
                "peer sent invalid getcfilters/getcfheaders with start height {start_height} and \
                 stop height {stop_height}, disconnecting peer={id}"
            );
            self.disconnect_by_id(id);
            return None;
        }
        if stop_height - start_height >= max_height_diff {
            tracing::debug!(
                "peer requested too many cfilters/cfheaders: {} / {max_height_diff}, disconnecting peer={id}",
                u64::from(stop_height - start_height) + 1
            );
            self.disconnect_by_id(id);
            return None;
        }
        // Core: "Filter index for supported type not found", no disconnect.
        self.filter_index.get().cloned().map(|idx| (stop_height, idx))
    }

    /// The half of Core's `BlockRequestAllowed` that admits a block off the
    /// active chain: one this node validated, no more than
    /// `STALE_RELAY_AGE_LIMIT` (30 days) older than the best header.
    /// `BlockStatus::Valid` is written only by `connect_block` and survives
    /// the reorg that takes the block off the active chain, as Core's
    /// `BLOCK_VALID_SCRIPTS` does. Core also bounds the block's
    /// work-equivalent age; that bound is not applied, so this admits a little
    /// more than Core does.
    #[cfg(feature = "block-filter-index")]
    fn stale_block_request_allowed(&self, entry: &crate::storage::blockindex::BlockIndexEntry) -> bool {
        const STALE_RELAY_AGE_LIMIT: i64 = 30 * 24 * 60 * 60;
        if entry.status != crate::storage::blockindex::BlockStatus::Valid {
            return false;
        }
        self.chain_state
            .get_block_index(&self.chain_state.best_header_hash())
            .is_some_and(|best| {
                i64::from(best.header.time) - i64::from(entry.header.time) < STALE_RELAY_AGE_LIMIT
            })
    }

    /// `getcfilters` handler per BIP 157, checked by
    /// [`Self::prepare_block_filter_request`]. Replies with one `CFilter` per
    /// height in the requested range (BIP 157 specifies per-height
    /// responses, not a batched form).
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfilters(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFilters) {
        use crate::index::filter::lookups::MAX_GETCFILTERS_SIZE;
        let bitcoin::p2p::message_filter::GetCFilters {
            filter_type,
            start_height,
            stop_hash,
        } = req;
        let Some((stop_height, idx)) =
            self.prepare_block_filter_request(id, filter_type, start_height, stop_hash, MAX_GETCFILTERS_SIZE)
        else {
            return;
        };
        // Stream responses via an async task with backpressure. The
        // 256-slot per-peer mpsc channel cannot fit a full
        // 1000-message response; `try_send` would silently drop the
        // tail (review 2026-05-04 H3). Spawn a task that holds the
        // peer's `Sender` clone and `await`s each send so the slow-
        // consumer/queue-full case naturally backpressures instead of
        // truncating the protocol response.
        let msg_tx = {
            let peers = self.peers.read();
            peers.get(&id).map(|h| h.msg_tx.clone())
        };
        let Some(msg_tx) = msg_tx else {
            return;
        };
        let chain_state = self.chain_state.clone();
        tokio::spawn(async move {
            for h in start_height..=stop_height {
                let Some(block_hash) = chain_state.get_block_hash_by_height(h) else {
                    return;
                };
                let Ok(filter) = idx.filter_at(filter_type, h) else {
                    return;
                };
                if msg_tx
                    .send(NetworkMessage::CFilter(
                        bitcoin::p2p::message_filter::CFilter {
                            filter_type,
                            block_hash,
                            filter,
                        },
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }

    /// `getcfheaders` handler per BIP 157, checked by
    /// [`Self::prepare_block_filter_request`].
    /// Replies with a single `CFHeaders` carrying
    /// `previous_filter_header` plus per-height filter hashes (computed
    /// on the fly from the stored filter blob — see plan §"Filter-hash
    /// CF for getcfheaders recompute" for why we don't persist a third
    /// CF).
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfheaders(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFHeaders) {
        use crate::index::filter::lookups::MAX_GETCFHEADERS_SIZE;
        use bitcoin::bip158::FilterHash;
        use bitcoin::hashes::Hash;
        let bitcoin::p2p::message_filter::GetCFHeaders {
            filter_type,
            start_height,
            stop_hash,
        } = req;
        // Bitcoin Core / BIP 157 cap getcfheaders at 2000, not the 1000
        // that applies to getcfilters. Review 2026-05-04 M1.
        let Some((stop_height, idx)) = self.prepare_block_filter_request(
            id,
            filter_type,
            start_height,
            stop_hash,
            MAX_GETCFHEADERS_SIZE,
        ) else {
            return;
        };
        // previous_filter_header: header at start_height - 1, or all-zeros for height 0.
        let previous_filter_header = if start_height == 0 {
            bitcoin::bip158::FilterHeader::from_byte_array([0u8; 32])
        } else {
            let Ok(prev) = idx.header_at(filter_type, start_height - 1) else {
                return;
            };
            bitcoin::bip158::FilterHeader::from_byte_array(prev)
        };
        // filter_hashes: sha256d(filter_blob) per height.
        let mut filter_hashes = Vec::with_capacity((stop_height - start_height + 1) as usize);
        for h in start_height..=stop_height {
            let Ok(blob) = idx.filter_at(filter_type, h) else {
                return;
            };
            let hash = bitcoin::hashes::sha256d::Hash::hash(&blob).to_byte_array();
            filter_hashes.push(FilterHash::from_byte_array(hash));
        }
        self.send_to_peer(
            id,
            NetworkMessage::CFHeaders(bitcoin::p2p::message_filter::CFHeaders {
                filter_type,
                stop_hash,
                previous_filter_header,
                filter_hashes,
            }),
        );
    }

    /// `getcfcheckpt` handler per BIP 157 — filter headers at every
    /// 1000-block boundary up to (and including) the highest 1000-block
    /// boundary ≤ `stop_height`. Checked by
    /// [`Self::prepare_block_filter_request`] with no range limit, as Core
    /// does.
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfcheckpt(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFCheckpt) {
        use bitcoin::hashes::Hash;
        let bitcoin::p2p::message_filter::GetCFCheckpt {
            filter_type,
            stop_hash,
        } = req;
        let Some((stop_height, idx)) =
            self.prepare_block_filter_request(id, filter_type, 0, stop_hash, u32::MAX)
        else {
            return;
        };
        let max_idx = stop_height / 1000;
        let mut filter_headers = Vec::with_capacity(max_idx as usize);
        for i in 1..=max_idx {
            let h = i * 1000;
            if h > stop_height {
                break;
            }
            let Ok(header) = idx.header_at(filter_type, h) else {
                return;
            };
            filter_headers.push(bitcoin::bip158::FilterHeader::from_byte_array(header));
        }
        self.send_to_peer(
            id,
            NetworkMessage::CFCheckpt(bitcoin::p2p::message_filter::CFCheckpt {
                filter_type,
                stop_hash,
                filter_headers,
            }),
        );
    }

    /// Height of the fork point between a peer's locator and our active
    /// chain — Core's `CChain::FindForkInGlobalIndex`.
    ///
    /// Two things this gets right that a bare block-index lookup does not:
    ///
    /// * A locator entry we know about but that sits on a *stale fork* is
    ///   not a fork point. Accepting it made us start the reply at
    ///   `stale_height + 1` on the active chain, which serves headers/invs
    ///   the peer cannot connect to anything it holds.
    /// * When nothing matches, the fork point is the genesis block, so the
    ///   reply starts at height 1. Starting at 0 re-announces genesis, which
    ///   no peer will ever accept as new.
    fn locator_fork_height(&self, locator: &[bitcoin::BlockHash]) -> u32 {
        for hash in locator {
            if let Some(entry) = self.chain_state.get_block_index(hash)
                && self.chain_state.get_block_hash_by_height(entry.height) == Some(*hash)
            {
                return entry.height;
            }
        }
        0
    }

    fn handle_getheaders(
        &self,
        id: PeerId,
        msg: bitcoin::p2p::message_blockdata::GetHeadersMessage,
    ) {
        if msg.locator_hashes.len() > MAX_LOCATOR_SZ {
            // Core disconnects, it does not ban: `net_processing.cpp` sets
            // `pfrom.fDisconnect = true` and returns, with no misbehaviour
            // score. Banning the address here would refuse the peer's next
            // connection too, which Core allows.
            self.disconnect_by_id(id);
            return;
        }

        let start = self.locator_fork_height(&msg.locator_hashes) + 1;
        let tip = self.chain_state.tip_height();
        let end = std::cmp::min(start + 2000, tip + 1);

        let mut headers = Vec::new();
        for h in start..end {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h)
                && let Some(entry) = self.chain_state.get_block_index(&hash) {
                    headers.push(entry.header);
                    // Core's `nLimit`/`hashStop` loop pushes the header and
                    // *then* breaks on the stop hash, so the stop block is
                    // included. Ignoring `hashStop` entirely — as this did —
                    // answers a narrow range request with up to 2000 headers.
                    if hash == msg.stop_hash {
                        break;
                    }
                }
        }

        // Always send a Headers reply, even when empty. Bitcoin Core and
        // btcd both unconditionally respond to getheaders; some Core
        // versions track silent-drops as soft misbehavior. Empty reply
        // signals "I have nothing newer than your locator."
        self.send_to_peer(id, NetworkMessage::Headers(headers));
    }

    fn handle_getblocks(
        &self,
        id: PeerId,
        msg: bitcoin::p2p::message_blockdata::GetBlocksMessage,
    ) {
        if msg.locator_hashes.len() > MAX_LOCATOR_SZ {
            // Core disconnects, it does not ban: `net_processing.cpp` sets
            // `pfrom.fDisconnect = true` and returns, with no misbehaviour
            // score. Banning the address here would refuse the peer's next
            // connection too, which Core allows.
            self.disconnect_by_id(id);
            return;
        }

        let start = self.locator_fork_height(&msg.locator_hashes) + 1;
        let tip = self.chain_state.tip_height();
        let end = std::cmp::min(start + 500, tip + 1);

        let mut inv = Vec::new();
        for h in start..end {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                // Core breaks on the stop hash *before* pushing it
                // (`net_processing.cpp`, "getblocks stopping at"), because
                // the requester already has that block — it named it as the
                // point to stop at. Pushing it first invs the peer a block
                // it asked us not to send.
                if hash == msg.stop_hash {
                    break;
                }
                inv.push(Inventory::Block(hash));
            }
        }

        if !inv.is_empty() {
            self.send_to_peer(id, NetworkMessage::Inv(inv));
        }
    }

    /// Answer a `MSG_CMPCT_BLOCK` getdata with a `cmpctblock`, if the block
    /// is within [`compact::MAX_CMPCTBLOCK_DEPTH`] of the tip and we are not
    /// syncing (Core: `can_direct_fetch && pindex->nHeight >= tip->nHeight -
    /// MAX_CMPCTBLOCK_DEPTH`). `None` when the full block should be sent
    /// instead; otherwise whether the `cmpctblock` was queued.
    fn serve_compact_block(&self, id: PeerId, hash: &bitcoin::BlockHash) -> Option<bool> {
        if self.ibd.read().is_some() || self.is_ibd() {
            return None;
        }
        let entry = self.chain_state.get_block_index(hash)?;
        if entry.height.saturating_add(compact::MAX_CMPCTBLOCK_DEPTH) < self.chain_state.tip_height() {
            return None;
        }
        let compact = match self.cached_compact(hash) {
            Some(c) => c,
            None => {
                let block = self.chain_state.get_block(hash)?;
                self.compact_for(&block, entry.height, false)?
            }
        };
        let msg = NetworkMessage::CmpctBlock(bitcoin::p2p::message_compact_blocks::CmpctBlock {
            compact_block: (*compact).clone(),
        });
        let queued = self.send_to_peer(id, msg);
        if queued {
            self.compact_stats.sent_getdata.fetch_add(1, Ordering::Relaxed);
            self.note_peer_has_block(id, *hash);
        }
        Some(queued)
    }

    fn handle_getdata(&self, id: PeerId, inventory: Vec<Inventory>) {
        // Core's `MAX_INV_SZ` (`net_processing.cpp` GETDATA), checked before
        // anything in the request is looked at.
        if inventory.len() > MAX_INV_PER_MSG {
            self.add_ban_score(id, 100, &format!("getdata message size = {}", inventory.len()));
            return;
        }
        // Core's `ProcessMessage` line for every getdata.
        match inventory.as_slice() {
            [inv] => tracing::debug!("received getdata for: {} peer={id}", inv_to_string(inv)),
            invs => tracing::debug!("received getdata ({} invsz) peer={id}", invs.len()),
        }
        let Some(sender) = self.peer_sender(id) else {
            return;
        };
        // Queued behind anything still unserved and served from there:
        // Core's `m_getdata_requests` and `ProcessGetData`.
        sender.queue().push_getdata(inventory);
        self.serve_getdata(id, &sender);
    }

    /// [`NetEvent::GetDataResume`]: the peer's queue has drained enough to
    /// serve more of its `getdata` backlog.
    fn resume_getdata(&self, id: PeerId) {
        let Some(sender) = self.peer_sender(id) else {
            return;
        };
        // Before looking at the queue: a write that drains it after this
        // point asks again rather than finding a request already waiting.
        sender.queue().resume_taken();
        self.serve_getdata(id, &sender);
    }

    /// The sending end of a peer's queue, while the peer is connected.
    fn peer_sender(&self, id: PeerId) -> Option<crate::net::send_queue::PeerSender> {
        self.peers.read().get(&id).map(|h| h.msg_tx.clone())
    }

    /// Core's `ProcessGetData`: serve the peer's unserved `getdata` entries,
    /// oldest first, until none are left or its queue is past the send
    /// buffer (`fPauseSend`).
    ///
    /// The rest waits for the queue to drain. The peer's write loop asks for
    /// more as it does ([`NetEvent::GetDataResume`]), and takes no other
    /// message from the peer until the backlog is empty, which keeps the
    /// answers in the order asked and the backlog to one request.
    ///
    /// satd served every entry at once, reading and deserializing each block
    /// and queueing it with a `try_send` whose failure it ignored. One
    /// request could hold a peer's whole queue of blocks in memory for as
    /// long as the peer did not read them, and the blocks that did not fit
    /// were read, dropped, and still charged to `-maxuploadtarget`.
    fn serve_getdata(&self, id: PeerId, sender: &crate::net::send_queue::PeerSender) {
        let queue = sender.queue();
        let mut not_found = Vec::new();
        while !sender.paused() {
            let Some(inv) = queue.front_getdata() else {
                break;
            };
            if !self.serve_getdata_entry(id, sender, inv, &mut not_found) {
                // The queue filled after the check above, or the peer is
                // gone. The entry stays first; the write loop asks again once
                // there is room.
                break;
            }
            queue.pop_getdata();
        }
        if !not_found.is_empty() {
            let _ = sender.try_send(NetworkMessage::NotFound(not_found));
        }
        if queue.getdata_backlog() == 0 {
            queue.wake_reader();
        }
    }

    /// Answer one `getdata` entry: queue what it asks for, or add it to the
    /// `notfound`. False when nothing could be queued and the entry is still
    /// to be served.
    fn serve_getdata_entry(
        &self,
        id: PeerId,
        sender: &crate::net::send_queue::PeerSender,
        inv: Inventory,
        not_found: &mut Vec<Inventory>,
    ) -> bool {
        match inv {
            // `MSG_CMPCT_BLOCK` (BIP 152). A block within
            // `MAX_CMPCTBLOCK_DEPTH` of the tip is answered with a
            // `cmpctblock` (`serve_compact_block`). Anything deeper, or
            // anything while we are still syncing, gets the full `block`,
            // which BIP 152 permits and Core itself sends; Core accepts
            // it against its in-flight compact request. Letting the
            // request fall through to `_ => {}` instead would silently
            // drop it, and a Core peer never re-requests.
            Inventory::Block(hash)
            | Inventory::WitnessBlock(hash)
            | Inventory::CompactBlock(hash) => {
                // A `cmpctblock` that could not be queued leaves the entry to
                // be served again once the queue drains, as below.
                if matches!(inv, Inventory::CompactBlock(_))
                    && let Some(queued) = self.serve_compact_block(id, &hash)
                {
                    return queued;
                }
                let Some(block) = self.chain_state.get_block(&hash) else {
                    not_found.push(inv);
                    return true;
                };
                // -maxuploadtarget: decline historical blocks once
                // the rolling budget is spent (download/noban peers
                // and recent blocks are exempt).
                if !self.upload_permits_block(id, &block) {
                    tracing::debug!(id, %hash, "maxuploadtarget reached; declining historical block");
                    not_found.push(inv);
                    return true;
                }
                let size = block.total_size() as u64;
                if sender.try_send(NetworkMessage::Block(block)).is_err() {
                    return false;
                }
                // Charged for a block that was queued, not one that was read.
                self.record_upload(size);
            }
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                // Relay-quarantined txs are not served via `getdata`:
                // announce-suppression without serve-suppression would be
                // incoherent — a peer that learned the txid elsewhere must
                // not be able to pull it from us (design §6.1). Report it
                // as not-found, exactly as if we did not hold it.
                let Some(entry) = self.mempool.get(&txid).filter(|e| e.scope.assists_relay()) else {
                    not_found.push(inv);
                    return true;
                };
                // The peer pulled this tx from us. If it's a pending
                // local broadcast, that's the primary proof it has
                // propagated — count the peer toward stopping
                // rebroadcast. Only once the Tx is actually enqueued:
                // retiring the tx on a send that did not happen would
                // defeat the exact failure mode rebroadcast exists to cover.
                if sender.try_send(NetworkMessage::Tx(entry.tx)).is_err() {
                    return false;
                }
                self.note_broadcast_witness(id, txid);
            }
            // BIP 339: the same, looked up by wtxid. A resident
            // transaction with the same txid and another witness is not
            // the one asked for, so the answer is `notfound`.
            Inventory::WTx(wtxid) => {
                let Some((txid, entry)) =
                    self.mempool.get_by_wtxid(&wtxid).filter(|(_, e)| e.scope.assists_relay())
                else {
                    not_found.push(inv);
                    return true;
                };
                if sender.try_send(NetworkMessage::Tx(entry.tx)).is_err() {
                    return false;
                }
                self.note_broadcast_witness(id, txid);
            }
            // An entry of a type that is not served is skipped, as in Core.
            _ => {}
        }
        true
    }

    /// Accept the header a `cmpctblock` carries, the way a `headers` message
    /// would be, and return its index entry.
    ///
    /// `None` means stop: the parent is unknown (a rate-limited `getheaders`
    /// has gone out), or the header is invalid. An invalid header here earns
    /// no ban score. BIP 152 lets a high-bandwidth peer relay a block after
    /// checking only its header, so Core's `MaybePunishNodeForBlock` goes
    /// easy on header invalidity that arrives `via_compact_block`; satd goes
    /// further and never penalises it, because the message was pushed to us,
    /// not requested, and nothing is stored for a header that fails.
    fn accept_compact_header(
        &self,
        id: PeerId,
        header: &bitcoin::block::Header,
    ) -> Option<crate::storage::blockindex::BlockIndexEntry> {
        let hash = header.block_hash();
        if self.chain_state.get_block_index(&header.prev_blockhash).is_none() {
            self.maybe_send_getheaders(id);
            return None;
        }
        match self.chain_state.accept_header(header) {
            Ok(_) => {
                self.apply_header_row_changes();
                let htip = self.chain_state.headers_tip_height() as u64;
                self.headers_tip.store(htip, Ordering::Relaxed);
            }
            Err(crate::chain::state::ChainError::Duplicate) => {}
            Err(crate::chain::state::ChainError::PrevBlockNotFound) => {
                self.maybe_send_getheaders(id);
                return None;
            }
            Err(e) => {
                tracing::debug!(id, %hash, error = %e, "ignoring cmpctblock with an invalid header");
                return None;
            }
        }
        // A high-bandwidth peer announces with `cmpctblock` instead of
        // `headers` (BIP 152), so this is the only place the announcement is
        // seen. Without it the peer stays pinned at whatever height its last
        // `headers` message left it at and the scheduler stops asking it for
        // anything.
        self.note_block_availability(id, &hash);
        self.chain_state.get_block_index(&hash)
    }

    /// Whether segwit is active for a block building on `prev`, for the
    /// mutation check. `None` when the parent is unknown.
    fn segwit_active_after(&self, prev: &bitcoin::BlockHash) -> Option<bool> {
        self.chain_state.get_block_index(prev).map(|parent| {
            crate::validation::block::segwit_active_at(self.chain_state.network, parent.height + 1)
        })
    }

    /// A block delivered by `from` has just become our tip. Core promotes the
    /// peer that delivered the best block to high-bandwidth compact relay
    /// (`BlockChecked` → `MaybeSetPeerAsAnnouncingHeaderAndIDs`).
    fn block_became_tip(&self, from: PeerId, block: &bitcoin::Block, height: u32) {
        let _ = (block, height);
        if self.ibd.read().is_some() || self.is_ibd() {
            return;
        }
        self.maybe_set_peer_as_hb(from);
    }

    /// Bitcoin Core's `NewPoWValidBlock`: announce a block that extends our
    /// tip to high-bandwidth peers before connecting it. It has passed proof
    /// of work, header context and `check_block`; script validation and the
    /// UTXO update come after. BIP 152 allows relaying a block this early,
    /// and a connect failure does not take the announcement back: every
    /// receiver validates the block itself, and whoever produced an invalid
    /// block paid for its proof of work.
    ///
    /// Called under the chain's accept lock, so it only reads chain state.
    pub fn fast_announce(&self, block: &bitcoin::Block, height: u32) {
        if self.ibd.read().is_some() || self.is_ibd() {
            return;
        }
        // One early announcement per height, and never for a lower one.
        if self
            .highest_fast_announce
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |h| (height > h).then_some(height))
            .is_err()
        {
            return;
        }
        if !crate::validation::block::segwit_active_at(self.chain_state.network, height) {
            return;
        }
        let hash = block.block_hash();
        let Some(compact) = self.compact_for(block, height, true) else {
            return;
        };
        let msg = NetworkMessage::CmpctBlock(bitcoin::p2p::message_compact_blocks::CmpctBlock {
            compact_block: (*compact).clone(),
        });
        let mut announced = Vec::new();
        {
            let peers = self.peers.read();
            for (id, handle) in peers.iter() {
                if handle.info.state == PeerState::Connected
                    && handle.info.hb_from
                    && handle.info.compact_blocks
                    && handle.info.known_block != Some(hash)
                    && handle.msg_tx.try_send(msg.clone()).is_ok()
                {
                    announced.push(*id);
                }
            }
        }
        if announced.is_empty() {
            return;
        }
        tracing::debug!(
            %hash,
            height,
            peers = announced.len(),
            prefilled = compact.prefilled_txs.len(),
            "announcing block before connecting it"
        );
        self.compact_stats
            .sent_announce
            .fetch_add(announced.len() as u64, Ordering::Relaxed);
        let mut peers = self.peers.write();
        for id in announced {
            if let Some(h) = peers.get_mut(&id) {
                h.info.known_block = Some(hash);
            }
        }
    }

    /// The `cmpctblock` form of `block`, from the tip cache or built now. A
    /// block at least as high as the cached one replaces it; an older block
    /// (a `MSG_CMPCT_BLOCK` getdata a few blocks back) is built without
    /// displacing the tip.
    ///
    /// With `-cmpctblockprefill`, the transactions this node lacked are
    /// prefilled. Which those were can only be read off the mempool before
    /// the block is connected (`before_connect`), since connecting removes
    /// its transactions; a block first built afterwards is sent plain rather
    /// than with a guess.
    fn compact_for(
        &self,
        block: &bitcoin::Block,
        height: u32,
        before_connect: bool,
    ) -> Option<Arc<bitcoin::bip152::HeaderAndShortIds>> {
        let hash = block.block_hash();
        if let Some(recent) = self.most_recent_block.read().as_ref()
            && recent.hash == hash
        {
            return Some(recent.compact.clone());
        }
        let prefill = if before_connect && self.compact_prefill.load(Ordering::Relaxed) {
            let candidates = {
                let extra = self.extra_txns.lock();
                compact::prefill_candidates(block, &self.mempool, &extra)
            };
            match candidates {
                Some(c) => compact::prefill_indexes(block, &c, self.compact_prefill_bytes.load(Ordering::Relaxed)),
                None => {
                    tracing::debug!(%hash, "mempool busy; announcing without a prefill");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let compact = match compact::make_prefilled_compact_block(block, rand::random(), &prefill) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::warn!(%hash, error = %e, "could not build a compact block");
                return None;
            }
        };
        let mut recent = self.most_recent_block.write();
        match recent.as_ref() {
            // Built concurrently by another path: keep one nonce per block.
            Some(r) if r.hash == hash => return Some(r.compact.clone()),
            Some(r) if r.height > height => return Some(compact),
            _ => {}
        }
        *recent = Some(RecentBlock {
            hash,
            height,
            block: Arc::new(block.clone()),
            compact: compact.clone(),
        });
        Some(compact)
    }

    /// The cached `cmpctblock` for `hash`, if it is the tip cache's block.
    fn cached_compact(&self, hash: &bitcoin::BlockHash) -> Option<Arc<bitcoin::bip152::HeaderAndShortIds>> {
        self.most_recent_block
            .read()
            .as_ref()
            .filter(|r| r.hash == *hash)
            .map(|r| r.compact.clone())
    }

    /// Record that `id` has `hash` (it sent or announced it, or we announced
    /// it to the peer).
    fn note_peer_has_block(&self, id: PeerId, hash: bitcoin::BlockHash) {
        if let Some(h) = self.peers.write().get_mut(&id) {
            h.info.known_block = Some(hash);
        }
    }

    /// Bitcoin Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs`
    /// (`net_processing.cpp`): ask `id` to announce new blocks to us as
    /// `cmpctblock`s, keeping at most [`MAX_HB_PEERS`] such peers. The least
    /// recently useful is demoted to make room, but an inbound promotion never
    /// demotes our only outbound high-bandwidth peer.
    fn maybe_set_peer_as_hb(&self, id: PeerId) {
        use bitcoin::p2p::message_compact_blocks::SendCmpct;
        // Under -blocksonly our mempool cannot reconstruct compact blocks.
        if self.blocksonly() {
            return;
        }
        let (demoted, promoted) = {
            let mut hb = self.hb_peers.lock();
            let peers = self.peers.read();
            let Some(handle) = peers.get(&id) else {
                return;
            };
            if !handle.info.compact_blocks {
                return;
            }
            if let Some(pos) = hb.iter().position(|p| *p == id) {
                let _ = hb.remove(pos);
                hb.push_back(id);
                return;
            }
            let is_outbound =
                |p: &PeerId| peers.get(p).is_some_and(|h| h.info.direction == Direction::Outbound);
            if handle.info.direction == Direction::Inbound
                && hb.len() >= MAX_HB_PEERS
                && hb.iter().filter(|p| is_outbound(p)).count() == 1
                && hb.front().is_some_and(is_outbound)
            {
                // Put the outbound peer in the second slot, out of reach of
                // the pop below.
                hb.swap(0, 1);
            }
            let demoted = if hb.len() >= MAX_HB_PEERS { hb.pop_front() } else { None };
            hb.push_back(id);
            (demoted, id)
        };
        {
            let mut peers = self.peers.write();
            if let Some(d) = demoted.and_then(|d| peers.get_mut(&d)) {
                d.info.hb_to = false;
            }
            if let Some(p) = peers.get_mut(&promoted) {
                p.info.hb_to = true;
            }
        }
        if let Some(d) = demoted {
            tracing::debug!(peer = d, "demoting peer from high-bandwidth compact relay");
            self.send_to_peer(d, NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: 2 }));
        }
        tracing::debug!(peer = promoted, "selecting peer for high-bandwidth compact relay");
        self.send_to_peer(promoted, NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }));
    }

    /// Compact block relay counters, for the metrics endpoint.
    pub fn compact_block_stats(&self) -> &CompactBlockStats {
        &self.compact_stats
    }

    /// `-cmpctblockprefill` and `-cmpctblockprefillbytes`. Call once at
    /// startup, before blocks are announced.
    pub fn set_compact_block_prefill(&self, enabled: bool, budget_bytes: usize) {
        self.compact_prefill.store(enabled, Ordering::Relaxed);
        self.compact_prefill_bytes.store(budget_bytes, Ordering::Relaxed);
    }

    /// Size the extra-transaction ring (`-blockreconstructionextratxn`).
    /// Call once at startup: resizing discards what the ring holds.
    pub fn set_block_reconstruction_extra_txn(&self, capacity: usize) {
        *self.extra_txns.lock() = compact::ExtraTxnCache::new(capacity);
    }

    /// Keep a transaction the mempool refused, for reconstruction. Core's
    /// `AddToCompactExtraTransactions` on a first-time rejection.
    fn keep_for_reconstruction(&self, tx: bitcoin::Transaction) {
        self.extra_txns.lock().insert(tx);
    }

    /// One line per finished reconstruction. The counts are the ones taken
    /// while the block was filled.
    fn log_reconstructed(
        &self,
        id: PeerId,
        hash: &bitcoin::BlockHash,
        height: u32,
        stats: &compact::ReconstructStats,
        round_trip: bool,
        since: Instant,
    ) {
        self.compact_stats.record(stats, round_trip);
        tracing::info!(
            hash = %hash,
            height,
            peer = id,
            prefilled = stats.prefilled,
            prefilled_bytes = stats.prefilled_bytes,
            mempool = stats.mempool,
            mempool_bytes = stats.mempool_bytes,
            extra = stats.extra,
            extra_bytes = stats.extra_bytes,
            requested = stats.requested,
            fetched_bytes = stats.requested_bytes,
            redundant_prefilled = stats.redundant_prefilled,
            round_trip,
            elapsed_ms = since.elapsed().as_millis() as u64,
            "compact block reconstructed"
        );
    }

    fn log_abandoned(&self, id: PeerId, hash: &bitcoin::BlockHash, reason: CompactAbandon) {
        let counter = match reason {
            CompactAbandon::Merkle | CompactAbandon::Timeout => &self.compact_stats.fallback,
            CompactAbandon::Invalid => &self.compact_stats.invalid,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::info!(hash = %hash, peer = id, reason = reason.as_str(), "compact block abandoned");
    }

    /// BIP 152 `cmpctblock`. The gate order follows Bitcoin Core's
    /// `CMPCTBLOCK` handler: nothing about the message is trusted, and no
    /// mempool work is done or state kept, until its header has been
    /// accepted and found to extend our tip.
    fn handle_compact_block(&self, id: PeerId, compact: bitcoin::bip152::HeaderAndShortIds) {
        use crate::storage::blockindex::BlockStatus;
        let started = Instant::now();
        let block_hash = compact.header.block_hash();

        // 1. Still syncing: take the header, leave the block to the download
        // scheduler. Core: `if (!already_in_flight && !CanDirectFetch()) return`.
        if self.ibd.read().is_some() || self.is_ibd() {
            let _ = self.accept_compact_header(id, &compact.header);
            return;
        }

        // 2 + 3. Parent known, header valid (proof of work, difficulty).
        let Some(entry) = self.accept_compact_header(id, &compact.header) else {
            return;
        };
        self.note_peer_has_block(id, block_hash);

        // 4. Already have the block.
        if entry.status != BlockStatus::HeaderOnly {
            self.note_block_arrived(&block_hash);
            return;
        }

        let request = self.block_request(id, &block_hash);
        let requested = request.is_some();
        // Asked of this peer as a `cmpctblock` (see `request_announced_blocks`):
        // no full block is coming behind it.
        let requested_compact = request.is_some_and(|r| r.compact);

        // 5. Must beat our tip, and by no more than two blocks — Core keeps
        // compact reconstruction to blocks right at the tip "to be extra
        // careful about DoS possibilities". The index stores chain work, so
        // the comparison is Core's own rather than a height proxy. A block we
        // asked this peer for is still fetched, in full.
        let tip_hash = self.chain_state.tip_hash();
        let Some(tip) = self.chain_state.get_block_index(&tip_hash) else {
            return;
        };
        if entry.height > tip.height + 2
            || crate::chain::state::compare_u256(&entry.chainwork, &tip.chainwork) <= 0
        {
            if requested {
                self.send_to_peer(id, sync::make_getdata_blocks(&[block_hash]));
            }
            return;
        }

        // 5b. The parent's block data must be here. Core stores a block whose
        // parent is only a header and connects it later; satd connects a block
        // as it arrives, so reconstructing this one would start a reorg that
        // cannot finish. Take it as a header announcement and fetch the chain
        // in order.
        if self
            .chain_state
            .get_block_index(&compact.header.prev_blockhash)
            .is_none_or(|parent| parent.status == BlockStatus::HeaderOnly)
        {
            tracing::debug!(id, %block_hash, "cmpctblock parent has no block data yet; fetching in order");
            self.request_missing_blocks(id);
            return;
        }

        // 6. Only a high-bandwidth peer may push a block at us. Anyone else's
        // `cmpctblock` counts as a header announcement: the header is in, so
        // fetch the block the ordinary way. Core: `fRevertToHeaderProcessing`,
        // and #32606's rule for unsolicited compact blocks.
        let hb_to = self.peers.read().get(&id).is_some_and(|h| h.info.hb_to);
        if !requested && !hb_to {
            self.request_missing_blocks(id);
            return;
        }

        // 7. One reconstruction per peer, at most three per block.
        let superseded = {
            let mut pending = self.pending_compact.write();
            if pending.get(&id).is_some_and(|p| p.hash == block_hash) {
                // Core keeps a failed partial block for exactly this: a peer
                // may not restart a reconstruction of the same block.
                tracing::debug!(id, %block_hash, "peer sent a compact block we are already reconstructing");
                return;
            }
            // Unlike Core, a block we asked this peer for does not get past
            // the cap: satd's tip-following fetch asks every peer for a
            // missing block, so "requested" would exempt nearly everyone. The
            // full block that request asked for still comes -- unless what we
            // asked for was this `cmpctblock`, and then we ask again, in full.
            let others = pending.values().filter(|p| p.hash == block_hash).count();
            if others >= compact::MAX_CMPCT_INFLIGHT_PER_BLOCK {
                drop(pending);
                tracing::debug!(id, %block_hash, others, "compact block already in flight from enough peers");
                if requested_compact {
                    self.request_full_block(id, block_hash);
                }
                return;
            }
            pending.remove(&id)
        };
        if let Some(old) = superseded
            && old.requested
            && self
                .chain_state
                .get_block_index(&old.hash)
                .is_some_and(|e| e.status == BlockStatus::HeaderOnly)
        {
            self.send_to_peer(id, sync::make_getdata_blocks(&[old.hash]));
        }

        // 8. A shape no valid block has is misbehaviour (Core:
        // `READ_STATUS_INVALID` from `InitData`).
        if let Err(e) = compact::check_shape(&compact) {
            tracing::debug!(id, %block_hash, reason = %e, "invalid cmpctblock");
            self.log_abandoned(id, &block_hash, CompactAbandon::Invalid);
            self.add_ban_score(id, 100, "invalid-cmpctblock");
            return;
        }

        // From here the block is on its way in compactly, so the
        // tip-following sweep leaves it alone; every path that gives up below
        // clears the mark, as does the block arriving or the sweep in
        // `expire_compact_state`.
        self.compact_in_progress.write().insert(block_hash, Instant::now());

        // 9. Reconstruct from the mempool and the extra-transaction cache.
        let reconstruction = {
            let extra = self.extra_txns.lock();
            compact::try_reconstruct(&compact, &self.mempool, &extra)
        };
        let reconstruction = match reconstruction {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(id, %block_hash, reason = %e, "invalid cmpctblock");
                self.compact_in_progress.write().remove(&block_hash);
                self.log_abandoned(id, &block_hash, CompactAbandon::Invalid);
                self.add_ban_score(id, 100, "invalid-cmpctblock");
                return;
            }
        };
        match reconstruction {
            compact::Reconstruction::Complete(block, stats) => {
                // 10. A block that fails its merkle check after a full
                // reconstruction may be an honest block whose short IDs
                // collided with something in our mempool. Core returns
                // `READ_STATUS_FAILED` and fetches the full block without
                // penalty; the full block then goes through `handle_block`'s
                // mutation check, which does penalise, since we asked for it.
                let segwit_active = self.segwit_active_after(&block.header.prev_blockhash).unwrap_or(true);
                if crate::validation::block::is_block_mutated(&block, segwit_active) {
                    tracing::debug!(
                        id, %block_hash,
                        "compact block failed merkle check, possible short-ID collision; requesting full block"
                    );
                    self.compact_in_progress.write().remove(&block_hash);
                    self.log_abandoned(id, &block_hash, CompactAbandon::Merkle);
                    self.send_to_peer(id, sync::make_getdata_blocks(&[block_hash]));
                    self.note_blocks_requested(id, &[block_hash]);
                    self.pending_compact.write().insert(
                        id,
                        compact::PendingCompact::failed(block_hash, compact.header, entry.height),
                    );
                    return;
                }
                self.log_reconstructed(id, &block_hash, entry.height, &stats, false, started);
                // The block is in hand, so no peer is asked for it any more.
                // It is not stored yet: see `forget_block_requests`.
                self.forget_block_requests(&block_hash);
                let _ = self.block_tx.send((
                    id,
                    self.peer_stats(id),
                    block,
                    crate::net::flow::InFlight::new(self.peer_flow(id)),
                    // Its header connected before it was rebuilt, so it never
                    // waits for a parent.
                    false,
                ));
            }
            compact::Reconstruction::Partial { txs, missing_indices, stats } => {
                // 11. Ask the peer for what the mempool could not supply.
                tracing::debug!(
                    %block_hash,
                    missing = missing_indices.len(),
                    "Compact block incomplete, requesting missing txs"
                );
                let request = compact::make_get_block_txn(block_hash, &missing_indices);
                self.pending_compact.write().insert(
                    id,
                    compact::PendingCompact {
                        hash: block_hash,
                        header: compact.header,
                        txs,
                        missing_indices,
                        since: started,
                        requested,
                        failed: false,
                        height: entry.height,
                        stats,
                    },
                );
                self.send_to_peer(
                    id,
                    NetworkMessage::GetBlockTxn(
                        bitcoin::p2p::message_compact_blocks::GetBlockTxn {
                            txs_request: request,
                        },
                    ),
                );
            }
        }
    }

    /// BIP 152 `getblocktxn`. Bitcoin Core's rules: a block we do not hold is
    /// ignored; one more than [`compact::MAX_BLOCKTXN_DEPTH`] below the tip is
    /// sent in full, so a peer cannot turn cheap requests into disk reads for
    /// a few bytes of reply; an index past the end of the block is
    /// misbehaviour.
    fn handle_get_block_txn(
        &self,
        id: PeerId,
        request: bitcoin::bip152::BlockTransactionsRequest,
    ) {
        // The tip cache first, as Core does: the block a peer is most likely
        // reconstructing is the one we just announced, and it needs no disk
        // read.
        let cached = self
            .most_recent_block
            .read()
            .as_ref()
            .filter(|r| r.hash == request.block_hash)
            .map(|r| r.block.clone());
        if let Some(block) = cached {
            self.send_block_txn(id, &request, &block);
            return;
        }
        let Some(entry) = self.chain_state.get_block_index(&request.block_hash) else {
            tracing::debug!(id, hash = %request.block_hash, "getblocktxn for a block we don't have");
            return;
        };
        if entry.height.saturating_add(compact::MAX_BLOCKTXN_DEPTH) < self.chain_state.tip_height() {
            tracing::debug!(
                id, hash = %request.block_hash,
                "getblocktxn for a block more than {} deep; sending the full block",
                compact::MAX_BLOCKTXN_DEPTH
            );
            self.handle_getdata(id, vec![Inventory::WitnessBlock(request.block_hash)]);
            return;
        }
        let Some(block) = self.chain_state.get_block(&request.block_hash) else {
            tracing::debug!(id, hash = %request.block_hash, "getblocktxn for a block we don't have");
            return;
        };
        self.send_block_txn(id, &request, &block);
    }

    /// Answer a `getblocktxn` from `block`; an out-of-range index is
    /// misbehaviour (Core: "getblocktxn with out-of-bounds tx indices").
    fn send_block_txn(
        &self,
        id: PeerId,
        request: &bitcoin::bip152::BlockTransactionsRequest,
        block: &bitcoin::Block,
    ) {
        match bitcoin::bip152::BlockTransactions::from_request(request, block) {
            Ok(txns) => {
                self.send_to_peer(
                    id,
                    NetworkMessage::BlockTxn(
                        bitcoin::p2p::message_compact_blocks::BlockTxn {
                            transactions: txns,
                        },
                    ),
                );
            }
            Err(e) => {
                tracing::debug!(id, "getblocktxn with out-of-bounds tx indices: {}", e);
                self.add_ban_score(id, 100, "getblocktxn-out-of-range");
            }
        }
    }

    /// BIP 152 `blocktxn`: the answer to a `getblocktxn` we sent this peer.
    fn handle_block_txn(&self, id: PeerId, txns: bitcoin::bip152::BlockTransactions) {
        let block_hash = txns.block_hash;
        // Only the reconstruction this peer has open, for this block. Core
        // ignores a `blocktxn` "for block we weren't expecting".
        let pending = {
            let mut pending = self.pending_compact.write();
            match pending.get(&id) {
                Some(p) if p.hash == block_hash => pending.remove(&id),
                _ => None,
            }
        };
        let Some(pending) = pending else {
            tracing::debug!(id, %block_hash, "blocktxn for a block we did not request from this peer");
            return;
        };
        if pending.failed {
            // Core: "previous compact block reconstruction attempt failed".
            self.add_ban_score(id, 100, "blocktxn-after-failed-reconstruction");
            return;
        }
        let header = pending.header;
        let (height, since) = (pending.height, pending.since);
        let segwit_active = self.segwit_active_after(&header.prev_blockhash).unwrap_or(true);
        match compact::complete_pending(pending, &txns, segwit_active) {
            Ok((block, stats)) => {
                self.log_reconstructed(id, &block_hash, height, &stats, true, since);
                self.forget_block_requests(&block_hash);
                let _ = self.block_tx.send((
                    id,
                    self.peer_stats(id),
                    block,
                    crate::net::flow::InFlight::new(self.peer_flow(id)),
                    // Its header connected before it was rebuilt, so it never
                    // waits for a parent.
                    false,
                ));
            }
            Err(compact::CompleteError::Invalid) => {
                tracing::debug!(id, %block_hash, "blocktxn does not match the compact block");
                self.log_abandoned(id, &block_hash, CompactAbandon::Invalid);
                self.add_ban_score(id, 100, "invalid-blocktxn");
            }
            Err(compact::CompleteError::Mutated) => {
                // Core: "Might have collided, fall back to getdata now".
                tracing::debug!(
                    id, %block_hash,
                    "compact block failed merkle check, possible short-ID collision; requesting full block"
                );
                self.log_abandoned(id, &block_hash, CompactAbandon::Merkle);
                self.send_to_peer(id, sync::make_getdata_blocks(&[block_hash]));
                self.note_blocks_requested(id, &[block_hash]);
                self.pending_compact
                    .write()
                    .insert(id, compact::PendingCompact::failed(block_hash, header, height));
            }
        }
    }

    /// Send `getheaders` to a peer for headers-first chain discovery, but no
    /// more than once per [`GETHEADERS_MIN_INTERVAL`] per peer. Returns whether
    /// a message was sent. Used on inv/headers announcements so a flood of
    /// announcements (or unconnectable headers) can't make us emit a getheaders
    /// — and the locator-building work behind it — on every message.
    fn maybe_send_getheaders(&self, id: PeerId) -> bool {
        {
            let mut peers = self.peers.write();
            let Some(handle) = peers.get_mut(&id) else {
                return false;
            };
            let now = Instant::now();
            let due = handle
                .last_getheaders_sent
                .is_none_or(|t| now.duration_since(t) >= GETHEADERS_MIN_INTERVAL);
            if !due {
                return false;
            }
            handle.last_getheaders_sent = Some(now);
        }
        self.send_to_peer(id, sync::make_getheaders(&self.chain_state));
        true
    }

    fn request_missing_blocks(&self, id: PeerId) {
        let to_request = self.missing_blocks_to_fetch();
        self.request_full_blocks(id, &to_request);
    }

    /// Fetch what a `headers` message from `id`, ending at `last`, left
    /// missing: Bitcoin Core's `HeadersDirectFetchBlocks` (v31.1
    /// `net_processing.cpp:2844`), on satd's tip-following fetch.
    ///
    /// When the only block missing is the one the peer announced, and
    /// [`Self::may_fetch_compact`] allows, it is asked for as a `cmpctblock`
    /// -- Core, `net_processing.cpp:2890-2896`: "In any case, we want to
    /// download using a compact block, not a regular one". Core's walk starts
    /// at the announced header and needs its parent connected, so the block
    /// it rewrites is always that header; `last` is the same condition here.
    /// Anything else is fetched in full, as before.
    fn request_announced_blocks(&self, id: PeerId, last: bitcoin::BlockHash) {
        let to_request = self.missing_blocks_to_fetch();
        if let [hash] = to_request.as_slice()
            && *hash == last
            && self.may_fetch_compact(id, hash)
        {
            tracing::debug!(id, %hash, "Requesting announced block as a compact block");
            if self.send_to_peer(id, sync::make_getdata_compact_block(*hash)) {
                self.note_compact_requested(id, *hash);
            }
            return;
        }
        self.request_full_blocks(id, &to_request);
    }

    /// The blocks the best header chain lacks, oldest first, less any
    /// already on their way in as a `cmpctblock`.
    fn missing_blocks_to_fetch(&self) -> Vec<bitcoin::BlockHash> {
        // Fork-aware: walk back from the best-work header chain tip to the
        // fork point, requesting blocks we lack data for in connect order.
        // This requests a competing chain's fork block(s) at heights at or
        // below our active tip — a plain forward-by-height walk skips them,
        // and without them a reorg onto a longer competing chain announced by
        // a peer can never reconnect.
        let mut to_request = self.chain_state.missing_blocks_for_best_header_chain(128);
        // A block already arriving as a `cmpctblock` is not fetched in full:
        // the sweep runs on a timer, and without this it downloads the very
        // block a reconstruction is a round trip away from finishing.
        to_request.retain(|hash| !self.compact_reconstruction_in_flight(hash));
        to_request
    }

    /// Ask `id` for `to_request` as full blocks, and record the request.
    fn request_full_blocks(&self, id: PeerId, to_request: &[bitcoin::BlockHash]) {
        if !to_request.is_empty() {
            tracing::debug!(count = to_request.len(), "Requesting blocks for best header chain");
            if self.send_to_peer(id, sync::make_getdata_blocks(to_request)) {
                self.note_blocks_requested(id, to_request);
            }
        }
    }

    /// Ask `id` for the whole of `hash` after a `cmpctblock` we asked it for
    /// cannot be used. Without this the request would be answered and still
    /// leave the block unfetched until the sweep's suppression ran out.
    fn request_full_block(&self, id: PeerId, hash: bitcoin::BlockHash) {
        tracing::debug!(id, %hash, "Requesting the full block after a compact request");
        self.request_full_blocks(id, &[hash]);
    }

    /// Whether the one block a `headers` announcement from `id` leaves to
    /// fetch goes out as `MSG_CMPCT_BLOCK`. Bitcoin Core's conditions
    /// (v31.1 `net_processing.cpp`):
    ///
    /// - the tip is recent (`CanDirectFetch`, L2849 and L1347);
    /// - not `-blocksonly` (`!m_opts.ignore_incoming_txs`, L2890): the
    ///   mempool is empty, so nearly every transaction would need a round
    ///   trip;
    /// - the peer sent `sendcmpct` with version 2 (`m_provides_cmpctblocks`,
    ///   L2891, set at L3917), high-bandwidth or not;
    /// - no other block is in flight from anyone
    ///   (`mapBlocksInFlight.size() == 1`, L2893; see
    ///   [`Self::nothing_else_in_flight`]);
    /// - the parent is connected (`pprev->IsValid(BLOCK_VALID_CHAIN)`,
    ///   L2894), so the block can connect as soon as it is rebuilt.
    ///
    /// Core's remaining gate, exactly one block to fetch (`vGetData.size()
    /// == 1`, L2892), is the caller's.
    fn may_fetch_compact(&self, id: PeerId, hash: &bitcoin::BlockHash) -> bool {
        use crate::storage::blockindex::BlockStatus;
        if self.blocksonly() || !self.can_direct_fetch() {
            return false;
        }
        if !self.peers.read().get(&id).is_some_and(|h| h.info.compact_blocks) {
            return false;
        }
        let parent_connected = self
            .chain_state
            .get_block_index(hash)
            .and_then(|entry| self.chain_state.get_block_index(&entry.header.prev_blockhash))
            .is_some_and(|parent| parent.status == BlockStatus::Valid);
        parent_connected && self.nothing_else_in_flight(id, hash)
    }

    /// Bitcoin Core's `CanDirectFetch` (v31.1 `net_processing.cpp:1347`): the
    /// tip is less than [`DIRECT_FETCH_MAX_TIP_AGE_SECS`] old by the node
    /// clock, which follows `setmocktime`.
    fn can_direct_fetch(&self) -> bool {
        let tip_time = self
            .chain_state
            .get_block_index(&self.chain_state.tip_hash())
            .map_or(0, |entry| entry.header.time);
        u64::from(tip_time) > crate::time::now_secs().saturating_sub(DIRECT_FETCH_MAX_TIP_AGE_SECS)
    }

    /// Core's `mapBlocksInFlight.size() == 1` once `hash` is asked of `id`:
    /// no other block is being downloaded or rebuilt, from anyone. Core's
    /// table holds every block download -- the parallel sync, direct fetches
    /// and compact reconstructions alike -- so each of satd's counterparts
    /// counts: the background (AssumeUTXO) downloader, the tip-following
    /// requests, and reconstructions in progress. (The IBD scheduler needs
    /// no check: `handle_headers` does not direct-fetch while it exists.) A
    /// record of `hash` already asked of `id` is the request being made, and
    /// Core would not add a second one for it.
    fn nothing_else_in_flight(&self, id: PeerId, hash: &bitcoin::BlockHash) -> bool {
        if self.bg_downloader.read().in_flight_len() > 0 {
            return false;
        }
        let other_request = self.in_flight_blocks.read().iter().any(|(peer, asked)| {
            asked
                .iter()
                .any(|(h, r)| r.at.elapsed() < BLOCK_IN_FLIGHT_TTL && !(*peer == id && h == hash))
        });
        let marked: Vec<bitcoin::BlockHash> = self
            .compact_in_progress
            .read()
            .iter()
            .filter(|(_, at)| at.elapsed() < COMPACT_RECONSTRUCT_SUPPRESSION)
            .map(|(h, _)| *h)
            .collect();
        // A rebuilt block keeps its mark until it lapses (see
        // `forget_block_requests`); once the block is stored it is no longer
        // in flight.
        let reconstructing = !self.pending_compact.read().is_empty()
            || marked.iter().any(|h| !self.chain_state.has_block_data(h));
        !other_request && !reconstructing
    }

    /// Record that `id` was asked for `hashes` (see `in_flight_blocks`).
    /// Records past [`MAX_IN_FLIGHT_BLOCKS_PER_PEER`] are dropped, expired
    /// ones first: the `getdata` still goes out, we just stop remembering
    /// having sent it once a peer has more outstanding than any honest peer
    /// needs.
    fn note_blocks_requested(&self, id: PeerId, hashes: &[bitcoin::BlockHash]) {
        self.record_block_requests(id, hashes, false);
    }

    /// Record that `id` was asked for `hash` as a `cmpctblock`. The block is
    /// on its way in compactly from this moment, so the tip-following sweep
    /// holds off for [`COMPACT_RECONSTRUCT_SUPPRESSION`], as it does for a
    /// reconstruction; if nothing usable comes by then, the sweep fetches it
    /// in full from every peer.
    fn note_compact_requested(&self, id: PeerId, hash: bitcoin::BlockHash) {
        self.record_block_requests(id, &[hash], true);
        self.compact_in_progress.write().insert(hash, Instant::now());
    }

    fn record_block_requests(&self, id: PeerId, hashes: &[bitcoin::BlockHash], compact: bool) {
        let now = Instant::now();
        let mut in_flight = self.in_flight_blocks.write();
        let asked = in_flight.entry(id).or_default();
        for hash in hashes {
            if asked.len() >= MAX_IN_FLIGHT_BLOCKS_PER_PEER && !asked.contains_key(hash) {
                asked.retain(|_, r| r.at.elapsed() < BLOCK_IN_FLIGHT_TTL);
                if asked.len() >= MAX_IN_FLIGHT_BLOCKS_PER_PEER {
                    tracing::debug!(id, "peer has too many blocks in flight to track; not recording");
                    break;
                }
            }
            asked.insert(*hash, BlockRequest { at: now, compact });
        }
    }

    /// Our request to `id` for `hash`, if it is recent enough to still
    /// expect an answer.
    fn block_request(&self, id: PeerId, hash: &bitcoin::BlockHash) -> Option<BlockRequest> {
        self.in_flight_blocks
            .read()
            .get(&id)
            .and_then(|asked| asked.get(hash).copied())
            .filter(|r| r.at.elapsed() < BLOCK_IN_FLIGHT_TTL)
    }

    /// Whether we asked `id` for `hash` recently enough to still expect it.
    #[cfg(test)]
    fn block_requested_from(&self, id: PeerId, hash: &bitcoin::BlockHash) -> bool {
        self.block_request(id, hash).is_some()
    }

    /// Whether a compact reconstruction of `hash` started recently enough to
    /// still be worth waiting for instead of fetching the block in full.
    fn compact_reconstruction_in_flight(&self, hash: &bitcoin::BlockHash) -> bool {
        self.compact_in_progress
            .read()
            .get(hash)
            .is_some_and(|at| at.elapsed() < COMPACT_RECONSTRUCT_SUPPRESSION)
    }

    /// A block arrived, by whatever route: nothing is in flight for it any
    /// more, and no partial compact reconstruction of it needs finishing.
    fn note_block_arrived(&self, hash: &bitcoin::BlockHash) {
        self.forget_block_requests(hash);
        if self.compact_in_progress.read().contains_key(hash) {
            self.compact_in_progress.write().remove(hash);
        }
    }

    /// No peer is asked for `hash` any more, and no partial reconstruction of
    /// it needs finishing. A rebuilt `cmpctblock` clears only this much: the
    /// block is on its way to the connect thread and not stored yet, so it
    /// keeps its `compact_in_progress` mark. Without the mark, a
    /// tip-following sweep in that window reads the block as missing and
    /// downloads it again in full. The mark lapses after
    /// [`COMPACT_RECONSTRUCT_SUPPRESSION`].
    fn forget_block_requests(&self, hash: &bitcoin::BlockHash) {
        // Read-only fast path: this runs for every block, IBD included, and
        // both tables are empty for all but the blocks at the tip.
        if self.in_flight_blocks.read().values().any(|asked| asked.contains_key(hash)) {
            self.in_flight_blocks.write().retain(|_, asked| {
                asked.remove(hash);
                !asked.is_empty()
            });
        }
        if self.pending_compact.read().values().any(|p| p.hash == *hash) {
            self.pending_compact.write().retain(|_, p| p.hash != *hash);
        }
    }

    /// Drop compact reconstructions that have waited longer than
    /// [`compact::COMPACT_PENDING_TIMEOUT`] and stale in-flight records. A
    /// dropped reconstruction of a block we had asked that peer for is
    /// re-requested as a full block, so a requested block is never left
    /// unfetched because a `blocktxn` never came.
    fn expire_compact_state(&self) {
        let expired: Vec<(PeerId, bitcoin::BlockHash, bool, bool)> = {
            let mut pending = self.pending_compact.write();
            let stale: Vec<PeerId> = pending
                .iter()
                .filter(|(_, p)| p.since.elapsed() >= compact::COMPACT_PENDING_TIMEOUT)
                .map(|(id, _)| *id)
                .collect();
            stale
                .into_iter()
                .filter_map(|id| pending.remove(&id).map(|p| (id, p.hash, p.requested, p.failed)))
                .collect()
        };
        for (id, hash, requested, failed) in expired {
            // A failed entry was already counted when its merkle check failed.
            if !failed {
                self.log_abandoned(id, &hash, CompactAbandon::Timeout);
            }
            let have_data = self
                .chain_state
                .get_block_index(&hash)
                .is_some_and(|e| e.status != crate::storage::blockindex::BlockStatus::HeaderOnly);
            tracing::debug!(id, %hash, requested, have_data, "compact block reconstruction timed out");
            if requested && !have_data {
                self.send_to_peer(id, sync::make_getdata_blocks(&[hash]));
            }
        }
        self.in_flight_blocks.write().retain(|_, asked| {
            asked.retain(|_, r| r.at.elapsed() < BLOCK_IN_FLIGHT_TTL);
            !asked.is_empty()
        });
        self.compact_in_progress
            .write()
            .retain(|_, at| at.elapsed() < COMPACT_RECONSTRUCT_SUPPRESSION);
    }

    /// Queue a message to a peer. Returns whether the message was actually
    /// enqueued — `false` if the peer is gone or its (bounded) channel is
    /// full and the message was dropped. Most callers ignore the result
    /// (P2P sends are best-effort), but callers that derive *state* from
    /// having sent something (e.g. the getdata-served propagation witness)
    /// must check it: a dropped send is not evidence of anything.
    fn send_to_peer(&self, id: PeerId, msg: NetworkMessage) -> bool {
        let peers = self.peers.read();
        match peers.get(&id) {
            Some(handle) => handle.msg_tx.try_send(msg).is_ok(),
            None => false,
        }
    }

    #[allow(dead_code)]
    fn broadcast(&self, msg: NetworkMessage) {
        self.broadcast_except(0, msg);
    }

    #[allow(dead_code)]
    fn broadcast_except(&self, exclude_id: PeerId, msg: NetworkMessage) {
        let peers = self.peers.read();
        for (id, handle) in peers.iter() {
            if *id != exclude_id && handle.info.state == PeerState::Connected {
                let _ = handle.msg_tx.try_send(msg.clone());
            }
        }
    }

    /// How an outbound connection that no caller typed is reported: `manual`
    /// when it reaches a peer the operator named, `outbound-full-relay`
    /// otherwise. An onion peer is judged by its host: its socket is the
    /// `0.0.0.0` placeholder every onion peer shares.
    ///
    /// Only the operator's own lists decide. The automatic dial list once
    /// counted too, and it holds every gossiped address, so every peer the
    /// node reached through gossip was reported `manual` (#866).
    fn untyped_outbound_conn_type(&self, addr: &SocketAddr, onion_host: Option<&str>) -> ConnType {
        let named = match onion_host {
            Some(host) => self.manual_onion_hosts.read().contains(host),
            None => self.manual_addrs.read().contains(addr),
        };
        if named { ConnType::Manual } else { ConnType::OutboundFullRelay }
    }

    /// The `-whitelist` permissions an outbound connection takes. Core
    /// consults its outgoing whitelist only for a manual connection
    /// (`ConnectNode`, v31.1 `src/net.cpp:514`) and hands an automatic one
    /// nothing.
    ///
    /// Nor does a manual onion peer take any. Its socket is the `0.0.0.0`
    /// placeholder every onion peer shares, and matching that would hand it
    /// whatever an `out` entry covering `0.0.0.0` grants; Core matches the
    /// onion address itself, which no IP subnet contains.
    fn outbound_whitelist_permissions(
        &self,
        conn_type: ConnType,
        addr: &SocketAddr,
        onion_host: Option<&str>,
    ) -> crate::net::permissions::NetPermissions {
        if conn_type == ConnType::Manual && onion_host.is_none() {
            self.whitelist_permissions_for(addr.ip(), crate::net::permissions::Direction::OUT)
        } else {
            crate::net::permissions::NetPermissions::NONE
        }
    }

    /// Spawn read/write tasks for a new peer connection.
    ///
    /// `conn_type` is `Some` when the caller has already decided what kind of
    /// connection this is: `Manual` for a dial the operator asked for, or
    /// the type `addconnection` was given. `None` means "work it out from
    /// the address" ([`Self::untyped_outbound_conn_type`]), which is how the
    /// reconnect loop's dials, and a seed's, reach here.
    fn spawn_peer(
        self: &Arc<Self>,
        id: PeerId,
        addr: SocketAddr,
        transport: IncomingTransport,
        direction: Direction,
        onion_host: Option<&str>,
        conn_type: Option<ConnType>,
    ) {
        let (msg_tx, msg_rx) = mpsc::channel::<NetworkMessage>(256);
        let mut info = PeerInfo::new(id, addr, direction);
        info.onion_host = onion_host.map(str::to_string);
        // Peers from `addnode` / `-connect` are `manual`; everything the
        // node dials by itself is `outbound-full-relay`. The type is not a
        // label only: it decides the outgoing `-whitelist` below, whether a
        // peer lacking the desired services is dropped at the handshake, and
        // which outbound slots the peer counts against.
        if direction == Direction::Outbound {
            info.conn_type = conn_type
                .unwrap_or_else(|| self.untyped_outbound_conn_type(&addr, onion_host));
        }
        // `-whitelist` permissions, scoped to the direction this peer was
        // reached in. Core consults its *outgoing* whitelist only for a
        // manual connection and hands an automatic outbound one nothing at
        // all; satd applied every entry to both directions, so a bare
        // `-whitelist=noban@<subnet>` made outbound peers in that range
        // un-bannable and exempt from the upload budget without any `out`
        // token asking for it. An inbound peer's permissions are set on the
        // accept path, which is where `-whitebind` is unioned in.
        info.permissions = match direction {
            Direction::Inbound => self
                .whitelist_permissions_for(addr.ip(), crate::net::permissions::Direction::IN),
            Direction::Outbound => {
                self.outbound_whitelist_permissions(info.conn_type, &addr, onion_host)
            }
        };
        // `getpeerinfo`'s `addrbind`: our end of this socket. For an onion
        // peer this is the socket to the proxy, not a clearnet listener.
        info.bind_addr = match &transport {
            IncomingTransport::Raw(s) => s.local_addr().ok(),
            IncomingTransport::Established(c) => c.local_addr().ok(),
        };
        // The BIP 324 session ID is recorded where the transport is (after
        // the handshake), so the two can never disagree. An inbound peer
        // arrives here already `Established` and gets it immediately.
        info.session_id = match &transport {
            IncomingTransport::Raw(_) => None,
            IncomingTransport::Established(c) => c.session_id(),
        };
        // An inbound socket is `detecting` until its first bytes arrive, when
        // v2 is on; otherwise it can only be v1.
        info.transport = match &transport {
            IncomingTransport::Raw(_) if self.v2_transport_enabled() => {
                crate::net::peer::TransportProtocol::Detecting
            }
            IncomingTransport::Raw(_) => crate::net::peer::TransportProtocol::V1,
            IncomingTransport::Established(c) => c.transport_protocol(),
        };
        let handle = PeerHandle {
            info,
            msg_tx: msg_tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            last_mempool_served: None,
                    fee_filter_sent: None,
            stats: PeerStats::new(self.net_totals.clone()),
        };
        {
            let mut peers = self.peers.write();
            // Authoritative pause check: under the same lock `set_network_active`
            // flips the flag + clears peers under, so a dial that raced a pause
            // is resolved deterministically — it either registers (and the pause
            // then clears it) or is refused here. Returning drops `transport`,
            // closing the freshly-dialed socket; the peer task is never spawned.
            if !self.is_network_active() {
                tracing::debug!(id, %addr, "networkactive=false: dropping freshly-connected peer");
                return;
            }
            peers.insert(id, handle);
        }
        tracing::debug!("Added connection peer={id}");
        self.spawn_peer_task(id, addr, transport, direction, msg_rx);
    }

    /// Inner half of `spawn_peer`: spawns the peer task once the
    /// `PeerHandle` is already in `self.peers`. Split out so
    /// `accept_inbound` can do the cap-check + insertion atomically
    /// under one write lock and then call this without re-inserting.
    fn spawn_peer_task(
        self: &Arc<Self>,
        id: PeerId,
        addr: SocketAddr,
        transport: IncomingTransport,
        direction: Direction,
        msg_rx: mpsc::Receiver<NetworkMessage>,
    ) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = manager.peer_task(id, transport, direction, msg_rx).await {
                tracing::warn!(id, %addr, "Peer task ended: {}", e);
            }
            let _ = manager.event_tx.send(NetEvent::PeerDisconnected { id }).await;
        });
    }

    /// Negotiate the transport for an inbound connection.
    ///
    /// BIP 324 leaves v1/v2 detection to the responder. Core's
    /// `ProcessReceivedMaybeV1Bytes`: the peer speaks v1 only if its first 16
    /// bytes are the network magic followed by the `version` command, and v2
    /// as soon as any byte departs from that prefix. The detection bytes are
    /// consumed off the socket and replayed into whichever transport is built.
    async fn accept_transport(self: &Arc<Self>, id: PeerId, mut stream: TcpStream) -> Result<Connection, String> {
        const V1_PREFIX_LEN: usize = 16;
        let magic = self.chain_state.p2p_magic();
        let timeout = Duration::from_millis(self.connect_timeout_ms.load(Ordering::Relaxed));
        let deadline = tokio::time::Instant::now() + timeout;
        let counters = self.peers.read().get(&id).map(|h| h.stats.clone());

        let mut v1_prefix = [0u8; V1_PREFIX_LEN];
        v1_prefix[..4].copy_from_slice(&magic.to_bytes());
        v1_prefix[4..11].copy_from_slice(b"version");

        // Read until a byte departs from the prefix or all 16 match.
        let mut first: Vec<u8> = Vec::with_capacity(V1_PREFIX_LEN);
        while first.len() < V1_PREFIX_LEN && first[..] == v1_prefix[..first.len()] {
            let mut tmp = [0u8; V1_PREFIX_LEN];
            let want = V1_PREFIX_LEN - first.len();
            let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp[..want]))
                .await
                .map_err(|_| "v2 detection timeout".to_string())?
                .map_err(|e| format!("v2 detection read: {}", e))?;
            if n == 0 {
                return Err("v2 detection read: early eof".to_string());
            }
            first.extend_from_slice(&tmp[..n]);
        }

        if first[..] == v1_prefix[..] {
            if self.v2_only() {
                return Err("v2only: rejecting inbound v1 peer".to_string());
            }
            return Ok(Connection::v1_with_leading(stream, magic, first));
        }

        // A v2 key. Its bytes count as they arrive, as Core's do.
        if let Some(c) = &counters {
            c.record_recv(first.len());
        }
        while first.len() < V1_PREFIX_LEN {
            let mut tmp = [0u8; V1_PREFIX_LEN];
            let want = V1_PREFIX_LEN - first.len();
            let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp[..want]))
                .await
                .map_err(|_| "v2 handshake timeout".to_string())?
                .map_err(|e| format!("v2 responder handshake: {}", e))?;
            if n == 0 {
                return Err("v2 responder handshake: early eof".to_string());
            }
            if let Some(c) = &counters {
                c.record_recv(n);
            }
            first.extend_from_slice(&tmp[..n]);
        }
        // A v1 `version` message under another network's magic.
        if first[4..] == v1_prefix[4..] {
            tracing::debug!(
                "V2 transport error: V1 peer with wrong MessageStart {}, peer={id}",
                hex::encode(&first[..4])
            );
            return Err("v1 peer with the wrong network magic".to_string());
        }

        let network = self.chain_state.network;
        let (cipher, leftover) = tokio::time::timeout_at(
            deadline,
            crate::net::v2transport::responder_handshake(
                &mut stream,
                network,
                &first,
                id,
                counters.as_ref(),
            ),
        )
        .await
        .map_err(|_| "v2 handshake timeout".to_string())?
        .map_err(|e| format!("v2 responder handshake: {}", e))?;
        Ok(Connection::v2(crate::net::v2transport::V2Connection::new(
            stream, cipher, leftover,
        )))
    }

    /// Dial a direct outbound peer (through the SOCKS5 proxy when one is
    /// configured), bounded by Core's `-timeout`.
    ///
    /// An address Core calls unroutable — loopback, RFC 1918 private space,
    /// link-local and the rest of `IsRoutable`'s list — connects directly,
    /// bypassing any configured proxy. Core's `ConnectNode` reaches the proxy
    /// through `GetProxy(addr.GetNetwork(), proxy)`, and an unroutable
    /// address has no proxy configured for its network.
    ///
    /// satd bypassed for *loopback only*, so a `-proxy` node dialling a peer
    /// on 192.168.x.x or 10.x.x.x sent the dial through the proxy — which for
    /// a private address is at best pointless and at worst a leak of the
    /// local topology to whatever is on the other end of it. It also breaks
    /// the functional tests, whose nodes talk over a private range with a
    /// placeholder proxy that never accepts.
    async fn dial_direct(&self, addr: SocketAddr) -> Result<TcpStream, String> {
        let connect_timeout = Duration::from_millis(self.connect_timeout_ms.load(Ordering::Relaxed));
        let use_proxy = self.proxy.is_some() && crate::net::is_routable(addr.ip());
        if let Some(ref proxy_addr) = self.proxy {
            if use_proxy {
                // Per-dial random SOCKS credentials isolate this peer on its own Tor
                // circuit (see `socks_cred`).
                let cred = self.socks_cred();
                let cred_ref = cred.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
                return tokio::time::timeout(connect_timeout, proxy::connect_socks5(proxy_addr, addr, cred_ref))
                    .await
                    .map_err(|_| {
                        format!(
                            "connect to {addr} via proxy timed out after {}ms",
                            connect_timeout.as_millis()
                        )
                    })?
                    .map_err(|e| e.to_string());
            }
            let _ = proxy_addr; // suppress unused warning on the direct path
        }
        tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                format!(
                    "connect to {addr} timed out after {}ms",
                    connect_timeout.as_millis()
                )
            })?
            .map_err(|e| format!("connect failed: {}", e))
    }

    /// Dial a .onion outbound peer through the configured SOCKS5 proxy,
    /// bounded by Core's `-timeout`.
    async fn dial_onion(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        let proxy_addr = self
            .onion_proxy
            .as_deref()
            .or(self.proxy.as_deref())
            .ok_or("no proxy configured for .onion connections")?;
        // Floor the onion dial timeout at ONION_DIAL_TIMEOUT_FLOOR_MS so the Tor
        // rendezvous has time to complete even when `-timeout` is at its 5s
        // default; a larger `-timeout` still extends it.
        let configured = self.connect_timeout_ms.load(Ordering::Relaxed);
        let connect_timeout =
            Duration::from_millis(configured.max(ONION_DIAL_TIMEOUT_FLOOR_MS));
        // Per-dial random SOCKS credentials isolate this onion peer on its own
        // Tor circuit (see `socks_cred`).
        let cred = self.socks_cred();
        let cred_ref = cred.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        tokio::time::timeout(
            connect_timeout,
            proxy::connect_socks5_onion(proxy_addr, host, port, cred_ref),
        )
        .await
        .map_err(|_| {
            format!(
                "connect to onion {host}:{port} via proxy timed out after {}ms",
                connect_timeout.as_millis()
            )
        })?
        .map_err(|e| e.to_string())
    }

    /// (Re-)dial an outbound destination.
    async fn redial(&self, target: &OutboundDial) -> Result<TcpStream, String> {
        match target {
            OutboundDial::Direct(addr) => self.dial_direct(*addr).await,
            OutboundDial::Onion(host, port) => self.dial_onion(host, *port).await,
        }
    }

    /// Establish the transport for an outbound connection on an
    /// already-dialed socket.
    ///
    /// When `-v2transport` is enabled, attempt the BIP 324 v2 initiator
    /// handshake; if it fails (a v1-only peer rejects the ellswift bytes as
    /// bad magic), re-dial a fresh socket and fall back to plaintext v1,
    /// remembering the destination so the next attempt skips v2 directly.
    /// `-v2only` peers are out of scope here (added in PR 5).
    ///
    /// `use_v2` overrides the node-wide `-v2transport` setting for this one
    /// dial: `Some(false)` speaks v1 outright. Only `addconnection` passes it
    /// -- the functional-test framework decides per connection whether its
    /// listener speaks v2, and a v2 attempt against a v1 listener would burn
    /// the single connection that listener accepts before the v1 re-dial
    /// could reach it.
    async fn establish_outbound(
        self: &Arc<Self>,
        id: PeerId,
        mut stream: TcpStream,
        target: OutboundDial,
        use_v2: Option<bool>,
    ) -> Result<(Connection, PeerId), String> {
        let magic = self.chain_state.p2p_magic();
        let skip_v2 = match &target {
            OutboundDial::Direct(addr) => self.v2_downgraded.read().contains(addr),
            OutboundDial::Onion(..) => false,
        };
        let v2_wanted = use_v2.unwrap_or_else(|| self.v2_transport_enabled());
        if !v2_wanted || skip_v2 {
            return Ok((Connection::with_magic(stream, magic), id));
        }

        let network = self.chain_state.network;
        let timeout = Duration::from_millis(self.connect_timeout_ms.load(Ordering::Relaxed));
        let v2 = tokio::time::timeout(
            timeout,
            crate::net::v2transport::initiator_handshake(&mut stream, network, id, None),
        )
        .await;
        match v2 {
            Ok(Ok((cipher, leftover))) => Ok((
                Connection::v2(crate::net::v2transport::V2Connection::new(stream, cipher, leftover)),
                id,
            )),
            _ => {
                drop(stream);
                // Under -v2only we never fall back to v1.
                if self.v2_only() {
                    return Err("v2only: outbound v2 handshake failed".to_string());
                }
                if let OutboundDial::Direct(addr) = &target {
                    self.v2_downgraded.write().insert(*addr);
                }
                tracing::debug!("retrying with v1 transport protocol for peer={id}");
                tracing::debug!("Cleared nodestate for peer={id}");
                // Core retries on a new connection, and so a new peer id.
                let stream = self.redial(&target).await?;
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                Ok((Connection::with_magic(stream, magic), id))
            }
        }
    }

    /// The main task for a single peer.
    async fn peer_task(
        self: &Arc<Self>,
        id: PeerId,
        transport: IncomingTransport,
        direction: Direction,
        mut msg_rx: mpsc::Receiver<NetworkMessage>,
    ) -> Result<(), String> {
        // Outbound transports are established before spawn (so a failed v2
        // handshake can re-dial for v1). Inbound transports are negotiated
        // here, in the spawned task, so the accept loop is never blocked on
        // a peer's handshake: read the first bytes and run v2 detection
        // when enabled, else plaintext v1.
        // Core's `m_connected`, on the node clock: the inactivity check
        // measures `-peertimeout` from here.
        let connected_at = crate::time::now_secs();
        let mut conn = match transport {
            IncomingTransport::Established(conn) => *conn,
            IncomingTransport::Raw(stream) => {
                if self.v2_transport_enabled() {
                    self.accept_transport(id, stream).await?
                } else {
                    Connection::with_magic(stream, self.chain_state.p2p_magic())
                }
            }
        };

        // Record the negotiated transport for getpeerinfo / metrics, and the
        // BIP 324 session ID alongside it. Set together, from the same
        // connection, so `transport == "v2transport"` and an empty
        // `session_id` cannot be reported for the same peer.
        let transport_protocol = conn.transport_protocol();
        let session_id = conn.session_id();
        if let Some(handle) = self.peers.write().get_mut(&id) {
            handle.info.transport = transport_protocol;
            handle.info.session_id = session_id;
        }

        // Count the version handshake too: Core attributes `version` and
        // `verack` in `bytessent_per_msg` / `bytesrecv_per_msg`.
        if let Some(stats) = self.peers.read().get(&id).map(|h| h.stats.clone()) {
            conn.set_counters(stats);
        }

        // Perform handshake with timeout
        let version = self.perform_handshake(id, &mut conn, direction, connected_at).await?;

        // The handshake is done, so record it here rather than waiting for the
        // manager to drain the event below. The manager still gets the event
        // -- it owns the rest of the transition (addrman promotion, sync
        // scheduling) -- but the peer is observably connected the moment it
        // is, not up to one manager drain later.
        //
        // This used to be masked. `getpeerinfo` lists only `Connected` peers,
        // and anything that round-tripped a message through the manager
        // (answering a ping, until it moved onto this task) forced the queue
        // to drain first, so the state was always in place by the time a
        // caller could look. Core's test framework leans on exactly that
        // sequence: `add_p2p_connection` does a ping round trip and then
        // asserts its connection appears in `getpeerinfo`.
        let addr = conn.peer_addr().map_err(|e| e.to_string())?;
        if let Some(handle) = self.peers.write().get_mut(&id) {
            handle.info.set_version(version.clone());
            handle.info.state = PeerState::Connected;
        }
        self.event_tx
            .send(NetEvent::PeerConnected {
                id,
                addr,
                version,
            })
            .await
            .map_err(|e| e.to_string())?;

        // Split connection into read/write halves to avoid cancel-safety issues.
        // read_exact is not cancel-safe — if tokio::select! drops a recv() future
        // mid-read, consumed bytes are lost and the stream becomes misaligned.
        // By running the reader in a dedicated task, it is never cancelled.
        let (mut reader, mut writer) = conn.split();

        // Attach the per-peer wire counters (bytes + last-activity) so the
        // read/write halves record steady-state traffic for getpeerinfo /
        // getnettotals / metrics. Looked up from the already-registered
        // PeerHandle; if the peer was dropped between registration and here,
        // the connection is torn down anyway.
        // Also the ping accounting the write loop needs below, so the map is
        // read once rather than again just before the loop starts.
        let (ping_stats, peer_flow, disconnect_signal, send_queue) = {
            let peers = self.peers.read();
            match peers.get(&id) {
                Some(h) => (
                    Some(h.stats.clone()),
                    Some(h.flow.clone()),
                    Some(h.disconnect.clone()),
                    Some(h.msg_tx.queue().clone()),
                ),
                None => (None, None, None, None),
            }
        };
        if let Some(stats) = &ping_stats {
            reader.set_counters(stats.clone());
            writer.set_counters(stats.clone());
        }

        // An addr-fetch peer is asked for addresses and nothing else: Core
        // marks it not-preferred-for-download and never syncs headers with it
        // (`fPreferredDownload`/`CanServeBlocks` both exclude it), because the
        // connection is about to be dropped.
        let conn_type = self.conn_type_of(id);
        if conn_type == ConnType::AddrFetch {
            writer
                .send(NetworkMessage::GetAddr)
                .await
                .map_err(|e| format!("send getaddr: {}", e))?;
        } else {
            // Request headers to start sync, from one below our best so an
            // up-to-date peer answers with a header rather than nothing.
            let getheaders = sync::make_initial_getheaders(&self.chain_state);
            writer.send(getheaders)
                .await
                .map_err(|e| e.to_string())?;
        }

        // Negotiate compact block support (BIP 152, version 2 = with witness)
        // in low-bandwidth mode, as Core does. A peer is asked for
        // high-bandwidth announcements only once it has delivered a block
        // that became our tip (`maybe_set_peer_as_hb`).
        writer.send(NetworkMessage::SendCmpct(
            bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact: false,
                version: 2,
            },
        ))
        .await
        .map_err(|e| format!("send sendcmpct: {}", e))?;

        // Send our fee filter (BIP 133) so peer doesn't relay low-fee txs to us
        if let Some(rate) = self.fee_filter_for(id) {
            writer
                .send(NetworkMessage::FeeFilter(rate as i64))
                .await
                .map_err(|e| format!("send feefilter: {}", e))?;
            if let Some(h) = self.peers.write().get_mut(&id) {
                h.fee_filter_sent = Some(rate);
            }
        }

        // Core enables address relay on an outbound link as the handshake
        // completes — that is when it sends its one-shot `getaddr` — and
        // skips block-relay-only peers. Inbound links latch lazily instead,
        // in the addr handlers.
        if direction == Direction::Outbound {
            self.setup_address_relay(id);
        }

        // Proactively request addresses from outbound peers when running over a
        // proxy. Onion peers are discovered only through gossip (the hardcoded
        // seeds aside), and a one-time getaddr pulls the peer's address set
        // promptly instead of waiting for unsolicited trickle — which a short-
        // lived connection may never deliver. Matches Bitcoin Core, which sends
        // getaddr to outbound peers. Scoped to proxy mode to leave clearnet
        // address handling unchanged in this fix.
        if direction == Direction::Outbound
            && conn_type != ConnType::AddrFetch
            && (self.proxy.is_some() || self.onion_proxy.is_some())
        {
            writer.send(NetworkMessage::GetAddr)
                .await
                .map_err(|e| format!("send getaddr: {}", e))?;
        }

        // Proactively advertise our own hidden service to this peer so the
        // network can discover and dial us inbound. A v3 onion only rides on
        // addrv2, so this fires only for peers that sent `sendaddrv2` (captured
        // during the handshake). Sent to both inbound and outbound peers — they
        // relay it onward, which is the actual propagation seed; without it a
        // listenonion node is reachable only by peers handed the address out of
        // band.
        if let Some(addr_msg) = self.self_advertise_addrv2(id) {
            // Best-effort gossip: a failed advertisement must NOT tear down an
            // otherwise-healthy peer we just spent a full Tor rendezvous
            // establishing. Log and continue (unlike the session-setup sends
            // above, this is optional and the last step).
            if let Err(e) = writer.send(NetworkMessage::AddrV2(vec![addr_msg])).await {
                tracing::debug!(id, "self-advertise addrv2 send failed: {}", e);
            }
        }

        // Spawn a dedicated read task that forwards messages via a channel.
        // This task is never cancelled, so read_exact always completes.
        let (read_tx, mut read_rx) = mpsc::channel::<NetworkMessage>(64);
        let read_manager = Arc::clone(self);
        let read_task = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(600),
                    reader.recv(),
                )
                .await
                {
                    Ok(Ok(msg)) => {
                        log_received(id, &msg);
                        // Past the handshake, so any `verack` repeats one.
                        if matches!(msg, NetworkMessage::Verack) {
                            tracing::debug!("ignoring redundant verack message from peer={id}");
                        }
                        // Core applies a peer's fee filter on the message
                        // thread. Through the manager's drain it could be up
                        // to a tick late, and a transaction announced in that
                        // window is judged against the filter the peer has
                        // already replaced -- which, coming out of initial
                        // block download, is the one that drops everything.
                        if let NetworkMessage::FeeFilter(rate) = msg {
                            read_manager.set_peer_fee_filter(id, rate);
                        }
                        if read_tx.send(msg).await.is_err() {
                            break; // receiver dropped, peer_task ended
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        tracing::debug!("Peer idle timeout");
                        break;
                    }
                }
            }
        });

        // Main loop: receive from reader task OR send outbound messages.
        // Ping accounting rides on the per-peer counters cloned above, which
        // the write loop needs anyway to decide whether a ping is already
        // outstanding.
        let result = Self::peer_write_loop(
            id,
            &self.event_tx,
            &mut writer,
            &mut msg_rx,
            &mut read_rx,
            ping_stats,
            peer_flow,
            Some(self.drain_now.clone()),
            disconnect_signal,
            send_queue,
        )
        .await;

        read_task.abort();
        result
    }

    /// Wait for everything this peer sent ahead of a `ping` to be finished
    /// with, so the pong answers for it the way Core's does.
    ///
    /// Wakes the manager's drain first. Without that the wait is paced by
    /// the loop's 500 ms tick, which is precisely the cadence this node
    /// answers `ping` off the socket task to keep *out* of the round-trip
    /// time the peer measures.
    ///
    /// Bounded, and deliberately so. Core can wait forever because its
    /// message loop is the thing doing the work; satd's pong waits on other
    /// tasks, and a message that never completes — a bug anywhere along the
    /// block pipeline — would hold the pong until the peer dropped us for
    /// not answering. The bound is well inside a peer's ping timeout
    /// (Core's is 20 minutes), so the connection survives the bug.
    ///
    /// Returns whether the wait timed out.
    async fn await_peer_idle(
        id: PeerId,
        flow: &crate::net::flow::PeerFlow,
        drain_now: &Option<Arc<tokio::sync::Notify>>,
    ) -> bool {
        const MAX_PONG_WAIT: Duration = Duration::from_secs(60);
        let in_flight = flow.in_flight();
        let start = std::time::Instant::now();
        if let Some(wake) = drain_now {
            wake.notify_one();
        }
        let timed_out = tokio::time::timeout(MAX_PONG_WAIT, flow.wait_idle()).await.is_err();
        tracing::trace!(
            "pong peer={id}: waited {:?} for {in_flight} message(s) ahead of it",
            start.elapsed()
        );
        timed_out
    }

    /// Write loop for a peer: forwards received messages to the manager
    /// and sends outbound messages. Separated for clarity.
    ///
    /// Termination contract:
    ///   - `read_rx` closing → reader task ended; exit with error so the
    ///     outer `peer_task` emits `NetEvent::PeerDisconnected`.
    ///   - `msg_rx` closing → manager dropped our `PeerHandle` (e.g. the
    ///     silent-peer drop path, or a deliberate `handle_peer_disconnected`
    ///     call). Exit too, so the TCP socket and reader task actually
    ///     terminate instead of leaving an untracked peer feeding events.
    ///     The earlier `Some(msg) = msg_rx.recv()` pattern silently
    ///     disabled the branch on close — review F2 (PRs #180-#184).
    ///   - the disconnect signal, or a write that makes no progress for
    ///     [`crate::net::send_queue::SEND_TIMEOUT`] → exit, even with the
    ///     write unfinished (`send_watched`).
    ///
    /// Flow control, after Core's send buffer (`send_queue`): the bytes of
    /// every message written are taken off the peer's queue count; while the
    /// count is over the limit, or a `getdata` of the peer's is being served,
    /// the peer's next message is left unread.
    #[allow(clippy::too_many_arguments)]
    async fn peer_write_loop(
        id: PeerId,
        event_tx: &mpsc::Sender<NetEvent>,
        writer: &mut ConnectionWriter,
        msg_rx: &mut mpsc::Receiver<NetworkMessage>,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
        stats: Option<Arc<crate::net::stats::PeerStats>>,
        flow: Option<Arc<crate::net::flow::PeerFlow>>,
        drain_now: Option<Arc<tokio::sync::Notify>>,
        disconnect_signal: Option<Arc<tokio::sync::Notify>>,
        send_queue: Option<Arc<crate::net::send_queue::SendQueue>>,
    ) -> Result<(), String> {
        // Bitcoin Core's keepalive cadence (`PING_INTERVAL`, net_processing.h).
        // The first tick of a tokio interval fires immediately, which is also
        // what Core does: a peer whose last ping time is still zero is pinged
        // as soon as it is set up, not two minutes later.
        // Polled rather than scheduled: the interval and the timeout are
        // judged on the node clock, which `setmocktime` moves (Core's
        // `MaybeSendPing` runs on every send pass).
        let mut ping_timer = tokio::time::interval(Duration::from_secs(1));
        // After a stall, catch up by resuming the cadence rather than firing
        // the missed ticks back to back. The `ping_outstanding()` guard below
        // already swallows a burst, but not relying on that keeps the
        // argument for why this cannot flood a peer a local one.
        ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Built once and pinned, not rebuilt each pass. A `Notified` that is
        // created, polled, and dropped can take a stored permit with it, and
        // here that would be a disconnect the peer never hears about. Peers
        // registered before this signal existed (only the unit-test handles)
        // get a future that never completes, leaving them on the other
        // branches exactly as before.
        let disconnect_requested = async {
            match &disconnect_signal {
                Some(signal) => signal.notified().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(disconnect_requested);

        loop {
            // Core's `ProcessMessages` takes nothing more from a peer while a
            // `getdata` of its is being served, or while its send buffer is
            // full ("Don't bother if send buffer is too full to respond
            // anyway"). The message stays in the peer's read queue, and the
            // reader task stops reading the socket once that is full.
            let reading_paused = send_queue.as_ref().is_some_and(|q| q.reading_paused());
            tokio::select! {
                _ = &mut disconnect_requested => {
                    // Explicit teardown, as opposed to noticing `msg_rx`
                    // close. Same exit, so the outer task aborts the reader
                    // and closes the socket.
                    return Err("disconnected by manager".to_string());
                }
                // Woken when the manager has served a `getdata`, to look
                // again. The writes below re-check after every message.
                _ = async {
                    match &send_queue {
                        Some(q) => q.reader_woken().await,
                        None => std::future::pending::<()>().await,
                    }
                }, if reading_paused => {}
                _ = ping_timer.tick() => {
                    // A peer that keeps talking but never answers a ping is
                    // dropped here. Returning takes the ordinary teardown
                    // path -- the reader task is aborted, the socket closed,
                    // and PeerDisconnected emitted, so IBD block reassignment
                    // runs as it would for any drop.
                    //
                    // A peer that goes fully silent is dealt with earlier and
                    // elsewhere: the reader task's 600s recv timeout ends the
                    // connection well before this deadline. So this branch is
                    // specifically for a peer that is present on the wire and
                    // declining to answer, which is the case a read timeout
                    // cannot see.
                    //
                    // Detection lands within one tick of the timeout, so up to
                    // PING_INTERVAL late; Core polls more often and is tighter.
                    if let Some(stats) = &stats
                        && stats.ping_timed_out(PING_TIMEOUT)
                    {
                        stats.note_ping_timeout();
                        tracing::debug!(
                            "ping timeout: {:.6}s, disconnecting peer={id}",
                            stats.ping_wait_secs().unwrap_or_default()
                        );
                        tracing::warn!(
                            id,
                            timeout_secs = PING_TIMEOUT.as_secs(),
                            reason = "ping_timeout",
                            "Dropping peer that stopped answering pings"
                        );
                        return Err(format!(
                            "ping timeout: no pong in {}s",
                            PING_TIMEOUT.as_secs()
                        ));
                    }
                    // Only one ping in flight at a time, as in Core -- a peer
                    // that never pongs is not sent a fresh nonce every two
                    // minutes, so `pingwait` keeps measuring from the ping
                    // that actually went unanswered.
                    if let Some(stats) = &stats
                        && stats.ping_due(PING_INTERVAL)
                    {
                        // Nonce 0 is the "nothing outstanding" sentinel, so
                        // it must never go on the wire.
                        let nonce = rand::random::<u64>().max(1);
                        stats.ping_sent(nonce);
                        Self::send_watched(
                            id,
                            writer,
                            NetworkMessage::Ping(nonce),
                            Some(stats),
                            disconnect_requested.as_mut(),
                        )
                        .await?;
                    }
                }
                msg = read_rx.recv(), if !reading_paused => {
                    match msg {
                        // A pong is matched here, on the peer's own task,
                        // rather than forwarded to the manager loop.
                        //
                        // Two reasons. The round trip is only meaningful if
                        // it is stamped where the ping was sent: the manager
                        // drains events at most every 500ms, so routing the
                        // pong through it added up to half a second of
                        // queueing delay to every measurement, and `minping`
                        // -- a lifetime minimum -- would converge on the
                        // manager's scheduling floor instead of the link.
                        //
                        // More importantly, the deadline is evaluated on this
                        // task. Judging it against evidence that arrives on a
                        // *different*, shared task means a backlog anywhere
                        // in the node is charged against every peer's
                        // deadline at once -- all of them timing out together
                        // while their pongs sit unprocessed in the queue.
                        // Send and receipt now sit on the same task, so a
                        // peer can only ever be dropped for its own silence.
                        Some(NetworkMessage::Pong(nonce)) => {
                            if let Some(stats) = &stats {
                                let expected = stats.ping_nonce();
                                let problem = if expected == 0 {
                                    Some("Unsolicited pong without ping")
                                } else if nonce == expected {
                                    None
                                } else if nonce == 0 {
                                    Some("Nonce zero")
                                } else {
                                    Some("Nonce mismatch")
                                };
                                stats.pong_received(nonce);
                                if let Some(problem) = problem {
                                    tracing::debug!(
                                        "pong peer={id}: {problem}, {expected:x} expected, {nonce:x} received, 8 bytes"
                                    );
                                }
                            }
                        }
                        // A pong too short to hold a nonce: Core cancels the
                        // outstanding ping ("Short payload").
                        Some(NetworkMessage::Unknown { command, payload })
                            if command.as_ref() == "pong" && payload.len() < 8 =>
                        {
                            if let Some(stats) = &stats {
                                let expected = stats.ping_nonce();
                                stats.cancel_ping();
                                tracing::debug!(
                                    "pong peer={id}: Short payload, {expected:x} expected, 0 received, {} bytes",
                                    payload.len()
                                );
                            }
                        }
                        // Answered here for the same reason the pong is
                        // matched here: a pong is a reflex that needs no
                        // manager state, and routing it through the manager
                        // put the manager's 500ms drain cadence into the
                        // round-trip time our *peer* measures. Core answers
                        // from its message-processing loop, promptly.
                        //
                        // But Core answers it *in order*, having finished
                        // every message that arrived ahead of it on this
                        // connection — which is what makes `send_and_ping`
                        // mean "the block is connected" to a peer and to
                        // Core's own functional tests. satd spreads that
                        // work across tasks, so when the peer has something
                        // outstanding the pong waits for it. An idle peer's
                        // keepalive, which is nearly all of them, still gets
                        // the immediate answer.
                        Some(NetworkMessage::Ping(nonce)) => {
                            if let Some(flow) = &flow
                                && !flow.is_idle()
                            {
                                let waited = Self::await_peer_idle(id, flow, &drain_now).await;
                                if waited {
                                    // A message that never completes is a
                                    // bug in the pipeline, and holding the
                                    // pong past the peer's ping timeout
                                    // would cost us the connection over it.
                                    tracing::debug!(
                                        "pong peer={id}: still {} message(s) in flight after \
                                         waiting, answering anyway",
                                        flow.in_flight()
                                    );
                                }
                            }
                            Self::send_watched(
                                id,
                                writer,
                                NetworkMessage::Pong(nonce),
                                stats.as_ref(),
                                disconnect_requested.as_mut(),
                            )
                            .await?;
                        }
                        Some(msg) => {
                            // Counted in here and out wherever the work ends
                            // — the manager's drain for a message handled
                            // inline, the block processor for a block. A
                            // pong behind this message waits for that.
                            if let Some(flow) = &flow {
                                flow.queued();
                            }
                            // Nothing more is read until the manager has
                            // served this request (`reading_paused`), so it
                            // is served now rather than at the manager's next
                            // tick: a peer fetching blocks sends one `getdata`
                            // after another.
                            let getdata = matches!(msg, NetworkMessage::GetData(_));
                            if let (true, Some(q)) = (getdata, &send_queue) {
                                q.note_getdata_forwarded();
                            }
                            event_tx
                                .send(NetEvent::MessageReceived { id, msg })
                                .await
                                .map_err(|e| e.to_string())?;
                            if let (true, Some(wake)) = (getdata, &drain_now) {
                                wake.notify_one();
                            }
                        }
                        None => {
                            // Reader task ended (error or timeout)
                            return Err("connection closed".to_string());
                        }
                    }
                }
                msg = msg_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            // A ping queued by the manager (the `ping` RPC)
                            // is recorded here, at transmit, not where it was
                            // queued. The RPC task recording it raced this
                            // loop: the pong could arrive before the RPC task
                            // stored the nonce, be discarded as unsolicited,
                            // and leave the nonce outstanding until the peer
                            // was dropped at PING_TIMEOUT for a ping it
                            // answered. Recording at transmit puts every ping
                            // state transition on this task, in order. If a
                            // periodic ping is already in flight, the new
                            // nonce overrides it and the older pong is
                            // discarded as a mismatch — Core's behaviour when
                            // an RPC ping lands on top of a keepalive.
                            if let (NetworkMessage::Ping(nonce), Some(stats)) = (&msg, &stats) {
                                stats.ping_sent(*nonce);
                            }
                            // What the sender counted the message at.
                            let size = send_queue
                                .as_ref()
                                .map(|_| crate::net::send_queue::queued_size(&msg));
                            Self::send_watched(id, writer, msg, stats.as_ref(), disconnect_requested.as_mut())
                                .await?;
                            if let (Some(q), Some(size)) = (&send_queue, size) {
                                q.sent(size);
                                // Back under the send buffer with `getdata`
                                // entries waiting: ask the manager for more.
                                if q.take_resume() {
                                    event_tx
                                        .send(NetEvent::GetDataResume { id })
                                        .await
                                        .map_err(|e| e.to_string())?;
                                    if let Some(wake) = &drain_now {
                                        wake.notify_one();
                                    }
                                }
                            }
                        }
                        None => {
                            // Manager dropped our handle. Return so the
                            // outer task aborts the reader and closes
                            // the TCP socket; without this exit, the
                            // task would keep running on `read_rx` and
                            // emit `MessageReceived` events for a peer
                            // no longer in `self.peers`.
                            return Err("disconnected by manager".to_string());
                        }
                    }
                }
            }
        }
    }

    /// Write one message to the peer, giving up if the manager drops the peer
    /// or the socket takes no bytes for
    /// [`crate::net::send_queue::SEND_TIMEOUT`].
    ///
    /// A peer that stops reading leaves a write parked for as long as it
    /// likes, and the write loop looked at the disconnect signal and the ping
    /// deadline only between writes. So `disconnectnode`, a ban and the ping
    /// timeout could not reach such a peer, and its socket and everything
    /// queued to it stayed. Core drops a peer that has taken no bytes for
    /// `TIMEOUT_INTERVAL` (`InactivityCheck`, "socket sending timeout").
    /// Progress is the bytes the socket takes, counted as it takes them, so a
    /// slow reader is not mistaken for a stalled one. Without counters, which
    /// only a loop whose peer handle was already gone when it started lacks,
    /// progress cannot be seen and the deadline runs from the start of the
    /// write.
    async fn send_watched<F: std::future::Future<Output = ()>>(
        id: PeerId,
        writer: &mut ConnectionWriter,
        msg: NetworkMessage,
        stats: Option<&Arc<PeerStats>>,
        mut disconnect: std::pin::Pin<&mut F>,
    ) -> Result<(), String> {
        use crate::net::send_queue::SEND_TIMEOUT;
        /// How often a parked write is checked for progress.
        const PROGRESS_CHECK: Duration = Duration::from_secs(10);

        let send = writer.send(msg);
        tokio::pin!(send);
        // Most writes finish at once; only one that has to wait is watched.
        tokio::select! {
            biased;
            res = &mut send => return res.map_err(|e| e.to_string()),
            _ = std::future::ready(()) => {}
        }
        let mut check = tokio::time::interval(PROGRESS_CHECK);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sent = stats.map(|s| s.bytes_sent());
        let mut progress_at = tokio::time::Instant::now();
        loop {
            tokio::select! {
                res = &mut send => return res.map_err(|e| e.to_string()),
                _ = disconnect.as_mut() => return Err("disconnected by manager".to_string()),
                _ = check.tick() => {
                    let now_sent = stats.map(|s| s.bytes_sent());
                    if now_sent != sent {
                        sent = now_sent;
                        progress_at = tokio::time::Instant::now();
                    } else if progress_at.elapsed() >= SEND_TIMEOUT {
                        let secs = progress_at.elapsed().as_secs();
                        tracing::debug!("socket sending timeout: {secs}s, disconnecting peer={id}");
                        return Err(format!("socket sending timeout: no bytes taken in {secs}s"));
                    }
                }
            }
        }
    }

    /// Receive the next handshake message, dropping the peer when Core's
    /// `InactivityCheck` would: `-peertimeout` seconds after it connected, on
    /// the node clock, with the handshake still incomplete.
    async fn recv_handshake(
        &self,
        id: PeerId,
        conn: &mut Connection,
        connected_at: u64,
    ) -> Result<NetworkMessage, String> {
        let recv = conn.recv();
        tokio::pin!(recv);
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                r = &mut recv => return r.map_err(|e| format!("recv: {}", e)),
                _ = tick.tick() => {
                    if let Some(reason) = self.handshake_inactivity(id, connected_at) {
                        tracing::debug!("{reason}");
                        return Err("handshake timeout".to_string());
                    }
                }
            }
        }
    }

    /// Core's `InactivityCheck` for a connection that has not finished its
    /// handshake: `None` until `-peertimeout` has passed, then the reason
    /// line Core logs.
    fn handshake_inactivity(&self, id: PeerId, connected_at: u64) -> Option<String> {
        let timeout = self.peer_connect_timeout_secs.load(Ordering::Relaxed);
        if crate::time::now_secs() <= connected_at.saturating_add(timeout) {
            return None;
        }
        let (received, sent) = self
            .peers
            .read()
            .get(&id)
            .map_or((true, true), |h| (h.stats.bytes_recv() > 0, h.stats.bytes_sent() > 0));
        if received && sent {
            return Some(format!("version handshake timeout, disconnecting peer={id}"));
        }
        let mut never = String::new();
        if !received {
            never.push_str(", never received from peer");
        }
        if !sent {
            never.push_str(", never sent to peer");
        }
        Some(format!("socket no message in first {timeout} seconds{never}, disconnecting peer={id}"))
    }

    /// Core's `HasAllDesirableServiceFlags` for an outbound full-relay,
    /// block-relay-only or addr-fetch peer: `NETWORK | WITNESS`, or
    /// `NETWORK_LIMITED | WITNESS` from a pruned peer while our tip is within a
    /// day of now. Returns the flags wanted when the peer lacks them.
    fn missing_desirable_services(&self, services: ServiceFlags) -> Option<ServiceFlags> {
        let mut wanted = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        if services.has(ServiceFlags::NETWORK_LIMITED) {
            let tip_time = self
                .chain_state
                .get_block_index(&self.chain_state.tip_hash())
                .map_or(0, |e| e.header.time as u64);
            let depth = crate::time::now_secs().saturating_sub(tip_time) / 600;
            if depth < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS {
                wanted = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
            }
        }
        (!services.has(wanted)).then_some(wanted)
    }

    /// Perform the version/verack handshake, bounded by `-peertimeout`.
    async fn perform_handshake(
        &self,
        id: PeerId,
        conn: &mut Connection,
        direction: Direction,
        connected_at: u64,
    ) -> Result<VersionMessage, String> {
        // The connection type is already recorded on the PeerHandle by
        // `spawn_peer` / `accept_inbound`, so the handshake can read it rather
        // than have it threaded down again.
        let conn_type = self.conn_type_of(id);
        let our_version =
            self.build_version_message(conn.peer_addr().map_err(|e| e.to_string())?, conn_type);
        if direction == Direction::Outbound
            && let Some(h) = self.peers.write().get_mut(&id)
        {
            h.info.local_nonce = Some(our_version.nonce);
        }

        // BIP 155: a peer sends `sendaddrv2` after its version and before its
        // verack to opt into addrv2. Those bytes arrive inside the recv loops
        // below, which otherwise only care about version/verack — so note the
        // flag here, or we'd silently drop it and never send addrv2 (incl. our
        // onion) to a peer that supports it.
        let mut peer_wants_addrv2 = false;
        // BIP 339: likewise `wtxidrelay`, which asks for transactions to be
        // announced by wtxid. It counts only between version and verack.
        let mut peer_wtxid_relay = false;

        if direction == Direction::Outbound {
            conn.send(NetworkMessage::Version(our_version.clone()))
                .await
                .map_err(|e| format!("send version: {}", e))?;
        }

        // Core's `ProcessMessage` before `version`: anything else is ignored
        // with a line naming it.
        let their_version = loop {
            match self.recv_handshake(id, conn, connected_at).await? {
                // Core reads the user agent as `LIMITED_STRING(strSubVer,
                // MAX_SUBVERSION_LENGTH)`. A longer one throws in
                // deserialization: the `version` is dropped, and the peer is
                // left without a handshake until a well-formed one arrives or
                // the connect timeout ends it (`recv_handshake` applies it
                // here too).
                NetworkMessage::Version(v) if v.user_agent.len() > crate::MAX_SUBVERSION_LENGTH => {
                    tracing::debug!(
                        "ignoring version message with a {}-byte user agent (limit {}) from peer={id}",
                        v.user_agent.len(),
                        crate::MAX_SUBVERSION_LENGTH
                    )
                }
                NetworkMessage::Version(v) => break v,
                other => tracing::debug!(
                    "non-version message before version handshake. Message \"{}\" from peer={id}",
                    handshake_msg_type(&other)
                ),
            }
        };

        if direction == Direction::Inbound {
            // Core's `CheckIncomingNonce`: our own outbound version coming back.
            let to_self = self.peers.read().values().any(|h| {
                h.info.direction == Direction::Outbound
                    && h.info.state != PeerState::Connected
                    && h.info.local_nonce == Some(their_version.nonce)
            });
            if to_self {
                let addr = conn.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
                tracing::info!("connected to self at {addr}, disconnecting");
                return Err("connected to self".to_string());
            }
        }

        if direction == Direction::Outbound
            && matches!(conn_type, ConnType::OutboundFullRelay | ConnType::BlockRelay | ConnType::AddrFetch)
            && let Some(wanted) = self.missing_desirable_services(their_version.services)
        {
            tracing::debug!(
                "peer does not offer the expected services ({:08x} offered, {:08x} expected), disconnecting peer={id}",
                their_version.services.to_u64(),
                wanted.to_u64()
            );
            return Err("peer lacks the expected services".to_string());
        }

        // The feature negotiation messages go out between the peer's version
        // and our verack, and only at a common version of at least 70016, as
        // Core sends them. BIP 339 negotiates on that version, so the peer's
        // `wtxidrelay` counts only there too. BIP 155 is defined for every
        // version, but Core withholds `sendaddrv2` below it as a courtesy to
        // software that rejects messages it does not know.
        let common_version = their_version.version.min(PROTOCOL_VERSION);
        let wtxid_relay_version = common_version >= WTXID_RELAY_VERSION;

        match direction {
            Direction::Outbound => {
                // A feeler exists to answer one question -- is anything still
                // listening there? -- and the peer's `version` answers it.
                // Core closes the connection here without sending a verack
                // (`net_processing.cpp`: "disconnect feeler connections after
                // the handshake"), so the peer never enters the connected set
                // and never reaches `getpeerinfo`.
                if conn_type == ConnType::Feeler {
                    tracing::debug!("feeler connection completed, disconnecting peer={id}");
                    // Drop the handle here rather than leaving it for the
                    // manager's next event drain. `is_addr_connected` counts
                    // anything not yet `Disconnected`, so a lingering feeler
                    // makes the very next dial to that address fail with
                    // "already connected" -- which is exactly what a caller
                    // does after a feeler tells it the address is alive.
                    self.peers.write().remove(&id);
                    return Err("feeler connection: closing after version".to_string());
                }
                self.send_feature_negotiation(conn, wtxid_relay_version).await?;
                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;
            }
            Direction::Inbound => {
                conn.send(NetworkMessage::Version(our_version))
                    .await
                    .map_err(|e| format!("send version: {}", e))?;
                self.send_feature_negotiation(conn, wtxid_relay_version).await?;
                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;
            }
        }

        // Between `version` and `verack` Core takes only the negotiation
        // messages; anything else is ignored with a line naming it.
        loop {
            match self.recv_handshake(id, conn, connected_at).await? {
                NetworkMessage::Verack => break,
                NetworkMessage::SendAddrV2 => peer_wants_addrv2 = true,
                // Core's `WTXIDRELAY` handler, with its log lines.
                NetworkMessage::WtxidRelay if !wtxid_relay_version => tracing::debug!(
                    "ignoring wtxidrelay due to old common version={common_version} from peer={id}"
                ),
                NetworkMessage::WtxidRelay if peer_wtxid_relay => {
                    tracing::debug!("ignoring duplicate wtxidrelay from peer={id}")
                }
                NetworkMessage::WtxidRelay => peer_wtxid_relay = true,
                NetworkMessage::Unknown { command, .. } if command.as_ref() == "sendtxrcncl" => {}
                other => tracing::debug!(
                    "Unsupported message \"{}\" prior to verack from peer={id}",
                    handshake_msg_type(&other)
                ),
            }
        }

        // An outbound peer is asked for header announcements now; an inbound
        // one once it has shown a block past the minimum chain work
        // (`maybe_send_sendheaders`, Core's condition). Core waits on the
        // outbound side too, but satd fetches a block announced by `inv`
        // before it has the header, so a peer that mines while this node
        // syncs would hand it an out-of-order chain; header announcements
        // from the start keep that sync in order. Marked sent, so the
        // condition never sends a second one.
        if direction == Direction::Outbound
            && their_version.version.min(PROTOCOL_VERSION) >= SENDHEADERS_VERSION
        {
            conn.send(NetworkMessage::SendHeaders)
                .await
                .map_err(|e| format!("send sendheaders: {}", e))?;
            if let Some(handle) = self.peers.write().get_mut(&id) {
                handle.info.sent_sendheaders = true;
            }
        }

        if peer_wants_addrv2
            && let Some(handle) = self.peers.write().get_mut(&id)
        {
            handle.info.wants_addrv2 = true;
        }
        // Set before the peer is marked connected, so it is never announced a
        // transaction by txid once it has asked for wtxids.
        if peer_wtxid_relay
            && let Some(handle) = self.peers.write().get_mut(&id)
        {
            handle.info.wtxid_relay = true;
        }

        Ok(their_version)
    }

    /// `wtxidrelay` (BIP 339) then `sendaddrv2` (BIP 155), Core's order, when
    /// the common version reaches 70016; nothing below it.
    async fn send_feature_negotiation(&self, conn: &mut Connection, at_70016: bool) -> Result<(), String> {
        if !at_70016 {
            return Ok(());
        }
        conn.send(NetworkMessage::WtxidRelay)
            .await
            .map_err(|e| format!("send wtxidrelay: {}", e))?;
        conn.send(NetworkMessage::SendAddrV2)
            .await
            .map_err(|e| format!("send sendaddrv2: {}", e))
    }

    /// Disconnect any `addr-fetch` peer that has been connected longer than
    /// [`ADDR_FETCH_TIMEOUT_SECS`] without completing.
    fn expire_addr_fetch_peers(self: &Arc<Self>) {
        let now = crate::time::now_secs();
        let stale: Vec<PeerId> = self
            .peers
            .read()
            .values()
            .filter(|h| h.info.conn_type == ConnType::AddrFetch)
            .filter(|h| {
                let connected_at = h
                    .info
                    .conn_time
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now.saturating_sub(connected_at) > ADDR_FETCH_TIMEOUT_SECS
            })
            .map(|h| h.info.id)
            .collect();
        for id in stale {
            tracing::debug!(id, "addrfetch connection timeout, disconnecting");
            self.disconnect_by_id(id);
        }
    }

    /// The connection type of a registered peer, defaulting to full-relay for
    /// a peer that has already gone away (nothing downstream of this reads it
    /// for a peer that no longer exists).
    /// Core's `SetupAddressRelay`: latch address relay on for this link and
    /// report whether it is on at all.
    ///
    /// A block-relay-only connection never participates, in either
    /// direction — answering or accepting addr traffic on one is exactly
    /// what would let an observer infer the link. For every other peer the
    /// flag latches on the first addr-related message, which is what
    /// `getpeerinfo.addr_relay_enabled` reports.
    fn setup_address_relay(&self, id: PeerId) -> bool {
        let mut peers = self.peers.write();
        let Some(handle) = peers.get_mut(&id) else {
            return false;
        };
        if !handle.info.conn_type.relays_addrs() {
            return false;
        }
        handle.info.addr_relay_enabled = true;
        true
    }

    fn conn_type_of(&self, id: PeerId) -> ConnType {
        self.peers
            .read()
            .get(&id)
            .map(|h| h.info.conn_type)
            .unwrap_or(ConnType::OutboundFullRelay)
    }

    /// The service flags this node advertises right now.
    ///
    /// The single source of truth for both the wire and `getnetworkinfo`.
    /// `localservices` used to be a hardcoded `0000000000000409`, claiming
    /// `NODE_NETWORK_LIMITED` — which satd never sets — and never reflecting
    /// `NODE_COMPACT_FILTERS`, which it does set once the filter index can
    /// serve. So the RPC described a node that did not exist, in both
    /// directions at once.
    pub fn local_services(&self) -> ServiceFlags {
        // Only the cfg-gated COMPACT_FILTERS bit below mutates this.
        let mut services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        // BIP 324 NODE_P2P_V2 (bit 11), which Core sets with -v2transport.
        if self.v2_transport_enabled() {
            services |= ServiceFlags::P2P_V2;
        }
        // BIP 157 NODE_COMPACT_FILTERS (bit 6) — advertised at version
        // time when the runtime predicate is true. Re-evaluated per
        // outgoing handshake so a node that finishes a backfill or
        // toggles `peerblockfilters` mid-run picks up the change for
        // new connections without a restart.
        #[cfg(feature = "block-filter-index")]
        if self.peer_serve_filters_ready() {
            services |= ServiceFlags::COMPACT_FILTERS;
        }
        services
    }

    fn build_version_message(&self, receiver: SocketAddr, conn_type: ConnType) -> VersionMessage {
        let services = self.local_services();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Advertise our first declared external address (`-externalip`)
        // as addr_from; fall back to the unspecified address otherwise.
        let sender = self
            .external_addrs
            .read()
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        VersionMessage {
            version: PROTOCOL_VERSION,
            services,
            timestamp,
            receiver: Address::new(&receiver, ServiceFlags::NONE),
            sender: Address::new(&sender, services),
            nonce: rand::random(),
            user_agent: crate::user_agent().to_string(),
            start_height: self.chain_state.tip_height() as i32,
            // BIP 37 fRelay. Core clears it on block-relay-only and feeler
            // connections regardless of -blocksonly: asking for transactions
            // on a connection whose whole purpose is to be invisible to a
            // tx-graph observer would defeat it.
            relay: !self.blocksonly() && conn_type.wants_tx_relay(),
        }
    }
}

/// Current Unix time in whole seconds (saturating; 0 before the epoch).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a block arriving for the background's historical range may be
/// stored. Pure decision so the AssumeUTXO height→hash poisoning guard is
/// unit-testable without a full `PeerManager`.
///
/// - A block above `snapshot_height` is forward-range, not part of the
///   fixed historical mapping → storable.
/// - At or below the snapshot it must be the canonical block for its
///   height (`canonical_at_height == Some(block_hash)`); a valid
///   non-canonical side block is refused so it cannot overwrite the
///   shared height→hash mapping the background connector reads.
fn historical_block_storable(
    snapshot_height: u32,
    prospective_height: u32,
    canonical_at_height: Option<bitcoin::BlockHash>,
    block_hash: bitcoin::BlockHash,
) -> bool {
    if prospective_height > snapshot_height {
        return true;
    }
    canonical_at_height == Some(block_hash)
}

#[cfg(test)]
#[path = "manager_blockaccept_tests.rs"]
mod blockaccept_tests;

#[cfg(test)]
#[path = "manager_orphanbuf_tests.rs"]
mod orphanbuf_tests;

/// Reconsider orphans whose missing parent was just confirmed in `block`.
///
/// Standalone so the `block_processor` thread — which doesn't have a
/// `PeerManager` handle — can invoke it after `remove_for_block`.
/// No peer relay: orphans admitted here are in our local mempool; peers
/// will re-announce on their own schedule.
pub fn reconsider_orphans_on_block(
    orphanage: &Arc<TxOrphanage>,
    mempool: &Arc<Mempool>,
    chain_state: &Arc<ChainState>,
    block: &bitcoin::Block,
) {
    use std::collections::VecDeque;
    let mut queue: VecDeque<bitcoin::Txid> = VecDeque::new();
    for tx in &block.txdata {
        let confirmed_txid = tx.compute_txid();
        // Drop any orphan that is itself the confirmed tx.
        let _ = orphanage.remove(&confirmed_txid);
        for child in orphanage.children_of(&confirmed_txid) {
            queue.push_back(child);
        }
    }
    while let Some(child_txid) = queue.pop_front() {
        let Some(child) = orphanage.remove(&child_txid) else {
            continue;
        };
        let result = mempool.accept_transaction(
            child.tx.clone(),
            chain_state,
            chain_state.script_verifier(),
            crate::mempool::pool::TxSource::P2p,
            false,
        );
        match result {
            Ok(_) => {
                for grandchild in orphanage.children_of(&child_txid) {
                    queue.push_back(grandchild);
                }
            }
            Err(MempoolError::MissingInputs) => {
                // Other parents still unresolved — re-orphan with updated
                // set. If the set is empty (race), `add` returns
                // NoMissingParents and we drop silently rather than
                // stranding an unreachable orphan.
                let mut missing = std::collections::HashSet::new();
                for input in &child.tx.input {
                    let parent = input.previous_output.txid;
                    if chain_state.get_coin(&input.previous_output).is_some() {
                        continue;
                    }
                    if mempool.get(&parent).is_some() {
                        continue;
                    }
                    missing.insert(parent);
                }
                let _ = orphanage.add(child.tx, child.from_peer, missing);
            }
            Err(e) => {
                tracing::debug!(%child_txid, "Orphan dropped on block-connect re-eval: {}", e);
            }
        }
    }
}

/// Minimum catch-up size (blocks behind the IBD target) before the
/// connect loop disables the RocksDB WAL via [`BulkLoadGuard`].
///
/// Below this, the WAL's per-write cost is noise but its crash-safety is
/// not: WAL-less writes survive a process exit only if a memtable flush
/// happened to run after them, and short catch-ups write too little data
/// to ever trigger one organically. 10k blocks is roughly two months of
/// mainnet — anything a routine restart or brief outage produces stays in
/// Normal mode.
const BULKLOAD_MIN_BLOCKS_BEHIND: u32 = 10_000;

/// Whether a catch-up of `blocks_behind` blocks is large enough to be
/// worth running with the WAL disabled.
fn use_bulkload_for_catchup(blocks_behind: u32) -> bool {
    blocks_behind >= BULKLOAD_MIN_BLOCKS_BEHIND
}

/// RAII guard that scopes `WriteMode::BulkLoad` to a lexical region.
///
/// Constructor sets BulkLoad. `Drop` attempts a best-effort
/// `flush_durable` and then unconditionally restores `Normal`, so WAL-
/// disabled write behavior cannot leak past IBD even if the IBD loop
/// exits via a non-success path or panics.
///
/// Callers on the clean-success IBD-complete path should still invoke
/// `flush_durable` explicitly and fail-closed if it errors — a silent
/// "IBD complete" with a failed checkpoint must not be allowed. The
/// guard's `Drop` is a backstop, not the primary durability contract.
struct BulkLoadGuard<'a> {
    chain_state: &'a ChainState,
}

impl<'a> BulkLoadGuard<'a> {
    fn new(chain_state: &'a ChainState) -> Self {
        chain_state.set_write_mode(crate::storage::WriteMode::BulkLoad);
        Self { chain_state }
    }
}

impl Drop for BulkLoadGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.chain_state.flush_durable() {
            tracing::error!(
                error = %e,
                "BulkLoadGuard: durable flush failed on IBD exit. \
                 Restoring Normal write mode anyway; next startup will \
                 replay any lost BulkLoad writes from the flat-file block \
                 store (DataStored -> Valid replay path)."
            );
        }
        self.chain_state.set_write_mode(crate::storage::WriteMode::Normal);
        tracing::info!("BulkLoadGuard: restored Normal write mode");
    }
}

/// Accept a locally-originated transaction into the mempool and announce
/// it to peers, as one operation. Implemented by [`PeerManager`] and
/// injected into the out-of-crate broadcast surfaces (Esplora `POST /tx`,
/// Electrum `transaction.broadcast`) so a surface cannot accept a tx into
/// the mempool without also putting it on the wire — the gap that left
/// MCP-, Esplora-, and Electrum-broadcast txs sitting unannounced.
///
/// A trait (rather than a concrete `Arc<PeerManager>`) keeps those crates
/// decoupled from the P2P manager and lets their tests inject a fake.
pub trait TxBroadcaster: Send + Sync {
    /// Accept `tx` into the mempool and announce it to peers. Returns the
    /// txid, or the mempool rejection reason. `source` records the submission
    /// surface for the transaction-policy engine (`tx.source`).
    ///
    /// `allow_quarantined` is the §6.1 override: when false (the default) a
    /// local submission drawing a relay-scoped quarantine verdict is refused
    /// (`MempoolError::Quarantined`); when true it is held in quarantine anyway.
    fn submit_and_announce(
        &self,
        tx: bitcoin::Transaction,
        source: crate::mempool::pool::TxSource,
        allow_quarantined: bool,
    ) -> Result<bitcoin::Txid, MempoolError>;
}

impl TxBroadcaster for PeerManager {
    fn submit_and_announce(
        &self,
        tx: bitcoin::Transaction,
        source: crate::mempool::pool::TxSource,
        allow_quarantined: bool,
    ) -> Result<bitcoin::Txid, MempoolError> {
        PeerManager::submit_and_announce(self, tx, source, allow_quarantined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::peer::{Direction, PeerInfo, PeerState};

    /// Drive the pacer through `secs` of a queue that is full after every
    /// drain, each drain taking `drain`. Returns when maintenance started.
    fn maintenance_under_a_full_queue(drain: Duration, secs: u64) -> Vec<Instant> {
        let t0 = Instant::now();
        let mut pacer = DrainPacer::default();
        let mut now = t0;
        let mut ran = Vec::new();
        while now < t0 + Duration::from_secs(secs) {
            match pacer.after_drain(EVENTS_PER_DRAIN, now) {
                AfterDrain::Maintain => {
                    pacer.maintained(now);
                    ran.push(now);
                }
                AfterDrain::DrainAgain => {}
                AfterDrain::Wait => panic!("a full queue must never wait"),
            }
            now += drain;
        }
        ran
    }

    /// #909: a queue that stays full, as in initial block download, still
    /// gets maintenance every `MAINTENANCE_INTERVAL`, at most one drain late,
    /// whether a drain is quick or, with an fsync per stored block, takes
    /// most of a second. 0.6.0 let the full queue put maintenance off, and
    /// stall detection ran tens of seconds apart.
    ///
    /// Perturbation: in `after_drain`, check for a full queue before checking
    /// whether maintenance is due, and maintenance never runs.
    #[test]
    fn maintenance_runs_on_time_under_a_queue_that_stays_full() {
        for drain in [Duration::from_millis(20), Duration::from_millis(600)] {
            let ran = maintenance_under_a_full_queue(drain, 30);
            let slowest = ran.windows(2).map(|w| w[1] - w[0]).max().unwrap_or_default();
            assert!(
                slowest <= MAINTENANCE_INTERVAL + drain,
                "{drain:?} drains: maintenance {slowest:?} apart"
            );
            let expected = 30_000 / (MAINTENANCE_INTERVAL + drain).as_millis() as usize;
            assert!(ran.len() >= expected, "{drain:?} drains: {} passes, want {expected}", ran.len());
        }
    }

    /// #781's fast drains stay: between maintenance passes a full queue is
    /// drained again at once rather than once per interval tick.
    #[test]
    fn a_full_queue_is_drained_again_until_maintenance_is_due() {
        let t0 = Instant::now();
        let mut pacer = DrainPacer::default();
        assert_eq!(pacer.after_drain(EVENTS_PER_DRAIN, t0), AfterDrain::Maintain, "first pass");
        pacer.maintained(t0);
        for ms in [1, 100, 499] {
            let at = t0 + Duration::from_millis(ms);
            assert_eq!(pacer.after_drain(EVENTS_PER_DRAIN, at), AfterDrain::DrainAgain, "{ms} ms");
        }
        let due = t0 + MAINTENANCE_INTERVAL;
        assert_eq!(pacer.after_drain(EVENTS_PER_DRAIN, due), AfterDrain::Maintain);
    }

    /// A drained queue waits for the next wake until maintenance is due.
    /// That holds for a wake from `drain_now` too (#776): pongs parked
    /// behind the queue arrive at the rate peers ping, and maintenance must
    /// not run at that rate.
    #[test]
    fn a_drained_queue_waits_until_maintenance_is_due() {
        let t0 = Instant::now();
        let mut pacer = DrainPacer::default();
        pacer.maintained(t0);
        for ms in [10, 20, 30, 250, 499] {
            let at = t0 + Duration::from_millis(ms);
            assert_eq!(pacer.after_drain(1, at), AfterDrain::Wait, "{ms} ms");
        }
        assert_eq!(pacer.after_drain(0, t0 + MAINTENANCE_INTERVAL), AfterDrain::Maintain);
    }

    /// An idle loop runs maintenance at every interval tick, as before,
    /// even when a tick finds it less than `MAINTENANCE_INTERVAL` after the
    /// last pass started because that pass began late, behind a slower
    /// drain. Skipping such a tick would stretch every cadence counted in
    /// ticks.
    ///
    /// Perturbation: make maintenance due by time alone and the tick after a
    /// 40 ms drain is skipped.
    #[test]
    fn an_idle_loop_maintains_at_every_tick() {
        let t0 = Instant::now();
        let mut pacer = DrainPacer::default();
        // Each tick's drain takes this long before the pass decides.
        let drains_ms = [0u64, 40, 2, 0, 15, 1, 30, 0];
        for (k, d) in drains_ms.iter().enumerate() {
            let tick = t0 + MAINTENANCE_INTERVAL * k as u32;
            if k > 0 {
                pacer.ticked();
            }
            let at = tick + Duration::from_millis(*d);
            assert_eq!(pacer.after_drain(2, at), AfterDrain::Maintain, "tick {k}");
            pacer.maintained(at);
        }
    }

    /// A wait shorter than the threshold is out-of-order download, not a
    /// stall: no warning, however many heights it happens at (#904).
    #[test]
    fn stuck_wait_does_not_warn_on_an_ordinary_wait() {
        let t0 = Instant::now();
        let mut wait = None;
        assert!(!StuckWait::should_warn(&mut wait, 100, t0));
        assert!(!StuckWait::should_warn(&mut wait, 100, t0 + Duration::from_secs(1)));
        // The next height starts its own wait, so waits just under the
        // threshold, such as one a stale-block release ends at 15 s, never
        // add up.
        let under = STUCK_WAIT_WARN_AFTER - Duration::from_secs(1);
        for (i, height) in (101..120).enumerate() {
            let at = t0 + Duration::from_secs(2) + STUCK_WAIT_WARN_AFTER * i as u32;
            assert!(!StuckWait::should_warn(&mut wait, height, at));
            assert!(!StuckWait::should_warn(&mut wait, height, at + under));
        }
    }

    /// Past the threshold on one height, the warning fires once, then again
    /// a minute later while the same wait goes on.
    #[test]
    fn stuck_wait_warns_once_past_the_threshold_then_every_minute() {
        let t0 = Instant::now();
        let mut wait = None;
        assert!(!StuckWait::should_warn(&mut wait, 100, t0));
        let just_before = t0 + STUCK_WAIT_WARN_AFTER - Duration::from_millis(1);
        assert!(!StuckWait::should_warn(&mut wait, 100, just_before));
        let first = t0 + STUCK_WAIT_WARN_AFTER;
        assert!(StuckWait::should_warn(&mut wait, 100, first));
        assert!(!StuckWait::should_warn(&mut wait, 100, first + Duration::from_secs(1)));
        let second = first + STUCK_WAIT_WARN_EVERY;
        assert!(!StuckWait::should_warn(&mut wait, 100, second - Duration::from_millis(1)));
        assert!(StuckWait::should_warn(&mut wait, 100, second));
        assert!(!StuckWait::should_warn(&mut wait, 100, second + Duration::from_secs(1)));
    }

    /// Moving to another height ends the wait, warned or not: the new
    /// height gets the full threshold before it can warn.
    #[test]
    fn stuck_wait_restarts_on_a_new_height() {
        let t0 = Instant::now();
        let mut wait = None;
        assert!(!StuckWait::should_warn(&mut wait, 100, t0));
        assert!(StuckWait::should_warn(&mut wait, 100, t0 + Duration::from_secs(30)));
        let moved = t0 + Duration::from_secs(31);
        assert!(!StuckWait::should_warn(&mut wait, 101, moved));
        assert!(!StuckWait::should_warn(&mut wait, 101, moved + Duration::from_secs(5)));
        assert!(StuckWait::should_warn(&mut wait, 101, moved + STUCK_WAIT_WARN_AFTER));
    }

    /// A peer relaying a *policy*-rejected tx (fee floor, dust, mempool limits,
    /// RBF, conflicts, non-standard) must NOT accrue ban score — banning for
    /// these severs honest peers on low-fee networks (the testnet4 wedge). Only
    /// consensus-invalid txs (bad script / outputs-exceed-inputs) are scored.
    #[test]
    fn tx_rejection_ban_score_only_scores_consensus_invalid() {
        // Consensus-invalid → scored.
        assert_eq!(
            PeerManager::tx_rejection_ban_score(&MempoolError::Script("x".into(), None)),
            INVALID_TX_BAN_SCORE
        );
        assert_eq!(
            PeerManager::tx_rejection_ban_score(&MempoolError::BadAmounts),
            INVALID_TX_BAN_SCORE
        );

        // Policy / standardness / resource / RBF / duplicate → no score.
        for e in [
            MempoolError::InsufficientFee(254, 1000),
            MempoolError::Dust,
            MempoolError::MempoolFull,
            MempoolError::AlreadyExists,
            MempoolError::ConflictingSpend,
            MempoolError::NonStandardOpReturn,
            MempoolError::InsufficientReplacementFee(1, 2, String::new(), String::new()),
            MempoolError::TooLongMempoolChain,
            MempoolError::PrematureCoinbaseSpend,
            MempoolError::Validation("nonstandard".into()),
            MempoolError::DecodeFailed,
            MempoolError::MissingInputs,
        ] {
            assert_eq!(
                PeerManager::tx_rejection_ban_score(&e),
                0,
                "policy rejection {e:?} must not be ban-scored"
            );
        }
    }

    fn bh(byte: u8) -> bitcoin::BlockHash {
        use bitcoin::hashes::Hash;
        bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    /// Small catch-ups must keep the WAL: a routine restart's connect run
    /// gains nothing from BulkLoad but inherits its full WAL-less
    /// data-loss exposure (mainnet-952978 regression).
    #[test]
    fn bulkload_reserved_for_large_catchups() {
        assert!(!use_bulkload_for_catchup(0));
        assert!(!use_bulkload_for_catchup(64)); // the 952978 incident size
        assert!(!use_bulkload_for_catchup(BULKLOAD_MIN_BLOCKS_BEHIND - 1));
        assert!(use_bulkload_for_catchup(BULKLOAD_MIN_BLOCKS_BEHIND));
        assert!(use_bulkload_for_catchup(u32::MAX)); // full IBD
    }

    #[test]
    fn historical_block_storable_accepts_canonical_in_range() {
        // At/below the snapshot, only the canonical block for the height
        // may be stored.
        assert!(historical_block_storable(800_000, 500, Some(bh(1)), bh(1)));
    }

    #[test]
    fn historical_block_storable_rejects_noncanonical_side_block() {
        // A valid non-canonical block at a historical height is refused so
        // it cannot overwrite the shared height→hash mapping.
        assert!(!historical_block_storable(800_000, 500, Some(bh(1)), bh(2)));
    }

    #[test]
    fn historical_block_storable_rejects_when_no_canonical_mapping() {
        // No canonical header for the height (cannot happen given the
        // loadtxoutset precondition, but fail safe): refuse rather than
        // poison.
        assert!(!historical_block_storable(800_000, 500, None, bh(2)));
    }

    #[test]
    fn historical_block_storable_allows_forward_range() {
        // Above the snapshot height the block is not part of the fixed
        // historical mapping and is always storable (forward IBD).
        assert!(historical_block_storable(800_000, 800_001, None, bh(9)));
        assert!(historical_block_storable(800_000, 800_001, Some(bh(1)), bh(9)));
    }

    #[test]
    fn historical_block_storable_snapshot_boundary_requires_canonical() {
        // Exactly at the snapshot height the canonical check still applies.
        assert!(historical_block_storable(800_000, 800_000, Some(bh(7)), bh(7)));
        assert!(!historical_block_storable(800_000, 800_000, Some(bh(7)), bh(8)));
    }

    /// Core's rounder: a node in IBD sends 0.09936506 BTC/kvB, the top bucket
    /// (`p2p_ibd_txrelay.py`'s `MAX_FEE_FILTER`), and a floor below the first
    /// bucket rounds to zero, which the caller lifts back to the floor.
    #[test]
    fn fee_filter_rounds_into_cores_buckets() {
        for random in [0, 1, 2] {
            assert_eq!(fee_filter_round(MAX_MONEY_SATS, 100, random), 9_936_506);
        }
        assert_eq!(fee_filter_round(10, 100, 1), 0);
        assert_eq!(fee_filter_round(10, 100, 0), 50);
        assert_eq!(fee_filter_round(50, 100, 0), 50);
    }

    fn mk_handle(id: PeerId, addr: SocketAddr, dir: Direction, state: PeerState) -> PeerHandle {
        let mut info = PeerInfo::new(id, addr, dir);
        info.state = state;
        // 1-slot channel; we never send on the test side.
        let (tx, _rx) = mpsc::channel::<NetworkMessage>(1);
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            last_mempool_served: None,
                    fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        }
    }

    #[test]
    fn count_inbound_classifies_by_direction_and_state() {
        let mut peers = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Inbound + Connected: counts.
        peers.insert(
            1,
            mk_handle(1, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Connected),
        );
        // Outbound + Connected: not counted as inbound.
        peers.insert(
            2,
            mk_handle(2, SocketAddr::new(ip, 8333), Direction::Outbound, PeerState::Connected),
        );
        // Inbound + Connecting (handshake in progress): F4 fix — must
        // count toward the cap, otherwise concurrent handshake bursts
        // from one IP bypass the limit until handshakes complete.
        peers.insert(
            3,
            mk_handle(3, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Connecting),
        );
        // Inbound + Disconnected: stale entry, no real socket, doesn't
        // count.
        peers.insert(
            4,
            mk_handle(4, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Disconnected),
        );
        let (total, same_ip) = PeerManager::count_inbound(&peers, ip);
        assert_eq!(total, 2);
        assert_eq!(same_ip, 2);
    }

    #[test]
    fn count_inbound_caps_against_handshake_burst() {
        // Regression for review F4: a burst of inbound TCP accepts from
        // a single IP must not all squeeze through the per-IP cap
        // while still in handshake. With the old semantics
        // (Connected-only), the entire burst could insert as
        // Connecting and each accept would observe same_ip_count == 0.
        let mut peers = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Simulate four concurrent accepts from the same IP that all
        // landed in Connecting before any handshake completed.
        for id in 1..=4u32 {
            peers.insert(
                id as PeerId,
                mk_handle(
                    id as PeerId,
                    SocketAddr::new(ip, 8333 + id as u16),
                    Direction::Inbound,
                    PeerState::Connecting,
                ),
            );
        }
        let (total, same_ip) = PeerManager::count_inbound(&peers, ip);
        assert_eq!(total, 4, "handshake-in-progress peers must consume slots");
        assert_eq!(same_ip, 4);
    }

    #[test]
    fn count_inbound_groups_by_ip() {
        let mut peers = HashMap::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        for (id, ip) in [(1, ip_a), (2, ip_a), (3, ip_a), (4, ip_b)] {
            peers.insert(
                id,
                mk_handle(
                    id,
                    SocketAddr::new(ip, 8333 + id as u16),
                    Direction::Inbound,
                    PeerState::Connected,
                ),
            );
        }
        let (total_a, same_a) = PeerManager::count_inbound(&peers, ip_a);
        assert_eq!(total_a, 4);
        assert_eq!(same_a, 3);
        let (total_b, same_b) = PeerManager::count_inbound(&peers, ip_b);
        assert_eq!(total_b, 4);
        assert_eq!(same_b, 1);
    }

    #[test]
    fn onion_dial_budget_caps_burst_and_counts_in_flight() {
        // Cold start: every slot open, but the per-tick burst is the ceiling.
        assert_eq!(PeerManager::onion_dial_budget(64, 0, 0), MAX_ONION_DIALS_PER_TICK);
        // In-flight dials count against the budget (outbound_count excludes
        // them) — this is what stops a gossip flood from spawning hundreds of
        // concurrent dials in one tick.
        assert_eq!(PeerManager::onion_dial_budget(8, 2, 6), 0);
        // Open slots below the burst cap return exactly the slot count.
        assert_eq!(PeerManager::onion_dial_budget(8, 5, 0), 3);
        // At or over target → no new dials (saturating).
        assert_eq!(PeerManager::onion_dial_budget(8, 8, 0), 0);
        assert_eq!(PeerManager::onion_dial_budget(8, 10, 0), 0);
    }

    #[test]
    fn onion_connected_in_matches_by_host_not_placeholder_addr() {
        // Onion peers all share the 0.0.0.0 placeholder socket, so dedup must
        // key on the onion host. Two distinct onion peers (same placeholder
        // addr, different hosts) must be told apart; a disconnected peer must
        // not count as connected.
        let placeholder: SocketAddr = "0.0.0.0:8333".parse().unwrap();
        let mut peers = HashMap::new();
        let mk = |id: PeerId, host: &str, state: PeerState| {
            let mut h = mk_handle(id, placeholder, Direction::Outbound, state);
            h.info.onion_host = Some(host.to_string());
            h
        };
        peers.insert(1, mk(1, "aaaa.onion", PeerState::Connected));
        peers.insert(2, mk(2, "bbbb.onion", PeerState::Connecting));
        peers.insert(3, mk(3, "cccc.onion", PeerState::Disconnected));

        assert!(PeerManager::onion_connected_in(&peers, "aaaa.onion"));
        // Mid-handshake (Connecting) still counts — we don't want a second dial.
        assert!(PeerManager::onion_connected_in(&peers, "bbbb.onion"));
        // Disconnected does not count — reconnect must be allowed.
        assert!(!PeerManager::onion_connected_in(&peers, "cccc.onion"));
        // Unknown host: not connected.
        assert!(!PeerManager::onion_connected_in(&peers, "zzzz.onion"));
        // A clearnet peer on the same placeholder addr must not match an onion host.
        peers.insert(
            4,
            mk_handle(4, placeholder, Direction::Outbound, PeerState::Connected),
        );
        assert!(!PeerManager::onion_connected_in(&peers, ""));
    }

    #[test]
    fn pending_connections_guard_releases_on_drop() {
        // Mirrors the RAII pattern inside `connect_outbound`. The guard
        // exists to ensure the pending slot is released even when the
        // dial fails or panics across an await point.
        let set: RwLock<HashSet<SocketAddr>> = RwLock::new(HashSet::new());
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        struct PendingGuard<'a> {
            set: &'a RwLock<HashSet<SocketAddr>>,
            addr: SocketAddr,
        }
        impl<'a> Drop for PendingGuard<'a> {
            fn drop(&mut self) {
                self.set.write().remove(&self.addr);
            }
        }

        {
            set.write().insert(addr);
            assert!(set.read().contains(&addr));
            let _g = PendingGuard { set: &set, addr };
            // ... pretend a dial happens here ...
        }
        assert!(!set.read().contains(&addr), "guard should release slot on drop");
    }

    #[test]
    fn add_learned_addr_dedups() {
        // Pure-Vec test of the dedup idiom used inside add_learned_addr.
        let mut addrs: Vec<SocketAddr> = Vec::new();
        let a: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let b: SocketAddr = "1.2.3.5:8333".parse().unwrap();
        for _ in 0..5 {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
        for _ in 0..3 {
            if !addrs.contains(&b) {
                addrs.push(b);
            }
        }
        assert_eq!(addrs, vec![a, b]);
    }

    /// Like [`mk_handle`] but retains the channel receiver and lets the
    /// caller set a fee filter, so a test can observe what `announce_tx`
    /// enqueues to the peer.
    fn mk_handle_rx(
        id: PeerId,
        addr: SocketAddr,
        state: PeerState,
        fee_filter: u64,
    ) -> (PeerHandle, mpsc::Receiver<NetworkMessage>) {
        let mut info = PeerInfo::new(id, addr, Direction::Outbound);
        info.state = state;
        info.fee_filter = fee_filter;
        let (tx, rx) = mpsc::channel::<NetworkMessage>(8);
        (
            PeerHandle {
                info,
                msg_tx: tx.into(),
                disconnect: Arc::new(tokio::sync::Notify::new()),
                flow: Arc::new(crate::net::flow::PeerFlow::new()),
                last_getheaders_sent: None,
                last_mempool_served: None,
                    fee_filter_sent: None,
                stats: PeerStats::new(NetTotals::new()),
            },
            rx,
        )
    }

    /// `announce_tx` is the local-origin broadcast path shared by the
    /// `sendrawtransaction` RPC and the MCP `send_transaction` tool. It
    /// must enqueue a tx INV to every Connected, fee-permitting peer —
    /// otherwise a locally-submitted tx enters the mempool but never
    /// reaches the wire (the bug behind a signet broadcast that sat
    /// unannounced for hours because the MCP tool skipped this call).
    #[test]
    fn announce_tx_invs_connected_fee_permitting_peers() {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;
        use bitcoin::hashes::Hash;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
            Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm =
            PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        // The tx is absent from the (empty) mempool, so announce_tx treats
        // its fee rate as 0 — only a peer whose fee_filter is also 0 clears it.
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        let (h2, mut rx2) = mk_handle_rx(2, addr, PeerState::Connected, 1000);
        let (h3, mut rx3) = mk_handle_rx(3, addr, PeerState::Connecting, 0);
        {
            let mut peers = pm.peers.write();
            peers.insert(1, h1);
            peers.insert(2, h2);
            peers.insert(3, h3);
        }

        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]));
        pm.announce_tx(txid);

        // Connected + fee-permitting peer gets exactly one tx inv.
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(txid)]);
            }
            other => panic!("connected fee-permitting peer should receive a tx inv, got {other:?}"),
        }
        // Fee filter above the tx rate → skipped.
        assert!(rx2.try_recv().is_err(), "high-fee-filter peer must be skipped");
        // Not yet Connected → skipped.
        assert!(rx3.try_recv().is_err(), "non-Connected peer must be skipped");
    }

    /// A block that fails validation must not, on its own, get the relaying
    /// peer banned or disconnected: an honest peer can forward a block that
    /// does not connect (a stale tip, a reorg race), and banning for that
    /// partitions the network. The normal-mode ingress path holds the peer id
    /// but only forwards to the peer-less block connector, which warns rather
    /// than bans. (A *mutated* block — same hash, different body — is the one
    /// exception and is scored 100 by `reject_if_mutated`; this test uses a
    /// well-formed block so that gate is not engaged.)
    #[test]
    fn an_invalid_block_from_a_peer_does_not_ban_or_drop_the_session() {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;
        use bitcoin::hashes::Hash;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm =
            PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
        assert!(pm.ibd.read().is_none(), "test assumes IBD inactive (normal mode)");

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        pm.peers.write().insert(
            1,
            mk_handle(1, addr, Direction::Outbound, PeerState::Connected),
        );

        // Well-formed block (valid merkle root, no witness-commitment or
        // 64-byte-tx malleation) with an unknown parent: it passes the
        // mutation gate but cannot connect. The regtest genesis block reparented
        // to an unknown hash is exactly such a block.
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.header.prev_blockhash =
            bitcoin::BlockHash::from_byte_array([0x42u8; 32]);

        pm.handle_block(1, block, crate::net::flow::InFlight::new(pm.peer_flow(1)));

        let peers = pm.peers.read();
        let handle = peers.get(&1).expect("peer session must stay up");
        assert_eq!(handle.info.ban_score, 0, "an unconnectable block must not be ban-scored");
    }

    /// A peer that announces headers we cannot connect is not misbehaving.
    /// Core's `HandleUnconnectingHeaders` charges nothing: it sends a
    /// getheaders to fill the gap and keeps the peer as a download source.
    ///
    /// satd charged a point per message, on the theory that an honest peer
    /// sends one and stays far under the threshold. Measured on a 999-block
    /// regtest sync from a peer that was still mining, the exchange reached
    /// 100 points — a ban — in half a second, and the syncing node was left
    /// with no block source at 21 of 551 blocks, permanently.
    #[test]
    fn a_peer_announcing_headers_we_cannot_connect_is_not_banned() {
        let (pm, _dir) = mk_test_pm();
        let addr: SocketAddr = "10.0.0.11:8333".parse().unwrap();
        pm.peers.write().insert(
            1,
            mk_handle(1, addr, Direction::Outbound, PeerState::Connected),
        );

        // A header whose parent we have never seen. Far more of them than the
        // ban threshold would have tolerated at a point apiece.
        use bitcoin::hashes::Hash as _;
        let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
        header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x7au8; 32]);
        for nonce in 0..(BAN_THRESHOLD + 10) {
            header.nonce = nonce;
            pm.handle_headers(1, vec![header]);
        }

        let peers = pm.peers.read();
        let handle = peers.get(&1).expect("the peer session must stay up");
        assert_eq!(
            handle.info.ban_score, 0,
            "an unconnecting header announcement must not be ban-scored"
        );
    }

    /// PR 5: the relay assist paths honor the quarantine scope bits. A
    /// relay-quarantined tx is never INV'd (`announce_tx`/`broadcast_inv`) and
    /// never served via `getdata` (the peer gets `NotFound`), while a tx
    /// quarantined only `on template` still relays normally (design §2.4/§6.1).
    #[test]
    fn assist_paths_skip_relay_quarantined() {
        use crate::chain::state::AssumeValid;
        use crate::mempool::pool::QuarantineScope;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
            Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = PeerManager::new(
            chain_state,
            mempool.clone(),
            fee_estimator,
            Network::Regtest,
            shutdown_rx,
        );

        // fee_rate 0 entries; the peer's fee_filter is 0 so the only thing that
        // can suppress an INV is the relay scope.
        let relay_q = mempool.insert_scoped_for_test(1, 0, QuarantineScope { relay: true, template: false });
        let template_q = mempool.insert_scoped_for_test(2, 0, QuarantineScope { relay: false, template: true });

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        // announce_tx: relay-quarantined → nothing on the wire.
        pm.announce_tx(relay_q);
        assert!(rx1.try_recv().is_err(), "relay-quarantined tx must not be announced");

        // broadcast_inv (peer-relay fan-out): same.
        pm.broadcast_inv(99, relay_q);
        assert!(rx1.try_recv().is_err(), "relay-quarantined tx must not be relayed");

        // getdata: peer asking for it gets NotFound, never the Tx.
        pm.handle_getdata(1, vec![Inventory::WitnessTransaction(relay_q)]);
        match rx1.try_recv() {
            Ok(NetworkMessage::NotFound(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(relay_q)]);
            }
            other => panic!("relay-quarantined getdata must return NotFound, got {other:?}"),
        }

        // Contrast: a tx quarantined only `on template` still relays.
        pm.announce_tx(template_q);
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(template_q)]);
            }
            other => panic!("on-template tx must still be announced, got {other:?}"),
        }
        // And it is served on getdata.
        pm.handle_getdata(1, vec![Inventory::WitnessTransaction(template_q)]);
        match rx1.try_recv() {
            Ok(NetworkMessage::Tx(tx)) => assert_eq!(tx.compute_txid(), template_q),
            other => panic!("on-template tx must be served via getdata, got {other:?}"),
        }
    }

    /// Mine `n` blocks onto the manager's chain and return their hashes in
    /// height order (index 0 = height 1). `tag` goes in the coinbase output
    /// so a re-mine at the same height produces a *different* block.
    fn mine_onto(pm: &Arc<PeerManager>, n: usize, tag: u8) -> Vec<bitcoin::BlockHash> {
        use bitcoin::ScriptBuf;
        let mempool = Mempool::new(1_000_000, 0);
        let mut hashes = Vec::with_capacity(n);
        for _ in 0..n {
            let block = crate::mining::miner::build_block_to_script(
                &pm.chain_state,
                &mempool,
                ScriptBuf::new_op_return([tag]),
                None,
            )
            .expect("mine regtest block");
            pm.chain_state.accept_block(&block).expect("accept block");
            hashes.push(block.block_hash());
        }
        hashes
    }

    fn sent_invs(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<bitcoin::BlockHash> {
        match rx.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => inv
                .into_iter()
                .map(|i| match i {
                    Inventory::Block(h) => h,
                    other => panic!("expected a block inv, got {other:?}"),
                })
                .collect(),
            Ok(other) => panic!("expected an inv, got {other:?}"),
            Err(_) => Vec::new(),
        }
    }

    /// Three separate `getblocks` defects, all in the same loop.
    ///
    /// * An unmatched locator fell back to `unwrap_or(0)` and so announced
    ///   the *genesis* block, which no peer will ever accept as new. Core's
    ///   `FindForkInGlobalIndex` returns genesis as the fork *point* and then
    ///   takes `Next()`, i.e. height 1.
    /// * `hashStop` was pushed and *then* broken on, so the peer was invd the
    ///   one block it explicitly said it already had.
    /// * A locator entry sitting on a stale fork was accepted as a fork point,
    ///   so the reply started at `stale_height + 1` on the *active* chain —
    ///   blocks the peer cannot connect to anything it holds.
    #[tokio::test]
    async fn getblocks_answers_from_cores_fork_point() {
        use bitcoin::BlockHash;
        use bitcoin::hashes::Hash;
        use bitcoin::p2p::message_blockdata::GetBlocksMessage;

        let pm = empty_peer_manager();
        let chain = mine_onto(&pm, 5, 0);
        let genesis = pm.chain_state.get_block_hash_by_height(0).unwrap();

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);
        let no_stop = BlockHash::all_zeros();

        // 1. Nothing in the locator matches: start at height 1, not genesis.
        pm.handle_getblocks(
            1,
            GetBlocksMessage::new(vec![BlockHash::from_byte_array([9u8; 32])], no_stop),
        );
        let invd = sent_invs(&mut rx1);
        assert_eq!(invd, chain, "an unmatched locator starts at height 1");
        assert!(!invd.contains(&genesis), "genesis is never announced");

        // 2. `hashStop` is the block at height 3: the peer gets 1 and 2 and
        //    not the stop block itself.
        pm.handle_getblocks(1, GetBlocksMessage::new(vec![genesis], chain[2]));
        assert_eq!(sent_invs(&mut rx1), chain[..2], "stop hash is not announced");

        // 3. A locator entry on a stale fork is not a fork point. Roll the
        //    chain back and re-mine so `stale` is a known block that is no
        //    longer on the active chain.
        pm.chain_state.invalidate_block(chain[2]).expect("invalidate");
        assert_eq!(pm.chain_state.tip_height(), 2);
        let stale = chain[2];
        pm.chain_state.reconsider_block(stale).expect("reconsider");
        // `reconsider` puts the original chain back; take a block from the
        // *other* side by invalidating the tip and mining a replacement.
        pm.chain_state.invalidate_block(chain[4]).expect("invalidate tip");
        let forked = mine_onto(&pm, 1, 1);
        assert_eq!(pm.chain_state.tip_height(), 5);
        assert_ne!(forked[0], chain[4], "the new height-5 block is a different one");
        assert!(
            pm.chain_state.get_block_index(&chain[4]).is_some(),
            "the displaced block is still in the index"
        );
        let _ = rx1.try_recv();
        // A locator naming only the displaced block must not be honoured as
        // "you are at height 5"; Core falls back to genesis.
        pm.handle_getblocks(1, GetBlocksMessage::new(vec![chain[4]], no_stop));
        let invd = sent_invs(&mut rx1);
        assert_eq!(
            invd.first(),
            Some(&chain[0]),
            "a stale-fork locator entry falls back to genesis, so the reply starts at height 1"
        );
        assert_eq!(invd.len(), 5, "heights 1..=5 of the active chain: {invd:?}");
    }

    /// `getheaders` shared the genesis and stale-fork bugs, and ignored
    /// `hashStop` altogether — answering a request for one header with up to
    /// 2000. Core pushes the stop header and *then* breaks, so the stop block
    /// is included.
    #[tokio::test]
    async fn getheaders_honours_the_stop_hash() {
        use bitcoin::BlockHash;
        use bitcoin::hashes::Hash;
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;

        let pm = empty_peer_manager();
        let chain = mine_onto(&pm, 5, 0);
        let genesis = pm.chain_state.get_block_hash_by_height(0).unwrap();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        let headers_for = |rx: &mut mpsc::Receiver<NetworkMessage>| match rx.try_recv() {
            Ok(NetworkMessage::Headers(hs)) => {
                hs.into_iter().map(|h| h.block_hash()).collect::<Vec<_>>()
            }
            other => panic!("expected headers, got {other:?}"),
        };

        pm.handle_getheaders(1, GetHeadersMessage::new(vec![genesis], chain[1]));
        assert_eq!(
            headers_for(&mut rx1),
            chain[..2],
            "the stop header is the last one sent"
        );

        // An unmatched locator starts at height 1, never at genesis.
        pm.handle_getheaders(
            1,
            GetHeadersMessage::new(
                vec![BlockHash::from_byte_array([9u8; 32])],
                BlockHash::all_zeros(),
            ),
        );
        assert_eq!(headers_for(&mut rx1), chain);
    }

    /// `addnode <peer> remove` cleared the reconnect list but left the
    /// address in `manual_addrs`, so the peer stayed "manual" for the life of
    /// the process: still dialled as a manual connection, and still exempt
    /// from `-connect` gating — which is precisely what that flag is for.
    #[test]
    fn removing_an_added_node_drops_its_manual_status() {
        let pm = empty_peer_manager();
        let sa: SocketAddr = "10.0.0.7:18444".parse().unwrap();
        assert!(pm.addnode_add("10.0.0.7:18444", PeerAddr::Socket(sa)));
        assert!(pm.manual_addrs.read().contains(&sa), "added nodes are manual");

        assert!(pm.addnode_remove(&PeerAddr::Socket(sa)));
        assert!(
            !pm.manual_addrs.read().contains(&sa),
            "a removed added-node is no longer manual"
        );

        // Same for an onion entry, which is tracked in its own set.
        let host = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let onion = PeerAddr::Onion { host: host.to_string(), port: 8333 };
        assert!(pm.addnode_add(&format!("{host}:8333"), onion.clone()));
        assert!(pm.manual_onion_hosts.read().contains(host));
        assert!(pm.addnode_remove(&onion));
        assert!(!pm.manual_onion_hosts.read().contains(host));
    }

    /// Core disconnects a peer that sends an oversized locator; it does not
    /// ban it (`net_processing.cpp` sets `pfrom.fDisconnect = true` and
    /// returns, with no misbehaviour score). satd scored 100 here, which is
    /// `BAN_THRESHOLD`, so the address was banned and the peer's *next*
    /// connection refused -- which is what p2p_invalid_locator.py trips over
    /// when it opens a second connection. Core's functional suite is nightly,
    /// so this is the PR-gated guard.
    #[tokio::test]
    async fn oversized_locator_disconnects_without_banning() {
        use bitcoin::BlockHash;
        use bitcoin::hashes::Hash;
        use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};

        // getheaders and getblocks share the check; both must behave.
        for use_getheaders in [true, false] {
            let pm = empty_peer_manager();
            let addr: SocketAddr = "10.0.0.11:8333".parse().unwrap();
            let handle = mk_handle(11, addr, Direction::Inbound, PeerState::Connected);
            pm.peers.write().insert(11, handle);

            let locator: Vec<BlockHash> = (0..=MAX_LOCATOR_SZ as u32)
                .map(|i| BlockHash::from_byte_array([i as u8; 32]))
                .collect();
            assert!(locator.len() > MAX_LOCATOR_SZ);
            let stop = BlockHash::from_byte_array([0u8; 32]);
            if use_getheaders {
                pm.handle_getheaders(11, GetHeadersMessage::new(locator, stop));
            } else {
                pm.handle_getblocks(11, GetBlocksMessage::new(locator, stop));
            }

            assert!(
                !pm.is_addr_banned(&addr),
                "an oversized locator must disconnect, not ban (getheaders={use_getheaders})"
            );
        }
    }

    /// Round 1 review: every path that removes a peer handle must fire the
    /// handle's disconnect signal, not only `disconnect_by_id`. Dropping the
    /// handle closes the peer task's `msg_rx` only when the *last* sender
    /// goes, and a `getcfilters` stream task can hold a clone -- so without
    /// the signal a banned peer (or every peer, on `setnetworkactive false`
    /// and shutdown, which share `drop_all_peers`) kept its socket open and
    /// kept feeding the node until that task drained. The held `msg_tx`
    /// clone below is that scenario.
    #[tokio::test]
    async fn banning_and_disconnect_all_fire_the_disconnect_signal() {
        let pm = empty_peer_manager();

        // Ban path: crossing BAN_THRESHOLD removes the handle.
        let addr: SocketAddr = "10.0.0.9:8333".parse().unwrap();
        let handle = mk_handle(9, addr, Direction::Outbound, PeerState::Connected);
        let notify = handle.disconnect.clone();
        let _held_sender = handle.msg_tx.clone();
        pm.peers.write().insert(9, handle);
        pm.add_ban_score(9, BAN_THRESHOLD, "test");
        assert!(pm.peers.read().is_empty(), "ban must remove the handle");
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("banning a peer must signal its write loop");

        // Disconnect-all path (`setnetworkactive false`; shutdown shares it).
        let addr2: SocketAddr = "10.0.0.10:8333".parse().unwrap();
        let handle2 = mk_handle(10, addr2, Direction::Outbound, PeerState::Connected);
        let notify2 = handle2.disconnect.clone();
        let _held_sender2 = handle2.msg_tx.clone();
        pm.peers.write().insert(10, handle2);
        pm.set_network_active(false);
        assert!(pm.peers.read().is_empty(), "pause must remove every handle");
        tokio::time::timeout(std::time::Duration::from_secs(1), notify2.notified())
            .await
            .expect("disconnecting all peers must signal each write loop");
    }

    fn empty_peer_manager() -> Arc<PeerManager> {
        empty_peer_manager_stopping_at(None)
    }

    /// [`empty_peer_manager`], with a `-stopatheight` target.
    fn empty_peer_manager_stopping_at(
        stop_at_height: Option<(u32, tokio::sync::watch::Sender<bool>)>,
    ) -> Arc<PeerManager> {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;
        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
            Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        // Leak the TempDir so the blocks dir outlives the manager for the test.
        std::mem::forget(dir);
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        PeerManager::with_config(
            chain_state,
            mempool,
            fee_estimator,
            Network::Regtest,
            shutdown_rx,
            0,
            125,
            DEFAULT_MAX_INBOUND_PER_IP,
            86400,
            None,
            None,
            workers,
            50_000,
            0,
            stop_at_height,
        )
    }

    /// `getaddednodeinfo` reports the added-node list, and Core keeps config
    /// `-addnode` entries and RPC-added ones in the *same* list
    /// (`CConnman::m_added_nodes`). Recording an address without recording the
    /// entry dials the peer but hides it from the RPC, so pin the distinction
    /// here: only `addnode_add` makes a peer an *added node*.
    #[test]
    fn only_addnode_add_registers_an_added_node() {
        let pm = empty_peer_manager();
        assert!(pm.get_added_node_info().is_empty());

        // A dial candidate is not an added node — this is the path
        // `-connect` and `-seednode` addresses take, and they must not show
        // up here.
        let candidate: SocketAddr = "127.0.0.1:18445".parse().unwrap();
        pm.add_peer_addr(PeerAddr::Socket(candidate));
        assert!(
            pm.get_added_node_info().is_empty(),
            "a plain dial candidate must not appear in getaddednodeinfo"
        );

        // Whereas an added node is, and keeps the operator's own spelling of
        // the address rather than the resolved form.
        assert!(pm.addnode_add("localhost:18444", PeerAddr::Socket("127.0.0.1:18444".parse().unwrap())));
        let info = pm.get_added_node_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0]["addednode"], "localhost:18444");
        assert_eq!(info[0]["connected"], false);
    }

    /// Point `pm`'s peer-name lookups at `resolve` instead of the system
    /// resolver.
    fn set_test_resolver(
        pm: &PeerManager,
        resolve: impl Fn(&str) -> Result<PeerAddr, crate::net::dns::PeerTargetError> + Send + Sync + 'static,
    ) {
        *pm.test_resolver.write() = Some(Arc::new(resolve));
    }

    /// Wait up to `within` for one TCP connection on `listener`.
    async fn accepts_within(listener: &TcpListener, within: Duration) -> bool {
        tokio::time::timeout(within, listener.accept()).await.is_ok()
    }

    /// Core's `CConnman::AddNode` stores the string without looking it up,
    /// so a name that does not resolve is still an added node: listed by
    /// `getaddednodeinfo` (not connected, no addresses), refused as a
    /// duplicate, and removable by that same string. satd looked the name up
    /// first and dropped it on failure, so neither the config entry nor the
    /// RPC could record it.
    #[test]
    fn an_added_node_that_does_not_resolve_is_listed_and_removable() {
        let pm = empty_peer_manager();
        assert!(pm.addnode_add_unresolved("tank-0001:18444"));
        assert!(!pm.addnode_add_unresolved("tank-0001:18444"), "the same string is one entry");

        let info = pm.get_added_node_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0]["addednode"], "tank-0001:18444");
        assert_eq!(info[0]["connected"], false);
        assert_eq!(info[0]["addresses"], serde_json::json!([]), "Core lists addresses only when connected");

        assert!(pm.addnode_remove_target("tank-0001:18444", None));
        assert!(pm.get_added_node_info().is_empty());
        assert!(!pm.addnode_remove_target("tank-0001:18444", None));
    }

    /// Two spellings of one numeric address are one added node (Core's
    /// `AddNode` compares `LookupNumeric` results), whereas an address that
    /// is merely a dial candidate -- gossip, `peers.dat` -- is not an added
    /// node and must not make `addnode add` report a duplicate.
    #[test]
    fn added_node_duplicates_are_decided_by_the_added_node_list() {
        let pm = empty_peer_manager();
        let sa: SocketAddr = "10.0.0.9:18444".parse().unwrap();
        pm.add_peer_addr(PeerAddr::Socket(sa));
        assert!(pm.addnode_add("10.0.0.9:18444", PeerAddr::Socket(sa)), "a dial candidate is not an added node");
        assert!(!pm.addnode_add("10.0.0.9", PeerAddr::Socket(sa)), "same numeric address, default port");
        assert_eq!(pm.get_added_node_info().len(), 1);
    }

    /// Startup registers the `-addnode` entries before RPC serves (#876),
    /// with `register_config_addnodes`, which is not async and so cannot
    /// wait on a lookup. Every entry is listed at once: a literal or
    /// `.onion` target with its address to dial, a name unresolved, left
    /// for `refresh_manual_targets`. Only a target that can never resolve is
    /// left out, and a duplicate is neither listed nor dialled twice.
    #[test]
    fn config_addnodes_are_all_listed_before_any_lookup() {
        let pm = empty_peer_manager();
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let dial = pm.register_config_addnodes(&[
            "10.0.0.7".to_string(),
            format!("{onion}:18444"),
            "tank-0000:18444".to_string(),
            format!("{onion}:notaport"),
            "10.0.0.7:18444".to_string(),
        ]);
        assert_eq!(
            dial,
            vec![
                PeerAddr::Socket("10.0.0.7:18444".parse().unwrap()),
                PeerAddr::Onion { host: onion.to_string(), port: 18444 },
            ]
        );
        let listed: Vec<String> = pm
            .get_added_node_info()
            .iter()
            .map(|e| e["addednode"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(listed, ["10.0.0.7".to_string(), format!("{onion}:18444"), "tank-0000:18444".to_string()]);
        assert!(pm.manual_targets_due(Instant::now()), "the name is due its lookup");
    }

    /// `-stopatheight` on the connects that emit no chain event (#873):
    /// nothing below the target, shutdown at it and past it, and nothing at
    /// all when no target is set.
    #[test]
    fn reaching_stop_at_height_asks_for_shutdown() {
        assert!(!empty_peer_manager().stop_if_at_height(u32::MAX), "no target set");

        let (tx, rx) = tokio::sync::watch::channel(false);
        let pm = empty_peer_manager_stopping_at(Some((100, tx)));
        assert!(!pm.stop_if_at_height(99));
        assert!(!*rx.borrow(), "below the target");
        assert!(pm.stop_if_at_height(100));
        assert!(*rx.borrow(), "at the target");
        // A node restarted above its target stops after its next block, as
        // Core's does.
        assert!(pm.stop_if_at_height(101));
    }

    /// The fix proper: a name that does not resolve when it is configured is
    /// looked up again, and dialled as soon as it resolves. A node started
    /// alongside its peers otherwise never connects to them.
    #[tokio::test]
    async fn an_added_node_that_resolves_later_is_dialled() {
        let pm = empty_peer_manager();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let resolvable = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&resolvable);
        set_test_resolver(&pm, move |s| {
            assert_eq!(s, "tank-0000");
            if flag.load(Ordering::SeqCst) {
                Ok(PeerAddr::Socket(target))
            } else {
                Err(crate::net::dns::PeerTargetError::Lookup("no such host yet".into()))
            }
        });
        assert!(pm.addnode_add_unresolved("tank-0000"));

        Arc::clone(&pm).refresh_manual_targets().await;
        assert!(!accepts_within(&listener, Duration::from_millis(300)).await, "nothing to dial yet");
        assert!(pm.manual_targets_due(Instant::now()), "an unresolved name stays due");

        resolvable.store(true, Ordering::SeqCst);
        Arc::clone(&pm).refresh_manual_targets().await;
        assert!(
            accepts_within(&listener, Duration::from_secs(5)).await,
            "the name resolved, so the peer must be dialled"
        );
        assert!(pm.manual_addrs.read().contains(&target), "and dialled as a manual peer");
        // Still the operator's entry, not a second one.
        assert_eq!(pm.get_added_node_info().len(), 1);
    }

    /// A `-connect` name gets the same treatment, and stays out of
    /// `getaddednodeinfo`, which lists added nodes only.
    #[tokio::test]
    async fn a_connect_name_that_resolves_later_is_dialled() {
        let pm = empty_peer_manager();
        pm.set_automatic_outbound(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        set_test_resolver(&pm, move |_| Ok(PeerAddr::Socket(target)));
        assert!(pm.connect_name_add("tank-0002", None));
        assert!(pm.get_added_node_info().is_empty());

        Arc::clone(&pm).refresh_manual_targets().await;
        assert!(accepts_within(&listener, Duration::from_secs(5)).await);
        assert!(pm.may_dial(&target), "a -connect peer stays dialable under -connect");
    }

    /// Startup and a config reload register `-connect` entries through
    /// `register_connect_target` (#879). A name that resolves is dialled
    /// and tracked for a later lookup, one that does not resolve yet is
    /// kept for `refresh_manual_targets` rather than dropped, and one that
    /// can never resolve is refused. None of them is an added node.
    #[tokio::test]
    async fn connect_targets_are_kept_whether_or_not_they_resolve_yet() {
        use crate::net::dns::PeerTargetError;
        let pm = empty_peer_manager();
        let up: SocketAddr = "10.0.0.8:18444".parse().unwrap();
        set_test_resolver(&pm, move |s| match s {
            "tank-0005" => Ok(PeerAddr::Socket(up)),
            "tank-0006" => Err(PeerTargetError::Lookup("no such host yet".into())),
            _ => Err(PeerTargetError::Refused("name lookups are disabled (-dns=0)".into())),
        });

        assert_eq!(pm.register_connect_target("tank-0005").await, Some(PeerAddr::Socket(up)));
        assert!(pm.manual_addrs.read().contains(&up), "dialled as a manual peer");
        assert_eq!(pm.register_connect_target("tank-0006").await, None, "nothing to dial yet");
        assert_eq!(pm.register_connect_target("tank-0007").await, None, "refused");

        let tracked: Vec<(String, bool)> = pm
            .addnode_entries
            .read()
            .iter()
            .map(|e| (e.target.clone(), e.resolved.is_some()))
            .collect();
        assert_eq!(
            tracked,
            [("tank-0005".to_string(), true), ("tank-0006".to_string(), false)],
            "both names are tracked; the refused one is not"
        );
        assert!(pm.manual_targets_due(Instant::now()), "the unresolved name is due its lookup");
        assert!(pm.get_added_node_info().is_empty(), "a -connect entry is not an added node");
    }

    /// A resolved name whose peer is gone is looked up again, and when the
    /// name has moved the old address stops being dialled and the new one
    /// is -- a restarted peer in a container network comes back on a new
    /// address under the same name.
    #[tokio::test]
    async fn a_name_that_moves_is_dialled_at_its_new_address() {
        let pm = empty_peer_manager();
        let old: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let new = listener.local_addr().unwrap();
        set_test_resolver(&pm, move |_| Ok(PeerAddr::Socket(new)));
        assert!(pm.addnode_add("tank-0003", PeerAddr::Socket(old)));

        Arc::clone(&pm).refresh_manual_targets().await;
        assert!(accepts_within(&listener, Duration::from_secs(5)).await);
        assert!(
            !pm.manual_addrs.read().contains(&old),
            "the old address is no longer a manual peer, nor dialled as one"
        );
        assert!(pm.manual_addrs.read().contains(&new));
    }

    /// `addnode <name> remove` while that name's lookup is in flight must
    /// win: the lookup finishing afterwards must not register the peer.
    #[tokio::test]
    async fn a_removed_name_is_not_registered_by_a_late_lookup() {
        let pm = empty_peer_manager();
        let target: SocketAddr = "127.0.0.1:18460".parse().unwrap();
        let weak = Arc::downgrade(&pm);
        set_test_resolver(&pm, move |s| {
            // The lookup is "in flight": the operator removes the node now.
            if let Some(pm) = weak.upgrade() {
                assert!(pm.addnode_remove_target(s, None));
            }
            Ok(PeerAddr::Socket(target))
        });
        assert!(pm.addnode_add_unresolved("tank-0004"));
        Arc::clone(&pm).refresh_manual_targets().await;
        assert!(pm.get_added_node_info().is_empty());
        assert!(!pm.manual_addrs.read().contains(&target));
        assert!(!pm.learned_addrs.read().contains(&target));
    }

    /// An explicitly configured peer must stay dialable under `-connect`
    /// even when its address was already a learned candidate. `peers.dat` is
    /// loaded into `learned_addrs` at startup, ~1400 lines before `-connect`
    /// is applied and the configured peers are registered, so for a node
    /// with an address book this is the *common* case, not the odd one.
    /// When the two were one list, registering the manual marker only on the
    /// newly-added path left `may_dial` refusing the one peer the operator
    /// named: the startup dial still happened, but nothing could retry it.
    #[test]
    fn a_configured_peer_already_in_the_dial_pool_stays_dialable() {
        let pm = empty_peer_manager();
        let addr: SocketAddr = "127.0.0.1:18455".parse().unwrap();

        // As the address book does at startup, before `-connect` is applied.
        pm.add_learned_addr(addr);
        assert!(pm.learned_addrs.read().contains(&addr));
        pm.set_automatic_outbound(false);

        // Then the configured `-connect=<addr>`, finding it already learned:
        // it is still newly a peer the operator named.
        assert!(
            pm.add_peer_addr(PeerAddr::Socket(addr)),
            "being learned does not make an address the operator's"
        );
        assert!(!pm.add_peer_addr(PeerAddr::Socket(addr)), "registering twice is one entry");
        assert!(
            pm.may_dial(&addr),
            "an explicitly configured peer must stay dialable under -connect"
        );
    }

    /// The type of a peer found by the peer's `conn_type` on the handle.
    fn conn_type_at(pm: &PeerManager, addr: SocketAddr) -> Option<ConnType> {
        pm.peers
            .read()
            .values()
            .find(|h| h.info.addr == addr)
            .map(|h| h.info.conn_type)
    }

    /// Only the operator's own lists make a dial `manual` (#866). The
    /// automatic dial list used to count too, and it holds every gossiped
    /// address, so every peer reached through gossip was reported, granted
    /// the outgoing whitelist and slotted as a manual one. An onion peer is
    /// judged by its host: its socket is the placeholder all onion peers
    /// share, which a `-connect=0.0.0.0:<port>` entry would otherwise match.
    #[test]
    fn untyped_dials_are_manual_only_for_the_operators_peers() {
        let pm = empty_peer_manager();
        let learned: SocketAddr = "127.0.0.1:18461".parse().unwrap();
        let named: SocketAddr = "127.0.0.1:18462".parse().unwrap();
        pm.add_learned_addr(learned);
        assert!(pm.learned_addrs.read().contains(&learned));
        pm.add_peer_addr(PeerAddr::Socket(named));
        assert_eq!(pm.untyped_outbound_conn_type(&learned, None), ConnType::OutboundFullRelay);
        assert_eq!(pm.untyped_outbound_conn_type(&named, None), ConnType::Manual);

        let named_host = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let learned_host = "2bqghnldu6mcug4pikzprwhtjjnsyederctvci6klcwzepnjd46ikjyd.onion";
        pm.add_peer_addr(PeerAddr::Onion { host: named_host.to_string(), port: 8333 });
        pm.add_learned_peer_addr(&PeerAddr::Onion { host: learned_host.to_string(), port: 8333 });
        let placeholder: SocketAddr = ([0, 0, 0, 0], 8333).into();
        // An operator entry for the placeholder itself must not reach an
        // onion peer that shares it.
        pm.add_peer_addr(PeerAddr::Socket(placeholder));
        assert_eq!(pm.untyped_outbound_conn_type(&placeholder, Some(named_host)), ConnType::Manual);
        assert_eq!(
            pm.untyped_outbound_conn_type(&placeholder, Some(learned_host)),
            ConnType::OutboundFullRelay
        );
    }

    /// Core consults its outgoing whitelist for manual connections only, so
    /// a learned peer takes none of an `out` entry. A manual onion peer
    /// takes none either: matching its `0.0.0.0` placeholder against an
    /// entry that covers it would grant it the entry.
    #[test]
    fn the_outgoing_whitelist_reaches_manual_clearnet_peers_only() {
        let pm = empty_peer_manager();
        pm.set_whitelist(vec![
            crate::net::permissions::WhitelistEntry::parse("noban,out@0.0.0.0/0").unwrap(),
        ]);
        let peer: SocketAddr = "127.0.0.1:18463".parse().unwrap();
        assert!(pm.outbound_whitelist_permissions(ConnType::Manual, &peer, None).noban);
        assert_eq!(
            pm.outbound_whitelist_permissions(ConnType::OutboundFullRelay, &peer, None),
            crate::net::permissions::NetPermissions::NONE
        );
        let placeholder: SocketAddr = ([0, 0, 0, 0], 8333).into();
        assert_eq!(
            pm.outbound_whitelist_permissions(ConnType::Manual, &placeholder, Some("x.onion")),
            crate::net::permissions::NetPermissions::NONE
        );
    }

    /// `addnode onetry` is a manual connection, typed at its dial. It used
    /// to register the address as manual for the dial and remove it after
    /// only if it was not a dial candidate -- which every gossiped address
    /// was -- so a onetry to a learned address made it manual for good:
    /// reported and whitelisted as one on every later automatic dial, and
    /// dialled even under `-connect`.
    #[tokio::test]
    async fn an_onetry_dial_is_manual_and_registers_nothing() {
        let pm = empty_peer_manager();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        pm.add_learned_addr(target);

        pm.connect_peer_addr(&PeerAddr::Socket(target)).await.expect("the onetry dial connects");
        assert!(accepts_within(&listener, Duration::from_secs(5)).await);
        assert_eq!(conn_type_at(&pm, target), Some(ConnType::Manual), "an onetry dial is manual");
        assert!(!pm.manual_addrs.read().contains(&target), "and leaves no registration behind");
        assert_eq!(pm.untyped_outbound_conn_type(&target, None), ConnType::OutboundFullRelay);
        pm.set_automatic_outbound(false);
        assert!(!pm.may_dial(&target), "a learned address stays undialable under -connect");
    }

    /// A DNS or fixed seed is the node's own bootstrap source, not a peer
    /// the operator named: Core dials it as an automatic connection. It
    /// joins the learned candidates, under the book's rule, and is dialled
    /// as `outbound-full-relay`.
    #[tokio::test]
    async fn a_seed_is_learned_and_dialled_as_outbound_full_relay() {
        let pm = empty_peer_manager();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let seed = listener.local_addr().unwrap();
        pm.add_learned_peer_addr(&PeerAddr::Socket(seed));
        assert!(pm.learned_addrs.read().contains(&seed));
        assert!(!pm.manual_addrs.read().contains(&seed));

        pm.connect_peer_addr_automatic(&PeerAddr::Socket(seed)).await.expect("the seed dial connects");
        assert!(accepts_within(&listener, Duration::from_secs(5)).await);
        assert_eq!(conn_type_at(&pm, seed), Some(ConnType::OutboundFullRelay));

        // Nothing the book refuses, and nothing at all under `-connect`.
        let zero: SocketAddr = ([0, 0, 0, 0], seed.port()).into();
        pm.add_learned_peer_addr(&PeerAddr::Socket(zero));
        assert!(!pm.learned_addrs.read().contains(&zero));
        pm.set_automatic_outbound(false);
        let other: SocketAddr = "127.0.0.1:18464".parse().unwrap();
        pm.add_learned_peer_addr(&PeerAddr::Socket(other));
        assert!(!pm.learned_addrs.read().contains(&other));
    }

    /// Every socket dial refuses an address that names no host, manual or
    /// automatic, as Core's `ConnectNode` does (`src/net.cpp:443`). On Linux
    /// a connect to `0.0.0.0` reaches the local host, so without the check
    /// the listener below takes the dial.
    #[tokio::test]
    async fn an_invalid_address_is_never_dialled() {
        let pm = empty_peer_manager();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let zero: SocketAddr = ([0, 0, 0, 0], port).into();

        assert!(pm.connect_peer_addr(&PeerAddr::Socket(zero)).await.is_err(), "manual");
        assert!(pm.connect_outbound(zero).await.is_err(), "automatic");
        assert!(
            !accepts_within(&listener, Duration::from_millis(500)).await,
            "0.0.0.0 must not be dialled"
        );
        // The same listener does take a dial to an address that names it.
        pm.connect_outbound(listener.local_addr().unwrap()).await.expect("a valid address is dialled");
        assert!(accepts_within(&listener, Duration::from_secs(5)).await);
    }

    /// A real PeerManager over a caller-supplied chain state — spawns the
    /// real block_processor thread. No peers are ever attached, so any
    /// chain progress observed by these tests is self-driven.
    fn peer_manager_over(chain_state: Arc<ChainState>) -> Arc<PeerManager> {
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        // Leak the sender so the channel stays open for the manager's life.
        std::mem::forget(shutdown_tx);
        PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx)
    }

    /// Issue #582, stored-tail half: a connector that tears down leaving
    /// downloaded-but-unconnected blocks on disk must have that tail
    /// drained by the steady-state block processor without any network
    /// event. Nothing else can reach those blocks — the header-driven
    /// scheduler gate needs a gap over 24, `request_missing_blocks` skips
    /// them (data present), and a re-sent copy dies in `accept_block` as
    /// `Duplicate` because the index status is already DataStored.
    #[test]
    fn a_stored_but_unconnected_tail_is_drained_without_a_network_event() {
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, store_block_without_connecting,
        };

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let h1 = cs.accept_block(&b1).expect("connect block 1").hash();
        let b2 = build_test_block(h1, 2, 1_707_000_001);
        let b3 = build_test_block(b2.block_hash(), 3, 1_707_000_002);
        // Exactly what a torn-down IBD scheduler leaves behind: headers
        // accepted (height rows exist), block data stored, tip parked below.
        let (accepted, err) = cs.accept_headers(&[b2.header, b3.header]);
        assert_eq!(accepted, 2, "fixture: headers must be accepted ({err:?})");
        store_block_without_connecting(&cs, &b2, 2);
        store_block_without_connecting(&cs, &b3, 3);
        assert_eq!(cs.tip_height(), 1, "fixture: the tail must start unconnected");
        assert_eq!(
            cs.next_block_to_connect(2),
            Some(b2.block_hash()),
            "fixture: the frontier must name the stored block"
        );
        assert!(cs.has_block_data(&b2.block_hash()), "fixture: data must be stored");

        // Gap of 2 is far under the +24 scheduler-creation threshold, so
        // only the steady-state drain can connect these.
        let chain_state = Arc::new(cs);
        let _pm = peer_manager_over(chain_state.clone());

        let deadline = Instant::now() + Duration::from_secs(10);
        while chain_state.tip_height() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            chain_state.tip_height(),
            3,
            "the stored tail must connect without a network event"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Accept the headers of `n` test blocks on regtest genesis and, when
    /// `store` is set, store their data, connecting none of them.
    fn headers_ahead_of_the_tip(cs: &ChainState, n: u32, store: bool) {
        use crate::chain::state::tests::{build_test_block, store_block_without_connecting};
        let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut blocks = Vec::new();
        for h in 1..=n {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            blocks.push(b);
        }
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, n, "fixture: headers must be accepted ({err:?})");
        if store {
            for (b, h) in blocks.iter().zip(1..) {
                store_block_without_connecting(cs, b, h);
            }
        }
    }

    /// A real PeerManager over `chain_state`, with the sender of its
    /// shutdown watch, initially `shutdown`.
    fn peer_manager_with_shutdown(
        chain_state: Arc<ChainState>,
        shutdown: bool,
    ) -> (Arc<PeerManager>, tokio::sync::watch::Sender<bool>) {
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(shutdown);
        let pm =
            PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
        (pm, shutdown_tx)
    }

    /// #868: once shutdown is signalled the IBD connect loop connects
    /// nothing more and its thread exits, so the tip the shutdown flush
    /// writes, and the clean-shutdown marker records, is the tip the node
    /// stops at. The loop had no shutdown path: it went on connecting after
    /// the marker was written, and was inside RocksDB when the process
    /// exited.
    ///
    /// Thirty blocks are stored above the tip and their headers put the node
    /// more than 24 behind, so the manager starts in IBD, with shutdown
    /// already signalled.
    ///
    /// Perturbations: without the check at the top of the IBD connect loop
    /// all thirty connect; without the one at the top of the block
    /// processor's loop it re-enters the IBD loop forever and the join
    /// times out.
    #[test]
    fn the_ibd_connector_connects_nothing_after_shutdown_and_exits() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        headers_ahead_of_the_tip(&cs, 30, true);
        let chain_state = Arc::new(cs);
        let (pm, _shutdown_tx) = peer_manager_with_shutdown(chain_state.clone(), true);
        assert!(pm.ibd.read().is_some(), "fixture: the manager must start in IBD");

        assert!(
            pm.join_connectors(Duration::from_secs(10)),
            "the connector threads must exit on shutdown"
        );
        assert_eq!(
            chain_state.tip_height(),
            0,
            "no block may connect once shutdown is signalled"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #868: shutdown ends the IBD connector's wait for block data. The
    /// reproduction crashed with the connector parked there, waiting on a
    /// block no peer was sending, minutes after the clean-shutdown marker.
    ///
    /// Perturbation: without the check at the top of the IBD connect loop,
    /// the loop never exits and the join times out.
    #[test]
    fn shutdown_ends_the_ibd_connectors_wait_for_block_data() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        headers_ahead_of_the_tip(&cs, 30, false);
        let chain_state = Arc::new(cs);
        let (pm, shutdown_tx) = peer_manager_with_shutdown(chain_state.clone(), false);
        assert!(pm.ibd.read().is_some(), "fixture: the manager must start in IBD");
        // Let the connector reach its wait for block 1.
        std::thread::sleep(Duration::from_millis(200));

        shutdown_tx.send_replace(true);
        assert!(
            pm.join_connectors(Duration::from_secs(10)),
            "the connector threads must exit on shutdown"
        );
        assert_eq!(chain_state.tip_height(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #868: shutdown also ends the IBD connector's compaction backpressure
    /// pause, which otherwise waits up to 60 s and then connects a block
    /// anyway.
    ///
    /// The store reports an L0 file count at the pause threshold, so the
    /// connector pauses before its first block, with thirty stored and ready.
    ///
    /// Perturbation: drop the check in the backpressure wait and the join
    /// times out while the wait runs its 60 s.
    #[test]
    fn shutdown_ends_the_ibd_connectors_backpressure_pause() {
        let store = crate::storage::test_store::ControllableStore::new();
        store.controls().set_chainstate_l0_files(8);
        let (cs, dir) = crate::chain::state::tests::make_chain_state_with_store(Box::new(store));
        headers_ahead_of_the_tip(&cs, 30, true);
        let chain_state = Arc::new(cs);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = PeerManager::with_config(
            chain_state.clone(),
            Arc::new(Mempool::new(1_000_000, 0)),
            Arc::new(FeeEstimator::new()),
            Network::Regtest,
            shutdown_rx,
            0,
            125,
            DEFAULT_MAX_INBOUND_PER_IP,
            86400,
            None,
            None,
            1,
            50_000,
            8,
            None,
        );
        assert!(pm.ibd.read().is_some(), "fixture: the manager must start in IBD");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(chain_state.tip_height(), 0, "fixture: the connector must be paused");

        shutdown_tx.send_replace(true);
        assert!(
            pm.join_connectors(Duration::from_secs(10)),
            "the connector threads must exit on shutdown"
        );
        assert_eq!(chain_state.tip_height(), 0, "no block may connect once shutdown is signalled");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #873: `-stopatheight` stops the IBD connector at the target. Its
    /// connects emit no chain event, so the watcher in `main`, which heard
    /// of nothing else, never saw them, and IBD ran straight past it.
    ///
    /// Thirty blocks are stored and ready, as on a restart that finds a
    /// downloaded tail: the manager arms IBD as it is built, and the
    /// connector connects from the moment its thread starts. The target is
    /// therefore fixed by the constructor, before that thread exists.
    ///
    /// Perturbations: without the check after each connect, all thirty
    /// connect and nothing asks for shutdown; stopping only past the target
    /// leaves the tip at 11; a target set only after the threads start is
    /// missed while the connector runs ahead of it.
    #[test]
    fn the_ibd_connector_stops_at_stop_at_height() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        headers_ahead_of_the_tip(&cs, 30, true);
        let chain_state = Arc::new(cs);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = PeerManager::with_config(
            chain_state.clone(),
            Arc::new(Mempool::new(1_000_000, 0)),
            Arc::new(FeeEstimator::new()),
            Network::Regtest,
            shutdown_rx,
            0,
            125,
            DEFAULT_MAX_INBOUND_PER_IP,
            86400,
            None,
            None,
            1,
            50_000,
            0,
            Some((10, shutdown_tx.clone())),
        );

        assert!(
            pm.join_connectors(Duration::from_secs(20)),
            "the connector must stop once it reaches the target"
        );
        assert!(*shutdown_tx.borrow(), "reaching the target asks for shutdown");
        assert_eq!(chain_state.tip_height(), 10, "the connector stops at the target, not past it");
        // Checked last: an IBD that stops for shutdown keeps its scheduler,
        // one that runs to the end clears it.
        assert!(
            pm.ibd.read().is_some(),
            "fixture: the blocks must come through the IBD connector, stopped short of its end"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #868: the IBD connector stops for shutdown without waiting for a
    /// prefetch worker that is still busy. One transaction's scripts can
    /// take a worker tens of seconds, and waiting for it held the connector,
    /// and with it the shutdown flush, past its deadline.
    ///
    /// Block 1's data is never stored, so the connector waits for it and
    /// never reads a coin; block 2 is stored and spends a coin whose read
    /// parks, so the prefetch worker that takes it is held inside the read.
    ///
    /// Perturbation: stop the pipeline with `stop` on shutdown too, and the
    /// join times out waiting for the parked worker.
    #[test]
    fn the_ibd_connector_does_not_wait_for_a_busy_prefetch_worker() {
        use crate::chain::state::tests::{
            build_test_block, build_test_block_spending, make_chain_state_with_store,
            store_block_without_connecting,
        };
        use bitcoin::hashes::Hash as _;
        let store = crate::storage::test_store::ControllableStore::new();
        let controls = store.controls();
        let (cs, dir) = make_chain_state_with_store(Box::new(store));

        let gated = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x68; 32]),
            vout: 0,
        };
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_001);
        let b2 = build_test_block_spending(b1.block_hash(), 2, 1_707_000_002, gated);
        let mut blocks = vec![b1, b2];
        for h in 3..=30u32 {
            let parent = blocks.last().unwrap().block_hash();
            blocks.push(build_test_block(parent, h, 1_707_000_000 + h));
        }
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 30, "fixture: headers must be accepted ({err:?})");
        for (b, h) in blocks.iter().zip(1..).skip(1) {
            store_block_without_connecting(&cs, b, h);
        }
        let gate = controls.arm_coin_gate(gated);

        let chain_state = Arc::new(cs);
        let (pm, shutdown_tx) = peer_manager_with_shutdown(chain_state.clone(), false);
        assert!(pm.ibd.read().is_some(), "fixture: the manager must start in IBD");
        gate.wait_entered();

        shutdown_tx.send_replace(true);
        let stopped = pm.join_connectors(Duration::from_secs(10));
        gate.release();
        assert!(stopped, "the connector must not wait for the parked prefetch worker");
        assert_eq!(chain_state.tip_height(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Outside IBD the block processor serves the block channel; it stops
    /// on shutdown too.
    ///
    /// Perturbation: without the check at the top of the block processor's
    /// loop, it never exits and the join times out.
    #[test]
    fn the_steady_state_block_processor_exits_on_shutdown() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        let (pm, shutdown_tx) = peer_manager_with_shutdown(Arc::new(cs), false);
        assert!(pm.ibd.read().is_none(), "fixture: the manager must not be in IBD");
        std::thread::sleep(Duration::from_millis(100));

        shutdown_tx.send_replace(true);
        assert!(
            pm.join_connectors(Duration::from_secs(10)),
            "the connector threads must exit on shutdown"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A join that runs out of time keeps the threads it could not join, so
    /// a later call can still wait for them rather than report them gone.
    #[test]
    fn join_connectors_keeps_the_threads_it_could_not_join() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        let (pm, shutdown_tx) = peer_manager_with_shutdown(Arc::new(cs), false);

        assert!(
            !pm.join_connectors(Duration::from_millis(200)),
            "without a shutdown signal the connectors keep running"
        );
        assert_eq!(pm.connector_threads.lock().len(), 2, "both threads must be kept");

        shutdown_tx.send_replace(true);
        assert!(pm.join_connectors(Duration::from_secs(10)));
        assert!(pm.connector_threads.lock().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #582, re-arm half: a node holding headers more than 24 past
    /// its tip with no live scheduler must re-create one from the run
    /// loop's periodic fallback. Before the fix, scheduler creation ran
    /// only inside `handle_headers`, so this state — reachable when the
    /// connector tears down after a late headers batch, or exits via the
    /// fork-blocked handoff — parked until a peer volunteered the *next*
    /// headers announcement, an unbounded wait on a slow chain. No peers
    /// exist in this test, so only the poll path can arm it.
    #[tokio::test]
    async fn the_run_loop_re_arms_ibd_without_an_inbound_headers_message() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};

        let (cs, dir) = make_chain_state();
        let chain_state = Arc::new(cs);
        // Constructed at tip == headers tip, so the startup resume path
        // arms nothing — the parked state is created after construction.
        let pm = peer_manager_over(chain_state.clone());
        assert!(pm.ibd.read().is_none(), "fixture: no scheduler at construction");

        let mut headers = Vec::new();
        let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        for h in 1..=30u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
        }
        let (accepted, err) = chain_state.accept_headers(&headers);
        assert_eq!(accepted, 30, "fixture: headers must be accepted ({err:?})");
        assert!(pm.ibd.read().is_none(), "fixture: accepting headers directly must not arm");

        let pm_run = pm.clone();
        let run = tokio::spawn(async move { pm_run.run().await });

        let deadline = Instant::now() + Duration::from_secs(10);
        while pm.ibd.read().is_none() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let target = pm.ibd.read().as_ref().map(|s| s.target_height());
        run.abort();
        assert_eq!(
            target,
            Some(30),
            "the fallback tick must re-create the scheduler for the known headers tip"
        );
        // Tear the leaked machinery down: scheduler-cleared is a documented
        // ibd_connect_loop exit path, and taking it also stops the
        // prefetch dispatcher the loop spawned — otherwise both poll for
        // the life of the test binary.
        *pm.ibd.write() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mainnet stall reached through out-of-order delivery rather than a
    /// torn-down scheduler: block N+2 arrives before N+1 — ordinary at the
    /// tip. `accept_block` stores N+2 and waits, since its parent has no
    /// data. (It used to try to activate the branch, find N+1 missing and
    /// abort the reorg, #739.) Nothing queues N+2 for another attempt:
    /// `request_missing_blocks` skips it forever after (data present)
    /// and a re-sent copy dies in `accept_block` as `Duplicate`. When
    /// N+1 then arrives and connects, only the steady-state drain can
    /// pick N+2 back up. On a build without the drain, a synced mainnet
    /// node was observed parked two blocks behind its headers tip for 21
    /// minutes, in total silence, with 40+ peers connected.
    #[test]
    fn a_block_stored_ahead_of_its_parent_connects_once_the_parent_arrives() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let h1 = cs.accept_block(&b1).expect("connect block 1").hash();
        let b2 = build_test_block(h1, 2, 1_707_000_001);
        let b3 = build_test_block(b2.block_hash(), 3, 1_707_000_002);
        // Headers for both are already known, as on the stalled node
        // (`getblockheader` answered with confirmations -1 throughout).
        let (accepted, err) = cs.accept_headers(&[b2.header, b3.header]);
        assert_eq!(accepted, 2, "fixture: headers must be accepted ({err:?})");

        // N+2 first. The side-chain branch stores it, and with N+1's data
        // missing there is no chain to activate yet.
        let r = cs.accept_block(&b3);
        assert!(
            matches!(r, Ok(crate::chain::state::BlockAcceptance::Stored(_))),
            "N+2 must be stored and wait for N+1: {r:?}"
        );
        assert_eq!(cs.tip_height(), 1, "the tip must not move");
        assert_eq!(cs.reorg_abort_count(), 0, "no reorg may be attempted");
        assert!(
            cs.has_block_data(&b3.block_hash()),
            "the waiting block's data must be stored"
        );

        // N+1 arrives moments later and extends the tip normally.
        cs.accept_block(&b2).expect("N+1 extends the tip");
        assert_eq!(cs.tip_height(), 2);

        // No further network events: only the block processor's stored-tail
        // drain can finish the job.
        let chain_state = Arc::new(cs);
        let _pm = peer_manager_over(chain_state.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        while chain_state.tip_height() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            chain_state.tip_height(),
            3,
            "the drain must connect the waiting block without a network event"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Block 1 connected; block 2 stored above the tip with its record gone,
    /// as #852's prune left it; headers known through `headers_tip`.
    fn a_chain_whose_next_block_has_no_record(
        headers_tip: u32,
    ) -> (Arc<ChainState>, bitcoin::Block, std::path::PathBuf) {
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, roll_append_file, store_block_without_connecting,
        };
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let mut parent = cs.accept_block(&b1).expect("connect block 1").hash();
        let mut blocks = Vec::new();
        for h in 2..=headers_tip {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            blocks.push(b);
        }
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted as usize, headers.len(), "fixture: headers accepted ({err:?})");
        let b2 = blocks.swap_remove(0);
        store_block_without_connecting(&cs, &b2, 2);
        roll_append_file(&cs);
        std::fs::remove_file(cs.blocks_dir().join("blk00000.dat")).unwrap();
        assert!(cs.has_block_data(&b2.block_hash()), "fixture: the index says stored");
        assert!(!cs.block_data_readable(&b2.block_hash()), "fixture: the record is gone");
        (Arc::new(cs), b2, dir)
    }

    /// A connected peer advertising NODE_NETWORK and NODE_WITNESS; what the
    /// node sends it comes back on the receiver.
    fn attach_block_serving_peer(pm: &PeerManager, id: PeerId) -> mpsc::Receiver<NetworkMessage> {
        let addr: SocketAddr = "10.0.0.7:8333".parse().unwrap();
        let (mut handle, rx) = mk_handle_rx(id, addr, PeerState::Connected, 0);
        handle.info.services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        pm.peers.write().insert(id, handle);
        rx
    }

    /// How many `getdata` requests for `hash` arrive within `within`.
    fn count_getdata(
        rx: &mut mpsc::Receiver<NetworkMessage>,
        hash: bitcoin::BlockHash,
        within: Duration,
        stop_at_first: bool,
    ) -> usize {
        let deadline = Instant::now() + within;
        let mut seen = 0;
        while Instant::now() < deadline {
            match rx.try_recv() {
                Ok(NetworkMessage::GetData(inv))
                    if inv.iter().any(|i| {
                        matches!(i, Inventory::WitnessBlock(h) | Inventory::Block(h) if *h == hash)
                    }) =>
                {
                    seen += 1;
                    if stop_at_first {
                        return seen;
                    }
                }
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        seen
    }

    fn tip_reaches(cs: &ChainState, height: u32, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while cs.tip_height() < height && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        cs.tip_height() >= height
    }

    /// #852: the IBD connector's next block was stored, but pruning had
    /// deleted its file. The index says the data is here, so the scheduler
    /// never asks for it again and a re-sent copy dies as `Duplicate`; the
    /// connector retried the read for 30 hours. It now asks a peer for the
    /// block on the repair route and connects the copy.
    ///
    /// Headers run 29 past the tip, so the node starts in the IBD connector
    /// and the steady-state drain (which has its own re-fetch) never runs.
    ///
    /// Perturbation: drop the re-fetch from `ibd_connect_loop`'s error arm and
    /// no `getdata` for block 2 is sent.
    #[test]
    fn the_ibd_connector_fetches_again_a_stored_block_it_cannot_read() {
        let (cs, b2, dir) = a_chain_whose_next_block_has_no_record(30);
        let pm = peer_manager_over(cs.clone());
        assert!(pm.ibd.read().is_some(), "fixture: the node starts in IBD");
        let mut rx = attach_block_serving_peer(&pm, 7);

        assert_eq!(
            count_getdata(&mut rx, b2.block_hash(), Duration::from_secs(15), true),
            1,
            "the connector must ask a peer for block 2"
        );
        pm.handle_message(7, NetworkMessage::Block(b2.clone()), crate::net::flow::InFlight::new(None));
        assert!(
            tip_reaches(&cs, 2, Duration::from_secs(10)),
            "block 2 must connect from the repaired record"
        );

        *pm.ibd.write() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same hole one block above the tip of a synced node: the
    /// steady-state drain reads the block before connecting it, and on a
    /// missing record it stopped for that wakeup, every wakeup.
    ///
    /// Perturbation: drop the re-fetch from `connect_stored_tail` and no
    /// `getdata` for block 2 is sent.
    #[test]
    fn the_stored_tail_drain_fetches_again_a_stored_block_it_cannot_read() {
        let (cs, b2, dir) = a_chain_whose_next_block_has_no_record(2);
        let pm = peer_manager_over(cs.clone());
        assert!(pm.ibd.read().is_none(), "fixture: a one-block gap is the drain's");
        let mut rx = attach_block_serving_peer(&pm, 7);

        assert_eq!(
            count_getdata(&mut rx, b2.block_hash(), Duration::from_secs(15), true),
            1,
            "the drain must ask a peer for block 2"
        );
        pm.handle_message(7, NetworkMessage::Block(b2.clone()), crate::net::flow::InFlight::new(None));
        assert!(
            tip_reaches(&cs, 2, Duration::from_secs(10)),
            "block 2 must connect from the repaired record"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The IBD connector retries once a second and the drain wakes every
    /// 500 ms; without a floor each attempt would be another request.
    ///
    /// Perturbation: drop the `UNREADABLE_REFETCH_INTERVAL` check and the
    /// second call sends a second `getdata`.
    #[test]
    fn a_stored_block_is_fetched_again_at_most_once_per_interval() {
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        let pm = peer_manager_over(Arc::new(cs));
        let mut rx = attach_block_serving_peer(&pm, 7);
        use bitcoin::hashes::Hash as _;
        let hash = bitcoin::BlockHash::from_byte_array([7u8; 32]);

        pm.refetch_unreadable_block(hash, 5);
        pm.refetch_unreadable_block(hash, 5);
        assert_eq!(count_getdata(&mut rx, hash, Duration::from_millis(500), false), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A re-fetch whose `getdata` could not be sent still counts toward the
    /// interval. The repair registration is dropped on a failed send, so a
    /// floor read from it let the IBD connector's once-a-second retries each
    /// make a fresh attempt, and log it, against a saturated or failing peer.
    ///
    /// Perturbation: record the attempt only once the request is sent and the
    /// second call asks the working peer at once.
    #[test]
    fn a_refetch_that_fails_to_send_still_waits_out_the_interval() {
        use bitcoin::hashes::Hash as _;
        let (cs, dir) = crate::chain::state::tests::make_chain_state();
        let pm = peer_manager_over(Arc::new(cs));
        let hash = bitcoin::BlockHash::from_byte_array([7u8; 32]);

        // A peer whose receiver is gone: the send fails.
        drop(attach_block_serving_peer(&pm, 7));
        pm.refetch_unreadable_block(hash, 5);

        // A peer that would answer, well inside the interval.
        let mut rx = attach_block_serving_peer(&pm, 7);
        pm.refetch_unreadable_block(hash, 5);
        assert_eq!(count_getdata(&mut rx, hash, Duration::from_millis(500), false), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The connector asks a different peer each interval, so several can be
    /// asked for one block. Any of them may answer first, and each reply is as
    /// good as the others: the copy is authenticated against the header either
    /// way. A registration held only by the latest peer dropped an earlier
    /// one's reply to the ordinary route, where it died as `Duplicate`. A peer
    /// nobody asked still gets the ordinary route, so it cannot consume a
    /// request an operator made of a peer they chose.
    ///
    /// Perturbations: keep only the latest peer's registration and peer 7's
    /// reply repairs nothing; match the registration on the hash alone and
    /// peer 9's unsolicited copy repairs it.
    #[test]
    fn a_reply_from_any_peer_asked_repairs_a_block_and_no_other_does() {
        use crate::chain::state::tests::{build_test_block, make_chain_state, roll_append_file};
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let h1 = cs.accept_block(&b1).expect("connect block 1").hash();
        let b2 = build_test_block(h1, 2, 1_707_000_001);
        let h2 = cs.accept_block(&b2).expect("connect block 2").hash();
        roll_append_file(&cs);
        let b3 = build_test_block(h2, 3, 1_707_000_002);
        cs.accept_block(&b3).expect("connect block 3");
        // Block 2 is connected and its record is gone: a hole below the tip,
        // which no connector will touch.
        std::fs::remove_file(cs.blocks_dir().join("blk00000.dat")).unwrap();
        assert!(!cs.block_data_readable(&h2), "fixture: block 2 has no record");

        let cs = Arc::new(cs);
        let pm = peer_manager_over(cs.clone());
        let _rx7 = attach_block_serving_peer(&pm, 7);
        let _rx8 = attach_block_serving_peer(&pm, 8);
        let _rx9 = attach_block_serving_peer(&pm, 9);
        pm.request_block_from_peer(h2, 7).expect("ask peer 7");
        pm.request_block_from_peer(h2, 8).expect("then peer 8");

        pm.handle_message(9, NetworkMessage::Block(b2.clone()), crate::net::flow::InFlight::new(None));
        assert!(!cs.block_data_readable(&h2), "peer 9 was not asked");

        pm.handle_message(7, NetworkMessage::Block(b2.clone()), crate::net::flow::InFlight::new(None));
        assert!(cs.block_data_readable(&h2), "peer 7 was asked, before peer 8");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The drain must return to its caller after a bounded batch. The
    /// block processor is single-threaded: while the drain walks, it
    /// cannot notice a newly-armed scheduler, service the block channel,
    /// or observe shutdown — and a fork-blocked handoff can strand a tail
    /// up to `maxahead` (default 50,000) blocks that becomes connectable
    /// all at once after the reorg. Anything longer than the cap
    /// coincides with a headers gap over 24, which the run loop's poll
    /// hands to the IBD connect loop and its flush/backpressure rails.
    #[test]
    fn the_stored_tail_drain_is_capped_per_wakeup() {
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, store_block_without_connecting,
        };

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let mut parent = cs.accept_block(&b1).expect("connect block 1").hash();
        let mut headers = Vec::new();
        let mut tail = Vec::new();
        for h in 2..=31u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
            tail.push((b, h));
        }
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 30, "fixture: headers must be accepted ({err:?})");
        for (b, h) in &tail {
            store_block_without_connecting(&cs, b, *h);
        }
        assert_eq!(cs.tip_height(), 1, "fixture: 30-block tail stored, none connected");

        let chain_state = Arc::new(cs);
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = FeeEstimator::new();
        let orphanage = Arc::new(TxOrphanage::with_defaults());

        let first = PeerManager::connect_stored_tail(
            &chain_state,
            &fee_estimator,
            &mempool,
            &orphanage,
            &std::sync::Weak::new(),
        );
        assert_eq!(first, 24, "one wakeup must connect exactly the cap");
        assert_eq!(chain_state.tip_height(), 25, "tip must stop at the cap boundary");

        let second = PeerManager::connect_stored_tail(
            &chain_state,
            &fee_estimator,
            &mempool,
            &orphanage,
            &std::sync::Weak::new(),
        );
        assert_eq!(second, 6, "the next wakeup must finish the remainder");
        assert_eq!(chain_state.tip_height(), 31, "the whole tail must connect across wakeups");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #873: the stored-tail drain stops at `-stopatheight` and asks for
    /// shutdown itself, rather than leaving it to the watcher that hears its
    /// chain events after the walk has moved on. The manager only holds the
    /// target; the drain walks its own chain state.
    ///
    /// Perturbation: without the check, the walk connects all nine.
    #[test]
    fn the_stored_tail_drain_stops_at_stop_at_height() {
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, store_block_without_connecting,
        };

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let mut parent = cs.accept_block(&b1).expect("connect block 1").hash();
        let mut headers = Vec::new();
        let mut tail = Vec::new();
        for h in 2..=10u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
            tail.push((b, h));
        }
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 9, "fixture: headers must be accepted ({err:?})");
        for (b, h) in &tail {
            store_block_without_connecting(&cs, b, *h);
        }
        let chain_state = Arc::new(cs);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = empty_peer_manager_stopping_at(Some((5, shutdown_tx)));
        let connected = PeerManager::connect_stored_tail(
            &chain_state,
            &FeeEstimator::new(),
            &Arc::new(Mempool::new(1_000_000, 0)),
            &Arc::new(TxOrphanage::with_defaults()),
            &Arc::downgrade(&pm),
        );
        assert_eq!(connected, 4);
        assert_eq!(chain_state.tip_height(), 5, "the drain stops at the target");
        assert!(*shutdown_rx.borrow(), "and asks for shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #900: every block the stored-tail drain connects is reported with one
    /// `BlockConnected`, in order, as `accept_block` reports its connects.
    /// `-blocknotify`, block announcement, Electrum, Esplora SSE, streaming
    /// and ZMQ subscribers hear of new blocks only through that event.
    ///
    /// Perturbation: drop the emit from `connect_stored_tail` and no event
    /// arrives.
    #[test]
    fn the_stored_tail_drain_reports_each_block_it_connects() {
        use crate::chain::events::ChainEvent;
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, store_block_without_connecting,
        };

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let mut parent = cs.accept_block(&b1).expect("connect block 1").hash();
        let mut headers = Vec::new();
        let mut tail = Vec::new();
        for h in 2..=4u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
            tail.push((b, h));
        }
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 3, "fixture: headers must be accepted ({err:?})");
        for (b, h) in &tail {
            store_block_without_connecting(&cs, b, *h);
        }
        let (tx, mut rx) = tokio::sync::broadcast::channel::<ChainEvent>(16);
        cs.set_chain_event_sender(tx);
        let chain_state = Arc::new(cs);

        let connected = PeerManager::connect_stored_tail(
            &chain_state,
            &FeeEstimator::new(),
            &Arc::new(Mempool::new(1_000_000, 0)),
            &Arc::new(TxOrphanage::with_defaults()),
            &std::sync::Weak::new(),
        );
        assert_eq!(connected, 3);
        assert_eq!(chain_state.tip_height(), 4);

        let events: Vec<ChainEvent> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let expected: Vec<(bitcoin::BlockHash, u32)> =
            tail.iter().map(|(b, h)| (b.block_hash(), *h)).collect();
        let got: Vec<(bitcoin::BlockHash, u32)> = events
            .iter()
            .filter_map(|e| match e {
                ChainEvent::BlockConnected { hash, height } => Some((*hash, *height)),
                _ => None,
            })
            .collect();
        assert_eq!(got, expected, "one BlockConnected per drained block, in order: {events:?}");
        assert_eq!(events.len(), expected.len(), "and nothing else: {events:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every other connect at the tip reports its block before it releases
    /// `accept_lock`, which is what keeps events in connect order. A drain
    /// that released the lock first would let a `submitblock` of the child
    /// connect and report in between, so subscribers heard of the child
    /// before its parent. The test holds the event sender, so the drain's
    /// emit blocks, and checks that the drain still holds the lock there.
    #[test]
    fn the_stored_tail_drain_reports_a_block_before_releasing_the_accept_lock() {
        use crate::chain::events::ChainEvent;
        use crate::chain::state::tests::{
            build_test_block, make_chain_state, store_block_without_connecting,
        };

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let parent = cs.accept_block(&b1).expect("connect block 1").hash();
        let b2 = build_test_block(parent, 2, 1_707_000_002);
        let (accepted, err) = cs.accept_headers(&[b2.header]);
        assert_eq!(accepted, 1, "fixture: header must be accepted ({err:?})");
        store_block_without_connecting(&cs, &b2, 2);
        let (tx, mut rx) = tokio::sync::broadcast::channel::<ChainEvent>(16);
        cs.set_chain_event_sender(tx);
        let chain_state = Arc::new(cs);

        let connected = std::thread::scope(|scope| {
            // Inside the scope, so a failed assertion drops it and lets the
            // drain finish before the scope joins it.
            let sender = chain_state.hold_chain_event_sender_for_test();
            let drain = scope.spawn(|| {
                PeerManager::connect_stored_tail(
                    &chain_state,
                    &FeeEstimator::new(),
                    &Arc::new(Mempool::new(1_000_000, 0)),
                    &Arc::new(TxOrphanage::with_defaults()),
                    &std::sync::Weak::new(),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            while chain_state.tip_height() < 2 {
                assert!(Instant::now() < deadline, "the drain never connected block 2");
                std::thread::sleep(Duration::from_millis(1));
            }
            // The tip moves under the lock, so from here the drain either
            // still holds it, waiting on the sender, or has let it go.
            let watch_until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < watch_until {
                assert!(
                    chain_state.accept_lock_is_held_for_test(),
                    "the drain released accept_lock before reporting block 2"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(sender);
            drain.join().expect("drain thread")
        });
        assert_eq!(connected, 1);
        match rx.try_recv() {
            Ok(ChainEvent::BlockConnected { hash, height }) => {
                assert_eq!((hash, height), (b2.block_hash(), 2));
            }
            other => panic!("expected BlockConnected for block 2, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The re-arm gate must refuse to (re)create a scheduler while the
    /// connect frontier is fork-blocked — the linear connector cannot
    /// reorg, so arming it there re-wedges on `bad-prevblk`, and with the
    /// gate now polled every ~5s a regression means continuous
    /// teardown↔re-create oscillation that starves the reorg-capable
    /// steady-state path, not a once-per-headers-batch mistake.
    #[test]
    fn a_fork_blocked_frontier_never_re_arms_ibd() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};

        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        // Chain A: one connected block — the tip.
        let a1 = build_test_block(genesis, 1, 1_707_000_000);
        cs.accept_block(&a1).expect("connect chain A block 1");
        // Construct at tip == headers tip so the startup resume path
        // (which deliberately does not check the frontier) arms nothing.
        let chain_state = Arc::new(cs);
        let pm = peer_manager_over(chain_state.clone());
        assert!(pm.ibd.read().is_none(), "fixture: no scheduler at construction");

        // Chain B: a 30-header competing branch forking at genesis. More
        // work than A, so it becomes the best header chain and owns the
        // height rows — but block 2's parent is B's block 1, not the tip:
        // the frontier is fork-blocked until the reorg path moves the tip.
        let mut headers = Vec::new();
        let mut parent = genesis;
        for h in 1..=30u32 {
            let b = build_test_block(parent, h, 1_707_100_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
        }
        let (accepted, err) = chain_state.accept_headers(&headers);
        assert_eq!(accepted, 30, "fixture: fork headers must be accepted ({err:?})");
        assert!(
            !chain_state.frontier_connects_to_tip(),
            "fixture: the frontier must actually be fork-blocked"
        );
        assert!(
            chain_state.headers_tip_height() > chain_state.tip_height() + 24,
            "fixture: the gap alone must pass the creation threshold"
        );
        assert!(
            !pm.maybe_start_ibd(),
            "a fork-blocked frontier must not arm the linear IBD scheduler"
        );
        assert!(pm.ibd.read().is_none(), "no scheduler may exist afterwards");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A headers batch arriving while a scheduler is live must extend it,
    /// not replace it. Two guards are load-bearing in the refactored
    /// control flow: `maybe_start_ibd`'s is-some re-entry check (without
    /// it every mid-IBD batch clobbers the live scheduler, losing its
    /// in-flight assignments) and `handle_headers`' extension arm
    /// (without it a late batch strands the new headers' blocks — the
    /// wedge documented at the call site). In-flight state surviving with
    /// the raised target proves extension; a fresh scheduler would carry
    /// the target but empty assignments.
    #[test]
    fn a_headers_batch_extends_a_live_scheduler_instead_of_replacing_it() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};

        let (cs, dir) = make_chain_state();
        let chain_state = Arc::new(cs);
        let pm = peer_manager_over(chain_state.clone());

        let mut headers = Vec::new();
        let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut all_blocks = Vec::new();
        for h in 1..=60u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = b.block_hash();
            headers.push(b.header);
            all_blocks.push(b);
        }
        let (accepted, err) = chain_state.accept_headers(&headers[..30]);
        assert_eq!(accepted, 30, "fixture: first batch must be accepted ({err:?})");
        assert!(pm.maybe_start_ibd(), "fixture: the first batch must arm a scheduler");

        // Give the live scheduler observable state a replacement would lose.
        let assigned = {
            let mut ibd = pm.ibd.write();
            let sched = ibd.as_mut().expect("scheduler just armed");
            assert_eq!(sched.target_height(), 30);
            sched.register_peer(1);
            sched.assign_blocks(1)
        };
        assert!(!assigned.is_empty(), "fixture: peer 1 must hold assignments");

        // Second batch through the real headers handler (no peer 7 exists;
        // outbound sends are best-effort no-ops).
        pm.handle_headers(7, headers[30..].to_vec());

        let (target, inflight) = {
            let ibd = pm.ibd.read();
            let sched = ibd.as_ref().expect("scheduler must still exist");
            (sched.target_height(), sched.peer_inflight_count(1))
        };
        assert_eq!(target, 60, "the live scheduler must extend to the new headers tip");
        assert_eq!(
            inflight,
            assigned.len(),
            "in-flight assignments must survive — a fresh scheduler here means \
             the batch replaced the live one instead of extending it"
        );
        *pm.ibd.write() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn nth_txid(n: u32) -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(b))
    }

    /// PR 6b: the promotion queue dedups on enqueue and drains at most
    /// `PROMOTION_DRAIN_PER_TICK` per tick (token-bucket cap, §8).
    #[test]
    fn promotion_queue_dedups_and_drains_bounded() {
        let pm = empty_peer_manager();

        // Dedup: b appears in both batches but is queued once.
        pm.enqueue_promotions([nth_txid(1), nth_txid(2)]);
        pm.enqueue_promotions([nth_txid(2), nth_txid(3)]);
        assert_eq!(pm.promotion_queue_len(), 3, "duplicate enqueue is deduped");

        // Bounded drain: fill past one tick's cap and confirm only the cap drains.
        let pm = empty_peer_manager();
        let total = PROMOTION_DRAIN_PER_TICK + 5;
        pm.enqueue_promotions((0..total as u32).map(nth_txid));
        assert_eq!(pm.promotion_queue_len(), total);

        let drained = pm.drain_promotion_queue();
        assert_eq!(drained, PROMOTION_DRAIN_PER_TICK, "one tick drains the cap");
        assert_eq!(pm.promotion_queue_len(), 5, "the overflow waits for the next tick");

        let drained = pm.drain_promotion_queue();
        assert_eq!(drained, 5);
        assert_eq!(pm.promotion_queue_len(), 0);
        assert_eq!(pm.drain_promotion_queue(), 0, "empty queue drains nothing");
    }

    /// PR 6b: draining the queue re-announces each promoted tx to fee-permitting
    /// peers (the bounded counterpart of `announce_tx`).
    #[test]
    fn promotion_drain_announces_to_peers() {
        let pm = empty_peer_manager();
        // An acting tx in the mempool (fee_rate 0).
        let txid = pm
            .mempool
            .insert_scoped_for_test(1, 0, crate::mempool::pool::QuarantineScope::acting());

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        pm.enqueue_promotions([txid]);
        assert_eq!(pm.drain_promotion_queue(), 1);
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(txid)]);
            }
            other => panic!("promoted tx must be announced on drain, got {other:?}"),
        }
    }

    /// `submit_and_announce` — the shared core behind the Esplora / Electrum
    /// broadcast surfaces — must NOT announce a tx the mempool rejects.
    /// (The accepted-and-announced path is covered by the mechanism test
    /// above plus the surface integration tests.)
    #[test]
    fn submit_and_announce_does_not_announce_rejected_tx() {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;
        use bitcoin::hashes::Hash;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, absolute::LockTime,
            transaction,
        };

        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
            Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm =
            PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        // A tx spending a non-existent output → rejected (missing inputs).
        let tx = bitcoin::Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([9u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };

        assert!(
            pm.submit_and_announce(tx, crate::mempool::pool::TxSource::Rpc, false).is_err(),
            "tx with missing inputs must be rejected"
        );
        assert!(rx1.try_recv().is_err(), "a rejected tx must not be announced to peers");
    }

    /// Resubmitting a tx that is already in the mempool must succeed and
    /// re-announce it (Core's `BroadcastTransaction` semantics) — wallets
    /// resubmit to force re-relay of a stuck tx, and the tx may have entered
    /// the mempool from a peer rather than a local submit.
    #[test]
    fn submit_and_announce_resubmit_of_mempool_tx_succeeds_and_announces() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (pm, _dir) = mk_test_pm();

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        // Seed the mempool with the tx (as if it arrived via P2P relay),
        // keyed by its real computed txid so the resubmit collides. The tx
        // must clear the context-free + standardness checks (non-empty
        // in/out, standard non-dust output) so the accept path reaches the
        // already-in-mempool check; its input doesn't resolve, but
        // `AlreadyExists` is detected before input lookup — same order as
        // Core (CheckTransaction → standardness → mempool dedup → inputs).
        let tx = bitcoin::Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [0x42u8; 20],
                )),
            }],
        };
        let txid = tx.compute_txid();
        pm.mempool.insert_entry_for_test(txid, tx.clone(), 0);

        let result = pm.submit_and_announce(tx, crate::mempool::pool::TxSource::Rpc, false);
        assert_eq!(result.ok(), Some(txid), "resubmit of a mempool tx must succeed");
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(txid)]);
            }
            other => panic!("resubmit must re-announce the tx, got {other:?}"),
        }
    }

    /// Resubmitting the same txid with another witness succeeds too, and
    /// re-announces the witness the pool holds, as Core's
    /// `BroadcastTransaction` does: a wtxid relay peer is offered the
    /// resident wtxid, never the submitted one, which the node cannot serve.
    #[test]
    fn a_resubmit_with_another_witness_reannounces_the_resident_one() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let (mut h1, mut rx1) = mk_handle_rx(1, "10.0.0.1:8333".parse().unwrap(), PeerState::Connected, 0);
        h1.info.wtxid_relay = true;
        pm.peers.write().insert(1, h1);

        let mut resident = witness_tx(4, 0xaa);
        resident.output[0].script_pubkey =
            bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x42u8; 20]));
        let mut other = resident.clone();
        other.input[0].witness = bitcoin::Witness::from_slice(&[vec![0xbbu8]]);
        let txid = resident.compute_txid();
        assert_eq!(other.compute_txid(), txid, "fixture: same txid");
        pm.mempool.insert_entry_for_test(txid, resident.clone(), 0);

        let result = pm.submit_and_announce(other, crate::mempool::pool::TxSource::Rpc, false);
        assert_eq!(result.ok(), Some(txid), "a resubmit with another witness must succeed");
        expect_inv(&mut rx1, &[Inventory::WTx(resident.compute_wtxid())], "the resident witness");
        assert!(pm.mempool.is_unbroadcast(&txid), "and it is rebroadcast like any resubmit");
    }

    /// Minimal regtest `PeerManager` for the rebroadcast / echo tests.
    fn mk_test_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Regtest,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
                4,
                Default::default(),
                Default::default(),
            Default::default(),
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
        (pm, dir)
    }

    /// The periodic rebroadcast pass re-announces every unbroadcast local tx
    /// to fee-permitting peers; a peer fetching it via `getdata` is the
    /// primary signal that clears it from the set.
    #[test]
    fn rebroadcast_reannounces_then_getdata_clears() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        pm.set_rebroadcast_config(0, 1); // auto interval, 1-peer confirm

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        pm.rebroadcast_unbroadcast_txs();
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(txid)]);
            }
            other => panic!("rebroadcast should re-announce the unbroadcast tx, got {other:?}"),
        }
        assert!(pm.mempool.is_unbroadcast(&txid));

        // The peer fetches it via getdata → we serve the tx AND record the
        // peer as a propagation witness, clearing it at threshold 1.
        pm.handle_getdata(1, vec![Inventory::WitnessTransaction(txid)]);
        // (The synthetic test entry's real txid differs from its map key, so
        // assert we served a Tx rather than recomputing the id.)
        match rx1.try_recv() {
            Ok(NetworkMessage::Tx(_)) => {}
            other => panic!("getdata should be served the tx, got {other:?}"),
        }
        assert!(
            !pm.mempool.is_unbroadcast(&txid),
            "a peer fetching the tx via getdata clears the unbroadcast set at threshold 1"
        );
    }

    /// A peer announcing the tx back via `inv` is also accepted as a
    /// (secondary) propagation witness. Witnesses are keyed by the peer's
    /// IP, so the peer must be resolvable in the peers map.
    #[test]
    fn inv_echo_also_confirms_propagation() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        pm.set_rebroadcast_config(0, 1);
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let addr: SocketAddr = "10.0.0.2:8333".parse().unwrap();
        let (h2, _rx2) = mk_handle_rx(2, addr, PeerState::Connected, 0);
        pm.peers.write().insert(2, h2);

        // An inbound inv for a tx we already hold, from a peer, counts as a witness.
        pm.handle_inv(2, vec![Inventory::WitnessTransaction(txid)]);
        assert!(!pm.mempool.is_unbroadcast(&txid), "inv echo at threshold 1 clears the set");
    }

    /// Reconnecting from the same host must not stack witnesses: a fresh
    /// peer id with the same IP is still one witness, so a single host
    /// cannot satisfy `broadcastconfirmpeers > 1` by cycling connections.
    #[test]
    fn same_ip_reconnect_is_one_witness() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        pm.set_rebroadcast_config(0, 2); // require two distinct witnesses
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([8u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let addr: SocketAddr = "10.0.0.3:8333".parse().unwrap();
        let (h5, _rx5) = mk_handle_rx(5, addr, PeerState::Connected, 0);
        let (h6, _rx6) = mk_handle_rx(6, addr, PeerState::Connected, 0); // same IP, new id
        {
            let mut peers = pm.peers.write();
            peers.insert(5, h5);
            peers.insert(6, h6);
        }
        pm.handle_inv(5, vec![Inventory::WitnessTransaction(txid)]);
        pm.handle_inv(6, vec![Inventory::WitnessTransaction(txid)]);
        assert!(
            pm.mempool.is_unbroadcast(&txid),
            "two connections from one IP are a single witness"
        );

        let addr2: SocketAddr = "10.0.0.4:8333".parse().unwrap();
        let (h7, _rx7) = mk_handle_rx(7, addr2, PeerState::Connected, 0);
        pm.peers.write().insert(7, h7);
        pm.handle_inv(7, vec![Inventory::WitnessTransaction(txid)]);
        assert!(
            !pm.mempool.is_unbroadcast(&txid),
            "a second distinct IP crosses the threshold"
        );
    }

    /// On new-peer-connect we re-announce pending local txs to that peer, so a
    /// tx submitted while we had no peers reaches the network on connect. A
    /// peer still mid-handshake (not Connected) is skipped.
    #[test]
    fn announce_unbroadcast_to_new_peer_respects_state() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([4u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        let (h2, mut rx2) = mk_handle_rx(2, addr, PeerState::Connecting, 0);
        {
            let mut peers = pm.peers.write();
            peers.insert(1, h1);
            peers.insert(2, h2);
        }

        pm.announce_unbroadcast_to_peer(1);
        match rx1.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessTransaction(txid)]);
            }
            other => panic!("connected peer should receive the unbroadcast inv, got {other:?}"),
        }

        pm.announce_unbroadcast_to_peer(2);
        assert!(rx2.try_recv().is_err(), "a not-yet-Connected peer must be skipped");
    }

    /// The on-connect re-announce is outbound-only: an unsolicited inv of
    /// exactly our pending local txs to a peer that connected *to us* would
    /// let a sybil enumerate our wallet's txs just by connecting. Inbound
    /// peers still hear about the tx on the periodic rebroadcast timer.
    #[test]
    fn announce_unbroadcast_skips_inbound_peers() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([5u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let addr: SocketAddr = "10.0.0.9:8333".parse().unwrap();
        let mut info = PeerInfo::new(9, addr, Direction::Inbound);
        info.state = PeerState::Connected;
        let (tx, mut rx) = mpsc::channel::<NetworkMessage>(8);
        pm.peers.write().insert(
            9,
            PeerHandle {
                info,
                msg_tx: tx.into(),
                disconnect: Arc::new(tokio::sync::Notify::new()),
                flow: Arc::new(crate::net::flow::PeerFlow::new()),
                last_getheaders_sent: None,
                last_mempool_served: None,
                    fee_filter_sent: None,
                stats: PeerStats::new(NetTotals::new()),
            },
        );

        pm.announce_unbroadcast_to_peer(9);
        assert!(
            rx.try_recv().is_err(),
            "inbound peers must not receive the on-connect unbroadcast dump"
        );
    }

    /// BIP35 `mempool` is served only to peers with the `mempool` permission
    /// (satd doesn't advertise NODE_BLOOM), and the response is an inv of
    /// the mempool txids.
    #[test]
    fn bip35_mempool_served_only_with_permission() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([5u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        // No mempool permission → request ignored.
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);
        pm.handle_mempool_request(1);
        assert!(rx1.try_recv().is_err(), "peer without mempool permission gets no dump");

        // With the mempool permission → inv of the mempool txid.
        let (mut h2, mut rx2) = mk_handle_rx(2, addr, PeerState::Connected, 0);
        h2.info.permissions.mempool = true;
        pm.peers.write().insert(2, h2);
        pm.handle_mempool_request(2);
        match rx2.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => {
                assert!(
                    inv.contains(&Inventory::WitnessTransaction(txid)),
                    "mempool inv should list the resident tx"
                );
            }
            other => panic!("permissioned peer should receive a mempool inv, got {other:?}"),
        }
    }

    /// A BIP35 mempool response honors the requesting peer's fee filter.
    /// Core's `MaybeSendFeefilter` advertises `m_mempool.GetMinFee()`, not the
    /// static relay floor. A pool that has evicted its way to a higher minimum
    /// has to say so, or peers keep offering transactions it is about to
    /// refuse — and the periodic send is also the call that keeps the rolling
    /// minimum's decay clock moving on a node nobody submits to.
    #[test]
    fn the_fee_filter_advertises_the_rolling_minimum() {
        let (pm, _dir) = mk_test_pm();
        let addr: SocketAddr = "10.0.0.9:8333".parse().unwrap();
        let (h, _rx) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h);

        // Leave IBD: the tip has to be recent, or every filter is the maximum
        // and the mempool's minimum never reaches this code.
        let tip = pm.chain_state.tip_hash();
        let block = crate::chain::state::tests::build_test_block(
            tip,
            1,
            crate::time::now_secs() as u32,
        );
        pm.chain_state.accept_block(&block).expect("block connects");
        assert!(
            !pm.chain_state.is_initial_block_download(),
            "in IBD every filter is the maximum and this proves nothing"
        );

        let idle = pm.fee_filter_for(1).expect("a tx-relay peer is sent a filter");

        // An eviction raises the rolling minimum well past the static floor.
        pm.mempool.raise_rolling_min_for_test(200_000);
        let raised = pm.fee_filter_for(1).expect("a tx-relay peer is sent a filter");
        assert!(
            raised > idle,
            "the filter ignored the rolling minimum ({idle} -> {raised})"
        );
    }

    #[test]
    fn bip35_mempool_respects_fee_filter() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let addr: SocketAddr = "10.0.0.2:8333".parse().unwrap();
        // Entry at fee rate 0; peer's filter is 1000 sat/kvB → excluded.
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([6u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let (mut h, mut rx) = mk_handle_rx(1, addr, PeerState::Connected, 1000);
        h.info.permissions.mempool = true;
        pm.peers.write().insert(1, h);
        pm.handle_mempool_request(1);
        assert!(rx.try_recv().is_err(), "a tx below the peer's fee filter is not advertised");
    }

    /// Repeated `mempool` requests from the same peer inside the cooldown
    /// window are ignored — each dump is a full mempool scan plus large
    /// queued invs, and the permission grant is not a license to loop.
    #[test]
    fn bip35_mempool_requests_are_rate_limited_per_peer() {
        use bitcoin::hashes::Hash;
        let (pm, _dir) = mk_test_pm();
        let addr: SocketAddr = "10.0.0.3:8333".parse().unwrap();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]));
        pm.mempool.insert_unbroadcast_for_test(txid, 0);

        let (mut h, mut rx) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        h.info.permissions.mempool = true;
        pm.peers.write().insert(1, h);

        pm.handle_mempool_request(1);
        assert!(
            matches!(rx.try_recv(), Ok(NetworkMessage::Inv(_))),
            "first request is served"
        );
        pm.handle_mempool_request(1);
        assert!(
            rx.try_recv().is_err(),
            "an immediate second request falls inside the cooldown and is ignored"
        );
    }

    /// A transaction with a witness, so its wtxid is not its txid. Two calls
    /// that differ only in `witness_byte` give the same txid.
    fn witness_tx(seed: u8, witness_byte: u8) -> bitcoin::Transaction {
        use bitcoin::hashes::Hash;
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(&[vec![witness_byte]]),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new_op_return([seed]),
            }],
        }
    }

    fn expect_inv(rx: &mut mpsc::Receiver<NetworkMessage>, want: &[Inventory], path: &str) {
        match rx.try_recv() {
            Ok(NetworkMessage::Inv(inv)) => assert_eq!(inv, want, "{path}"),
            other => panic!("{path}: expected an inv, got {other:?}"),
        }
    }

    fn expect_getdata(rx: &mut mpsc::Receiver<NetworkMessage>, want: &[Inventory], what: &str) {
        match rx.try_recv() {
            Ok(NetworkMessage::GetData(inv)) => assert_eq!(inv, want, "{what}"),
            other => panic!("{what}: expected a getdata, got {other:?}"),
        }
    }

    /// BIP 339: every path that announces a transaction gives a peer that
    /// negotiated wtxid relay `MSG_WTX` with the wtxid, and every other peer
    /// the txid -- peer relay, a local broadcast, the rebroadcast pass, the
    /// on-connect announcement and a BIP 35 `mempool` reply.
    #[test]
    fn every_announcement_is_by_wtxid_to_a_wtxid_relay_peer_and_by_txid_to_the_rest() {
        let (pm, _dir) = mk_test_pm();
        pm.set_rebroadcast_config(0, 99);
        let tx = witness_tx(1, 0xaa);
        let txid = pm
            .mempool
            .insert_tx_scoped_for_test(tx.clone(), crate::mempool::pool::QuarantineScope::acting());
        let by_wtxid = [Inventory::WTx(tx.compute_wtxid())];
        let by_txid = [Inventory::WitnessTransaction(txid)];

        let (mut h1, mut rx1) = mk_handle_rx(1, "10.0.0.1:8333".parse().unwrap(), PeerState::Connected, 0);
        h1.info.wtxid_relay = true;
        h1.info.permissions.mempool = true;
        let (mut h2, mut rx2) = mk_handle_rx(2, "10.0.0.2:8333".parse().unwrap(), PeerState::Connected, 0);
        h2.info.permissions.mempool = true;
        {
            let mut peers = pm.peers.write();
            peers.insert(1, h1);
            peers.insert(2, h2);
        }

        pm.announce_tx(txid);
        expect_inv(&mut rx1, &by_wtxid, "local broadcast to the wtxid relay peer");
        expect_inv(&mut rx2, &by_txid, "local broadcast to the other peer");

        pm.broadcast_inv(99, txid);
        expect_inv(&mut rx1, &by_wtxid, "peer relay to the wtxid relay peer");
        expect_inv(&mut rx2, &by_txid, "peer relay to the other peer");

        pm.mempool.mark_unbroadcast(txid);
        pm.rebroadcast_unbroadcast_txs();
        expect_inv(&mut rx1, &by_wtxid, "rebroadcast to the wtxid relay peer");
        expect_inv(&mut rx2, &by_txid, "rebroadcast to the other peer");

        pm.announce_unbroadcast_to_peer(1);
        expect_inv(&mut rx1, &by_wtxid, "on-connect announcement to the wtxid relay peer");
        pm.announce_unbroadcast_to_peer(2);
        expect_inv(&mut rx2, &by_txid, "on-connect announcement to the other peer");

        pm.handle_mempool_request(1);
        expect_inv(&mut rx1, &by_wtxid, "mempool reply to the wtxid relay peer");
        pm.handle_mempool_request(2);
        expect_inv(&mut rx2, &by_txid, "mempool reply to the other peer");

        assert!(rx1.try_recv().is_err() && rx2.try_recv().is_err(), "one announcement per path");
    }

    /// BIP 339: a `getdata` for `MSG_WTX` is served by wtxid. The same txid
    /// with another witness is not what was asked for, nor is a txid read as
    /// a wtxid, and a relay-quarantined tx is not served at all. Serving a
    /// pending local tx counts as propagation, as a fetch by txid does.
    #[test]
    fn a_getdata_by_wtxid_serves_exactly_that_transaction() {
        use crate::mempool::pool::QuarantineScope;
        let (pm, _dir) = mk_test_pm();
        pm.set_rebroadcast_config(0, 1);
        let tx = witness_tx(1, 0xaa);
        let txid = pm.mempool.insert_tx_scoped_for_test(tx.clone(), QuarantineScope::acting());
        pm.mempool.mark_unbroadcast(txid);
        let quarantined = witness_tx(2, 0xaa);
        pm.mempool
            .insert_tx_scoped_for_test(quarantined.clone(), QuarantineScope { relay: true, template: false });

        let (mut h1, mut rx1) = mk_handle_rx(1, "10.0.0.1:8333".parse().unwrap(), PeerState::Connected, 0);
        h1.info.wtxid_relay = true;
        pm.peers.write().insert(1, h1);

        pm.handle_getdata(1, vec![Inventory::WTx(tx.compute_wtxid())]);
        match rx1.try_recv() {
            Ok(NetworkMessage::Tx(served)) => assert_eq!(served.compute_wtxid(), tx.compute_wtxid()),
            other => panic!("a getdata by wtxid must be served the tx, got {other:?}"),
        }
        assert!(
            !pm.mempool.is_unbroadcast(&txid),
            "a peer fetching the local tx by wtxid is a propagation witness"
        );

        let other_witness = Inventory::WTx(witness_tx(1, 0xbb).compute_wtxid());
        let txid_as_wtxid = Inventory::WTx(bitcoin::Wtxid::from_raw_hash(txid.to_raw_hash()));
        let withheld = Inventory::WTx(quarantined.compute_wtxid());
        pm.handle_getdata(1, vec![other_witness, txid_as_wtxid, withheld]);
        match rx1.try_recv() {
            Ok(NetworkMessage::NotFound(inv)) => {
                assert_eq!(inv, vec![other_witness, txid_as_wtxid, withheld]);
            }
            other => panic!("none of these is servable, got {other:?}"),
        }
        assert!(rx1.try_recv().is_err());
    }

    /// BIP 339 on the receive side, as Core's `INV` handler takes it. On a
    /// wtxid relay link `MSG_WTX` is fetched by wtxid and `MSG_TX` ignored;
    /// on any other link `MSG_WTX` is ignored. The ignored kind is dropped
    /// before the blocks-only check, so it costs a block-relay-only peer
    /// nothing, and a `MSG_WTX` for a resident tx is a propagation witness
    /// rather than a fetch.
    #[test]
    fn an_inv_is_taken_only_in_the_form_the_link_negotiated() {
        use crate::mempool::pool::QuarantineScope;
        let (pm, _dir) = mk_test_pm();
        let tip = pm.chain_state.tip_hash();
        let block =
            crate::chain::state::tests::build_test_block(tip, 1, crate::time::now_secs() as u32);
        pm.chain_state.accept_block(&block).expect("block connects");
        assert!(!pm.is_ibd(), "no transaction is fetched in IBD, and this would prove nothing");
        pm.set_rebroadcast_config(0, 1);

        let resident = witness_tx(1, 0xaa);
        let resident_txid = pm.mempool.insert_tx_scoped_for_test(resident.clone(), QuarantineScope::acting());
        pm.mempool.mark_unbroadcast(resident_txid);
        let new = witness_tx(2, 0xaa);
        let (new_txid, new_wtxid) = (new.compute_txid(), new.compute_wtxid());

        let (mut h1, mut rx1) = mk_handle_rx(1, "10.0.0.1:8333".parse().unwrap(), PeerState::Connected, 0);
        h1.info.wtxid_relay = true;
        let (h2, mut rx2) = mk_handle_rx(2, "10.0.0.2:8333".parse().unwrap(), PeerState::Connected, 0);
        let (mut h3, mut rx3) = mk_handle_rx(3, "10.0.0.3:8333".parse().unwrap(), PeerState::Connected, 0);
        h3.info.conn_type = ConnType::BlockRelay;
        let (mut h4, _rx4) = mk_handle_rx(4, "10.0.0.4:8333".parse().unwrap(), PeerState::Connected, 0);
        h4.info.conn_type = ConnType::BlockRelay;
        h4.info.wtxid_relay = true;
        {
            let mut peers = pm.peers.write();
            peers.insert(1, h1);
            peers.insert(2, h2);
            peers.insert(3, h3);
            peers.insert(4, h4);
        }

        pm.handle_inv(1, vec![Inventory::Transaction(new_txid), Inventory::WTx(new_wtxid)]);
        expect_getdata(&mut rx1, &[Inventory::WTx(new_wtxid)], "a wtxid relay peer's MSG_WTX, not its MSG_TX");
        // Core skips only `MSG_TX` on a wtxid link; `MSG_WITNESS_TX` is a
        // getdata type that nothing announces, and passes.
        pm.handle_inv(1, vec![Inventory::WitnessTransaction(new_txid)]);
        expect_getdata(&mut rx1, &[Inventory::WitnessTransaction(new_txid)], "MSG_WITNESS_TX");

        pm.handle_inv(2, vec![Inventory::WTx(new_wtxid), Inventory::Transaction(new_txid)]);
        expect_getdata(&mut rx2, &[Inventory::WitnessTransaction(new_txid)], "the other peer's MSG_TX only");

        pm.handle_inv(3, vec![Inventory::WTx(new_wtxid)]);
        assert!(rx3.try_recv().is_err());
        assert!(
            pm.peers.read().contains_key(&3),
            "a MSG_WTX the link did not negotiate is ignored, not a protocol violation"
        );
        pm.handle_inv(4, vec![Inventory::WTx(new_wtxid)]);
        assert!(
            !pm.peers.read().contains_key(&4),
            "a negotiated tx inv on a block-relay-only link is a protocol violation"
        );

        pm.handle_inv(1, vec![Inventory::WTx(resident.compute_wtxid())]);
        assert!(rx1.try_recv().is_err(), "a resident tx is not fetched again");
        assert!(
            !pm.mempool.is_unbroadcast(&resident_txid),
            "a wtxid relay peer announcing the local tx back is a propagation witness"
        );
    }

    /// Core disconnects a peer that sends `wtxidrelay` after its verack: the
    /// two ends would otherwise disagree on how transactions are announced.
    #[test]
    fn a_wtxidrelay_after_verack_disconnects() {
        let (pm, _dir) = mk_test_pm();
        let (h1, _rx1) = mk_handle_rx(1, "10.0.0.1:8333".parse().unwrap(), PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);
        pm.handle_message(1, NetworkMessage::WtxidRelay, crate::net::flow::InFlight::new(None));
        assert!(!pm.peers.read().contains_key(&1));
    }

    /// BIP 339's negotiation over a real socket, with satd on either end.
    /// `wtxidrelay` and `sendaddrv2` go out after the peer's version and
    /// before satd's verack when the common version reaches 70016, and not
    /// below, as Core sends them; the peer's `wtxidrelay` is honoured on the
    /// same condition, and only before its verack.
    #[tokio::test]
    async fn wtxid_relay_is_negotiated_between_version_and_verack() {
        use crate::net::connection::Connection;
        use bitcoin::p2p::{Address, Magic};

        async fn remote_side(
            conn: &mut Connection,
            version: u32,
            send_wtxidrelay: bool,
        ) -> Vec<&'static str> {
            let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
            let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
            conn.send(NetworkMessage::Version(VersionMessage {
                version,
                services,
                timestamp: crate::time::now_secs() as i64,
                receiver: Address::new(&zero, ServiceFlags::NONE),
                sender: Address::new(&zero, services),
                nonce: 0x5eed,
                user_agent: "/wtxid-test/".into(),
                start_height: 0,
                relay: true,
            }))
            .await
            .unwrap();
            let mut seen = Vec::new();
            loop {
                let msg = conn.recv().await.unwrap();
                seen.push(msg.cmd());
                if matches!(msg, NetworkMessage::Verack) {
                    break;
                }
            }
            if send_wtxidrelay {
                conn.send(NetworkMessage::WtxidRelay).await.unwrap();
            }
            conn.send(NetworkMessage::Verack).await.unwrap();
            seen
        }

        for direction in [Direction::Inbound, Direction::Outbound] {
            for (version, send_wtxidrelay, negotiated) in
                [(70016, true, true), (70016, false, false), (70015, true, false)]
            {
                let case = format!("{direction:?}, peer at {version}, peer sends wtxidrelay: {send_wtxidrelay}");
                let (pm, _dir) = mk_test_pm();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
                let (dialed, accepted) = tokio::join!(dialer, listener.accept());
                let (dialed, (accepted, peer_addr)) = (dialed.unwrap(), accepted.unwrap());
                let (ours, theirs) = match direction {
                    Direction::Inbound => (accepted, dialed),
                    Direction::Outbound => (dialed, accepted),
                };
                pm.peers.write().insert(1, mk_handle(1, peer_addr, direction, PeerState::Connecting));
                let mut ours = Connection::with_magic(ours, Magic::REGTEST);
                let mut theirs = Connection::with_magic(theirs, Magic::REGTEST);

                let (handshake, seen) = tokio::join!(
                    pm.perform_handshake(1, &mut ours, direction, crate::time::now_secs()),
                    remote_side(&mut theirs, version, send_wtxidrelay),
                );
                handshake.unwrap_or_else(|e| panic!("{case}: handshake failed: {e}"));

                let version_at = seen.iter().position(|c| *c == "version").expect("satd sent version");
                for negotiation in ["wtxidrelay", "sendaddrv2"] {
                    let at = seen.iter().position(|c| *c == negotiation);
                    if version >= WTXID_RELAY_VERSION {
                        assert!(
                            at.is_some_and(|at| at > version_at),
                            "{case}: satd must send {negotiation} between its version and verack, sent {seen:?}"
                        );
                    } else {
                        assert_eq!(at, None, "{case}: no {negotiation} below 70016, sent {seen:?}");
                    }
                }
                assert_eq!(pm.peers.read()[&1].info.wtxid_relay, negotiated, "{case}");
            }
        }
    }

    /// `bind_listener` must surface a bind failure as `Err` *before* any accept
    /// loop starts, so the startup path can treat a port collision (a second
    /// satd instance) as fatal instead of logging it on a detached task.
    #[tokio::test]
    async fn bind_listener_reports_port_collision() {
        // Bind an ephemeral port, then try to bind the same addr again.
        let first = PeerManager::bind_listener("127.0.0.1:0".parse().unwrap())
            .await
            .expect("first bind on an ephemeral port succeeds");
        let addr = first.local_addr().unwrap();
        let second = PeerManager::bind_listener(addr).await;
        assert!(
            second.is_err(),
            "binding an already-bound address must return Err, not panic or succeed"
        );
    }

    // ---- BIP 152 compact block receive state ----

    /// A regtest block on top of the manager's genesis tip, ground to a valid
    /// proof of work. `salt` varies the coinbase so sibling blocks differ.
    fn regtest_child_of_genesis(pm: &PeerManager, salt: u8) -> bitcoin::Block {
        use bitcoin::hashes::Hash;
        let genesis = pm.chain_state.tip_hash();
        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::script::Builder::new()
                    .push_int(1)
                    .push_int(i64::from(salt))
                    .into_script(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: genesis,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_296_688_602 + 600,
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    fn stale_pending(
        hash: bitcoin::BlockHash,
        header: bitcoin::block::Header,
        requested: bool,
    ) -> compact::PendingCompact {
        compact::PendingCompact {
            hash,
            header,
            txs: vec![None],
            missing_indices: vec![0],
            since: Instant::now()
                .checked_sub(compact::COMPACT_PENDING_TIMEOUT + Duration::from_secs(1))
                .expect("monotonic clock far enough from its origin"),
            requested,
            failed: false,
            height: 1,
            stats: compact::ReconstructStats::default(),
        }
    }

    /// A reconstruction whose `blocktxn` never comes is dropped after
    /// `COMPACT_PENDING_TIMEOUT`. If we had asked that peer for the block, the
    /// full block is requested from it, so the block is not left unfetched;
    /// an unrequested push is simply forgotten.
    #[test]
    fn pending_entry_expires_and_requested_block_falls_back_to_getdata() {
        use bitcoin::hashes::Hash;
        let pm = empty_peer_manager();
        let block = regtest_child_of_genesis(&pm, 1);
        let hash = block.block_hash();
        pm.chain_state.accept_header(&block.header).expect("header accepted");

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        let (h2, mut rx2) = mk_handle_rx(2, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);
        pm.peers.write().insert(2, h2);

        {
            let mut pending = pm.pending_compact.write();
            pending.insert(1, stale_pending(hash, block.header, true));
            pending.insert(2, stale_pending(hash, block.header, false));
            // A fresh entry must survive the sweep.
            let other = bitcoin::BlockHash::all_zeros();
            let mut fresh = stale_pending(other, block.header, true);
            fresh.since = Instant::now();
            pending.insert(3, fresh);
        }

        pm.expire_compact_state();

        let pending = pm.pending_compact.read();
        assert!(!pending.contains_key(&1) && !pending.contains_key(&2), "stale entries dropped");
        assert!(pending.contains_key(&3), "a fresh entry is kept");
        drop(pending);

        match rx1.try_recv() {
            Ok(NetworkMessage::GetData(inv)) => {
                assert_eq!(inv, vec![Inventory::WitnessBlock(hash)]);
            }
            other => panic!("the requested block must be fetched in full, got {other:?}"),
        }
        assert!(rx2.try_recv().is_err(), "an unrequested push earns no getdata");
    }

    /// A departed peer's reconstruction can never complete; it must not keep
    /// its memory.
    #[test]
    fn disconnect_drops_the_peers_pending_entry() {
        let pm = empty_peer_manager();
        let block = regtest_child_of_genesis(&pm, 2);
        let hash = block.block_hash();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        pm.peers.write().insert(1, mk_handle(1, addr, Direction::Inbound, PeerState::Connected));
        pm.peers.write().insert(2, mk_handle(2, addr, Direction::Inbound, PeerState::Connected));
        pm.pending_compact.write().insert(1, stale_pending(hash, block.header, false));
        pm.pending_compact.write().insert(2, stale_pending(hash, block.header, false));
        pm.note_blocks_requested(1, &[hash]);

        pm.handle_peer_disconnected(1);

        assert!(!pm.pending_compact.read().contains_key(&1));
        assert!(pm.pending_compact.read().contains_key(&2), "other peers are untouched");
        assert!(!pm.block_requested_from(1, &hash), "the peer's requests are forgotten too");
    }

    /// The in-flight table is charged to the peer that fills it. An `inv` is
    /// peer-controlled input and every announced block we lack earns a
    /// `getdata`, so recording those requests must not let a peer that keeps
    /// announcing fresh hashes — none of which has to be a block anyone mined
    /// — grow the table for as long as the records live.
    #[test]
    fn announced_blocks_cannot_grow_the_in_flight_table_without_bound() {
        use bitcoin::hashes::Hash;
        let pm = empty_peer_manager();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h1, mut rx1) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h1);

        let mut nth: u32 = 0;
        for _ in 0..20 {
            let inv: Vec<Inventory> = (0..200)
                .map(|_| {
                    nth += 1;
                    let mut bytes = [0u8; 32];
                    bytes[..4].copy_from_slice(&nth.to_le_bytes());
                    Inventory::Block(bitcoin::BlockHash::from_byte_array(bytes))
                })
                .collect();
            pm.handle_inv(1, inv);
            // Drained, as a peer keeping its queue empty would: a full channel
            // must not be what bounds this.
            while rx1.try_recv().is_ok() {}
        }
        assert_eq!(nth as usize, 4000, "the peer announced more than the cap");

        let in_flight = pm.in_flight_blocks.read();
        assert_eq!(in_flight.len(), 1, "one entry per peer, not one per announced hash");
        let asked = in_flight.get(&1).expect("the peer's records");
        assert!(
            asked.len() <= MAX_IN_FLIGHT_BLOCKS_PER_PEER,
            "{} records retained for one peer, cap is {MAX_IN_FLIGHT_BLOCKS_PER_PEER}",
            asked.len()
        );
    }

    /// A block already on its way in as a `cmpctblock` must not also be
    /// fetched in full: the tip-following sweep runs on a timer, and the
    /// reconstruction is typically a round trip from done — downloading the
    /// block spends exactly the bandwidth the compact form saved. The
    /// suppression is bounded, so a reconstruction that never finishes still
    /// gets the block fetched.
    #[test]
    fn a_block_being_reconstructed_is_not_also_fetched_in_full() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};

        let (cs, _dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis, 1, 1_707_000_000);
        let h1 = cs.accept_block(&b1).expect("connect block 1").hash();
        let pm = peer_manager_over(Arc::new(cs));

        let mut block = build_test_block(h1, 2, 1_707_000_001);
        // A transaction the mempool has never seen: the reconstruction stops
        // at a `getblocktxn` and the block stays unfinished.
        block.txdata.push(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(b1.txdata[0].compute_txid(), 0),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block.header.nonce = 0;
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        let hash = block.block_hash();

        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h, mut rx) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h);
        // We asked this peer for high-bandwidth relay, so its push is taken.
        pm.peers.write().get_mut(&1).unwrap().info.hb_to = true;

        let compact = bitcoin::bip152::HeaderAndShortIds::from_block(&block, 42, 2, &[])
            .expect("compact form");
        pm.handle_compact_block(1, compact);
        assert!(
            matches!(rx.try_recv(), Ok(NetworkMessage::GetBlockTxn(_))),
            "the missing transaction must be requested"
        );

        let fetched_in_full = |rx: &mut mpsc::Receiver<NetworkMessage>| {
            let mut seen = false;
            while let Ok(msg) = rx.try_recv() {
                if let NetworkMessage::GetData(inv) = msg {
                    seen |= inv.iter().any(|i| {
                        matches!(i, Inventory::Block(h) | Inventory::WitnessBlock(h) if *h == hash)
                    });
                }
            }
            seen
        };

        pm.request_missing_blocks(1);
        assert!(
            !fetched_in_full(&mut rx),
            "the block must not be fetched in full while it is being reconstructed"
        );

        // Bounded: once the reconstruction has had its window, the ordinary
        // fetch is back.
        let stale = Instant::now()
            .checked_sub(COMPACT_RECONSTRUCT_SUPPRESSION + Duration::from_secs(1))
            .expect("a monotonic clock that far along");
        pm.compact_in_progress.write().insert(hash, stale);
        pm.request_missing_blocks(1);
        assert!(
            fetched_in_full(&mut rx),
            "a reconstruction that never finishes must not hold the block hostage"
        );
    }

    /// A pushed block raises the height we believe its peer has — but only if
    /// its header cost real work, judged against the network's powLimit and
    /// not against the target the header names for itself.
    #[test]
    fn a_pushed_block_whose_header_names_a_free_target_does_not_raise_the_peers_height() {
        let pm = empty_peer_manager();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        for id in [1, 2] {
            pm.peers.write().insert(id, mk_handle(id, addr, Direction::Inbound, PeerState::Connected));
        }
        let height_of = |pm: &PeerManager, id| pm.peers.read()[&id].info.best_known_height;

        // 0x2101ffff overflows 256 bits; decoded without Core's checks the
        // shift wraps it to a target near 2^256, which essentially any nonce
        // meets. Regtest is the network where this matters least and it is
        // still refused: its limit is easy, but a wrapped target is not a
        // target at all.
        let mut forged = regtest_child_of_genesis(&pm, 7);
        forged.header.bits = bitcoin::CompactTarget::from_consensus(0x2101_ffff);
        while crate::validation::pow::check_proof_of_work(&forged.header).is_err() {
            forged.header.nonce += 1;
        }
        assert!(
            forged.header.nonce < 4,
            "precondition: the header must be free under the unbounded check"
        );
        pm.handle_block(1, forged, crate::net::flow::InFlight::new(pm.peer_flow(1)));
        assert_eq!(height_of(&pm, 1), None, "a free header must not move the belief");

        // A real regtest block does, so the gate is not refusing everything.
        let honest = regtest_child_of_genesis(&pm, 8);
        pm.handle_block(2, honest, crate::net::flow::InFlight::new(pm.peer_flow(2)));
        assert_eq!(height_of(&pm, 2), Some(1), "a block with real work records its height");
    }

    /// However a block arrives, every partial reconstruction of it is moot.
    #[test]
    fn full_block_arrival_drops_every_pending_entry_for_that_hash() {
        let pm = empty_peer_manager();
        let block = regtest_child_of_genesis(&pm, 3);
        let other = regtest_child_of_genesis(&pm, 4);
        let hash = block.block_hash();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        for id in 1..=3 {
            pm.peers.write().insert(id, mk_handle(id, addr, Direction::Inbound, PeerState::Connected));
        }
        pm.pending_compact.write().insert(1, stale_pending(hash, block.header, false));
        pm.pending_compact.write().insert(2, stale_pending(hash, block.header, false));
        pm.pending_compact
            .write()
            .insert(3, stale_pending(other.block_hash(), other.header, false));
        pm.note_blocks_requested(1, &[hash]);

        pm.handle_block(3, block, crate::net::flow::InFlight::new(pm.peer_flow(3)));

        let pending = pm.pending_compact.read();
        assert!(!pending.contains_key(&1) && !pending.contains_key(&2));
        assert!(pending.contains_key(&3), "a reconstruction of another block survives");
        assert!(!pm.block_requested_from(1, &hash));
    }

    /// `sendcmpct`'s boolean is the high-bandwidth flag, and only version 2 is
    /// spoken. satd used to store the flag as "supports compact blocks".
    #[test]
    fn sendcmpct_records_version_two_support_and_the_high_bandwidth_flag() {
        use bitcoin::p2p::message_compact_blocks::SendCmpct;
        let pm = empty_peer_manager();
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        pm.peers.write().insert(1, mk_handle(1, addr, Direction::Inbound, PeerState::Connected));
        let info = |pm: &PeerManager| {
            let peers = pm.peers.read();
            let h = &peers[&1].info;
            (h.compact_blocks, h.hb_from)
        };

        pm.handle_message(1, NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 1 }), crate::net::flow::InFlight::new(pm.peer_flow(1)));
        assert_eq!(info(&pm), (false, false), "version 1 is ignored");

        pm.handle_message(1, NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: 2 }), crate::net::flow::InFlight::new(pm.peer_flow(1)));
        assert_eq!(info(&pm), (true, false), "low-bandwidth v2");

        pm.handle_message(1, NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }), crate::net::flow::InFlight::new(pm.peer_flow(1)));
        assert_eq!(info(&pm), (true, true), "high-bandwidth v2");
    }

    /// `addr` and `addrv2` record what `getnodeaddresses` and
    /// `getrawaddrman` report: the announced service bits, and the peer that
    /// announced the address as its source.
    #[test]
    fn gossiped_addresses_keep_their_services_and_source() {
        use bitcoin::p2p::ServiceFlags;
        use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
        let pm = empty_peer_manager();
        let announcer: SocketAddr = "203.0.113.9:8333".parse().unwrap();
        pm.peers
            .write()
            .insert(1, mk_handle(1, announcer, Direction::Inbound, PeerState::Connected));

        let v1: SocketAddr = "198.51.100.1:8333".parse().unwrap();
        let v1_services = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS;
        pm.handle_message(
            1,
            NetworkMessage::Addr(vec![(1, Address::new(&v1, v1_services))]),
            crate::net::flow::InFlight::new(pm.peer_flow(1)),
        );
        pm.handle_message(
            1,
            NetworkMessage::AddrV2(vec![AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK_LIMITED,
                addr: AddrV2::Ipv4("198.51.100.2".parse().unwrap()),
                port: 8333,
            }]),
            crate::net::flow::InFlight::new(pm.peer_flow(1)),
        );

        let book = pm.addrman_snapshot();
        let entry = |ip: &str| {
            book.iter()
                .find(|e| e.addr.ip().to_string() == ip)
                .unwrap_or_else(|| panic!("{ip} not in the address book: {book:?}"))
        };
        assert_eq!(entry("198.51.100.1").services, v1_services.to_u64());
        assert_eq!(entry("198.51.100.1").source, announcer.ip());
        assert_eq!(entry("198.51.100.2").services, ServiceFlags::NETWORK_LIMITED.to_u64());
        assert_eq!(entry("198.51.100.2").source, announcer.ip());
    }

    // ---- BIP 152 high-bandwidth peer selection ----

    fn hb_peer(
        pm: &PeerManager,
        id: PeerId,
        dir: Direction,
    ) -> mpsc::Receiver<NetworkMessage> {
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (mut h, rx) = mk_handle_rx(id, addr, PeerState::Connected, 0);
        h.info.direction = dir;
        h.info.compact_blocks = true;
        pm.peers.write().insert(id, h);
        rx
    }

    fn sendcmpct_flags(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<bool> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let NetworkMessage::SendCmpct(s) = m {
                out.push(s.send_compact);
            }
        }
        out
    }

    /// Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs`, case by case: a known
    /// peer moves to the back; a fourth peer demotes the front; an inbound
    /// promotion never demotes the only outbound high-bandwidth peer; a peer
    /// without version-2 compact block support is never selected.
    #[test]
    fn maybe_set_peer_as_hb_follows_cores_selection() {
        let pm = empty_peer_manager();
        let mut rx: HashMap<PeerId, mpsc::Receiver<NetworkMessage>> = HashMap::new();
        rx.insert(1, hb_peer(&pm, 1, Direction::Outbound));
        for id in 2..=5 {
            rx.insert(id, hb_peer(&pm, id, Direction::Inbound));
        }
        let deque = |pm: &PeerManager| pm.hb_peers.lock().iter().copied().collect::<Vec<_>>();
        let hb_to = |pm: &PeerManager, id: PeerId| pm.peers.read()[&id].info.hb_to;

        for id in 1..=3 {
            pm.maybe_set_peer_as_hb(id);
        }
        assert_eq!(deque(&pm), vec![1, 2, 3]);
        assert_eq!(sendcmpct_flags(rx.get_mut(&1).unwrap()), vec![true]);
        assert!(hb_to(&pm, 1) && hb_to(&pm, 2) && hb_to(&pm, 3));

        // Already selected: moves to the back, nothing is sent.
        pm.maybe_set_peer_as_hb(1);
        assert_eq!(deque(&pm), vec![2, 3, 1]);
        assert!(sendcmpct_flags(rx.get_mut(&1).unwrap()).is_empty());

        // A fourth, inbound: the front (inbound 2) is demoted.
        pm.maybe_set_peer_as_hb(4);
        assert_eq!(deque(&pm), vec![3, 1, 4]);
        assert_eq!(sendcmpct_flags(rx.get_mut(&2).unwrap()), vec![true, false]);
        assert!(!hb_to(&pm, 2));

        // Make the outbound peer the front: 3 out, then 1 and 4 remain with
        // the outbound first.
        pm.hb_peers.lock().clear();
        pm.hb_peers.lock().extend([1, 3, 4]);
        // An inbound promotion with the only outbound peer at the front swaps
        // it into the second slot, so inbound 3 is demoted instead.
        pm.maybe_set_peer_as_hb(5);
        assert_eq!(deque(&pm), vec![1, 4, 5]);
        assert_eq!(sendcmpct_flags(rx.get_mut(&3).unwrap()).last(), Some(&false));
        assert!(!sendcmpct_flags(rx.get_mut(&1).unwrap()).contains(&false));

        // No v2 compact block support: never selected.
        let _rx6 = hb_peer(&pm, 6, Direction::Inbound);
        pm.peers.write().get_mut(&6).unwrap().info.compact_blocks = false;
        pm.maybe_set_peer_as_hb(6);
        assert!(!deque(&pm).contains(&6));

        // -blocksonly: never selected.
        pm.set_blocksonly(true);
        pm.hb_peers.lock().clear();
        pm.maybe_set_peer_as_hb(2);
        assert!(deque(&pm).is_empty());
    }

    /// A disconnected peer leaves the high-bandwidth set.
    #[test]
    fn disconnect_removes_a_high_bandwidth_peer() {
        let pm = empty_peer_manager();
        let _rx = hb_peer(&pm, 1, Direction::Inbound);
        pm.maybe_set_peer_as_hb(1);
        assert_eq!(pm.hb_peers.lock().len(), 1);
        pm.handle_peer_disconnected(1);
        assert!(pm.hb_peers.lock().is_empty());
    }

    // ---- Blocks announced by `headers`, fetched as `cmpctblock`s ----

    /// A chain whose tip was mined at `tip_time`, a peer manager over it, and
    /// a connected peer `1` that sent `sendcmpct(0, version)`: low-bandwidth,
    /// never selected for high-bandwidth relay.
    struct CompactFetch {
        pm: Arc<PeerManager>,
        tip: bitcoin::Block,
        rx: mpsc::Receiver<NetworkMessage>,
        _dir: std::path::PathBuf,
    }

    fn compact_fetch_fixture_with(tip_time: u32, sendcmpct_version: u64) -> CompactFetch {
        use crate::chain::state::tests::{build_test_block, make_chain_state};
        use bitcoin::p2p::message_compact_blocks::SendCmpct;
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let tip = build_test_block(genesis, 1, tip_time);
        cs.accept_block(&tip).expect("connect block 1");
        let pm = peer_manager_over(Arc::new(cs));
        let addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let (h, rx) = mk_handle_rx(1, addr, PeerState::Connected, 0);
        pm.peers.write().insert(1, h);
        deliver(
            &pm,
            1,
            NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: sendcmpct_version }),
        );
        CompactFetch { pm, tip, rx, _dir: dir }
    }

    /// [`compact_fetch_fixture_with`] with a tip mined now, so Core's
    /// `CanDirectFetch` holds, and a peer speaking BIP 152 version 2.
    fn compact_fetch_fixture() -> CompactFetch {
        compact_fetch_fixture_with(crate::time::now_secs() as u32, 2)
    }

    /// Hand `msg` to the real message handler as if `id` had sent it.
    fn deliver(pm: &PeerManager, id: PeerId, msg: NetworkMessage) {
        pm.handle_message(id, msg, crate::net::flow::InFlight::new(pm.peer_flow(id)));
    }

    fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    /// Every request for `hash` in `msgs`, in order: `true` for
    /// `MSG_CMPCT_BLOCK`, `false` for the full block.
    fn block_requests(msgs: &[NetworkMessage], hash: bitcoin::BlockHash) -> Vec<bool> {
        msgs.iter()
            .filter_map(|m| match m {
                NetworkMessage::GetData(inv) => Some(inv),
                _ => None,
            })
            .flatten()
            .filter_map(|i| match i {
                Inventory::CompactBlock(h) if *h == hash => Some(true),
                Inventory::Block(h) | Inventory::WitnessBlock(h) if *h == hash => Some(false),
                _ => None,
            })
            .collect()
    }

    /// A child of `parent` holding only its coinbase: a `cmpctblock` of it
    /// is complete without any help from the mempool.
    fn coinbase_only_child(parent: &bitcoin::Block, height: u32) -> bitcoin::Block {
        crate::chain::state::tests::build_test_block(parent.block_hash(), height, parent.header.time + 1)
    }

    /// A child of `parent` carrying one transaction nobody has, so rebuilding
    /// it from a `cmpctblock` takes a `getblocktxn` round trip. Its input does
    /// not exist, so it never connects; these tests stop short of that.
    fn child_with_unknown_tx(parent: &bitcoin::Block, height: u32, salt: u8) -> bitcoin::Block {
        use bitcoin::hashes::Hash;
        let mut block = coinbase_only_child(parent, height);
        block.txdata.push(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([salt; 32]), 0),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block.header.nonce = 0;
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    fn cmpctblock_of(block: &bitcoin::Block) -> NetworkMessage {
        NetworkMessage::CmpctBlock(bitcoin::p2p::message_compact_blocks::CmpctBlock {
            compact_block: bitcoin::bip152::HeaderAndShortIds::from_block(block, 7, 2, &[])
                .expect("compact form"),
        })
    }

    fn wait_for_tip(pm: &PeerManager, hash: bitcoin::BlockHash) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while pm.chain_state.tip_hash() != hash {
            assert!(Instant::now() < deadline, "block {hash} never connected");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Core's headers direct fetch (`HeadersDirectFetchBlocks`): a peer that
    /// speaks BIP 152 version 2 but was never selected for high-bandwidth
    /// relay announces one new block by `headers`, and the block is asked for
    /// as `MSG_CMPCT_BLOCK`. The `cmpctblock` that answers takes the road a
    /// pushed one does -- a `getblocktxn` for what the mempool lacks -- and
    /// the rebuilt block leaves nothing in flight behind it.
    #[test]
    fn an_announced_block_is_fetched_as_a_cmpctblock_and_rebuilt_by_round_trip() {
        let mut f = compact_fetch_fixture();
        let b2 = child_with_unknown_tx(&f.tip, 2, 0x71);
        let h2 = b2.block_hash();

        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![true], "one request, for a cmpctblock");
        assert!(!f.pm.peers.read()[&1].info.hb_to, "precondition: a low-bandwidth peer");

        deliver(&f.pm, 1, cmpctblock_of(&b2));
        let msgs = drain(&mut f.rx);
        let asked: Vec<Vec<u64>> = msgs
            .iter()
            .filter_map(|m| match m {
                NetworkMessage::GetBlockTxn(g) if g.txs_request.block_hash == h2 => {
                    Some(g.txs_request.indexes.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(asked, vec![vec![1]], "the transaction the mempool lacks is asked for: {msgs:?}");
        assert!(block_requests(&msgs, h2).is_empty(), "and the block is not fetched in full");

        deliver(
            &f.pm,
            1,
            NetworkMessage::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
                transactions: bitcoin::bip152::BlockTransactions {
                    block_hash: h2,
                    transactions: vec![b2.txdata[1].clone()],
                },
            }),
        );
        assert!(!f.pm.block_requested_from(1, &h2), "a rebuilt block is no longer in flight");
        assert!(
            f.pm.compact_reconstruction_in_flight(&h2),
            "the sweep leaves it alone until the connector has it"
        );
        assert!(f.pm.pending_compact.read().is_empty());
    }

    /// A requested `cmpctblock` the mempool completes on its own ends the
    /// request that asked for it, so the next block announced alone is
    /// fetched compactly too. Left behind, the finished request reads as
    /// another block in flight for as long as it lives, and every block
    /// after the first goes back to being fetched whole. The rebuilt block's
    /// reconstruction mark outlives it on purpose, and counts as nothing in
    /// flight once the block is stored.
    ///
    /// Perturbation: count every recent mark in `nothing_else_in_flight`, as
    /// before, and B3 is fetched whole.
    #[test]
    fn a_cmpctblock_rebuilt_from_the_mempool_ends_its_request() {
        let mut f = compact_fetch_fixture();
        let b2 = coinbase_only_child(&f.tip, 2);
        let h2 = b2.block_hash();
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![true]);

        deliver(&f.pm, 1, cmpctblock_of(&b2));
        assert!(!f.pm.block_requested_from(1, &h2), "the rebuilt block is no longer in flight");
        wait_for_tip(&f.pm, h2);

        let b3 = coinbase_only_child(&b2, 3);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b3.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), b3.block_hash()), vec![true]);
    }

    /// A rebuilt block is on its way to the connect thread, not stored, and
    /// the tip-following sweep leaves it alone until it is. The sweep runs in
    /// the manager loop pass that handled the `cmpctblock`, so clearing the
    /// block's reconstruction mark as it was rebuilt made that pass download
    /// it again in full. The accept lock holds the connector off, so the
    /// block is still unstored when the sweep runs.
    ///
    /// Perturbation: clear the mark in `forget_block_requests` and the sweep
    /// asks for the block.
    #[test]
    fn the_sweep_does_not_fetch_a_rebuilt_block_before_it_is_stored() {
        let mut f = compact_fetch_fixture();
        let b2 = coinbase_only_child(&f.tip, 2);
        let h2 = b2.block_hash();
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![true]);

        let held = f.pm.chain_state.hold_accept_lock_for_test();
        deliver(&f.pm, 1, cmpctblock_of(&b2));
        assert!(!f.pm.chain_state.has_block_data(&h2), "precondition: not stored yet");
        f.pm.request_missing_blocks(1);
        assert!(block_requests(&drain(&mut f.rx), h2).is_empty(), "the sweep must not fetch it again");
        drop(held);
        wait_for_tip(&f.pm, h2);
    }

    /// A `cmpctblock` we asked a peer for, turned away because three other
    /// peers are already rebuilding the block, has no full block behind it.
    /// The node asks that peer for the whole block rather than leave the
    /// request answered and the block unfetched.
    #[test]
    fn a_requested_cmpctblock_the_per_block_cap_turns_away_is_asked_for_in_full() {
        let mut f = compact_fetch_fixture();
        let b2 = child_with_unknown_tx(&f.tip, 2, 0x72);
        let h2 = b2.block_hash();
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![true]);

        for other in 2..=4 {
            let mut pending = stale_pending(h2, b2.header, false);
            pending.since = Instant::now();
            f.pm.pending_compact.write().insert(other, pending);
        }
        deliver(&f.pm, 1, cmpctblock_of(&b2));
        let msgs = drain(&mut f.rx);
        assert!(
            !msgs.iter().any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
            "the cap holds: this peer does not rebuild the block"
        );
        assert_eq!(block_requests(&msgs, h2), vec![false], "the full block is asked for instead");
    }

    /// A block asked for as a `cmpctblock` is on its way in compactly, so the
    /// tip-following sweep does not fetch it whole straight away -- and only
    /// for a bounded time: a request nobody answers is fetched in full once
    /// the window passes, rather than stalling.
    #[test]
    fn a_compact_request_holds_off_the_sweep_for_a_bounded_time() {
        let mut f = compact_fetch_fixture();
        let b2 = child_with_unknown_tx(&f.tip, 2, 0x73);
        let h2 = b2.block_hash();
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![true]);

        f.pm.request_missing_blocks(1);
        assert!(
            block_requests(&drain(&mut f.rx), h2).is_empty(),
            "the sweep must not fetch in full a block just asked for compactly"
        );

        let stale = Instant::now()
            .checked_sub(COMPACT_RECONSTRUCT_SUPPRESSION + Duration::from_secs(1))
            .expect("a monotonic clock that far along");
        f.pm.compact_in_progress.write().insert(h2, stale);
        f.pm.request_missing_blocks(1);
        assert_eq!(
            block_requests(&drain(&mut f.rx), h2),
            vec![false],
            "an unanswered compact request must not hold the block hostage"
        );
    }

    /// Core's single-block condition (`vGetData.size() == 1`): an
    /// announcement that leaves two blocks to fetch fetches both in full.
    #[test]
    fn two_blocks_announced_together_are_fetched_in_full() {
        let mut f = compact_fetch_fixture();
        let b2 = coinbase_only_child(&f.tip, 2);
        let b3 = coinbase_only_child(&b2, 3);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header, b3.header]));
        let msgs = drain(&mut f.rx);
        assert_eq!(block_requests(&msgs, b2.block_hash()), vec![false]);
        assert_eq!(block_requests(&msgs, b3.block_hash()), vec![false]);
    }

    /// Core's `pprev->IsValid(BLOCK_VALID_CHAIN)`: the one block missing has
    /// a parent that is stored but not connected -- a side branch -- so it
    /// could not connect straight after being rebuilt, and is fetched in
    /// full.
    #[test]
    fn a_block_whose_parent_is_not_connected_is_fetched_in_full() {
        use crate::chain::state::tests::{build_test_block, store_block_without_connecting};
        let mut f = compact_fetch_fixture();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        // A sibling of the tip, stored and never connected: equal work does
        // not displace the tip.
        let side = build_test_block(genesis, 1, f.tip.header.time + 1);
        store_block_without_connecting(&f.pm.chain_state, &side, 1);
        let child = coinbase_only_child(&side, 2);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![child.header]));
        assert_eq!(
            f.pm.chain_state.missing_blocks_for_best_header_chain(128),
            vec![child.block_hash()],
            "precondition: the announced block is the only one missing"
        );
        assert_eq!(block_requests(&drain(&mut f.rx), child.block_hash()), vec![false]);
    }

    /// Core's `m_provides_cmpctblocks`: a peer that never sent a version-2
    /// `sendcmpct` -- here it offered only version 1, which is ignored -- is
    /// asked for full blocks.
    #[test]
    fn a_peer_without_version_two_compact_blocks_is_asked_for_full_blocks() {
        let mut f = compact_fetch_fixture_with(crate::time::now_secs() as u32, 1);
        let b2 = coinbase_only_child(&f.tip, 2);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), b2.block_hash()), vec![false]);
    }

    /// Core's `!m_opts.ignore_incoming_txs`: under `-blocksonly` the mempool
    /// is empty, and a compact block would need nearly every transaction by
    /// round trip.
    #[test]
    fn a_blocksonly_node_fetches_announced_blocks_in_full() {
        let mut f = compact_fetch_fixture();
        f.pm.set_blocksonly(true);
        let b2 = coinbase_only_child(&f.tip, 2);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), b2.block_hash()), vec![false]);
    }

    /// Core's `CanDirectFetch`: a tip older than twenty block intervals
    /// means the node is catching up, and the block is fetched in full.
    /// Three hours is inside the window, four is outside it.
    #[test]
    fn a_stale_tip_fetches_announced_blocks_in_full() {
        let now = crate::time::now_secs() as u32;
        for (age_hours, compact) in [(3u32, true), (4, false)] {
            let mut f = compact_fetch_fixture_with(now - age_hours * 3600, 2);
            let b2 = coinbase_only_child(&f.tip, 2);
            deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
            assert_eq!(
                block_requests(&drain(&mut f.rx), b2.block_hash()),
                vec![compact],
                "a tip {age_hours}h old"
            );
        }
    }

    /// Core walks back from the header the peer announced, so the block it
    /// may ask for compactly is always that one. Here the peer announces a
    /// stale sibling of the tip while the best chain is missing a different
    /// block, one this peer never claimed to have: it is fetched in full.
    #[test]
    fn only_the_announced_block_is_fetched_as_a_cmpctblock() {
        use crate::chain::state::tests::build_test_block;
        let mut f = compact_fetch_fixture();
        let best = coinbase_only_child(&f.tip, 2);
        f.pm.chain_state.accept_header(&best.header).expect("best header");
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let sibling = build_test_block(genesis, 1, f.tip.header.time + 2);
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![sibling.header]));
        let msgs = drain(&mut f.rx);
        assert_eq!(block_requests(&msgs, best.block_hash()), vec![false]);
        assert!(block_requests(&msgs, sibling.block_hash()).is_empty());
    }

    /// Core's `mapBlocksInFlight.size() == 1`: while any other block is
    /// being downloaded or rebuilt, from anyone, an announced block is
    /// fetched in full. Each of satd's in-flight tables counts.
    #[test]
    fn another_block_in_flight_keeps_the_fetch_full() {
        use bitcoin::hashes::Hash;
        let other = bitcoin::BlockHash::from_byte_array([0x5a; 32]);
        type Setup = fn(&PeerManager, bitcoin::BlockHash);
        let cases: [(&str, Setup); 4] = [
            ("a block requested from another peer", |pm, other| pm.note_blocks_requested(2, &[other])),
            ("a reconstruction awaiting blocktxn", |pm, other| {
                let mut pending = stale_pending(other, bitcoin::constants::genesis_block(Network::Regtest).header, false);
                pending.since = Instant::now();
                pm.pending_compact.write().insert(2, pending);
            }),
            ("a cmpctblock being rebuilt", |pm, other| {
                pm.compact_in_progress.write().insert(other, Instant::now());
            }),
            ("a background download", |pm, _| {
                pm.bg_downloader.write().mark_in_flight(5, 2, Instant::now());
            }),
        ];
        let fetched_compactly: Vec<&str> = cases
            .into_iter()
            .filter(|(_, setup)| {
                let mut f = compact_fetch_fixture();
                setup(&f.pm, other);
                let b2 = coinbase_only_child(&f.tip, 2);
                deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
                block_requests(&drain(&mut f.rx), b2.block_hash()) != vec![false]
            })
            .map(|(what, _)| what)
            .collect();
        assert!(fetched_compactly.is_empty(), "not fetched in full despite {fetched_compactly:?}");
    }

    /// The block being asked for does not count against itself: announced
    /// first by `inv` (which satd answers with a full `getdata`) and then by
    /// `headers`, it is still the only block in flight, as Core counts.
    #[test]
    fn the_announced_block_already_asked_of_the_same_peer_is_not_another() {
        let mut f = compact_fetch_fixture();
        let b2 = coinbase_only_child(&f.tip, 2);
        let h2 = b2.block_hash();
        deliver(&f.pm, 1, NetworkMessage::Inv(vec![Inventory::Block(h2)]));
        deliver(&f.pm, 1, NetworkMessage::Headers(vec![b2.header]));
        assert_eq!(block_requests(&drain(&mut f.rx), h2), vec![false, true]);
    }

    // ---- BIP 130 `sendheaders`, on Core's condition ----

    /// A connected peer that sent `version` with `version`.
    fn versioned_peer(
        pm: &PeerManager,
        id: PeerId,
        dir: Direction,
        version: u32,
    ) -> mpsc::Receiver<NetworkMessage> {
        use bitcoin::p2p::{Address, ServiceFlags};
        let addr: SocketAddr = "10.0.0.2:8333".parse().unwrap();
        let (mut h, rx) = mk_handle_rx(id, addr, PeerState::Connected, 0);
        h.info.direction = dir;
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        h.info.set_version(VersionMessage {
            version,
            services,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, services),
            nonce: 1,
            user_agent: "/test/".into(),
            start_height: 0,
            relay: true,
        });
        pm.peers.write().insert(id, h);
        rx
    }

    fn sendheaders_count(msgs: &[NetworkMessage]) -> usize {
        msgs.iter().filter(|m| matches!(m, NetworkMessage::SendHeaders)).count()
    }

    /// Core's `MaybeSendSendHeaders`: an inbound peer is sent `sendheaders`
    /// once it shows a block past the minimum chain work (none on regtest),
    /// and only once however many more it shows. satd used to send it only
    /// to outbound peers, during the handshake.
    #[test]
    fn sendheaders_goes_to_an_inbound_peer_once() {
        let mut f = compact_fetch_fixture();
        let mut rx = versioned_peer(&f.pm, 2, Direction::Inbound, 70016);
        assert_eq!(sendheaders_count(&drain(&mut rx)), 0, "nothing before the peer shows a block");

        deliver(&f.pm, 2, NetworkMessage::Headers(vec![f.tip.header]));
        assert_eq!(sendheaders_count(&drain(&mut rx)), 1);

        let b2 = coinbase_only_child(&f.tip, 2);
        deliver(&f.pm, 2, NetworkMessage::Headers(vec![b2.header]));
        deliver(&f.pm, 2, NetworkMessage::Headers(vec![f.tip.header]));
        deliver(&f.pm, 2, cmpctblock_of(&b2));
        assert_eq!(sendheaders_count(&drain(&mut rx)), 0, "sent once per connection");
        let _ = drain(&mut f.rx);
    }

    /// The minimum chain work gate: on mainnet a peer that has shown only the
    /// genesis block has not shown a chain worth header announcements.
    #[test]
    fn sendheaders_waits_for_a_block_past_the_minimum_chain_work() {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;
        let dir = tempfile::TempDir::new().unwrap();
        let cs = ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
            Network::Bitcoin,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let pm = peer_manager_over(Arc::new(cs));
        let mut rx = versioned_peer(&pm, 1, Direction::Inbound, 70016);
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        deliver(&pm, 1, NetworkMessage::Headers(vec![genesis.header]));
        assert_eq!(pm.peers.read()[&1].info.best_known_height, Some(0), "precondition: genesis is recorded");
        assert_eq!(sendheaders_count(&drain(&mut rx)), 0);
        assert!(!pm.peers.read()[&1].info.sent_sendheaders);
    }

    /// Core's `GetCommonVersion() >= SENDHEADERS_VERSION`: a peer older than
    /// BIP 130 is never sent `sendheaders`.
    #[test]
    fn sendheaders_needs_a_common_version_of_70012() {
        for (version, expected) in [(70011u32, 0usize), (70012, 1)] {
            let mut f = compact_fetch_fixture();
            let mut rx = versioned_peer(&f.pm, 2, Direction::Inbound, version);
            deliver(&f.pm, 2, NetworkMessage::Headers(vec![f.tip.header]));
            assert_eq!(sendheaders_count(&drain(&mut rx)), expected, "version {version}");
            let _ = drain(&mut f.rx);
        }
    }

    /// Core's INV handler records availability for every block announced,
    /// known or not. A known block announced by `inv` raises the height the
    /// peer is believed to have reached and, past the minimum chain work,
    /// earns it `sendheaders` -- which a peer announcing by `inv` otherwise
    /// never would.
    #[test]
    fn a_known_block_announced_by_inv_counts_as_shown() {
        let mut f = compact_fetch_fixture();
        let mut rx = versioned_peer(&f.pm, 2, Direction::Outbound, 70016);
        deliver(&f.pm, 2, NetworkMessage::Inv(vec![Inventory::Block(f.tip.block_hash())]));
        assert_eq!(f.pm.peers.read()[&2].info.best_known_height, Some(1));
        let msgs = drain(&mut rx);
        assert_eq!(sendheaders_count(&msgs), 1);
        assert!(block_requests(&msgs, f.tip.block_hash()).is_empty(), "a block we have is not fetched");
        let _ = drain(&mut f.rx);
    }
}
