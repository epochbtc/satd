//! Listeners, the template refresh loop, and block submission.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use bitcoin::{Block, Network};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast, watch};
use tls_config::{ClientAllowList, ClientAuthPolicy, TlsAcceptor, TlsConfigError};

use super::config::{StratumConfig, should_issue_work};
use super::template::Work;
use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;

/// How often work is rebuilt when the tip has not moved, so new mempool
/// transactions reach the miners.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How often the tip is checked directly, independent of chain events.
///
/// Not a fallback for a missing event channel: some connect paths move the
/// tip without emitting an event at all (the IBD connect loop is the one
/// that matters, and a node catching up after a restart runs it), so a
/// stratum server that only listened would hand out work for a tip the
/// chain had already left behind, until the next [`REFRESH_INTERVAL`].
const TIP_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum StratumServerError {
    #[error("bind to {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
    #[error("tls config: {0}")]
    Tls(#[from] TlsConfigError),
    #[error("--stratumtlsbind is set without both --stratumtlscert and --stratumtlskey")]
    TlsMissingPaths,
    #[error("--stratummtls=1 requires --stratummtlsclientca")]
    MtlsMissingCa,
    #[error("Stratum V2 authority key {path}: {source}")]
    AuthorityKey { path: std::path::PathBuf, source: io::Error },
    #[error("this build has no Stratum V2 support (the `stratum-v2` feature is off)")]
    V2Unavailable,
}

/// The bound Stratum V2 listener.
#[cfg(feature = "stratum-v2")]
struct V2Listener {
    listener: TcpListener,
    ctx: Arc<super::v2::session::V2Context>,
}

/// Counters the server keeps for `getstratuminfo`.
#[derive(Default)]
pub struct StratumStats {
    /// Open connections, both protocols.
    pub connections: AtomicU64,
    /// Authorized Stratum V1 connections plus open Stratum V2 channels.
    pub channels: AtomicU64,
    pub shares_accepted: AtomicU64,
    /// Rejected for any reason other than staleness.
    pub shares_rejected: AtomicU64,
    pub shares_stale: AtomicU64,
    /// Blocks found by miners that joined the active chain.
    pub blocks_found: AtomicU64,
    /// The miners connected now.
    pub miners: Arc<super::miner::MinerRegistry>,
    last_block: parking_lot::Mutex<Option<LastBlock>>,
}

#[derive(Clone, Copy)]
struct LastBlock {
    height: u32,
    hash: bitcoin::BlockHash,
    time: u64,
}

impl StratumStats {
    /// Count a connection until the returned guard drops.
    pub(crate) fn connection(self: &Arc<Self>) -> CountGuard {
        CountGuard::new(self.clone(), |s| &s.connections)
    }

    pub(crate) fn share(&self, outcome: ShareOutcome) {
        let counter = match outcome {
            ShareOutcome::Accepted => &self.shares_accepted,
            ShareOutcome::Stale => &self.shares_stale,
            ShareOutcome::Rejected => &self.shares_rejected,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// How a share was judged, for the counters.
#[derive(Clone, Copy)]
pub(crate) enum ShareOutcome {
    Accepted,
    Stale,
    Rejected,
}

/// Holds one unit of a gauge in [`StratumStats`], released on drop.
pub(crate) struct CountGuard {
    stats: Arc<StratumStats>,
    gauge: fn(&StratumStats) -> &AtomicU64,
}

impl CountGuard {
    pub(crate) fn new(stats: Arc<StratumStats>, gauge: fn(&StratumStats) -> &AtomicU64) -> Self {
        gauge(&stats).fetch_add(1, Ordering::Relaxed);
        Self { stats, gauge }
    }
}

impl Drop for CountGuard {
    fn drop(&mut self) {
        (self.gauge)(&self.stats).fetch_sub(1, Ordering::Relaxed);
    }
}

/// What was bound, for reporting.
#[derive(Default, Clone)]
struct Listeners {
    v1: Option<SocketAddr>,
    v1_tls: Option<SocketAddr>,
    v2: Option<SocketAddr>,
    authority_pubkey: Option<[u8; 32]>,
}

/// State every connection shares.
pub(crate) struct Shared {
    pub config: Arc<StratumConfig>,
    pub chain: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    /// The latest work, or `None` while none should be issued.
    pub work: watch::Sender<Option<Arc<Work>>>,
    /// The node's core runtime. Found blocks are connected there: block
    /// connection must never originate on the API runtime the listeners run
    /// on (see `ChainState::emit_chain_event`).
    pub(crate) core: tokio::runtime::Handle,
    pub stats: Arc<StratumStats>,
    listeners: Listeners,
    next_extranonce1: AtomicU32,
}

/// A read handle on a running server, for `getstratuminfo`.
#[derive(Clone)]
pub struct StratumHandle {
    shared: Arc<Shared>,
}

impl StratumHandle {
    /// The server's counters and connected miners.
    pub fn stats(&self) -> &StratumStats {
        &self.shared.stats
    }

    /// The `getstratuminfo` result.
    pub fn info(&self) -> serde_json::Value {
        let shared = &self.shared;
        let stats = &shared.stats;
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let addr = |a: Option<SocketAddr>| a.map(|a| a.to_string());
        let work = shared.work.borrow().clone();
        let current_job = work.map(|w| {
            serde_json::json!({
                "height": w.height,
                "job_id": format!("{:x}", w.id),
                "prev_hash": w.prev_hash.to_string(),
                "template_txs": w.txdata.len(),
                "template_fees": w.fees,
            })
        });
        let last_block = stats.last_block.lock().map(|b| {
            serde_json::json!({ "height": b.height, "hash": b.hash.to_string(), "time": b.time })
        });
        serde_json::json!({
            "enabled": true,
            "listeners": {
                "v1": addr(shared.listeners.v1),
                "v1_tls": addr(shared.listeners.v1_tls),
                "v2": addr(shared.listeners.v2),
            },
            "authority_pubkey": shared.listeners.authority_pubkey.map(hex::encode),
            "job_declaration": shared.config.v2.as_ref().is_some_and(|v| v.job_declaration),
            "connections": load(&stats.connections),
            "channels": load(&stats.channels),
            "current_job": current_job,
            "shares": {
                "accepted": load(&stats.shares_accepted),
                "rejected": load(&stats.shares_rejected),
                "stale": load(&stats.shares_stale),
            },
            "blocks_found": load(&stats.blocks_found),
            "last_block": last_block,
            "hashrate": stats.miners.hashrate(),
            "miners": stats.miners.info(),
        })
    }

    /// The `getstratuminfo` result on a node with the server off.
    pub fn disabled_info() -> serde_json::Value {
        serde_json::json!({
            "enabled": false,
            "listeners": { "v1": null, "v1_tls": null, "v2": null },
            "authority_pubkey": null,
            "job_declaration": false,
            "connections": 0,
            "channels": 0,
            "current_job": null,
            "shares": { "accepted": 0, "rejected": 0, "stale": 0 },
            "blocks_found": 0,
            "last_block": null,
            "hashrate": 0.0,
            "miners": [],
        })
    }
}

impl Shared {
    /// A fresh extranonce1 for a new connection. Unique per connection for
    /// the life of the process (until it wraps), so no two miners hash the
    /// same coinbase.
    pub fn next_extranonce1(&self) -> [u8; 4] {
        self.next_extranonce1.fetch_add(1, Ordering::Relaxed).to_be_bytes()
    }
}

#[cfg(test)]
impl Shared {
    /// Shared state over an empty in-memory regtest chain, for driving a
    /// session directly. No work is issued until a test sends some.
    pub(crate) fn for_test(config: StratumConfig) -> Arc<Self> {
        use crate::chain::state::AssumeValid;
        use crate::storage::db::InMemoryStore;
        use crate::storage::flatfile::FlatFileManager;
        use crate::validation::script::NoopVerifier;

        let dir = std::env::temp_dir().join(format!(
            "satd-stratum-session-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let chain = ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.join("blocks")).unwrap(),
            config.network,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let (work, _) = watch::channel(None);
        Arc::new(Self {
            config: Arc::new(config),
            chain: Arc::new(chain),
            mempool: Arc::new(Mempool::new(1_000_000, 0)),
            work,
            core: tokio::runtime::Handle::current(),
            stats: Arc::new(StratumStats::default()),
            listeners: Listeners::default(),
            next_extranonce1: AtomicU32::new(0),
        })
    }
}

/// A bound Stratum server, ready to [`run`](Self::run).
pub struct StratumServer {
    listener: TcpListener,
    tls: Option<(TcpListener, TlsAcceptor)>,
    allow: ClientAllowList,
    semaphore: Arc<Semaphore>,
    shared: Arc<Shared>,
    peers: Option<Arc<PeerManager>>,
    #[cfg(feature = "stratum-v2")]
    v2: Option<V2Listener>,
}

impl StratumServer {
    /// Bind every configured listener. Binding here rather than in
    /// [`run`](Self::run) makes a port conflict or an unreadable certificate
    /// a startup error.
    ///
    /// `peers` is used only to warn when work is being issued with no peer
    /// to relay a found block to. Relay itself needs nothing from this
    /// module: every block that connects is announced by the node's
    /// block-announcement task.
    ///
    /// `core` is the runtime found blocks are submitted on. The server itself
    /// may run elsewhere — the node runs it on the API runtime — but block
    /// connection has to happen on the core runtime, exactly as `submitblock`
    /// does.
    pub async fn bind(
        config: StratumConfig,
        chain: Arc<ChainState>,
        mempool: Arc<Mempool>,
        peers: Option<Arc<PeerManager>>,
        core: tokio::runtime::Handle,
    ) -> Result<Self, StratumServerError> {
        let listener = TcpListener::bind(config.bind)
            .await
            .map_err(|source| StratumServerError::Bind { addr: config.bind, source })?;
        let tls = match (config.tls_bind, config.tls_cert.as_ref(), config.tls_key.as_ref()) {
            (None, _, _) => None,
            (Some(addr), Some(cert), Some(key)) => {
                let policy = match (config.mtls, config.mtls_client_ca.as_ref()) {
                    (false, _) => ClientAuthPolicy::Disabled,
                    (true, Some(ca)) => ClientAuthPolicy::Required { ca_path: ca.clone() },
                    (true, None) => return Err(StratumServerError::MtlsMissingCa),
                };
                let acceptor = tls_config::build_acceptor(cert, key, &policy)?;
                let tls_listener = TcpListener::bind(addr)
                    .await
                    .map_err(|source| StratumServerError::Bind { addr, source })?;
                Some((tls_listener, acceptor))
            }
            (Some(_), _, _) => return Err(StratumServerError::TlsMissingPaths),
        };
        #[cfg(feature = "stratum-v2")]
        let v2 = match config.v2.as_ref() {
            None => None,
            Some(v2) => Some(bind_v2(v2).await?),
        };
        #[cfg(not(feature = "stratum-v2"))]
        if config.v2.is_some() {
            return Err(StratumServerError::V2Unavailable);
        }
        let allow = ClientAllowList::new(config.mtls_client_allow.iter().cloned());
        let semaphore = Arc::new(Semaphore::new(config.max_conns.max(1)));
        let (work, _) = watch::channel(None);
        let listeners = Listeners {
            v1: listener.local_addr().ok(),
            v1_tls: tls.as_ref().and_then(|(l, _)| l.local_addr().ok()),
            #[cfg(feature = "stratum-v2")]
            v2: v2.as_ref().and_then(|v| v.listener.local_addr().ok()),
            #[cfg(feature = "stratum-v2")]
            authority_pubkey: v2.as_ref().map(|v| v.ctx.authority_public),
            #[cfg(not(feature = "stratum-v2"))]
            v2: None,
            #[cfg(not(feature = "stratum-v2"))]
            authority_pubkey: None,
        };
        let shared = Arc::new(Shared {
            config: Arc::new(config),
            chain,
            mempool,
            work,
            core,
            stats: Arc::new(StratumStats::default()),
            listeners,
            next_extranonce1: AtomicU32::new(rand::random()),
        });
        Ok(Self {
            listener,
            tls,
            allow,
            semaphore,
            shared,
            peers,
            #[cfg(feature = "stratum-v2")]
            v2,
        })
    }

    /// A read handle for `getstratuminfo`.
    pub fn handle(&self) -> StratumHandle {
        StratumHandle { shared: self.shared.clone() }
    }

    /// The plaintext listener's bound address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The TLS listener's bound address, when one is configured.
    pub fn local_tls_addr(&self) -> Option<io::Result<SocketAddr>> {
        self.tls.as_ref().map(|(l, _)| l.local_addr())
    }

    /// The Stratum V2 listener's bound address, when one is configured.
    pub fn local_v2_addr(&self) -> Option<io::Result<SocketAddr>> {
        #[cfg(feature = "stratum-v2")]
        return self.v2.as_ref().map(|v| v.listener.local_addr());
        #[cfg(not(feature = "stratum-v2"))]
        None
    }

    /// The Stratum V2 authority public key (x-only), when V2 is configured.
    pub fn authority_pubkey(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "stratum-v2")]
        return self.v2.as_ref().map(|v| v.ctx.authority_public);
        #[cfg(not(feature = "stratum-v2"))]
        None
    }

    /// Serve until `shutdown` flips to `true`.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        tokio::spawn(refresh_loop(self.shared.clone(), self.peers.clone(), shutdown.clone()));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => return,
                accept = self.listener.accept() => {
                    let Some((stream, peer)) = self.admit(accept) else { continue };
                    let Ok(permit) = self.semaphore.clone().try_acquire_owned() else {
                        self.at_capacity(peer);
                        continue;
                    };
                    let shared = self.shared.clone();
                    let conn_shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        super::v1::session::run(stream, peer, shared, conn_shutdown).await;
                    });
                }
                accept = self.accept_v2() => {
                    let Some((stream, peer)) = self.admit(accept) else { continue };
                    let Ok(permit) = self.semaphore.clone().try_acquire_owned() else {
                        self.at_capacity(peer);
                        continue;
                    };
                    self.spawn_v2(stream, peer, permit, shutdown.clone());
                }
                accept = accept_tls(self.tls.as_ref()) => {
                    let Some((stream, peer)) = self.admit(accept) else { continue };
                    let Ok(permit) = self.semaphore.clone().try_acquire_owned() else {
                        self.at_capacity(peer);
                        continue;
                    };
                    let acceptor = self.tls.as_ref().expect("arm is gated on tls").1.clone();
                    let shared = self.shared.clone();
                    let conn_shutdown = shutdown.clone();
                    let allow = self.allow.clone();
                    let mtls = shared.config.mtls;
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(tls) = super::tls::accept(&acceptor, stream, peer, mtls, &allow).await {
                            super::v1::session::run(tls, peer, shared, conn_shutdown).await;
                        }
                    });
                }
            }
        }
    }

    /// The next Stratum V2 connection; never resolves without a V2 listener.
    async fn accept_v2(&self) -> io::Result<(TcpStream, SocketAddr)> {
        #[cfg(feature = "stratum-v2")]
        if let Some(v2) = self.v2.as_ref() {
            return v2.listener.accept().await;
        }
        std::future::pending().await
    }

    #[cfg(feature = "stratum-v2")]
    fn spawn_v2(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        permit: tokio::sync::OwnedSemaphorePermit,
        shutdown: watch::Receiver<bool>,
    ) {
        let Some(v2) = self.v2.as_ref() else { return };
        let ctx = v2.ctx.clone();
        let shared = self.shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            super::v2::session::run(stream, peer, shared, ctx, shutdown).await;
        });
    }

    #[cfg(not(feature = "stratum-v2"))]
    fn spawn_v2(
        &self,
        _stream: TcpStream,
        _peer: SocketAddr,
        _permit: tokio::sync::OwnedSemaphorePermit,
        _shutdown: watch::Receiver<bool>,
    ) {
    }

    fn admit(&self, accept: io::Result<(TcpStream, SocketAddr)>) -> Option<(TcpStream, SocketAddr)> {
        match accept {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                Some((stream, peer))
            }
            Err(e) => {
                tracing::warn!(target: "node::stratum", error = %e, "Stratum accept error");
                None
            }
        }
    }

    fn at_capacity(&self, peer: SocketAddr) {
        static AT_CAPACITY: crate::warn_budget::WarnBudget =
            crate::warn_budget::WarnBudget::new(5, std::time::Duration::from_secs(60));
        if let Some(suppressed) = AT_CAPACITY.tick() {
            tracing::warn!(
                target: "node::stratum",
                %peer,
                suppressed,
                max = self.shared.config.max_conns,
                "Stratum connection refused: at --stratummaxconns"
            );
        }
    }
}


/// Load (or create) the authority key and bind the Stratum V2 listener.
#[cfg(feature = "stratum-v2")]
async fn bind_v2(config: &super::config::V2Config) -> Result<V2Listener, StratumServerError> {
    use super::v2::authority;
    let key_error = |source| StratumServerError::AuthorityKey { path: config.key_path.clone(), source };
    let (private, origin) = authority::load_or_create(&config.key_path).map_err(key_error)?;
    let private = zeroize::Zeroizing::new(private);
    let public = authority::authority_pubkey(&private)
        .map_err(|e| key_error(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|source| StratumServerError::Bind { addr: config.bind, source })?;
    tracing::info!(
        target: "node::stratum",
        path = %config.key_path.display(),
        created = origin == authority::KeyOrigin::Created,
        authority_pubkey = %hex::encode(public),
        authority_pubkey_base58 = %authority::authority_pubkey_base58(&public),
        "Stratum V2 authority key; miners that pin the server's key need this value, \
         and the key file must be backed up with the datadir"
    );
    Ok(V2Listener {
        listener,
        ctx: Arc::new(super::v2::session::V2Context {
            authority_public: public,
            authority_private: private,
            max_channels: config.max_channels,
            jd: config.job_declaration.then(|| Arc::new(super::v2::jd::JobDeclaration::default())),
        }),
    })
}

async fn accept_tls(
    tls: Option<&(TcpListener, TlsAcceptor)>,
) -> io::Result<(TcpStream, SocketAddr)> {
    match tls {
        Some((listener, _)) => listener.accept().await,
        None => std::future::pending().await,
    }
}

/// Keep [`Shared::work`] current: rebuild on every chain event, and every
/// [`REFRESH_INTERVAL`] otherwise.
async fn refresh_loop(
    shared: Arc<Shared>,
    peers: Option<Arc<PeerManager>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut events = shared.chain.subscribe_chain_events();
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut poll = tokio::time::interval(TIP_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut polled_tip = shared.chain.tip_snapshot();
    let mut withheld_warned = false;
    let mut no_peers_warned = false;
    let mut next_work_id = 1u64;
    let network = shared.config.network;

    loop {
        // The first `refresh` tick completes immediately, which builds the
        // initial work.
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            event = next_event(&mut events) => {
                if event.is_none() {
                    // The sender is gone; the tip poll below carries on alone.
                    events = None;
                    continue;
                }
                // A burst of connects (catching up after a restart) needs one
                // rebuild, not one per block.
                if let Some(rx) = events.as_mut() {
                    while rx.try_recv().is_ok() {}
                }
                polled_tip = shared.chain.tip_snapshot();
                refresh.reset();
            }
            _ = refresh.tick() => {
                // The periodic rebuild reads the tip too, so record what it
                // built on; otherwise the next poll sees a tip that "moved"
                // and rebuilds the same work again.
                polled_tip = shared.chain.tip_snapshot();
            }
            // Polled even while events flow: the download scheduler connects
            // blocks without emitting chain events, so a node that catches up
            // that way would otherwise hand out work on an old tip until the
            // next refresh.
            _ = poll.tick() => {
                let tip = shared.chain.tip_snapshot();
                if tip == polled_tip {
                    continue;
                }
                polled_tip = tip;
                refresh.reset();
            }
        }

        let chain = shared.chain.clone();
        let mempool = shared.mempool.clone();
        let built = tokio::task::spawn_blocking(move || {
            if !should_issue_work(network, chain.is_initial_block_download()) {
                return None;
            }
            let template = crate::mining::template::create_template(&chain, &mempool);
            let prev_time = chain
                .get_block_index(&template.prev_hash)
                .map(|e| e.header.time)
                .unwrap_or(0);
            Some(Work::new(template, network, prev_time))
        })
        .await;
        let work = match built {
            Ok(work) => work,
            Err(e) => {
                tracing::error!(target: "node::stratum", error = %e, "Stratum template build panicked");
                continue;
            }
        };
        match work {
            None => {
                if !withheld_warned {
                    tracing::warn!(
                        target: "node::stratum",
                        "stratum: not issuing work during initial block download"
                    );
                    withheld_warned = true;
                }
                shared.work.send_if_modified(|w| w.take().is_some());
            }
            Some(mut work) => {
                work.id = next_work_id;
                next_work_id += 1;
                if withheld_warned {
                    tracing::info!(target: "node::stratum", "stratum: initial block download finished; issuing work");
                    withheld_warned = false;
                }
                if network != Network::Regtest
                    && !no_peers_warned
                    && peers.as_ref().is_some_and(|p| p.connection_count() == 0)
                {
                    tracing::warn!(
                        target: "node::stratum",
                        "stratum: issuing work with no connected peers; a block found now cannot be relayed"
                    );
                    no_peers_warned = true;
                }
                tracing::debug!(
                    target: "node::stratum",
                    height = work.height,
                    txs = work.txdata.len(),
                    fees = work.fees,
                    "Stratum work refreshed"
                );
                shared.work.send_replace(Some(Arc::new(work)));
            }
        }
    }
}

/// The next chain event, or `None` when the channel closed. Never resolves
/// when there is no channel.
async fn next_event(
    events: &mut Option<broadcast::Receiver<crate::chain::events::ChainEvent>>,
) -> Option<()> {
    let Some(rx) = events.as_mut() else {
        return std::future::pending().await;
    };
    match rx.recv().await {
        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => Some(()),
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

/// Hand a found block to the chain and log the outcome. The miner is told the
/// share was accepted whatever happens here: it did its part.
pub(crate) async fn submit_found_block(
    shared: &Shared,
    block: Block,
    height: u32,
    payout: &super::config::Payout,
    peer: SocketAddr,
) {
    let hash = block.block_hash();
    let chain = shared.chain.clone();
    let mempool = shared.mempool.clone();
    // Every caller builds a block only from a header that meets its target;
    // checked again here so no path can fill the directory with blocks that
    // are not blocks.
    let dir = shared
        .config
        .found_block_dir
        .clone()
        .filter(|_| crate::validation::pow::check_proof_of_work(&block.header).is_ok());
    // Where the copy lands. Worked out here rather than returned from the
    // blocking task, because a task that panics returns nothing.
    let expected = dir.as_deref().map(|d| super::found::found_block_path(d, height, &block));
    // Saved on the same blocking thread, ahead of the submission, so a panic
    // in `accept_block` cannot take the only copy with it.
    let outcome = shared
        .core
        .spawn_blocking(move || {
            super::found::save_then_submit(dir.as_deref(), height, &block, |b| submit_block(&chain, &mempool, b)).1
        })
        .await;
    let saved = expected.filter(|p| p.exists()).map(|p| p.display().to_string()).unwrap_or_default();
    let address = payout.address.as_deref().unwrap_or("<--stratumaddress>");
    match outcome {
        Ok(Ok(true)) => {
            shared.stats.blocks_found.fetch_add(1, Ordering::Relaxed);
            *shared.stats.last_block.lock() =
                Some(LastBlock { height, hash, time: crate::time::now_secs() });
            tracing::info!(
                target: "node::stratum",
                %peer,
                height,
                %hash,
                address,
                worker = payout.worker.as_deref().unwrap_or(""),
                "Stratum miner found a block"
            )
        }
        Ok(Ok(false)) => tracing::warn!(
            target: "node::stratum",
            height,
            %hash,
            saved,
            "Stratum block was valid but did not join the active chain"
        ),
        // Point at the saved copy only when there is one: when the save
        // failed (logged above) or no directory is configured, there is none.
        Ok(Err(e)) if saved.is_empty() => tracing::warn!(
            target: "node::stratum",
            height,
            %hash,
            error = %e,
            "Stratum block was not accepted, and no copy of it was saved"
        ),
        Ok(Err(e)) => tracing::warn!(
            target: "node::stratum",
            height,
            %hash,
            error = %e,
            saved,
            "Stratum block was not accepted; the saved copy can be submitted to another node"
        ),
        Err(e) if saved.is_empty() => tracing::error!(
            target: "node::stratum",
            %hash,
            error = %e,
            "Stratum block submission panicked, and no copy of it was saved"
        ),
        Err(e) => tracing::error!(
            target: "node::stratum",
            %hash,
            error = %e,
            saved,
            "Stratum block submission panicked; the saved copy can be submitted to another node"
        ),
    }
}

/// Submit a block a miner found — the `submitblock` sequence.
///
/// Returns whether it joined the active chain. The mempool is cleared of the
/// block's transactions only then: a block that was stored without connecting
/// (a stale sibling) confirms nothing, and removing its transactions would
/// purge live ones.
///
/// Synchronous and heavy; call it from `spawn_blocking`.
pub fn submit_block(chain: &ChainState, mempool: &Mempool, block: &Block) -> Result<bool, String> {
    crate::validation::pow::check_proof_of_work(&block.header).map_err(|e| e.to_string())?;
    let acceptance = chain.accept_block(block).map_err(|e| e.to_string())?;
    if let Some(height) = chain.connected_height(&acceptance) {
        mempool.remove_for_block(block, height);
    }
    Ok(acceptance.connected())
}
