//! Listeners, the template refresh loop, and block submission.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Tip polling interval when no chain-event channel is wired.
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
    next_extranonce1: AtomicU32,
}

impl Shared {
    /// A fresh extranonce1 for a new connection. Unique per connection for
    /// the life of the process (until it wraps), so no two miners hash the
    /// same coinbase.
    pub fn next_extranonce1(&self) -> [u8; 4] {
        self.next_extranonce1.fetch_add(1, Ordering::Relaxed).to_be_bytes()
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
        let allow = ClientAllowList::new(config.mtls_client_allow.iter().cloned());
        let semaphore = Arc::new(Semaphore::new(config.max_conns.max(1)));
        let (work, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            config: Arc::new(config),
            chain,
            mempool,
            work,
            core,
            next_extranonce1: AtomicU32::new(rand::random()),
        });
        Ok(Self { listener, tls, allow, semaphore, shared, peers })
    }

    /// The plaintext listener's bound address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The TLS listener's bound address, when one is configured.
    pub fn local_tls_addr(&self) -> Option<io::Result<SocketAddr>> {
        self.tls.as_ref().map(|(l, _)| l.local_addr())
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
        tracing::warn!(
            target: "node::stratum",
            %peer,
            max = self.shared.config.max_conns,
            "Stratum connection refused: at --stratummaxconns"
        );
    }
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
    let network = shared.config.network;

    loop {
        // The first `refresh` tick completes immediately, which builds the
        // initial work.
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            event = next_event(&mut events) => {
                if event.is_none() {
                    // The sender is gone; fall back to polling the tip.
                    events = None;
                    continue;
                }
                // A burst of connects (catching up after a restart) needs one
                // rebuild, not one per block.
                if let Some(rx) = events.as_mut() {
                    while rx.try_recv().is_ok() {}
                }
                refresh.reset();
            }
            _ = refresh.tick() => {}
            _ = poll.tick(), if events.is_none() => {
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
            Some(work) => {
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
