//! The status snapshot: one read-only picture of the node, for the status
//! page.
//!
//! A simplified, single-page sat-tui. One struct is built per request and
//! both renderings come from it — `/status` as HTML, `/status.json` for the
//! page's own refresh — so they cannot drift apart.
//!
//! What it reads, and what it does not:
//!
//! - The top-line state starts from [`crate::metrics::readiness`], the same
//!   function `/readyz` answers from. The page can say "ready" only when
//!   `/readyz` does.
//! - Sync progress is weighted by [`crate::ibd_eta`]'s cost table, not the
//!   height ratio, and not `verificationprogress`.
//! - Nothing that takes the chain's accept lock or flushes the coin cache:
//!   no `gettxoutsetinfo`. The page is polled every few seconds from every
//!   open tab, and that call would stall block connection each time.
//! - Nothing that names a host or a peer: no peer addresses, no listen
//!   addresses, no error text (which can carry paths). The page may be
//!   served with nothing in front of it.
//!
//! The JSON shape is internal to the page and unstable (`STABILITY_POLICY.md`).

pub mod advertise;
pub mod indexes;
pub mod render;
pub mod startup;

pub use advertise::{Advertised, Surface};

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::{BlockHash, Network};
use parking_lot::Mutex;
use serde::Serialize;

use crate::metrics::{MetricsContext, NotReady};
use crate::storage::Store as _;
use indexes::{IndexReport, IndexState, classify};

/// Inputs the snapshot needs beyond what `/metrics` already has. Built once
/// at startup and shared by every request.
pub struct StatusSources {
    pub listener_status: Arc<crate::rpc::server::ServerListenerStatus>,
    pub addr_backfill: Option<Arc<crate::index::address::BackfillHandle>>,
    pub sp_backfill: Option<Arc<crate::index::silent_payments::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")]
    pub filter_backfill: Option<Arc<crate::index::filter::BackfillHandle>>,
    pub fee_estimator: Arc<crate::mempool::fee::FeeEstimator>,
    /// Configured, which is not the same as serving: a server can be enabled
    /// and still waiting on an index before it binds.
    pub esplora_enabled: bool,
    pub electrum_enabled: bool,
    /// Whether the previous run shut down cleanly.
    pub last_shutdown_clean: bool,
    /// `statusadvertise`, in the order given.
    pub advertise: Vec<Advertised>,
    rates: Mutex<Rates>,
    latest_block: Mutex<Option<LatestBlock>>,
}

impl StatusSources {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listener_status: Arc<crate::rpc::server::ServerListenerStatus>,
        addr_backfill: Option<Arc<crate::index::address::BackfillHandle>>,
        sp_backfill: Option<Arc<crate::index::silent_payments::BackfillHandle>>,
        #[cfg(feature = "block-filter-index")] filter_backfill: Option<
            Arc<crate::index::filter::BackfillHandle>,
        >,
        fee_estimator: Arc<crate::mempool::fee::FeeEstimator>,
        esplora_enabled: bool,
        electrum_enabled: bool,
        last_shutdown_clean: bool,
        advertise: Vec<Advertised>,
    ) -> Self {
        Self {
            listener_status,
            addr_backfill,
            sp_backfill,
            #[cfg(feature = "block-filter-index")]
            filter_backfill,
            fee_estimator,
            esplora_enabled,
            electrum_enabled,
            last_shutdown_clean,
            advertise,
            rates: Mutex::new(Rates::default()),
            latest_block: Mutex::new(None),
        }
    }
}

/// The page's top line, from most to least urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The block connector has given up; the chain cannot advance.
    Stalled,
    /// The best known header is more than a day old: the header chain is
    /// still downloading, so the block count cannot yet be measured against
    /// the real chain.
    SyncingHeaders,
    /// Blocks trail the headers by more than `/readyz` allows.
    SyncingBlocks,
    /// Serving from an AssumeUTXO snapshot while history validates behind it.
    BackgroundValidation,
    /// At the tip, with an enabled index not yet complete.
    BuildingIndexes,
    Ready,
}

/// Everything that decides the phase.
#[derive(Debug, Clone)]
pub struct PhaseInputs {
    /// `/readyz`'s own answer.
    pub readyz: Result<(), NotReady>,
    /// The best header's timestamp is more than a day behind the node clock.
    pub headers_stale: bool,
    pub background_validation: bool,
    pub indexes_building: bool,
}

/// The phase, starting from `/readyz`. `Ready` only when `/readyz` is 200,
/// and never `Ready` or a later phase when it is 503.
pub fn phase(i: &PhaseInputs) -> Phase {
    match &i.readyz {
        Err(NotReady::Stalled) => return Phase::Stalled,
        Err(NotReady::Lag { .. }) if !i.headers_stale => return Phase::SyncingBlocks,
        _ => {}
    }
    if i.headers_stale {
        return Phase::SyncingHeaders;
    }
    if i.background_validation {
        Phase::BackgroundValidation
    } else if i.indexes_building {
        Phase::BuildingIndexes
    } else {
        Phase::Ready
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub version: &'static str,
    pub network: &'static str,
    pub uptime_secs: u64,
    pub phase: Phase,
    /// `/readyz` returns 200.
    pub ready: bool,
    pub warnings: Vec<StatusWarning>,
    /// The previous run did not shut down cleanly.
    pub unclean_shutdown: bool,
    pub sync: SyncStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumeutxo: Option<AssumeUtxoStatus>,
    pub indexes: Vec<NamedIndex>,
    pub services: Services,
    /// The operator's `statusadvertise` values.
    pub connect: Vec<Advertised>,
    pub peers: Peers,
    pub mempool: MempoolStatus,
    /// Absent while syncing, when there is no mempool to estimate from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<Fees>,
    /// Absent while syncing: the tip moves too fast to be worth reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block: Option<LatestBlock>,
}

/// A warning's id and severity. Not its message, which can carry host paths
/// or peer details; `getwarnings` has it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StatusWarning {
    pub id: String,
    pub severity: &'static str,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub blocks: u32,
    pub headers: u32,
    pub tip_time: u32,
    pub header_time: u32,
    /// Cost-weighted share of the way from genesis to the best header.
    pub progress: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks_per_sec: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_per_sec: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssumeUtxoStatus {
    pub snapshot_height: u32,
    pub background_height: u32,
    /// Cost-weighted share of genesis to the snapshot validated so far.
    pub background_progress: f64,
    /// Background validation proved the snapshot invalid.
    pub rejected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamedIndex {
    pub name: &'static str,
    #[serde(flatten)]
    pub state: IndexState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Off,
    /// Enabled, not bound yet.
    Starting,
    Serving,
}

#[derive(Debug, Clone, Serialize)]
pub struct Services {
    pub esplora: ServiceState,
    pub electrum: ServiceState,
    /// A wallet can connect and get complete answers: Electrum or Esplora is
    /// serving, the address index is complete, and the chain is at its tip.
    pub wallets_ready: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Peers {
    pub inbound: usize,
    pub outbound: usize,
    /// Peers per client version, most common first.
    pub clients: Vec<ClientCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientCount {
    pub user_agent: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MempoolStatus {
    pub transactions: usize,
    pub bytes: usize,
    pub min_fee_rate_sat_vb: f64,
}

/// Fee rates to confirm within 1, 3 and 6 blocks, in sat/vB.
#[derive(Debug, Clone, Serialize)]
pub struct Fees {
    pub next_block: f64,
    pub three_blocks: f64,
    pub six_blocks: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatestBlock {
    pub height: u32,
    pub hash: BlockHash,
    pub time: u32,
    pub transactions: usize,
    pub weight: u64,
    /// Coinbase outputs less the subsidy: the fees the miner claimed.
    pub fees_sat: u64,
}

/// Block and header rates, measured over the last minute of requests.
///
/// Measured here rather than in the page's script so that a freshly opened
/// tab has a rate at once, and every tab shows the same one.
#[derive(Debug, Default)]
struct Rates {
    samples: VecDeque<(Instant, u32, u32)>,
}

const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_MIN_SPAN: Duration = Duration::from_secs(5);
const RATE_SAMPLE_EVERY: Duration = Duration::from_secs(1);

impl Rates {
    fn observe(&mut self, now: Instant, blocks: u32, headers: u32) -> (Option<f64>, Option<f64>) {
        if self
            .samples
            .back()
            .is_none_or(|(t, _, _)| now.duration_since(*t) >= RATE_SAMPLE_EVERY)
        {
            self.samples.push_back((now, blocks, headers));
        }
        while self
            .samples
            .front()
            .is_some_and(|(t, _, _)| now.duration_since(*t) > RATE_WINDOW)
        {
            self.samples.pop_front();
        }
        let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) else {
            return (None, None);
        };
        let span = last.0.duration_since(first.0);
        if span < RATE_MIN_SPAN {
            return (None, None);
        }
        let secs = span.as_secs_f64();
        let rate = |a: u32, b: u32| f64::from(b.saturating_sub(a)) / secs;
        (Some(rate(first.1, last.1)), Some(rate(first.2, last.2)))
    }
}

/// The network as the status page names it.
pub fn network_label(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        _ => "regtest",
    }
}

/// Build the snapshot. Reads only in-memory state, the block index, the
/// shared 3-second fee-simulation cache, and one block from disk per new tip
/// once synced.
pub fn build(ctx: &MetricsContext, sources: &StatusSources) -> StatusSnapshot {
    build_at(ctx, sources, crate::time::now_secs())
}

/// [`build`] against a given node-clock reading.
fn build_at(ctx: &MetricsContext, sources: &StatusSources, now: u64) -> StatusSnapshot {
    let cs = &ctx.chain_state;
    let (tip_hash, tip_height) = cs.tip_snapshot();
    let headers = cs.headers_tip_height().max(tip_height);
    let tip_time = cs.get_block_index(&tip_hash).map(|e| e.header.time).unwrap_or(0);
    let header_time = cs
        .get_block_index(&cs.best_header_hash())
        .map(|e| e.header.time)
        .unwrap_or(tip_time)
        .max(tip_time);
    let mainnet = ctx.network == Network::Bitcoin;

    let readyz = crate::metrics::readiness(cs.warnings(), tip_height, cs.headers_tip_height());
    let headers_stale = crate::chain::state::ChainState::time_is_ibd_at(header_time, now);

    let background = cs.background().map(|bg| {
        let snapshot_height = bg.snapshot_height();
        let background_height = bg.tip_height();
        AssumeUtxoStatus {
            snapshot_height,
            background_height,
            background_progress: crate::ibd_eta::weighted_progress(
                0,
                background_height,
                snapshot_height,
                mainnet,
            ),
            rejected: bg.is_rejected(),
        }
    });

    let indexes = index_states(ctx, sources);
    let indexes_building = indexes
        .iter()
        .any(|i| !matches!(i.state, IndexState::Off | IndexState::Synced));

    let phase = phase(&PhaseInputs {
        readyz: readyz.clone(),
        headers_stale,
        background_validation: background.as_ref().is_some_and(|b| !b.rejected),
        indexes_building,
    });
    let syncing = matches!(
        phase,
        Phase::Stalled | Phase::SyncingHeaders | Phase::SyncingBlocks
    );

    let (blocks_per_sec, headers_per_sec) =
        sources.rates.lock().observe(Instant::now(), tip_height, headers);

    let service = |enabled: bool, bound: bool| match (enabled, bound) {
        (_, true) => ServiceState::Serving,
        (true, false) => ServiceState::Starting,
        (false, false) => ServiceState::Off,
    };
    let esplora = service(sources.esplora_enabled, sources.listener_status.esplora_serving());
    let electrum = service(sources.electrum_enabled, sources.listener_status.electrum_serving());
    let address_synced = indexes
        .iter()
        .find(|i| i.name == "address")
        .is_some_and(|i| i.state.is_synced());
    let wallets_ready = !syncing
        && address_synced
        && (esplora == ServiceState::Serving || electrum == ServiceState::Serving);

    let peer_summary = ctx.peer_manager.peer_summary();
    let mut clients: Vec<ClientCount> = peer_summary
        .clients
        .into_iter()
        .map(|(user_agent, count)| ClientCount { user_agent, count })
        .collect();
    clients.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.user_agent.cmp(&b.user_agent)));

    let info = ctx.mempool.info();

    StatusSnapshot {
        version: ctx.version,
        network: network_label(ctx.network),
        uptime_secs: ctx.start_time.elapsed().as_secs(),
        phase,
        ready: readyz.is_ok(),
        warnings: cs
            .warnings()
            .list()
            .into_iter()
            .map(|w| StatusWarning {
                id: w.id,
                severity: match w.severity {
                    crate::warnings::Severity::Error => "error",
                    crate::warnings::Severity::Warn => "warn",
                },
                count: w.count,
            })
            .collect(),
        unclean_shutdown: !sources.last_shutdown_clean,
        sync: SyncStatus {
            blocks: tip_height,
            headers,
            tip_time,
            header_time,
            progress: crate::ibd_eta::weighted_progress(0, tip_height, headers, mainnet),
            blocks_per_sec,
            headers_per_sec,
            eta_secs: ctx.peer_manager.ibd_eta_secs(),
        },
        assumeutxo: background,
        indexes,
        services: Services {
            esplora,
            electrum,
            wallets_ready,
        },
        connect: sources.advertise.clone(),
        peers: Peers {
            inbound: peer_summary.inbound,
            outbound: peer_summary.outbound,
            clients,
        },
        mempool: MempoolStatus {
            transactions: info.size,
            bytes: info.bytes,
            min_fee_rate_sat_vb: info.min_fee_rate as f64 / 1000.0,
        },
        fees: (!syncing).then(|| fees(ctx, sources, info.min_fee_rate)),
        latest_block: if syncing {
            None
        } else {
            latest_block(ctx, sources, tip_hash, tip_height)
        },
    }
}

fn index_states(ctx: &MetricsContext, sources: &StatusSources) -> Vec<NamedIndex> {
    let store = ctx.chain_state.store_ref();
    let mut out = Vec::new();

    let addr = crate::index::address::render_status(sources.addr_backfill.as_deref(), ctx.addr_enabled);
    out.push(NamedIndex {
        name: "address",
        state: classify(&IndexReport {
            enabled: addr.enabled,
            // sat-tui's rule: the on-disk marker the wallet servers gate on.
            complete: store.address_index_complete(),
            backfill_state: addr.state,
            pass: Some(addr.pass.clamp(1, 2)),
            progress: addr.progress_ratio,
            cursor_height: addr.cursor_height,
            snapshot_height: addr.snapshot_height,
            eta_secs: addr.estimated_remaining_seconds,
        }),
    });

    // Listed only when switched on, as sat-tui does, so a node not using the
    // feature does not carry a permanent "off" row.
    let sp = crate::index::silent_payments::render_status(
        sources.sp_backfill.as_deref(),
        ctx.sp_enabled,
        store.silent_payment_index_complete(),
        crate::index::silent_payments::walk_start(ctx.network),
    );
    if sp.enabled || matches!(sp.state.as_str(), "running" | "paused" | "failed") {
        out.push(NamedIndex {
            name: "silent_payments",
            state: classify(&IndexReport {
                enabled: sp.enabled,
                complete: sp.synced,
                backfill_state: sp.state,
                pass: None,
                progress: sp.progress_ratio,
                cursor_height: sp.cursor_height,
                snapshot_height: sp.snapshot_height,
                eta_secs: sp.estimated_remaining_seconds,
            }),
        });
    }

    #[cfg(feature = "block-filter-index")]
    {
        let bf = crate::index::filter::render_status(
            sources.filter_backfill.as_deref(),
            ctx.filter_enabled,
            store.block_filter_index_complete(),
        );
        if bf.enabled || matches!(bf.state.as_str(), "running" | "paused" | "failed") {
            out.push(NamedIndex {
                name: "block_filters",
                state: classify(&IndexReport {
                    enabled: bf.enabled,
                    complete: bf.synced,
                    backfill_state: bf.state,
                    pass: None,
                    progress: bf.progress_ratio,
                    cursor_height: bf.cursor_height,
                    snapshot_height: bf.snapshot_height,
                    eta_secs: bf.estimated_remaining_seconds,
                }),
            });
        }
    }
    out
}

/// The smart-fee ladder every other fee surface serves, from the same
/// 3-second simulation cache Esplora and Electrum share.
fn fees(ctx: &MetricsContext, sources: &StatusSources, min_fee_rate: u64) -> Fees {
    let est = sources.fee_estimator.cached_mempool_estimate(&ctx.mempool);
    let sf = crate::mempool::estimate::smart_fees_from_estimate(
        &est,
        &sources.fee_estimator,
        &[1, 3, 6],
        crate::mempool::estimate::EstimateMode::Blend,
        min_fee_rate.max(1_000),
    );
    let at = |t: u32| {
        sf.targets
            .iter()
            .find(|r| r.target == t)
            .map(|r| r.feerate_sat_per_kvb as f64 / 1000.0)
            .unwrap_or(0.0)
    };
    Fees {
        next_block: at(1),
        three_blocks: at(3),
        six_blocks: at(6),
    }
}

/// The tip block's summary, read from disk once per new tip.
fn latest_block(
    ctx: &MetricsContext,
    sources: &StatusSources,
    tip_hash: BlockHash,
    tip_height: u32,
) -> Option<LatestBlock> {
    let mut cached = sources.latest_block.lock();
    if let Some(b) = cached.as_ref()
        && b.hash == tip_hash
    {
        return Some(b.clone());
    }
    let block = ctx.chain_state.get_block(&tip_hash)?;
    let claimed: u64 = block
        .txdata
        .first()
        .map(|cb| cb.output.iter().map(|o| o.value.to_sat()).sum())
        .unwrap_or(0);
    let fresh = LatestBlock {
        height: tip_height,
        hash: tip_hash,
        time: block.header.time,
        transactions: block.txdata.len(),
        weight: block.weight().to_wu(),
        fees_sat: claimed
            .saturating_sub(crate::chain::connect::block_subsidy(ctx.network, tip_height)),
    };
    *cached = Some(fresh.clone());
    Some(fresh)
}

#[cfg(test)]
mod tests;
