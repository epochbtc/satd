mod config;
mod notify;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Tune jemalloc: return freed pages to the OS faster to reduce RSS bloat.
// Default decay is 10s; under heavy alloc/free churn (LRU eviction, HashMap
// resize) dirty pages accumulate faster than they decay, inflating RSS by 2-3x.
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: &[u8] = b"dirty_decay_ms:1000,muzzy_decay_ms:2000\0";

use config::Config;
use config::ConsensusEngine;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::{Mempool, MempoolConfig};
use node::rpc::auth::RpcAuth;
use node::storage::Store;
use node::storage::flatfile::FlatFileManager;
use node::storage::rocksdb_store::RocksDbStore;
use node::validation::script::{ConsensusVerifier, RustVerifier, ScriptVerifier, ShadowVerifier};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Config must be parsed before tracing init so --log-format can select
    // the formatter. Config parse errors go to stderr as plain text.
    let mut config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match config.log_format {
        config::LogFormat::Json => {
            // Stable JSON shape: `timestamp`, `level`, `target`,
            // `fields.message`, plus any per-event structured fields.
            tracing_subscriber::fmt()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_env_filter(env_filter)
                .init();
        }
        config::LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    // Drain config-load notes (Esplora ↔ txindex reconciliation,
    // prune auto-disable). These were collected before tracing was
    // initialized; emit them now so the operator can see them
    // (round-3 M2).
    for note in config.take_pending_notes() {
        match note.level {
            config::NoteLevel::Info => tracing::info!("{}", note.message),
            config::NoteLevel::Warn => tracing::warn!("{}", note.message),
        }
    }

    tracing::info!(
        network = %config.network,
        datadir = %config.datadir.display(),
        rpcport = config.rpcport,
        "satd v0.1.0 starting"
    );

    // Configure server-wide structured-error switch before any RPC handlers run.
    node::rpc::error::set_extended_enabled(config.rpc_extended_errors);
    if config.rpc_extended_errors {
        tracing::info!(
            "RPC extended errors enabled — responses include data.category/suggestion/debug (non-Core-compat wire format)"
        );
    }

    // Configure server-wide default RPC amount unit before any RPC starts.
    node::rpc::amounts::set_default(config.rpc_default_units);
    if config.rpc_default_units != node::rpc::amounts::AmountUnit::Btc {
        tracing::info!(
            units = config.rpc_default_units.as_str(),
            "RPC default units: integer satoshis (non-Core-compat; clients expecting BTC will see numeric differences)"
        );
    }

    if config.max_ahead < 1000 && config.max_ahead != u32::MAX {
        tracing::warn!(
            max_ahead = config.max_ahead,
            "Low --maxahead value may cause slow IBD block assignment. Consider >= 1000."
        );
    }

    // Create network-specific data directory
    let net_datadir = config.network_datadir();
    if let Err(e) = std::fs::create_dir_all(&net_datadir) {
        eprintln!(
            "Error creating data directory {}: {}",
            net_datadir.display(),
            e
        );
        std::process::exit(1);
    }

    // Consume the clean-shutdown marker from the previous run (if any), BEFORE
    // opening the chain database. Unlinking happens first so a crash during
    // startup always results in "dirty" on the next run.
    let prior_shutdown = node::shutdown::consume_marker(&net_datadir);
    let last_shutdown_clean = prior_shutdown.is_some();
    match &prior_shutdown {
        Some(rec) => tracing::info!(
            tip_height = rec.tip_height,
            tip_hash = %rec.tip_hash,
            "Clean shutdown marker observed — previous exit flushed cleanly"
        ),
        None => tracing::warn!(
            "No clean-shutdown marker — previous exit was dirty or this is a fresh datadir. \
             Block-index replay will run lazily as needed via DataStored→Valid path."
        ),
    }

    // Set up authentication
    let auth = if let (Some(user), Some(pass)) = (&config.rpcuser, &config.rpcpassword) {
        RpcAuth::from_user_pass(user.clone(), pass.clone())
    } else {
        match RpcAuth::generate_cookie(&net_datadir) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Error generating cookie file: {}", e);
                std::process::exit(1);
            }
        }
    };
    let auth = Arc::new(auth);

    // Start a lightweight startup-status RPC server immediately.
    // This lets the TUI show "Loading database..." instead of "Connecting...".
    // It will be stopped once the full RPC server is ready.
    let rpc_bind: SocketAddr = format!("{}:{}", config.rpcbind, config.rpcport)
        .parse()
        .expect("Invalid RPC bind address");
    let startup_progress = node::startup_progress::StartupProgress::new();
    let startup_handle = {
        let progress = startup_progress.clone();
        let auth_clone = auth.clone();
        start_startup_rpc(rpc_bind, auth_clone, progress).await
    };

    // Service-manager heartbeat. On systemd this prevents the unit from
    // hitting TimeoutStartSec during long-running startup phases like
    // `--reindex-chainstate` (hours on mainnet). Each tick reads the
    // shared StartupProgress snapshot and emits both
    //   STATUS=<phase: progress>
    //   EXTEND_TIMEOUT_USEC=120000000
    // The unit file ships TimeoutStartSec=infinity; the heartbeat IS
    // the liveness check — silence for >120s and systemd kills us.
    // No-op on non-systemd hosts (NOTIFY_SOCKET unset) so the same
    // binary works under OpenRC, runit, macOS, plain shell, etc.
    notify::notify_status("Starting up");
    let (heartbeat_stop_tx, heartbeat_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let heartbeat_handle =
        notify::spawn_startup_heartbeat(startup_progress.clone(), heartbeat_stop_rx);

    // Open block storage
    let blocks_dir = net_datadir.join("blocks");

    // Detect legacy redb database and fail fast
    let legacy_redb = net_datadir.join("chainstate.redb");
    if legacy_redb.exists() {
        eprintln!(
            "Error: found legacy redb database at {}.\n\
             The storage engine has changed to RocksDB. To continue:\n\
             1. Delete the old chainstate: rm {}\n\
             2. Restart with --reindex to rebuild from block files, or\n\
             3. Start fresh with a new datadir.",
            legacy_redb.display(),
            legacy_redb.display(),
        );
        auth.cleanup();
        std::process::exit(1);
    }

    // Partition dbcache budget: 1/3 to RocksDB block cache, 2/3 to CoinCache overlays
    let rocksdb_cache_mb = config.dbcache / 3;
    let coincache_mb = config.dbcache - rocksdb_cache_mb;

    let reindex = config.reindex || config.reindex_chainstate;
    let store = match RocksDbStore::open(
        &net_datadir,
        config.txindex,
        rocksdb_cache_mb,
        reindex,
        config.max_open_files,
    ) {
        // Round-1 review H2: tell the Store whether the address +
        // filter indexes are active so `write_batch_mode` can clear
        // the corresponding `*.complete` markers atomically with any
        // connect-with-index-off batch.
        Ok(s) => Box::new(
            s.with_addressindex_enabled(config.addressindex)
                .with_blockfilterindex_enabled(config.blockfilterindex),
        ),
        Err(e) => {
            eprintln!("Error opening chain database: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // Handle -reindex: clear everything, will rebuild from flat files
    if config.reindex {
        startup_progress.set_phase("clearing_db", "Clearing chain database for reindex...");
        tracing::info!("Reindexing: clearing database, will rebuild from block files");
        if let Err(e) = store.clear_all() {
            eprintln!("Error clearing database for reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    } else if config.reindex_chainstate {
        // Handle -reindex-chainstate: clear UTXO/undo, keep block index
        tracing::info!("Reindexing chainstate: clearing UTXO set, will rebuild from block files");
        if let Err(e) = store.clear_chainstate() {
            eprintln!("Error clearing chainstate for reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    }

    let flat_files = match FlatFileManager::new(&blocks_dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error initializing block storage: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // -reindex used to eagerly slurp every block into a `Vec` here so the
    // FlatFileManager could be moved into ChainState; on a fully-synced
    // mainnet that path needs ~900 GB RSS and OOM-kills the process. The
    // reindex now streams directly from disk inside ChainState — no upfront
    // scan needed.

    // Parse assumevalid: Core-compatible semantics + "all" extension
    //   (none)       → per-network default hash
    //   <hash>       → skip scripts at or below that hash
    //   0            → disable (verify all scripts)
    //   all          → skip scripts for ALL blocks (trust network)
    let assumevalid = match config.assumevalid.as_deref() {
        None | Some("") => {
            let av = node::chain::state::default_assumevalid(config.network);
            match &av {
                node::chain::state::AssumeValid::Hash(h) => {
                    tracing::info!(%h, "Using default assumevalid hash");
                }
                node::chain::state::AssumeValid::Disabled => {
                    tracing::info!("No default assumevalid for this network");
                }
                _ => {}
            }
            av
        }
        Some("0") => {
            tracing::info!("assumevalid disabled — verifying all scripts");
            node::chain::state::AssumeValid::Disabled
        }
        Some("all") => {
            tracing::info!(
                max_age_secs = config.assumevalidage,
                "assumevalid=all — skipping script verification for blocks older than {}s",
                config.assumevalidage,
            );
            node::chain::state::AssumeValid::All {
                max_age_secs: config.assumevalidage,
            }
        }
        Some(hash_str) => match hash_str.parse::<bitcoin::BlockHash>() {
            Ok(h) => {
                tracing::info!(%h, "Assuming blocks valid up to hash");
                node::chain::state::AssumeValid::Hash(h)
            }
            Err(e) => {
                eprintln!("Error: invalid assumevalid hash '{}': {}", hash_str, e);
                std::process::exit(1);
            }
        },
    };

    // Initialize chain state with script verification
    startup_progress.set_phase("chain_init", "Initializing chain state...");
    let verifier: Box<dyn ScriptVerifier> = match config.consensus {
        ConsensusEngine::Cpp => Box::new(ConsensusVerifier),
        ConsensusEngine::Rust => {
            tracing::warn!("Using Rust consensus engine — NOT YET VALIDATED FOR PRODUCTION");
            Box::new(RustVerifier)
        }
        ConsensusEngine::RustShadow => {
            tracing::info!("Consensus: rust-shadow (cpp authoritative, rust shadow)");
            Box::new(ShadowVerifier::new(
                Box::new(ConsensusVerifier),
                Box::new(RustVerifier),
                "cpp",
                "rust",
                config.shadow_queue_size,
                config.shadow_workers,
            ))
        }
        ConsensusEngine::CppShadow => {
            tracing::info!("Consensus: cpp-shadow (rust authoritative, cpp shadow)");
            Box::new(ShadowVerifier::new(
                Box::new(RustVerifier),
                Box::new(ConsensusVerifier),
                "rust",
                "cpp",
                config.shadow_queue_size,
                config.shadow_workers,
            ))
        }
    };
    let chain_state = match ChainState::new(
        store,
        flat_files,
        config.network,
        verifier,
        assumevalid,
        coincache_mb as u64,
        config.prefetch_workers,
        node::index::address::AddressIndexConfig {
            enabled: config.addressindex,
            max_subscriptions: config.addrindexsubscriptions,
            ..Default::default()
        },
        // BIP 158 filter index: gated on `--blockfilterindex=basic`.
        // When `enabled = false`, the per-block emit helper is a
        // no-op and the open-time consistency check stamps the
        // completeness marker false on the next connect. The
        // `peer_serve` knob (`--peerblockfilters=1`) gates the BIP
        // 157 P2P service handlers.
        node::index::filter::FilterIndexConfig {
            enabled: config.blockfilterindex,
            peer_serve: config.peerblockfilters,
        },
    ) {
        Ok(cs) => Arc::new(cs),
        Err(e) => {
            eprintln!("Error initializing chain state: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    tracing::info!(
        height = chain_state.tip_height(),
        tip = %chain_state.tip_hash(),
        "Chain state initialized"
    );

    // Open reorg log + optional webhook dispatcher. Failure is non-fatal
    // — the node still runs, just without persistent reorg history.
    match node::chain::reorg_log::ReorgLog::open(
        &net_datadir,
        node::chain::reorg_log::DEFAULT_RING_CAPACITY,
    ) {
        Ok(log) => {
            let reorg_log = Arc::new(log);
            if let Some(url) = config.reorg_webhook.clone() {
                let (tx, rx) =
                    tokio::sync::mpsc::channel::<node::chain::reorg_log::ReorgRecord>(64);
                reorg_log.set_webhook_sender(tx);
                let secret = config.reorg_webhook_secret.clone();
                tokio::spawn(reorg_webhook_dispatcher(url, secret, rx));
            }
            chain_state.attach_reorg_log(reorg_log);
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to open reorg log; running without persistent reorg history");
        }
    }

    // Run reindex replay if requested
    if config.reindex {
        startup_progress.set_phase("reindex_scan", "Scanning block files (phase 1/2)");
        if let Err(e) = chain_state.reindex_from_flat_files(
            config.stopatheight,
            Some(startup_progress.clone()),
        ) {
            eprintln!("Error during reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
        // Mirror PR #185's IBD behavior: when `-stopatheight` is set
        // and reindex halts at the target, exit cleanly. The operator's
        // intent is "bring the chainstate to height H and stop"; if we
        // continued startup we'd stand up RPC + P2P only to have the
        // chain-event watcher tear them down on the first peer-driven
        // block. Restart without `-stopatheight` (and typically with
        // `-connect=0`) to dump or otherwise inspect the result.
        if config.stopatheight.is_some() {
            tracing::info!(
                stop_at = config.stopatheight,
                "Exiting after reindex reached -stopatheight"
            );
            auth.cleanup();
            return;
        }
    } else if config.reindex_chainstate {
        startup_progress.set_phase("reindex_chainstate", "Replaying UTXO set");
        if let Err(e) = chain_state.reindex_chainstate(
            config.stopatheight,
            Some(startup_progress.clone()),
        ) {
            eprintln!("Error during chainstate reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
        if config.stopatheight.is_some() {
            tracing::info!(
                stop_at = config.stopatheight,
                "Exiting after chainstate reindex reached -stopatheight"
            );
            auth.cleanup();
            return;
        }
    }

    // Shutdown channel — created before the mempool so the snapshotter
    // task can subscribe to it.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Initialize mempool with policy from config
    let mempool = Arc::new(Mempool::with_config(MempoolConfig {
        max_size_bytes: config.maxmempool * 1_000_000,
        min_fee_rate: config.minrelaytxfee,
        full_rbf: config.mempoolfullrbf,
        dust_relay_fee: config.dustrelayfee,
        data_carrier: config.datacarrier,
        data_carrier_size: config.datacarriersize,
        max_ancestor_count: config.limitancestorcount,
        max_descendant_count: config.limitdescendantcount,
        expiry_secs: config.mempoolexpiry * 3600,
        permit_bare_multisig: config.permitbaremultisig,
    }));
    let fee_estimator = Arc::new(FeeEstimator::new());

    // Wire the mempool event broadcaster used by `subscribemempool`
    // AND by the address-index mempool variant (M4). The address index
    // task subscribes before any tx admission so it observes every
    // Enter/Leave event from startup onward.
    //
    // Only the index task subscribes to mempool events — the M5
    // notifier piggybacks on the index task (mutate-then-notify in the
    // same tokio arm) so chain/mempool ordering is deterministic.
    let (mempool_event_tx, _) = tokio::sync::broadcast::channel::<
        node::mempool::events::MempoolEvent,
    >(node::mempool::pool::EVENT_BROADCAST_CAPACITY);
    let addr_index_mempool_event_rx = mempool_event_tx.subscribe();
    let events_bus_mempool_rx = mempool_event_tx.subscribe();
    mempool.set_event_sender(mempool_event_tx);

    // Wire the chain-event broadcaster used by the address-index
    // notifier (M5) and any future observability subscribers.
    let (chain_event_tx, _) = tokio::sync::broadcast::channel::<node::chain::events::ChainEvent>(
        node::chain::events::CHAIN_EVENT_BROADCAST_CAPACITY,
    );
    let addr_notifier_chain_event_rx = chain_event_tx.subscribe();
    let events_bus_chain_rx = chain_event_tx.subscribe();

    // -stopatheight watcher: subscribe to chain events and broadcast
    // graceful shutdown when the active-chain tip first reaches the
    // configured height. Matches Bitcoin Core's `-stopatheight`. Uses
    // the chain-event channel rather than polling so the latency
    // between block-connected and shutdown is bounded by the broadcast
    // delivery (microseconds) rather than a polling interval — without
    // this guarantee, fast IBD could advance the tip several blocks
    // past the target before we noticed.
    if let Some(target_height) = config.stopatheight {
        let mut rx = chain_event_tx.subscribe();
        let stop_tx = shutdown_tx.clone();
        let chain_state_for_stop = std::sync::Arc::clone(&chain_state);
        tracing::info!(
            target = target_height,
            "-stopatheight configured; will shut down when tip reaches this height"
        );
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(node::chain::events::ChainEvent::BlockConnected {
                        height,
                        ..
                    }) => {
                        if height >= target_height {
                            tracing::info!(
                                target = target_height,
                                tip = height,
                                "-stopatheight reached; broadcasting shutdown"
                            );
                            let _ = stop_tx.send(true);
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // We don't lose correctness — every chain event
                        // is also reflected in the tip atomic. On lag,
                        // re-check the current tip explicitly so we
                        // don't miss the boundary.
                        if chain_state_for_stop.tip_height() >= target_height {
                            tracing::info!(
                                target = target_height,
                                tip = chain_state_for_stop.tip_height(),
                                "-stopatheight reached after lag-recovery; broadcasting shutdown"
                            );
                            let _ = stop_tx.send(true);
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    chain_state.set_chain_event_sender(chain_event_tx);

    // Stand up the pluggable transport bus.
    //
    // Always-on, even when no external sink is configured: the daemon
    // resolves (and on first start, persists) a UUIDv4 to
    // `<datadir>/node_id`, spawns the mempool / chain bridges, and runs
    // a 1 Hz heartbeat task. With zero external sinks, the resulting
    // envelope `broadcast::send` calls return `Err(SendError)` (no
    // receivers) and are silently dropped — work per event is small
    // but not strictly zero. The trade-off is that operators can enable
    // a sink with a single restart flag, no code path changes.
    let edge_identity = match node::events::EdgeIdentity::resolve(
        &net_datadir,
        config.events_node_id.as_deref(),
        config.events_region.as_deref(),
    ) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("events bus: failed to resolve edge identity: {e}");
            auth.cleanup();
            std::process::exit(1);
        }
    };
    tracing::info!(
        target: "events",
        node_id = %edge_identity.node_id_hex(),
        region = edge_identity.region_str().unwrap_or(""),
        "events bus edge identity resolved",
    );
    let event_publisher =
        node::events::EventPublisher::new(edge_identity, node::events::ENVELOPE_BROADCAST_CAPACITY);
    event_publisher.spawn_bridges(
        events_bus_mempool_rx,
        events_bus_chain_rx,
        shutdown_rx.clone(),
    );
    event_publisher.spawn_heartbeat(
        node::events::publisher::HEARTBEAT_INTERVAL,
        shutdown_rx.clone(),
    );

    // Build configured external sinks. Each sink is feature-gated in
    // the `satd-events` crate; this match enables what the operator
    // asked for via CLI / `bitcoin.conf`.
    let mut event_sinks: Vec<Box<dyn node::events::EventSink>> = Vec::new();
    if let Some(bind) = config.events_grpc_bind.as_deref() {
        match satd_events::GrpcEventSink::bind(
            bind,
            config.events_grpc_allow_remote,
            event_publisher.clone(),
        )
        .await
        {
            Ok(sink) => {
                tracing::info!(
                    target: "events",
                    bind,
                    allow_remote = config.events_grpc_allow_remote,
                    "events gRPC sink configured",
                );
                event_sinks.push(Box::new(sink));
            }
            Err(e) => {
                tracing::error!("events gRPC sink: {e}");
                auth.cleanup();
                std::process::exit(1);
            }
        }
    }
    if let Some(bind) = config.events_zmq_bind.as_deref() {
        let topics = satd_events::ZmqTopicConfig {
            hashtx: config.events_zmq_hashtx,
            hashblock: config.events_zmq_hashblock,
            mpevict: config.events_zmq_mpevict,
            mpreplace: config.events_zmq_mpreplace,
            mpconfirm: config.events_zmq_mpconfirm,
            nodeevent: config.events_zmq_nodeevent,
        };
        match satd_events::ZmqEventSink::bind(bind, topics).await {
            Ok(sink) => {
                tracing::info!(target: "events", bind, "events ZMQ sink configured");
                event_sinks.push(Box::new(sink));
            }
            Err(e) => {
                tracing::error!("events ZMQ sink: {e}");
                auth.cleanup();
                std::process::exit(1);
            }
        }
    }
    if !event_sinks.is_empty() {
        let count = event_publisher.attach_sinks(event_sinks, shutdown_rx.clone());
        tracing::info!(target: "events", sinks = count, "events bus external sinks attached");
    }

    // Hook the mempool back into ChainState so `perform_reorg` can
    // re-add disconnected non-coinbase txs after a reorg (Bitcoin Core
    // semantics). Without this, every reorg would silently drop
    // unconfirmed-but-still-valid user txs.
    chain_state.set_mempool(mempool.clone());

    // Shared MempoolAddrIndex handle. Both the read-side
    // RocksAddressIndex (for RPC queries) and the background
    // event-loop task hold the same Arc<RwLock<...>>.
    let mempool_addr_index = std::sync::Arc::new(parking_lot::RwLock::new(
        node::index::address::MempoolAddrIndex::new(),
    ));

    // Construct the read-side RocksAddressIndex up front so its
    // `subscription_registry()` handle is available to the mempool
    // index task (which fires status-update notifications inline with
    // each event mutation — see `NotifyBundle`).
    let address_index_store: std::sync::Arc<dyn node::storage::Store> =
        chain_state.store_ref().clone();
    let address_index_concrete =
        std::sync::Arc::new(node::index::address::RocksAddressIndex::with_mempool_index(
            address_index_store,
            node::index::address::AddressIndexConfig {
                enabled: config.addressindex,
                max_subscriptions: config.addrindexsubscriptions,
                ..Default::default()
            },
            mempool_addr_index.clone(),
        ));
    let address_index: std::sync::Arc<dyn node::index::address::AddressIndex> =
        address_index_concrete.clone();

    // BIP 158 filter index. Built unconditionally (the runtime knob
    // gates per-block emission); the `Arc<dyn FilterIndex>` is shared
    // by the BIP 157 P2P arms in `PeerManager` and the
    // `getblockfilter` RPC (PR-5). Reads `config.blockfilterindex` so
    // `is_complete()` correctly returns true once the on-disk marker
    // is stamped — without this, the predicate gating the version
    // handshake's `NODE_COMPACT_FILTERS` advertisement would never
    // fire even with the operator opting in via `--peerblockfilters=1`.
    let filter_index_store: std::sync::Arc<dyn node::storage::Store> =
        chain_state.store_ref().clone();
    let filter_index: std::sync::Arc<dyn node_filter_index::FilterIndex> = std::sync::Arc::new(
        node::index::filter::RocksFilterIndex::new(
            filter_index_store,
            node_filter_index::FilterIndexConfig {
                enabled: config.blockfilterindex,
                peer_serve: config.peerblockfilters,
            },
        ),
    );

    {
        let task_index = mempool_addr_index.clone();
        let task_mempool = mempool.clone();
        let task_chain = chain_state.clone();
        let task_shutdown = shutdown_rx.clone();
        let notify = node::index::address::NotifyBundle {
            index: address_index_concrete.clone(),
            registry: address_index_concrete.subscription_registry(),
        };
        tokio::spawn(async move {
            node::index::address::mempool_index_task(
                task_index,
                task_mempool,
                task_chain,
                addr_index_mempool_event_rx,
                task_shutdown,
                Some(notify),
            )
            .await;
        });
    }

    // Open the mempool history ring + spawn the snapshotter task.
    // Failure is non-fatal — the node still runs, but the
    // `getmempoolhistory` RPC reports `available: false` so operators
    // know the feature is off, not just quiet. 10 s cadence × 256-entry
    // ring ≈ 40 min of coverage.
    let mempool_history: Option<Arc<node::mempool::history::MempoolHistory>> =
        match node::mempool::history::MempoolHistory::open(
            &net_datadir,
            node::mempool::history::DEFAULT_RING_CAPACITY,
        ) {
            Ok(h) => {
                let arc = Arc::new(h);
                let snap_arc = arc.clone();
                let snap_mempool = mempool.clone();
                let mut snap_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            _ = snap_shutdown.changed() => break,
                            _ = interval.tick() => {
                                let snap = node::mempool::history::snapshot_from_mempool(&snap_mempool);
                                snap_arc.record_if_changed(snap);
                            }
                        }
                    }
                });
                Some(arc)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open mempool history; getmempoolhistory will report available=false"
                );
                None
            }
        };

    // Initialize P2P peer manager
    let peer_manager = node::net::manager::PeerManager::with_config(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        config.network,
        shutdown_rx.clone(),
        config.prune,
        config.maxconnections,
        config.bantime,
        config.proxy.clone(),
        config.onion.clone(),
        config.prefetch_workers,
        config.max_ahead,
        config.ibd_l0_pause_at,
    );

    // Wire the BIP 158 filter index into the peer manager so the BIP
    // 157 service arms can read filter rows and the version handshake
    // can advertise `NODE_COMPACT_FILTERS` when both runtime knobs say
    // yes (`--blockfilterindex=basic` AND `--peerblockfilters=1`) AND
    // the on-disk completeness marker is true.
    peer_manager.set_filter_index(filter_index.clone(), config.peerblockfilters);

    if config.prune > 0 {
        tracing::info!(target_mb = config.prune, "Block pruning enabled");
    }

    if config.proxy.is_some() {
        tracing::info!(
            proxy = config.proxy.as_deref().unwrap(),
            "SOCKS5 proxy enabled for outbound connections"
        );
    }

    // Start Tor hidden service if -torcontrol is set
    let mut _onion_addr: Option<String> = None;
    if let Some(ref torcontrol) = config.torcontrol {
        match node::net::tor::TorController::connect(torcontrol).await {
            Ok(mut controller) => {
                let password = config.torpassword.as_deref().unwrap_or("");
                match controller.authenticate(password).await {
                    Ok(()) => {
                        let target = format!("127.0.0.1:{}", config.port);
                        match controller.create_hidden_service(config.port, &target).await {
                            Ok(onion) => {
                                tracing::info!(onion_addr = %onion, "Tor hidden service created");
                                _onion_addr = Some(onion);
                            }
                            Err(e) => {
                                tracing::error!("Failed to create Tor hidden service: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Tor control authentication failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to connect to Tor control port: {}", e);
            }
        }
    }

    // Stop the startup RPC server and start the real one on the same port
    startup_handle.stop().expect("Failed to stop startup RPC");
    // Give the port a moment to be released
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let bind_addr = rpc_bind;

    let effective_config_view = config.effective_view();

    // Spawn the chain-driven status-update notifier (M5). The mempool-
    // driven path is folded into `mempool_index_task` above so the
    // index mutation and notification fire as a single unit; this
    // task only handles `BlockConnected` / `BlockDisconnected` events
    // that affect every subscribed scripthash with confirmed history.
    {
        let task_index = address_index_concrete.clone();
        let task_registry = address_index_concrete.subscription_registry();
        let task_chain = chain_state.clone();
        let task_mempool = mempool.clone();
        let task_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            node::index::address::notifier_task(
                task_index,
                task_registry,
                task_chain,
                task_mempool,
                addr_notifier_chain_event_rx,
                task_shutdown,
            )
            .await;
        });
    }

    // Backfill handle (M7). Initial cursor is loaded from persisted
    // metadata so a restart resumes from the last batch boundary
    // (state == Running) or stays idle (state == Idle/Completed/etc).
    let initial_cursor = chain_state.store_ref().read_backfill_cursor();
    if !matches!(
        initial_cursor.state,
        node::index::address::BackfillState::Idle
    ) {
        tracing::info!(
            state = %initial_cursor.state.label(),
            pass = initial_cursor.pass,
            cursor_height = initial_cursor.cursor_height,
            snapshot_height = initial_cursor.snapshot_height,
            "addr-index backfill cursor restored from metadata"
        );
    }
    let backfill_handle =
        std::sync::Arc::new(node::index::address::BackfillHandle::new(initial_cursor));

    // Orphan-temp-CF cleanup: if the persisted cursor isn't actively
    // mid-backfill (Running/Paused) but the temp CF still exists,
    // drop it. This handles the "crashed between mark_completed and
    // drop_cf" window — without this, the temp CF would survive
    // forever after a clean Completed run that was interrupted at
    // exactly the wrong moment.
    if !matches!(
        initial_cursor.state,
        node::index::address::BackfillState::Running | node::index::address::BackfillState::Paused
    ) && chain_state.store_ref().backfill_temp_cf_exists()
        && let Err(e) = chain_state.store_ref().drop_backfill_temp_cf()
    {
        tracing::warn!(error = %e, "failed to drop orphan addr-index backfill temp CF at startup");
    }

    // Backfill supervisor: receives RPC commands, spawns at most one
    // runner at a time. Crash recovery: if persisted cursor.state ==
    // Running on startup AND the address index is enabled, immediately
    // spawn a runner so backfill resumes after a kill -9. `Paused` is
    // sticky — operator must `resumeindex` to continue. `Failed` and
    // other terminal states require a fresh `backfillindex` call.
    let (backfill_cmd_tx, backfill_cmd_rx) =
        tokio::sync::mpsc::channel::<node::index::address::BackfillCommand>(1);
    {
        let handle = backfill_handle.clone();
        let chain = chain_state.clone();
        let addr_cfg = node::index::address::AddressIndexConfig {
            enabled: config.addressindex,
            max_subscriptions: config.addrindexsubscriptions,
            ..Default::default()
        };
        let shutdown = shutdown_rx.clone();
        // Auto-resume on Running OR Paused with the index actually
        // enabled. Skipping the auto-resume when --addressindex=0
        // prevents the supervisor from advancing the cursor through a
        // runner that would refuse to write rows (silently leaving
        // history gaps — see review-1 finding #4).
        //
        // Paused is included so a sticky-paused cursor across restart
        // has a live runner to observe `resumeindex`/`cancelindex`. The
        // runner enters check_pause_loop immediately (paused atomic is
        // initialized from the cursor in BackfillHandle::new) and waits
        // there until the operator hits resume/cancel — see review-2
        // finding #3.
        let auto_resume_state = matches!(
            handle.cursor().state,
            node::index::address::BackfillState::Running
                | node::index::address::BackfillState::Paused
        );
        let resume_on_start = config.addressindex && auto_resume_state;
        if !resume_on_start && auto_resume_state && !config.addressindex {
            tracing::warn!(
                state = %handle.cursor().state.label(),
                "addr-index backfill cursor is active but --addressindex=0; \
                 supervisor will NOT auto-resume — re-enable the index and restart"
            );
        }
        tokio::spawn(async move {
            backfill_supervisor(
                handle,
                chain,
                addr_cfg,
                backfill_cmd_rx,
                shutdown,
                resume_on_start,
            )
            .await;
        });
    }

    // Filter-index backfill state machine. Mirrors the address-index
    // setup above: read persisted cursor, build handle, log on
    // restored state, conditionally auto-resume. The runtime knob
    // comes from `config.blockfilterindex` (added in PR-3 via the
    // `--blockfilterindex=basic|0|1` CLI flag). PR-5 layers the
    // bitcoin.conf alias and the `peerblockfilters` companion knob.
    let blockfilterindex_runtime: bool = config.blockfilterindex;

    let filter_initial_cursor = chain_state.store_ref().read_filter_backfill_cursor();
    if !matches!(
        filter_initial_cursor.state,
        node::index::filter::cursor::BackfillState::Idle
    ) {
        tracing::info!(
            state = %filter_initial_cursor.state.label(),
            cursor_height = filter_initial_cursor.cursor_height,
            snapshot_height = filter_initial_cursor.snapshot_height,
            "filter-index backfill cursor restored from metadata"
        );
    }
    let filter_backfill_handle = std::sync::Arc::new(node::index::filter::BackfillHandle::new(
        filter_initial_cursor,
    ));

    let (filter_backfill_cmd_tx, filter_backfill_cmd_rx) =
        tokio::sync::mpsc::channel::<node::index::filter::BackfillCommand>(1);
    {
        let handle = filter_backfill_handle.clone();
        let chain = chain_state.clone();
        let filter_cfg = node::index::filter::FilterIndexConfig {
            enabled: blockfilterindex_runtime,
            peer_serve: false,
        };
        let shutdown = shutdown_rx.clone();
        let auto_resume_state = matches!(
            handle.cursor().state,
            node::index::filter::cursor::BackfillState::Running
                | node::index::filter::cursor::BackfillState::Paused
        );
        let resume_on_start = blockfilterindex_runtime && auto_resume_state;
        if !resume_on_start && auto_resume_state && !blockfilterindex_runtime {
            tracing::warn!(
                state = %handle.cursor().state.label(),
                "filter-index backfill cursor is active but blockfilterindex=0; \
                 supervisor will NOT auto-resume — re-enable the index and restart"
            );
        }
        tokio::spawn(async move {
            filter_backfill_supervisor(
                handle,
                chain,
                filter_cfg,
                filter_backfill_cmd_rx,
                shutdown,
                resume_on_start,
            )
            .await;
        });
    }

    // Keep a clone of the shutdown sender in main so Ctrl-C / SIGTERM
    // can broadcast shutdown to all watch receivers (including the
    // backfill supervisor + runner). The RPC server takes its own
    // clone for the `stop` RPC path. Without this, signal-driven
    // shutdown would proceed to the flush phase without notifying
    // long-running blocking tasks like the backfill runner, which
    // would keep the Tokio runtime alive past the deadline.
    let shutdown_signal_tx = shutdown_tx.clone();
    // Live listener status — populated as each optional server (Esplora,
    // Electrum, Electrum TLS) successfully binds below. Read by the
    // `getserverstatus` RPC. Created before rpc::start so the RPC
    // handler holds the same Arc the bind sites mutate.
    let listener_status = node::rpc::server::ServerListenerStatus::new();

    // Optional JSON-RPC TLS surface. Bitcoin Core's RPC is HTTP-only;
    // this is a satd-specific addition for operators who want native
    // TLS without a reverse proxy. Partial-config (bind without
    // cert/key, or vice versa) was already rejected at config-load
    // time; here we just parse the bind addr.
    let rpc_tls = match (
        config.rpc_tls_bind.as_deref(),
        config.rpc_tls_cert.as_deref(),
        config.rpc_tls_key.as_deref(),
    ) {
        (Some(addr_str), Some(cert), Some(key)) => match addr_str.parse::<SocketAddr>() {
            Ok(bind_addr) => Some(node::rpc::server::RpcTlsConfig {
                bind_addr,
                cert_path: cert.to_path_buf(),
                key_path: key.to_path_buf(),
                mtls_enabled: config.rpc_mtls,
                mtls_client_ca: config.rpc_mtls_client_ca.clone(),
                mtls_client_allow: config.rpc_mtls_client_allow.clone(),
                handshake_timeout: std::time::Duration::from_secs(
                    config.rpc_tls_handshake_timeout,
                ),
                // Default 100 mirrors jsonrpsee's
                // `ServerConfig::max_connections`. The plain-HTTP
                // path's cap; the TLS surface keeps the same default
                // so operator expectations don't drift between paths.
                max_connections: 100,
            }),
            Err(e) => {
                eprintln!("Error: invalid --rpctlsbind {addr_str:?}: {e}");
                auth.cleanup();
                std::process::exit(1);
            }
        },
        (None, None, None) => None,
        _ => {
            // Should be unreachable given config-load validation, but
            // be explicit so a future refactor doesn't silently drop the
            // partial-config gate.
            eprintln!("Error: --rpctlsbind requires --rpctlscert AND --rpctlskey");
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // When `--rpcdisableauth=1` is combined with `--rpcmtls=1`, the
    // TLS surface gets a separate "auth disabled" handle so the
    // rustls handshake is the only gate. The plain-HTTP surface
    // always retains full auth — config-load validation enforces that
    // `rpc_disable_auth` requires `rpc_mtls`, so this branch only
    // fires when both are set.
    let tls_auth = if config.rpc_disable_auth {
        Some(std::sync::Arc::new(node::rpc::auth::RpcAuth::Disabled))
    } else {
        None
    };
    let server_handle = match node::rpc::server::start(
        bind_addr,
        rpc_tls,
        auth.clone(),
        tls_auth,
        chain_state.clone(),
        mempool.clone(),
        peer_manager.clone(),
        fee_estimator.clone(),
        shutdown_tx,
        last_shutdown_clean,
        effective_config_view,
        mempool_history.clone(),
        address_index.clone(),
        config.addressindex,
        Some(backfill_handle.clone()),
        Some(backfill_cmd_tx.clone()),
        listener_status.clone(),
        // BIP 158 filter index: passed unconditionally because `node`'s
        // `block-filter-index` feature is always on in any workspace
        // build of `satd` (esplora-handlers / electrum-proto pull node
        // in without `default-features = false`, so Cargo unifies the
        // feature on regardless of satd's per-binary feature gate).
        config.blockfilterindex,
        Some(filter_index.clone()),
        Some(filter_backfill_handle.clone()),
        Some(filter_backfill_cmd_tx.clone()),
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error starting RPC server: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    tracing::info!(%bind_addr, "RPC server listening");

    // Start MCP server if enabled
    if config.mcp {
        let mcp_ctx = std::sync::Arc::new(satd_mcp::McpContext {
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            peer_manager: peer_manager.clone(),
            fee_estimator: fee_estimator.clone(),
            start_time: std::time::Instant::now(),
            network: config.network,
            effective_config: config.effective_view(),
            mempool_history: mempool_history.clone(),
        });

        if config.mcp_stdio {
            let ctx = mcp_ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = satd_mcp::serve_stdio(ctx).await {
                    tracing::error!("MCP stdio server error: {}", e);
                }
            });
            tracing::info!("MCP stdio server started");
        }

        if let Some(mcp_port) = config.mcp_port {
            let mcp_bind: SocketAddr = format!("{}:{}", config.mcp_bind, mcp_port)
                .parse()
                .expect("Invalid MCP bind address");
            let ctx = mcp_ctx.clone();
            let rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = satd_mcp::serve_http(ctx, mcp_bind, rx).await {
                    tracing::error!("MCP HTTP server error: {}", e);
                }
            });
        }
    }

    // Start metrics/health HTTP server if enabled (unauthenticated — bind to
    // loopback by default, or firewall externally).
    if let Some(metricsport) = config.metricsport {
        let metrics_bind: SocketAddr = format!("{}:{}", config.metricsbind, metricsport)
            .parse()
            .expect("Invalid metrics bind address");
        let metrics_ctx = node::metrics::MetricsContext {
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            peer_manager: peer_manager.clone(),
            network: config.network,
            start_time: std::time::Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            addr_subs: Some(address_index_concrete.subscription_registry()),
            addr_enabled: config.addressindex,
        };
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = node::metrics::serve_metrics_http(metrics_ctx, metrics_bind, rx).await {
                tracing::error!("Metrics HTTP server error: {}", e);
            }
        });
    }

    // Start the Esplora REST server if enabled. Refuses to bind when
    // `--addressindex=0` so operators don't end up with an HTTP
    // surface that 503's every read-side endpoint. Also requires
    // `--txindex=1` (review H3) — without it, confirmed tx lookups
    // would 404 silently and fees would report as null. Auth init
    // failure, CORS validation, and the listener bind itself are ALL
    // fatal at startup (review H1, H4); an operator who explicitly
    // enabled Esplora must not see the daemon come up "successfully"
    // without the listener.
    if config.esplora {
        if !config.addressindex {
            tracing::warn!(
                "esplora server requested but --addressindex=0; refusing to start (Esplora reads through the address index)"
            );
        } else {
            // The esplora ↔ txindex coupling is reconciled in
            // config::from_cli (review-2 H3): by the time we get
            // here, config.esplora=true implies config.txindex=true.
            debug_assert!(
                config.txindex,
                "config invariant: esplora=true must imply txindex=true after Config::load"
            );
            // Round-3 H1: txindex completeness check.
            //
            // The runtime flag tells us txindex is enabled, but the
            // CF could be partially populated from a previous
            // `--txindex=0` run. With Esplora on, that produces
            // false 404s for historical confirmed txs — exactly the
            // failure mode round-1's H3 hard-fail was designed to
            // prevent. Refuse to start the listener and tell the
            // operator how to fix.
            if !chain_state.store_ref().tx_index_complete() {
                eprintln!(
                    "Error: esplora is enabled and --txindex=1, but the on-disk tx_index \n\
                     CF is incomplete (this datadir was previously synced with \n\
                     --txindex=0). Restart with --reindex-chainstate to populate \n\
                     historical rows, or set --esplora=0 to skip the tx-endpoint surface."
                );
                auth.cleanup();
                std::process::exit(1);
            }
            // Round-2 review H1: same address-index completeness gate
            // as the Electrum startup path. Esplora's `/address/*`
            // endpoints read through `address_index.confirmed_history`
            // and `address_index.utxos`; without this check they would
            // return well-formed but partial historical results on a
            // datadir that was previously synced with --addressindex=0.
            if !chain_state.store_ref().address_index_complete() {
                eprintln!(
                    "Error: esplora is enabled and --addressindex=1, but the on-disk \n\
                     address-history CFs are incomplete (this datadir was previously \n\
                     synced with --addressindex=0, or the backfill has not finished). \n\
                     Run the address-index backfill to completion before enabling \n\
                     Esplora, or restart with --reindex-chainstate. Set --esplora=0 \n\
                     to skip the Esplora listener."
                );
                auth.cleanup();
                std::process::exit(1);
            }
            let bind: SocketAddr = config
                .esplora_bind
                .parse()
                .expect("Invalid esplora bind address");
            let auth_cfg = match &config.esplora_auth {
                crate::config::EsploraAuthMode::None => esplora_handlers::EsploraAuth::None,
                crate::config::EsploraAuthMode::Cookie => {
                    let path = config
                        .esplora_cookie_file
                        .clone()
                        .unwrap_or_else(|| net_datadir.join(".cookie"));
                    esplora_handlers::EsploraAuth::Cookie { path }
                }
                crate::config::EsploraAuthMode::UserPass => {
                    let (u, p) = config
                        .esplora_userpass
                        .clone()
                        .expect("esplora userpass validated at config-load");
                    esplora_handlers::EsploraAuth::UserPass {
                        username: u,
                        password: p,
                    }
                }
            };
            let esplora_cfg = esplora_handlers::EsploraConfig {
                enabled: true,
                bind: config.esplora_bind.clone(),
                tls_bind: config.esplora_tls_bind.clone(),
                tls_cert_path: config.esplora_tls_cert.clone(),
                tls_key_path: config.esplora_tls_key.clone(),
                mtls_enabled: config.esplora_mtls,
                mtls_client_ca: config.esplora_mtls_client_ca.clone(),
                mtls_client_allow: config.esplora_mtls_client_allow.clone(),
                prefix: config.esplora_prefix.clone(),
                cors_origins: config.esplora_cors.clone(),
                request_timeout: std::time::Duration::from_secs(config.esplora_request_timeout),
                max_concurrency: config.esplora_max_conns,
                max_sse_conns: config.esplora_sse_max_conns,
                auth: auth_cfg,
            };
            // Semaphore sized for SSE only — distinct from the request
            // concurrency layer which doesn't bound long-lived streams
            // (review M2). `0` means "no cap"; we still use a sized-1
            // semaphore + add_permits so try_acquire never fails in
            // that mode.
            let sse_cap = if config.esplora_sse_max_conns == 0 {
                let s = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
                s.add_permits(usize::MAX >> 8);
                s
            } else {
                std::sync::Arc::new(tokio::sync::Semaphore::new(config.esplora_sse_max_conns))
            };
            let state = esplora_handlers::EsploraState {
                chain: chain_state.clone(),
                mempool: mempool.clone(),
                address_index: address_index.clone(),
                spend_index: Arc::new(node::index::outpoint_spend::lookups::RocksSpendIndex::new(
                    chain_state.store_ref().clone(),
                    Arc::new(node::index::address::AddressIndexConfig {
                        enabled: config.addressindex,
                        max_subscriptions: config.addrindexsubscriptions,
                        ..Default::default()
                    }),
                )),
                fee_estimator: fee_estimator.clone(),
                network: config.network,
                config: Arc::new(esplora_cfg),
                sse_semaphore: sse_cap,
            };
            // Auth/CORS/prefix validation surfaces here. A misconfigured
            // auth scheme is a user-visible exit, not a silent fall-back
            // to no-auth (review H1, L2).
            let router = match esplora_handlers::build_router(state) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: esplora startup failed: {e}");
                    auth.cleanup();
                    std::process::exit(1);
                }
            };
            // Bind synchronously so a port conflict / permissions error
            // becomes a daemon startup failure rather than a logged
            // warning in a detached task (review H4).
            let listener = match tokio::net::TcpListener::bind(bind).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error: esplora listener could not bind to {bind}: {e}");
                    auth.cleanup();
                    std::process::exit(1);
                }
            };
            // TLS listener (optional). Same pattern as Electrum:
            // load the cert/key + bind the TLS port synchronously so
            // a misconfigured TLS surface is a startup-fatal error
            // rather than a logged warning on the first handshake.
            let tls_handshake_timeout =
                std::time::Duration::from_secs(config.esplora_request_timeout);
            let tls_setup = match (
                config.esplora_tls_bind.as_ref(),
                config.esplora_tls_cert.as_ref(),
                config.esplora_tls_key.as_ref(),
            ) {
                (None, _, _) => None,
                (Some(_), None, _) | (Some(_), _, None) => {
                    eprintln!(
                        "Error: --esploratlsbind requires --esploratlscert AND --esploratlskey"
                    );
                    auth.cleanup();
                    std::process::exit(1);
                }
                (Some(addr_str), Some(cert), Some(key)) => {
                    let tls_bind: SocketAddr = match addr_str.parse() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "Error: invalid --esploratlsbind {addr_str:?}: {e}"
                            );
                            auth.cleanup();
                            std::process::exit(1);
                        }
                    };
                    // mTLS policy: when --esploramtls=1, build the
                    // acceptor with `Required` so rustls refuses any
                    // client without a CA-signed cert at handshake
                    // time. Validation above already ensured the CA
                    // path is set in that branch.
                    let policy = if config.esplora_mtls {
                        esplora_handlers::ClientAuthPolicy::Required {
                            ca_path: config
                                .esplora_mtls_client_ca
                                .clone()
                                .expect("config validation enforces CA when mtls=1"),
                        }
                    } else {
                        esplora_handlers::ClientAuthPolicy::Disabled
                    };
                    let acceptor = match esplora_handlers::build_acceptor(cert, key, &policy) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("Error: esplora TLS config: {e}");
                            auth.cleanup();
                            std::process::exit(1);
                        }
                    };
                    let tls_listener =
                        match tokio::net::TcpListener::bind(tls_bind).await {
                            Ok(l) => l,
                            Err(e) => {
                                eprintln!(
                                    "Error: esplora TLS listener could not bind to {tls_bind}: {e}"
                                );
                                auth.cleanup();
                                std::process::exit(1);
                            }
                        };
                    Some((tls_bind, tls_listener, acceptor))
                }
            };
            // Use the listener's actual bound address — when the
            // operator passes `--esplorabind=127.0.0.1:0`, the
            // configured `bind` value still reads as `:0`, but the OS
            // has assigned a real port. `getserverstatus` callers
            // (sat-tui, ops scripts, integration tests) need the
            // actual port.
            let reported_bind = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| bind.to_string());
            tracing::info!(
                bind = %reported_bind,
                tls_bind = ?tls_setup.as_ref().map(|(a, _, _)| *a),
                "Esplora REST listening"
            );
            listener_status.set_esplora(reported_bind);
            let mut esplora_shutdown = shutdown_rx.clone();
            // The plain and TLS arms share the same `router` (axum's
            // Router is Clone-cheap). They observe the same shutdown
            // watch, so SIGTERM gracefully drains both surfaces.
            let plain_router = router.clone();
            tokio::spawn(async move {
                let serve =
                    axum::serve(listener, plain_router).with_graceful_shutdown(async move {
                        let _ = esplora_shutdown.changed().await;
                    });
                if let Err(e) = serve.await {
                    tracing::error!(error = %e, "Esplora server error");
                }
            });
            if let Some((tls_bind, tls_listener, acceptor)) = tls_setup {
                let tls_router = router.clone();
                let mut tls_shutdown = shutdown_rx.clone();
                let allow = esplora_handlers::ClientAllowList::new(
                    config.esplora_mtls_client_allow.iter().cloned(),
                );
                let tls_wrap = esplora_handlers::TlsListener::new_with_mtls(
                    tls_listener,
                    acceptor,
                    tls_handshake_timeout,
                    config.esplora_mtls,
                    allow,
                );
                tokio::spawn(async move {
                    let serve = axum::serve(tls_wrap, tls_router)
                        .with_graceful_shutdown(async move {
                            let _ = tls_shutdown.changed().await;
                        });
                    if let Err(e) = serve.await {
                        tracing::error!(
                            error = %e,
                            %tls_bind,
                            "Esplora TLS server error",
                        );
                    }
                });
            }
        }
    }

    // Start the Electrum server if enabled. Refuses to bind when
    // addressindex=0 (already enforced by Config::load) or when the
    // tx_index CF is incomplete (a datadir previously synced with
    // --txindex=0 has historical gaps that would 404 silently). Bind
    // failure is fatal, mirroring the Esplora pattern above.
    if config.electrum {
        if !chain_state.store_ref().tx_index_complete() {
            eprintln!(
                "Error: electrum is enabled and --txindex=1, but the on-disk tx_index \n\
                 CF is incomplete (this datadir was previously synced with \n\
                 --txindex=0). Restart with --reindex-chainstate to populate \n\
                 historical rows, or set --electrum=0 to skip the Electrum server."
            );
            auth.cleanup();
            std::process::exit(1);
        }
        // Round-1 review H2: refuse to bind Electrum when the
        // address-history CFs are known to be partial. Without this
        // check, a datadir previously synced with --addressindex=0
        // (then flipped on alongside --electrum=1) would serve
        // well-formed but partial scripthash histories indistinguishable
        // from real "no history" answers — a silent correctness bug.
        // The marker is set true on a fresh sync from genesis with
        // addressindex on, or after the address-index backfill
        // completes pass 2.
        if !chain_state.store_ref().address_index_complete() {
            eprintln!(
                "Error: electrum is enabled and --addressindex=1, but the on-disk \n\
                 address-history CFs are incomplete (this datadir was previously \n\
                 synced with --addressindex=0, or the backfill has not finished). \n\
                 Run the address-index backfill to completion before enabling \n\
                 Electrum, or restart with --reindex-chainstate. Set --electrum=0 \n\
                 to skip the Electrum server."
            );
            auth.cleanup();
            std::process::exit(1);
        }
        // Bind-address parsing exits cleanly on invalid input rather
        // than panicking (review H3). The plain-bind value comes from
        // an unvalidated CLI/config string — `.expect()` would surface
        // an operator typo as a SIGABRT instead of a friendly message.
        let electrum_bind: SocketAddr = match config.electrum_bind.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "Error: invalid --electrumbind {:?}: {e}",
                    config.electrum_bind
                );
                auth.cleanup();
                std::process::exit(1);
            }
        };
        let electrum_tls_bind = match config
            .electrum_tls_bind
            .as_ref()
            .map(|s| (s, s.parse::<SocketAddr>()))
        {
            None => None,
            Some((_, Ok(a))) => Some(a),
            Some((raw, Err(e))) => {
                eprintln!("Error: invalid --electrumtlsbind {raw:?}: {e}");
                auth.cleanup();
                std::process::exit(1);
            }
        };
        let electrum_cfg = electrum_proto::ElectrumConfig {
            bind: electrum_bind,
            tls_bind: electrum_tls_bind,
            tls_cert_path: config.electrum_tls_cert.clone(),
            tls_key_path: config.electrum_tls_key.clone(),
            mtls_enabled: config.electrum_mtls,
            mtls_client_ca: config.electrum_mtls_client_ca.clone(),
            mtls_client_allow: config.electrum_mtls_client_allow.clone(),
            banner: config.electrum_banner.clone(),
            donation_address: String::new(),
            max_history_entries: electrum_proto::config::MAX_HISTORY_ENTRIES,
            max_headers_per_request: electrum_proto::config::MAX_HEADERS_PER_REQUEST,
            max_conns: config.electrum_max_conns,
            max_subs_per_conn: config.electrum_max_subs_per_conn,
            request_timeout: std::time::Duration::from_secs(config.electrum_request_timeout),
            max_batch_requests: config.electrum_max_batch_requests,
            max_broadcast_package_txs: config.electrum_max_broadcast_package_txs,
            fee_histogram_ttl: std::time::Duration::from_secs(config.electrum_fee_histogram_ttl),
        };
        let electrum_extras: std::sync::Arc<dyn electrum_proto::ElectrumExtras> =
            std::sync::Arc::new(electrum_proto::RocksElectrumExtras::new(
                chain_state.clone(),
            ));
        let spend_index: std::sync::Arc<dyn node_index::SpendIndex> =
            std::sync::Arc::new(node::index::outpoint_spend::lookups::RocksSpendIndex::new(
                chain_state.store_ref().clone(),
                Arc::new(node::index::address::AddressIndexConfig {
                    enabled: config.addressindex,
                    max_subscriptions: config.addrindexsubscriptions,
                    ..Default::default()
                }),
            ));
        let electrum_state = std::sync::Arc::new(electrum_proto::ElectrumState {
            chain: chain_state.clone(),
            mempool: mempool.clone(),
            address_index: address_index.clone(),
            spend_index,
            fee_estimator: fee_estimator.clone(),
            electrum_extras,
            network: config.network,
            config: std::sync::Arc::new(electrum_cfg.clone()),
            fee_histogram_cache: std::sync::Arc::new(
                electrum_proto::handlers::mempool::FeeHistogramCache::new(
                    electrum_cfg.fee_histogram_ttl,
                ),
            ),
        });
        let server = match electrum_proto::ElectrumServer::bind(electrum_cfg, electrum_state).await
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: electrum server bind failed: {e}");
                auth.cleanup();
                std::process::exit(1);
            }
        };
        // Mirror the Esplora fix: read back actual bound addresses
        // from the listener so `--electrumbind=127.0.0.1:0` reports
        // the OS-assigned port via `getserverstatus`. Fall back to
        // the configured value if `local_addr()` errors (rare; mostly
        // for parity with the old behaviour if the listener somehow
        // doesn't know its own address).
        let reported_electrum_bind = server
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| electrum_bind.to_string());
        let reported_electrum_tls_bind = match (server.local_tls_addr(), electrum_tls_bind) {
            (Some(Ok(a)), _) => Some(a.to_string()),
            (Some(Err(_)), Some(cfg)) => Some(cfg.to_string()),
            (None, _) | (Some(Err(_)), None) => None,
        };
        tracing::info!(
            bind = %reported_electrum_bind,
            tls_bind = ?reported_electrum_tls_bind,
            "Electrum server listening"
        );
        listener_status.set_electrum(reported_electrum_bind);
        if let Some(tls_bind) = reported_electrum_tls_bind {
            listener_status.set_electrum_tls(tls_bind);
        }
        let electrum_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            server.serve(electrum_shutdown).await;
        });
    }

    // Write PID file if requested
    if let Some(ref pid_path) = config.pid
        && let Err(e) = std::fs::write(pid_path, std::process::id().to_string())
    {
        eprintln!("Warning: failed to write PID file {}: {}", pid_path, e);
    }

    // Start P2P networking
    if config.listen {
        let p2p_addr: SocketAddr = format!("{}:{}", config.bind, config.port)
            .parse()
            .expect("Invalid P2P bind address");
        let pm = peer_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = pm.listen(p2p_addr).await {
                tracing::error!("P2P listener error: {}", e);
            }
        });
        tracing::info!(port = config.port, "P2P listening");
    }

    // Connect to configured peers (and register for auto-reconnect)
    for addr_str in &config.connect {
        match node::net::peer::PeerAddr::parse(addr_str) {
            Ok(addr) => {
                peer_manager.add_peer_addr(addr.clone());
                let pm = peer_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::warn!(%addr, "Failed to connect to peer: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = addr_str, "Invalid connect address: {}", e);
            }
        }
    }

    // Connect to -addnode peers (does NOT disable DNS seeding)
    for addr_str in &config.addnode {
        match node::net::peer::PeerAddr::parse(addr_str) {
            Ok(addr) => {
                peer_manager.add_peer_addr(addr.clone());
                let pm = peer_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::warn!(%addr, "Failed to connect to addnode peer: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = addr_str, "Invalid addnode address: {}", e);
            }
        }
    }

    // DNS seeding: only if no explicit --connect peers and --dns is enabled
    if config.connect.is_empty() && config.dns {
        let seed_addrs =
            node::net::dns::resolve_seeds(config.network, config.proxy.as_deref()).await;
        let max_dns_outbound = 64;
        for addr in seed_addrs.into_iter().take(max_dns_outbound) {
            peer_manager.add_peer_addr(addr.clone());
            let pm = peer_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = pm.connect_peer_addr(&addr).await {
                    tracing::warn!(%addr, "Seed peer connection failed: {}", e);
                }
            });
        }
    }

    // Spawn P2P event loop
    {
        let pm = peer_manager.clone();
        tokio::spawn(async move { pm.run().await });
    }

    // Spawn adaptive-dbcache controller if --dbcache=auto was requested.
    // It resizes the RocksDB block cache and the CoinCache clean LRU every
    // 30 seconds based on /proc/meminfo MemAvailable.
    if config.dbcache_mode.is_auto() {
        let max_bytes = config.dbcache as u64 * 1_000_000;
        let cs = chain_state.clone();
        let rx = shutdown_rx.clone();
        node::adaptive_cache::spawn_adaptive_cache(cs, max_bytes, rx);
        tracing::info!(
            max_mb = config.dbcache,
            "Adaptive dbcache enabled — cap set to max budget, adjusted from /proc/meminfo"
        );
    }

    // Stall watchdog: dedicated OS thread that detects connector wedges
    // and dumps thread states (and after a grace period, aborts so systemd
    // restarts us). Deliberately not a tokio task — the wedge we are
    // protecting against parks every tokio worker, so a tokio-scheduled
    // watchdog would freeze with the rest.
    node::stall_watchdog::spawn_stall_watchdog(
        chain_state.clone(),
        std::time::Duration::from_secs(config.stall_watchdog_secs),
        std::time::Duration::from_secs(config.stall_abort_secs),
        shutdown_rx.clone(),
    );

    // Periodic forced-compaction thread: backstop for RocksDB compaction
    // falling behind. Forces a chainstate compaction when the L0 file count
    // stays above the configured threshold for a full interval. Synchronous
    // and long-running, so it gets its own OS thread rather than a tokio
    // worker.
    node::stall_watchdog::spawn_periodic_compactor(
        chain_state.clone(),
        std::time::Duration::from_secs(config.compaction_interval_secs),
        config.compaction_l0_at,
        shutdown_rx.clone(),
    );

    // All listeners bound, all background tasks spawned. Tell the
    // service manager we're up. This stops the startup heartbeat and
    // transitions the systemd unit to `active (running)`; dependent
    // units (Tor onion services, watchtower processes pointing at our
    // RPC) start now. IBD continues in the background — operators that
    // care about chain-tip readiness should poll `getblockchaininfo`,
    // not the unit state.
    let _ = heartbeat_stop_tx.send(());
    let _ = heartbeat_handle.await;
    notify::notify_ready();

    // Wait for shutdown signal (stop RPC, Ctrl+C, or SIGTERM)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to register SIGTERM handler");
    tokio::select! {
        _ = shutdown_rx.wait_for(|v| *v) => {
            tracing::info!("Shutdown signal received from RPC");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down");
            // Broadcast shutdown so the backfill runner + supervisor
            // and any other watch subscribers exit promptly. Without
            // this, a paused or running blocking task could keep the
            // Tokio runtime alive past the flush deadline.
            let _ = shutdown_signal_tx.send(true);
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down");
            let _ = shutdown_signal_tx.send(true);
        }
    }

    // Tell the service manager we're shutting down BEFORE the blocking
    // RocksDB flush. Operators running `systemctl stop satd` or watching
    // `systemctl status satd` see "deactivating" immediately rather than
    // staring at "active" for the full TimeoutStopSec while the flush
    // runs.
    notify::notify_stopping();

    // Graceful shutdown — flush UTXO cache before stopping, bounded by
    // --max-shutdown-secs so we actually exit within the deadline no matter
    // how long the blocking flush takes.
    //
    // Implementation note: tokio::task::spawn_blocking cannot be aborted, and
    // tokio's runtime shutdown will wait for blocking tasks to complete. If
    // we only wrapped it in tokio::time::timeout, the outer await would
    // return but the process would still hang until the flush finishes (or
    // forever, on a stuck flush). To genuinely enforce the deadline we run
    // the flush on a dedicated std::thread, signal completion over a oneshot,
    // and std::process::exit on timeout — that's the only way to end the
    // process when the flush is stuck inside the rocksdb FFI.
    //
    // Safety on timeout-forced exit: no data is lost. The next startup will
    // replay any DataStored-but-not-Valid blocks from flat files. We just
    // lose the clean-shutdown marker (which advertises "we flushed cleanly").
    let shutdown_deadline = std::time::Duration::from_secs(config.max_shutdown_secs);
    let tip_hash = chain_state.tip_hash().to_string();
    let tip_height = chain_state.tip_height();
    let flush_cs = chain_state.clone();
    let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        // Drain dirty cache to RocksDB memtable, THEN fsync the memtable to
        // SST. With BulkLoad mode (WAL disabled) a bare `flush_coin_cache`
        // leaves every post-last-atomic-flush mutation volatile — recovery
        // on restart replays from DataStored blocks, but only if those
        // blocks' chainstate effects were truly durable. Relying on the
        // RocksDB Drop-time flush is not safe: force-exit, SIGKILL or
        // panic skip destructors and memtable contents are lost. An
        // explicit `flush_durable` after `flush_coin_cache` guarantees the
        // tip pointer and its coin mutations are on disk together before
        // we signal shutdown-complete.
        let result = flush_cs
            .flush_coin_cache()
            .and_then(|()| flush_cs.flush_durable());
        let _ = flush_tx.send(result);
    });
    let flushed_ok = match node::shutdown::await_bounded_flush(flush_rx, shutdown_deadline).await {
        node::shutdown::BoundedFlushOutcome::Clean => {
            tracing::info!(
                "UTXO cache flushed cleanly within {}s deadline",
                config.max_shutdown_secs
            );
            true
        }
        node::shutdown::BoundedFlushOutcome::FlushError(e) => {
            tracing::error!("UTXO cache flush reported error on shutdown: {}", e);
            false
        }
        node::shutdown::BoundedFlushOutcome::ChannelDropped => {
            tracing::error!("UTXO cache flush sender dropped before completing");
            false
        }
        node::shutdown::BoundedFlushOutcome::TimedOut => {
            // Flush exceeded the deadline. The std::thread is still inside
            // the rocksdb FFI and we can't reach in to cancel it. Force exit
            // at the OS level so the deadline is actually honored — this is
            // the point of --max-shutdown-secs. Emit the same cleanup we
            // would have done below first (PID file, cookie) so operators
            // don't see leftover state.
            tracing::error!(
                deadline_secs = config.max_shutdown_secs,
                "UTXO cache flush exceeded --max-shutdown-secs; force-exiting. \
                 Next startup will replay DataStored blocks from flat files."
            );
            auth.cleanup();
            if let Some(ref pid_path) = config.pid {
                let _ = std::fs::remove_file(pid_path);
            }
            std::process::exit(1);
        }
    };

    // Write the clean-shutdown marker only if the flush actually succeeded.
    // If we timed out or errored, leaving the marker absent is correct — it
    // tells the next startup (and the operator) that this exit was dirty.
    if flushed_ok {
        if let Err(e) = node::shutdown::write_marker(&net_datadir, &tip_hash, tip_height) {
            tracing::warn!(error = %e, "Failed to write clean-shutdown marker");
        } else {
            tracing::info!(tip_height, "Wrote clean-shutdown marker");
        }
    }

    server_handle.stop().expect("Failed to stop server");
    auth.cleanup();
    if let Some(ref pid_path) = config.pid {
        let _ = std::fs::remove_file(pid_path);
    }

    // Drop local references to help cleanup, but spawned tasks may still hold Arcs
    drop(peer_manager);
    drop(mempool);
    drop(fee_estimator);
    drop(chain_state);
    tracing::info!("Shutdown complete — local references released");

    tracing::info!("satd stopped");
}

/// Start a minimal RPC server that only serves `getstartupinfo`.
/// This runs on the RPC port before the full node is initialized,
/// so the TUI can show startup progress instead of "Connecting...".
async fn start_startup_rpc(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    progress: Arc<node::startup_progress::StartupProgress>,
) -> jsonrpsee::server::ServerHandle {
    use jsonrpsee::server::{RpcModule, ServerBuilder};
    use jsonrpsee::types::ErrorObjectOwned;
    use node::rpc::auth::AuthLayer;

    let mut module = RpcModule::new(progress);

    module
        .register_method("getstartupinfo", |_params, ctx, _extensions| {
            let snap = ctx.snapshot();
            // Prefer `stop_height` as the percent denominator when set:
            // the operator's goal is to reach the stop target, not the
            // file tip, so the gauge should fill from 0..stop_height.
            let percent_denom = snap.stop_height.unwrap_or(snap.total);
            let percent = if percent_denom > 0 {
                Some(((snap.current as f64 / percent_denom as f64) * 100.0 * 10.0).round() / 10.0)
            } else {
                None
            };
            Ok::<_, ErrorObjectOwned>(serde_json::json!({
                "started": false,
                "status": snap.message,
                "phase": snap.phase,
                "current": snap.current,
                "total": snap.total,
                "stop_height": snap.stop_height,
                "percent": percent,
            }))
        })
        .unwrap();

    let middleware = tower::ServiceBuilder::new().layer(AuthLayer::new(auth));
    let server = ServerBuilder::new()
        .set_http_middleware(middleware)
        .build(bind_addr)
        .await
        .expect("Failed to start startup RPC server");

    server.start(module)
}

/// Forwards reorg records to the configured HTTP webhook. Best effort —
/// failures are logged and dropped. Never blocks the consensus path:
/// the only backpressure is the channel itself, which `ReorgLog::record`
/// `try_send`s into (full queue = silent drop, counted).
async fn reorg_webhook_dispatcher(
    url: String,
    secret: Option<String>,
    mut rx: tokio::sync::mpsc::Receiver<node::chain::reorg_log::ReorgRecord>,
) {
    use reqwest::header::{HeaderMap, HeaderValue};
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to build reorg webhook HTTP client");
            return;
        }
    };
    tracing::info!(url = %url, signed = secret.is_some(), "Reorg webhook dispatcher started");
    while let Some(record) = rx.recv().await {
        let body = match serde_json::to_vec(&record) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize reorg record for webhook");
                continue;
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(ref key) = secret {
            let sig = hmac_sha256_hex(key.as_bytes(), &body);
            if let Ok(h) = HeaderValue::from_str(&format!("sha256={}", sig)) {
                headers.insert("X-Satd-Signature", h);
            }
        }

        // Simple retry loop: 3 attempts with jittered backoff. A failing
        // webhook must not back up consensus, so we stop after 3 and move
        // on to the next record.
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match client
                .post(&url)
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => break,
                Ok(r) => {
                    tracing::warn!(status = %r.status(), attempt, "Reorg webhook returned non-2xx");
                }
                Err(e) => {
                    tracing::warn!(error = %e, attempt, "Reorg webhook request failed");
                }
            }
            if attempt >= 3 {
                break;
            }
            let backoff_ms = 200u64 * (1 << (attempt - 1));
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }
    }
    tracing::info!("Reorg webhook dispatcher stopped");
}

/// Address-index backfill supervisor. Owns serialization (one runner
/// at a time) and crash recovery (auto-respawns on startup if the
/// persisted cursor state is Running and the index is enabled).
///
/// The runner itself is synchronous (RocksDB calls are blocking), so
/// it executes inside `spawn_blocking`. The supervisor stays in tokio
/// to react to shutdown and incoming commands.
async fn backfill_supervisor(
    handle: std::sync::Arc<node::index::address::BackfillHandle>,
    chain: std::sync::Arc<node::chain::state::ChainState>,
    cfg: node::index::address::AddressIndexConfig,
    mut cmd_rx: tokio::sync::mpsc::Receiver<node::index::address::BackfillCommand>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    resume_on_start: bool,
) {
    if resume_on_start {
        tracing::info!("addr-index backfill: auto-resuming from persisted cursor");
        spawn_runner(handle.clone(), chain.clone(), cfg.clone(), shutdown.clone()).await;
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("addr-index backfill supervisor: shutdown");
                    return;
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    // All senders dropped; nothing else can request a backfill.
                    return;
                };
                match cmd {
                    node::index::address::BackfillCommand::Start => {
                        spawn_runner(
                            handle.clone(),
                            chain.clone(),
                            cfg.clone(),
                            shutdown.clone(),
                        )
                        .await;
                    }
                }
            }
        }
    }
}

/// Spawn a runner on the blocking pool and log its result. On a
/// non-shutdown error, persist `Failed` with the error message so
/// `getindexinfo` surfaces it to the operator and `cancelindex` can
/// clear stale active state without requiring a live runner. The
/// supervisor awaits the join handle so subsequent commands queue up
/// behind it (channel size 1; further sends backpressure or fail).
async fn spawn_runner(
    handle: std::sync::Arc<node::index::address::BackfillHandle>,
    chain: std::sync::Arc<node::chain::state::ChainState>,
    cfg: node::index::address::AddressIndexConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let handle_for_failure = handle.clone();
    let chain_for_failure = chain.clone();
    let join = tokio::task::spawn_blocking(move || {
        let runner = node::index::address::BackfillRunner {
            handle,
            chain,
            cfg,
            shutdown,
        };
        runner.run()
    });
    let result = join.await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(node::index::address::BackfillError::Shutdown)) => {
            tracing::info!("addr-index backfill: stopped for shutdown (resume on next start)");
        }
        Ok(Err(node::index::address::BackfillError::Cancelled)) => {
            tracing::info!("addr-index backfill: cancelled by operator");
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "addr-index backfill runner exited with error");
            persist_failed_with_cleanup(&handle_for_failure, &chain_for_failure, &e).await;
        }
        Err(e) => {
            tracing::error!(error = %e, "addr-index backfill runner task panicked");
            let msg = format!("runner panicked: {}", e);
            if let Err(p) =
                handle_for_failure.mark_failed(chain_for_failure.store_ref().as_ref(), &msg)
            {
                tracing::warn!(error = %p, "failed to persist Failed state after runner panic");
            }
            // Best-effort: drop temp CF on panic so a fresh start
            // doesn't reuse partial pass-1 state.
            let _ = chain_for_failure.store_ref().drop_backfill_temp_cf();
        }
    }
}

/// Persist Failed and clean up. For ReorgInvalidated specifically,
/// run the OLD-snapshot stale-row cleanup before transitioning so a
/// subsequent fresh backfill doesn't see stale rows from the
/// abandoned chain. Other errors don't need the cleanup walk because
/// they don't imply chain divergence (insufficient disk, missing
/// block, temp CF miss, etc.).
async fn persist_failed_with_cleanup(
    handle: &std::sync::Arc<node::index::address::BackfillHandle>,
    chain: &std::sync::Arc<node::chain::state::ChainState>,
    err: &node::index::address::BackfillError,
) {
    use node::index::address::BackfillError;
    let cleanup_needed = matches!(err, BackfillError::ReorgInvalidated { .. });
    if cleanup_needed {
        let chain_clone = chain.clone();
        let handle_clone = handle.clone();
        let cleanup_join = tokio::task::spawn_blocking(move || {
            node::index::address::BackfillRunner::cleanup_stale_rows_after_reorg(
                chain_clone.as_ref(),
                handle_clone.as_ref(),
            )
        })
        .await;
        match cleanup_join {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "addr-index reorg cleanup failed; proceeding to mark Failed");
            }
            Err(e) => {
                tracing::warn!(error = %e, "addr-index reorg cleanup task panicked");
            }
        }
    }
    let msg = format!("{}", err);
    if let Err(p) = handle.mark_failed(chain.store_ref().as_ref(), &msg) {
        tracing::warn!(error = %p, "failed to persist Failed state");
    }
    // Drop temp CF so a fresh backfill starts from a clean slate
    // rather than reusing pass-1 mappings from the failed run.
    if let Err(e) = chain.store_ref().drop_backfill_temp_cf() {
        tracing::warn!(error = %e, "failed to drop temp CF after Failed");
    }
}

// ============================================================================
// Filter-index backfill supervisor (mirrors the address-index pattern above
// for BIP 158 filter rows). Single-pass walk, no temp CF.
// ============================================================================

/// Filter-index backfill supervisor. Same lifecycle as
/// `backfill_supervisor` for the address index but for the filter
/// backfill — single-pass, no temp CF cleanup.
async fn filter_backfill_supervisor(
    handle: std::sync::Arc<node::index::filter::BackfillHandle>,
    chain: std::sync::Arc<node::chain::state::ChainState>,
    cfg: node::index::filter::FilterIndexConfig,
    mut cmd_rx: tokio::sync::mpsc::Receiver<node::index::filter::BackfillCommand>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    resume_on_start: bool,
) {
    if resume_on_start {
        tracing::info!("filter-index backfill: auto-resuming from persisted cursor");
        spawn_filter_runner(handle.clone(), chain.clone(), cfg.clone(), shutdown.clone()).await;
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("filter-index backfill supervisor: shutdown");
                    return;
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    return;
                };
                match cmd {
                    node::index::filter::BackfillCommand::Start => {
                        spawn_filter_runner(
                            handle.clone(),
                            chain.clone(),
                            cfg.clone(),
                            shutdown.clone(),
                        )
                        .await;
                    }
                }
            }
        }
    }
}

async fn spawn_filter_runner(
    handle: std::sync::Arc<node::index::filter::BackfillHandle>,
    chain: std::sync::Arc<node::chain::state::ChainState>,
    cfg: node::index::filter::FilterIndexConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let handle_for_failure = handle.clone();
    let chain_for_failure = chain.clone();
    let join = tokio::task::spawn_blocking(move || {
        let runner = node::index::filter::BackfillRunner {
            handle,
            chain,
            cfg,
            shutdown,
        };
        runner.run()
    });
    let result = join.await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(node::index::filter::BackfillError::Shutdown)) => {
            tracing::info!("filter-index backfill: stopped for shutdown (resume on next start)");
        }
        Ok(Err(node::index::filter::BackfillError::Cancelled)) => {
            tracing::info!("filter-index backfill: cancelled by operator");
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "filter-index backfill runner exited with error");
            persist_filter_failed_with_cleanup(&handle_for_failure, &chain_for_failure, &e).await;
        }
        Err(e) => {
            tracing::error!(error = %e, "filter-index backfill runner task panicked");
            let msg = format!("runner panicked: {}", e);
            if let Err(p) =
                handle_for_failure.mark_failed(chain_for_failure.store_ref().as_ref(), &msg)
            {
                tracing::warn!(error = %p, "failed to persist Failed state after filter runner panic");
            }
        }
    }
}

async fn persist_filter_failed_with_cleanup(
    handle: &std::sync::Arc<node::index::filter::BackfillHandle>,
    chain: &std::sync::Arc<node::chain::state::ChainState>,
    err: &node::index::filter::BackfillError,
) {
    use node::index::filter::BackfillError;
    let cleanup_needed = matches!(err, BackfillError::ReorgInvalidated { .. });
    if cleanup_needed {
        let chain_clone = chain.clone();
        let handle_clone = handle.clone();
        let cleanup_join = tokio::task::spawn_blocking(move || {
            node::index::filter::BackfillRunner::cleanup_stale_rows_after_reorg(
                chain_clone.as_ref(),
                handle_clone.as_ref(),
            )
        })
        .await;
        match cleanup_join {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "filter-index reorg cleanup failed; proceeding to mark Failed"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "filter-index reorg cleanup task panicked");
            }
        }
    }
    let msg = format!("{}", err);
    if let Err(p) = handle.mark_failed(chain.store_ref().as_ref(), &msg) {
        tracing::warn!(error = %p, "failed to persist filter-index Failed state");
    }
}

/// HMAC-SHA256 over `msg` keyed by `key`, hex-encoded. Pure Rust so we
/// don't pull in yet another dep; reorg rate is low so the tiny-fast-
/// crypto path is unnecessary.
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
    let mut hmac: HmacEngine<sha256::Hash> = HmacEngine::new(key);
    hmac.input(msg);
    let out = Hmac::<sha256::Hash>::from_engine(hmac);
    hex::encode(out.to_byte_array())
}
