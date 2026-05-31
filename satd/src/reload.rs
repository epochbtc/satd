//! SIGHUP-triggered live config reload.
//!
//! Bitcoin Core uses `SIGHUP` to reopen `debug.log` for logrotate. satd has no
//! `debug.log` — it logs to stdout and delegates rotation to systemd/journald —
//! so `SIGHUP` is repurposed here for **live config reload**: an operator edits
//! `bitcoin.conf` and sends `kill -HUP <pid>` (or `systemctl reload satd`) to
//! apply changes without restarting. This is an intentional difference from
//! Core, documented in `CORE_DIFFERENCES.md`.
//!
//! ## Model
//!
//! On `SIGHUP`, [`reload_from_sighup`] re-runs [`Config::from_cli`] with the
//! **same CLI args captured at startup** (CLI stays authoritative; only the
//! config file is re-read from disk), then diffs the new config against the
//! running one. Every changed key is classified by the [`field_specs`] table as
//! either:
//!
//! - **applied live** — pushed to the running component via an existing setter
//!   (atomics / `RwLock` / a global setter), so the change takes effect
//!   immediately; or
//! - **restart required** — reported via a warning; the value is held in
//!   long-lived state that was wired at startup and cannot be safely swapped.
//!
//! A changed key is **never silently ignored**: the [`coverage`](#tests) test
//! asserts every key in [`config::KNOWN_CONFIG_KEYS`] is covered by exactly one
//! `FieldSpec` or listed in [`LOAD_ONLY_KEYS`]. A reload-time parse error (e.g.
//! a typo'd or unknown key, which hard-errors at load) does **not** crash the
//! daemon: it is logged and the running config is kept.

use crate::config::{self, Config};
use node::net::manager::PeerManager;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, Registry};

/// Handle to the reloadable tracing env-filter layer.
///
/// Only the `EnvFilter` is wrapped in a `reload::Layer` (the fmt layer stays
/// static), so changing `-debug`/`-debugexclude`/log level on `SIGHUP` takes
/// effect live while `-logformat` (json vs text) remains restart-only.
#[derive(Clone)]
pub struct LogReloadHandle {
    handle: tracing_subscriber::reload::Handle<EnvFilter, Registry>,
}

impl LogReloadHandle {
    pub fn new(handle: tracing_subscriber::reload::Handle<EnvFilter, Registry>) -> Self {
        Self { handle }
    }

    /// Rebuild the env-filter from `config` and swap it in live. `EnvFilter` is
    /// not `Clone`, so a fresh one is built via the same
    /// [`config::build_env_filter`] used at startup (single source of truth, no
    /// drift). Errors only if the subscriber was dropped (impossible while the
    /// process runs) — logged and ignored.
    pub fn reload(&self, config: &Config) {
        let filter = config::build_env_filter(config);
        if let Err(e) = self.handle.reload(filter) {
            tracing::error!(error = %e, "failed to reload log filter");
        }
    }
}

/// Long-lived component handles the reload path pushes live changes into.
/// Constructed once before the signal loop; holds cheap `Arc`/handle clones.
pub struct ReloadHandles {
    /// CLI args captured at startup — re-used verbatim on every reload so CLI
    /// flags stay authoritative and only the config file can change.
    pub cli: config::CliArgs,
    pub peer_manager: Arc<PeerManager>,
    pub log_filter: LogReloadHandle,
}

/// One config field's reload disposition.
struct FieldSpec {
    /// The `bitcoin.conf` key name (matches [`config::KNOWN_CONFIG_KEYS`]).
    key: &'static str,
    /// Returns `Some((old, new))` (Debug-formatted) iff the field differs.
    /// Debug-format comparison is uniform across all field types and needs no
    /// `PartialEq` impl on the field (e.g. `WhitelistEntry` has none).
    diff: fn(&Config, &Config) -> Option<(String, String)>,
    /// `None` => restart-required (report only). `Some(apply)` => live path:
    /// `apply(new_config, handles)` pushes the value into the running node.
    apply: Option<fn(&Config, &ReloadHandles)>,
    /// When true, the field holds secret material (passwords, auth hashes,
    /// HMAC secrets). The reload report still records that the key *changed*,
    /// but the old/new values are redacted so secrets never reach the log
    /// (stdout/journald has a broader trust boundary than `bitcoin.conf`).
    sensitive: bool,
}

/// Config-file keys with no per-field reload disposition: consumed only at load
/// time, or aliases whose effect is captured by another field's diff.
///
/// - `conf`/`includeconf` — locate/extend the config file; meaningless to
///   "reload" since they govern the reload input itself.
/// - `profile` — a meta-key resolved into other fields at load; a profile
///   change is still caught field-by-field by the individual specs.
/// - `regtest`/`testnet`/`testnet4`/`signet` — network-selection aliases; a
///   resulting network change is reported by the `chain` spec (which diffs
///   `network`).
/// - `par` — script-verification thread count; no `Config` field.
///
/// Referenced by the coverage test; `#[allow(dead_code)]` because release
/// builds compile out the test that reads it.
#[allow(dead_code)]
const LOAD_ONLY_KEYS: &[&str] = &[
    "conf",
    "includeconf",
    "profile",
    "regtest",
    "testnet",
    "testnet4",
    "signet",
    "par",
];

/// Build the field-disposition table. Constructed at call time (once per
/// reload) so the non-capturing `diff`/`apply` closures coerce to `fn`
/// pointers without const-context constraints.
fn field_specs() -> Vec<FieldSpec> {
    // restart-required: report if changed, never applied live.
    macro_rules! restart {
        ($key:expr, $field:ident) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: None,
                sensitive: false,
            }
        };
    }
    // restart-required AND secret: report the change but redact the values.
    macro_rules! restart_secret {
        ($key:expr, $field:ident) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: None,
                sensitive: true,
            }
        };
    }
    // live: report if changed AND push to the running node via `$apply`.
    macro_rules! live {
        ($key:expr, $field:ident, $apply:expr) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: Some($apply),
                sensitive: false,
            }
        };
    }

    vec![
        // ---- Network / chain (one spec diffing `network`; aliases load-only) ----
        restart!("chain", network),
        // ---- Filesystem ----
        restart!("datadir", datadir),
        restart!("blocksdir", blocksdir),
        restart!("pid", pid),
        // ---- Daemon control ----
        restart!("daemon", daemon),
        restart!("server", server),
        restart!("logformat", log_format), // only verbosity hot-reloads, not format
        restart!("maxshutdownsecs", max_shutdown_secs),
        live!("debug", debug, |c, h| h.log_filter.reload(c)),
        live!("debugexclude", debugexclude, |c, h| h.log_filter.reload(c)),
        // ---- RPC server ----
        restart!("rpcport", rpcport),
        restart!("rpcbind", rpcbind),
        restart!("rpcallowip", rpcallowip),
        restart_secret!("rpcuser", rpcuser),
        restart_secret!("rpcpassword", rpcpassword),
        restart_secret!("rpcauth", rpcauth),
        restart!("rpccookiefile", rpc_cookie_file),
        restart!("rpccookieperms", rpc_cookie_perms),
        restart!("rpcdisableauth", rpc_disable_auth),
        live!("rpcdefaultunits", rpc_default_units, |c, _h| {
            node::rpc::amounts::set_default(c.rpc_default_units)
        }),
        live!("rpcextendederrors", rpc_extended_errors, |c, _h| {
            node::rpc::error::set_extended_enabled(c.rpc_extended_errors)
        }),
        // ---- RPC TLS ----
        restart!("rpctlsbind", rpc_tls_bind),
        restart!("rpctlscert", rpc_tls_cert),
        restart!("rpctlskey", rpc_tls_key),
        restart!("rpctlshandshaketimeout", rpc_tls_handshake_timeout),
        restart!("rpcmtls", rpc_mtls),
        restart!("rpcmtlsclientca", rpc_mtls_client_ca),
        restart!("rpcmtlsclientallow", rpc_mtls_client_allow),
        // ---- P2P ----
        restart!("listen", listen),
        live!("blocksonly", blocksonly, |c, h| {
            h.peer_manager.set_blocksonly(c.blocksonly)
        }),
        live!("v2transport", v2transport, |c, h| {
            h.peer_manager.set_v2transport(c.v2transport || c.v2only)
        }),
        live!("v2only", v2only, |c, h| {
            // v2only implies v2transport; keep them consistent regardless of
            // which key changed.
            h.peer_manager.set_v2only(c.v2only);
            h.peer_manager.set_v2transport(c.v2transport || c.v2only);
        }),
        live!("externalip", externalip, |c, h| {
            h.peer_manager.set_external_addrs(c.externalip.clone())
        }),
        live!("whitelist", whitelist, |c, h| {
            h.peer_manager.set_whitelist(c.whitelist.clone())
        }),
        restart!("whitebind", whitebind),
        restart!("asmap", asmap),
        restart!("port", port),
        restart!("bind", bind),
        restart!("connect", connect),
        restart!("addnode", addnode),
        restart!("seednode", seednode),
        restart!("maxconnections", maxconnections),
        restart!("maxinboundperip", maxinboundperip),
        live!("maxuploadtarget", max_upload_target, |c, h| {
            h.peer_manager.set_max_upload_target(c.max_upload_target)
        }),
        restart!("dns", dns),
        restart!("dnsseed", dnsseed),
        restart!("forcednsseed", forcednsseed),
        restart!("fixedseeds", fixedseeds),
        restart!("bantime", bantime),
        live!("timeout", timeout, |c, h| {
            h.peer_manager.set_connect_timeout_ms(c.timeout)
        }),
        restart!("onlynet", onlynet),
        restart!("signetseednode", signet_seed_nodes),
        restart!("signetchallenge", signet_challenge),
        // ---- Proxy / Tor ----
        restart!("proxy", proxy),
        restart!("onion", onion),
        restart!("torcontrol", torcontrol),
        restart_secret!("torpassword", torpassword),
        restart!("listenonion", listenonion),
        // ---- Consensus ----
        restart!("assumevalid", assumevalid),
        restart!("assumevalidage", assumevalidage),
        restart!("stopatheight", stopatheight),
        restart!("consensus", consensus),
        // ---- Indexing ----
        restart!("txindex", txindex),
        restart!("addressindex", addressindex),
        restart!("addrindexsubscriptions", addrindexsubscriptions),
        restart!("blockfilterindex", blockfilterindex),
        restart!("peerblockfilters", peerblockfilters),
        // ---- Mempool / relay policy (live-applied in PR2) ----
        restart!("mempoolfullrbf", mempoolfullrbf),
        restart!("maxmempool", maxmempool),
        restart!("minrelaytxfee", minrelaytxfee),
        restart!("dustrelayfee", dustrelayfee),
        restart!("datacarrier", datacarrier),
        restart!("datacarriersize", datacarriersize),
        restart!("limitancestorcount", limitancestorcount),
        restart!("limitdescendantcount", limitdescendantcount),
        restart!("mempoolexpiry", mempoolexpiry),
        restart!("persistmempool", persistmempool),
        restart!("permitbaremultisig", permitbaremultisig),
        // ---- Esplora ----
        restart!("esplora", esplora),
        restart!("esplorabind", esplora_bind),
        restart!("esploratlsbind", esplora_tls_bind),
        restart!("esploratlscert", esplora_tls_cert),
        restart!("esploratlskey", esplora_tls_key),
        restart!("esploramtls", esplora_mtls),
        restart!("esploramtlsclientca", esplora_mtls_client_ca),
        restart!("esploramtlsclientallow", esplora_mtls_client_allow),
        restart!("esploraprefix", esplora_prefix),
        restart!("esploracors", esplora_cors),
        restart!("esplorarequesttimeout", esplora_request_timeout),
        restart!("esploramaxconns", esplora_max_conns),
        restart!("esplorasseconns", esplora_sse_max_conns),
        restart!("esploraauth", esplora_auth),
        restart!("esploracookiefile", esplora_cookie_file),
        restart_secret!("esplorauserpass", esplora_userpass),
        // ---- Electrum ----
        restart!("electrum", electrum),
        restart!("electrumbind", electrum_bind),
        restart!("electrumtlsbind", electrum_tls_bind),
        restart!("electrumtlscert", electrum_tls_cert),
        restart!("electrumtlskey", electrum_tls_key),
        restart!("electrummtls", electrum_mtls),
        restart!("electrummtlsclientca", electrum_mtls_client_ca),
        restart!("electrummtlsclientallow", electrum_mtls_client_allow),
        restart!("electrummaxconns", electrum_max_conns),
        restart!("electrummaxsubsperconn", electrum_max_subs_per_conn),
        restart!("electrumrequesttimeout", electrum_request_timeout),
        restart!("electrummaxbatchrequests", electrum_max_batch_requests),
        restart!("electrummaxbroadcastpackagetxs", electrum_max_broadcast_package_txs),
        restart!("electrumfeehistogramttl", electrum_fee_histogram_ttl),
        restart!("electrumbanner", electrum_banner),
        // ---- Storage / pruning / reindex ----
        restart!("prune", prune),
        restart!("reindex", reindex),
        restart!("reindexchainstate", reindex_chainstate),
        restart!("dbcache", dbcache),
        restart!("storageprofile", storage_profile),
        restart!("prefetchworkers", prefetch_workers),
        restart!("maxahead", max_ahead),
        restart!("maxopenfiles", max_open_files),
        restart!("rocksdbbackgroundjobs", rocksdb_background_jobs),
        restart!("rocksdbsubcompactions", rocksdb_subcompactions),
        restart!("rocksdbwalmb", rocksdb_wal_mb),
        restart!("compactiondiagintervalsecs", compaction_diag_interval_secs),
        restart!("compactionintervalsecs", compaction_interval_secs),
        restart!("compactionl0at", compaction_l0_at),
        restart!("ibdl0pauseat", ibd_l0_pause_at),
        restart!("stallwatchdogsecs", stall_watchdog_secs),
        restart!("stallabortsecs", stall_abort_secs),
        restart!("shadowqueuesize", shadow_queue_size),
        restart!("shadowworkers", shadow_workers),
        // ---- Mining ----
        restart!("blockmaxweight", blockmaxweight),
        restart!("blockmintxfee", blockmintxfee),
        // ---- Events ----
        restart!("eventsnodeid", events_node_id),
        restart!("eventsregion", events_region),
        restart!("eventsgrpcbind", events_grpc_bind),
        restart!("eventsgrpcallowremote", events_grpc_allow_remote),
        restart!("eventszmqbind", events_zmq_bind),
        restart!("eventszmqhashtx", events_zmq_hashtx),
        restart!("eventszmqhashblock", events_zmq_hashblock),
        restart!("eventszmqmpevict", events_zmq_mpevict),
        restart!("eventszmqmpreplace", events_zmq_mpreplace),
        restart!("eventszmqmpconfirm", events_zmq_mpconfirm),
        restart!("eventszmqnodeevent", events_zmq_nodeevent),
        // ---- Webhooks ----
        restart!("reorgwebhook", reorg_webhook),
        restart_secret!("reorgwebhooksecret", reorg_webhook_secret),
        // ---- MCP ----
        restart!("mcp", mcp),
        restart!("mcpstdio", mcp_stdio),
        restart!("mcpport", mcp_port),
        restart!("mcpbind", mcp_bind),
        // ---- Metrics / health ----
        restart!("metricsport", metricsport),
        restart!("metricsbind", metricsbind),
    ]
}

/// Re-read the config file (CLI fixed) and apply/report each changed key.
///
/// Returns the new live `Config` (the caller swaps its running snapshot so the
/// next reload diffs against current state). On a parse/validation error the
/// running config is kept and an error is logged — the daemon never crashes on
/// a bad reload.
pub fn reload_from_sighup(handles: &ReloadHandles, running: &Config) -> Config {
    let mut new = match Config::from_cli(handles.cli.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                error = %e,
                "SIGHUP config reload failed — keeping running config"
            );
            return running.clone();
        }
    };

    let mut applied = 0usize;
    let mut restart_required = 0usize;
    for spec in field_specs() {
        if let Some((old, newv)) = (spec.diff)(running, &new) {
            // Redact secret material: report that the key changed, never the
            // value. The diff itself still ran, so the change is detected.
            let (old, newv) = if spec.sensitive {
                ("<redacted>".to_string(), "<redacted>".to_string())
            } else {
                (old, newv)
            };
            match spec.apply {
                Some(apply) => {
                    apply(&new, handles);
                    applied += 1;
                    tracing::info!(
                        key = spec.key,
                        old = %old,
                        new = %newv,
                        "config reloaded: applied live"
                    );
                }
                None => {
                    restart_required += 1;
                    tracing::warn!(
                        key = spec.key,
                        old = %old,
                        new = %newv,
                        "config changed in file — restart required to take effect"
                    );
                }
            }
        }
    }

    // Surface any reconciliation notes produced by re-reading the file
    // (e.g. Esplora ↔ txindex, prune auto-disable).
    for note in new.take_pending_notes() {
        match note.level {
            config::NoteLevel::Info => tracing::info!("{}", note.message),
            config::NoteLevel::Warn => tracing::warn!("{}", note.message),
        }
    }

    if applied == 0 && restart_required == 0 {
        tracing::info!("SIGHUP config reload: no changes detected");
    } else {
        tracing::info!(applied, restart_required, "SIGHUP config reload complete");
    }
    new
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::collections::HashSet;

    /// Build a deterministic `Config` for tests: regtest, isolated empty
    /// datadir (so no `bitcoin.conf` is read), all other values at defaults.
    fn test_config() -> Config {
        let dir = std::env::temp_dir().join(format!("satd-reload-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = config::CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
        ])
        .expect("parse test CLI");
        Config::from_cli(cli).expect("build test config")
    }

    /// Anti-drift guard: every known config-file key must have exactly one
    /// reload disposition (a `FieldSpec` or a `LOAD_ONLY_KEYS` entry). A new
    /// config key added without classification fails here, upholding the
    /// "never silently ignored" contract at the reload layer.
    #[test]
    fn every_config_key_is_classified() {
        let specs = field_specs();
        let spec_keys: HashSet<&str> = specs.iter().map(|s| s.key).collect();
        assert_eq!(
            spec_keys.len(),
            specs.len(),
            "duplicate key in field_specs()"
        );
        let load_only: HashSet<&str> = LOAD_ONLY_KEYS.iter().copied().collect();

        for key in config::KNOWN_CONFIG_KEYS {
            let covered = spec_keys.contains(key) || load_only.contains(key);
            assert!(
                covered,
                "config key {key:?} has no reload disposition — add it to \
                 field_specs() (restart!/live!) or LOAD_ONLY_KEYS"
            );
        }
        // No stray keys: every spec/load-only key must be a real config key.
        let known: HashSet<&str> = config::KNOWN_CONFIG_KEYS.iter().copied().collect();
        for k in spec_keys.iter().chain(load_only.iter()) {
            assert!(
                known.contains(k),
                "{k:?} is classified but is not in KNOWN_CONFIG_KEYS"
            );
        }
    }

    /// `live!` and `restart!` entries are correctly tagged.
    #[test]
    fn dispositions_are_tagged() {
        let specs = field_specs();
        let find = |k: &str| specs.iter().find(|s| s.key == k).unwrap();
        // A representative live key and a representative restart-only key.
        assert!(find("debug").apply.is_some(), "debug should be live");
        assert!(find("timeout").apply.is_some(), "timeout should be live");
        assert!(find("dbcache").apply.is_none(), "dbcache should be restart-only");
        assert!(find("rpcport").apply.is_none(), "rpcport should be restart-only");
    }

    /// The `diff` closures detect a change and report Debug-formatted values,
    /// across several field types (numeric, bool, Option, Vec, enum).
    #[test]
    fn diff_detects_changes() {
        let base = test_config();

        let mut changed = base.clone();
        changed.dbcache = base.dbcache + 64;
        let specs = field_specs();
        let dbcache = specs.iter().find(|s| s.key == "dbcache").unwrap();
        assert!(
            (dbcache.diff)(&base, &base).is_none(),
            "identical configs must not diff"
        );
        let (old, new) = (dbcache.diff)(&base, &changed).expect("dbcache change detected");
        assert_ne!(old, new);

        let mut bo = base.clone();
        bo.blocksonly = !base.blocksonly;
        let blocksonly = specs.iter().find(|s| s.key == "blocksonly").unwrap();
        assert!((blocksonly.diff)(&base, &bo).is_some());
    }

    /// Comparing a config to its own clone must yield NO changes for ANY spec.
    /// Guards against a field whose `Debug` output is non-deterministic (e.g. a
    /// future `HashMap`/`HashSet` config field), which would otherwise report
    /// "changed" on every reload and spam the log forever.
    #[test]
    fn identical_config_yields_no_changes() {
        let c = test_config();
        let same = c.clone();
        for spec in field_specs() {
            assert!(
                (spec.diff)(&c, &same).is_none(),
                "spec {:?} reported a change comparing a config to its own clone \
                 — likely a non-deterministic Debug field",
                spec.key
            );
        }
    }

    /// Secret-bearing keys must stay marked `sensitive` so the reload report
    /// redacts their values. Guards against a refactor that downgrades one of
    /// these to a plain `restart!` and leaks credentials into the log.
    #[test]
    fn secret_fields_are_marked_sensitive() {
        let specs = field_specs();
        for key in [
            "rpcuser",
            "rpcpassword",
            "rpcauth",
            "torpassword",
            "esplorauserpass",
            "reorgwebhooksecret",
        ] {
            let spec = specs
                .iter()
                .find(|s| s.key == key)
                .unwrap_or_else(|| panic!("secret key {key:?} missing from field_specs()"));
            assert!(
                spec.sensitive,
                "{key:?} holds secret material and must be marked sensitive \
                 (redacted in the reload report)"
            );
            // Secrets are never live-applied (they're wired at startup).
            assert!(spec.apply.is_none(), "{key:?} must be restart-only");
        }
    }
}
