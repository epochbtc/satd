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
use node::index::address::SubscriptionRegistry;
use node::mempool::pool::{Mempool, MempoolConfig};
use node::net::manager::PeerManager;
use node::rpc::auth::{RpcAuth, RpcAuthCredential, UserPassCredential};
use parking_lot::RwLock;
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

/// Reorg-webhook target the dispatcher reads per record. Held behind a
/// [`SharedWebhook`] so a SIGHUP reload can change the URL/secret — or turn the
/// webhook on/off — without restarting the dispatcher task. `None` means "no
/// webhook configured"; the dispatcher then drains and drops records.
#[derive(Clone, Debug)]
pub struct WebhookTarget {
    pub url: String,
    pub secret: Option<String>,
}

/// Shared, reloadable reorg-webhook target. The dispatcher (spawned once at
/// startup regardless of whether a webhook is configured) snapshots this per
/// record; the reload path swaps its contents.
pub type SharedWebhook = Arc<RwLock<Option<WebhookTarget>>>;

/// Build a [`WebhookTarget`] from a config, or `None` if no URL is set.
pub fn webhook_target_from(c: &Config) -> Option<WebhookTarget> {
    c.reorg_webhook.clone().map(|url| WebhookTarget {
        url,
        secret: c.reorg_webhook_secret.clone(),
    })
}

/// No-op live apply for keys whose only consumer reads them from the reloaded
/// `Config` snapshot at a later point — there is no separate running copy to
/// push into. `main` reassigns its `config` local from `reload_from_sighup`'s
/// return value, so the shutdown path (`-persistmempool`, `-maxshutdownsecs`)
/// already sees the new value; classifying these as live (not restart-required)
/// reflects that they take effect without a restart.
fn consumed_from_reloaded_config(_c: &Config, _h: &ReloadHandles) {}

/// Register + dial the socket-style peer addresses present in `new` but not in
/// `old` (`-addnode`/`-connect` reload). Mirrors the startup path: `add_peer_addr`
/// registers for auto-reconnect (idempotent/deduped), then a spawned task dials.
///
/// Only the *added* entries are dialed — existing peers are left alone, so a
/// reload that merely appends a peer doesn't churn live connections. Removing an
/// entry from the file does NOT disconnect that peer (matches Core's `-addnode`:
/// use `disconnectnode` for that). Runs inside the tokio runtime (the reload is
/// driven from the main select loop), so `tokio::spawn` is valid here.
fn dial_added_peers(old: &[String], new: &[String], pm: &Arc<PeerManager>, label: &'static str) {
    for addr_str in new {
        if old.iter().any(|o| o == addr_str) {
            continue;
        }
        match node::net::peer::PeerAddr::parse(addr_str) {
            Ok(addr) => {
                pm.add_peer_addr(addr.clone());
                let pm = pm.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::warn!(addr = %addr, "{label} reload connect failed: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = addr_str, "invalid {label} address on reload: {e}");
            }
        }
    }
}

/// `-seednode` reload: resolve + dial the entries added since the last config.
/// Seednodes need DNS/Tor resolution (async), so the whole add-set is resolved
/// in one spawned task — same resolver and semantics as the startup path.
fn dial_added_seednodes(old: &Config, new: &Config, h: &ReloadHandles) {
    let added: Vec<String> = new
        .seednode
        .iter()
        .filter(|s| !old.seednode.contains(s))
        .cloned()
        .collect();
    if added.is_empty() {
        return;
    }
    let pm = h.peer_manager.clone();
    let network = new.network;
    let proxy = new.proxy.clone();
    tokio::spawn(async move {
        let seed_addrs =
            node::net::dns::resolve_operator_seeds(&added, network, proxy.as_deref()).await;
        for addr in seed_addrs {
            pm.add_peer_addr(addr.clone());
            let pm = pm.clone();
            tokio::spawn(async move {
                if let Err(e) = pm.connect_peer_addr(&addr).await {
                    tracing::warn!(addr = %addr, "seednode reload connection failed: {e}");
                }
            });
        }
    });
}

/// Long-lived component handles the reload path pushes live changes into.
/// Constructed once before the signal loop; holds cheap `Arc`/handle clones.
pub struct ReloadHandles {
    /// CLI args captured at startup — re-used verbatim on every reload so CLI
    /// flags stay authoritative and only the config file can change.
    pub cli: config::CliArgs,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub log_filter: LogReloadHandle,
    /// Address-index subscription registry — its cap is reloadable.
    pub addr_sub_registry: Arc<SubscriptionRegistry>,
    /// Reloadable reorg-webhook target read by the dispatcher. `None` when the
    /// reorg log failed to open at startup (no dispatcher exists), in which
    /// case a webhook config change cannot take effect — `apply_webhook` warns
    /// rather than letting the generic "applied live" line mislead the operator.
    pub webhook: Option<SharedWebhook>,
    /// RPC auth handle — its `-rpcuser`/`-rpcpassword`/`-rpcauth` credentials
    /// are rotatable live (the cookie is preserved). Shared with every RPC
    /// listener surface, so a reload covers all of them at once.
    pub rpc_auth: Arc<RpcAuth>,
    /// Unified-auth bearer-token store, present only when `authfile=` is set.
    /// Re-read on every SIGHUP independently of the rest of the config so that
    /// removing a `[[token]]` revokes it live; a re-read error keeps the
    /// last-good table (never strands the node without auth). The `authfile`
    /// *path* itself is restart-only (the store binds to a path at startup).
    pub token_store: Option<Arc<satd_auth::TokenStore>>,
}

/// Apply a reorg-webhook config change to the running dispatcher. Shared by the
/// `reorgwebhook` and `reorgwebhooksecret` specs. When the reorg log failed to
/// open at startup there is no dispatcher to feed, so the change cannot take
/// effect; warn explicitly instead of silently claiming success.
fn apply_webhook(c: &Config, h: &ReloadHandles) {
    match &h.webhook {
        Some(target) => *target.write() = webhook_target_from(c),
        None => tracing::warn!(
            "reorg-webhook config changed, but reorg logging is unavailable \
             (the reorg log failed to open at startup) — the change has no \
             effect until the daemon is restarted"
        ),
    }
}

/// Rebuild the live-rotatable RPC credentials (userpass + rpcauth) from a
/// config. Mirrors the startup construction in `main`: a userpass credential
/// exists only when BOTH `-rpcuser` and `-rpcpassword` are set; each `-rpcauth`
/// line becomes one HMAC credential. The cookie is NOT rebuilt here — it is
/// generated once at startup and preserved across reloads.
fn rebuild_rpc_credentials(c: &Config) -> (Vec<UserPassCredential>, Vec<RpcAuthCredential>) {
    let userpass = match (&c.rpcuser, &c.rpcpassword) {
        (Some(user), Some(pass)) => vec![UserPassCredential {
            username: user.clone(),
            password: pass.clone(),
        }],
        _ => vec![],
    };
    let rpcauth = c
        .rpcauth
        .iter()
        .map(|e| RpcAuthCredential {
            username: e.username.clone(),
            salt: e.salt.clone(),
            hash: e.hash.clone(),
        })
        .collect();
    (userpass, rpcauth)
}

/// Apply the RPC credential set from `c` to the running auth handle. Shared by
/// the `rpcuser`/`rpcpassword`/`rpcauth` specs (any one changing rebuilds the
/// whole set — idempotent).
fn apply_rpc_credentials(c: &Config, h: &ReloadHandles) {
    let (userpass, rpcauth) = rebuild_rpc_credentials(c);
    h.rpc_auth.reload_credentials(userpass, rpcauth);
}

/// Map a `Config` to the mempool's `MempoolConfig`. Single source of truth for
/// both startup (`main`) and SIGHUP reload, so the two cannot drift.
pub fn mempool_config_from(c: &Config) -> MempoolConfig {
    MempoolConfig {
        // Saturating: a pathological `maxmempool`/`mempoolexpiry` in the config
        // must not overflow-panic (overflow-checks abort the process in debug/
        // test builds; release would silently wrap to a tiny/garbage policy).
        // This runs on the main task on every SIGHUP, so a panic here would
        // crash the daemon — exactly the "never crash on a bad reload" case.
        max_size_bytes: c.maxmempool.saturating_mul(1_000_000),
        min_fee_rate: c.minrelaytxfee,
        full_rbf: c.mempoolfullrbf,
        dust_relay_fee: c.dustrelayfee,
        data_carrier: c.datacarrier,
        data_carrier_size: c.datacarriersize,
        max_ancestor_count: c.limitancestorcount,
        max_descendant_count: c.limitdescendantcount,
        expiry_secs: c.mempoolexpiry.saturating_mul(3600),
        permit_bare_multisig: c.permitbaremultisig,
    }
}

/// How a live field is pushed into the running node.
enum Apply {
    /// Apply from the new config alone: `f(new, handles)`. The common case —
    /// the value is absolute (a fee rate, a flag), not a delta.
    Whole(fn(&Config, &ReloadHandles)),
    /// Apply from the (old, new) delta: `f(old, new, handles)`. For list-valued
    /// keys where only the *added* entries should act (e.g. dialing newly-added
    /// `-addnode` peers without re-dialing existing ones).
    Delta(fn(&Config, &Config, &ReloadHandles)),
}

/// One config field's reload disposition.
struct FieldSpec {
    /// The `bitcoin.conf` key name (matches [`config::KNOWN_CONFIG_KEYS`]).
    key: &'static str,
    /// Returns `Some((old, new))` (Debug-formatted) iff the field differs.
    /// Debug-format comparison is uniform across all field types and needs no
    /// `PartialEq` impl on the field (e.g. `WhitelistEntry` has none).
    diff: fn(&Config, &Config) -> Option<(String, String)>,
    /// `None` => restart-required (report only). `Some(_)` => live path that
    /// pushes the value into the running node.
    apply: Option<Apply>,
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
    "allowignoredconf",
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
    // live: report if changed AND push to the running node via `$apply`
    // (`fn(&Config, &ReloadHandles)`).
    macro_rules! live {
        ($key:expr, $field:ident, $apply:expr) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: Some(Apply::Whole($apply)),
                sensitive: false,
            }
        };
    }
    // live AND secret: applied live, but old/new values redacted in the report.
    macro_rules! live_secret {
        ($key:expr, $field:ident, $apply:expr) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: Some(Apply::Whole($apply)),
                sensitive: true,
            }
        };
    }
    // live, delta-aware: `$apply` is `fn(&Config /*old*/, &Config /*new*/,
    // &ReloadHandles)` so it can act on only the entries added since the last
    // config (e.g. dial newly-added peers without churning existing ones).
    macro_rules! live_delta {
        ($key:expr, $field:ident, $apply:expr) => {
            FieldSpec {
                key: $key,
                diff: |old, new| {
                    let o = format!("{:?}", old.$field);
                    let n = format!("{:?}", new.$field);
                    if o != n { Some((o, n)) } else { None }
                },
                apply: Some(Apply::Delta($apply)),
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
        // The fmt layer (timestamps / thread-names / source-locations) is
        // built once at startup alongside the format, so these are restart-only.
        restart!("logtimestamps", log_timestamps),
        restart!("logthreadnames", log_thread_names),
        restart!("logsourcelocations", log_source_locations),
        // -checkpoints is consumed once at ChainState construction.
        restart!("checkpoints", enforce_checkpoints),
        live!("maxshutdownsecs", max_shutdown_secs, consumed_from_reloaded_config),
        live!("debug", debug, |c, h| h.log_filter.reload(c)),
        live!("debugexclude", debugexclude, |c, h| h.log_filter.reload(c)),
        live!("loglevel", log_level, |c, h| h.log_filter.reload(c)),
        // ---- RPC server ----
        restart!("rpcport", rpcport),
        restart!("rpcbind", rpcbind),
        restart!("rpcallowip", rpcallowip),
        // RPC admission budget is fixed at server-build time (the
        // AdmissionState is constructed in rpc::server::start), so changing
        // it requires a restart.
        restart!("rpcthreads", rpc_threads),
        restart!("rpcworkqueue", rpc_workqueue),
        // The token store binds to a fixed path when it is loaded at startup
        // and is shared (as an `Arc`) with the surfaces. Changing WHERE the
        // file lives therefore requires a restart; changing its CONTENTS (token
        // edits / revocations) is picked up live by the independent
        // `token_store.reload()` at the end of `reload_from_sighup`.
        restart!("authfile", authfile),
        // Whether a listener installs the bearer carrier + capability filter is
        // decided when the listener is built at startup, so toggling it requires
        // a restart. (Token edits/revocations are live — see authfile.)
        restart!("rpcauthbearer", rpc_auth_bearer),
        // The API runtime's worker count is fixed when the runtime is built
        // at startup; changing it requires a restart.
        restart!("apithreads", api_threads),
        // The opt-in read-only listener is bound and its admission budget +
        // method filter wired at server-build time, so every read-only knob
        // is restart-only.
        restart!("rpcreadonlybind", rpc_readonly_bind),
        restart!("rpcreadonlyport", rpc_readonly_port),
        restart!("rpcreadonlyallowip", rpc_readonly_allowip),
        restart!("rpcreadonlythreads", rpc_readonly_threads),
        restart!("rpcreadonlyworkqueue", rpc_readonly_workqueue),
        // Read-only TLS surface: bound + acceptor built at startup. The cert/
        // key themselves hot-reload via SIGUSR1 (tls_config registry), but
        // the bind/mTLS-policy wiring is restart-only, like the main RPC TLS.
        restart!("rpcreadonlytlsbind", rpc_readonly_tls_bind),
        restart!("rpcreadonlytlscert", rpc_readonly_tls_cert),
        restart!("rpcreadonlytlskey", rpc_readonly_tls_key),
        restart!("rpcreadonlymtls", rpc_readonly_mtls),
        restart!("rpcreadonlymtlsclientca", rpc_readonly_mtls_client_ca),
        restart!("rpcreadonlymtlsclientallow", rpc_readonly_mtls_client_allow),
        live_secret!("rpcuser", rpcuser, apply_rpc_credentials),
        live_secret!("rpcpassword", rpcpassword, apply_rpc_credentials),
        live_secret!("rpcauth", rpcauth, apply_rpc_credentials),
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
        // The global relay-permission defaults are baked into the rebuilt
        // whitelist entries, so re-pushing the whitelist applies a change.
        live!("whitelistrelay", whitelist_relay, |c, h| {
            h.peer_manager.set_whitelist(c.whitelist.clone())
        }),
        live!("whitelistforcerelay", whitelist_force_relay, |c, h| {
            h.peer_manager.set_whitelist(c.whitelist.clone())
        }),
        restart!("whitebind", whitebind),
        restart!("asmap", asmap),
        restart!("port", port),
        restart!("bind", bind),
        live_delta!("connect", connect, |old, new, h| dial_added_peers(
            &old.connect,
            &new.connect,
            &h.peer_manager,
            "connect"
        )),
        live_delta!("addnode", addnode, |old, new, h| dial_added_peers(
            &old.addnode,
            &new.addnode,
            &h.peer_manager,
            "addnode"
        )),
        live_delta!("seednode", seednode, dial_added_seednodes),
        live!("maxconnections", maxconnections, |c, h| {
            h.peer_manager.set_max_connections(c.maxconnections)
        }),
        live!("maxinboundperip", maxinboundperip, |c, h| {
            h.peer_manager.set_max_inbound_per_ip(c.maxinboundperip)
        }),
        live!("maxuploadtarget", max_upload_target, |c, h| {
            h.peer_manager.set_max_upload_target(c.max_upload_target)
        }),
        restart!("dns", dns),
        restart!("dnsseed", dnsseed),
        restart!("forcednsseed", forcednsseed),
        restart!("fixedseeds", fixedseeds),
        live!("bantime", bantime, |c, h| {
            h.peer_manager.set_ban_duration_secs(c.bantime)
        }),
        live!("timeout", timeout, |c, h| {
            h.peer_manager.set_connect_timeout_ms(c.timeout)
        }),
        restart!("onlynet", onlynet),
        restart!("signetseednode", signet_seed_nodes),
        restart!("signetchallenge", signet_challenge),
        // ---- Proxy / Tor ----
        restart!("proxy", proxy),
        restart!("proxyrandomize", proxyrandomize),
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
        live!("addrindexsubscriptions", addrindexsubscriptions, |c, h| h
            .addr_sub_registry
            .set_max_subs(c.addrindexsubscriptions)),
        restart!("blockfilterindex", blockfilterindex),
        live!("peerblockfilters", peerblockfilters, |c, h| h
            .peer_manager
            .set_peer_serve_filters(c.peerblockfilters)),
        // ---- Mempool / relay policy ----
        // All map into a single `MempoolConfig` swapped atomically via
        // `reload_policy`; `accept_transaction` snapshots the policy at entry,
        // so the change governs subsequent admissions (admitted entries are not
        // re-evaluated). They share one apply that rebuilds the whole policy.
        live!("mempoolfullrbf", mempoolfullrbf, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("maxmempool", maxmempool, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("minrelaytxfee", minrelaytxfee, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("dustrelayfee", dustrelayfee, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("datacarrier", datacarrier, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("datacarriersize", datacarriersize, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("limitancestorcount", limitancestorcount, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("limitdescendantcount", limitdescendantcount, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        live!("mempoolexpiry", mempoolexpiry, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
        // `persistmempool` only governs save-on-shutdown behavior, which reads
        // the (reassigned) running config at exit — report rather than apply.
        live!("persistmempool", persistmempool, consumed_from_reloaded_config),
        live!("permitbaremultisig", permitbaremultisig, |c, h| {
            h.mempool.reload_policy(mempool_config_from(c))
        }),
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
        restart!("esploraauthbearer", esplora_auth_bearer),
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
        restart!("checkblockindex", check_block_index),
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
        restart!("eventsgrpcauth", events_grpc_auth),
        // gRPC admission caps are applied when the sink is built at
        // startup; changing them requires a restart.
        restart!("eventsgrpcmaxconns", events_grpc_max_conns),
        restart!("eventsgrpcmaxsubscriptions", events_grpc_max_subscriptions),
        restart!("eventszmqbind", events_zmq_bind),
        restart!("eventszmqhashtx", events_zmq_hashtx),
        restart!("eventszmqhashblock", events_zmq_hashblock),
        restart!("eventszmqmpevict", events_zmq_mpevict),
        restart!("eventszmqmpreplace", events_zmq_mpreplace),
        restart!("eventszmqmpconfirm", events_zmq_mpconfirm),
        restart!("eventszmqnodeevent", events_zmq_nodeevent),
        // Streaming WS/SSE transport: the listener is bound on the API
        // runtime at startup; changing the bind/auth posture requires a
        // restart (same disposition as the events-grpc listener).
        restart!("streamws", streamws_bind),
        restart!("streamwsallowremote", streamws_allow_remote),
        restart!("streamwsauth", streamws_auth),
        // Listener caps are bound at WsStreamServer construction (startup), so a
        // change takes effect on restart.
        restart!("streamwsmaxconns", streamws_max_conns),
        restart!("streamwsmaxsubscriptions", streamws_max_subscriptions),
        restart!("streamwsmaxmessagebytes", streamws_max_message_bytes),
        // The matcher captures this cap when spawned at startup, so a change
        // takes effect on restart (same disposition as the listener caps).
        restart!("streammaxresyncblocks", stream_max_resync_blocks),
        // Prefix-watch granularity bounds bind at listener construction (startup).
        restart!("streamprefixminbits", stream_prefix_min_bits),
        restart!("streamprefixmaxbits", stream_prefix_max_bits),
        // ---- Webhooks ----
        live!("reorgwebhook", reorg_webhook, apply_webhook),
        live_secret!("reorgwebhooksecret", reorg_webhook_secret, apply_webhook),
        // ---- MCP ----
        restart!("mcp", mcp),
        restart!("mcpport", mcp_port),
        restart!("mcpbind", mcp_bind),
        restart!("mcpcert", mcp_tls_cert),
        restart!("mcpkey", mcp_tls_key),
        restart!("mcpmtls", mcp_mtls),
        restart!("mcpmtlsclientca", mcp_mtls_client_ca),
        restart!("mcpmtlsclientallow", mcp_mtls_client_allow),
        restart!("mcpauth", mcp_auth),
        restart!("mcpallowremote", mcp_allow_remote),
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
                    match apply {
                        Apply::Whole(f) => f(&new, handles),
                        Apply::Delta(f) => f(running, &new, handles),
                    }
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

    // Independently re-read the unified-auth token file (if configured). This
    // is intentionally decoupled from the network/consensus config diff above:
    // a SIGHUP must pick up token edits — above all, revocations — even when no
    // `bitcoin.conf` key changed. A re-read error keeps the last-good table.
    if let Some(store) = &handles.token_store {
        match store.reload() {
            Ok(delta) => {
                if !delta.removed.is_empty() {
                    tracing::warn!(
                        revoked = ?delta.removed,
                        "auth token(s) revoked on reload"
                    );
                }
                if !delta.added.is_empty() {
                    tracing::info!(added = ?delta.added, "auth token(s) added on reload");
                }
                if delta.added.is_empty() && delta.removed.is_empty() {
                    tracing::debug!("auth token file reloaded: no token changes");
                }
            }
            Err(e) => tracing::error!(
                error = %e,
                path = %store.path().display(),
                "auth token file reload failed — keeping the last-good token table"
            ),
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

    /// The settings promoted to hot-reloadable in this change are all live.
    /// Guards against a refactor silently dropping one back to restart-only.
    #[test]
    fn tier1_keys_are_live() {
        let specs = field_specs();
        let find = |k: &str| specs.iter().find(|s| s.key == k).unwrap();
        for key in [
            "connect",
            "addnode",
            "seednode",
            "peerblockfilters",
            "addrindexsubscriptions",
            "persistmempool",
            "maxshutdownsecs",
            "reorgwebhook",
            "reorgwebhooksecret",
        ] {
            assert!(
                find(key).apply.is_some(),
                "{key:?} should be hot-reloadable (live)"
            );
        }
        // The peer-list keys act on the (old, new) delta, not the new value
        // alone — verify they use the delta apply path.
        for key in ["connect", "addnode", "seednode"] {
            assert!(
                matches!(find(key).apply, Some(Apply::Delta(_))),
                "{key:?} should use the delta apply (dial only added peers)"
            );
        }
    }

    /// `webhook_target_from` mirrors the config: `None` with no URL, else the
    /// URL plus optional secret. This is what the reload apply stores into the
    /// shared target the dispatcher reads.
    #[test]
    fn webhook_target_tracks_config() {
        let mut c = test_config();
        c.reorg_webhook = None;
        c.reorg_webhook_secret = None;
        assert!(webhook_target_from(&c).is_none(), "no URL => no target");

        c.reorg_webhook = Some("https://example.com/hook".to_string());
        c.reorg_webhook_secret = Some("s3cret".to_string());
        let t = webhook_target_from(&c).expect("target built");
        assert_eq!(t.url, "https://example.com/hook");
        assert_eq!(t.secret.as_deref(), Some("s3cret"));

        // URL without a secret => unsigned webhook.
        c.reorg_webhook_secret = None;
        assert!(webhook_target_from(&c).unwrap().secret.is_none());
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
        let find = |key: &str| {
            specs
                .iter()
                .find(|s| s.key == key)
                .unwrap_or_else(|| panic!("secret key {key:?} missing from field_specs()"))
        };
        // Every secret-bearing key must redact its value in the report,
        // whether or not it is applied live.
        for key in [
            "rpcuser",
            "rpcpassword",
            "rpcauth",
            "torpassword",
            "esplorauserpass",
            "reorgwebhooksecret",
        ] {
            assert!(
                find(key).sensitive,
                "{key:?} holds secret material and must be marked sensitive \
                 (redacted in the reload report)"
            );
        }
        // Secrets wired into long-lived startup state stay restart-only.
        for key in ["torpassword", "esplorauserpass"] {
            assert!(find(key).apply.is_none(), "{key:?} must be restart-only");
        }
        // Live-rotatable secrets: applied live but still redacted in the
        // report. RPC credentials rotate via the shared auth handle; the
        // reorg-webhook secret via the shared dispatcher target.
        for key in ["rpcuser", "rpcpassword", "rpcauth", "reorgwebhooksecret"] {
            assert!(
                find(key).apply.is_some(),
                "{key:?} should be live (rotatable without restart)"
            );
        }
    }
}
