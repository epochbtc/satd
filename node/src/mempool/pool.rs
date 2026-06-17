use bitcoin::{Block, OutPoint, Transaction, TxOut, Txid};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::broadcast;

use crate::chain::state::ChainState;
use crate::mempool::events::{EvictReason, MempoolEvent, QuarantineEvent};
use crate::mempool::policy::{self, MAX_STANDARD_TX_WEIGHT};
use crate::mempool::policy_engine::{self, PolicyCtx};
use crate::validation::script::ScriptVerifier;
use crate::validation::tx::check_transaction;
use node_index::keys::{scripthash_of, Scripthash};

/// Capacity of the broadcast channel for `subscribemempool`. Large
/// enough to absorb short bursts; a subscriber that lags past this
/// will see `RecvError::Lagged` and skip to the latest events —
/// correct behavior for a best-effort stream.
pub const EVENT_BROADCAST_CAPACITY: usize = 1024;

/// Capacity of the in-memory event ring tapped by MCP
/// `subscribe_mempool_snapshot`. Kept small — MCP is request/response,
/// clients pull the last N events, not a long history.
pub const EVENT_RING_CAPACITY: usize = 50;

/// Coinbase maturity: outputs cannot be spent until this many confirmations.
const COINBASE_MATURITY: u32 = 100;

/// Rule name attributed to a quarantine placement whose held scope is *only*
/// inherited from a quarantined ancestor (§3 infectious descendants) — the tx
/// itself matched no rule. Surfaced in the §6.1 refusal error and the
/// `Quarantined` event so the cause is legible.
const INFECTIOUS_RULE: &str = "(infectious: quarantined ancestor)";

/// Current Unix time in seconds (saturating to 0 before the epoch). Used for
/// policy-load timestamps; the hot paths inline their own `now`.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("txn-already-in-mempool")]
    AlreadyExists,
    #[error("txn-mempool-conflict")]
    ConflictingSpend,
    #[error("bad-txns-inputs-missingorspent")]
    MissingInputs,
    #[error("min relay fee not met. {0} < {1}")]
    InsufficientFee(u64, u64),
    #[error("mempool full")]
    MempoolFull,
    #[error("{0}")]
    Validation(String),
    #[error("mandatory-script-verify-flag-failed ({0})")]
    Script(String),
    #[error("bad-txns-in-belowout")]
    BadAmounts,
    #[error("bad-txns-premature-spend-of-coinbase")]
    PrematureCoinbaseSpend,
    #[error("TX decode failed")]
    DecodeFailed,
    #[error("dust")]
    Dust,
    #[error("scriptpubkey")]
    NonStandardOpReturn,
    #[error("insufficient fee for RBF. {0} < {1}")]
    InsufficientReplacementFee(u64, u64),
    #[error("too-long-mempool-chain")]
    TooLongMempoolChain,
    /// A locally-submitted transaction drew a relay-scoped quarantine verdict
    /// (design §6.1): refused rather than silently held, with the rule named.
    /// Resubmit with `allowquarantined` to hold it locally anyway. P2P-sourced
    /// transactions are never refused — they quarantine as designed.
    #[error(
        "txn-policy-quarantined: held by policy rule '{0}' (would not be relayed); \
         resubmit with allowquarantined=true to hold it locally"
    )]
    Quarantined(String),
}

/// How a transaction reached this node — the value behind the policy engine's
/// `tx.source` attribute (design §4.3). Recorded on every [`MempoolEntry`] at
/// admission. As of PR 4a it is *recorded but unused*; PR 4c feeds it to the
/// transaction-policy evaluator and PR 4d uses it to distinguish local from
/// peer submissions for the refusal mapping.
///
/// Mirrors `satd_policy::Source`; the eval point converts between them so the
/// node crate need not depend on the policy crate until PR 4c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSource {
    /// Received from a peer over P2P (direct relay or orphan resolution).
    P2p,
    /// Local JSON-RPC `sendrawtransaction`.
    Rpc,
    /// Electrum `transaction.broadcast` / `broadcast_package`.
    Electrum,
    /// Esplora `POST /tx`.
    Esplora,
    /// MCP `send_transaction` tool.
    Mcp,
    /// Re-evaluation of an already-resident transaction: `mempool.dat` reload at
    /// startup, or re-offer of a disconnected block's transactions after a reorg.
    Reload,
}

impl TxSource {
    /// True for the four local submission surfaces (`sendrawtransaction`,
    /// Electrum broadcast, Esplora `POST /tx`, MCP `send_transaction`). These are
    /// subject to the §6.1 relay-quarantine refusal; `P2p` and `Reload` are not
    /// (P2P traffic quarantines as designed; reloaded/reorged txs re-enter
    /// normally).
    pub fn is_local(self) -> bool {
        matches!(
            self,
            TxSource::Rpc | TxSource::Electrum | TxSource::Esplora | TxSource::Mcp
        )
    }
}

/// The relay/template surfaces a quarantined mempool entry is withheld from
/// (design §3, §5). An **empty** scope marks an ordinary "acting" entry — the
/// only kind that exists until a policy is loaded (PR 4c). A non-empty scope
/// marks a held ("quarantine class") entry: `relay` withholds it from
/// announce / serve / rebroadcast, `template` withholds it from blocks this
/// node builds. Mirrors `satd_policy::ScopeSet`; PR 4c maps the policy
/// verdict's scope onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuarantineScope {
    pub relay: bool,
    pub template: bool,
}

impl QuarantineScope {
    /// Acting entry — withheld from nothing.
    pub const fn acting() -> Self {
        QuarantineScope {
            relay: false,
            template: false,
        }
    }
    /// True for an acting (non-quarantined) entry.
    pub fn is_acting(self) -> bool {
        !self.relay && !self.template
    }
    /// True for a held (quarantine-class) entry.
    pub fn is_quarantined(self) -> bool {
        !self.is_acting()
    }
    /// True if the entry may be assisted on the **relay** path — announced via
    /// `inv`, BIP35-listed, served via `getdata`, and rebroadcast. False once
    /// the `relay` scope withholds it. (A `quarantine … on template` entry is
    /// still relayed; only the `relay` bit gates this path — design §3.)
    pub fn assists_relay(self) -> bool {
        !self.relay
    }
    /// True if the entry may be assisted on the **template** path — selected
    /// into block templates this node builds *and* counted by the mempool
    /// smart-fee simulator (which simulates what we would mine — design §2.4).
    /// False once the `template` scope withholds it.
    pub fn assists_template(self) -> bool {
        !self.template
    }
}

/// Metadata for a transaction in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub fee: u64,
    pub weight: usize,
    pub fee_rate: u64,
    pub time: u64,
    /// Miner-adjustable fee delta (satoshis) from `prioritisetransaction`.
    pub fee_delta: i64,
    /// BIP 141 witness-aware sigop cost of this tx. Computed at admission
    /// using the resolved `prev_outputs` so P2SH / P2WSH redeem scripts are
    /// accounted for accurately.
    pub sigop_cost: u64,
    /// `sha256(scriptPubKey)` of each spent prevout, one per input in input
    /// order (`prev_scripthashes[i]` ↔ `tx.input[i]`). Resolved once at
    /// admission from `prev_outputs` (which is otherwise discarded) so the
    /// streaming watch matcher can do **mempool spend-side** matching (exact
    /// script and prefix bucket) — the unconfirmed analogue of the undo-driven
    /// confirmed path — without re-resolving prevouts off the hot path. Hashes
    /// (32 B/input), not full scripts: enough to match, bounded by mempool size.
    /// Empty for entries built outside admission (test fixtures, direct inserts).
    pub prev_scripthashes: Vec<Scripthash>,
    /// How this transaction reached the node. Recorded at admission for the
    /// transaction-policy engine (`tx.source`); unused until PR 4c.
    pub source: TxSource,
    /// Quarantine scope. Empty ([`QuarantineScope::acting`]) for every entry
    /// until a policy is loaded (PR 4c); a non-empty scope places the entry in
    /// the quarantine class for per-class accounting and eviction.
    pub scope: QuarantineScope,
    /// Name of the policy rule responsible for the current `scope` (the tx's own
    /// first-match rule, or the infectious-ancestor marker when the scope is
    /// only inherited). `None` for acting entries. Stamped at admission and
    /// re-stamped by the reload re-placement pass; surfaced by the quarantine
    /// observability extension (`listquarantine`/`getquarantineentry`/
    /// `getquarantineinfo`, PR 7b). Never leaks onto a standard surface.
    pub quarantine_rule: Option<String>,
}

/// Statistics about the mempool.
#[derive(Debug, Clone)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
    pub max_size: usize,
    pub min_fee_rate: u64,
    pub full_rbf: bool,
    /// Count of locally-originated txs not yet confirmed propagated.
    pub unbroadcast: usize,
}

/// Outcome of a ruleset re-placement pass ([`Mempool::reapply_policy`], §8).
/// The caller drives the side effects it owns from these lists: re-announcing
/// `promoted` transactions on the bounded promotion queue and re-arming local
/// rebroadcast (PR 6b). `evicted` are entries dropped only because a class
/// overflowed its budget *after* the moves (the sole lossy outcome permitted by
/// I9). `demoted` is informational (the events already fired).
/// Outcome of a live policy-file reload ([`Mempool::reload_policy_file`], §8).
pub enum PolicyReloadKind {
    /// The file's contents were unchanged (same `sha256`); nothing was swapped
    /// and no re-placement is needed.
    Unchanged,
    /// A new ruleset was compiled and swapped in. The caller should run
    /// [`Mempool::reapply_policy`] and announce the resulting promotions. Carries
    /// the load summary for logging.
    Changed(policy_engine::PolicyLoad),
}

#[derive(Debug, Default, Clone)]
pub struct PolicyTransition {
    /// Quarantine → acting (scope cleared, or it newly assists relay): must be
    /// re-announced to the network.
    pub promoted: Vec<Txid>,
    /// Acting → quarantine (newly withheld by the reloaded ruleset).
    pub demoted: Vec<Txid>,
    /// Removed by per-class budget eviction after the moves.
    pub evicted: Vec<Txid>,
}

/// Load metadata for the currently-installed ruleset — the source of
/// `getpolicyinfo`'s static fields (design §10). `None` when no ruleset is
/// loaded. Distinct from the live [`CompiledRuleset`] snapshot (which carries
/// the rules themselves) because the path and load time are node-side facts the
/// compiled form does not retain.
#[derive(Debug, Clone)]
pub struct PolicyMeta {
    /// Source file path, when loaded from disk (`None` for a direct
    /// [`Mempool::set_policy`] install — test/embedding only).
    pub path: Option<std::path::PathBuf>,
    pub sha256: String,
    /// Unix seconds at which this ruleset was installed.
    pub loaded_at: u64,
    pub version: u32,
    pub rules: usize,
    pub total_cost: u64,
    pub has_allow: bool,
}

/// Per-rule and aggregate evaluation counters accumulated **since the current
/// ruleset loaded** (reset on every swap). Feeds `getpolicyinfo` and the
/// Prometheus policy counters (PR 7c). The per-rule map is keyed by rule name;
/// a rule's [`satd_policy::ruleset::Action`] tells whether its count is
/// quarantines or allows, so a single count per rule suffices.
#[derive(Debug, Default)]
struct PolicyStats {
    evaluations: std::sync::atomic::AtomicU64,
    fuel_exhausted: std::sync::atomic::AtomicU64,
    per_rule: Mutex<HashMap<String, u64>>,
}

impl PolicyStats {
    fn reset(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.evaluations.store(0, Relaxed);
        self.fuel_exhausted.store(0, Relaxed);
        self.per_rule.lock().clear();
    }

    /// Record one evaluation outcome. Cheap (one atomic + a small map bump on a
    /// match); the `per_rule` mutex is a strict leaf — only ever acquired here
    /// and in [`Mempool::policy_stats_snapshot`], never while it is itself held.
    fn record(&self, verdict: &satd_policy::Verdict) {
        use std::sync::atomic::Ordering::Relaxed;
        self.evaluations.fetch_add(1, Relaxed);
        if let Some(rule) = verdict.rule() {
            *self.per_rule.lock().entry(rule.to_string()).or_insert(0) += 1;
            if rule == satd_policy::verdict::FUEL_RULE {
                self.fuel_exhausted.fetch_add(1, Relaxed);
            }
        }
    }

    fn snapshot(&self) -> PolicyStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        PolicyStatsSnapshot {
            evaluations: self.evaluations.load(Relaxed),
            fuel_exhausted: self.fuel_exhausted.load(Relaxed),
            per_rule: self.per_rule.lock().clone(),
        }
    }
}

/// A consistent read of [`PolicyStats`] for `getpolicyinfo`.
#[derive(Debug, Clone, Default)]
pub struct PolicyStatsSnapshot {
    pub evaluations: u64,
    pub fuel_exhausted: u64,
    pub per_rule: HashMap<String, u64>,
}

/// One quarantined entry as surfaced by `listquarantine` (design §10).
#[derive(Debug, Clone)]
pub struct QuarantineListEntry {
    pub txid: Txid,
    pub rule: String,
    pub relay: bool,
    pub template: bool,
    pub time: u64,
    pub vsize: u64,
    pub fee: u64,
    pub fee_rate: u64,
}

/// Detailed view of a single quarantined entry — the `getmempoolentry` analogue
/// for the quarantine class (`getquarantineentry`, design §10).
#[derive(Debug, Clone)]
pub struct QuarantineEntryDetail {
    pub txid: Txid,
    pub rule: String,
    pub relay: bool,
    pub template: bool,
    pub time: u64,
    pub vsize: u64,
    pub weight: u64,
    pub fee: u64,
    pub fee_rate: u64,
    /// In-mempool parents (`depends`), regardless of class.
    pub depends: Vec<Txid>,
}

/// Per-rule rollup within the quarantine class.
#[derive(Debug, Clone, Default)]
pub struct QuarantineRuleStat {
    pub count: u64,
    pub bytes: u64,
    pub min_fee_rate: u64,
    pub max_fee_rate: u64,
}

/// The comparison surface for `getquarantineinfo` (design §10): live per-rule
/// rollup of the quarantine class plus the two economic signals — foregone fees
/// and the confirmed-anyway count.
#[derive(Debug, Clone, Default)]
pub struct QuarantineReport {
    pub total_count: u64,
    pub total_bytes: u64,
    pub budget_bytes: u64,
    pub per_rule: HashMap<String, QuarantineRuleStat>,
    /// Sum of fees (sat) of **template-withheld** quarantined txs whose fee rate
    /// exceeds the supplied template floor — what declining to mine them is
    /// costing a miner. Relay-only quarantine is still mined, so it is excluded.
    pub foregone_fees_sat: u64,
    /// Quarantined txs later seen confirmed in a block (process-lifetime; D4's
    /// evidence that filtering cannot prevent confirmation, only decline to
    /// assist it).
    pub confirmed_anyway: u64,
}

struct MempoolInner {
    entries: HashMap<Txid, MempoolEntry>,
    spends: HashMap<OutPoint, Txid>,
    /// Serialized bytes of **all** entries (acting + quarantine) — the single
    /// physical pool's occupancy. `acting_bytes()` derives the acting class by
    /// subtracting `quarantine_bytes`.
    total_bytes: usize,
    /// Serialized bytes of the **quarantine class** alone (entries whose
    /// [`MempoolEntry::scope`] is non-empty). Maintained in lockstep with
    /// `total_bytes` by [`MempoolInner::account_insert`] /
    /// [`MempoolInner::account_remove`]. Always 0 until a policy is loaded
    /// (PR 4c), so `acting_bytes() == total_bytes` and behavior is unchanged.
    quarantine_bytes: usize,
    /// Locally-originated txs (submitted here via a broadcast surface) that
    /// have not yet been confirmed to have propagated. Maps each txid to the
    /// set of peer IPs that have since demonstrated knowledge of it
    /// (fetched it via `getdata` or announced it back) — evidence it reached
    /// the network. Witnesses are keyed by IP, not per-connection peer id:
    /// peer ids are monotonic and never reused, so a single host
    /// reconnecting could otherwise satisfy any `broadcastconfirmpeers`
    /// threshold with sequential connections. The peer manager rebroadcasts
    /// these on a timer and on new-peer-connect; an entry is dropped once
    /// enough distinct witnesses accrue (see
    /// [`Mempool::record_broadcast_witness`]) or the tx leaves the mempool
    /// (mined/evicted/replaced/expired — every removal path prunes it).
    /// Always a subset of `entries`. This is satd's analogue of Core's
    /// `m_unbroadcast_txids`, surfaced as `getmempoolinfo.unbroadcastcount`.
    unbroadcast: HashMap<Txid, HashSet<std::net::IpAddr>>,
}

impl MempoolInner {
    /// Bytes occupied by the **acting class** (everything not quarantined). The
    /// acting capacity check (`max_size_bytes`) is measured against this, not
    /// the physical `total_bytes`, so the quarantine class never crowds the
    /// acting mempool. Equal to `total_bytes` until a policy is loaded (PR 4c).
    fn acting_bytes(&self) -> usize {
        self.total_bytes.saturating_sub(self.quarantine_bytes)
    }

    /// Account a newly-inserted entry of `tx_size` bytes into the per-class
    /// counters. Call right after `entries.insert`.
    fn account_insert(&mut self, scope: QuarantineScope, tx_size: usize) {
        self.total_bytes += tx_size;
        if scope.is_quarantined() {
            self.quarantine_bytes += tx_size;
        }
    }

    /// Reverse [`account_insert`](Self::account_insert) for a removed entry.
    /// Call right after `entries.remove`, passing the removed entry's scope and
    /// serialized size.
    fn account_remove(&mut self, scope: QuarantineScope, tx_size: usize) {
        self.total_bytes = self.total_bytes.saturating_sub(tx_size);
        if scope.is_quarantined() {
            self.quarantine_bytes = self.quarantine_bytes.saturating_sub(tx_size);
        }
    }
}

/// Configurable mempool policy. All fields map to Bitcoin Core-compatible
/// config flags, with the same defaults (or more permissive where noted).
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_size_bytes: usize,
    pub min_fee_rate: u64,
    pub full_rbf: bool,
    pub dust_relay_fee: u64,
    pub data_carrier: bool,
    pub data_carrier_size: usize,
    pub max_ancestor_count: usize,
    pub max_descendant_count: usize,
    pub expiry_secs: u64,
    pub permit_bare_multisig: bool,
    /// Bitcoin Core's `-acceptnonstdtxn`: when true, skip the *standardness*
    /// relay checks (oversize, dust, OP_RETURN/datacarrier, non-standard
    /// output scripts) and admit any consensus-valid transaction. Consensus
    /// rules are never relaxed. Default false (standard relay), matching Core.
    pub accept_non_std_txn: bool,
    /// Byte budget for the **quarantine class** (`quarantinemempool`). Held
    /// transactions are accounted and fee-rate-evicted against this, separately
    /// from the acting mempool's `max_size_bytes`. Has no effect until a policy
    /// quarantines something (PR 4c). Default [`policy::DEFAULT_QUARANTINE_MEMPOOL_SIZE`].
    pub quarantine_max_bytes: usize,
    /// `allowdangerousfilters`: opt out of the strict-by-default Lightning-
    /// enforcement danger gate. When false (default), a policy file with a rule
    /// that would **withhold relay** for an L2 enforcement shape is refused at
    /// load (fatal at startup; last-good kept on SIGHUP). When true, such rules
    /// load with a loud warning instead. Template-only matches always warn-only.
    pub allow_dangerous_filters: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: policy::DEFAULT_MAX_MEMPOOL_SIZE,
            min_fee_rate: policy::DEFAULT_MIN_RELAY_FEE_RATE,
            full_rbf: true,
            dust_relay_fee: policy::DUST_RELAY_FEE_RATE,
            data_carrier: true,
            data_carrier_size: policy::MAX_OP_RETURN_SIZE,
            max_ancestor_count: policy::MAX_ANCESTOR_COUNT,
            max_descendant_count: policy::MAX_DESCENDANT_COUNT,
            expiry_secs: policy::MEMPOOL_EXPIRY_SECS,
            permit_bare_multisig: true,
            accept_non_std_txn: false,
            quarantine_max_bytes: policy::DEFAULT_QUARANTINE_MEMPOOL_SIZE,
            allow_dangerous_filters: false,
        }
    }
}

/// In-memory transaction pool.
pub struct Mempool {
    inner: RwLock<MempoolInner>,
    /// Mirror of `inner.unbroadcast.len()`, maintained at every mutation
    /// site (under the `inner` write lock, so it is always coherent with
    /// the map). Lets the hot P2P paths (`inv`/`getdata` handlers asking
    /// "could this be a pending local broadcast?") skip the `inner` lock
    /// entirely in the ~always case where nothing is pending — a relay
    /// node would otherwise pay a write-lock acquisition per inv item.
    unbroadcast_len: std::sync::atomic::AtomicUsize,
    /// Mempool/relay policy. Behind a `RwLock` so SIGHUP config reload can swap
    /// it live (`reload_policy`); `accept_transaction` snapshots it once at
    /// entry so a transaction is judged against a single policy version.
    ///
    /// Lock discipline: this is a **leaf lock** — acquire, read/clone what you
    /// need, release. NEVER hold it while acquiring `inner` (snapshot the needed
    /// fields into locals first, as `remove_expired`/`info` do). This keeps the
    /// lock order uniform so a concurrent `reload_policy` write can never form a
    /// cycle with `inner`.
    config: RwLock<MempoolConfig>,
    /// Live transaction-filtering policy ruleset (the DSL engine, §7). `None`
    /// until a `policyfile` is loaded; an empty ruleset is also possible but the
    /// hot path treats both as "no policy" (I8 — byte-identical to a build with
    /// the engine compiled out). Behind an `ArcSwap` so the admission hot path
    /// reads the pointer lock-free while startup load / SIGHUP reload (PR 6) swap
    /// it atomically. Snapshotted once at the top of `accept_transaction` so a
    /// transaction is judged against a single ruleset version.
    policy: arc_swap::ArcSwapOption<satd_policy::CompiledRuleset>,
    /// `sha256` of the source text of the currently-loaded `policyfile` (the
    /// digest [`policy_engine::load_policy_file`] returns). Lets the SIGHUP
    /// handler ([`Self::reload_policy_file`]) detect a no-op reload — same file
    /// contents — and skip the (bounded but non-trivial) re-placement walk. The
    /// `CompiledRuleset` itself carries no digest, so it is tracked here. `None`
    /// when no ruleset is loaded.
    policy_sha: Mutex<Option<String>>,
    /// Load metadata for the installed ruleset (`getpolicyinfo` static fields).
    /// Set alongside `policy`/`policy_sha`; `None` when no ruleset is loaded.
    policy_meta: Mutex<Option<PolicyMeta>>,
    /// Per-rule and aggregate evaluation counters since the current ruleset
    /// loaded (reset on every swap). Drives `getpolicyinfo` and the Prometheus
    /// policy counters.
    policy_stats: PolicyStats,
    /// Quarantined transactions later observed confirmed in a block — the
    /// confirmed-anyway signal (D4). Process-lifetime, never reset on reload,
    /// so the evidence accumulates across ruleset edits. Surfaced by
    /// `getquarantineinfo`.
    quarantine_confirmed: std::sync::atomic::AtomicU64,
    /// Process-lifetime policy-transition and reload counters for the Prometheus
    /// surface (PR 7c). `promoted`/`demoted` accumulate the re-placement moves
    /// across reloads; `reload_failures` counts SIGHUP reloads that kept
    /// last-good on a compile error.
    policy_promoted_total: std::sync::atomic::AtomicU64,
    policy_demoted_total: std::sync::atomic::AtomicU64,
    policy_reload_failures: std::sync::atomic::AtomicU64,
    /// Broadcast channel fanout for `subscribemempool`. Populated via
    /// `set_event_sender`; remains `None` in tests that don't need
    /// event emission.
    event_tx: Mutex<Option<broadcast::Sender<MempoolEvent>>>,
    /// Bounded ring of recent events for MCP snapshot consumption.
    /// Always maintained (cheap) so MCP tools work whether or not
    /// the broadcast sender is wired.
    event_ring: Mutex<VecDeque<MempoolEvent>>,
    /// Separate broadcast channel for quarantine-class lifecycle events
    /// (design §10): the default `event_tx` stream stays acting-class only, so a
    /// quarantined admission emits no `Enter` there — it emits `Quarantined`
    /// here instead. Wired by the opt-in subscription surface (PR 7); `None`
    /// until then, so emission is a no-op exactly like `event_tx`.
    quarantine_event_tx: Mutex<Option<broadcast::Sender<QuarantineEvent>>>,
}

impl Mempool {
    pub fn new(max_size_bytes: usize, min_fee_rate: u64) -> Self {
        Self::with_config(MempoolConfig {
            max_size_bytes,
            min_fee_rate,
            ..Default::default()
        })
    }

    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                entries: HashMap::new(),
                spends: HashMap::new(),
                total_bytes: 0,
                quarantine_bytes: 0,
                unbroadcast: HashMap::new(),
            }),
            unbroadcast_len: std::sync::atomic::AtomicUsize::new(0),
            config: RwLock::new(config),
            policy: arc_swap::ArcSwapOption::empty(),
            policy_sha: Mutex::new(None),
            policy_meta: Mutex::new(None),
            policy_stats: PolicyStats::default(),
            quarantine_confirmed: std::sync::atomic::AtomicU64::new(0),
            policy_promoted_total: std::sync::atomic::AtomicU64::new(0),
            policy_demoted_total: std::sync::atomic::AtomicU64::new(0),
            policy_reload_failures: std::sync::atomic::AtomicU64::new(0),
            event_tx: Mutex::new(None),
            event_ring: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAPACITY)),
            quarantine_event_tx: Mutex::new(None),
        }
    }

    /// Wire a broadcast sender for mempool events. Must be called
    /// once at startup before any mempool mutations that should be
    /// observed by subscribers.
    pub fn set_event_sender(&self, tx: broadcast::Sender<MempoolEvent>) {
        *self.event_tx.lock() = Some(tx);
    }

    /// Subscribe to live mempool events. Returns `None` if no sender
    /// has been wired (typical in tests that bypass `main.rs`).
    pub fn subscribe_events(&self) -> Option<broadcast::Receiver<MempoolEvent>> {
        self.event_tx.lock().as_ref().map(|tx| tx.subscribe())
    }

    /// Wire the broadcast sender for the separate quarantine-event channel
    /// (design §10). Optional; the opt-in subscription surface (PR 7) installs
    /// it. Until then `Quarantined` emissions are dropped, like default events
    /// with no sender.
    pub fn set_quarantine_event_sender(&self, tx: broadcast::Sender<QuarantineEvent>) {
        *self.quarantine_event_tx.lock() = Some(tx);
    }

    /// Subscribe to quarantine-class lifecycle events. `None` if no sender is
    /// wired.
    pub fn subscribe_quarantine_events(&self) -> Option<broadcast::Receiver<QuarantineEvent>> {
        self.quarantine_event_tx
            .lock()
            .as_ref()
            .map(|tx| tx.subscribe())
    }

    /// Return the most recent `EVENT_RING_CAPACITY` events tapped
    /// off the broadcast. Used by MCP `subscribe_mempool_snapshot`.
    pub fn recent_events(&self) -> Vec<MempoolEvent> {
        self.event_ring.lock().iter().cloned().collect()
    }

    /// Emit an event: push into the ring, then best-effort broadcast.
    /// Never blocks; broadcast backpressure is the subscriber's problem.
    fn emit(&self, event: MempoolEvent) {
        {
            let mut ring = self.event_ring.lock();
            ring.push_back(event.clone());
            while ring.len() > EVENT_RING_CAPACITY {
                ring.pop_front();
            }
        }
        if let Some(tx) = self.event_tx.lock().as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Emit a quarantine-class event on the separate channel (§10). Best-effort,
    /// no-op when no sender is wired.
    fn emit_quarantine(&self, event: QuarantineEvent) {
        if let Some(tx) = self.quarantine_event_tx.lock().as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Get a snapshot of the current mempool policy. Returns a clone because
    /// the policy is behind a lock (live-reloadable via [`Mempool::reload_policy`]).
    pub fn policy(&self) -> MempoolConfig {
        self.config.read().clone()
    }

    /// Current minimum relay fee rate (sat/kvB). Scalar accessor so hot paths
    /// (e.g. per-peer `feefilter`) avoid cloning the whole policy struct.
    pub fn min_fee_rate(&self) -> u64 {
        self.config.read().min_fee_rate
    }

    /// Current maximum mempool size in bytes.
    pub fn max_size_bytes(&self) -> usize {
        self.config.read().max_size_bytes
    }

    /// Bytes held by the **quarantine class**. Always 0 until a policy is
    /// loaded (PR 4c). Surfaced for per-class observability (PR 7) and tests.
    pub fn quarantine_bytes(&self) -> usize {
        self.inner.read().quarantine_bytes
    }

    /// Bytes occupied by the **acting class** (total minus quarantine). Equal to
    /// the physical pool size until a policy is loaded.
    pub fn acting_bytes(&self) -> usize {
        self.inner.read().acting_bytes()
    }

    /// Swap in a new mempool/relay policy live (SIGHUP config reload). Takes
    /// effect on the next `accept_transaction` call; already-admitted entries
    /// are not re-evaluated.
    pub fn reload_policy(&self, new: MempoolConfig) {
        *self.config.write() = new;
    }

    /// Load (or replace) the transaction-filtering ruleset from a file. Returns
    /// the load summary on success; on failure the previous ruleset is left
    /// untouched (last-good-wins, §8) and a rendered diagnostic is returned.
    /// Startup wiring treats the error as fatal (fail-loud); SIGHUP reload (PR 6)
    /// will keep last-good.
    pub fn load_policy_file(
        &self,
        path: &std::path::Path,
    ) -> Result<policy_engine::PolicyLoad, String> {
        let (ruleset, load) = policy_engine::load_policy_file(path)?;
        self.danger_gate(&ruleset)?;
        self.policy.store(Some(std::sync::Arc::new(ruleset)));
        *self.policy_sha.lock() = Some(load.sha256.clone());
        *self.policy_meta.lock() = Some(Self::build_policy_meta(Some(path), &load));
        self.policy_stats.reset();
        Ok(load)
    }

    /// The strict-by-default Lightning-enforcement danger gate (§2.5).
    ///
    /// Runs the semantic [`satd_policy::analyze_danger`] over the compiled
    /// ruleset. Template-only matches are logged as warnings (E1 turns on relay
    /// homogeneity, and an `on template` rule still relays). A rule that would
    /// **withhold relay** for an enforcement shape is refused (`Err`) unless
    /// `allowdangerousfilters` is set, in which case it loads with a loud
    /// warning. Returning `Err` makes startup fatal and a SIGHUP reload keep
    /// last-good — exactly the existing fail-loud / last-good behavior.
    fn danger_gate(&self, ruleset: &satd_policy::CompiledRuleset) -> Result<(), String> {
        let findings = satd_policy::analyze_danger(ruleset);
        if findings.is_empty() {
            return Ok(());
        }
        let allow = self.config.read().allow_dangerous_filters;
        let mut relay_rules: Vec<&str> = Vec::new();
        for f in &findings {
            if f.withholds_relay() {
                if !relay_rules.contains(&f.rule.as_str()) {
                    relay_rules.push(f.rule.as_str());
                }
                tracing::warn!(
                    rule = %f.rule, shape = %f.shape.label(), scope = %f.scope,
                    "policy rule withholds relay for a Lightning enforcement shape (E1)"
                );
            } else {
                tracing::warn!(
                    rule = %f.rule, shape = %f.shape.label(),
                    "policy rule declines to mine a Lightning enforcement shape \
                     (on template — still relayed)"
                );
            }
        }
        if relay_rules.is_empty() {
            return Ok(());
        }
        if allow {
            tracing::warn!(
                rules = ?relay_rules,
                "loading policy with relay-withholding Lightning-enforcement rule(s); \
                 allowed by allowdangerousfilters"
            );
            Ok(())
        } else {
            Err(format!(
                "refusing policy: rule(s) [{}] would withhold relay for Lightning \
                 enforcement transactions, degrading L2 enforcement network-wide (E1). \
                 Narrow them, scope them `on template`, or set allowdangerousfilters=1 \
                 to override.",
                relay_rules.join(", ")
            ))
        }
    }

    /// Re-evaluate the danger gate against the *currently loaded* ruleset under
    /// the current config — without the per-rule warning side effects of
    /// [`Self::danger_gate`]. Used on SIGHUP to reconcile an already-loaded
    /// policy with a tightened `allowdangerousfilters` even when the policy file
    /// is unchanged: `reload_policy_file` short-circuits on an unchanged sha and
    /// would otherwise skip the gate, leaving a relay-withholding policy live
    /// while strict mode is reported as on. `Ok` when no policy is loaded, the
    /// flag still permits it, or it has no relay-withholding enforcement match;
    /// `Err` (naming the rules) when it is now disallowed and must be ejected.
    pub fn recheck_loaded_danger_gate(&self) -> Result<(), String> {
        let Some(rs) = self.policy.load_full() else {
            return Ok(());
        };
        if rs.is_empty() || self.config.read().allow_dangerous_filters {
            return Ok(());
        }
        let mut relay_rules: Vec<String> = Vec::new();
        for f in satd_policy::analyze_danger(&rs) {
            if f.withholds_relay() && !relay_rules.contains(&f.rule) {
                relay_rules.push(f.rule);
            }
        }
        if relay_rules.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "loaded policy has rule(s) [{}] that withhold relay for Lightning \
                 enforcement transactions (E1) while allowdangerousfilters is off",
                relay_rules.join(", ")
            ))
        }
    }

    /// Build the [`PolicyMeta`] for a freshly-loaded ruleset (load-time fields +
    /// the node-side path/timestamp).
    fn build_policy_meta(
        path: Option<&std::path::Path>,
        load: &policy_engine::PolicyLoad,
    ) -> PolicyMeta {
        PolicyMeta {
            path: path.map(|p| p.to_path_buf()),
            sha256: load.sha256.clone(),
            loaded_at: now_unix_secs(),
            version: load.version,
            rules: load.rules,
            total_cost: load.total_cost,
            has_allow: load.has_allow,
        }
    }

    /// Live SIGHUP reload of the policy file (§8 — the `TokenStore` precedent:
    /// re-read the external file's *contents* on every signal, recompile, swap).
    /// Detects a no-op reload by comparing the source `sha256` to the loaded
    /// ruleset's, so an unchanged file skips the re-placement walk. On a compile
    /// error the previous ruleset is kept untouched (last-good-wins) and the
    /// error is returned for the caller to log — never a partial apply (I7).
    /// The caller drives re-placement ([`Self::reapply_policy`]) and promotion
    /// announcements when this returns [`PolicyReloadKind::Changed`].
    pub fn reload_policy_file(
        &self,
        path: &std::path::Path,
    ) -> Result<PolicyReloadKind, String> {
        let (ruleset, load) = match policy_engine::load_policy_file(path) {
            Ok(v) => v,
            Err(e) => {
                // Last-good kept (I7); count the failed reload for the metric.
                self.policy_reload_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e);
            }
        };
        if self.policy_sha.lock().as_deref() == Some(load.sha256.as_str()) {
            return Ok(PolicyReloadKind::Unchanged);
        }
        // Gate the reload exactly as startup: a relay-withholding enforcement
        // rule keeps last-good (I7) unless allowdangerousfilters is set.
        if let Err(e) = self.danger_gate(&ruleset) {
            self.policy_reload_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(e);
        }
        self.policy.store(Some(std::sync::Arc::new(ruleset)));
        *self.policy_sha.lock() = Some(load.sha256.clone());
        *self.policy_meta.lock() = Some(Self::build_policy_meta(Some(path), &load));
        self.policy_stats.reset();
        Ok(PolicyReloadKind::Changed(load))
    }

    /// Drop any loaded ruleset — reverts the node to baseline behavior (the
    /// engine compiled out, I8). Used when `policyfile` is removed (PR 6) and in
    /// tests.
    pub fn clear_policy(&self) {
        self.policy.store(None);
        *self.policy_sha.lock() = None;
        *self.policy_meta.lock() = None;
        self.policy_stats.reset();
    }

    /// Install an already-compiled ruleset directly. Test/embedding hook; the
    /// file path is the production entry point.
    pub fn set_policy(&self, ruleset: std::sync::Arc<satd_policy::CompiledRuleset>) {
        *self.policy_meta.lock() = Some(PolicyMeta {
            path: None,
            sha256: String::new(),
            loaded_at: now_unix_secs(),
            version: ruleset.version(),
            rules: ruleset.rules().len(),
            total_cost: ruleset.total_cost().total(),
            has_allow: ruleset.has_allow(),
        });
        self.policy_stats.reset();
        self.policy.store(Some(ruleset));
    }

    /// Whether a non-empty ruleset is currently loaded. When false the admission
    /// path skips policy evaluation entirely (I8).
    pub fn has_policy(&self) -> bool {
        self.policy
            .load()
            .as_ref()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }

    /// Snapshot the live ruleset pointer (for `getpolicyinfo`, PR 7).
    pub fn policy_snapshot(&self) -> Option<std::sync::Arc<satd_policy::CompiledRuleset>> {
        self.policy.load_full()
    }

    /// Load metadata for the installed ruleset (`getpolicyinfo` static fields).
    pub fn policy_meta(&self) -> Option<PolicyMeta> {
        self.policy_meta.lock().clone()
    }

    /// Per-rule and aggregate evaluation counters since the current ruleset
    /// loaded (`getpolicyinfo`).
    pub fn policy_stats_snapshot(&self) -> PolicyStatsSnapshot {
        self.policy_stats.snapshot()
    }

    /// Number of transactions currently in the **quarantine class**. Always 0
    /// until a policy quarantines something. Cheap relative to the full
    /// [`Self::quarantine_report`]; used where only the count is needed.
    pub fn quarantine_count(&self) -> usize {
        self.inner
            .read()
            .entries
            .values()
            .filter(|e| !e.scope.is_acting())
            .count()
    }

    /// Count of quarantined transactions later seen confirmed in a block — the
    /// confirmed-anyway signal (process-lifetime).
    pub fn quarantine_confirmed_count(&self) -> u64 {
        self.quarantine_confirmed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Process-lifetime count of acting→quarantine and quarantine→acting moves
    /// made by the reload re-placement pass, and SIGHUP reloads that failed to
    /// compile (last-good kept). For the Prometheus policy counters (PR 7c).
    pub fn policy_transition_totals(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.policy_promoted_total.load(Relaxed),
            self.policy_demoted_total.load(Relaxed),
            self.policy_reload_failures.load(Relaxed),
        )
    }

    /// Live `getquarantineinfo` rollup (design §10): per-rule count/bytes/fee-rate
    /// span over the quarantine class, the confirmed-anyway count, and the
    /// foregone-fees estimate against `template_floor` (sat/kvB — the current
    /// template's minimum fee rate; pass the same floor the fee estimator uses).
    pub fn quarantine_report(&self, template_floor: u64) -> QuarantineReport {
        // Snapshot the config (leaf lock) BEFORE taking `inner`, never the
        // reverse — uniform leaf-lock discipline (see `info()`); holding `inner`
        // while acquiring `config` would invert the order every other path uses.
        let budget_bytes = self.config.read().quarantine_max_bytes as u64;
        let confirmed_anyway = self.quarantine_confirmed_count();
        let inner = self.inner.read();
        let mut report = QuarantineReport {
            budget_bytes,
            confirmed_anyway,
            ..Default::default()
        };
        for e in inner.entries.values() {
            if e.scope.is_acting() {
                continue;
            }
            let size = bitcoin::consensus::serialize(&e.tx).len() as u64;
            report.total_count += 1;
            report.total_bytes += size;
            let rule = e
                .quarantine_rule
                .clone()
                .unwrap_or_else(|| "(policy)".to_string());
            let stat = report.per_rule.entry(rule).or_default();
            if stat.count == 0 {
                stat.min_fee_rate = e.fee_rate;
                stat.max_fee_rate = e.fee_rate;
            } else {
                stat.min_fee_rate = stat.min_fee_rate.min(e.fee_rate);
                stat.max_fee_rate = stat.max_fee_rate.max(e.fee_rate);
            }
            stat.count += 1;
            stat.bytes += size;
            // Foregone fees: only entries withheld from the template are a cost
            // to a miner; a relay-only quarantine is still mined.
            if !e.scope.assists_template() && e.fee_rate > template_floor {
                report.foregone_fees_sat = report.foregone_fees_sat.saturating_add(e.fee);
            }
        }
        report
    }

    /// `listquarantine` (design §10): the quarantine class as a paged list,
    /// optionally filtered to one `rule`. Sorted by entry time (newest first) so
    /// paging is stable. `limit == 0` means "no limit".
    pub fn list_quarantine(
        &self,
        rule: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Vec<QuarantineListEntry> {
        let inner = self.inner.read();
        let mut out: Vec<QuarantineListEntry> = inner
            .entries
            .iter()
            .filter(|(_, e)| !e.scope.is_acting())
            .filter(|(_, e)| {
                rule.is_none_or(|want| {
                    e.quarantine_rule.as_deref() == Some(want)
                })
            })
            .map(|(txid, e)| QuarantineListEntry {
                // Use the map key — recomputing the txid per entry re-hashes the
                // whole transaction for no reason.
                txid: *txid,
                rule: e
                    .quarantine_rule
                    .clone()
                    .unwrap_or_else(|| "(policy)".to_string()),
                relay: e.scope.relay,
                template: e.scope.template,
                time: e.time,
                vsize: policy::weight_to_vsize(e.weight as u64),
                fee: e.fee,
                fee_rate: e.fee_rate,
            })
            .collect();
        // Newest first, then txid for a total order (stable paging).
        out.sort_by(|a, b| b.time.cmp(&a.time).then(a.txid.cmp(&b.txid)));
        let out: Vec<_> = out.into_iter().skip(offset).collect();
        if limit == 0 {
            out
        } else {
            out.into_iter().take(limit).collect()
        }
    }

    /// `getquarantineentry` (design §10): the `getmempoolentry` analogue for a
    /// single quarantined transaction. `None` if the txid is absent or acting
    /// (an acting entry is served by `getmempoolentry`).
    pub fn get_quarantine_entry(&self, txid: &Txid) -> Option<QuarantineEntryDetail> {
        let inner = self.inner.read();
        let e = inner.entries.get(txid)?;
        if e.scope.is_acting() {
            return None;
        }
        let mut seen: HashSet<Txid> = HashSet::new();
        let depends: Vec<Txid> = e
            .tx
            .input
            .iter()
            .map(|i| i.previous_output.txid)
            .filter(|p| inner.entries.contains_key(p) && seen.insert(*p))
            .collect();
        Some(QuarantineEntryDetail {
            txid: *txid,
            rule: e
                .quarantine_rule
                .clone()
                .unwrap_or_else(|| "(policy)".to_string()),
            relay: e.scope.relay,
            template: e.scope.template,
            time: e.time,
            vsize: policy::weight_to_vsize(e.weight as u64),
            weight: e.weight as u64,
            fee: e.fee,
            fee_rate: e.fee_rate,
            depends,
        })
    }

    /// In-mempool dependency order, parents before children (Kahn's algorithm
    /// over the spend edges that stay inside the pool). A transaction DAG has no
    /// cycles, so a single sweep totally orders it; any entry left after the
    /// sweep (impossible without a cycle) is appended so nothing is dropped.
    /// Used by [`Self::reapply_policy`] so a parent's recomputed scope is visible
    /// when its child is re-evaluated (§7 infectious propagation).
    fn topological_order(entries: &HashMap<Txid, MempoolEntry>) -> Vec<Txid> {
        // Direct in-mempool parents (deduped) and the reverse child edges.
        let mut parents: HashMap<Txid, HashSet<Txid>> = HashMap::with_capacity(entries.len());
        let mut children: HashMap<Txid, Vec<Txid>> = HashMap::new();
        for (txid, entry) in entries {
            let mut ps: HashSet<Txid> = HashSet::new();
            for input in &entry.tx.input {
                let p = input.previous_output.txid;
                if p != *txid && entries.contains_key(&p) {
                    ps.insert(p);
                }
            }
            for p in &ps {
                children.entry(*p).or_default().push(*txid);
            }
            parents.insert(*txid, ps);
        }

        let mut order: Vec<Txid> = Vec::with_capacity(entries.len());
        let mut indegree: HashMap<Txid, usize> =
            parents.iter().map(|(t, ps)| (*t, ps.len())).collect();
        let mut queue: Vec<Txid> = indegree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(t, _)| *t)
            .collect();
        while let Some(t) = queue.pop() {
            order.push(t);
            if let Some(cs) = children.get(&t) {
                for c in cs {
                    if let Some(d) = indegree.get_mut(c) {
                        *d -= 1;
                        if *d == 0 {
                            queue.push(*c);
                        }
                    }
                }
            }
        }
        // Belt-and-suspenders: append anything a (non-existent) cycle stranded.
        if order.len() != entries.len() {
            for t in entries.keys() {
                if !order.contains(t) {
                    order.push(*t);
                }
            }
        }
        order
    }

    /// Re-evaluate every resident transaction against the current ruleset and
    /// move it between the acting and quarantine classes accordingly — the
    /// synchronous re-placement pass run after a policy reload (§8). Lossless
    /// (I9): nothing is dropped except by the destination class's ordinary
    /// budget eviction; removing a rule promotes everything it was holding back
    /// without re-hearing anything from the network.
    ///
    /// The pool is walked parents-before-children ([`Self::topological_order`])
    /// so each transaction's infectious-ancestor scope (§3/§7) is derived from
    /// its parents' already-recomputed scopes in one sweep. Standardness is
    /// never re-litigated here — an already-admitted entry stays admitted; the
    /// reload only changes *placement*, never validity. Bounded by pool size and
    /// run off the hot path (the reload path), per §8.
    ///
    /// Returns the [`PolicyTransition`] so the caller (PR 6b) can re-announce
    /// promoted txs; emits `Promoted`/`Demoted` quarantine events for streaming
    /// subscribers.
    pub fn reapply_policy(&self, chain_state: &ChainState) -> PolicyTransition {
        let cfg = self.config.read().clone();
        let ruleset = self.policy.load_full();
        let policy_active = ruleset.as_ref().map(|r| !r.is_empty()).unwrap_or(false);
        let tip_height = chain_state.tip_height();
        let network = chain_state.network;

        let mut promoted: Vec<Txid> = Vec::new();
        // (txid, new scope, responsible rule) — for the Demoted event.
        let mut demoted: Vec<(Txid, QuarantineScope, String)> = Vec::new();
        let mut evicted: Vec<Txid> = Vec::new();

        {
            let mut inner = self.inner.write();
            let order = Self::topological_order(&inner.entries);

            for txid in order {
                let (tx, fee, fee_rate, weight, source, old_scope) =
                    match inner.entries.get(&txid) {
                        Some(e) => (e.tx.clone(), e.fee, e.fee_rate, e.weight, e.source, e.scope),
                        None => continue,
                    };

                // Re-resolve prevouts (confirmed coins or in-mempool parents),
                // exactly as admission does, and note the direct in-mempool
                // parents for infectious propagation. An admitted tx always
                // resolves: every input resolved at admission, a mined parent's
                // outputs become confirmed coins, and removing a parent
                // cascade-removes its children — so a *resident* entry never has
                // a dangling prevout. If one somehow does, it is an invariant
                // violation (the entry is effectively invalid), surfaced below.
                let mut prev_outputs: Vec<TxOut> = Vec::with_capacity(tx.input.len());
                let mut prev_is_coinbase: Vec<bool> = Vec::with_capacity(tx.input.len());
                let mut parents: Vec<Txid> = Vec::new();
                let mut resolved = true;
                for input in &tx.input {
                    if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                        prev_outputs.push(TxOut {
                            value: bitcoin::Amount::from_sat(coin.amount),
                            script_pubkey: coin.script_pubkey.clone(),
                        });
                        prev_is_coinbase.push(coin.coinbase);
                    } else if let Some(parent) = inner.entries.get(&input.previous_output.txid)
                        && let Some(o) = parent.tx.output.get(input.previous_output.vout as usize)
                    {
                        parents.push(input.previous_output.txid);
                        prev_outputs.push(o.clone());
                        prev_is_coinbase.push(false);
                    } else {
                        resolved = false;
                        break;
                    }
                }
                if !resolved {
                    // Cannot re-judge a transaction whose prevouts we can't
                    // resolve (the evaluator needs every prevout to build the
                    // view). Do NOT guess a placement, and do NOT drop the entry
                    // here — re-placement is lossless (I9); reaping a genuinely
                    // dangling entry is owned by the mempool's own maintenance
                    // (block-connect removal, expiry, conflict eviction). But it
                    // is an invariant violation, so warn loudly rather than skip
                    // silently — a recurring line points at a removal-ordering or
                    // chainstate-consistency bug, not a policy issue.
                    tracing::warn!(
                        %txid,
                        "reapply_policy: prevouts unresolvable; leaving placement \
                         unchanged (entry has a dangling parent / missing coin — \
                         it should be reaped by mempool maintenance)"
                    );
                    continue;
                }

                // Own scope from the verdict.
                let (own_scope, own_rule): (QuarantineScope, Option<String>) = if policy_active {
                    let rs = ruleset.as_ref().expect("policy_active ⇒ Some");
                    let ctx = PolicyCtx {
                        network,
                        height: tip_height,
                        mempool_bytes: inner.total_bytes,
                    };
                    match policy_engine::evaluate(
                        rs, &tx, &txid, &prev_outputs, &prev_is_coinbase, fee, fee_rate, weight,
                        &cfg, ctx, source, false,
                    ) {
                        satd_policy::Verdict::Allow { .. } | satd_policy::Verdict::Pass => {
                            (QuarantineScope::acting(), None)
                        }
                        satd_policy::Verdict::Quarantine { rule, scope } => {
                            (policy_engine::map_scope(scope), Some(rule))
                        }
                    }
                } else {
                    (QuarantineScope::acting(), None)
                };

                // Infectious propagation: union the direct parents' already-
                // recomputed scopes (transitive via the topological order).
                let mut new_scope = own_scope;
                for p in &parents {
                    if let Some(pe) = inner.entries.get(p) {
                        new_scope.relay |= pe.scope.relay;
                        new_scope.template |= pe.scope.template;
                    }
                }

                // The rule responsible for the placement: the tx's own match, or
                // the infectious-ancestor marker when the scope is inherited.
                // Cleared when the entry is acting. Stamped on the entry so
                // `listquarantine`/`getquarantineinfo` (PR 7b) can attribute it.
                let stamped_rule = if new_scope.is_quarantined() {
                    Some(own_rule.unwrap_or_else(|| INFECTIOUS_RULE.to_string()))
                } else {
                    None
                };

                if new_scope == old_scope {
                    // Placement unchanged — but a reload may have RENAMED the
                    // matching rule while keeping its scope; keep the attributed
                    // rule current for the observability surfaces. No accounting
                    // move, and not a promotion/demotion.
                    if let Some(e) = inner.entries.get_mut(&txid)
                        && e.quarantine_rule != stamped_rule
                    {
                        e.quarantine_rule = stamped_rule;
                    }
                    continue;
                }

                // Apply: per-class byte accounting, then stamp the new scope+rule.
                let size = bitcoin::consensus::serialize(&tx).len();
                inner.account_remove(old_scope, size);
                inner.account_insert(new_scope, size);
                if let Some(e) = inner.entries.get_mut(&txid) {
                    e.scope = new_scope;
                    e.quarantine_rule = stamped_rule.clone();
                }

                // Classify the move for the streaming surface. `Promoted` has a
                // strict contract: the scope FULLY cleared and the tx is acting
                // again (I9). A move that recovers *one* path (e.g. relay) while
                // the other stays withheld is NOT a promotion — the tx is still
                // quarantined. Report every still-held outcome via `Demoted`,
                // which carries the resulting held scope (relay/template) so
                // subscribers converge on the correct state instead of being told
                // a still-template-held tx is acting. (When `new_scope.is_acting()`
                // here, `old_scope` was necessarily quarantined: the two differ
                // and the acting scope is unique.)
                if new_scope.is_acting() {
                    promoted.push(txid);
                } else {
                    let rule = stamped_rule.unwrap_or_else(|| INFECTIOUS_RULE.to_string());
                    demoted.push((txid, new_scope, rule));
                }
            }

            // Per-class budget eviction after the moves (§8): only the class
            // that overflowed, only the overflow amount.
            if inner.acting_bytes() > cfg.max_size_bytes {
                let over = inner.acting_bytes() - cfg.max_size_bytes;
                evicted.extend(Self::evict_lowest_fee_entries(&mut inner, over, false));
            }
            if inner.quarantine_bytes > cfg.quarantine_max_bytes {
                let over = inner.quarantine_bytes - cfg.quarantine_max_bytes;
                evicted.extend(Self::evict_lowest_fee_entries(&mut inner, over, true));
            }
            self.sync_unbroadcast_len(&inner);
        }

        // A move recorded above can be undone by the post-replacement budget
        // eviction: a tx promoted into an already-full acting class (or demoted
        // into a full quarantine class) can itself be the lowest-fee victim and
        // leave the pool in the same pass. Such a tx is gone — it must surface
        // only `LeaveEvicted`, never a `Promoted`/`Demoted` event, and must not
        // be handed back in `promoted` for PR 6b to re-announce. Drop every
        // evicted txid from the transition lists before emitting/returning.
        if !evicted.is_empty() {
            let gone: std::collections::HashSet<Txid> = evicted.iter().copied().collect();
            promoted.retain(|t| !gone.contains(t));
            demoted.retain(|(t, _, _)| !gone.contains(t));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for txid in &promoted {
            self.emit_quarantine(QuarantineEvent::Promoted { txid: *txid, time: now });
        }
        for (txid, scope, rule) in &demoted {
            self.emit_quarantine(QuarantineEvent::Demoted {
                txid: *txid,
                rule: rule.clone(),
                relay: scope.relay,
                template: scope.template,
                time: now,
            });
        }
        for txid in &evicted {
            self.emit(MempoolEvent::LeaveEvicted { txid: *txid, reason: EvictReason::Policy });
        }

        // Accumulate the transition into the process-lifetime Prometheus counters.
        use std::sync::atomic::Ordering::Relaxed;
        self.policy_promoted_total
            .fetch_add(promoted.len() as u64, Relaxed);
        self.policy_demoted_total
            .fetch_add(demoted.len() as u64, Relaxed);

        PolicyTransition {
            promoted,
            demoted: demoted.into_iter().map(|(t, _, _)| t).collect(),
            evicted,
        }
    }

    /// The exemptable standardness set (§6.2 / Core's `-acceptnonstdtxn` family):
    /// oversize, dust, OP_RETURN/datacarrier limits, and non-standard output
    /// scripts. Returns the first failure as the error that *would* be returned
    /// at admission. Pulled out of `accept_transaction` so the deferred-
    /// standardness path (an `allow` rule may forgive these) and the eager path
    /// share one definition and can never drift. Consensus rules are **not** here
    /// — those are never exemptable (§6.2 floor).
    fn check_standardness(
        tx: &Transaction,
        cfg: &MempoolConfig,
        weight: usize,
    ) -> Result<(), MempoolError> {
        // Standard tx weight ceiling (oversize relay check).
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolError::Validation("tx-size".to_string()));
        }

        // Dust output check (configurable via -dustrelayfee, 0 = disable).
        if cfg.dust_relay_fee > 0 {
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    continue;
                }
                let threshold =
                    policy::dust_threshold_with_rate(&output.script_pubkey, cfg.dust_relay_fee);
                if output.value.to_sat() < threshold {
                    return Err(MempoolError::Dust);
                }
            }
        }

        // OP_RETURN limits (configurable via -datacarrier and -datacarriersize).
        if !cfg.data_carrier {
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    return Err(MempoolError::NonStandardOpReturn);
                }
            }
        } else {
            let mut op_return_count = 0;
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    op_return_count += 1;
                    if op_return_count > 1 {
                        return Err(MempoolError::NonStandardOpReturn);
                    }
                    if output.script_pubkey.len() > cfg.data_carrier_size {
                        return Err(MempoolError::NonStandardOpReturn);
                    }
                }
            }
        }

        // Non-standard output scripts.
        for output in &tx.output {
            if !policy::is_standard_output_script(&output.script_pubkey, cfg.permit_bare_multisig) {
                return Err(MempoolError::Validation("scriptpubkey".to_string()));
            }
        }

        Ok(())
    }

    /// Accept a transaction into the mempool after full validation.
    pub fn accept_transaction(
        &self,
        tx: Transaction,
        chain_state: &ChainState,
        script_verifier: &dyn ScriptVerifier,
        source: TxSource,
        allow_quarantined: bool,
    ) -> Result<Txid, MempoolError> {
        let txid = tx.compute_txid();

        // Snapshot the live policy once so the entire acceptance is judged
        // against a single config version. A concurrent SIGHUP reload can swap
        // `self.config` between calls but never mid-transaction.
        let cfg = self.config.read().clone();

        // Snapshot the policy ruleset pointer once (§7 step 1). `policy_active`
        // gates every engine-touching branch below; when there is no ruleset
        // (the common case, I8) the path is byte-identical to a build with the
        // engine compiled out — `has_allow` stays false (so standardness keeps
        // its early-return) and `scope` stays acting.
        let ruleset = self.policy.load_full();
        let policy_active = ruleset.as_ref().map(|r| !r.is_empty()).unwrap_or(false);
        // Only thread deferred-standardness when an `allow` rule could forgive a
        // failure; otherwise the common case pays nothing (§6.2/§7).
        let has_allow = policy_active && ruleset.as_ref().map(|r| r.has_allow()).unwrap_or(false);

        // Context-free checks
        check_transaction(&tx).map_err(|e| MempoolError::Validation(e.to_string()))?;

        // Must not be coinbase
        if tx.is_coinbase() {
            return Err(MempoolError::Validation(
                "coinbase not accepted in mempool".to_string(),
            ));
        }

        // Standardness relay checks (oversize, dust, OP_RETURN/datacarrier,
        // non-standard output scripts). Bitcoin Core's `-acceptnonstdtxn`
        // bypasses these so any consensus-valid tx is admitted; consensus
        // rules below (check_transaction above, script verification later)
        // are never relaxed. Default keeps standard relay (cfg default false).
        // Transaction weight is needed downstream (ancestor/descendant size,
        // entry accounting) regardless of standardness.
        let weight = tx.weight().to_wu() as usize;

        // §6.2/§7 deferred standardness: when the loaded ruleset contains at
        // least one `allow` rule, a failure in the exemptable standardness set is
        // *recorded* and resolved at the eval point below (an `Allow` match
        // forgives it; `Pass`/`Quarantine` let it stand) — an `allow` rule may
        // key on prevout-derived attributes not known until after input
        // resolution. With no `allow` rules (the common case, `has_allow ==
        // false`, which includes "no policy loaded"), failures reject early
        // exactly as today and nothing is threaded.
        let mut deferred_nonstd: Option<MempoolError> = None;
        if !cfg.accept_non_std_txn
            && let Err(e) = Self::check_standardness(&tx, &cfg, weight)
        {
            if has_allow {
                deferred_nonstd = Some(e);
            } else {
                return Err(e);
            }
        }

        let tx_size = bitcoin::consensus::serialize(&tx).len();

        // Take write lock for the rest (prevents TOCTOU races)
        let mut inner = self.inner.write();

        // Check not already in mempool
        if inner.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }

        // Detect conflicting spends (RBF candidates)
        let mut conflicts: HashSet<Txid> = HashSet::new();
        for input in &tx.input {
            if let Some(conflict_txid) = inner.spends.get(&input.previous_output) {
                conflicts.insert(*conflict_txid);
            }
        }

        // Look up UTXOs and validate inputs (with CPFP support)
        let tip_height = chain_state.tip_height();
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();
        // Per-input coinbase flag (input order), for the policy engine's
        // `in.spends_coinbase`. Only populated/consumed when a policy is active.
        let mut prev_is_coinbase: Vec<bool> = Vec::new();
        let mut ancestors: HashSet<Txid> = HashSet::new();

        for input in &tx.input {
            // First try chain state (confirmed UTXOs)
            if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                // Check coinbase maturity. A mempool tx is spent at the next
                // block (tip + 1) at the earliest, so the spend height — to
                // match Bitcoin Core's `CheckTxInputs` (nSpendHeight = tip + 1)
                // and satd's own connect-time check (which uses the connecting
                // block's height) — is `tip_height + 1`. Using `tip_height`
                // here made the mempool reject a coinbase at exactly
                // COINBASE_MATURITY confirmations that consensus would accept
                // in the next block (off-by-one, surfaced by the BDK canary).
                let spend_height = tip_height + 1;
                if coin.coinbase && spend_height - coin.height < COINBASE_MATURITY {
                    return Err(MempoolError::PrematureCoinbaseSpend);
                }
                sum_inputs += coin.amount;
                prev_outputs.push(TxOut {
                    value: bitcoin::Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });
                prev_is_coinbase.push(coin.coinbase);
                continue;
            }

            // CPFP: check if the input references an output from a mempool transaction
            let parent_txid = input.previous_output.txid;
            let parent_vout = input.previous_output.vout as usize;
            if let Some(parent) = inner.entries.get(&parent_txid)
                && let Some(output) = parent.tx.output.get(parent_vout)
            {
                ancestors.insert(parent_txid);
                sum_inputs += output.value.to_sat();
                prev_outputs.push(output.clone());
                // A mempool parent is never a coinbase (coinbase is rejected
                // above), so a spend of one never spends a coinbase output.
                prev_is_coinbase.push(false);
                continue;
            }

            return Err(MempoolError::MissingInputs);
        }

        // CPFP: build full ancestor set (transitive) and enforce limits
        if !ancestors.is_empty() {
            let mut queue: Vec<Txid> = ancestors.iter().copied().collect();
            while let Some(ancestor_txid) = queue.pop() {
                if let Some(ancestor) = inner.entries.get(&ancestor_txid) {
                    for anc_input in &ancestor.tx.input {
                        let grandparent = anc_input.previous_output.txid;
                        if inner.entries.contains_key(&grandparent)
                            && ancestors.insert(grandparent)
                        {
                            queue.push(grandparent);
                        }
                    }
                }
                if ancestors.len() > cfg.max_ancestor_count {
                    return Err(MempoolError::TooLongMempoolChain);
                }
            }
        }

        // RBF: if there are conflicts, check replacement rules
        if !conflicts.is_empty() {
            // Sum fees of all conflicted transactions
            let mut conflict_fee_total: u64 = 0;
            for conflict_txid in &conflicts {
                if let Some(conflict_entry) = inner.entries.get(conflict_txid) {
                    // RBF: in opt-in mode, conflicted tx must signal replaceability
                    // (any input with sequence < 0xfffffffe). Full RBF skips this check.
                    if !cfg.full_rbf {
                        let signals_rbf = conflict_entry
                            .tx
                            .input
                            .iter()
                            .any(|i| i.sequence.0 < 0xffff_fffe);
                        if !signals_rbf {
                            return Err(MempoolError::ConflictingSpend);
                        }
                    }
                    conflict_fee_total += conflict_entry.fee;
                }
            }

            // Compute new tx fee (we have sum_inputs and sum_outputs from below)
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            if sum_inputs < sum_outputs {
                return Err(MempoolError::BadAmounts);
            }
            let new_fee = sum_inputs - sum_outputs;

            // New fee must exceed old fees + incremental relay fee (per vbyte).
            let min_replacement_fee = conflict_fee_total
                + policy::INCREMENTAL_RELAY_FEE * policy::weight_to_vsize(weight as u64) / 1000;
            if new_fee < min_replacement_fee {
                return Err(MempoolError::InsufficientReplacementFee(
                    new_fee,
                    min_replacement_fee,
                ));
            }
        }

        // Check amounts
        let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if sum_inputs < sum_outputs {
            return Err(MempoolError::BadAmounts);
        }

        let fee = sum_inputs - sum_outputs;

        // Check fee rate (sat/kvB, i.e. per virtual byte — matches Core).
        let fee_rate = policy::fee_rate_sat_per_kvb(fee, weight as u64);
        if fee_rate < cfg.min_fee_rate {
            return Err(MempoolError::InsufficientFee(fee_rate, cfg.min_fee_rate));
        }

        // ── DSL evaluation (§7 step 6) ──────────────────────────────────────
        // The single policy eval point: after the DoS floor (fee / RBF / ancestor
        // limits), before per-class capacity and script verification. It computes
        // this transaction's quarantine `scope` and resolves any deferred
        // standardness failure. When no policy is active it is a no-op (acting
        // scope; no deferral is possible) — byte-identical to a build with the
        // engine compiled out (I8).
        // `quarantine_rule` names the rule responsible for any held scope — the
        // tx's own matching `quarantine` rule, or the infectious-ancestor marker
        // when the scope is purely inherited. Used for the §6.1 refusal error and
        // the `Quarantined` event below.
        let (scope, quarantine_rule): (QuarantineScope, Option<String>) = if policy_active {
            let rs = ruleset
                .as_ref()
                .expect("policy_active is set only when the ruleset is Some");
            let ctx = PolicyCtx {
                network: chain_state.network,
                height: tip_height,
                mempool_bytes: inner.total_bytes,
            };
            let verdict = policy_engine::evaluate(
                rs,
                &tx,
                &txid,
                &prev_outputs,
                &prev_is_coinbase,
                fee,
                fee_rate,
                weight,
                &cfg,
                ctx,
                source,
                // `tx.from_whitelisted_peer`: peer-whitelist threading into the
                // admission path is deferred (no peer handle here yet); baseline
                // `forcerelay` is unaffected. Conservatively false (§6.3).
                false,
            );

            // Per-rule / aggregate counters since load (getpolicyinfo, PR 7b).
            // Records every evaluation including `Pass`; a match bumps the rule's
            // count and the fuel-backstop counter when the fail-safe fired.
            self.policy_stats.record(&verdict);

            // Resolve the verdict against any deferred standardness failure
            // (§6.2/§7): `Allow` forgives it; `Pass`/`Quarantine` let the
            // baseline rejection stand — the quarantine class is not a dumping
            // ground for nonstandard traffic.
            let (own_scope, own_rule) = match &verdict {
                satd_policy::Verdict::Allow { .. } => (QuarantineScope::acting(), None),
                satd_policy::Verdict::Pass => {
                    if let Some(e) = deferred_nonstd {
                        return Err(e);
                    }
                    (QuarantineScope::acting(), None)
                }
                satd_policy::Verdict::Quarantine { rule, scope } => {
                    if let Some(e) = deferred_nonstd {
                        return Err(e);
                    }
                    if rule.as_str() == satd_policy::verdict::FUEL_RULE {
                        tracing::warn!(
                            %txid,
                            "policy fuel exhausted — fail-safe full-scope quarantine \
                             (a sound static cost model makes this unreachable; firing is a bug signal)"
                        );
                    } else {
                        tracing::debug!(%txid, rule = %rule, scope = %scope, "policy quarantine");
                    }
                    (policy_engine::map_scope(*scope), Some(rule.clone()))
                }
            };

            // Infectious-descendant propagation (§3/§7): a transaction inherits
            // the union of its quarantined in-mempool ancestors' scopes,
            // regardless of its own verdict — announcing or mining a child whose
            // parent we withhold would be incoherent. The ancestor set is already
            // computed above, so this is a flag union, not a traversal.
            let mut final_scope = own_scope;
            for anc in &ancestors {
                if let Some(e) = inner.entries.get(anc)
                    && e.scope.is_quarantined()
                {
                    final_scope.relay |= e.scope.relay;
                    final_scope.template |= e.scope.template;
                }
            }
            // Name the responsible rule: the tx's own match, or — when the held
            // scope is only inherited — the infectious-ancestor marker.
            let rule = if final_scope.is_quarantined() {
                own_rule.or_else(|| Some(INFECTIOUS_RULE.to_string()))
            } else {
                None
            };
            (final_scope, rule)
        } else {
            // No active policy ⇒ `has_allow` is false ⇒ `deferred_nonstd` is None
            // (standardness already rejected early). Acting scope, unconditionally.
            (QuarantineScope::acting(), None)
        };

        // §6.1 local-submission refusal: a transaction submitted through a local
        // surface that draws a *relay*-scoped quarantine verdict is refused (with
        // the rule named) rather than silently held — a relay-quarantined local
        // tx is dead on arrival (never announced, never mined), so returning a
        // success txid that then never appears in standard mempool queries is a
        // trap for Core-compatible wallets. Three boundaries (§6.1):
        //   • template-only quarantine does NOT refuse (it relays/serves fine);
        //   • `allowquarantined` overrides, submitting into quarantine anyway;
        //   • P2P-sourced traffic is never refused — it quarantines as designed.
        // Refusing here (before placement) keeps a refused tx out of every view.
        if source.is_local() && scope.relay && !allow_quarantined {
            return Err(MempoolError::Quarantined(
                quarantine_rule
                    .clone()
                    .unwrap_or_else(|| "(policy)".to_string()),
            ));
        }

        // Per-class capacity check — the new tx is charged to its own class's
        // budget (acting → `max_size_bytes`, quarantine → `quarantine_max_bytes`)
        // and fee-rate eviction only considers entries in that same class, so
        // neither class can crowd the other out. Until a policy is loaded every
        // tx is acting, `acting_bytes() == total_bytes`, and this reduces to the
        // historical single-pool check (the quarantine branch stays dead-data).
        let quarantined = scope.is_quarantined();
        let class_bytes = if quarantined {
            inner.quarantine_bytes
        } else {
            inner.acting_bytes()
        };
        let class_budget = if quarantined {
            cfg.quarantine_max_bytes
        } else {
            cfg.max_size_bytes
        };
        let evict_reason = if quarantined {
            EvictReason::Policy
        } else {
            EvictReason::FullPool
        };
        let mut evicted_full_pool: Vec<Txid> = Vec::new();
        if class_bytes + tx_size > class_budget {
            // Only evict if the new tx outbids the cheapest entry *in its own class*.
            let min_class_fee_rate = inner
                .entries
                .values()
                .filter(|e| e.scope.is_quarantined() == quarantined)
                .map(|e| e.fee_rate)
                .min()
                .unwrap_or(0);
            if fee_rate <= min_class_fee_rate {
                return Err(MempoolError::MempoolFull);
            }
            // Evict enough lowest-fee-rate entries *of this class* to make room.
            evicted_full_pool = Self::evict_lowest_fee_entries(&mut inner, tx_size, quarantined);
            self.sync_unbroadcast_len(&inner);
            // If still not enough room after eviction, reject.
            let class_bytes_after = if quarantined {
                inner.quarantine_bytes
            } else {
                inner.acting_bytes()
            };
            if class_bytes_after + tx_size > class_budget {
                return Err(MempoolError::MempoolFull);
            }
        }

        // Script verification (all inputs at once for taproot)
        // Use tip_height + 1 since the tx will be mined in the next block
        script_verifier
            .verify_transaction(&tx, &prev_outputs, tip_height + 1)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        // RBF: remove conflicted transactions before inserting replacement.
        // Collect replaced txids so we can emit LeaveReplaced events
        // after the write lock is dropped (broadcast is best-effort but
        // still prefer not to hold a lock while sending).
        let mut replaced: Vec<Txid> = Vec::new();
        for conflict_txid in &conflicts {
            if let Some(conflict_entry) = inner.entries.remove(conflict_txid) {
                let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                inner.account_remove(conflict_entry.scope, sz);
                for ci in &conflict_entry.tx.input {
                    inner.spends.remove(&ci.previous_output);
                }
                inner.unbroadcast.remove(conflict_txid);
                replaced.push(*conflict_txid);
                tracing::info!(%conflict_txid, "RBF: evicted conflicting transaction");
            }
        }
        self.sync_unbroadcast_len(&inner);

        // Insert
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for input in &tx.input {
            inner.spends.insert(input.previous_output, txid);
        }

        let prev_outputs_map: HashMap<OutPoint, TxOut> = tx
            .input
            .iter()
            .zip(prev_outputs.iter())
            .map(|(i, o)| (i.previous_output, o.clone()))
            .collect();
        let sigop_cost = tx.total_sigop_cost(|op| prev_outputs_map.get(op).cloned()) as u64;

        // Retain the spent prevout scripthashes (input order) for mempool
        // spend-side matching (exact script + prefix bucket). `prev_outputs` is
        // fully resolved above and dropped after this; hashing it now is the one
        // chance to keep the data without re-resolving prevouts in the
        // (decoupled) matcher.
        let prev_scripthashes: Vec<Scripthash> = prev_outputs
            .iter()
            .map(|o| scripthash_of(&o.script_pubkey))
            .collect();

        let entry_weight_u64 = weight as u64;
        let vsize_u64 = policy::weight_to_vsize(entry_weight_u64);
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                weight,
                fee_rate,
                time: now,
                fee_delta: 0,
                sigop_cost,
                prev_scripthashes,
                source,
                scope,
                quarantine_rule: quarantine_rule.clone(),
            },
        );
        inner.account_insert(scope, tx_size);

        if !conflicts.is_empty() {
            tracing::info!(%txid, fee, fee_rate, replaced = conflicts.len(), "RBF replacement accepted to mempool");
        } else {
            tracing::info!(%txid, fee, fee_rate, ancestors = ancestors.len(), "Transaction accepted to mempool");
        }

        // Drop the write lock before emitting events — broadcast sends
        // are best-effort but keeping the lock duration tight is the rule.
        drop(inner);

        for evicted_txid in &evicted_full_pool {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *evicted_txid,
                reason: evict_reason,
            });
        }
        for conflict_txid in &replaced {
            self.emit(MempoolEvent::LeaveReplaced {
                txid: *conflict_txid,
                replacing_txid: txid,
            });
        }
        // §10: the default mempool stream reflects the *acting* class only — a
        // quarantined admission emits no `Enter` there. Held placements emit
        // `Quarantined` on the separate channel instead; acting placements emit
        // `Enter` exactly as before.
        if scope.is_quarantined() {
            self.emit_quarantine(QuarantineEvent::Quarantined {
                txid,
                rule: quarantine_rule.unwrap_or_else(|| "(policy)".to_string()),
                relay: scope.relay,
                template: scope.template,
                time: now,
            });
        } else {
            self.emit(MempoolEvent::Enter {
                txid,
                fee,
                vsize: vsize_u64,
                fee_rate_sat_per_kvb: fee_rate,
                time: now,
            });
        }

        Ok(txid)
    }

    /// Remove all transactions confirmed in the given block. Emits
    /// `LeaveConfirmed` events for txids that were in the mempool.
    /// `height` is the connected block's height and is threaded into
    /// the event so subscribers can filter / correlate.
    pub fn remove_for_block(&self, block: &Block, height: u32) {
        let block_hash = block.block_hash();
        let mut confirmed: Vec<Txid> = Vec::new();
        let mut evicted_conflicts: Vec<Txid> = Vec::new();
        {
            let mut inner = self.inner.write();
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                if let Some(entry) = inner.entries.remove(&txid) {
                    let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                    inner.account_remove(entry.scope, tx_size);
                    for input in &entry.tx.input {
                        inner.spends.remove(&input.previous_output);
                    }
                    inner.unbroadcast.remove(&txid);
                    // Confirmed-anyway (D4): a transaction we declined to assist
                    // got mined regardless. Process-lifetime evidence for
                    // getquarantineinfo — filtering cannot prevent confirmation.
                    if entry.scope.is_quarantined() {
                        self.quarantine_confirmed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    confirmed.push(txid);
                }

                // Also remove any mempool txs whose inputs are now
                // double-spent by the block. The chain — not policy —
                // retired these, surfaced as
                // `LeaveEvicted { BlockConflict }` so operators don't
                // read them as mempool pressure.
                if !tx.is_coinbase() {
                    for input in &tx.input {
                        if let Some(conflict_txid) =
                            inner.spends.remove(&input.previous_output)
                            && let Some(conflict_entry) = inner.entries.remove(&conflict_txid)
                        {
                            let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                            inner.account_remove(conflict_entry.scope, sz);
                            for ci in &conflict_entry.tx.input {
                                inner.spends.remove(&ci.previous_output);
                            }
                            inner.unbroadcast.remove(&conflict_txid);
                            evicted_conflicts.push(conflict_txid);
                        }
                    }
                }
            }
            self.sync_unbroadcast_len(&inner);
        }

        for txid in &confirmed {
            self.emit(MempoolEvent::LeaveConfirmed {
                txid: *txid,
                block_hash,
                height,
            });
        }
        for txid in &evicted_conflicts {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *txid,
                reason: EvictReason::BlockConflict,
            });
        }
    }

    /// Get a transaction by txid.
    pub fn get(&self, txid: &Txid) -> Option<MempoolEntry> {
        self.inner.read().entries.get(txid).cloned()
    }

    /// Adjust the fee delta for a transaction in the mempool (for mining priority).
    pub fn prioritise_transaction(&self, txid: &Txid, fee_delta: i64) -> bool {
        let mut inner = self.inner.write();
        if let Some(entry) = inner.entries.get_mut(txid) {
            // Saturating: fee_delta comes from `prioritisetransaction` RPC
            // and from re-admitted persisted mempool entries (untrusted
            // mempool.dat), so a malicious/corrupt value must not overflow.
            entry.fee_delta = entry.fee_delta.saturating_add(fee_delta);
            true
        } else {
            false
        }
    }

    /// Get all txids in the mempool — the **union** of the acting and
    /// quarantine classes.
    ///
    /// This is the unfiltered view. Only consumers that must see every held
    /// transaction may use it: compact-block reconstruction
    /// ([`crate::net::compact::try_reconstruct`], which reconstructs blocks
    /// from *any* tx we hold), mempool persistence, and the quarantine-aware
    /// observability surfaces. The **assist** paths (relay, BIP35, `getdata`,
    /// rebroadcast, templates, the smart-fee simulator) must NOT use this —
    /// they take a scope-filtered view ([`Self::get_template_entries`] for the
    /// template/fee paths; per-entry [`QuarantineScope::assists_relay`] checks
    /// for the relay paths). Mixing these up is a silent correctness bug
    /// (design §2.4), so the divergence is documented at the source.
    pub fn get_all_entries(&self) -> Vec<(Txid, MempoolEntry)> {
        self.inner
            .read()
            .entries
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Entries in the **acting class** only — every transaction the node is
    /// fully assisting (`scope.is_acting()`): both relayed and mineable.
    ///
    /// This is the view every **standard wallet-serving read surface** presents
    /// (design §6.1/§10): `getrawmempool`, `getmempoolinfo`, `getmempoolentry`,
    /// the address index, the mempool history snapshot, Electrum/Esplora, the
    /// standard MCP mempool tools. To each of these the node behaves exactly
    /// like a Core node whose relay policy refused the transaction — the
    /// quarantine class is invisible, not even surfaced as extension fields.
    /// Consumers that *want* the quarantine view ask for it by name through the
    /// dedicated extension surfaces (`getquarantineinfo`/`listquarantine`/
    /// `getquarantineentry`, PR 7b). Until a policy is loaded every scope is
    /// empty, so this equals the union and behavior is byte-identical.
    pub fn get_acting_entries(&self) -> Vec<(Txid, MempoolEntry)> {
        self.inner
            .read()
            .entries
            .iter()
            .filter(|(_, v)| v.scope.is_acting())
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Entries eligible for the **template** assist path — block-template
    /// assembly ([`crate::mining::template::create_template`]) and the mempool
    /// smart-fee simulator ([`crate::mempool::fee::FeeEstimator::cached_mempool_estimate`]).
    ///
    /// Filters [`Self::get_all_entries`] down to entries whose scope
    /// [`assists_template`](QuarantineScope::assists_template) — i.e. excludes
    /// transactions quarantined `on template` (those we hold but will never
    /// mine). The fee simulator shares this exact view so it never quotes fees
    /// for transactions the node would not include in a block (design §2.4).
    /// Until a policy is loaded every scope is empty, so this equals the union.
    pub fn get_template_entries(&self) -> Vec<(Txid, MempoolEntry)> {
        self.inner
            .read()
            .entries
            .iter()
            .filter(|(_, v)| v.scope.assists_template())
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Txids of mempool entries whose fee rate is at least `min_fee_rate`
    /// (sat/kvB). Used to answer a BIP35 `mempool` request without cloning
    /// every entry's transaction.
    ///
    /// BIP35 is a **relay** assist path (we are announcing our mempool to a
    /// peer), so quarantine-relay entries are excluded — the node never
    /// advertises a transaction it has declined to gossip (design §2.4/§6.1).
    pub fn txids_above_feerate(&self, min_fee_rate: u64) -> Vec<Txid> {
        self.inner
            .read()
            .entries
            .iter()
            .filter(|(_, e)| e.scope.assists_relay() && e.fee_rate >= min_fee_rate)
            .map(|(txid, _)| *txid)
            .collect()
    }

    /// Cheap O(1) lookup: which mempool tx (and which input vin) consumes
    /// `outpoint`? Returns `None` if the outpoint is not consumed by any
    /// mempool tx. Used by Esplora's `/tx/:txid/outspend/:vout` so the
    /// single-output path doesn't have to clone the whole mempool to
    /// answer one question (review M4).
    ///
    /// The outer lookup hits the existing `spends` index in O(1); the
    /// inner walk over the spending tx's inputs is bounded by that
    /// tx's own input count, not by mempool size.
    pub fn spending_tx(&self, outpoint: &OutPoint) -> Option<(Txid, u32)> {
        let inner = self.inner.read();
        let spending_txid = *inner.spends.get(outpoint)?;
        let entry = inner.entries.get(&spending_txid)?;
        let vin = entry
            .tx
            .input
            .iter()
            .position(|i| i.previous_output == *outpoint)?
            as u32;
        Some((spending_txid, vin))
    }

    /// Remove transactions that have been in the mempool longer than the expiry time.
    /// Returns the number of transactions removed.
    pub fn remove_expired(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Snapshot the policy field BEFORE locking `inner`, so the policy lock
        // is never held while `inner` is. This keeps the policy lock a leaf
        // (acquire → read → release) and the lock order uniform across the pool,
        // so a concurrent `reload_policy` (config.write) can never form a lock
        // cycle with the mempool lock.
        let expiry_secs = self.config.read().expiry_secs;
        let mut expired_txids: Vec<Txid> = Vec::new();
        {
            let mut inner = self.inner.write();
            let expired: Vec<Txid> = inner
                .entries
                .iter()
                .filter(|(_, entry)| now.saturating_sub(entry.time) > expiry_secs)
                .map(|(txid, _)| *txid)
                .collect();

            for txid in &expired {
                if let Some(entry) = inner.entries.remove(txid) {
                    let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                    inner.account_remove(entry.scope, tx_size);
                    for input in &entry.tx.input {
                        inner.spends.remove(&input.previous_output);
                    }
                    inner.unbroadcast.remove(txid);
                    expired_txids.push(*txid);
                }
            }
            self.sync_unbroadcast_len(&inner);
        }

        let count = expired_txids.len();
        for txid in &expired_txids {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *txid,
                reason: EvictReason::Expiry,
            });
        }

        if count > 0 {
            tracing::info!(count, "Expired transactions removed from mempool");
        }

        count
    }

    /// Get the set of in-mempool ancestors for a transaction.
    pub fn get_ancestors(&self, txid: &Txid) -> Option<HashSet<Txid>> {
        let inner = self.inner.read();
        let entry = inner.entries.get(txid)?;
        let mut ancestors = HashSet::new();
        let mut queue: Vec<Txid> = Vec::new();

        // Find direct parents
        for input in &entry.tx.input {
            let parent = input.previous_output.txid;
            if inner.entries.contains_key(&parent) && ancestors.insert(parent) {
                queue.push(parent);
            }
        }

        // Walk transitively
        while let Some(anc_txid) = queue.pop() {
            if let Some(anc) = inner.entries.get(&anc_txid) {
                for input in &anc.tx.input {
                    let grandparent = input.previous_output.txid;
                    if inner.entries.contains_key(&grandparent) && ancestors.insert(grandparent) {
                        queue.push(grandparent);
                    }
                }
            }
        }

        Some(ancestors)
    }

    /// Get the set of in-mempool descendants for a transaction.
    pub fn get_descendants(&self, txid: &Txid) -> Option<HashSet<Txid>> {
        let inner = self.inner.read();
        if !inner.entries.contains_key(txid) {
            return None;
        }

        let mut descendants = HashSet::new();
        let mut queue = vec![*txid];

        while let Some(current) = queue.pop() {
            if let Some(current_entry) = inner.entries.get(&current) {
                let current_txid = current_entry.tx.compute_txid();
                // Find children: entries whose inputs reference outputs of current
                for (child_txid, child_entry) in &inner.entries {
                    if *child_txid != *txid
                        && !descendants.contains(child_txid)
                        && child_entry
                            .tx
                            .input
                            .iter()
                            .any(|i| i.previous_output.txid == current_txid)
                    {
                        descendants.insert(*child_txid);
                        queue.push(*child_txid);
                    }
                }
            }
        }

        Some(descendants)
    }

    /// Get the direct in-mempool children of `txid` — transactions
    /// that spend any output of `txid`. Uses the `spends` reverse
    /// index for O(outputs) lookup. Does *not* recurse.
    pub fn get_children(&self, txid: &Txid) -> Option<Vec<Txid>> {
        let inner = self.inner.read();
        let entry = inner.entries.get(txid)?;
        let n_outs = entry.tx.output.len() as u32;
        let mut children: Vec<Txid> = Vec::new();
        let mut seen: HashSet<Txid> = HashSet::new();
        for vout in 0..n_outs {
            let op = OutPoint { txid: *txid, vout };
            if let Some(child) = inner.spends.get(&op)
                && seen.insert(*child)
            {
                children.push(*child);
            }
        }
        Some(children)
    }

    /// Get verbose entry data for a single mempool transaction (for RPC).
    pub fn get_entry_verbose(&self, txid: &Txid) -> Option<serde_json::Value> {
        let inner = self.inner.read();
        let entry = inner.entries.get(txid)?;
        // Standard surface (design §6.1): a quarantined entry is invisible here —
        // `getmempoolentry` reports it as not-found, exactly as a Core node whose
        // relay policy refused it. The quarantine view is `getquarantineentry`.
        if !entry.scope.is_acting() {
            return None;
        }
        let vsize = entry.weight / 4;
        let entry_fee = entry.fee;
        let entry_weight = entry.weight;
        let entry_time = entry.time;
        let entry_tx_inputs: Vec<_> = entry.tx.input.clone();
        let is_unbroadcast = inner.unbroadcast.contains_key(txid);
        drop(inner);

        let ancestors = self.get_ancestors(txid).unwrap_or_default();
        let descendants = self.get_descendants(txid).unwrap_or_default();
        let children = self.get_children(txid).unwrap_or_default();

        let inner = self.inner.read();

        // Invisibility (design §6.1): the ancestor/descendant graph reported on
        // this standard surface must exclude the quarantine class. Infectious
        // propagation (§3) guarantees an acting entry has no quarantined
        // ancestor, but it can have a quarantined descendant/child (quarantined
        // by its own rule); filter all three so counts and rollups never leak.
        let ancestors: HashSet<Txid> = ancestors
            .into_iter()
            .filter(|a| inner.entries.get(a).is_some_and(|e| e.scope.is_acting()))
            .collect();
        let descendants: HashSet<Txid> = descendants
            .into_iter()
            .filter(|d| inner.entries.get(d).is_some_and(|e| e.scope.is_acting()))
            .collect();
        let children: Vec<Txid> = children
            .into_iter()
            .filter(|c| inner.entries.get(c).is_some_and(|e| e.scope.is_acting()))
            .collect();

        let ancestor_count = ancestors.len();
        let ancestor_size: usize = ancestors
            .iter()
            .filter_map(|a| inner.entries.get(a))
            .map(|e| e.weight / 4)
            .sum::<usize>()
            + vsize;
        let ancestor_fees: u64 = ancestors
            .iter()
            .filter_map(|a| inner.entries.get(a))
            .map(|e| e.fee)
            .sum::<u64>()
            + entry_fee;

        let descendant_count = descendants.len() + 1; // includes self
        let descendant_size: usize = descendants
            .iter()
            .filter_map(|d| inner.entries.get(d))
            .map(|e| e.weight / 4)
            .sum::<usize>()
            + vsize;
        let descendant_fees: u64 = descendants
            .iter()
            .filter_map(|d| inner.entries.get(d))
            .map(|e| e.fee)
            .sum::<u64>()
            + entry_fee;

        let bip125_replaceable = entry_tx_inputs
            .iter()
            .any(|i| i.sequence.0 < 0xffff_fffe);

        Some(serde_json::json!({
            "fees": {
                "base": entry_fee as f64 / 100_000_000.0,
                "modified": entry_fee as f64 / 100_000_000.0,
                "ancestor": ancestor_fees as f64 / 100_000_000.0,
                "descendant": descendant_fees as f64 / 100_000_000.0,
            },
            "vsize": vsize,
            "weight": entry_weight,
            "fee": entry_fee as f64 / 100_000_000.0,
            "time": entry_time,
            "height": 0, // would need chain height at time of entry
            "descendantcount": descendant_count,
            "descendantsize": descendant_size,
            "descendantfees": descendant_fees,
            "ancestorcount": ancestor_count + 1,
            "ancestorsize": ancestor_size,
            "ancestorfees": ancestor_fees,
            "depends": ancestors.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "spentby": children.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            "bip125-replaceable": bip125_replaceable,
            "unbroadcast": is_unbroadcast,
        }))
    }

    /// Dry-run transaction validation without inserting into the mempool.
    /// Returns (txid, vsize, fee) on success.
    pub fn test_accept(
        &self,
        tx: &Transaction,
        chain_state: &ChainState,
        script_verifier: &dyn ScriptVerifier,
    ) -> Result<(Txid, usize, u64), MempoolError> {
        let txid = tx.compute_txid();

        crate::validation::tx::check_transaction(tx)
            .map_err(|e| MempoolError::Validation(e.to_string()))?;

        if tx.is_coinbase() {
            return Err(MempoolError::Validation("coinbase not accepted".to_string()));
        }

        let weight = tx.weight().to_wu() as usize;
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolError::Validation("tx-size".to_string()));
        }

        let inner = self.inner.read();
        if inner.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }
        drop(inner);

        // Look up inputs
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();

        for input in &tx.input {
            if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                sum_inputs += coin.amount;
                prev_outputs.push(TxOut {
                    value: bitcoin::Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });
            } else {
                // Check mempool parents
                let inner = self.inner.read();
                if let Some(parent) = inner.entries.get(&input.previous_output.txid)
                    && let Some(output) = parent.tx.output.get(input.previous_output.vout as usize) {
                        sum_inputs += output.value.to_sat();
                        prev_outputs.push(output.clone());
                        continue;
                    }
                return Err(MempoolError::MissingInputs);
            }
        }

        let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if sum_inputs < sum_outputs {
            return Err(MempoolError::BadAmounts);
        }
        let fee = sum_inputs - sum_outputs;

        // Script verification (tip + 1 = next block height)
        let tip_height = chain_state.tip_height();
        script_verifier
            .verify_transaction(tx, &prev_outputs, tip_height + 1)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        let vsize = policy::weight_to_vsize(weight as u64) as usize;
        Ok((txid, vsize, fee))
    }

    /// Evict lowest-fee-rate entries **of one class** (acting if
    /// `want_quarantined` is false, the quarantine class if true) to free at
    /// least `bytes_needed` bytes. Descendants of an evicted entry are removed
    /// regardless of class (graph integrity) — but under the infectious-
    /// descendant rule (PR 4c) a held entry's descendants are themselves held,
    /// so within a class the freed bytes track that class. Returns the evicted
    /// txids so the caller can emit `LeaveEvicted` with the appropriate reason
    /// after dropping the write lock. Until a policy is loaded `want_quarantined`
    /// is always false and this is the historical pool-wide eviction.
    fn evict_lowest_fee_entries(
        inner: &mut MempoolInner,
        bytes_needed: usize,
        want_quarantined: bool,
    ) -> Vec<Txid> {
        // Sort *this class's* entries by fee_rate ascending; the other class is
        // never an eviction candidate (its own budget governs it).
        let mut by_fee_rate: Vec<(Txid, u64)> = inner
            .entries
            .iter()
            .filter(|(_, entry)| entry.scope.is_quarantined() == want_quarantined)
            .map(|(txid, entry)| (*txid, entry.fee_rate))
            .collect();
        by_fee_rate.sort_by_key(|(_, rate)| *rate);

        let mut freed = 0usize;
        let mut to_remove: Vec<Txid> = Vec::new();

        for (txid, _) in &by_fee_rate {
            if freed >= bytes_needed {
                break;
            }
            if to_remove.contains(txid) {
                continue;
            }
            to_remove.push(*txid);
            if let Some(entry) = inner.entries.get(txid) {
                freed += bitcoin::consensus::serialize(&entry.tx).len();
            }
            // Also collect descendants of the evicted entry
            let mut desc_queue = vec![*txid];
            while let Some(current) = desc_queue.pop() {
                let current_txid_for_search = current;
                let children: Vec<Txid> = inner
                    .entries
                    .iter()
                    .filter(|(child_txid, child_entry)| {
                        !to_remove.contains(child_txid)
                            && child_entry
                                .tx
                                .input
                                .iter()
                                .any(|i| i.previous_output.txid == current_txid_for_search)
                    })
                    .map(|(child_txid, _)| *child_txid)
                    .collect();
                for child in children {
                    if let Some(child_entry) = inner.entries.get(&child) {
                        // A cross-class descendant (e.g. a quarantined child of an
                        // evicted acting parent) must still be removed for graph
                        // integrity — its input vanishes with the parent — but its
                        // bytes belong to the *other* class's budget. Counting them
                        // toward this class's `bytes_needed` would stop eviction
                        // early and leave the acting class over budget, so only
                        // same-class bytes count toward the goal.
                        if child_entry.scope.is_quarantined() == want_quarantined {
                            freed += bitcoin::consensus::serialize(&child_entry.tx).len();
                        }
                    }
                    to_remove.push(child);
                    desc_queue.push(child);
                }
            }
        }

        for txid in &to_remove {
            if let Some(entry) = inner.entries.remove(txid) {
                let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                inner.account_remove(entry.scope, tx_size);
                for input in &entry.tx.input {
                    inner.spends.remove(&input.previous_output);
                }
                inner.unbroadcast.remove(txid);
                tracing::debug!(%txid, fee_rate = entry.fee_rate, "Evicted low-fee tx from mempool");
            }
        }

        if !to_remove.is_empty() {
            tracing::info!(evicted = to_remove.len(), "Mempool eviction complete");
        }
        to_remove
    }

    /// Keep the lock-free `unbroadcast_len` mirror coherent with the map.
    /// Must be called (with the `inner` write lock still held) after any
    /// mutation of `inner.unbroadcast`.
    fn sync_unbroadcast_len(&self, inner: &MempoolInner) {
        self.unbroadcast_len
            .store(inner.unbroadcast.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether any local tx is pending propagation confirmation. Lock-free
    /// fast path for the hot P2P handlers (`inv`/`getdata`): on a node
    /// that isn't actively broadcasting this is `false` and the caller can
    /// skip [`record_broadcast_witness`](Self::record_broadcast_witness)'s
    /// write-lock acquisition entirely.
    pub fn has_unbroadcast(&self) -> bool {
        self.unbroadcast_len.load(std::sync::atomic::Ordering::Relaxed) > 0
    }

    /// Mark a locally-originated tx as unbroadcast (pending propagation
    /// confirmation). No-op if the tx isn't currently in the mempool.
    pub fn mark_unbroadcast(&self, txid: Txid) {
        let mut inner = self.inner.write();
        if inner.entries.contains_key(&txid) {
            inner.unbroadcast.entry(txid).or_default();
            self.sync_unbroadcast_len(&inner);
        }
    }

    /// Record that the peer at `witness` (its IP) demonstrated knowledge of
    /// `txid` — evidence the tx propagated into the network. Returns `true`
    /// once at least `confirm_threshold` distinct IPs have witnessed it, at
    /// which point the tx is dropped from the unbroadcast set (we stop
    /// rebroadcasting it). Witnesses are keyed by IP so a reconnecting host
    /// (fresh peer id each time) cannot stack the count. `confirm_threshold`
    /// is clamped to a minimum of 1. Returns `false` for a txid that isn't
    /// pending broadcast.
    pub fn record_broadcast_witness(
        &self,
        txid: &Txid,
        witness: std::net::IpAddr,
        confirm_threshold: usize,
    ) -> bool {
        let threshold = confirm_threshold.max(1);
        let mut inner = self.inner.write();
        if let Some(witnesses) = inner.unbroadcast.get_mut(txid) {
            witnesses.insert(witness);
            if witnesses.len() >= threshold {
                inner.unbroadcast.remove(txid);
                self.sync_unbroadcast_len(&inner);
                return true;
            }
        }
        false
    }

    /// Live unbroadcast txids (those still resident in the mempool), for
    /// persistence. Every mempool removal path prunes `unbroadcast` inline;
    /// the retain here is a cheap second line of defense.
    pub fn unbroadcast_txids(&self) -> Vec<Txid> {
        let mut inner = self.inner.write();
        let MempoolInner { entries, unbroadcast, .. } = &mut *inner;
        unbroadcast.retain(|txid, _| entries.contains_key(txid));
        let txids = unbroadcast.keys().copied().collect();
        self.sync_unbroadcast_len(&inner);
        txids
    }

    /// Live unbroadcast `(txid, fee_rate)` pairs, for the announce paths —
    /// the fee rate is captured here so callers never have to re-enter the
    /// mempool lock (or clone whole entries) while holding the peers lock.
    ///
    /// Rebroadcast and announce-to-new-peer are **relay** assist paths, so
    /// quarantine-relay entries are excluded: a local tx that became
    /// relay-quarantined (via `allowquarantined` opt-in or a later ruleset
    /// demotion — design §6.1/§8) stays in the unbroadcast set for promotion
    /// on reload but is never put on the wire while withheld. The `retain`
    /// still prunes departed txids regardless of scope.
    pub fn unbroadcast_entries(&self) -> Vec<(Txid, u64)> {
        let mut inner = self.inner.write();
        let MempoolInner { entries, unbroadcast, .. } = &mut *inner;
        unbroadcast.retain(|txid, _| entries.contains_key(txid));
        let pairs = unbroadcast
            .keys()
            .filter_map(|txid| {
                let e = entries.get(txid)?;
                e.scope.assists_relay().then_some((*txid, e.fee_rate))
            })
            .collect();
        self.sync_unbroadcast_len(&inner);
        pairs
    }

    /// Count of live unbroadcast txs — Core's `getmempoolinfo.unbroadcastcount`.
    pub fn unbroadcast_count(&self) -> usize {
        let mut inner = self.inner.write();
        let MempoolInner { entries, unbroadcast, .. } = &mut *inner;
        unbroadcast.retain(|txid, _| entries.contains_key(txid));
        let count = unbroadcast.len();
        self.sync_unbroadcast_len(&inner);
        count
    }

    /// Whether `txid` is a pending-broadcast local tx still in the mempool.
    pub fn is_unbroadcast(&self, txid: &Txid) -> bool {
        let inner = self.inner.read();
        inner.unbroadcast.contains_key(txid) && inner.entries.contains_key(txid)
    }

    /// Get mempool statistics.
    pub fn info(&self) -> MempoolInfo {
        // Snapshot policy first (lock released) so the policy lock is never held
        // while `inner` is — uniform leaf-lock discipline (see `remove_expired`).
        let (max_size, min_fee_rate, full_rbf) = {
            let cfg = self.config.read();
            (cfg.max_size_bytes, cfg.min_fee_rate, cfg.full_rbf)
        };
        let inner = self.inner.read();
        // Standard surface (design §6.1/§10): report the **acting class** only,
        // so `getmempoolinfo` is byte-identical to a node whose relay policy
        // refused the quarantined transactions. Until a policy is loaded every
        // entry is acting, so this equals the physical pool and is unchanged.
        let size = inner
            .entries
            .values()
            .filter(|e| e.scope.is_acting())
            .count();
        // Count only acting unbroadcast entries still resident (read-only belt —
        // the removal paths prune inline). A quarantined-relay entry is never
        // announced, so it never belongs to the broadcast-confirmation set.
        let unbroadcast = inner
            .unbroadcast
            .keys()
            .filter(|txid| {
                inner
                    .entries
                    .get(*txid)
                    .is_some_and(|e| e.scope.is_acting())
            })
            .count();
        MempoolInfo {
            size,
            bytes: inner.acting_bytes(),
            max_size,
            min_fee_rate,
            full_rbf,
            unbroadcast,
        }
    }

    /// Test-only: insert a synthetic entry keyed by `txid` so unit tests can
    /// exercise already-in-mempool paths without building a fully valid tx.
    #[cfg(test)]
    pub(crate) fn insert_entry_for_test(&self, txid: Txid, tx: Transaction, fee_rate: u64) {
        let mut inner = self.inner.write();
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee: 0,
                weight: 4,
                fee_rate,
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                source: TxSource::Rpc,
                scope: QuarantineScope::acting(),
                quarantine_rule: None,
            },
        );
    }
}

#[cfg(test)]
impl Mempool {
    /// Test-only: insert a minimal entry for `txid` (with `fee_rate`) and mark
    /// it unbroadcast. Lets cross-module tests (the peer manager) exercise the
    /// rebroadcast path without standing up a funded UTXO set.
    pub(crate) fn insert_unbroadcast_for_test(&self, txid: Txid, fee_rate: u64) {
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let mut inner = self.inner.write();
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee: 0,
                weight: 4,
                fee_rate,
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                source: TxSource::Rpc,
                scope: QuarantineScope::acting(),
                quarantine_rule: None,
            },
        );
        inner.unbroadcast.entry(txid).or_default();
        self.sync_unbroadcast_len(&inner);
    }

    /// Test-only: insert a minimal entry with an explicit quarantine `scope`,
    /// routed through the real per-class accounting (`account_insert`), so the
    /// quarantine-class mechanics can be exercised without the (not-yet-wired)
    /// policy engine. `nonce` varies the txid/serialized size slightly.
    pub(crate) fn insert_scoped_for_test(
        &self,
        nonce: u64,
        fee_rate: u64,
        scope: QuarantineScope,
    ) -> Txid {
        use bitcoin::{Amount, ScriptBuf, TxOut};
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(nonce),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let txid = tx.compute_txid();
        let tx_size = bitcoin::consensus::serialize(&tx).len();
        let mut inner = self.inner.write();
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee: 0,
                weight: 4,
                fee_rate,
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                source: TxSource::Rpc,
                scope,
                quarantine_rule: None,
            },
        );
        inner.account_insert(scope, tx_size);
        txid
    }

    /// Test-only: insert a caller-provided `tx` with an explicit quarantine
    /// `scope`, through the real per-class accounting. Lets the compact-block
    /// reconstruction test place a *specific* (quarantined) transaction in the
    /// pool so it can be looked up by its wtxid.
    pub(crate) fn insert_tx_scoped_for_test(
        &self,
        tx: Transaction,
        scope: QuarantineScope,
    ) -> Txid {
        let txid = tx.compute_txid();
        let tx_size = bitcoin::consensus::serialize(&tx).len();
        let mut inner = self.inner.write();
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee: 0,
                weight: 4,
                fee_rate: 0,
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                source: TxSource::Rpc,
                scope,
                quarantine_rule: None,
            },
        );
        inner.account_insert(scope, tx_size);
        txid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::chain::state::AssumeValid;
    use crate::validation::script::NoopVerifier;

    fn make_test_env() -> (ChainState, Mempool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-mempool-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            bitcoin::Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let mp = Mempool::new(1_000_000, 0); // 1MB, no min fee for tests
        (cs, mp, dir)
    }

    #[test]
    fn test_mempool_info_empty() {
        let (_cs, mp, dir) = make_test_env();
        let info = mp.info();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mempool_eviction_low_fee_evicted() {
        // Create a tiny mempool and verify low-fee txs get evicted for higher-fee ones
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Make an extremely small pool so we can fill it easily
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 500, // Very small
            min_fee_rate: 0,
            ..Default::default()
        });

        let mut inner = mp.inner.write();

        // Insert a low-fee "transaction" directly (bypass validation for unit test)
        let low_fee_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let low_txid = low_fee_tx.compute_txid();
        let low_size = bitcoin::consensus::serialize(&low_fee_tx).len();
        for input in &low_fee_tx.input {
            inner.spends.insert(input.previous_output, low_txid);
        }
        inner.entries.insert(
            low_txid,
            MempoolEntry {
                tx: low_fee_tx,
                fee: 10,
                weight: 400,
                fee_rate: 25, // very low fee rate
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                source: TxSource::Rpc,
                scope: QuarantineScope::acting(),
                quarantine_rule: None,
            },
        );
        inner.total_bytes = low_size;

        // Pool should have 1 entry
        assert_eq!(inner.entries.len(), 1);
        let original_bytes = inner.total_bytes;

        // Evict to free space
        Mempool::evict_lowest_fee_entries(&mut inner, original_bytes, false);

        // The low-fee tx should be gone
        assert_eq!(inner.entries.len(), 0);
        assert!(!inner.entries.contains_key(&low_txid));
        assert_eq!(inner.total_bytes, 0);
    }

    #[test]
    fn test_mempool_full_rejects_lower_fee() {
        // Verify that when pool is full, a tx with lower fee rate than minimum
        // is rejected with MempoolFull
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1, // 1 byte = always "full" for any tx
            min_fee_rate: 0,
            ..Default::default()
        });

        let dir = std::env::temp_dir().join(format!(
            "satd-mempool-evict-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            bitcoin::Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Create a minimal tx (will fail on missing inputs, but we check MempoolFull first)
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        // Should fail (either MempoolFull or MissingInputs, depending on order)
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_policy_swaps_live() {
        // SIGHUP config reload swaps the policy behind the RwLock; every read
        // path (the scalar accessors, policy(), and info() — which shares the
        // exact `self.config.read()` path accept_transaction snapshots) must
        // observe the new values immediately.
        let mp = Mempool::with_config(MempoolConfig {
            min_fee_rate: 1_000,
            max_size_bytes: 1_000_000,
            full_rbf: true,
            ..Default::default()
        });
        assert_eq!(mp.min_fee_rate(), 1_000);
        assert_eq!(mp.max_size_bytes(), 1_000_000);
        assert!(mp.info().full_rbf);

        mp.reload_policy(MempoolConfig {
            min_fee_rate: 5_000,
            max_size_bytes: 2_000_000,
            full_rbf: false,
            ..Default::default()
        });
        assert_eq!(
            mp.min_fee_rate(),
            5_000,
            "scalar accessor must read the reloaded policy"
        );
        assert_eq!(mp.max_size_bytes(), 2_000_000);
        assert_eq!(
            mp.policy().min_fee_rate,
            5_000,
            "policy() must read the reloaded policy"
        );
        let info = mp.info();
        assert_eq!(info.min_fee_rate, 5_000, "info() must read the reloaded policy");
        assert_eq!(info.max_size, 2_000_000);
        assert!(!info.full_rbf, "info() must reflect the reloaded full_rbf");
    }

    #[test]
    fn test_coinbase_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a coinbase transaction (input with null outpoint)
        let coinbase_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = mp.accept_transaction(coinbase_tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("coinbase"),
            "Expected coinbase rejection, got: {}",
            err
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_inputs() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a tx referencing a non-existent UTXO
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac,
                ]),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(matches!(result, Err(MempoolError::MissingInputs)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dust_output_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create mempool with default dust relay fee
        let (cs, _mp, dir) = make_test_env();
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            dust_relay_fee: 3_000, // 3 sat/vB — standard dust relay fee
            ..Default::default()
        });

        // Build a tx with a tiny (1 sat) P2PKH output — well below dust threshold
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1), // 1 sat — definitely dust
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac,
                ]),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(matches!(result, Err(MempoolError::Dust)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_non_std_txn_bypasses_standardness_checks() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, _mp, dir) = make_test_env();
        // Same dust-relay policy as the rejection test, but with
        // -acceptnonstdtxn on: the standardness checks (including dust) are
        // skipped, so admission proceeds past them to input validation.
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            dust_relay_fee: 3_000,
            accept_non_std_txn: true,
            ..Default::default()
        });

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1), // dust under standard relay
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac,
                ]),
            }],
        };

        // The dust gate must NOT fire (it's bypassed). The tx still fails
        // later on the missing/unspendable input — that's a non-standardness
        // path, which is exactly the point: consensus/input rules still apply.
        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(
            !matches!(result, Err(MempoolError::Dust)),
            "acceptnonstdtxn must bypass the dust standardness check, got {result:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_op_return_too_large() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build an OP_RETURN output > 83 bytes
        let mut op_return_script = vec![0x6a]; // OP_RETURN
        op_return_script.extend_from_slice(&[0x00; 90]); // 91 bytes total > 83

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xcc; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(op_return_script),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_op_return_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a tx with two OP_RETURN outputs (each within size limit)
        let op_return_script = ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xdd; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return_script.clone(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return_script,
                },
            ],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_data_carrier_disabled() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create mempool with data_carrier disabled
        let (cs, _mp, dir) = make_test_env();
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            data_carrier: false,
            ..Default::default()
        });

        // A small, valid OP_RETURN output
        let op_return_script = ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xee; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_for_block_empty_pool() {
        let (_cs, mp, dir) = make_test_env();

        // Verify remove_for_block on an empty pool is a no-op and doesn't panic
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        mp.remove_for_block(&genesis, 0);

        let info = mp.info();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_for_block_conflict_emits_block_conflict_not_full_pool() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        let (_cs, mp, dir) = make_test_env();
        let (event_tx, mut event_rx) =
            tokio::sync::broadcast::channel::<MempoolEvent>(64);
        mp.set_event_sender(event_tx);

        // A mempool tx spending UTXO X. We bypass accept_transaction
        // validation and wire the state by hand — the scenario we need
        // is "tx is in the mempool, a conflicting block arrives" and
        // that state is awkward to reach through the public API.
        let contested = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
            ),
            vout: 0,
        };
        let mempool_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: contested,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mempool_txid = mempool_tx.compute_txid();
        {
            let mut inner = mp.inner.write();
            inner.spends.insert(contested, mempool_txid);
            inner.entries.insert(
                mempool_txid,
                MempoolEntry {
                    tx: mempool_tx,
                    fee: 500,
                    weight: 400,
                    fee_rate: 1_250,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                    source: TxSource::Rpc,
                    scope: QuarantineScope::acting(),
                    quarantine_rule: None,
                },
            );
        }

        // Build a block containing a different tx that spends the same
        // UTXO X — chain-induced conflict.
        let block_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: contested,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // Minimum-viable block: take regtest genesis and append our tx.
        let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        block.txdata.push(block_tx);

        mp.remove_for_block(&block, 123);

        // Consume events until we see the LeaveEvicted for mempool_txid.
        // The broadcast is synchronous in-process; a handful of recv
        // iterations is enough.
        let mut saw_block_conflict = false;
        for _ in 0..8 {
            match event_rx.try_recv() {
                Ok(MempoolEvent::LeaveEvicted { txid, reason })
                    if txid == mempool_txid =>
                {
                    assert_eq!(
                        reason,
                        EvictReason::BlockConflict,
                        "chain-induced removal must be BlockConflict, not {:?}",
                        reason
                    );
                    saw_block_conflict = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(
            saw_block_conflict,
            "expected a LeaveEvicted{{BlockConflict}} event for the conflicting mempool tx"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getrawmempool_verbose_includes_ancestor_descendant_fields() {
        // Regression guard: the sat-tui mempool pane reads
        // `ancestorfees` / `ancestorsize` / `descendantcount` from
        // getrawmempool verbose to build its top-N table. If those
        // fields are ever dropped from the response, the TUI silently
        // displays an empty table on real nodes.
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let mp = Mempool::new(1_000_000, 0);

        // Build a parent tx spending some synthetic prevout.
        let parent_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        // Build a child spending parent:0 — establishes an ancestor link
        // inside the mempool so the rollup stats exceed the self values.
        let child_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(8_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let child_txid = child_tx.compute_txid();

        {
            let mut inner = mp.inner.write();
            for input in &parent_tx.input {
                inner.spends.insert(input.previous_output, parent_txid);
            }
            inner.entries.insert(
                parent_txid,
                MempoolEntry {
                    tx: parent_tx,
                    fee: 1_000,
                    weight: 400,
                    fee_rate: 10_000,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                    source: TxSource::Rpc,
                    scope: QuarantineScope::acting(),
                    quarantine_rule: None,
                },
            );
            for input in &child_tx.input {
                inner.spends.insert(input.previous_output, child_txid);
            }
            inner.entries.insert(
                child_txid,
                MempoolEntry {
                    tx: child_tx,
                    fee: 2_000,
                    weight: 400,
                    fee_rate: 20_000,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                    source: TxSource::Rpc,
                    scope: QuarantineScope::acting(),
                    quarantine_rule: None,
                },
            );
        }

        let resp = crate::rpc::rawtx::get_raw_mempool(&mp, true);
        let map = resp.as_object().expect("verbose response is a map");
        let parent_v = &map[&parent_txid.to_string()];
        let child_v = &map[&child_txid.to_string()];

        // Self-only: parent has no ancestors, child has parent as ancestor.
        assert_eq!(parent_v["ancestorcount"].as_u64(), Some(1));
        assert_eq!(child_v["ancestorcount"].as_u64(), Some(2));

        // Descendants: parent has the child, child has none.
        assert_eq!(parent_v["descendantcount"].as_u64(), Some(2));
        assert_eq!(child_v["descendantcount"].as_u64(), Some(1));

        // Fee rollups include the entry itself.
        assert_eq!(child_v["ancestorfees"].as_u64(), Some(1_000 + 2_000));
        assert_eq!(parent_v["descendantfees"].as_u64(), Some(1_000 + 2_000));

        // Sizes in vbytes (weight/4 ceil).
        assert_eq!(parent_v["ancestorsize"].as_u64(), Some(100));
        assert_eq!(child_v["ancestorsize"].as_u64(), Some(200));

        // Confirm the tui-critical shape: fields are u64 integers, not strings.
        assert!(parent_v["ancestorfees"].is_u64());
        assert!(parent_v["ancestorsize"].is_u64());
        assert!(parent_v["descendantcount"].is_u64());
    }

    #[test]
    fn mempool_entry_retains_prev_scripthashes() {
        // Admission must hash each spent prevout's scriptPubKey (input order)
        // onto the entry so the streaming matcher can prefix-match mempool
        // spends without re-resolving prevouts. Exercise the real admission
        // path via CPFP: a parent already in the pool supplies the child's
        // prevout script, so accept_transaction resolves it from the mempool.
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        let (cs, mp, dir) = make_test_env();

        // A distinctive *standard* prevout script (P2WPKH) the child will spend
        // — admission enforces output standardness, so it can't be arbitrary.
        let prevout_spk = {
            let mut b = vec![0x00, 0x14];
            b.extend_from_slice(&[0xab; 20]);
            ScriptBuf::from(b)
        };
        let child_spk = {
            let mut b = vec![0x00, 0x14];
            b.extend_from_slice(&[0xcd; 20]);
            ScriptBuf::from(b)
        };
        let parent_tx = Transaction {
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
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: prevout_spk.clone(),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        // Seed the parent directly (bypass its own input resolution); the child
        // then goes through the public accept path, which is what we test.
        {
            let mut inner = mp.inner.write();
            inner.entries.insert(
                parent_txid,
                MempoolEntry {
                    tx: parent_tx,
                    fee: 0,
                    weight: 400,
                    fee_rate: 0,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                    source: TxSource::Rpc,
                    scope: QuarantineScope::acting(),
                    quarantine_rule: None,
                },
            );
        }

        let child_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: child_spk,
            }],
        };
        let child_txid = child_tx.compute_txid();

        mp.accept_transaction(child_tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("child admits via CPFP");

        let entry = mp.get(&child_txid).expect("child in mempool");
        assert_eq!(
            entry.prev_scripthashes,
            vec![scripthash_of(&prevout_spk)],
            "entry retains the spent prevout's scripthash in input order"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dummy_txid(byte: u8) -> Txid {
        use bitcoin::hashes::Hash;
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn unbroadcast_mark_witness_threshold_and_count() {
        let mp = Mempool::new(1_000_000, 0);
        let txid = dummy_txid(1);

        // Marking a tx not in the mempool is a no-op.
        mp.mark_unbroadcast(txid);
        assert!(!mp.is_unbroadcast(&txid));
        assert_eq!(mp.unbroadcast_count(), 0);

        mp.insert_unbroadcast_for_test(txid, 0);
        assert!(mp.is_unbroadcast(&txid));
        assert_eq!(mp.unbroadcast_count(), 1);
        assert_eq!(mp.unbroadcast_txids(), vec![txid]);

        // Witnesses key on IP: the same host twice is one distinct witness,
        // no matter how many times it reconnects.
        let ip7: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        let ip8: std::net::IpAddr = "10.0.0.8".parse().unwrap();
        let ip9: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        assert!(!mp.record_broadcast_witness(&txid, ip7, 2));
        assert!(!mp.record_broadcast_witness(&txid, ip7, 2));
        assert!(mp.is_unbroadcast(&txid), "one distinct witness < threshold 2");
        assert!(mp.has_unbroadcast());

        // A second distinct host crosses the threshold → dropped.
        assert!(mp.record_broadcast_witness(&txid, ip8, 2));
        assert!(!mp.is_unbroadcast(&txid));
        assert_eq!(mp.unbroadcast_count(), 0);
        assert!(!mp.has_unbroadcast(), "lock-free mirror tracks the map");

        // Recording against an unknown/cleared txid is false, not a panic.
        assert!(!mp.record_broadcast_witness(&txid, ip9, 1));
    }

    #[test]
    fn unbroadcast_pruned_when_tx_leaves_mempool() {
        let mp = Mempool::new(1_000_000, 0);
        let txid = dummy_txid(2);
        mp.insert_unbroadcast_for_test(txid, 0);
        assert_eq!(mp.unbroadcast_count(), 1);

        // Simulate the tx being mined/evicted: it leaves `entries`.
        mp.inner.write().entries.remove(&txid);

        // The unbroadcast view self-prunes against live entries.
        assert_eq!(mp.unbroadcast_count(), 0);
        assert!(mp.unbroadcast_txids().is_empty());
        assert!(!mp.is_unbroadcast(&txid));
        assert_eq!(mp.info().unbroadcast, 0);
    }

    // --- PR 4b: quarantine-class mechanics (engine not yet wired) ---

    const RELAY_TEMPLATE: QuarantineScope = QuarantineScope {
        relay: true,
        template: true,
    };

    #[test]
    fn per_class_byte_accounting_tracks_both_classes() {
        let mp = Mempool::new(1_000_000, 0);
        let a1 = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let _a2 = mp.insert_scoped_for_test(2, 100, QuarantineScope::acting());
        let q1 = mp.insert_scoped_for_test(3, 100, RELAY_TEMPLATE);

        let total = mp.inner.read().total_bytes;
        let qbytes = mp.quarantine_bytes();
        assert!(qbytes > 0, "quarantine bytes should be nonzero");
        assert_eq!(
            mp.acting_bytes() + qbytes,
            total,
            "acting + quarantine must equal the physical pool size"
        );
        // Two acting entries vs one quarantined ⇒ acting bytes ≈ 2× quarantine.
        assert!(mp.acting_bytes() > qbytes);

        // Removing the quarantine entry zeroes the quarantine class only.
        {
            let mut inner = mp.inner.write();
            let e = inner.entries.remove(&q1).unwrap();
            let sz = bitcoin::consensus::serialize(&e.tx).len();
            inner.account_remove(e.scope, sz);
        }
        assert_eq!(mp.quarantine_bytes(), 0);
        assert!(mp.acting_bytes() > 0);
        assert!(mp.inner.read().entries.contains_key(&a1));
    }

    #[test]
    fn acting_eviction_never_touches_quarantine_class() {
        // The 4b safety invariant: filling/evicting the acting class must leave
        // held transactions alone, even when they are the cheapest in the pool.
        let mp = Mempool::new(1_000_000, 0);
        let cheap_q = mp.insert_scoped_for_test(1, 1, RELAY_TEMPLATE); // lowest fee overall
        let a_lo = mp.insert_scoped_for_test(2, 10, QuarantineScope::acting());
        let _a_hi = mp.insert_scoped_for_test(3, 1000, QuarantineScope::acting());

        let evicted = {
            let mut inner = mp.inner.write();
            // Free a large amount from the ACTING class.
            Mempool::evict_lowest_fee_entries(&mut inner, 10_000_000, false)
        };
        assert!(
            evicted.contains(&a_lo),
            "cheapest acting entry must be evicted"
        );
        assert!(
            !evicted.contains(&cheap_q),
            "a quarantined entry must NOT be evicted by acting-class pressure"
        );
        assert!(mp.inner.read().entries.contains_key(&cheap_q));
        assert!(mp.quarantine_bytes() > 0);
    }

    #[test]
    fn quarantine_eviction_only_evicts_held_lowest_fee_first() {
        let mp = Mempool::new(1_000_000, 0);
        let q_lo = mp.insert_scoped_for_test(1, 5, RELAY_TEMPLATE);
        let q_hi = mp.insert_scoped_for_test(2, 5000, RELAY_TEMPLATE);
        let acting = mp.insert_scoped_for_test(3, 1, QuarantineScope::acting()); // cheapest overall

        // Free just enough to drop one held entry — the cheapest held one.
        let one_entry = bitcoin::consensus::serialize(
            &mp.inner.read().entries.get(&q_lo).unwrap().tx,
        )
        .len();
        let evicted = {
            let mut inner = mp.inner.write();
            Mempool::evict_lowest_fee_entries(&mut inner, one_entry, true)
        };
        assert!(evicted.contains(&q_lo), "cheapest held entry evicted first");
        assert!(!evicted.contains(&q_hi), "higher-fee held entry retained");
        assert!(
            !evicted.contains(&acting),
            "acting entry untouched by quarantine-class eviction"
        );
        assert_eq!(mp.acting_bytes(), {
            let inner = mp.inner.read();
            bitcoin::consensus::serialize(&inner.entries.get(&acting).unwrap().tx).len()
        });
    }

    #[test]
    fn acting_eviction_counts_only_same_class_bytes_toward_goal() {
        // A quarantined child of an evicted acting parent must be removed for
        // graph integrity (its input vanishes with the parent) — but its bytes
        // belong to the quarantine class, so they must NOT count toward the
        // acting class's eviction goal. Otherwise eviction stops early and leaves
        // the acting class over budget.
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let mp = Mempool::new(1_000_000, 0);

        let insert = |inputs: Vec<OutPoint>, nonce: u64, fee_rate: u64, scope: QuarantineScope| -> Txid {
            let tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: inputs
                    .into_iter()
                    .map(|o| TxIn {
                        previous_output: o,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    })
                    .collect(),
                output: vec![TxOut {
                    value: Amount::from_sat(nonce),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            let txid = tx.compute_txid();
            let tx_size = bitcoin::consensus::serialize(&tx).len();
            let mut inner = mp.inner.write();
            inner.entries.insert(
                txid,
                MempoolEntry {
                    tx,
                    fee: 0,
                    weight: 4,
                    fee_rate,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                    source: TxSource::Rpc,
                    scope,
                    quarantine_rule: None,
                },
            );
            inner.account_insert(scope, tx_size);
            txid
        };

        // Acting parent P (cheapest), a quarantined child C spending P, and a
        // second acting entry that also has to go to meet the goal.
        let p = insert(vec![], 1, 1, QuarantineScope::acting());
        let c = insert(vec![OutPoint { txid: p, vout: 0 }], 2, 1, RELAY_TEMPLATE);
        let a_other = insert(vec![], 3, 2, QuarantineScope::acting());

        let p_size = {
            let inner = mp.inner.read();
            bitcoin::consensus::serialize(&inner.entries.get(&p).unwrap().tx).len()
        };

        // Just one byte past the parent alone: only by *excluding* C's bytes from
        // the acting goal does eviction continue on to `a_other`.
        let evicted = {
            let mut inner = mp.inner.write();
            Mempool::evict_lowest_fee_entries(&mut inner, p_size + 1, false)
        };

        assert!(evicted.contains(&p), "acting parent evicted");
        assert!(
            evicted.contains(&c),
            "quarantined child removed for graph integrity (its parent is gone)"
        );
        assert!(
            evicted.contains(&a_other),
            "cross-class child bytes must not satisfy the acting goal — the second \
             acting entry must still be evicted"
        );
    }

    // ───────────────────────── PR 4c: the eval point ─────────────────────────
    //
    // These exercise the policy engine wired into `accept_transaction`: the I8
    // no-op, quarantine placement, the deferred-standardness matrix (§6.2/§7),
    // and infectious-descendant propagation (§3/§7). They fund confirmed UTXOs
    // directly in the backing store (the `CoinCache` reads through on miss) so a
    // transaction can pass input resolution and reach the eval point.

    use crate::storage::Store as _;
    use crate::storage::coinview::Coin;

    /// Build a test env with a set of confirmed (non-coinbase) UTXOs pre-funded
    /// in the backing store. `dust_relay_fee` is on (3000) so the dust
    /// standardness check is live for the deferred-standardness tests.
    fn make_funded_env(coins: &[(OutPoint, Coin)]) -> (ChainState, Mempool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-evalpoint-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        if !coins.is_empty() {
            let mut batch = crate::storage::StoreBatch::default();
            for (op, c) in coins {
                batch.coin_puts.push((*op, c.clone()));
            }
            store.write_batch(batch).unwrap();
        }
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            bitcoin::Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            dust_relay_fee: 3_000,
            ..Default::default()
        });
        (cs, mp, dir)
    }

    fn outpoint(tag: u8) -> OutPoint {
        use bitcoin::hashes::Hash;
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [tag; 32],
            )),
            vout: 0,
        }
    }

    fn coin(amount: u64) -> Coin {
        // Standard P2WPKH so the prevout classifies cleanly; non-coinbase so
        // maturity never blocks the spend.
        Coin {
            amount,
            script_pubkey: p2wpkh_spk(0x11),
            height: 1,
            coinbase: false,
        }
    }

    fn p2wpkh_spk(tag: u8) -> bitcoin::ScriptBuf {
        let mut v = vec![0x00, 0x14];
        v.extend_from_slice(&[tag; 20]);
        bitcoin::ScriptBuf::from_bytes(v)
    }

    /// 1-in / 1-out spend of `prev`, paying `out_value` to a P2WPKH output.
    fn spend(prev: OutPoint, out_value: u64, out_tag: u8) -> Transaction {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};
        Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: p2wpkh_spk(out_tag),
            }],
        }
    }

    fn set_ruleset(mp: &Mempool, src: &str) {
        let rs = satd_policy::parse_ruleset(src).expect("test ruleset must compile");
        mp.set_policy(std::sync::Arc::new(rs));
    }

    fn write_policy(tag: &str, src: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-danger-{tag}-{}-{}",
            std::process::id(),
            now_unix_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.policy");
        std::fs::write(&path, src).unwrap();
        (dir, path)
    }

    const CSV_RULE: &str =
        "version 1\nquarantine csv when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n";

    #[test]
    fn danger_gate_refuses_relay_withholding_rule_unless_allowed() {
        let (dir, path) = write_policy("refuse", CSV_RULE);

        // Strict (default): the relay-withholding enforcement rule is refused.
        let mp = Mempool::with_config(MempoolConfig::default());
        let err = mp.load_policy_file(&path).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(!mp.has_policy(), "nothing loaded on refusal");

        // allowdangerousfilters: loads with a warning.
        let mp2 = Mempool::with_config(MempoolConfig {
            allow_dangerous_filters: true,
            ..Default::default()
        });
        mp2.load_policy_file(&path)
            .expect("loads with allowdangerousfilters");
        assert!(mp2.has_policy());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn danger_gate_allows_template_only_match() {
        // The same enforcement matcher scoped `on template` still relays, so it
        // is not gated even in strict mode.
        let (dir, path) = write_policy(
            "tmpl",
            "version 1\nquarantine csv on template when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
        );
        let mp = Mempool::with_config(MempoolConfig::default());
        mp.load_policy_file(&path)
            .expect("template-only enforcement match must not be gated");
        assert!(mp.has_policy());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn danger_gate_reload_keeps_last_good() {
        // A safe ruleset loads; a dangerous reload is refused and the safe one
        // stays installed (I7 last-good).
        let (dir, safe) = write_policy("safe", "version 1\nquarantine cheap when tx.fee_rate < 1000\n");
        let danger = dir.join("danger.policy");
        std::fs::write(&danger, CSV_RULE).unwrap();

        let mp = Mempool::with_config(MempoolConfig::default());
        mp.load_policy_file(&safe).expect("safe loads");
        let before = mp.policy_snapshot().map(|rs| rs.rules()[0].name.clone());

        let err = match mp.reload_policy_file(&danger) {
            Err(e) => e,
            Ok(_) => panic!("dangerous reload must be refused"),
        };
        assert!(err.contains("refusing"), "{err}");
        let after = mp.policy_snapshot().map(|rs| rs.rules()[0].name.clone());
        assert_eq!(before, after, "dangerous reload must keep last-good");
        assert_eq!(before.as_deref(), Some("cheap"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recheck_flags_loaded_policy_when_flag_tightened() {
        // Review round 1 (PR 410): tightening allowdangerousfilters true→false
        // with an unchanged dangerous policy loaded must be detected so the SIGHUP
        // handler can eject it — the sha-dedup would otherwise skip the gate.
        let (dir, path) = write_policy("recheck", CSV_RULE);

        // Loaded with the flag on: passes recheck.
        let mp = Mempool::with_config(MempoolConfig {
            allow_dangerous_filters: true,
            ..Default::default()
        });
        mp.load_policy_file(&path).expect("loads with flag on");
        assert!(mp.has_policy());
        assert!(
            mp.recheck_loaded_danger_gate().is_ok(),
            "allowed ⇒ recheck passes"
        );

        // Tighten the flag (as the live! reload does) WITHOUT touching the file:
        // recheck must now flag the still-loaded relay-withholding rule.
        mp.reload_policy(MempoolConfig::default());
        let err = mp
            .recheck_loaded_danger_gate()
            .expect_err("tightened flag ⇒ loaded dangerous policy is now disallowed");
        assert!(err.contains("withhold relay"), "{err}");

        // A safe policy never trips the recheck regardless of the flag.
        let (sdir, safe) = write_policy("recheck-safe", "version 1\nquarantine cheap when tx.fee_rate < 1000\n");
        let mp2 = Mempool::with_config(MempoolConfig::default());
        mp2.load_policy_file(&safe).expect("safe loads");
        assert!(mp2.recheck_loaded_danger_gate().is_ok());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&sdir);
    }

    #[test]
    fn tightened_flag_ejects_live_dangerous_policy_and_promotes() {
        // Deep-review (PR 410): exercise the FULL fail-safe eject sequence the
        // SIGHUP handler runs in `apply_policyfile_reload` — recheck → clear →
        // reapply → promote — not just `recheck_loaded_danger_gate` in isolation.
        // A `tx.version == 2` rule is relay-withholding (every danger probe is
        // version 2) AND matches a plain test spend, so it both trips the gate
        // and actually quarantines a transaction we can watch get promoted.
        let op = outpoint(0xb7);
        let (cs, _discard, dir) = make_funded_env(&[(op, coin(100_000))]);
        let cfg = MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            dust_relay_fee: 3_000,
            allow_dangerous_filters: true,
            ..Default::default()
        };
        let mp = Mempool::with_config(cfg.clone());

        let (pdir, path) = write_policy("eject", "version 1\nquarantine catch when tx.version == 2\n");
        mp.load_policy_file(&path)
            .expect("dangerous policy loads with the flag on");
        assert!(mp.has_policy());

        // A matching tx is admitted into the quarantine (relay-withheld) class.
        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted into quarantine");
        assert!(
            mp.inner.read().entries.get(&txid).unwrap().scope.is_quarantined(),
            "tx is held under the dangerous policy"
        );

        // Tighten the flag (as the live! reload does) with the file unchanged.
        mp.reload_policy(MempoolConfig {
            allow_dangerous_filters: false,
            ..cfg
        });

        // The unified post-reload recheck flags the now-disallowed live policy …
        let err = mp
            .recheck_loaded_danger_gate()
            .expect_err("tightened flag ⇒ live dangerous policy is disallowed");
        assert!(err.contains("withhold relay"), "{err}");

        // … and the eject sequence drops the engine and promotes the held tx.
        mp.clear_policy();
        let t = mp.reapply_policy(&cs);
        assert!(!mp.has_policy(), "dangerous policy ejected");
        assert!(
            t.promoted.contains(&txid),
            "held tx promoted to acting on eject: {:?}",
            t.promoted
        );
        assert!(
            mp.inner.read().entries.get(&txid).unwrap().scope.is_acting(),
            "tx is acting after the eject"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&pdir);
    }

    #[test]
    fn no_policy_is_byte_identical_to_engine_compiled_out() {
        // I8: with no ruleset (and with an *empty* ruleset, which the hot path
        // treats identically), a tx is admitted to the acting class and the
        // quarantine class stays empty.
        let op = outpoint(0xa1);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        assert!(!mp.has_policy());

        // Empty ruleset ⇒ still "no policy" for the hot path.
        set_ruleset(&mp, "version 1");
        assert!(!mp.has_policy(), "an empty ruleset is inert (I8)");

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("admitted");
        let inner = mp.inner.read();
        assert!(inner.entries.get(&txid).unwrap().scope.is_acting());
        assert_eq!(inner.quarantine_bytes, 0);
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_rule_places_entry_in_quarantine_class() {
        let op = outpoint(0xa2);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        // Match every version-2 transaction → full-scope quarantine (default).
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        assert!(mp.has_policy());

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted into quarantine");
        let inner = mp.inner.read();
        let entry = inner.entries.get(&txid).unwrap();
        assert!(entry.scope.is_quarantined(), "held in quarantine class");
        assert!(entry.scope.relay && entry.scope.template, "default full scope");
        assert!(inner.quarantine_bytes > 0);
        // The held entry must NOT count against the acting class.
        assert_eq!(inner.acting_bytes(), 0);
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deferred_standardness_allow_match_admits_to_acting() {
        // A dust output is nonstandard, but an `allow` matching the submission
        // forgives it (§6.2) → admitted to the acting class.
        let op = outpoint(0xa3);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nallow mine when tx.source == rpc");

        let tx = spend(op, 1, 0x22); // 1-sat output ⇒ dust
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("allow forgives the dust nonstandardness");
        let inner = mp.inner.read();
        assert!(inner.entries.get(&txid).unwrap().scope.is_acting());
        assert_eq!(inner.quarantine_bytes, 0);
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deferred_standardness_pass_lets_rejection_stand() {
        // Dust + a ruleset that *has* an allow rule (so deferral happens) but the
        // allow doesn't match this submission and nothing quarantines ⇒ Pass ⇒
        // the baseline dust rejection stands.
        let op = outpoint(0xa4);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nallow mine when tx.source == mcp");

        let tx = spend(op, 1, 0x22); // dust
        let err = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .unwrap_err();
        assert!(matches!(err, MempoolError::Dust), "got {err:?}");
        assert_eq!(mp.quarantine_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deferred_standardness_quarantine_is_not_a_dumping_ground() {
        // Dust + an allow rule (deferral on) + a quarantine rule that matches:
        // the deferred baseline rejection still stands — a nonstandard tx is
        // rejected, NOT quarantined (§6.2).
        let op = outpoint(0xa5);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(
            &mp,
            "version 1\nallow mine when tx.source == mcp\nquarantine catch when tx.version == 2",
        );

        let tx = spend(op, 1, 0x22); // dust, version 2 (would match the quarantine rule)
        let err = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .unwrap_err();
        assert!(matches!(err, MempoolError::Dust), "got {err:?}");
        assert_eq!(
            mp.quarantine_bytes(),
            0,
            "nonstandard tx must not land in quarantine"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_allow_rules_rejects_nonstandard_early() {
        // With zero `allow` rules the deferral machinery is skipped entirely:
        // standardness rejects before input resolution, exactly as today. Proven
        // by rejecting with `Dust` even though the input is unfunded (which would
        // otherwise surface as `MissingInputs` later).
        let (cs, mp, dir) = make_funded_env(&[]); // no coins funded
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");

        let tx = spend(outpoint(0xde), 1, 0x22); // dust, unfunded input
        let err = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .unwrap_err();
        assert!(
            matches!(err, MempoolError::Dust),
            "must reject early on standardness, not reach input resolution: got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_is_infectious_to_descendants() {
        // A child that matches no rule still inherits its quarantined parent's
        // scope (§3/§7): announcing a child whose parent we withhold would be
        // incoherent.
        let op = outpoint(0xa6);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        // Match only the parent: its 90k output trips the threshold; the child's
        // 50k output does not.
        set_ruleset(
            &mp,
            "version 1\nquarantine big when any output (out.value > 80000)",
        );

        let parent = spend(op, 90_000, 0x22);
        let parent_txid = parent.compute_txid();
        mp.accept_transaction(parent, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("parent admitted (quarantined)");
        assert!(
            mp.inner
                .read()
                .entries
                .get(&parent_txid)
                .unwrap()
                .scope
                .is_quarantined(),
            "parent is quarantined"
        );

        // Child spends the parent's output; it matches no rule on its own.
        let child = spend(OutPoint { txid: parent_txid, vout: 0 }, 50_000, 0x33);
        let child_txid = child.compute_txid();
        mp.accept_transaction(child, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("child admitted");
        let inner = mp.inner.read();
        let child_entry = inner.entries.get(&child_txid).unwrap();
        assert!(
            child_entry.scope.is_quarantined(),
            "child inherits the parent's quarantine scope"
        );
        assert!(
            child_entry.scope.relay && child_entry.scope.template,
            "inherited the parent's full scope"
        );
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ───────────────────── PR 4d: local-submission refusal + events ──────────

    #[test]
    fn local_relay_quarantine_is_refused_with_rule_named() {
        // A local (RPC) submission drawing a relay-scoped quarantine verdict is
        // refused (§6.1), naming the rule, and is NOT placed.
        let op = outpoint(0xb1);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");

        let tx = spend(op, 99_000, 0x22);
        let err = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .unwrap_err();
        match &err {
            MempoolError::Quarantined(rule) => assert_eq!(rule, "catch"),
            other => panic!("expected Quarantined, got {other:?}"),
        }
        // Refused ⇒ never placed.
        assert_eq!(mp.quarantine_bytes(), 0);
        assert_eq!(mp.info().size, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowquarantined_override_admits_local_into_quarantine() {
        let op = outpoint(0xb2);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, true)
            .expect("override admits into quarantine");
        let inner = mp.inner.read();
        assert!(inner.entries.get(&txid).unwrap().scope.is_quarantined());
        assert!(inner.quarantine_bytes > 0);
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn template_only_quarantine_is_not_refused() {
        // `on template` withholds only from block building — the tx still relays,
        // so a local submission succeeds (§6.1) and carries only the template bit.
        let op = outpoint(0xb3);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(
            &mp,
            "version 1\nquarantine no-mine on template when tx.version == 2",
        );

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("template-only quarantine submits normally");
        let inner = mp.inner.read();
        let scope = inner.entries.get(&txid).unwrap().scope;
        assert!(scope.template && !scope.relay, "template-only scope");
        drop(inner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn p2p_relay_quarantine_is_never_refused() {
        // The refusal is local-only: a P2P-sourced tx quarantines as designed.
        let op = outpoint(0xb4);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("p2p quarantine is admitted, not refused");
        assert!(
            mp.inner.read().entries.get(&txid).unwrap().scope.is_quarantined()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantined_admission_emits_quarantined_not_enter() {
        // §10: a quarantined admission emits no `Enter` on the default stream; it
        // emits `Quarantined` on the separate channel instead.
        let op = outpoint(0xb5);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");

        let (etx, mut erx) = broadcast::channel::<MempoolEvent>(16);
        let (qtx, mut qrx) = broadcast::channel::<QuarantineEvent>(16);
        mp.set_event_sender(etx);
        mp.set_quarantine_event_sender(qtx);

        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted to quarantine");

        // No default-stream Enter for a held tx.
        assert!(
            matches!(erx.try_recv(), Err(broadcast::error::TryRecvError::Empty)),
            "quarantined admission must emit no Enter on the default stream"
        );
        // Exactly one Quarantined event on the separate channel, naming the rule.
        match qrx.try_recv() {
            Ok(QuarantineEvent::Quarantined { txid: t, rule, relay, template, .. }) => {
                assert_eq!(t, txid);
                assert_eq!(rule, "catch");
                assert!(relay && template, "full default scope");
            }
            other => panic!("expected one Quarantined event, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- PR 5: assist-path scope filtering (the three-consumer split, §2.4) ---

    const RELAY_ONLY: QuarantineScope = QuarantineScope { relay: true, template: false };
    const TEMPLATE_ONLY: QuarantineScope = QuarantineScope { relay: false, template: true };

    #[test]
    fn scope_assist_predicates() {
        // The two gates the assist paths read.
        assert!(QuarantineScope::acting().assists_relay());
        assert!(QuarantineScope::acting().assists_template());
        // `on template`: still relayed, never mined.
        assert!(TEMPLATE_ONLY.assists_relay());
        assert!(!TEMPLATE_ONLY.assists_template());
        // `on relay`: never gossiped, still mineable by us.
        assert!(!RELAY_ONLY.assists_relay());
        assert!(RELAY_ONLY.assists_template());
        // Full quarantine: assisted on neither path.
        assert!(!RELAY_TEMPLATE.assists_relay());
        assert!(!RELAY_TEMPLATE.assists_template());
    }

    #[test]
    fn template_entries_exclude_template_quarantined() {
        let mp = Mempool::new(1_000_000, 0);
        let acting = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let relay_only = mp.insert_scoped_for_test(2, 100, RELAY_ONLY);
        let template_only = mp.insert_scoped_for_test(3, 100, TEMPLATE_ONLY);
        let full = mp.insert_scoped_for_test(4, 100, RELAY_TEMPLATE);

        let ids: std::collections::HashSet<Txid> =
            mp.get_template_entries().into_iter().map(|(t, _)| t).collect();
        // The template (and the smart-fee simulator that shares this view)
        // mine what we would build: acting + relay-only-quarantined.
        assert!(ids.contains(&acting));
        assert!(ids.contains(&relay_only), "on-relay txs are still mineable by us");
        assert!(!ids.contains(&template_only), "on-template txs are withheld from blocks");
        assert!(!ids.contains(&full));
        // The union still has everything (reconstruction / observability rely on it).
        assert_eq!(mp.get_all_entries().len(), 4);
    }

    #[test]
    fn bip35_txids_exclude_relay_quarantined() {
        let mp = Mempool::new(1_000_000, 0);
        let acting = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let relay_only = mp.insert_scoped_for_test(2, 100, RELAY_ONLY);
        let template_only = mp.insert_scoped_for_test(3, 100, TEMPLATE_ONLY);
        let full = mp.insert_scoped_for_test(4, 100, RELAY_TEMPLATE);

        let ids: std::collections::HashSet<Txid> =
            mp.txids_above_feerate(0).into_iter().collect();
        // BIP35 is a relay path: announce only what we gossip.
        assert!(ids.contains(&acting));
        assert!(ids.contains(&template_only), "on-template txs are still relayed");
        assert!(!ids.contains(&relay_only), "on-relay txs are withheld from announcement");
        assert!(!ids.contains(&full));
    }

    #[test]
    fn unbroadcast_entries_exclude_relay_quarantined() {
        let mp = Mempool::new(1_000_000, 0);
        // Insert scoped entries, then mark each unbroadcast.
        let acting = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let relay_only = mp.insert_scoped_for_test(2, 100, RELAY_ONLY);
        mp.mark_unbroadcast(acting);
        mp.mark_unbroadcast(relay_only);

        let ids: std::collections::HashSet<Txid> =
            mp.unbroadcast_entries().into_iter().map(|(t, _)| t).collect();
        assert!(ids.contains(&acting));
        assert!(
            !ids.contains(&relay_only),
            "relay-quarantined local tx stays in the set but is never put on the wire"
        );
        // It is still tracked for promotion-on-reload, just not rebroadcast.
        assert!(mp.is_unbroadcast(&relay_only));
    }

    // --- PR 6a: ruleset reload re-placement (§8, I9) ---

    fn scope_of(mp: &Mempool, txid: &Txid) -> QuarantineScope {
        mp.inner.read().entries.get(txid).unwrap().scope
    }

    #[test]
    fn reapply_demotes_acting_into_quarantine() {
        // A tx admitted with no policy is acting; loading a ruleset that matches
        // it and reapplying demotes it into the quarantine class.
        let op = outpoint(0xc1);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted to acting");
        assert!(scope_of(&mp, &txid).is_acting());

        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        let t = mp.reapply_policy(&cs);

        assert_eq!(t.demoted, vec![txid]);
        assert!(t.promoted.is_empty());
        assert!(scope_of(&mp, &txid).is_quarantined());
        assert!(mp.quarantine_bytes() > 0);
        assert_eq!(mp.acting_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reapply_promotes_quarantine_back_to_acting_on_rule_removal() {
        // I9: removing the rule (clear_policy) recovers everything it held —
        // losslessly, with nothing re-heard from the network.
        let op = outpoint(0xc2);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted to quarantine");
        assert!(scope_of(&mp, &txid).is_quarantined());

        mp.clear_policy();
        let t = mp.reapply_policy(&cs);

        assert_eq!(t.promoted, vec![txid]);
        assert!(t.demoted.is_empty());
        assert!(scope_of(&mp, &txid).is_acting());
        assert_eq!(mp.quarantine_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reapply_round_trip_is_lossless_i9() {
        // The headline I9 test: add a rule → remove the rule → the pool is
        // byte-for-byte where it started (same entries, same acting scope, same
        // class accounting). Nothing was dropped or re-downloaded.
        let op = outpoint(0xc3);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        let tx = spend(op, 99_000, 0x22);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted");

        let before_total = mp.inner.read().total_bytes;
        let before_acting = mp.acting_bytes();
        assert!(scope_of(&mp, &txid).is_acting());

        // Add a quarantine rule and reapply → demoted.
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        mp.reapply_policy(&cs);
        assert!(scope_of(&mp, &txid).is_quarantined());

        // Remove it and reapply → promoted back, identical to the start.
        mp.clear_policy();
        mp.reapply_policy(&cs);
        assert!(scope_of(&mp, &txid).is_acting());
        assert!(mp.inner.read().entries.contains_key(&txid), "nothing dropped");
        assert_eq!(mp.inner.read().total_bytes, before_total);
        assert_eq!(mp.acting_bytes(), before_acting);
        assert_eq!(mp.quarantine_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reapply_partial_relay_recovery_is_demoted_not_promoted() {
        // Regression: a move that recovers relay assistance but leaves the tx
        // template-held must NOT be reported as `Promoted` (whose contract is a
        // FULL scope clear → acting again). It must surface as a `Demoted`-class
        // move carrying the new held scope, so subscribers don't believe a
        // still-template-held tx is acting.
        let op = outpoint(0xc7);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        let tx = spend(op, 99_000, 0x55);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted");

        // First ruleset: full quarantine (default scope = relay + template).
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        let t = mp.reapply_policy(&cs);
        assert_eq!(t.demoted, vec![txid]);
        let s = scope_of(&mp, &txid);
        assert!(s.relay && s.template, "withheld from both paths");

        // Reload to template-only quarantine: relay is recovered, template stays
        // held. Net result is still quarantined → this is a Demoted move, never a
        // Promoted one.
        set_ruleset(&mp, "version 1\nquarantine catch on template when tx.version == 2");
        let t = mp.reapply_policy(&cs);
        assert!(
            t.promoted.is_empty(),
            "still template-held ⇒ not a promotion"
        );
        assert_eq!(t.demoted, vec![txid], "partial recovery reported as a scope change");
        let s = scope_of(&mp, &txid);
        assert!(!s.relay && s.template, "now relay-assisting, template-held");
        assert!(s.is_quarantined(), "still quarantined overall");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reapply_promotion_evicted_in_same_pass_is_not_reported_promoted() {
        // Regression: a tx promoted into an already-full acting class can be the
        // lowest-fee victim of the post-replacement budget eviction in the SAME
        // pass. It left the pool entirely, so it must surface only as `evicted` —
        // never in `promoted` (which PR 6b re-announces) and never via a
        // `Promoted` event for a tx that no longer exists.
        let op_keep = outpoint(0xd1);
        let op_q = outpoint(0xd2);
        let (cs, mp, dir) =
            make_funded_env(&[(op_keep, coin(100_000)), (op_q, coin(100_000))]);

        // High-fee acting tx to keep; low-fee tx that will be quarantined then
        // promoted. Both are 1-in/1-out and serialize to the same length.
        let tx_keep = spend(op_keep, 90_000, 0x33); // fee 10_000 — high rate
        let tx_q = spend(op_q, 99_900, 0x44); // fee 100 — low rate, evict victim
        let l = bitcoin::consensus::serialize(&tx_keep).len();
        assert_eq!(l, bitcoin::consensus::serialize(&tx_q).len());

        // Quarantine only tx_q (match its 99_900 output); admit both.
        set_ruleset(
            &mp,
            "version 1\nquarantine onlyq when any outputs (out.value == 99900)",
        );
        let keep_txid = mp
            .accept_transaction(tx_keep, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("keep admitted");
        let q_txid = mp
            .accept_transaction(tx_q, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("q admitted");
        assert!(scope_of(&mp, &keep_txid).is_acting());
        assert!(scope_of(&mp, &q_txid).is_quarantined());

        // Tighten the acting budget so it fits exactly one tx, and remove the
        // rule: reapply promotes tx_q into acting → acting holds two txs → over
        // budget → the lowest-fee tx (tx_q) is evicted in the same pass.
        mp.clear_policy();
        mp.reload_policy(MempoolConfig {
            max_size_bytes: l + l / 2,
            min_fee_rate: 0,
            dust_relay_fee: 3_000,
            ..Default::default()
        });
        let t = mp.reapply_policy(&cs);

        assert!(
            t.evicted.contains(&q_txid),
            "the promoted-then-overflowing tx must be evicted"
        );
        assert!(
            !t.promoted.contains(&q_txid),
            "an evicted tx must not be reported as promoted (no phantom re-announce)"
        );
        assert!(
            !mp.inner.read().entries.contains_key(&q_txid),
            "evicted tx is gone from the pool"
        );
        assert!(
            mp.inner.read().entries.contains_key(&keep_txid),
            "the high-fee acting tx survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reapply_propagates_infectiously_in_topological_order() {
        // A parent matched by the rule and its (rule-unmatched) child: on reload
        // the child inherits the parent's held scope, derived from the parent's
        // already-recomputed scope in the same sweep.
        let op = outpoint(0xc4);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(200_000))]);
        // Parent: version 2, will match the rule. Child spends the parent.
        let parent = spend(op, 150_000, 0x33);
        let parent_txid = parent.compute_txid();
        let parent_out = OutPoint { txid: parent_txid, vout: 0 };
        let child = spend(parent_out, 100_000, 0x44);
        let child_txid = child.compute_txid();

        mp.accept_transaction(parent, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("parent admitted");
        mp.accept_transaction(child, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("child admitted");
        assert!(scope_of(&mp, &parent_txid).is_acting());
        assert!(scope_of(&mp, &child_txid).is_acting());

        // Quarantine only the parent (match its 150_000 output value); the child
        // pays 100_000 and is not matched directly.
        set_ruleset(
            &mp,
            "version 1\nquarantine big on template when any outputs (out.value == 150000)",
        );
        mp.reapply_policy(&cs);

        let pscope = scope_of(&mp, &parent_txid);
        let cscope = scope_of(&mp, &child_txid);
        assert!(pscope.template && !pscope.relay, "parent held on template");
        assert!(
            cscope.template,
            "child inherits the parent's template hold (infectious, §3/§7)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_policy_file_detects_noop_vs_change() {
        let mp = Mempool::new(1_000_000, 0);
        let path = std::env::temp_dir().join(format!(
            "satd-policy-reload-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // `tx.version == 3` is gate-safe (the danger vectors are version 2, like
        // real commitments) while staying distinct from the edited rule below.
        std::fs::write(&path, "version 1\nquarantine a when tx.version == 3\n").unwrap();
        // First load is a change (was none).
        assert!(matches!(
            mp.reload_policy_file(&path).unwrap(),
            PolicyReloadKind::Changed(_)
        ));
        assert!(mp.has_policy());
        // Same contents ⇒ no-op (skips the re-placement walk).
        assert!(matches!(
            mp.reload_policy_file(&path).unwrap(),
            PolicyReloadKind::Unchanged
        ));
        // Edited contents ⇒ change.
        std::fs::write(&path, "version 1\nquarantine a when tx.version == 1\n").unwrap();
        assert!(matches!(
            mp.reload_policy_file(&path).unwrap(),
            PolicyReloadKind::Changed(_)
        ));
        // A compile error keeps last-good and returns Err (I7).
        std::fs::write(&path, "version 1\nthis is not valid\n").unwrap();
        assert!(mp.reload_policy_file(&path).is_err());
        assert!(mp.has_policy(), "last-good ruleset survives a bad reload");
        // clear_policy resets the tracked sha so a later identical file reloads.
        mp.clear_policy();
        assert!(!mp.has_policy());
        std::fs::write(&path, "version 1\nquarantine a when tx.version == 1\n").unwrap();
        assert!(matches!(
            mp.reload_policy_file(&path).unwrap(),
            PolicyReloadKind::Changed(_)
        ));

        let _ = std::fs::remove_file(&path);
    }

    // --- PR 7a: standard-surface invisibility (design §6.1/§10) ---
    //
    // Every standard wallet-serving read surface presents the acting class
    // only — byte-identical to a node whose relay policy refused the
    // quarantined transactions. These cover the mempool-level views; the
    // RPC byte-identity differential lives in `crate::rpc::rawtx`.

    #[test]
    fn get_acting_entries_excludes_quarantine() {
        let mp = Mempool::new(300_000_000, 1_000);
        let a = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        mp.insert_scoped_for_test(2, 100, RELAY_ONLY);
        mp.insert_scoped_for_test(3, 100, TEMPLATE_ONLY);
        mp.insert_scoped_for_test(4, 100, RELAY_TEMPLATE);
        let acting: Vec<Txid> = mp
            .get_acting_entries()
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        assert_eq!(acting, vec![a], "only the fully-acting tx is visible");
        assert_eq!(mp.get_all_entries().len(), 4, "all four are physically held");
    }

    #[test]
    fn info_reports_acting_class_only() {
        // Reference pool: one acting tx, no policy.
        let reference = Mempool::new(300_000_000, 1_000);
        reference.insert_scoped_for_test(1, 100, QuarantineScope::acting());

        // Same acting tx plus a quarantined tx in every scope.
        let occupied = Mempool::new(300_000_000, 1_000);
        occupied.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        occupied.insert_scoped_for_test(2, 100, RELAY_ONLY);
        occupied.insert_scoped_for_test(3, 100, TEMPLATE_ONLY);
        occupied.insert_scoped_for_test(4, 100, RELAY_TEMPLATE);

        let r = reference.info();
        let q = occupied.info();
        assert_eq!(r.size, q.size, "getmempoolinfo.size counts the acting class only");
        assert_eq!(r.bytes, q.bytes, "getmempoolinfo.bytes counts the acting class only");
        assert_eq!(q.size, 1);
        assert!(
            occupied.quarantine_bytes() > 0,
            "the quarantine class is genuinely occupied — the equality is load-bearing"
        );
    }

    #[test]
    fn get_entry_verbose_hides_quarantined_txid() {
        let mp = Mempool::new(300_000_000, 1_000);
        let a = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let r = mp.insert_scoped_for_test(2, 100, RELAY_ONLY);
        let t = mp.insert_scoped_for_test(3, 100, TEMPLATE_ONLY);
        assert!(mp.get_entry_verbose(&a).is_some(), "acting entry is visible");
        assert!(
            mp.get_entry_verbose(&r).is_none(),
            "relay-quarantined entry is not-found on getmempoolentry"
        );
        assert!(
            mp.get_entry_verbose(&t).is_none(),
            "template-quarantined entry is not-found on getmempoolentry"
        );
    }

    #[test]
    fn get_entry_verbose_descendant_rollup_excludes_quarantined_child() {
        // parent (acting) → child (quarantined by its own rule). The child must
        // not appear in the parent's descendant rollup on this standard surface.
        let mp = Mempool::new(300_000_000, 1_000);
        let parent = spend(outpoint(1), 50_000, 2);
        let parent_txid = parent.compute_txid();
        mp.insert_tx_scoped_for_test(parent, QuarantineScope::acting());
        let child = spend(
            OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            40_000,
            3,
        );
        mp.insert_tx_scoped_for_test(child, RELAY_TEMPLATE);

        let v = mp
            .get_entry_verbose(&parent_txid)
            .expect("parent is acting, so visible");
        assert_eq!(
            v["descendantcount"],
            serde_json::json!(1),
            "self only — the quarantined child is hidden"
        );
        assert_eq!(
            v["spentby"].as_array().unwrap().len(),
            0,
            "the quarantined child is not listed in spentby"
        );
    }

    // --- PR 7b: observability data model (rule attribution, confirmed-anyway) ---

    #[test]
    fn reapply_stamps_quarantine_rule_name() {
        // A re-placement pass must stamp the responsible rule name onto the
        // entry so listquarantine / getquarantineentry can attribute it.
        let op = outpoint(0xd4);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        let tx = spend(op, 99_000, 0x33);
        let txid = mp
            .accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted to acting");

        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        mp.reapply_policy(&cs);

        let entry = mp.get_quarantine_entry(&txid).expect("now quarantined");
        assert_eq!(entry.rule, "catch");
        let list = mp.list_quarantine(Some("catch"), 0, 0);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].txid, txid);
        // A filter on a different rule yields nothing.
        assert!(mp.list_quarantine(Some("other"), 0, 0).is_empty());

        // Deep-review regression: a reload that RENAMES the matching rule but
        // keeps its scope must re-stamp the attributed rule (placement is
        // unchanged, so the byte-accounting move is correctly skipped).
        set_ruleset(&mp, "version 1\nquarantine renamed when tx.version == 2");
        let t = mp.reapply_policy(&cs);
        assert!(t.promoted.is_empty() && t.demoted.is_empty(), "scope unchanged ⇒ no move");
        assert_eq!(
            mp.get_quarantine_entry(&txid).expect("still quarantined").rule,
            "renamed",
            "rename with same scope must update the attributed rule"
        );
        assert!(mp.list_quarantine(Some("catch"), 0, 0).is_empty());
        assert_eq!(mp.list_quarantine(Some("renamed"), 0, 0).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirmed_anyway_counts_quarantined_tx_when_mined() {
        let mp = Mempool::new(300_000_000, 1_000);
        // A held (quarantined) tx, then the same tx appears in a block.
        let tx = spend(outpoint(0xe5), 40_000, 0x44);
        let txid = mp.insert_tx_scoped_for_test(tx.clone(), RELAY_TEMPLATE);
        assert_eq!(mp.quarantine_confirmed_count(), 0);

        let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        block.txdata.push(tx);
        mp.remove_for_block(&block, 101);

        assert!(mp.get(&txid).is_none(), "mined tx left the pool");
        assert_eq!(
            mp.quarantine_confirmed_count(),
            1,
            "a quarantined tx that got mined is counted as confirmed-anyway"
        );

        // An acting tx mined does NOT bump the confirmed-anyway counter.
        let tx2 = spend(outpoint(0xe6), 40_000, 0x45);
        mp.insert_tx_scoped_for_test(tx2.clone(), QuarantineScope::acting());
        let mut block2 = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        block2.txdata.push(tx2);
        mp.remove_for_block(&block2, 102);
        assert_eq!(mp.quarantine_confirmed_count(), 1, "acting confirmation is not counted");
    }

    #[test]
    fn policy_test_rpc_traces_and_places() {
        // policytest dry-run against the loaded ruleset: per-rule trace + the
        // placement the tx would receive. The tx is NOT admitted.
        let op = outpoint(0xab);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch on relay when tx.version == 2");
        let tx = spend(op, 99_000, 0x66);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let v = crate::rpc::policy::policy_test(&cs, &mp, &hex_tx).expect("dry-run ok");
        assert_eq!(v["loaded"], serde_json::json!(true));
        assert_eq!(v["verdict"], serde_json::json!("quarantine"));
        assert_eq!(v["decisive_rule"], serde_json::json!("catch"));
        assert_eq!(v["placement"]["class"], serde_json::json!("quarantine"));
        assert_eq!(v["placement"]["scope"]["relay"], serde_json::json!(true));
        assert_eq!(v["placement"]["scope"]["template"], serde_json::json!(false));
        assert_eq!(v["rules"][0]["name"], serde_json::json!("catch"));
        assert_eq!(v["rules"][0]["decisive"], serde_json::json!(true));
        // Dry-run only: nothing was admitted.
        assert!(mp.get(&tx.compute_txid()).is_none());

        // With no ruleset loaded, policytest reports unloaded.
        mp.clear_policy();
        let v = crate::rpc::policy::policy_test(&cs, &mp, &hex_tx).expect("ok");
        assert_eq!(v["loaded"], serde_json::json!(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_stats_reset_on_swap() {
        // Counters accumulate at the admission eval point and reset on reload.
        let op = outpoint(0xf7);
        let (cs, mp, dir) = make_funded_env(&[(op, coin(100_000))]);
        set_ruleset(&mp, "version 1\nquarantine catch when tx.version == 2");
        let tx = spend(op, 99_000, 0x55);
        mp.accept_transaction(tx, &cs, &NoopVerifier, TxSource::P2p, false)
            .expect("admitted (into quarantine)");

        let s = mp.policy_stats_snapshot();
        assert_eq!(s.evaluations, 1);
        assert_eq!(s.per_rule.get("catch").copied(), Some(1));

        // Swapping the ruleset resets the counters.
        set_ruleset(&mp, "version 1\nquarantine other when tx.version == 2");
        let s = mp.policy_stats_snapshot();
        assert_eq!(s.evaluations, 0);
        assert!(s.per_rule.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
