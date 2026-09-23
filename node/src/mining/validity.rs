//! Block-template validity checks.
//!
//! Bitcoin Core runs `TestBlockValidity` on every template `CreateNewBlock`
//! builds (`src/node/miner.cpp`), so a template that would make an invalid
//! block fails where it is built, not when a miner has already spent its luck
//! on it. satd does the same in two tiers, because a full check of a
//! mainnet-sized template runs its scripts again — satd has no script
//! execution cache — and costs seconds of CPU:
//!
//! - [`Check::Structural`] runs every rule block connection applies except
//!   script execution: structure, weight, sigops, BIP 34, finality and
//!   sequence locks, coinbase value, the witness commitment, missing or
//!   double-spent inputs. It is synchronous: `getblocktemplate` and the
//!   `generate` RPCs refuse a template that fails it, and the Stratum server
//!   issues a coinbase-only job instead.
//! - [`Check::Full`] adds the scripts, through the node's own verifier. The
//!   Stratum server runs it in the background ([`FullChecker`]) and never
//!   waits on it; a failure replaces every job with a coinbase-only one.
//!
//! A failure of either is a node bug — the mempool admitted a transaction
//! consensus would refuse — so it is logged at error with the reject reason
//! and the offending transaction, counted, and raised as the
//! `template_invalid` alert. The transaction is not evicted: Core does not
//! either, and a bug that let it in should stay visible rather than be
//! quietly cleaned up after.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

use bitcoin::{Block, ScriptBuf, Transaction, Txid};

use crate::chain::state::{ChainState, TemplateVerdict};
use crate::mining::template::BlockTemplate;

/// Which tier of the check ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Every consensus rule except script execution.
    Structural,
    /// Every consensus rule, scripts through the node's verifier.
    Full,
}

impl Check {
    pub const ALL: [Check; 2] = [Check::Structural, Check::Full];

    pub const fn as_str(self) -> &'static str {
        match self {
            Check::Structural => "structural",
            Check::Full => "full",
        }
    }

    const fn index(self) -> usize {
        match self {
            Check::Structural => 0,
            Check::Full => 1,
        }
    }
}

/// Where the template being checked was headed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOrigin {
    GetBlockTemplate,
    Generate,
    Stratum,
}

impl CheckOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            CheckOrigin::GetBlockTemplate => "getblocktemplate",
            CheckOrigin::Generate => "generate",
            CheckOrigin::Stratum => "stratum",
        }
    }
}

/// A check's verdict, and the transaction that made the block invalid when
/// one did and it could be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub verdict: TemplateVerdict,
    pub height: u32,
    pub offending_txid: Option<Txid>,
}

/// The `result` label of `satd_template_checks_total`.
const RESULTS: [&str; 3] = ["valid", "invalid", "superseded"];

/// The coinbase a template is checked with: anything-can-spend, which is a
/// standard output of no sigops and of the smallest size, so the coinbase is
/// never the part of the block that fails. The Stratum server's own coinbase
/// is tested against the template's reserves separately.
fn check_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

/// Check the block `template` describes, and on failure find the transaction
/// responsible.
pub fn check_template(chain_state: &ChainState, template: &BlockTemplate, check: Check) -> CheckOutcome {
    let txs: Vec<Transaction> = template.transactions.iter().map(|t| t.tx.clone()).collect();
    let block = crate::mining::miner::unsolved_block(
        chain_state,
        template,
        &check_script(),
        template.coinbase_value,
        txs,
    );
    check_block(chain_state, &block, template.height, check)
}

/// Check an assembled (unsolved) block at `height` on the current tip, and on
/// failure find the transaction responsible.
pub fn check_block(chain_state: &ChainState, block: &Block, height: u32, check: Check) -> CheckOutcome {
    let verdict = chain_state.check_template_block(block, check == Check::Full);
    let offending_txid = match verdict {
        TemplateVerdict::Invalid(_) => offending_transaction(chain_state, block, height, check),
        _ => None,
    };
    CheckOutcome { verdict, height, offending_txid }
}

/// The first transaction whose inclusion makes the block invalid, by bisection
/// over prefixes of it.
///
/// Every reason a transaction makes a block invalid — a missing or spent
/// input, an overspend, a failed script, an unmet lock, the sigops it adds to
/// the total — also holds for any longer prefix that includes it, and a
/// template orders parents before children, so the set of invalid prefixes
/// is upward closed and bisection finds its least member. A prefix's coinbase
/// claims the subsidy alone, which is always within what the block may claim.
///
/// `None` when every prefix is valid (the fault is in the coinbase or the fee
/// total, not a transaction), or when the chain moved while looking.
fn offending_transaction(chain_state: &ChainState, block: &Block, height: u32, check: Check) -> Option<Txid> {
    let txs = &block.txdata[1..];
    let subsidy = crate::chain::connect::block_subsidy(chain_state.network, height);
    let shell = BlockTemplate {
        version: block.header.version.to_consensus(),
        prev_hash: block.header.prev_blockhash,
        height,
        bits: block.header.bits,
        cur_time: block.header.time,
        min_time: 0,
        transactions: Vec::new(),
        coinbase_value: subsidy,
    };
    let invalid = |n: usize| -> Option<bool> {
        let prefix = crate::mining::miner::unsolved_block(
            chain_state,
            &shell,
            &check_script(),
            subsidy,
            txs[..n].to_vec(),
        );
        match chain_state.check_template_block(&prefix, check == Check::Full) {
            TemplateVerdict::Valid => Some(false),
            TemplateVerdict::Invalid(_) => Some(true),
            TemplateVerdict::Superseded => None,
        }
    };
    if !invalid(txs.len())? {
        return None;
    }
    // Invariant: the prefix of `lo` transactions is valid, of `hi` invalid.
    let (mut lo, mut hi) = (0usize, txs.len());
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if invalid(mid)? {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Some(txs[hi - 1].compute_txid())
}

/// Where the `template_invalid` alert goes. Installed at startup, once the
/// event publisher and the health state exist; until then, and in tests that
/// install none, a failure is still logged and counted.
pub struct AlertSink {
    pub warnings: Arc<crate::warnings::NodeWarnings>,
    pub publisher: Arc<crate::events::EventPublisher>,
    pub health: Option<Arc<crate::health::HealthState>>,
}

/// The node's record of template checks: counts for the metrics, and whether
/// the `template_invalid` alert stands.
#[derive(Default)]
pub struct TemplateValidity {
    /// `[check][result]`, results in [`RESULTS`] order.
    counts: [[AtomicU64; 3]; 2],
    /// Whether the last conclusive check of each tier failed.
    failing: [AtomicBool; 2],
    /// Whether the alert has been raised and not yet cleared.
    raised: AtomicBool,
    sink: OnceLock<AlertSink>,
    checker: OnceLock<Arc<FullChecker>>,
    /// The tip the last `getblocktemplate` full check was queued for.
    gbt_full_tip: parking_lot::Mutex<Option<bitcoin::BlockHash>>,
}

impl TemplateValidity {
    pub fn install_alert_sink(&self, sink: AlertSink) {
        let _ = self.sink.set(sink);
    }

    pub fn install_full_checker(&self, checker: Arc<FullChecker>) {
        let _ = self.checker.set(checker);
    }

    /// The background full checker, once the node has started one.
    pub fn full_checker(&self) -> Option<&Arc<FullChecker>> {
        self.checker.get()
    }

    /// Queue a `getblocktemplate` template for its full check, once per tip:
    /// a pool polling every few seconds must not buy a full script check
    /// each time.
    pub fn queue_full_check_for_gbt(&self, template: &BlockTemplate) {
        let Some(checker) = self.checker.get() else { return };
        let mut last = self.gbt_full_tip.lock();
        if *last == Some(template.prev_hash) {
            return;
        }
        *last = Some(template.prev_hash);
        checker.submit(0, Arc::new(template.clone()), CheckOrigin::GetBlockTemplate);
    }

    /// How many checks of a tier ended with `result` (`valid`, `invalid` or
    /// `superseded`).
    pub fn count(&self, check: Check, result: &str) -> u64 {
        RESULTS
            .iter()
            .position(|r| *r == result)
            .map_or(0, |i| self.counts[check.index()][i].load(Relaxed))
    }

    /// Whether the `template_invalid` alert stands.
    pub fn is_failing(&self) -> bool {
        self.raised.load(Relaxed)
    }

    /// The `satd_template_checks_total` metric family.
    pub fn render_metrics(&self, out: &mut String) {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "# HELP satd_template_checks_total Block-template validity checks, by tier and result. \
             An invalid result is a node bug: the template would have made a block the node rejects."
        );
        let _ = writeln!(out, "# TYPE satd_template_checks_total counter");
        for check in Check::ALL {
            for (i, result) in RESULTS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "satd_template_checks_total{{check=\"{}\",result=\"{}\"}} {}",
                    check.as_str(),
                    result,
                    self.counts[check.index()][i].load(Relaxed)
                );
            }
        }
    }

    /// Record a check's outcome: count it, and on a failure log it and raise
    /// the alert; on a pass that leaves no tier failing, clear it.
    ///
    /// A full pass also clears a structural failure, since it covers every
    /// structural rule. A structural pass does not clear a full failure: the
    /// scripts that failed have not been run again.
    pub fn record(&self, check: Check, outcome: &CheckOutcome, origin: CheckOrigin) {
        let result = match &outcome.verdict {
            TemplateVerdict::Valid => 0,
            TemplateVerdict::Invalid(_) => 1,
            TemplateVerdict::Superseded => 2,
        };
        self.counts[check.index()][result].fetch_add(1, Relaxed);
        match &outcome.verdict {
            TemplateVerdict::Superseded => {}
            TemplateVerdict::Invalid(reason) => {
                self.failing[check.index()].store(true, Relaxed);
                let txid = outcome.offending_txid.map(|t| t.to_string());
                tracing::error!(
                    target: "mining::template",
                    check = check.as_str(),
                    origin = origin.as_str(),
                    height = outcome.height,
                    reason = %reason,
                    txid = txid.as_deref().unwrap_or("unknown"),
                    "block template failed its validity check; a block found on it would be rejected. \
                     This is a bug: please report it"
                );
                if !self.raised.swap(true, Relaxed) {
                    let mut event = crate::events::StatusEvent::raised(
                        crate::events::StatusKind::TemplateInvalid,
                        format!("block template at height {} failed its {} check: {reason}", outcome.height, check.as_str()),
                    )
                    .with_detail("check", check.as_str())
                    .with_detail("origin", origin.as_str())
                    .with_detail("reason", reason.clone())
                    .with_detail("height", outcome.height.to_string());
                    if let Some(txid) = txid {
                        event = event.with_detail("txid", txid);
                    }
                    self.emit(event);
                }
            }
            TemplateVerdict::Valid => {
                self.failing[check.index()].store(false, Relaxed);
                if check == Check::Full {
                    self.failing[Check::Structural.index()].store(false, Relaxed);
                }
                let still_failing = self.failing.iter().any(|f| f.load(Relaxed));
                if !still_failing && self.raised.swap(false, Relaxed) {
                    self.emit(crate::events::StatusEvent::cleared(
                        crate::events::StatusKind::TemplateInvalid,
                        format!("block template at height {} passed its {} check", outcome.height, check.as_str()),
                    ));
                }
            }
        }
    }

    fn emit(&self, event: crate::events::StatusEvent) {
        if let Some(sink) = self.sink.get() {
            crate::health::report_external(sink.health.as_deref(), &sink.warnings, &sink.publisher, event);
        }
    }
}

/// Runs [`Check::Full`] off the path that issues work.
///
/// One template waits at a time: a newer submission replaces an older one
/// that has not started, so a check never runs on a template already
/// superseded. The verdict is published on a watch channel for whoever acts on
/// it (the Stratum server).
pub struct FullChecker {
    pending: tokio::sync::watch::Sender<Option<FullRequest>>,
    verdicts: tokio::sync::watch::Sender<Option<FullVerdict>>,
}

/// A template waiting for its full check.
#[derive(Clone)]
struct FullRequest {
    /// The caller's name for the template (the Stratum work id).
    id: u64,
    template: Arc<BlockTemplate>,
    origin: CheckOrigin,
}

/// The outcome of a background full check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerdict {
    pub id: u64,
    pub prev_hash: bitcoin::BlockHash,
    pub verdict: TemplateVerdict,
}

impl FullChecker {
    /// Spawn the checker on the calling runtime. The check itself runs on the
    /// blocking pool.
    pub fn spawn(chain_state: Arc<ChainState>, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Arc<Self> {
        let (pending, mut rx) = tokio::sync::watch::channel(None::<FullRequest>);
        let (verdicts, _) = tokio::sync::watch::channel(None);
        let checker = Arc::new(Self { pending, verdicts });
        let task = checker.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    changed = rx.changed() => if changed.is_err() { return },
                }
                let Some(request) = rx.borrow_and_update().clone() else { continue };
                let chain = chain_state.clone();
                let template = request.template.clone();
                let done = tokio::task::spawn_blocking(move || {
                    let outcome = check_template(&chain, &template, Check::Full);
                    chain.template_validity().record(Check::Full, &outcome, request.origin);
                    outcome
                })
                .await;
                match done {
                    Ok(outcome) => {
                        task.verdicts.send_replace(Some(FullVerdict {
                            id: request.id,
                            prev_hash: request.template.prev_hash,
                            verdict: outcome.verdict,
                        }));
                    }
                    Err(e) => tracing::error!(target: "mining::template", error = %e, "full template check panicked"),
                }
            }
        });
        checker
    }

    /// Queue `template` for a full check, replacing any not yet started.
    pub fn submit(&self, id: u64, template: Arc<BlockTemplate>, origin: CheckOrigin) {
        self.pending.send_replace(Some(FullRequest { id, template, origin }));
    }

    /// Every verdict, the latest first.
    pub fn verdicts(&self) -> tokio::sync::watch::Receiver<Option<FullVerdict>> {
        self.verdicts.subscribe()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mempool::pool::{Mempool, QuarantineScope};
    use crate::mining::template::tests::{confirmed_prev, make_funded_template_env_with, tx_spending};
    use crate::validation::script::{ConsensusVerifier, RustVerifier, ScriptVerifier, ShadowVerifier};
    use bitcoin::Network;

    /// A confirmed 100,000-sat coin locked by `script`.
    fn coin(script: &[u8]) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount: 100_000,
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        }
    }

    /// Coins the fixtures spend: `0xA1`/`0xA2` are anyone-can-spend
    /// (`OP_TRUE`), `0xB1` is locked by `OP_FALSE`, so no spend of it can
    /// pass its script.
    pub(crate) fn funded(verifier: Box<dyn ScriptVerifier>) -> (ChainState, Mempool, std::path::PathBuf) {
        make_funded_template_env_with(
            &[
                (confirmed_prev(0xA1), coin(&[0x51])),
                (confirmed_prev(0xA2), coin(&[0x51])),
                (confirmed_prev(0xB1), coin(&[0x00])),
            ],
            verifier,
        )
    }

    /// Admit `tx` to the mempool bypassing admission, as a node bug would.
    pub(crate) fn admit(mp: &Mempool, tx: Transaction, fee: u64) -> Txid {
        mp.insert_tx_weighted_for_test(tx, fee, 400, QuarantineScope::acting())
    }

    /// A spend of `prev` paying `value` out of its 100,000 sats.
    pub(crate) fn spend(prev: u8, value: u64, tag: u8) -> Transaction {
        tx_spending(confirmed_prev(prev), value, tag, 0xffff_ffff, 0)
    }

    fn rust() -> Box<dyn ScriptVerifier> {
        Box::new(RustVerifier::new(Network::Regtest))
    }

    fn template(cs: &ChainState, mp: &Mempool) -> BlockTemplate {
        crate::mining::template::create_template(cs, mp)
    }

    #[test]
    fn a_valid_template_passes_both_checks() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA1, 90_000, 1), 10_000);
        let t = template(&cs, &mp);
        assert_eq!(t.transactions.len(), 1);
        for check in Check::ALL {
            let outcome = check_template(&cs, &t, check);
            assert_eq!(outcome.verdict, TemplateVerdict::Valid, "{check:?}");
            assert_eq!(outcome.offending_txid, None);
            cs.template_validity().record(check, &outcome, CheckOrigin::Stratum);
        }
        assert!(!cs.template_validity().is_failing());
        assert_eq!(cs.template_validity().count(Check::Full, "valid"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An overspend is caught without running a script, and bisection names it
    /// even with a valid transaction ahead of it in the template.
    #[test]
    fn an_overspending_transaction_fails_the_structural_check() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA1, 50_000, 1), 50_000);
        let bad = admit(&mp, spend(0xA2, 200_000, 2), 1_000);
        let t = template(&cs, &mp);
        assert_eq!(t.transactions.len(), 2);
        let outcome = check_template(&cs, &t, Check::Structural);
        assert_eq!(outcome.verdict, TemplateVerdict::Invalid("bad-txns-in-belowout".into()));
        assert_eq!(outcome.offending_txid, Some(bad));
        assert_eq!(outcome.height, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The structural check skips scripts and nothing else; the full check
    /// runs them through the node's verifier.
    #[test]
    fn a_script_failure_passes_the_structural_check_and_fails_the_full_one() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA1, 50_000, 1), 50_000);
        let bad = admit(&mp, spend(0xB1, 90_000, 2), 10_000);
        let t = template(&cs, &mp);
        assert_eq!(check_template(&cs, &t, Check::Structural).verdict, TemplateVerdict::Valid);
        let full = check_template(&cs, &t, Check::Full);
        let TemplateVerdict::Invalid(reason) = &full.verdict else { panic!("{full:?}") };
        assert!(reason.starts_with("block-script-verify-flag-failed"), "{reason}");
        assert_eq!(full.offending_txid, Some(bad));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Under `-consensus=cpp-shadow` the full check goes through the shadow
    /// verifier the node connects blocks with, and still judges scripts.
    #[test]
    fn the_full_check_uses_a_cpp_shadow_verifier() {
        let shadow = || -> Box<dyn ScriptVerifier> {
            Box::new(ShadowVerifier::new(rust(), Box::new(ConsensusVerifier::new(Network::Regtest)), "rust", "cpp", 64, 1))
        };
        let (cs, mp, dir) = funded(shadow());
        admit(&mp, spend(0xA1, 90_000, 1), 10_000);
        assert_eq!(check_template(&cs, &template(&cs, &mp), Check::Full).verdict, TemplateVerdict::Valid);
        admit(&mp, spend(0xB1, 90_000, 2), 10_000);
        assert!(matches!(check_template(&cs, &template(&cs, &mp), Check::Full).verdict, TemplateVerdict::Invalid(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failure raises `template_invalid` once, however often it recurs; a
    /// structural pass leaves a full failure standing; a full pass clears it.
    #[test]
    fn a_failure_raises_the_alert_once_and_a_full_pass_clears_it() {
        let validity = TemplateValidity::default();
        let warnings = Arc::new(crate::warnings::NodeWarnings::new());
        let publisher = crate::events::EventPublisher::new(
            crate::events::EdgeIdentity::new([1; 16], None).unwrap(),
            64,
        );
        let mut rx = publisher.subscribe();
        let health = Arc::new(crate::health::HealthState::new());
        validity.install_alert_sink(AlertSink {
            warnings: warnings.clone(),
            publisher: publisher.clone(),
            health: Some(health.clone()),
        });
        let outcome = |verdict| CheckOutcome { verdict, height: 7, offending_txid: None };
        let invalid = outcome(TemplateVerdict::Invalid("bad-txns-in-belowout".into()));
        let kind = crate::events::StatusKind::TemplateInvalid;

        validity.record(Check::Full, &invalid, CheckOrigin::Stratum);
        validity.record(Check::Full, &invalid, CheckOrigin::Stratum);
        assert!(validity.is_failing());
        assert!(health.is_active(kind), "satd_alert_active follows it");
        assert!(warnings.list().iter().any(|w| w.id == kind.warning_id()), "a standing warning");
        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(events.len(), 1, "raised once, not per failure: {events:?}");

        validity.record(Check::Structural, &outcome(TemplateVerdict::Valid), CheckOrigin::Stratum);
        assert!(validity.is_failing(), "the scripts that failed have not been run again");
        validity.record(Check::Full, &outcome(TemplateVerdict::Superseded), CheckOrigin::Stratum);
        assert!(validity.is_failing(), "a superseded check proves nothing");
        validity.record(Check::Full, &outcome(TemplateVerdict::Valid), CheckOrigin::Stratum);
        assert!(!validity.is_failing());
        assert!(!health.is_active(kind));
        assert!(warnings.list().iter().all(|w| w.id != kind.warning_id()));
        assert_eq!(std::iter::from_fn(|| rx.try_recv().ok()).count(), 1, "one clear");
        assert_eq!(validity.count(Check::Full, "invalid"), 2);
        assert_eq!(validity.count(Check::Full, "superseded"), 1);

        let mut metrics = String::new();
        validity.render_metrics(&mut metrics);
        assert!(metrics.contains("satd_template_checks_total{check=\"full\",result=\"invalid\"} 2"), "{metrics}");
    }

    /// `getblocktemplate` refuses a template that fails, with Core's message.
    #[test]
    fn getblocktemplate_refuses_an_invalid_template() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA2, 200_000, 2), 1_000);
        let err = crate::rpc::mining::get_block_template(&cs, &mp).unwrap_err();
        assert_eq!(err, (-1, "TestBlockValidity failed: bad-txns-in-belowout".to_string()));
        assert!(cs.template_validity().is_failing());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// So do the `generate` RPCs, before any work goes into the block.
    #[test]
    fn generate_refuses_an_invalid_template() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA2, 200_000, 2), 1_000);
        let mut budget = 1_000_000;
        let err = crate::mining::miner::build_block_to_script_within(&cs, &mp, check_script(), None, &mut budget)
            .unwrap_err();
        assert_eq!(err.to_string(), "TestBlockValidity failed: bad-txns-in-belowout");
        assert_eq!(budget, 1_000_000, "refused before solving");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `getblocktemplate` queues its template for a full check once per tip,
    /// not per poll.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn getblocktemplate_queues_one_full_check_per_tip() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xA1, 90_000, 1), 10_000);
        let cs = Arc::new(cs);
        let (_stop, shutdown) = tokio::sync::watch::channel(false);
        let checker = FullChecker::spawn(cs.clone(), shutdown);
        cs.template_validity().install_full_checker(checker.clone());
        let mut verdicts = checker.verdicts();
        for _ in 0..3 {
            crate::rpc::mining::get_block_template(&cs, &mp).unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), verdicts.changed()).await.unwrap().unwrap();
        assert_eq!(verdicts.borrow().as_ref().map(|v| v.verdict.clone()), Some(TemplateVerdict::Valid));
        // Give a second queued check time to have run, were there one.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(cs.template_validity().count(Check::Full, "valid"), 1, "three polls, one tip, one full check");
        assert_eq!(cs.template_validity().count(Check::Structural, "valid"), 3, "every poll is checked structurally");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The background checker runs the full check and publishes the verdict.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_background_checker_publishes_a_full_verdict() {
        let (cs, mp, dir) = funded(rust());
        admit(&mp, spend(0xB1, 90_000, 2), 10_000);
        let cs = Arc::new(cs);
        let (_stop, shutdown) = tokio::sync::watch::channel(false);
        let checker = FullChecker::spawn(cs.clone(), shutdown);
        let mut verdicts = checker.verdicts();
        let t = Arc::new(template(&cs, &mp));
        checker.submit(9, t.clone(), CheckOrigin::Stratum);
        tokio::time::timeout(std::time::Duration::from_secs(20), verdicts.changed()).await.unwrap().unwrap();
        let verdict = verdicts.borrow().clone().unwrap();
        assert_eq!(verdict.id, 9);
        assert_eq!(verdict.prev_hash, t.prev_hash);
        assert!(matches!(verdict.verdict, TemplateVerdict::Invalid(_)));
        assert_eq!(cs.template_validity().count(Check::Full, "invalid"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
