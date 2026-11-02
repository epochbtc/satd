//! The AssumeUTXO background catch-up connector (#557): a failed connect is
//! retried as the IBD connector retries it, a persistent failure raises
//! `assumeutxo_catchup_stalled` and keeps retrying, progress clears it, and a
//! block that fails validation stops the connector without a retry.

use super::*;
use crate::chain::state::tests::{build_and_connect_chain, make_chain_state, utxo_anchor};
use crate::events::{NodeEvent, NodeEventBody, StatusEvent, StatusKind, StatusState};

/// A chain of `n` blocks with a background attached that re-validates it
/// against the correct anchor, plus the alert surfaces to watch.
struct Rig {
    cs: Arc<ChainState>,
    dir: std::path::PathBuf,
    health: Arc<crate::health::HealthState>,
    rx: tokio::sync::broadcast::Receiver<NodeEvent>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Rig {
    fn new(n: u32) -> Self {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, n);
        let anchor = utxo_anchor(&cs);
        cs.attach_background(dir.join("chainstate_background"), n, cs.tip_hash(), anchor, 64, -1)
            .unwrap();
        let publisher = crate::events::EventPublisher::new(
            crate::events::EdgeIdentity::new([4; 16], None).unwrap(),
            1024,
        );
        let rx = publisher.subscribe();
        let health = Arc::new(crate::health::HealthState::new());
        cs.background_alerts().install_sink(crate::health::AlertSink {
            warnings: cs.warnings().clone(),
            publisher,
            health: Some(health.clone()),
        });
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Rig { cs: Arc::new(cs), dir, health, rx, shutdown_tx, thread: None }
    }

    /// Run the real connector loop on its own thread, waiting 1 ms (rather
    /// than 1 s) between two attempts of one height.
    fn start(&mut self) {
        let cs = self.cs.clone();
        let signal = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));
        let shutdown = self.shutdown_tx.subscribe();
        self.thread = Some(std::thread::spawn(move || {
            PeerManager::bg_catchup_connect_loop_with(
                &cs,
                &signal,
                &shutdown,
                Duration::from_millis(1),
            );
        }));
    }

    fn wait_for(&self, what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn status_events(&mut self) -> Vec<StatusEvent> {
        std::iter::from_fn(|| self.rx.try_recv().ok())
            .filter_map(|e| match e.body {
                NodeEventBody::Status(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    fn stop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A connect failure inside the retry budget is retried, and the background
/// goes on to validate and hand off, with nothing raised.
///
/// Perturbation: restoring the old `Err` arm (log, warn, `return`) leaves the
/// background attached at height 0 and this times out.
#[test]
fn a_transient_connect_failure_is_retried_to_the_handoff() {
    let mut rig = Rig::new(5);
    rig.cs.bg_connect_faults.0.store(CONNECT_RETRY_LIMIT - 1, Ordering::Relaxed);
    rig.start();
    rig.wait_for("the handoff", || !rig.cs.has_background());
    assert_eq!(rig.cs.bg_connect_faults.0.load(Ordering::Relaxed), 0, "every fault was retried");
    assert!(
        rig.status_events().is_empty(),
        "a failure inside the retry budget raises nothing"
    );
    let ids: Vec<_> = rig.cs.warnings().list().into_iter().map(|w| w.id).collect();
    assert!(
        !ids.iter().any(|id| id.contains("assumeutxo")),
        "the retry notice clears on progress: {ids:?}"
    );
}

/// A failure that outlasts the budget raises `assumeutxo_catchup_stalled` on
/// every surface, keeps retrying, and clears once the block connects.
///
/// Perturbation: without the `retry_count >= CONNECT_RETRY_LIMIT` branch's
/// raise nothing is raised and the first assertion fails; without the clear in
/// the `Ok` arm the alert stands after the handoff and the last ones fail.
#[test]
fn a_persistent_connect_failure_raises_the_stall_and_progress_clears_it() {
    let mut rig = Rig::new(5);
    let kind = StatusKind::AssumeutxoCatchupStalled;
    // Two budgets' worth and a bit: raised at 30, refreshed at 60.
    rig.cs.bg_connect_faults.0.store(2 * CONNECT_RETRY_LIMIT + 5, Ordering::Relaxed);
    rig.start();
    rig.wait_for("the handoff", || !rig.cs.has_background());

    let events = rig.status_events();
    let seen: Vec<_> = events.iter().map(|e| (e.kind, e.state)).collect();
    assert_eq!(
        seen,
        vec![(kind, StatusState::Raised), (kind, StatusState::Cleared)],
        "one raise for the episode and one clear on progress"
    );
    assert_eq!(events[0].details.get("reason").map(String::as_str), Some("connect_failing"));
    assert_eq!(events[0].details.get("height").map(String::as_str), Some("1"));
    assert!(!rig.health.is_active(kind));
    assert!(rig.cs.warnings().list().iter().all(|w| w.id != kind.warning_id()));
}

/// A block that fails validation stops the connector at once: one attempt, no
/// retries, and the stall alert says why.
///
/// Perturbation: dropping the `is_verdict_on_block` arm sends the verdict down
/// the retry path, the injected fault is retried, the background validates,
/// and the thread-exit and `invalid_block` assertions fail.
#[test]
fn an_invalid_block_halts_the_connector_without_retrying() {
    let mut rig = Rig::new(5);
    rig.cs.bg_connect_faults.1.store(1, Ordering::Relaxed);
    rig.start();
    let thread = rig.thread.take().unwrap();
    rig.wait_for("the connector to stop", || thread.is_finished());
    thread.join().unwrap();

    let bg = rig.cs.background().expect("still attached: nothing was validated");
    assert_eq!(bg.tip_height(), 0, "it stopped at the failing block");
    assert!(!bg.is_rejected(), "a block verdict does not condemn the snapshot");
    let kind = StatusKind::AssumeutxoCatchupStalled;
    assert!(rig.health.is_active(kind));
    let events = rig.status_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].details.get("reason").map(String::as_str), Some("invalid_block"));
}
