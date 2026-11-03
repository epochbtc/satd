//! The AssumeUTXO background-validation alerts.
//!
//! Background validation can stop advancing, fail its handoff, or prove the
//! loaded snapshot invalid. Each of those is a standing
//! [`StatusKind`](crate::events::StatusKind) and goes out the way every other
//! node-health condition does ([`crate::health::report_external`]): a
//! `getwarnings` entry (which fires `-alertnotify`), a `status` event on the
//! event bus (streaming consumers and the alert webhooks), and the
//! `satd_alert_active{kind=...}` gauge. They used to reach `getwarnings` only.
//!
//! The conditions are detected on the background catch-up thread and inside
//! the handoff, both of which can run before the event bus and the health
//! state exist. A condition raised before [`BackgroundAlerts::install_sink`]
//! is recorded in `getwarnings` at once and goes out on the other two surfaces
//! when the sink is installed, so all three agree once startup is done.

use std::collections::BTreeMap;

use parking_lot::Mutex;

use crate::events::{StatusEvent, StatusKind};
use crate::health::AlertSink;
use crate::warnings::NodeWarnings;

#[derive(Default)]
struct Inner {
    sink: Option<AlertSink>,
    /// The latest raise of each condition that stands now.
    raised: BTreeMap<StatusKind, StatusEvent>,
}

/// Raises and clears the AssumeUTXO background-validation alerts, at most one
/// `raised` and one `cleared` per episode.
#[derive(Default)]
pub struct BackgroundAlerts {
    inner: Mutex<Inner>,
}

impl BackgroundAlerts {
    /// Connect the alerts to the event bus and the health gauges, and send
    /// out anything raised before this point. A second call is ignored.
    pub fn install_sink(&self, sink: AlertSink) {
        let mut inner = self.inner.lock();
        if inner.sink.is_some() {
            return;
        }
        for event in inner.raised.values() {
            sink.report(event.clone());
        }
        inner.sink = Some(sink);
    }

    /// Raise a standing condition.
    ///
    /// The first raise of an episode goes out on every surface. A raise while
    /// the condition already stands only refreshes its `getwarnings` entry
    /// (count, `last_seen`, the latest message and details): a condition that
    /// keeps failing should read as failing now, but subscribers and the
    /// webhooks get one `raised`, not one per retry.
    pub fn raise(&self, warnings: &NodeWarnings, event: StatusEvent) {
        let mut inner = self.inner.lock();
        let first = inner.raised.insert(event.kind, event.clone()).is_none();
        match (&inner.sink, first) {
            (Some(sink), true) => sink.report(event),
            _ => crate::health::mirror_into_warnings(warnings, &event),
        }
    }

    /// Clear a standing condition, if it stands.
    pub fn clear(&self, warnings: &NodeWarnings, kind: StatusKind, message: impl Into<String>) {
        let mut inner = self.inner.lock();
        if inner.raised.remove(&kind).is_none() {
            return;
        }
        let event = StatusEvent::cleared(kind, message);
        match &inner.sink {
            Some(sink) => sink.report(event),
            None => crate::health::mirror_into_warnings(warnings, &event),
        }
    }

    /// Whether `kind` stands now.
    pub fn is_raised(&self, kind: StatusKind) -> bool {
        self.inner.lock().raised.contains_key(&kind)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::events::{EdgeIdentity, EventPublisher, NodeEventBody, StatusState};
    use crate::health::HealthState;

    struct Rig {
        warnings: Arc<NodeWarnings>,
        publisher: Arc<EventPublisher>,
        health: Arc<HealthState>,
    }

    impl Rig {
        fn new() -> Self {
            Self {
                warnings: Arc::new(NodeWarnings::new()),
                publisher: EventPublisher::new(EdgeIdentity::new([2; 16], None).unwrap(), 64),
                health: Arc::new(HealthState::new()),
            }
        }

        fn sink(&self) -> AlertSink {
            AlertSink {
                warnings: self.warnings.clone(),
                publisher: self.publisher.clone(),
                health: Some(self.health.clone()),
            }
        }

        fn warning(&self, kind: StatusKind) -> Option<crate::warnings::Warning> {
            self.warnings.list().into_iter().find(|w| w.id == kind.warning_id())
        }
    }

    fn states(rx: &mut tokio::sync::broadcast::Receiver<crate::events::NodeEvent>) -> Vec<StatusState> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|e| match e.body {
                NodeEventBody::Status(s) => Some(s.state),
                _ => None,
            })
            .collect()
    }

    /// One condition reaches all three surfaces, once per episode, and a
    /// repeated raise keeps the `getwarnings` entry current.
    ///
    /// Perturbation: making `raise` call `sink.report` on every raise (not only
    /// the first) fails the "one raised" count; dropping the refresh branch
    /// fails the `count == 3` check.
    #[test]
    fn a_condition_reaches_every_surface_once_per_episode() {
        let rig = Rig::new();
        let alerts = BackgroundAlerts::default();
        alerts.install_sink(rig.sink());
        let mut rx = rig.publisher.subscribe();
        let kind = StatusKind::AssumeutxoCatchupStalled;

        for n in 1..=3 {
            alerts.raise(&rig.warnings, StatusEvent::raised(kind, format!("attempt {n}")));
        }
        assert!(rig.health.is_active(kind), "satd_alert_active follows the raise");
        let w = rig.warning(kind).expect("a standing getwarnings entry");
        assert_eq!(w.count, 3, "each raise refreshes the entry");
        assert_eq!(w.message, "attempt 3", "the entry carries the latest message");
        assert_eq!(states(&mut rx), vec![StatusState::Raised], "one raised event");

        alerts.clear(&rig.warnings, kind, "progress");
        alerts.clear(&rig.warnings, kind, "progress again");
        assert!(!rig.health.is_active(kind));
        assert!(rig.warning(kind).is_none());
        assert_eq!(states(&mut rx), vec![StatusState::Cleared], "one cleared event");
        assert!(!alerts.is_raised(kind));
    }

    /// A condition raised before the event bus exists shows in `getwarnings`
    /// at once and reaches the stream and the gauge when the sink arrives.
    ///
    /// Perturbation: removing the replay loop in `install_sink` leaves the
    /// gauge at 0 and no `raised` event, and this fails.
    #[test]
    fn a_raise_before_the_sink_is_sent_out_when_it_is_installed() {
        let rig = Rig::new();
        let alerts = BackgroundAlerts::default();
        let kind = StatusKind::AssumeutxoValidationFailed;
        alerts.raise(&rig.warnings, StatusEvent::raised(kind, "hash mismatch"));
        assert!(rig.warning(kind).is_some(), "getwarnings does not wait for the sink");

        let mut rx = rig.publisher.subscribe();
        alerts.install_sink(rig.sink());
        assert!(rig.health.is_active(kind), "the gauge catches up on install");
        assert_eq!(states(&mut rx), vec![StatusState::Raised]);

        // A condition raised and cleared before the sink leaves nothing behind.
        let other = StatusKind::AssumeutxoHandoffFailing;
        let early = BackgroundAlerts::default();
        early.raise(&rig.warnings, StatusEvent::raised(other, "flush failed"));
        early.clear(&rig.warnings, other, "flushed");
        assert!(rig.warning(other).is_none());
        early.install_sink(rig.sink());
        assert!(!rig.health.is_active(other));
        assert!(states(&mut rx).is_empty());
    }
}
