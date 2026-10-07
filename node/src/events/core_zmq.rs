//! Shared state of the Bitcoin Core-compatible ZMQ publisher (`-zmqpub*`).
//!
//! The publisher itself is an [`EventSink`](super::EventSink) in the
//! `satd-events` crate. What lives here is what the rest of the node needs to
//! see of it: the topic names, the notifier table `getzmqnotifications`
//! reports, and the counters `/metrics` exports. Keeping them in `node` lets
//! the RPC server and the metrics endpoint read them without depending on the
//! transport crate.

use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};

/// Core's `CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM`: the outbound high-water
/// mark a notifier gets when `-zmqpub<topic>hwm` is not set.
pub const DEFAULT_ZMQ_SNDHWM: i64 = 1000;

/// One of Core's five ZMQ publish topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreZmqTopic {
    HashBlock,
    HashTx,
    RawBlock,
    RawTx,
    Sequence,
}

impl CoreZmqTopic {
    /// Every topic, in Core's notifier order. Core builds its notifiers by
    /// walking a `std::map` keyed on the notifier type, so they come out
    /// alphabetically, and within a topic in option order
    /// (`CZMQNotificationInterface::Create`).
    pub const ALL: [CoreZmqTopic; 5] = [
        CoreZmqTopic::HashBlock,
        CoreZmqTopic::HashTx,
        CoreZmqTopic::RawBlock,
        CoreZmqTopic::RawTx,
        CoreZmqTopic::Sequence,
    ];

    /// The topic string on the wire: the first frame of every message.
    pub fn name(self) -> &'static str {
        match self {
            CoreZmqTopic::HashBlock => "hashblock",
            CoreZmqTopic::HashTx => "hashtx",
            CoreZmqTopic::RawBlock => "rawblock",
            CoreZmqTopic::RawTx => "rawtx",
            CoreZmqTopic::Sequence => "sequence",
        }
    }

    /// The address option, without its dash: `zmqpubhashblock`.
    pub fn option(self) -> &'static str {
        match self {
            CoreZmqTopic::HashBlock => "zmqpubhashblock",
            CoreZmqTopic::HashTx => "zmqpubhashtx",
            CoreZmqTopic::RawBlock => "zmqpubrawblock",
            CoreZmqTopic::RawTx => "zmqpubrawtx",
            CoreZmqTopic::Sequence => "zmqpubsequence",
        }
    }

    /// The high-water-mark option, without its dash: `zmqpubhashblockhwm`.
    pub fn hwm_option(self) -> &'static str {
        match self {
            CoreZmqTopic::HashBlock => "zmqpubhashblockhwm",
            CoreZmqTopic::HashTx => "zmqpubhashtxhwm",
            CoreZmqTopic::RawBlock => "zmqpubrawblockhwm",
            CoreZmqTopic::RawTx => "zmqpubrawtxhwm",
            CoreZmqTopic::Sequence => "zmqpubsequencehwm",
        }
    }

    /// The notifier type `getzmqnotifications` reports: `pubhashblock`.
    pub fn notifier_type(self) -> &'static str {
        match self {
            CoreZmqTopic::HashBlock => "pubhashblock",
            CoreZmqTopic::HashTx => "pubhashtx",
            CoreZmqTopic::RawBlock => "pubrawblock",
            CoreZmqTopic::RawTx => "pubrawtx",
            CoreZmqTopic::Sequence => "pubsequence",
        }
    }

    /// Position in [`Self::ALL`], for per-topic arrays.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// One configured notifier: a topic published on an address. Core creates
/// one per `-zmqpub<topic>=<address>` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreZmqNotifier {
    pub topic: CoreZmqTopic,
    /// The address as configured, with a `unix:` prefix rewritten to libzmq's
    /// `ipc://`, which is also the form Core stores and reports.
    pub address: String,
    /// The outbound high-water mark: the number of messages a subscriber may
    /// have queued before further ones are dropped for it. 0 is unlimited.
    pub hwm: i64,
}

/// What a publishing socket can report about itself, for `/metrics`.
/// Implemented by the transport.
pub trait CoreZmqSocketStats: Send + Sync {
    /// Subscribers connected now.
    fn subscriber_count(&self) -> usize;
    /// Messages dropped for a subscriber whose queue was full, since bind.
    fn dropped_total(&self) -> u64;
}

/// The running publisher, as the RPC server and the metrics endpoint see it.
/// Registered only once every socket is bound; a node with no `-zmqpub*`
/// option, or whose bind failed, has none.
pub struct CoreZmqStatus {
    notifiers: Vec<CoreZmqNotifier>,
    /// Weak, so that the sockets close when the publisher stops even though
    /// the RPC server still holds this.
    sockets: Vec<Weak<dyn CoreZmqSocketStats>>,
    messages: [AtomicU64; 5],
    events_lagged: AtomicU64,
    rawtx_unavailable: AtomicU64,
    block_read_failures: AtomicU64,
}

impl CoreZmqStatus {
    pub fn new(notifiers: Vec<CoreZmqNotifier>, sockets: Vec<Weak<dyn CoreZmqSocketStats>>) -> Self {
        Self {
            notifiers,
            sockets,
            messages: Default::default(),
            events_lagged: AtomicU64::new(0),
            rawtx_unavailable: AtomicU64::new(0),
            block_read_failures: AtomicU64::new(0),
        }
    }

    /// The notifiers, in Core's notifier order.
    pub fn notifiers(&self) -> &[CoreZmqNotifier] {
        &self.notifiers
    }

    /// `getzmqnotifications`' answer: one object per notifier, in notifier
    /// order.
    pub fn notifications_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.notifiers
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "type": n.topic.notifier_type(),
                        "address": n.address,
                        "hwm": n.hwm,
                    })
                })
                .collect(),
        )
    }

    /// Count one published message on `topic`.
    pub fn record_message(&self, topic: CoreZmqTopic) {
        self.messages[topic.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Count a lag at the publisher's own receiver: events the bus dropped
    /// before the publisher could read them.
    pub fn record_events_lagged(&self, n: u64) {
        self.events_lagged.fetch_add(n, Ordering::Relaxed);
    }

    /// Count an admitted transaction whose `rawtx` could not be published
    /// because neither the event nor the mempool still had it.
    pub fn record_rawtx_unavailable(&self) {
        self.rawtx_unavailable.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a block whose messages were skipped because it could not be
    /// read from disk.
    pub fn record_block_read_failure(&self) {
        self.block_read_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn messages_total(&self, topic: CoreZmqTopic) -> u64 {
        self.messages[topic.index()].load(Ordering::Relaxed)
    }

    pub fn events_lagged_total(&self) -> u64 {
        self.events_lagged.load(Ordering::Relaxed)
    }

    pub fn rawtx_unavailable_total(&self) -> u64 {
        self.rawtx_unavailable.load(Ordering::Relaxed)
    }

    pub fn block_read_failures_total(&self) -> u64 {
        self.block_read_failures.load(Ordering::Relaxed)
    }

    /// Subscribers connected now, across every socket.
    pub fn subscribers(&self) -> u64 {
        self.sockets
            .iter()
            .filter_map(Weak::upgrade)
            .map(|s| s.subscriber_count() as u64)
            .sum()
    }

    /// Messages dropped for full subscriber queues, across every socket.
    pub fn subscriber_drops_total(&self) -> u64 {
        self.sockets.iter().filter_map(Weak::upgrade).map(|s| s.dropped_total()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core's notifier types and option names, which `getzmqnotifications`,
    /// `help` and the config parser all spell out.
    #[test]
    fn topic_names_are_cores() {
        let names: Vec<_> = CoreZmqTopic::ALL
            .iter()
            .map(|t| (t.name(), t.option(), t.hwm_option(), t.notifier_type()))
            .collect();
        assert_eq!(
            names,
            [
                ("hashblock", "zmqpubhashblock", "zmqpubhashblockhwm", "pubhashblock"),
                ("hashtx", "zmqpubhashtx", "zmqpubhashtxhwm", "pubhashtx"),
                ("rawblock", "zmqpubrawblock", "zmqpubrawblockhwm", "pubrawblock"),
                ("rawtx", "zmqpubrawtx", "zmqpubrawtxhwm", "pubrawtx"),
                ("sequence", "zmqpubsequence", "zmqpubsequencehwm", "pubsequence"),
            ]
        );
        for (i, t) in CoreZmqTopic::ALL.iter().enumerate() {
            assert_eq!(t.index(), i);
        }
    }

    #[test]
    fn notifications_json_is_cores_shape() {
        let status = CoreZmqStatus::new(
            vec![
                CoreZmqNotifier {
                    topic: CoreZmqTopic::HashBlock,
                    address: "tcp://127.0.0.1:28332".into(),
                    hwm: 1000,
                },
                CoreZmqNotifier {
                    topic: CoreZmqTopic::Sequence,
                    address: "ipc:///tmp/satd.sock".into(),
                    hwm: 0,
                },
            ],
            vec![],
        );
        assert_eq!(
            status.notifications_json(),
            serde_json::json!([
                {"type": "pubhashblock", "address": "tcp://127.0.0.1:28332", "hwm": 1000},
                {"type": "pubsequence", "address": "ipc:///tmp/satd.sock", "hwm": 0},
            ])
        );
    }
}
