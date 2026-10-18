//! Seeding the address book after startup: Core's `ThreadDNSAddressSeed`
//! and the fixed-seed fallback in `ThreadOpenConnections` (`src/net.cpp`).
//!
//! satd seeded once, at startup, and only when the address book had nothing
//! reachable (#974). A node that came back to a stale `peers.dat` skipped
//! seeding entirely and, if every address in it was dead, stayed at zero
//! outbound peers until a restart with `-forcednsseed`. Core instead tries
//! the book first and seeds if that does not work: the DNS seeds after a
//! short wait without enough peers, the fixed seeds a minute in if the book
//! still has nothing reachable.

use std::future::Future;
use std::time::Duration;

use crate::net::peer::PeerAddr;

/// Core's `DNSSEEDS_DELAY_FEW_PEERS`: the wait before querying DNS seeds
/// when the address book has a few addresses, and the step a longer wait
/// is checked in.
pub const DNS_SEED_DELAY_FEW_PEERS: Duration = Duration::from_secs(11);
/// Core's `DNSSEEDS_DELAY_MANY_PEERS`.
pub const DNS_SEED_DELAY_MANY_PEERS: Duration = Duration::from_secs(5 * 60);
/// Core's `DNSSEEDS_DELAY_PEER_THRESHOLD`: how many addresses count as many.
pub const DNS_SEED_DELAY_PEER_THRESHOLD: usize = 1000;
/// Core's `SEED_OUTBOUND_CONNECTION_THRESHOLD`: full-relay outbound peers
/// that make seeding unnecessary.
pub const SEED_OUTBOUND_CONNECTION_THRESHOLD: usize = 2;
/// How long other sources get to fill the book before the fixed seeds are
/// added: Core's one minute.
pub const FIXED_SEEDS_DELAY: Duration = Duration::from_secs(60);

/// What seeding needs from the peer manager.
pub trait SeedTarget: Send + Sync {
    /// Addresses in the book.
    fn addrman_len(&self) -> usize;
    /// Whether the book holds an address on a network the node can reach.
    fn addrman_has_reachable(&self) -> bool;
    /// Full-relay outbound peers past the handshake: Core's
    /// `GetFullOutboundConnCount`.
    fn full_outbound_count(&self) -> usize;
    /// Add a seed's address to the book, as a learned address.
    fn add_seed(&self, addr: &PeerAddr);
    /// Run the automatic dial pass over what was added.
    fn dial(&self);
}

impl SeedTarget for std::sync::Arc<crate::net::manager::PeerManager> {
    fn addrman_len(&self) -> usize {
        crate::net::manager::PeerManager::addrman_len(self)
    }
    fn addrman_has_reachable(&self) -> bool {
        crate::net::manager::PeerManager::addrman_has_reachable(self)
    }
    fn full_outbound_count(&self) -> usize {
        crate::net::manager::PeerManager::full_outbound_count(self)
    }
    fn add_seed(&self, addr: &PeerAddr) {
        self.add_learned_peer_addr(addr);
    }
    fn dial(&self) {
        self.dial_learned_peers();
    }
}

/// When to wait, and for how long. [`SeedTimings::CORE`] in the node; tests
/// shrink it.
#[derive(Debug, Clone, Copy)]
pub struct SeedTimings {
    pub dns_few_peers: Duration,
    pub dns_many_peers: Duration,
    pub fixed_seeds_delay: Duration,
}

impl SeedTimings {
    pub const CORE: SeedTimings = SeedTimings {
        dns_few_peers: DNS_SEED_DELAY_FEW_PEERS,
        dns_many_peers: DNS_SEED_DELAY_MANY_PEERS,
        fixed_seeds_delay: FIXED_SEEDS_DELAY,
    };
}

/// Core's `ThreadDNSAddressSeed`, for a node with DNS seeding on.
///
/// With `-forcednsseed`, or nothing reachable in the book, the seeds are
/// queried at once. Otherwise the book is tried first: the task waits 11
/// seconds, or five minutes for a book of a thousand addresses or more,
/// checked every 11 seconds, and stops there if the node has reached
/// [`SEED_OUTBOUND_CONNECTION_THRESHOLD`] full-relay peers. Core then
/// queries three seeds at a time with a wait between; satd queries them
/// together.
///
/// Returns the number of addresses the seeds gave, `None` if it did not
/// query them.
pub async fn dns_seed<T, F, Fut>(
    target: &T,
    force: bool,
    timings: SeedTimings,
    resolve: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<usize>
where
    T: SeedTarget + ?Sized,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Vec<PeerAddr>>,
{
    if !force && target.addrman_has_reachable() {
        let mut to_wait = if target.addrman_len() >= DNS_SEED_DELAY_PEER_THRESHOLD {
            timings.dns_many_peers
        } else {
            timings.dns_few_peers
        };
        tracing::info!("Waiting {} seconds before querying DNS seeds.", to_wait.as_secs());
        while !to_wait.is_zero() {
            let step = to_wait.min(timings.dns_few_peers);
            tokio::select! {
                _ = tokio::time::sleep(step) => {}
                _ = shutdown.wait_for(|v| *v) => return None,
            }
            to_wait -= step;
            if target.full_outbound_count() >= SEED_OUTBOUND_CONNECTION_THRESHOLD {
                tracing::info!("P2P peers available. Skipped DNS seeding.");
                return None;
            }
        }
    }
    let found = resolve().await;
    let n = found.len();
    // Core takes at most 32 addresses from one seed; satd's resolver returns
    // every seed's answers together, and has always taken at most 64.
    for addr in found.into_iter().take(64) {
        target.add_seed(&addr);
    }
    tracing::info!("{n} addresses found from DNS seeds");
    target.dial();
    Some(n)
}

/// The fixed-seed fallback in Core's `ThreadOpenConnections`.
///
/// When nothing else can fill the book (DNS seeding off, no `-seednode`,
/// no `-addnode`), the fixed seeds are added at once if the book has
/// nothing reachable. Otherwise the other sources get a minute, and the
/// fixed seeds are added if the book still has nothing reachable then.
///
/// Returns whether it added them.
pub async fn fixed_seed(
    target: &(impl SeedTarget + ?Sized),
    other_sources: bool,
    timings: SeedTimings,
    fixed: Vec<PeerAddr>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> bool {
    if fixed.is_empty() {
        return false;
    }
    if other_sources {
        tokio::select! {
            _ = tokio::time::sleep(timings.fixed_seeds_delay) => {}
            _ = shutdown.wait_for(|v| *v) => return false,
        }
    }
    if target.addrman_has_reachable() {
        return false;
    }
    if other_sources {
        tracing::info!(
            "Adding fixed seeds as 60 seconds have passed and addrman is empty for at least one reachable network"
        );
    } else {
        tracing::info!(
            "Adding fixed seeds as -dnsseed=0 (or IPv4/IPv6 connections are disabled via -onlynet) and neither -addnode nor -seednode are provided"
        );
    }
    let n = fixed.len();
    for addr in &fixed {
        target.add_seed(addr);
    }
    tracing::info!("Added {n} fixed seeds from reachable networks.");
    target.dial();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Book {
        addrs: Mutex<Vec<PeerAddr>>,
        stale: AtomicUsize,
        outbound: AtomicUsize,
        dials: AtomicUsize,
    }

    impl SeedTarget for Book {
        fn addrman_len(&self) -> usize {
            self.stale.load(Ordering::Relaxed) + self.addrs.lock().unwrap().len()
        }
        fn addrman_has_reachable(&self) -> bool {
            self.addrman_len() > 0
        }
        fn full_outbound_count(&self) -> usize {
            self.outbound.load(Ordering::Relaxed)
        }
        fn add_seed(&self, addr: &PeerAddr) {
            self.addrs.lock().unwrap().push(addr.clone());
        }
        fn dial(&self) {
            self.dials.fetch_add(1, Ordering::Relaxed);
        }
    }

    const FAST: SeedTimings = SeedTimings {
        dns_few_peers: Duration::from_millis(20),
        dns_many_peers: Duration::from_millis(100),
        fixed_seeds_delay: Duration::from_millis(50),
    };

    fn seed(n: u8) -> PeerAddr {
        PeerAddr::Socket(format!("10.0.0.{n}:8333").parse().unwrap())
    }

    fn running() -> tokio::sync::watch::Receiver<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(tx);
        rx
    }

    /// #974: a book full of dead addresses no longer means no seeding. The
    /// task waits, finds no peers, and queries the seeds.
    #[tokio::test]
    async fn a_stale_book_with_no_peers_is_seeded_after_the_wait() {
        let book = Book::default();
        book.stale.store(50, Ordering::Relaxed);
        let started = tokio::time::Instant::now();
        let got = dns_seed(&book, false, FAST, || async { vec![seed(1), seed(2)] }, running()).await;
        assert_eq!(got, Some(2));
        assert!(started.elapsed() >= FAST.dns_few_peers, "queried before the wait");
        assert_eq!(book.addrs.lock().unwrap().len(), 2);
        assert_eq!(book.dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn enough_peers_after_the_wait_skips_the_seeds() {
        let book = Book::default();
        book.stale.store(50, Ordering::Relaxed);
        book.outbound.store(SEED_OUTBOUND_CONNECTION_THRESHOLD, Ordering::Relaxed);
        let got = dns_seed(&book, false, FAST, || async { panic!("seeds queried with enough peers") }, running()).await;
        assert_eq!(got, None);
    }

    /// A book of a thousand addresses waits the long interval, but stops as
    /// soon as a check finds enough peers.
    #[tokio::test]
    async fn a_large_book_waits_longer_and_checks_on_the_way() {
        let book = std::sync::Arc::new(Book::default());
        book.stale.store(DNS_SEED_DELAY_PEER_THRESHOLD, Ordering::Relaxed);
        let started = tokio::time::Instant::now();
        let got = dns_seed(&*book, false, FAST, || async { vec![seed(1)] }, running()).await;
        assert_eq!(got, Some(1));
        assert!(started.elapsed() >= FAST.dns_many_peers);

        let book = std::sync::Arc::new(Book::default());
        book.stale.store(DNS_SEED_DELAY_PEER_THRESHOLD, Ordering::Relaxed);
        let b = book.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            b.outbound.store(2, Ordering::Relaxed);
        });
        let started = tokio::time::Instant::now();
        let got = dns_seed(&*book, false, FAST, || async { panic!("seeds queried with enough peers") }, running()).await;
        assert_eq!(got, None);
        assert!(started.elapsed() < FAST.dns_many_peers, "it waited out the whole interval");
    }

    #[tokio::test]
    async fn an_empty_book_or_forcednsseed_queries_at_once() {
        let book = Book::default();
        let started = tokio::time::Instant::now();
        assert_eq!(dns_seed(&book, false, FAST, || async { vec![seed(1)] }, running()).await, Some(1));
        let book = Book::default();
        book.stale.store(50, Ordering::Relaxed);
        book.outbound.store(8, Ordering::Relaxed);
        assert_eq!(dns_seed(&book, true, FAST, || async { vec![seed(1)] }, running()).await, Some(1));
        assert!(started.elapsed() < FAST.dns_few_peers);
    }

    /// #974: with other sources configured, the fixed seeds wait a minute and
    /// are added only if the book still has nothing reachable then.
    #[tokio::test]
    async fn fixed_seeds_follow_a_minute_of_an_empty_book() {
        let book = Book::default();
        let started = tokio::time::Instant::now();
        assert!(fixed_seed(&book, true, FAST, vec![seed(9)], running()).await);
        assert!(started.elapsed() >= FAST.fixed_seeds_delay);
        assert_eq!(book.addrs.lock().unwrap().len(), 1);

        // The other sources filled it in time.
        let book = std::sync::Arc::new(Book::default());
        let b = book.clone();
        tokio::spawn(async move { b.add_seed(&seed(1)) });
        assert!(!fixed_seed(&*book, true, FAST, vec![seed(9)], running()).await);

        // Nothing else to wait for: at once.
        let book = Book::default();
        let started = tokio::time::Instant::now();
        assert!(fixed_seed(&book, false, FAST, vec![seed(9)], running()).await);
        assert!(started.elapsed() < FAST.fixed_seeds_delay);
    }

    #[tokio::test]
    async fn shutdown_ends_a_wait() {
        let book = Book::default();
        book.stale.store(DNS_SEED_DELAY_PEER_THRESHOLD, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::watch::channel(false);
        tx.send(true).unwrap();
        assert_eq!(dns_seed(&book, false, FAST, || async { vec![seed(1)] }, rx.clone()).await, None);
        assert!(!fixed_seed(&book, true, FAST, vec![seed(9)], rx).await);
    }
}
