//! The node's clock, and the test-only mock that can move it.
//!
//! Bitcoin Core routes behaviour-affecting time through `GetTime()` /
//! `NodeClock` so `setmocktime` can move it, which is what makes its
//! functional tests deterministic — the framework mines a chain at a chosen
//! timestamp, ages a mempool entry past its expiry, or steps a peer past a
//! timeout, without sleeping.
//!
//! satd read `SystemTime::now()` directly at every such site, so there was
//! nothing to move. This module is the single place a mock can be installed.
//!
//! ## What routes through here, and what does not
//!
//! Only time that changes *node behaviour*: block-template timestamps, the
//! `time-too-new` future-block check, mempool entry time and expiry, and the
//! tip-age test that decides whether the node considers itself in initial
//! block download (`ChainState::tip_time_is_ibd`, which gates the per-block
//! coin-cache flush and `getblockchaininfo`'s `initialblockdownload`). That
//! last one is not optional: it compares against a block header's timestamp,
//! and headers are stamped from this clock, so leaving it on the system clock
//! would put the two sides of the comparison on different clocks.
//!
//! Peer timeouts, reconnect backoff, ban expiry, fee-estimator decay, and the
//! orphanage all read `Instant::now()` and are deliberately **not** mockable:
//! a monotonic clock that can jump backwards underflows or waits forever.
//! Core's tests that need those mock its scheduler instead, which satd does
//! not implement. Log lines, metrics, and on-disk audit timestamps also keep
//! reading the real clock — mocking those would make a mocked run's logs lie
//! about when it happened, and Core does not mock them either.
//!
//! ## Why an offset rather than a stored instant
//!
//! The mock is stored as an absolute second, not a delta, matching Core: while
//! a mock is installed the clock does **not** advance on its own. Tests rely on
//! that — they step time explicitly and expect nothing to move in between.

use std::sync::atomic::{AtomicU64, Ordering};

/// Installed mock time in seconds since the epoch, or 0 for "no mock".
///
/// Zero doubles as the sentinel because Core spells "stop mocking" as
/// `setmocktime(0)`; a real node is never legitimately at the epoch.
static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

/// The real system clock, in seconds since the Unix epoch.
///
/// Saturates to 0 if the host clock is before the epoch, which only ever makes
/// the future-block check stricter, never laxer.
fn system_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The node's current time in seconds since the epoch: the mock if one is
/// installed, otherwise the system clock.
///
/// Every behaviour-affecting time read should come from here.
pub fn now_secs() -> u64 {
    match MOCK_TIME.load(Ordering::Relaxed) {
        0 => system_now_secs(),
        mocked => mocked,
    }
}

/// Whether `setmocktime` may move the clock on `network`.
///
/// Core gates on `Params().IsMockableChain()`, and only regtest sets
/// `m_is_mockable_chain = true` (`src/kernel/chainparams.cpp`); main, testnet3,
/// testnet4 and signet all set it false. This is the whole of the safety
/// argument for shipping a clock-moving RPC, so it is a named function with a
/// test rather than an inline comparison: on any other network a caller with
/// RPC access could move block-timestamp acceptance, mempool expiry, and the
/// IBD tip-age test.
pub fn clock_is_mockable(network: bitcoin::Network) -> bool {
    matches!(network, bitcoin::Network::Regtest)
}

/// Install (`Some`) or clear (`None`) the mock clock.
///
/// Only `setmocktime` calls this, and only on a mockable chain — see
/// `rpc::server`'s registration for the gate.
pub fn set_mock_time(secs: Option<u64>) {
    MOCK_TIME.store(secs.unwrap_or(0), Ordering::Relaxed);
}

/// The installed mock, if any. Test-only: satd exposes no `getmocktime`, so
/// nothing outside this module's own tests reads it.
#[cfg(test)]
pub fn mock_time() -> Option<u64> {
    match MOCK_TIME.load(Ordering::Relaxed) {
        0 => None,
        mocked => Some(mocked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests share one process-global clock, so they run as one test to
    /// keep them from racing each other.
    ///
    /// They also share it with every other test in this binary, which run on
    /// other threads. The window where a mock is installed must therefore stay
    /// as short as possible and the mock must be a time in the *past*: the
    /// future-block check only rejects timestamps that are too new, so a past
    /// mock is strictly stricter than the real clock and cannot make a
    /// concurrent test pass something it should have failed. Do not mock
    /// forward here.
    #[test]
    fn mock_replaces_the_system_clock_and_can_be_cleared() {
        assert!(mock_time().is_none(), "no mock installed by default");
        let real = now_secs();
        assert!(real > 1_600_000_000, "system clock looks wrong: {real}");

        set_mock_time(Some(1_296_688_602));
        assert_eq!(now_secs(), 1_296_688_602);
        assert_eq!(mock_time(), Some(1_296_688_602));

        // A mock does not advance on its own; tests depend on that.
        assert_eq!(now_secs(), now_secs());

        set_mock_time(None);
        assert!(mock_time().is_none());
        assert!(now_secs() >= real, "clock returned to real time");
    }

    /// The gate is the only thing standing between a test-only RPC and a
    /// mainnet node whose block-timestamp acceptance, mempool expiry and IBD
    /// judgement a caller can move. Regtest and nothing else, matching Core's
    /// `m_is_mockable_chain`.
    #[test]
    fn only_regtest_has_a_mockable_clock() {
        use bitcoin::Network;
        assert!(clock_is_mockable(Network::Regtest));
        for n in [Network::Bitcoin, Network::Testnet, Network::Testnet4, Network::Signet] {
            assert!(!clock_is_mockable(n), "{n:?} must not accept setmocktime");
        }
    }
}
