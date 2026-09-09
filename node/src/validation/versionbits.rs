//! BIP 9 deployment state, as Bitcoin Core computes it.
//!
//! satd enforces every consensus rule it has by height, so this exists for
//! one purpose: `getdeploymentinfo` has to describe deployments the way Core
//! does, and Core models two of them (`testdummy` and `taproot`) as BIP 9
//! rather than buried.
//!
//! Only `testdummy` actually runs the state machine, and only where it is
//! configured to run at all — every network but regtest gives it
//! [`NEVER_ACTIVE`], which short-circuits before any block is read. That
//! matters: the machine walks the chain a period at a time, so pointing it at
//! a real historical deployment on mainnet would read hundreds of thousands
//! of index entries to answer one RPC. `taproot` is therefore reported from
//! satd's own height model, in BIP 9 *shape*; see
//! [`taproot_deployment`] for what that does and does not claim.
//!
//! Every walk here follows `prev_blockhash`, never the height index: the
//! caller may name any block, including one on a stale fork, and the height
//! index describes the active chain alone.

use bitcoin::{BlockHash, Network};

/// `nStartTime` meaning "active from genesis" (Core's
/// `BIP9Deployment::ALWAYS_ACTIVE`).
pub const ALWAYS_ACTIVE: i64 = -1;
/// `nStartTime` meaning "never runs" (Core's `BIP9Deployment::NEVER_ACTIVE`).
pub const NEVER_ACTIVE: i64 = -2;
/// `nTimeout` meaning "no timeout" (Core's `BIP9Deployment::NO_TIMEOUT`).
pub const NO_TIMEOUT: i64 = i64::MAX;

/// Top three bits of a block version that mark it as version-bits signalling
/// (Core's `VERSIONBITS_TOP_MASK` / `VERSIONBITS_TOP_BITS`).
const VERSIONBITS_TOP_MASK: i32 = 0xE000_0000u32 as i32;
const VERSIONBITS_TOP_BITS: i32 = 0x2000_0000;

/// One BIP 9 deployment's parameters — Core's `Consensus::BIP9Deployment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip9Deployment {
    pub bit: u8,
    pub start_time: i64,
    pub timeout: i64,
    pub min_activation_height: u32,
    pub threshold: u32,
    pub period: u32,
}

/// `testdummy`, per network, from Core v31.1 `kernel/chainparams.cpp`.
///
/// Regtest is the only network where it runs: `nStartTime = 0`, a 144-block
/// period and a threshold of 108. Everywhere else it is [`NEVER_ACTIVE`],
/// which is why this is cheap to answer on a real chain.
pub fn testdummy_deployment(network: Network) -> Bip9Deployment {
    match network {
        Network::Regtest => Bip9Deployment {
            bit: 28,
            start_time: 0,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 108,
            period: 144,
        },
        Network::Bitcoin | Network::Signet => Bip9Deployment {
            bit: 28,
            start_time: NEVER_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 1815,
            period: 2016,
        },
        // Testnet3 and testnet4 use the 75% threshold.
        _ => Bip9Deployment {
            bit: 28,
            start_time: NEVER_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 1512,
            period: 2016,
        },
    }
}

/// `taproot`, per network, from Core v31.1 `kernel/chainparams.cpp`.
///
/// These are reported, not enforced. satd activates taproot at a height
/// ([`crate::validation::script::activation_heights`]) and never counts
/// signalling, so the *state* in `getdeploymentinfo` is derived from that
/// height rather than from this deployment's `start_time`/`threshold`. The
/// parameters are still Core's, because a client reading them is asking what
/// the deployment *is*, and on every network satd supports the outcome is
/// already settled: taproot is active from a fixed height.
pub fn taproot_deployment(network: Network) -> Bip9Deployment {
    match network {
        Network::Bitcoin => Bip9Deployment {
            bit: 2,
            start_time: 1_619_222_400,
            timeout: 1_628_640_000,
            min_activation_height: 709_632,
            threshold: 1815,
            period: 2016,
        },
        Network::Testnet => Bip9Deployment {
            bit: 2,
            start_time: 1_619_222_400,
            timeout: 1_628_640_000,
            min_activation_height: 0,
            threshold: 1512,
            period: 2016,
        },
        Network::Regtest => Bip9Deployment {
            bit: 2,
            start_time: ALWAYS_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 108,
            period: 144,
        },
        Network::Signet => Bip9Deployment {
            bit: 2,
            start_time: ALWAYS_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 1815,
            period: 2016,
        },
        // Testnet4.
        _ => Bip9Deployment {
            bit: 2,
            start_time: ALWAYS_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            threshold: 1512,
            period: 2016,
        },
    }
}

/// Core's `ThresholdState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

impl ThresholdState {
    /// Core's `StateName` — the string `getdeploymentinfo` reports.
    pub fn as_str(self) -> &'static str {
        match self {
            ThresholdState::Defined => "defined",
            ThresholdState::Started => "started",
            ThresholdState::LockedIn => "locked_in",
            ThresholdState::Active => "active",
            ThresholdState::Failed => "failed",
        }
    }
}

/// Core's `BIP9Stats`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip9Stats {
    pub period: u32,
    pub threshold: u32,
    pub elapsed: u32,
    pub count: u32,
    pub possible: bool,
}

/// Core's `BIP9Info` — everything `getdeploymentinfo` reports for one BIP 9
/// deployment.
#[derive(Clone, Debug)]
pub struct Bip9Info {
    pub current_state: ThresholdState,
    pub next_state: ThresholdState,
    pub since: u32,
    /// Signalling statistics, present only while `current_state` is
    /// `started` or `locked_in` (Core's `has_signal`).
    pub stats: Option<Bip9Stats>,
    /// One character per block in the current period, `#` for signalling.
    pub signalling: Option<String>,
    /// Height from which the deployment is (or will be) active.
    pub active_since: Option<u32>,
}

/// The header fields the state machine needs from one block.
#[derive(Clone, Copy, Debug)]
pub struct HeaderInfo {
    pub prev: BlockHash,
    pub height: u32,
    pub version: i32,
    pub time: u32,
}

/// Read-only access to the block index, by hash. Walking is by
/// `prev_blockhash` alone, so a caller can ask about a block on any branch.
pub trait BlockView {
    fn header(&self, hash: &BlockHash) -> Option<HeaderInfo>;
}

/// The ancestor of `hash` at `height`, or `None` if that is below genesis or
/// the chain of parents is broken.
fn ancestor<V: BlockView>(view: &V, hash: &BlockHash, height: u32) -> Option<(BlockHash, HeaderInfo)> {
    let mut cur_hash = *hash;
    let mut cur = view.header(&cur_hash)?;
    if height > cur.height {
        return None;
    }
    while cur.height > height {
        cur_hash = cur.prev;
        cur = view.header(&cur_hash)?;
    }
    Some((cur_hash, cur))
}

/// Core's `GetMedianTimePast`: the median of this block's time and its ten
/// ancestors'. Walks parents, so it is correct for a block on a stale fork.
fn median_time_past<V: BlockView>(view: &V, hash: &BlockHash) -> Option<u32> {
    let mut times = Vec::with_capacity(11);
    let mut cur_hash = *hash;
    for _ in 0..11 {
        let Some(info) = view.header(&cur_hash) else {
            break;
        };
        times.push(info.time);
        if info.height == 0 {
            break;
        }
        cur_hash = info.prev;
    }
    if times.is_empty() {
        return None;
    }
    times.sort_unstable();
    Some(times[times.len() / 2])
}

/// Core's `VersionBitsConditionChecker::Condition`: the block is a
/// version-bits block and has this deployment's bit set.
fn signals(version: i32, bit: u8) -> bool {
    (version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS && (version & (1i32 << bit)) != 0
}

/// Core's `GetStateFor`, for the block *after* `prev` (`prev` is
/// `pindexPrev`; `None` means "the parent of genesis").
fn state_for<V: BlockView>(
    view: &V,
    prev: Option<BlockHash>,
    dep: &Bip9Deployment,
) -> ThresholdState {
    if dep.start_time == ALWAYS_ACTIVE {
        return ThresholdState::Active;
    }
    if dep.start_time == NEVER_ACTIVE {
        return ThresholdState::Failed;
    }
    let period = dep.period.max(1);

    // A block's state is that of the first block of its period, so align
    // `prev` down to a height that is one below a multiple of the period.
    let mut cursor: Option<BlockHash> = match prev {
        None => None,
        Some(h) => {
            let Some(info) = view.header(&h) else {
                return ThresholdState::Defined;
            };
            // Core's `GetAncestor(nHeight - ((nHeight + 1) % nPeriod))`
            // returns null when that goes below genesis — the parent of the
            // genesis block, which is DEFINED by definition. In Rust the
            // same expression underflows, so the subtraction is checked.
            let back = (info.height + 1) % period;
            info.height
                .checked_sub(back)
                .and_then(|h2| ancestor(view, &h, h2))
                .map(|(hash, _)| hash)
        }
    };

    // Walk back a period at a time until we reach a block whose state is
    // known outright — genesis's parent, or a block before the start time.
    let mut to_compute: Vec<BlockHash> = Vec::new();
    let mut state = loop {
        let Some(hash) = cursor else {
            // The genesis block is by definition DEFINED.
            break ThresholdState::Defined;
        };
        let Some(info) = view.header(&hash) else {
            break ThresholdState::Defined;
        };
        match median_time_past(view, &hash) {
            Some(mtp) if (mtp as i64) < dep.start_time => break ThresholdState::Defined,
            None => break ThresholdState::Defined,
            _ => {}
        }
        to_compute.push(hash);
        cursor = if info.height < period {
            None
        } else {
            ancestor(view, &hash, info.height - period).map(|(h, _)| h)
        };
    };

    // …then forward, one period at a time.
    while let Some(hash) = to_compute.pop() {
        let Some(info) = view.header(&hash) else {
            break;
        };
        let mtp = median_time_past(view, &hash).unwrap_or(0) as i64;
        state = match state {
            ThresholdState::Defined => {
                if mtp >= dep.start_time {
                    ThresholdState::Started
                } else {
                    ThresholdState::Defined
                }
            }
            ThresholdState::Started => {
                let mut count = 0u32;
                let mut cur_hash = hash;
                for _ in 0..period {
                    let Some(cur) = view.header(&cur_hash) else {
                        break;
                    };
                    if signals(cur.version, dep.bit) {
                        count += 1;
                    }
                    if cur.height == 0 {
                        break;
                    }
                    cur_hash = cur.prev;
                }
                if count >= dep.threshold {
                    ThresholdState::LockedIn
                } else if mtp >= dep.timeout {
                    ThresholdState::Failed
                } else {
                    ThresholdState::Started
                }
            }
            ThresholdState::LockedIn => {
                if info.height + 1 >= dep.min_activation_height {
                    ThresholdState::Active
                } else {
                    ThresholdState::LockedIn
                }
            }
            terminal => terminal,
        };
    }
    state
}

/// Core's `GetStateSinceHeightFor`.
fn state_since_height<V: BlockView>(
    view: &V,
    prev: Option<BlockHash>,
    dep: &Bip9Deployment,
) -> u32 {
    if dep.start_time == ALWAYS_ACTIVE || dep.start_time == NEVER_ACTIVE {
        return 0;
    }
    let initial = state_for(view, prev, dep);
    if initial == ThresholdState::Defined {
        return 0;
    }
    let period = dep.period.max(1);
    let Some(prev_hash) = prev else { return 0 };
    let Some(info) = view.header(&prev_hash) else {
        return 0;
    };
    let back = (info.height + 1) % period;
    let Some((mut aligned, mut aligned_info)) = info
        .height
        .checked_sub(back)
        .and_then(|h| ancestor(view, &prev_hash, h))
    else {
        return 0;
    };
    loop {
        if aligned_info.height < period {
            break;
        }
        let Some((older, older_info)) = ancestor(view, &aligned, aligned_info.height - period)
        else {
            break;
        };
        if state_for(view, Some(older), dep) != initial {
            break;
        }
        aligned = older;
        aligned_info = older_info;
    }
    aligned_info.height + 1
}

/// Core's `GetStateStatisticsFor` — the signalling tally for the period
/// `hash` sits in, plus the per-block `#`/`-` string.
fn state_statistics<V: BlockView>(
    view: &V,
    hash: &BlockHash,
    dep: &Bip9Deployment,
) -> (Bip9Stats, String) {
    let period = dep.period.max(1);
    let mut stats = Bip9Stats {
        period,
        threshold: dep.threshold,
        elapsed: 0,
        count: 0,
        possible: true,
    };
    let Some(info) = view.header(hash) else {
        return (stats, String::new());
    };
    let mut blocks_in_period = 1 + (info.height % period);
    let mut signalling = vec![false; blocks_in_period as usize];
    let mut cur_hash = *hash;
    loop {
        let Some(cur) = view.header(&cur_hash) else {
            break;
        };
        stats.elapsed += 1;
        blocks_in_period -= 1;
        if signals(cur.version, dep.bit) {
            stats.count += 1;
            signalling[blocks_in_period as usize] = true;
        }
        if blocks_in_period == 0 || cur.height == 0 {
            break;
        }
        cur_hash = cur.prev;
    }
    stats.possible = (stats.period - stats.threshold) >= (stats.elapsed - stats.count);
    let text: String = signalling
        .iter()
        .map(|s| if *s { '#' } else { '-' })
        .collect();
    (stats, text)
}

/// Core's `VersionBitsCache::Info` for one deployment at one block.
pub fn info<V: BlockView>(view: &V, hash: &BlockHash, dep: &Bip9Deployment) -> Bip9Info {
    let block = view.header(hash);
    let prev = block.and_then(|b| if b.height == 0 { None } else { Some(b.prev) });
    let current_state = state_for(view, prev, dep);
    let next_state = state_for(view, Some(*hash), dep);
    let since = state_since_height(view, prev, dep);

    let has_signal = matches!(
        current_state,
        ThresholdState::Started | ThresholdState::LockedIn
    );
    let (stats, signalling) = if has_signal {
        let (mut s, text) = state_statistics(view, hash, dep);
        // Core zeroes the threshold once locked in: nothing can change it.
        if current_state == ThresholdState::LockedIn {
            s.threshold = 0;
            s.possible = false;
        }
        (Some(s), Some(text))
    } else {
        (None, None)
    };

    let active_since = if current_state == ThresholdState::Active {
        Some(since)
    } else if next_state == ThresholdState::Active {
        block.map(|b| b.height + 1)
    } else {
        None
    };

    Bip9Info {
        current_state,
        next_state,
        since,
        stats,
        signalling,
        active_since,
    }
}

/// Regtest-only `-vbparams` override for `testdummy`, Core's
/// `-vbparams=deployment:start:end[:min_activation_height]`.
///
/// Only `testdummy` is overridable. Core also accepts `taproot`, but satd
/// activates taproot by height and counts no signalling, so an override there
/// would be accepted and then ignored — the config layer refuses it by name
/// instead of pretending.
static TESTDUMMY_OVERRIDE: std::sync::OnceLock<Bip9Deployment> = std::sync::OnceLock::new();

/// Install the `-vbparams` override. Called once at daemon startup, before
/// any RPC is served, and only on regtest (the config layer refuses the
/// option elsewhere, as Core does). Returns `Err` if one is already set.
pub fn set_testdummy_override(dep: Bip9Deployment) -> Result<(), &'static str> {
    TESTDUMMY_OVERRIDE
        .set(dep)
        .map_err(|_| "vbparams override already set")
}

/// [`testdummy_deployment`] with any regtest `-vbparams` override applied.
pub fn testdummy_deployment_configured(network: Network) -> Bip9Deployment {
    if network == Network::Regtest
        && let Some(o) = TESTDUMMY_OVERRIDE.get()
    {
        return *o;
    }
    testdummy_deployment(network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use std::collections::HashMap;

    /// A straight chain of synthetic headers, indexed by hash. Height `h`
    /// gets hash `[h as bytes]`, so a test can name any block cheaply.
    struct FakeChain {
        headers: HashMap<BlockHash, HeaderInfo>,
        by_height: Vec<BlockHash>,
    }

    fn hash_at(height: u32) -> BlockHash {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    impl FakeChain {
        /// `signal(height)` decides whether that block sets the bit; `time`
        /// is `height` so median-time-past is monotonic and easy to reason
        /// about.
        fn new(len: u32, bit: u8, signal: impl Fn(u32) -> bool) -> Self {
            let mut headers = HashMap::new();
            let mut by_height = Vec::new();
            for h in 0..len {
                let hash = hash_at(h);
                let version = if signal(h) {
                    VERSIONBITS_TOP_BITS | (1i32 << bit)
                } else {
                    VERSIONBITS_TOP_BITS
                };
                headers.insert(
                    hash,
                    HeaderInfo {
                        prev: if h == 0 { hash_at(0) } else { hash_at(h - 1) },
                        height: h,
                        version,
                        time: 1_000 + h,
                    },
                );
                by_height.push(hash);
            }
            Self { headers, by_height }
        }
    }

    impl BlockView for FakeChain {
        fn header(&self, hash: &BlockHash) -> Option<HeaderInfo> {
            self.headers.get(hash).copied()
        }
    }

    fn regtest_testdummy() -> Bip9Deployment {
        testdummy_deployment(Network::Regtest)
    }

    /// A deployment nobody signals for stays `started` forever once the
    /// window opens, and never reports a `height`.
    #[test]
    fn an_unsignalled_deployment_starts_and_stays_started() {
        let dep = regtest_testdummy();
        let chain = FakeChain::new(500, dep.bit, |_| false);

        // Before the first period boundary: still defined, since 0.
        let early = info(&chain, &chain.by_height[100], &dep);
        assert_eq!(early.current_state, ThresholdState::Defined);
        assert_eq!(early.since, 0);
        assert!(early.stats.is_none(), "no statistics while defined");
        assert!(early.active_since.is_none());

        // At 144 the window has opened.
        let open = info(&chain, &chain.by_height[200], &dep);
        assert_eq!(open.current_state, ThresholdState::Started);
        assert_eq!(open.since, 144, "started at the first period boundary");
        let stats = open.stats.expect("started reports statistics");
        assert_eq!(stats.period, 144);
        assert_eq!(stats.threshold, 108);
        assert_eq!(stats.count, 0, "nothing signalled");
        assert_eq!(stats.elapsed, 200 - 143);
        // 144 - 108 = 36 blocks may miss; 57 have gone by with none
        // signalling, so the period is already out of reach.
        assert!(!stats.possible, "36 misses allowed, 57 already missed");
        assert!(open.active_since.is_none());
        assert_eq!(
            open.signalling.as_deref(),
            Some("-".repeat(200 - 143).as_str())
        );
    }

    /// The full walk: a chain that signals on every block reaches
    /// `locked_in` at the end of the first signalling period and `active`
    /// one period later, with `since` tracking each transition.
    #[test]
    fn full_signalling_locks_in_and_then_activates() {
        let dep = regtest_testdummy();
        let chain = FakeChain::new(600, dep.bit, |h| h >= 144);

        // 144..287 is the first STARTED period; it signals throughout, so
        // the state for 288.. is LOCKED_IN.
        let started = info(&chain, &chain.by_height[287], &dep);
        assert_eq!(started.current_state, ThresholdState::Started);
        assert_eq!(started.next_state, ThresholdState::LockedIn);
        assert_eq!(started.stats.unwrap().count, 144);

        let locked = info(&chain, &chain.by_height[288], &dep);
        assert_eq!(locked.current_state, ThresholdState::LockedIn);
        assert_eq!(locked.since, 288);
        // Core zeroes the threshold once locked in — nothing can change it.
        let stats = locked.stats.expect("locked_in still reports statistics");
        assert_eq!(stats.threshold, 0);
        assert!(!stats.possible);
        // A state change only lands on a period boundary, so mid-period the
        // next block is still locked in and no activation height is known.
        assert_eq!(locked.next_state, ThresholdState::LockedIn);
        assert!(locked.active_since.is_none());

        // The last block of the locked-in period is where `status_next`
        // finally reads `active`, and where the activation height appears.
        let eve = info(&chain, &chain.by_height[431], &dep);
        assert_eq!(eve.current_state, ThresholdState::LockedIn);
        assert_eq!(eve.next_state, ThresholdState::Active);
        assert_eq!(eve.active_since, Some(432));

        let active = info(&chain, &chain.by_height[500], &dep);
        assert_eq!(active.current_state, ThresholdState::Active);
        assert_eq!(active.since, 432, "active from the period after lock-in");
        assert_eq!(active.active_since, Some(432));
        assert!(active.stats.is_none(), "no statistics once active");
    }

    /// One block short of the threshold in a period does not lock in, and
    /// `possible` goes false as soon as the remaining blocks cannot make it.
    #[test]
    fn one_block_short_of_the_threshold_does_not_lock_in() {
        let dep = regtest_testdummy();
        // Signal on 107 of the 144 blocks in 144..287 (threshold is 108).
        let chain = FakeChain::new(600, dep.bit, |h| (144..251).contains(&h));

        let end_of_period = info(&chain, &chain.by_height[287], &dep);
        assert_eq!(end_of_period.stats.unwrap().count, 107);
        assert_eq!(
            end_of_period.next_state,
            ThresholdState::Started,
            "107 < 108 must not lock in"
        );

        // 37 non-signalling blocks in a 144/108 window means at most 107 can
        // signal, so it is no longer possible.
        let stats = info(&chain, &chain.by_height[287], &dep).stats.unwrap();
        assert!(!stats.possible);
    }

    /// A deployment past its timeout with too little signalling fails, and
    /// failure is terminal.
    #[test]
    fn a_timed_out_deployment_fails_and_stays_failed() {
        let dep = Bip9Deployment {
            // Block times are `1000 + height`, so this expires inside the
            // second signalling period.
            timeout: 1_300,
            ..regtest_testdummy()
        };
        let chain = FakeChain::new(600, dep.bit, |_| false);
        let failed = info(&chain, &chain.by_height[500], &dep);
        assert_eq!(failed.current_state, ThresholdState::Failed);
        assert_eq!(failed.next_state, ThresholdState::Failed);
        assert!(failed.active_since.is_none());
    }

    /// `min_activation_height` holds a locked-in deployment back, which is
    /// the whole reason taproot's mainnet parameters carry one.
    #[test]
    fn min_activation_height_delays_activation() {
        let dep = Bip9Deployment {
            min_activation_height: 1_000,
            ..regtest_testdummy()
        };
        let chain = FakeChain::new(600, dep.bit, |h| h >= 144);
        let at = info(&chain, &chain.by_height[500], &dep);
        assert_eq!(
            at.current_state,
            ThresholdState::LockedIn,
            "cannot activate below min_activation_height"
        );
        assert!(at.active_since.is_none());
    }

    /// The two special `nStartTime` values short-circuit without reading a
    /// single block — which is what keeps `getdeploymentinfo` cheap on a
    /// real chain, where a period walk would be hundreds of thousands of
    /// index reads.
    #[test]
    fn always_and_never_active_never_touch_the_chain() {
        struct Poisoned;
        impl BlockView for Poisoned {
            fn header(&self, _: &BlockHash) -> Option<HeaderInfo> {
                panic!("a short-circuiting deployment must not read the chain");
            }
        }
        // `info` reads the block itself for its height; give it one block and
        // poison everything else by making the deployment short-circuit.
        for (start, want) in [
            (ALWAYS_ACTIVE, ThresholdState::Active),
            (NEVER_ACTIVE, ThresholdState::Failed),
        ] {
            let dep = Bip9Deployment {
                start_time: start,
                ..regtest_testdummy()
            };
            assert_eq!(state_for(&Poisoned, Some(hash_at(9)), &dep), want);
            assert_eq!(state_since_height(&Poisoned, Some(hash_at(9)), &dep), 0);
        }
    }

    /// A block that is not a version-bits block does not signal, however its
    /// bit is set — Core's `Condition` checks the top three bits first.
    #[test]
    fn only_versionbits_blocks_signal() {
        let bit = 28u8;
        assert!(signals(VERSIONBITS_TOP_BITS | (1 << bit), bit));
        assert!(!signals(VERSIONBITS_TOP_BITS, bit));
        // Version 4 (a pre-BIP9 block) with the bit set is not signalling.
        assert!(!signals(4 | (1 << bit), bit));
        // Nor is a block whose top bits are 0b011.
        assert!(!signals(0x6000_0000u32 as i32 | (1 << bit), bit));
    }

    /// The deployment tables are Core v31.1's, and getting one wrong would
    /// report a window the network does not have.
    #[test]
    fn deployment_parameters_match_core_v31_1() {
        let rt = testdummy_deployment(Network::Regtest);
        assert_eq!((rt.bit, rt.start_time, rt.timeout), (28, 0, NO_TIMEOUT));
        assert_eq!((rt.threshold, rt.period), (108, 144));

        for net in [Network::Bitcoin, Network::Testnet, Network::Signet] {
            let d = testdummy_deployment(net);
            assert_eq!(d.start_time, NEVER_ACTIVE, "{net}: testdummy never runs");
        }
        assert_eq!(testdummy_deployment(Network::Bitcoin).threshold, 1815);
        assert_eq!(testdummy_deployment(Network::Testnet).threshold, 1512);

        let main = taproot_deployment(Network::Bitcoin);
        assert_eq!(main.bit, 2);
        assert_eq!(main.start_time, 1_619_222_400);
        assert_eq!(main.timeout, 1_628_640_000);
        assert_eq!(main.min_activation_height, 709_632);
        assert_eq!((main.threshold, main.period), (1815, 2016));

        let t3 = taproot_deployment(Network::Testnet);
        assert_eq!(t3.min_activation_height, 0, "no activation delay on testnet3");
        assert_eq!(t3.threshold, 1512);

        for net in [Network::Regtest, Network::Signet] {
            assert_eq!(taproot_deployment(net).start_time, ALWAYS_ACTIVE, "{net}");
        }
    }
}
