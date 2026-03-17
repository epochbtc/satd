/// Default maximum mempool size in bytes (300 MB).
pub const DEFAULT_MAX_MEMPOOL_SIZE: usize = 300 * 1_000_000;

/// Default minimum relay fee rate in sat per 1000 weight units.
/// 1000 sat/kvB = 1 sat/vB.
pub const DEFAULT_MIN_RELAY_FEE_RATE: u64 = 1_000;

/// Maximum standard transaction weight (400,000 weight units).
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
