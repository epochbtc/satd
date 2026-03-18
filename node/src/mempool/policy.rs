/// Default maximum mempool size in bytes (300 MB).
pub const DEFAULT_MAX_MEMPOOL_SIZE: usize = 300 * 1_000_000;

/// Default minimum relay fee rate in sat per 1000 weight units.
/// 1000 sat/kvB = 1 sat/vB.
pub const DEFAULT_MIN_RELAY_FEE_RATE: u64 = 1_000;

/// Maximum standard transaction weight (400,000 weight units).
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

/// Dust relay fee rate (sat/kvB) used to compute dust thresholds.
/// 3000 sat/kvB = 3 sat/vB, matching Bitcoin Core's default.
pub const DUST_RELAY_FEE_RATE: u64 = 3_000;

/// Maximum size of an OP_RETURN output script (including OP_RETURN opcode).
pub const MAX_OP_RETURN_SIZE: usize = 83;

/// Maximum number of in-mempool ancestors for a single transaction.
pub const MAX_ANCESTOR_COUNT: usize = 25;

/// Maximum number of in-mempool descendants for a single transaction.
pub const MAX_DESCENDANT_COUNT: usize = 25;

/// Mempool expiry time in seconds (14 days).
pub const MEMPOOL_EXPIRY_SECS: u64 = 336 * 3600;

/// Incremental relay fee (sat/kvB). RBF replacements must pay at least this
/// much more per kvB than the transaction(s) they replace.
pub const INCREMENTAL_RELAY_FEE: u64 = 1_000;

/// Compute the dust threshold for a given output script.
///
/// An output is "dust" if its value is less than the cost to spend it
/// at the dust relay fee rate. The spend cost depends on the script type:
/// - P2PKH: 34 + 148 = 182 bytes → 546 sats at 3 sat/vB
/// - P2SH:  34 + 107 = 141 bytes → 540 sats at 3 sat/vB (but Core uses 546)
/// - P2WPKH: 31 + 68 = 99 bytes → 294 sats at 3 sat/vB (×4 for vbytes)
/// - P2WSH:  43 + 68 = 111 bytes → 330 sats
/// - P2TR:   43 + 58 = 101 bytes → 330 sats
/// - Unknown witness: 43 + 68 = 111 bytes → 330 sats
///
/// Compute the dust threshold using the default dust relay fee rate.
pub fn dust_threshold(script_pubkey: &bitcoin::ScriptBuf) -> u64 {
    dust_threshold_with_rate(script_pubkey, DUST_RELAY_FEE_RATE)
}

/// Compute the dust threshold for a given output script and fee rate.
pub fn dust_threshold_with_rate(script_pubkey: &bitcoin::ScriptBuf, fee_rate: u64) -> u64 {
    // Size of the serialized output itself
    let output_size: u64 = 8 + 1 + script_pubkey.len() as u64; // value + varint + script

    // Estimate the input size needed to spend this output
    let spend_size: u64 = if script_pubkey.is_p2pkh() {
        148 // pubkey hash input
    } else if script_pubkey.is_p2sh() {
        107 // script hash input (conservative)
    } else if script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() || script_pubkey.is_p2tr() {
        68 // witness v0/v1 input (witness data at 1/4 weight)
    } else if script_pubkey.is_op_return() {
        0 // unspendable
    } else {
        // Unknown script type — use conservative witness estimate
        68
    };

    if spend_size == 0 {
        return 0; // OP_RETURN is never dust
    }

    // Total cost at the given fee rate
    let total_size = output_size + spend_size;
    // fee = size * rate / 1000 (rate is sat/kvB, 1 vB = 4 WU for legacy, 1 WU for witness)
    // Simplified: use vbytes for consistency with Bitcoin Core
    total_size * fee_rate / 1000
}
