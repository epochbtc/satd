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

/// Check if a script is a standard output type.
/// Standard types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN,
/// and bare multisig (if configured via `-permitbaremultisig`).
pub fn is_standard_output_script(script: &bitcoin::Script, permit_bare_multisig: bool) -> bool {
    script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
        || script.is_op_return()
        || (permit_bare_multisig && script.is_multisig())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    /// Helper to build a P2PKH script (25 bytes: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG)
    fn p2pkh_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20 zero bytes
            0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
        ])
    }

    /// Helper to build a P2SH script (23 bytes: OP_HASH160 <20> OP_EQUAL)
    fn p2sh_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![
            0xa9, 0x14, // OP_HASH160 PUSH20
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x87, // OP_EQUAL
        ])
    }

    /// Helper to build a P2WPKH script (22 bytes: OP_0 <20>)
    fn p2wpkh_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![
            0x00, 0x14, // OP_0 PUSH20
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }

    /// Helper to build a P2TR script (34 bytes: OP_1 <32>)
    fn p2tr_script() -> ScriptBuf {
        let mut bytes = vec![0x51, 0x20]; // OP_1 PUSH32
        bytes.extend_from_slice(&[0u8; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    /// Helper to build an OP_RETURN script
    fn op_return_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x6a]) // OP_RETURN
    }

    #[test]
    fn test_dust_p2pkh() {
        let script = p2pkh_script();
        assert!(script.is_p2pkh());
        // output_size = 8 + 1 + 25 = 34; spend_size = 148; total = 182
        // 182 * 3000 / 1000 = 546
        assert_eq!(dust_threshold(&script), 546);
    }

    #[test]
    fn test_dust_p2wpkh() {
        let script = p2wpkh_script();
        assert!(script.is_p2wpkh());
        // output_size = 8 + 1 + 22 = 31; spend_size = 68; total = 99
        // 99 * 3000 / 1000 = 297
        assert_eq!(dust_threshold(&script), 297);
    }

    #[test]
    fn test_dust_p2tr() {
        let script = p2tr_script();
        assert!(script.is_p2tr());
        // output_size = 8 + 1 + 34 = 43; spend_size = 68; total = 111
        // 111 * 3000 / 1000 = 333
        assert_eq!(dust_threshold(&script), 333);
    }

    #[test]
    fn test_dust_p2sh() {
        let script = p2sh_script();
        assert!(script.is_p2sh());
        // output_size = 8 + 1 + 23 = 32; spend_size = 107; total = 139
        // 139 * 3000 / 1000 = 417
        assert_eq!(dust_threshold(&script), 417);
    }

    #[test]
    fn test_dust_op_return() {
        let script = op_return_script();
        assert!(script.is_op_return());
        // OP_RETURN is unspendable — threshold is always 0
        assert_eq!(dust_threshold(&script), 0);
    }

    #[test]
    fn test_dust_custom_rate() {
        let script = p2pkh_script();
        // At double the default rate (6000 sat/kvB), threshold doubles
        // 182 * 6000 / 1000 = 1092
        assert_eq!(dust_threshold_with_rate(&script, 6_000), 1092);
        // Verify it's exactly double the default
        assert_eq!(
            dust_threshold_with_rate(&script, 6_000),
            dust_threshold(&script) * 2
        );
    }

    #[test]
    fn test_dust_zero_rate() {
        // With fee rate 0, all thresholds should be 0
        assert_eq!(dust_threshold_with_rate(&p2pkh_script(), 0), 0);
        assert_eq!(dust_threshold_with_rate(&p2wpkh_script(), 0), 0);
        assert_eq!(dust_threshold_with_rate(&p2tr_script(), 0), 0);
        assert_eq!(dust_threshold_with_rate(&p2sh_script(), 0), 0);
        assert_eq!(dust_threshold_with_rate(&op_return_script(), 0), 0);
    }

    #[test]
    fn test_dust_unknown_script() {
        // An unknown script type should use spend_size = 68 (witness estimate)
        // Script: 10 arbitrary bytes (not matching any known pattern)
        let script = ScriptBuf::from_bytes(vec![0xff; 10]);
        assert!(!script.is_p2pkh());
        assert!(!script.is_p2sh());
        assert!(!script.is_p2wpkh());
        assert!(!script.is_p2wsh());
        assert!(!script.is_p2tr());
        assert!(!script.is_op_return());
        // output_size = 8 + 1 + 10 = 19; spend_size = 68; total = 87
        // 87 * 3000 / 1000 = 261
        assert_eq!(dust_threshold(&script), 261);
    }
}
