/// Default maximum mempool size in bytes (300 MB).
pub const DEFAULT_MAX_MEMPOOL_SIZE: usize = 300 * 1_000_000;

/// Default byte budget for the **quarantine class** (`quarantinemempool=<MB>`),
/// 50 MB — ≈1/6 of the default acting mempool (design §13). Held transactions
/// get their own capacity with independent fee-rate eviction, so a broad policy
/// can never crowd out the acting mempool. Zero in effect until a policy is
/// loaded (PR 4c): with no ruleset every transaction is "acting".
pub const DEFAULT_QUARANTINE_MEMPOOL_SIZE: usize = 50 * 1_000_000;

/// Default minimum relay fee rate in sat/kvB (sat per 1000 *virtual* bytes),
/// matching Bitcoin Core v31's `DEFAULT_MIN_RELAY_TX_FEE` (100 sat/kvB,
/// lowered from 1000 in Core v28). Fee rates are always per vbyte, never per
/// weight unit — derive them with [`fee_rate_sat_per_kvb`].
pub const DEFAULT_MIN_RELAY_FEE_RATE: u64 = 100;

/// Maximum standard transaction weight (400,000 weight units).
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

/// The most dust outputs a standard transaction may carry (Core's
/// `MAX_DUST_OUTPUTS_PER_TX`, `src/policy/policy.h`). One is permitted so that
/// ephemeral dust — a zero-fee anchor swept by a child — stays relayable;
/// more than one is non-standard outright.
pub const MAX_DUST_OUTPUTS_PER_TX: usize = 1;

/// Dust relay fee rate (sat/kvB) used to compute dust thresholds.
/// 3000 sat/kvB = 3 sat/vB, matching Bitcoin Core's default.
pub const DUST_RELAY_FEE_RATE: u64 = 3_000;

/// Historical maximum size of an OP_RETURN output script (including OP_RETURN
/// opcode).  83 bytes was the hard cap through Bitcoin Core v30.
pub const MAX_OP_RETURN_SIZE: usize = 83;

/// Default OP_RETURN relay cap.  Core v31 changed the default from
/// [`MAX_OP_RETURN_SIZE`] (83) to `MAX_STANDARD_TX_WEIGHT / 4` (100 000),
/// making the relay effectively uncapped.  Match that so a default-config
/// node reports `getmempoolinfo.maxdatacarriersize = 100000` and accepts
/// large OP_RETURN outputs the same as Core.
pub const DEFAULT_DATA_CARRIER_SIZE: usize = 100_000;

/// Maximum number of transactions in one connected mempool cluster.
///
/// Core v31 replaced the ancestor/descendant package limits with a single
/// limit over a transaction's whole connected component
/// (`DEFAULT_CLUSTER_LIMIT{64}`, `src/policy/policy.h`). The older
/// `DEFAULT_ANCESTOR_LIMIT{25}` / `DEFAULT_DESCENDANT_LIMIT{25}` still
/// exist, but v31's own `-limitancestorcount` help calls them
/// "Deprecated ... replaced by cluster limits (see -limitclustercount) and
/// only used by wallet for coin selection": no acceptance path reads them,
/// and the reject string they produced (`too-long-mempool-chain`) is gone
/// from Core's source entirely.
///
/// satd tracks the transitive ancestor and descendant sets rather than a
/// true cluster. For the linear chains this limit actually governs the two
/// coincide, so the cluster bound is applied to each — a real cluster
/// implementation is separate work.
pub const MAX_CLUSTER_COUNT: usize = 64;

/// Maximum number of in-mempool ancestors for a single transaction.
/// See [`MAX_CLUSTER_COUNT`] for why this is the cluster bound.
pub const MAX_ANCESTOR_COUNT: usize = MAX_CLUSTER_COUNT;

/// Maximum number of in-mempool descendants for a single transaction.
/// See [`MAX_CLUSTER_COUNT`] for why this is the cluster bound.
pub const MAX_DESCENDANT_COUNT: usize = MAX_CLUSTER_COUNT;

/// Mempool expiry time in seconds (14 days).
pub const MEMPOOL_EXPIRY_SECS: u64 = 336 * 3600;

/// Incremental relay fee (sat/kvB). RBF replacements must pay at least this
/// much more per kvB than the transaction(s) they replace. Matches Bitcoin
/// Core v30's `DEFAULT_INCREMENTAL_RELAY_FEE` (100 sat/kvB).
pub const INCREMENTAL_RELAY_FEE: u64 = 100;

/// Virtual size (vbytes) for a given transaction weight, matching Bitcoin
/// Core's `GetVirtualTransactionSize`: ceil division by the witness scale
/// factor (4). Use this — never raw weight — wherever a vbyte quantity is
/// needed, so fee rates and size-based fees match Core.
pub fn weight_to_vsize(weight: u64) -> u64 {
    weight.div_ceil(4)
}

/// Fee rate in sat/kvB (sat per 1000 *virtual* bytes), matching Bitcoin Core's
/// `CFeeRate`. Fee rates throughout satd are sat/kvB and MUST be derived from
/// virtual size, not raw weight: weight ≈ 4× vsize, so dividing a fee by weight
/// understates the rate ~4× and applies a ~4× too-high effective relay floor
/// (rejecting standard 1–4 sat/vB transactions that the rest of the network
/// relays). Returns 0 for a zero-weight transaction.
pub fn fee_rate_sat_per_kvb(fee: u64, weight: u64) -> u64 {
    let vsize = weight_to_vsize(weight);
    if vsize == 0 {
        0
    } else {
        fee.saturating_mul(1000) / vsize
    }
}

/// Compute the dust threshold for a given output script.
///
/// An output is "dust" if its value is less than the cost to spend it
/// at the dust relay fee rate. The spend cost depends on whether the output is
/// a witness program, exactly as Bitcoin Core's `GetDustThreshold`
/// (`src/policy/policy.cpp`) computes it:
///
/// - a witness program costs `32 + 4 + 1 + 107/4 + 4` = **67** vbytes to spend
///   (the 75% witness discount applied to a 107-byte P2WPKH satisfaction),
/// - anything else costs `32 + 4 + 1 + 107 + 4` = **148** vbytes,
///
/// added to the serialized size of the output itself, with the fee rounded
/// **up**. Core deliberately keeps the P2WPKH estimate for every witness
/// version, including Taproot, whose real minimum satisfaction is smaller
/// (bitcoin/bitcoin#22779), so the thresholds at the default 3000 sat/kvB are:
///
/// | script | output | spend | threshold |
/// |---|---|---|---|
/// | P2PKH | 34 | 148 | 546 |
/// | P2SH | 32 | 148 | 540 |
/// | P2WPKH | 31 | 67 | 294 |
/// | P2WSH / P2TR | 43 | 67 | 330 |
/// | P2A (`OP_1 <2 bytes>`) | 13 | 67 | 240 |
///
/// An unspendable script — one starting with `OP_RETURN`, or longer than
/// `MAX_SCRIPT_SIZE` — is never dust and returns 0.
///
/// Compute the dust threshold using the default dust relay fee rate.
pub fn dust_threshold(script_pubkey: &bitcoin::ScriptBuf) -> u64 {
    dust_threshold_with_rate(script_pubkey, DUST_RELAY_FEE_RATE)
}

/// The vbytes it costs to spend a witness-program output, per Core's
/// `GetDustThreshold`: `32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4`.
const WITNESS_SPEND_VSIZE: u64 = 32 + 4 + 1 + (107 / 4) + 4;

/// The vbytes it costs to spend a non-witness output, per Core's
/// `GetDustThreshold`: `32 + 4 + 1 + 107 + 4`.
const LEGACY_SPEND_VSIZE: u64 = 32 + 4 + 1 + 107 + 4;

/// Core's `MAX_SCRIPT_SIZE`: a script longer than this can never be run, so an
/// output paying to one is unspendable.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Compute the dust threshold for a given output script and fee rate.
pub fn dust_threshold_with_rate(script_pubkey: &bitcoin::ScriptBuf, fee_rate: u64) -> u64 {
    // Core: `if (txout.scriptPubKey.IsUnspendable()) return 0;`
    if script_pubkey.is_op_return() || script_pubkey.len() > MAX_SCRIPT_SIZE {
        return 0;
    }

    // Core: `GetSerializeSize(txout)` — the 8-byte value, the compact-size
    // length prefix, and the script itself.
    let script_len = script_pubkey.len() as u64;
    let len_prefix: u64 = match script_len {
        0..=252 => 1,
        253..=0xffff => 3,
        _ => 5,
    };
    let output_size = 8 + len_prefix + script_len;

    // Core branches on `IsWitnessProgram`, not on the named script types: an
    // unknown witness version still gets the discounted estimate, and a P2SH
    // or bare output still gets the legacy one.
    let spend_size = if script_pubkey.witness_version().is_some() {
        WITNESS_SPEND_VSIZE
    } else {
        LEGACY_SPEND_VSIZE
    };

    // Core's `CFeeRate::GetFee` rounds up (`EvaluateFeeUp`).
    (output_size + spend_size)
        .saturating_mul(fee_rate)
        .div_ceil(1000)
}

/// Check if a script is a standard output type.
/// Standard types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN,
/// and bare multisig (if configured via `-permitbaremultisig`).
pub fn is_standard_output_script(script: &bitcoin::Script, permit_bare_multisig: bool) -> bool {
    // Core decides this with `Solver` (`src/script/solver.cpp`), and
    // `IsStandard` accepts every type it names except `NONSTANDARD` — with one
    // extra bound on `MULTISIG`. The list below is that set.
    script.is_p2pkh()
        || script.is_p2sh()
        || is_p2pk(script)
        || script.is_op_return()
        // Witness programs: v0 only at the two sizes Core recognises, and any
        // other version at any valid program size (`WITNESS_UNKNOWN`, which
        // also covers pay-to-anchor). A v0 program of some other length is
        // NONSTANDARD in Core and must be here too, so this cannot be written
        // as a bare `witness_version().is_some()`.
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || matches!(
            script.witness_version(),
            Some(v) if v != bitcoin::WitnessVersion::V0
        )
        || (permit_bare_multisig && is_standard_bare_multisig(script))
}

/// Core's `MatchPayToPubkey` (`src/script/solver.cpp`): a single 33- or
/// 65-byte push followed by `OP_CHECKSIG`, with the first byte of the key one
/// of the four valid prefixes.
///
/// rust-bitcoin has no `is_p2pk` predicate, and bare P2PK was simply missing
/// from satd's standard set — a `sendrawtransaction` of one was refused
/// `scriptpubkey`, and `mempool_dust.py` failed on its very first vector.
fn is_p2pk(script: &bitcoin::Script) -> bool {
    let b = script.as_bytes();
    match b.len() {
        // <33-byte push> <key> OP_CHECKSIG
        35 => b[0] == 33 && b[34] == 0xac && matches!(b[1], 0x02 | 0x03),
        // <65-byte push> <key> OP_CHECKSIG
        67 => b[0] == 65 && b[66] == 0xac && matches!(b[1], 0x04 | 0x06 | 0x07),
        _ => false,
    }
}

/// Core's `IsStandard` accepts `MULTISIG` only up to x-of-3: `1 <= n <= 3` and
/// `1 <= m <= n`. `Script::is_multisig` checks the shape but not the bound.
fn is_standard_bare_multisig(script: &bitcoin::Script) -> bool {
    if !script.is_multisig() {
        return false;
    }
    let b = script.as_bytes();
    let (Some(&first), Some(&last)) = (b.first(), b.get(b.len().wrapping_sub(2))) else {
        return false;
    };
    // OP_1..OP_16 encode as 0x51..0x60.
    let m = first.wrapping_sub(0x50);
    let n = last.wrapping_sub(0x50);
    (1..=3).contains(&n) && (1..=n).contains(&m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    /// Regression for the live signet rejection: a 5-in/2-out P2WPKH spend with
    /// fee 412 sat and weight 1108 (vsize 277) pays 1487 sat/kvB (1.49 sat/vB),
    /// comfortably above the 1000 sat/kvB floor — Bitcoin Core accepts it. The
    /// old `fee*1000/weight` formula computed 371 and wrongly rejected it as
    /// "min relay fee not met". Fee rates must divide by vsize, not weight.
    #[test]
    fn fee_rate_uses_vsize_not_weight() {
        assert_eq!(weight_to_vsize(1108), 277);
        assert_eq!(fee_rate_sat_per_kvb(412, 1108), 1487);
        assert!(fee_rate_sat_per_kvb(412, 1108) >= DEFAULT_MIN_RELAY_FEE_RATE);
        // For contrast, the old formula divided by weight (1108) not vsize (277),
        // giving 371 — below the 1000 sat/kvB floor that was in effect when the
        // bug was discovered. `black_box` keeps it a runtime check.
        let buggy_weight_based = std::hint::black_box(412u64) * 1000 / 1108;
        assert_eq!(buggy_weight_based, 371);
        assert!(buggy_weight_based < 1_000); // < old DEFAULT_MIN_RELAY_FEE_RATE
        // Exactly 1 sat/vB sits at 1000 sat/kvB.
        assert_eq!(fee_rate_sat_per_kvb(277, 1108), 1000);
        // vsize rounds up (ceil), matching Core's GetVirtualTransactionSize.
        assert_eq!(weight_to_vsize(1109), 278);
        // Zero weight is handled without dividing by zero.
        assert_eq!(fee_rate_sat_per_kvb(1000, 0), 0);
    }

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

    /// Helper to build a P2WSH script (34 bytes: OP_0 <32>)
    fn p2wsh_script() -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20]; // OP_0 PUSH32
        bytes.extend_from_slice(&[0u8; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    /// Helper to build a pay-to-anchor script (4 bytes: OP_1 <0x4e73>)
    fn p2a_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
    }

    /// Helper to build a witness program at a version satd knows nothing about
    /// (OP_16 <20>), which Core still treats as a witness spend.
    fn unknown_witness_script() -> ScriptBuf {
        let mut bytes = vec![0x60, 0x14]; // OP_16 PUSH20
        bytes.extend_from_slice(&[0u8; 20]);
        ScriptBuf::from_bytes(bytes)
    }

    /// The thresholds Bitcoin Core produces at its default 3000 sat/kvB, from
    /// `GetDustThreshold` in `src/policy/policy.cpp`. Every one of these is a
    /// consensus-adjacent number other software builds against — Lightning
    /// anchor outputs are sized against the 330 row — so they are pinned here
    /// as golden vectors rather than re-derived from satd's own arithmetic.
    #[test]
    fn dust_thresholds_match_bitcoin_core_at_the_default_rate() {
        // (script, output size, spend estimate, Core's threshold)
        let vectors: &[(&str, ScriptBuf, u64, u64, u64)] = &[
            ("P2PKH", p2pkh_script(), 34, 148, 546),
            ("P2SH", p2sh_script(), 32, 148, 540),
            ("P2WPKH", p2wpkh_script(), 31, 67, 294),
            ("P2WSH", p2wsh_script(), 43, 67, 330),
            ("P2TR", p2tr_script(), 43, 67, 330),
            ("P2A", p2a_script(), 13, 67, 240),
            ("unknown witness version", unknown_witness_script(), 31, 67, 294),
            ("bare 10-byte script", ScriptBuf::from_bytes(vec![0xff; 10]), 19, 148, 501),
        ];
        for (name, script, output_size, spend_size, expected) in vectors {
            assert_eq!(
                (output_size + spend_size) * DUST_RELAY_FEE_RATE / 1000,
                *expected,
                "{name}: the vector's own arithmetic disagrees with Core"
            );
            assert_eq!(
                dust_threshold(script),
                *expected,
                "{name}: dust threshold diverges from Bitcoin Core"
            );
        }
    }

    #[test]
    fn a_witness_program_is_classified_by_its_shape_not_by_a_named_type() {
        // Core branches on IsWitnessProgram, so every one of these gets the
        // discounted 67-vbyte spend estimate even though satd has no `is_p2a`
        // or `is_p2w16` predicate.
        for script in [p2a_script(), unknown_witness_script()] {
            assert!(script.witness_version().is_some());
            assert!(!script.is_p2wpkh() && !script.is_p2wsh() && !script.is_p2tr());
            let output_size = 8 + 1 + script.len() as u64;
            assert_eq!(
                dust_threshold(&script),
                (output_size + 67) * DUST_RELAY_FEE_RATE / 1000
            );
        }
    }

    #[test]
    fn a_p2sh_output_is_priced_as_a_legacy_spend() {
        // satd used to charge P2SH a 107-byte spend, producing 417 where Core
        // produces 540 — a 123-sat window in which satd relayed outputs Core
        // called dust.
        assert_eq!(dust_threshold(&p2sh_script()), 540);
    }

    #[test]
    fn the_dust_fee_is_rounded_up_not_truncated() {
        // 98 vbytes at 3001 sat/kvB is 294.098 sats. Core's CFeeRate::GetFee
        // uses EvaluateFeeUp, so the threshold is 295, not 294.
        assert_eq!(dust_threshold_with_rate(&p2wpkh_script(), 3_001), 295);
        // And an exact multiple is not rounded past itself.
        assert_eq!(dust_threshold_with_rate(&p2wpkh_script(), 3_000), 294);
    }

    /// Core's `IsStandard` accepts every type `Solver` names, and satd's set
    /// was missing two of them: bare P2PK — the very first vector in Core's
    /// `mempool_dust.py` — and witness programs at versions satd has no
    /// predicate for, which includes pay-to-anchor.
    #[test]
    fn the_standard_output_set_is_the_one_core_solves() {
        let compressed_p2pk = {
            let mut v = vec![33u8, 0x02];
            v.extend_from_slice(&[0x11; 32]);
            v.push(0xac);
            ScriptBuf::from_bytes(v)
        };
        let uncompressed_p2pk = {
            let mut v = vec![65u8, 0x04];
            v.extend_from_slice(&[0x11; 64]);
            v.push(0xac);
            ScriptBuf::from_bytes(v)
        };
        for (name, script) in [
            ("P2PKH", p2pkh_script()),
            ("P2SH", p2sh_script()),
            ("P2WPKH", p2wpkh_script()),
            ("P2WSH", p2wsh_script()),
            ("P2TR", p2tr_script()),
            ("P2A", p2a_script()),
            ("future witness version", unknown_witness_script()),
            ("OP_RETURN", op_return_script()),
            ("P2PK (compressed)", compressed_p2pk),
            ("P2PK (uncompressed)", uncompressed_p2pk),
        ] {
            assert!(
                is_standard_output_script(&script, false),
                "{name} is standard in Core but not in satd"
            );
        }

        // …and things Core's Solver calls NONSTANDARD stay out.
        for (name, script) in [
            ("bare junk", ScriptBuf::from_bytes(vec![0xff; 10])),
            // A v0 program of a length Core does not recognise: `Solver`
            // falls through to NONSTANDARD rather than WITNESS_UNKNOWN.
            (
                "v0 witness program of the wrong size",
                ScriptBuf::from_bytes({
                    let mut v = vec![0x00, 0x10];
                    v.extend_from_slice(&[0u8; 16]);
                    v
                }),
            ),
            (
                "P2PK with a bad key prefix",
                ScriptBuf::from_bytes({
                    let mut v = vec![33u8, 0x05];
                    v.extend_from_slice(&[0x11; 32]);
                    v.push(0xac);
                    v
                }),
            ),
        ] {
            assert!(
                !is_standard_output_script(&script, false),
                "{name} is nonstandard in Core but standard in satd"
            );
        }
    }

    /// Core bounds bare multisig at x-of-3 (`IsStandard`); `is_multisig`
    /// checks the shape but not the bound.
    #[test]
    fn bare_multisig_is_standard_only_up_to_three_keys() {
        fn multisig(m: u8, n: u8) -> ScriptBuf {
            let mut v = vec![0x50 + m];
            for _ in 0..n {
                v.push(33);
                v.push(0x02);
                v.extend_from_slice(&[0x11; 32]);
            }
            v.push(0x50 + n);
            v.push(0xae); // OP_CHECKMULTISIG
            ScriptBuf::from_bytes(v)
        }
        assert!(is_standard_output_script(&multisig(1, 1), true));
        assert!(is_standard_output_script(&multisig(3, 3), true));
        assert!(
            !is_standard_output_script(&multisig(4, 4), true),
            "4-of-4 exceeds Core's x-of-3 bound"
        );
        assert!(
            !is_standard_output_script(&multisig(1, 1), false),
            "-permitbaremultisig=0 still excludes it"
        );
    }

    #[test]
    fn test_dust_op_return() {
        let script = op_return_script();
        assert!(script.is_op_return());
        // OP_RETURN is unspendable — threshold is always 0
        assert_eq!(dust_threshold(&script), 0);
    }

    #[test]
    fn a_script_too_long_to_run_is_never_dust() {
        // Core's IsUnspendable() also covers size > MAX_SCRIPT_SIZE.
        let script = ScriptBuf::from_bytes(vec![0xac; MAX_SCRIPT_SIZE + 1]);
        assert!(!script.is_op_return());
        assert_eq!(dust_threshold(&script), 0);
        // One byte under the limit is an ordinary (if absurd) spendable output.
        let script = ScriptBuf::from_bytes(vec![0xac; MAX_SCRIPT_SIZE]);
        assert!(dust_threshold(&script) > 0);
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
    fn a_long_script_carries_a_three_byte_length_prefix() {
        // GetSerializeSize(txout) is 8 + CompactSize(len) + len; past 252
        // bytes the prefix grows to three.
        let script = ScriptBuf::from_bytes(vec![0xac; 253]);
        assert_eq!(
            dust_threshold(&script),
            (8 + 3 + 253 + 148) * DUST_RELAY_FEE_RATE / 1000
        );
    }
}
