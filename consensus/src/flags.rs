/// Script verification flags matching bitcoinconsensus crate bit positions exactly.
///
/// These values must match the C++ `script_verify_flag_name` enum bit positions.
/// The bitcoinconsensus crate uses `1 << bit_position` for each flag.
pub const VERIFY_NONE: u32 = 0;

/// Evaluate P2SH subscripts (BIP16).
pub const VERIFY_P2SH: u32 = 1 << 0;

/// Passing a non-strict-DER signature or one with undefined hashtype to a
/// checksig operation causes script failure. (not used or intended as a
/// consensus rule).
pub const VERIFY_STRICTENC: u32 = 1 << 1;

/// Passing a non-strict-DER signature to a checksig operation causes script
/// failure (BIP62 rule 1, BIP66).
pub const VERIFY_DERSIG: u32 = 1 << 2;

/// Passing a non-strict-DER signature or one with S > order/2 to a checksig
/// operation causes script failure (BIP62 rule 5).
pub const VERIFY_LOW_S: u32 = 1 << 3;

/// Verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62
/// rule 7, BIP147).
pub const VERIFY_NULLDUMMY: u32 = 1 << 4;

/// Using a non-push operator in the scriptSig causes script failure (BIP62
/// rule 2).
pub const VERIFY_SIGPUSHONLY: u32 = 1 << 5;

/// Require minimal encodings for all push operations and stack number
/// interpretations (BIP62 rule 3, 4).
pub const VERIFY_MINIMALDATA: u32 = 1 << 6;

/// Discourage use of NOPs reserved for upgrades (NOP1-10).
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 7;

/// Require that only a single stack element remains after evaluation (BIP62
/// rule 6).
pub const VERIFY_CLEANSTACK: u32 = 1 << 8;

/// Verify CHECKLOCKTIMEVERIFY (BIP65).
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;

/// Support CHECKSEQUENCEVERIFY opcode (BIP112).
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;

/// Support segregated witness (BIP141).
pub const VERIFY_WITNESS: u32 = 1 << 11;

/// Making v1-v16 witness program non-standard.
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 12;

/// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01
/// or empty vector.
pub const VERIFY_MINIMALIF: u32 = 1 << 13;

/// Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed (BIP146).
pub const VERIFY_NULLFAIL: u32 = 1 << 14;

/// Public keys in segregated witness scripts must be compressed.
pub const VERIFY_WITNESS_PUBKEYTYPE: u32 = 1 << 15;

/// Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts.
pub const VERIFY_CONST_SCRIPTCODE: u32 = 1 << 16;

/// Taproot/Tapscript validation (BIPs 341 & 342).
pub const VERIFY_TAPROOT: u32 = 1 << 17;

/// Making unknown Taproot leaf versions non-standard.
pub const VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: u32 = 1 << 18;

/// Making unknown OP_SUCCESS non-standard.
pub const VERIFY_DISCOURAGE_OP_SUCCESS: u32 = 1 << 19;

/// Making unknown public key versions (in BIP 342 scripts) non-standard.
pub const VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: u32 = 1 << 20;

/// Composite: all pre-taproot consensus flags.
pub const VERIFY_ALL_PRE_TAPROOT: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// Maximum valid flag bit.
pub const MAX_FLAGS_BIT: u32 = 20;

/// Mask of all recognized flags.
pub const ALL_FLAGS: u32 = (1u32 << (MAX_FLAGS_BIT + 1)) - 1;

/// satd extension, not a Bitcoin Core flag: apply [`VERIFY_MINIMALIF`]'s rule
/// to base scripts (bare and P2SH) as well as witness v0. BIP 322 lists
/// MINIMALIF among its required rules for every script, where Core's
/// interpreter applies it only to witness v0 (tapscript enforces it by
/// consensus).
///
/// It is deliberately outside [`ALL_FLAGS`], so [`valid_flags`] refuses it and
/// the crate's entry points (`verify`, `verify_transaction`) answer
/// `ErrInvalidFlags` if it is ever passed. Block
/// and mempool validation go through those, so they cannot set it. Only a
/// caller of [`crate::verify::verify_script`] can. Core's script-test flag
/// sets are built from `ALL_FLAGS` and never include it either.
pub const VERIFY_MINIMALIF_BASE: u32 = 1 << 31;

/// Check if a flags value contains only recognized bits.
pub fn valid_flags(flags: u32) -> bool {
    flags & !ALL_FLAGS == 0
}

/// Helper to check if a specific flag is set.
#[inline]
pub fn has_flag(flags: u32, flag: u32) -> bool {
    flags & flag != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// libbitcoinconsensus's `VERIFY_ALL` without taproot: P2SH, DERSIG,
    /// NULLDUMMY, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY and WITNESS, bits
    /// 0, 2, 4, 9, 10 and 11 of Core's `script_verify_flag_name`. A literal,
    /// so the check does not repeat the expression it pins.
    #[test]
    fn all_pre_taproot_is_libconsensus_verify_all_without_taproot() {
        assert_eq!(VERIFY_ALL_PRE_TAPROOT, 0b1110_0001_0101);
    }
}
