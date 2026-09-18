//! PSBT key types.
//!
//! BIP 174 (base), BIP 370 (version 2), BIP 371 (taproot) and BIP 375
//! (silent payments). A key type is itself a compact size, so these are
//! `u64` rather than `u8`; every type defined so far fits in one byte.

/// `psbt` + `0xff`.
pub const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global map key types.
pub mod global {
    pub const UNSIGNED_TX: u64 = 0x00;
    pub const XPUB: u64 = 0x01;
    /// BIP 370, version 2 only.
    pub const TX_VERSION: u64 = 0x02;
    /// BIP 370, version 2 only.
    pub const FALLBACK_LOCKTIME: u64 = 0x03;
    /// BIP 370, version 2 only.
    pub const INPUT_COUNT: u64 = 0x04;
    /// BIP 370, version 2 only.
    pub const OUTPUT_COUNT: u64 = 0x05;
    /// BIP 370, version 2 only.
    pub const TX_MODIFIABLE: u64 = 0x06;
    /// BIP 375, version 2 only. Key data is a 33-byte scan key.
    pub const SP_ECDH_SHARE: u64 = 0x07;
    /// BIP 375, version 2 only. Key data is a 33-byte scan key.
    pub const SP_DLEQ: u64 = 0x08;
    pub const VERSION: u64 = 0xfb;
    pub const PROPRIETARY: u64 = 0xfc;

    /// The version 2 fields a version 0 PSBT must not carry.
    pub const V2_ONLY: [u64; 5] = [
        TX_VERSION,
        FALLBACK_LOCKTIME,
        INPUT_COUNT,
        OUTPUT_COUNT,
        TX_MODIFIABLE,
    ];
}

/// Per-input map key types.
pub mod input {
    pub const NON_WITNESS_UTXO: u64 = 0x00;
    pub const WITNESS_UTXO: u64 = 0x01;
    pub const PARTIAL_SIG: u64 = 0x02;
    pub const SIGHASH_TYPE: u64 = 0x03;
    pub const REDEEM_SCRIPT: u64 = 0x04;
    pub const WITNESS_SCRIPT: u64 = 0x05;
    pub const BIP32_DERIVATION: u64 = 0x06;
    pub const FINAL_SCRIPTSIG: u64 = 0x07;
    pub const FINAL_SCRIPTWITNESS: u64 = 0x08;
    pub const POR_COMMITMENT: u64 = 0x09;
    pub const RIPEMD160: u64 = 0x0a;
    pub const SHA256: u64 = 0x0b;
    pub const HASH160: u64 = 0x0c;
    pub const HASH256: u64 = 0x0d;
    /// BIP 370, version 2 only.
    pub const PREVIOUS_TXID: u64 = 0x0e;
    /// BIP 370, version 2 only.
    pub const OUTPUT_INDEX: u64 = 0x0f;
    /// BIP 370, version 2 only.
    pub const SEQUENCE: u64 = 0x10;
    /// BIP 370, version 2 only.
    pub const REQUIRED_TIME_LOCKTIME: u64 = 0x11;
    /// BIP 370, version 2 only.
    pub const REQUIRED_HEIGHT_LOCKTIME: u64 = 0x12;
    pub const TAP_KEY_SIG: u64 = 0x13;
    pub const TAP_SCRIPT_SIG: u64 = 0x14;
    pub const TAP_LEAF_SCRIPT: u64 = 0x15;
    pub const TAP_BIP32_DERIVATION: u64 = 0x16;
    pub const TAP_INTERNAL_KEY: u64 = 0x17;
    pub const TAP_MERKLE_ROOT: u64 = 0x18;
    /// BIP 375, version 2 only. Key data is a 33-byte scan key.
    pub const SP_ECDH_SHARE: u64 = 0x1d;
    /// BIP 375, version 2 only. Key data is a 33-byte scan key.
    pub const SP_DLEQ: u64 = 0x1e;
    pub const PROPRIETARY: u64 = 0xfc;

    /// The version 2 fields a version 0 PSBT must not carry.
    pub const V2_ONLY: [u64; 5] = [
        PREVIOUS_TXID,
        OUTPUT_INDEX,
        SEQUENCE,
        REQUIRED_TIME_LOCKTIME,
        REQUIRED_HEIGHT_LOCKTIME,
    ];
}

/// Per-output map key types.
pub mod output {
    pub const REDEEM_SCRIPT: u64 = 0x00;
    pub const WITNESS_SCRIPT: u64 = 0x01;
    pub const BIP32_DERIVATION: u64 = 0x02;
    /// BIP 370, version 2 only.
    pub const AMOUNT: u64 = 0x03;
    /// BIP 370, version 2 only. BIP 375 makes it optional for an output that
    /// carries `SP_V0_INFO` and whose script has not been computed yet.
    pub const SCRIPT: u64 = 0x04;
    pub const TAP_INTERNAL_KEY: u64 = 0x05;
    pub const TAP_TREE: u64 = 0x06;
    pub const TAP_BIP32_DERIVATION: u64 = 0x07;
    /// BIP 375, version 2 only. 33-byte scan key followed by 33-byte spend key.
    pub const SP_V0_INFO: u64 = 0x09;
    /// BIP 375, version 2 only. A little-endian `u32`.
    pub const SP_V0_LABEL: u64 = 0x0a;
    pub const PROPRIETARY: u64 = 0xfc;

    /// The version 2 fields a version 0 PSBT must not carry.
    pub const V2_ONLY: [u64; 2] = [AMOUNT, SCRIPT];
}

/// BIP 370's `PSBT_GLOBAL_TX_MODIFIABLE` bits.
pub mod modifiable {
    pub const INPUTS: u8 = 0x01;
    pub const OUTPUTS: u8 = 0x02;
    pub const HAS_SIGHASH_SINGLE: u8 = 0x04;
}

/// The boundary between a height lock time and a time lock time (BIP 65).
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
