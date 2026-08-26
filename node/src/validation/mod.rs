pub mod block;
pub mod pow;
pub mod script;
pub mod signet;
pub mod tx;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("high-hash")]
    BadProofOfWork,
    #[error("time-too-old")]
    TimeTooOld,
    #[error("time-too-new")]
    TimeTooNew,
    #[error("bad-version(0x{0:08x})")]
    BadVersion(u32),
    #[error("bad-txnmrklroot")]
    BadMerkleRoot,
    #[error("bad-txns-duplicate")]
    BadTxDuplicate,
    #[error("bad-cb-missing")]
    NoCoinbase,
    #[error("bad-cb-multiple")]
    MultipleCoinbase,
    #[error("bad-blk-length")]
    OversizedBlock,
    // Core distinguishes the stripped-size limit in `CheckBlock`
    // (`bad-blk-length`, above) from `ContextualCheckBlock`'s full-weight
    // limit (`bad-blk-weight`) — the latter is only reachable when witness
    // bytes push a length-legal block over the weight cap (#548).
    #[error("bad-blk-weight")]
    OverweightBlock,
    #[error("bad-diffbits")]
    BadDifficulty,
    // Core folds the empty-block case into its size-limits check, which emits
    // `bad-blk-length` (the same reason as an over-weight block). We keep a
    // distinct variant for internal clarity but match Core's reject string.
    #[error("bad-blk-length")]
    EmptyBlock,
    #[error("bad-txns-vin-empty")]
    BadTxNoInputs,
    #[error("bad-txns-vout-empty")]
    BadTxNoOutputs,
    #[error("bad-txns-oversize")]
    BadTxOversize,
    // Core distinguishes a single output exceeding MAX_MONEY
    // (`bad-txns-vout-toolarge`) from the running/total sum exceeding it
    // (`bad-txns-txouttotal-toolarge`). The negative-value case
    // (`bad-txns-vout-negative`) cannot occur with an unsigned amount type.
    #[error("bad-txns-vout-toolarge")]
    BadTxOutputTooLarge,
    #[error("bad-txns-txouttotal-toolarge")]
    BadTxOutputTotalTooLarge,
    #[error("bad-txns-inputs-duplicate")]
    BadTxDuplicateInput,
    #[error("bad-cb-length")]
    BadTxCoinbaseSize,
    #[error("bad-txns-prevout-null")]
    BadTxNullInput,
    #[error("bad-witness-merkle-match")]
    BadWitnessCommitment,
    /// The coinbase witness is not exactly one 32-byte item while a BIP 141
    /// commitment output is present. Core's `bad-witness-nonce-size`.
    #[error("bad-witness-nonce-size")]
    BadWitnessNonceSize,
    /// A transaction carries witness data in a block that commits to none.
    /// Core's `unexpected-witness`.
    #[error("unexpected-witness")]
    UnexpectedWitness,
    #[error("bad-signet-solution")]
    BadSignetSolution,
    #[error("time-timewarp-attack")]
    TimewarpAttack,
}
