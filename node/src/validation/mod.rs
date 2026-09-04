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

impl ValidationError {
    /// Whether this rejection is *mutation-class*: the block's data did not
    /// match what the proof of work commits to, so a different — possibly
    /// honest — block can share this block hash.
    ///
    /// A verdict from one of these must never be written down against the
    /// hash. Core states the rule in `Chainstate::InvalidBlockFound`
    /// (`src/validation.cpp`), which skips `BLOCK_FAILED_VALID` entirely when
    /// `state.GetResult() == BlockValidationResult::BLOCK_MUTATED`, and
    /// repeats it at the `ActivateBestChainStep` and `AcceptBlock` call sites.
    /// The reason is CVE-2012-2459: a merkle tree that duplicates a trailing
    /// subtree hashes to the same root as the honest tree, so an attacker can
    /// hand us a malleated copy of a valid block. Persisting `Invalid` for it
    /// would make the honest block permanently unacceptable — and because the
    /// parent-status guard rejects descendants too, the node would wedge off
    /// the real chain until an operator ran `reconsiderblock`.
    ///
    /// The set matches Core's five `BLOCK_MUTATED` sites one for one.
    pub fn is_mutation_class(&self) -> bool {
        matches!(
            self,
            // "bad-txnmrklroot"
            Self::BadMerkleRoot
                // "bad-txns-duplicate"
                | Self::BadTxDuplicate
                // "bad-witness-merkle-match"
                | Self::BadWitnessCommitment
                // "bad-witness-nonce-size"
                | Self::BadWitnessNonceSize
                // "unexpected-witness"
                | Self::UnexpectedWitness
        )
    }
}
