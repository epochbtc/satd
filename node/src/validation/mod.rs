pub mod block;
pub mod pow;
pub mod script;
pub mod signet;
pub mod tx;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("bad-pow")]
    BadProofOfWork,
    #[error("time-too-old")]
    TimeTooOld,
    #[error("bad-txnmrklroot")]
    BadMerkleRoot,
    #[error("bad-cb-missing")]
    NoCoinbase,
    #[error("bad-cb-multiple")]
    MultipleCoinbase,
    #[error("bad-blk-length")]
    OversizedBlock,
    #[error("bad-diffbits")]
    BadDifficulty,
    #[error("bad-txns-empty")]
    EmptyBlock,
    #[error("bad-txns-vin-empty")]
    BadTxNoInputs,
    #[error("bad-txns-vout-empty")]
    BadTxNoOutputs,
    #[error("bad-txns-vout-negative")]
    BadTxOutputValue,
    #[error("bad-txns-inputs-duplicate")]
    BadTxDuplicateInput,
    #[error("bad-cb-length")]
    BadTxCoinbaseSize,
    #[error("bad-txns-prevout-null")]
    BadTxNullInput,
    #[error("bad-witness-commitment")]
    BadWitnessCommitment,
    #[error("bad-signet-solution")]
    BadSignetSolution,
    #[error("time-timewarp-attack")]
    TimewarpAttack,
}
