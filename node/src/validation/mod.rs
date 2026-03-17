pub mod block;
pub mod pow;

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
}
