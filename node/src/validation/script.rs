use bitcoin::{Transaction, TxOut};

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("script-verify-failed: {0}")]
    VerifyFailed(String),
}

/// Trait abstracting script/transaction verification.
/// Phase 1: implemented by ConsensusVerifier (bitcoinconsensus FFI).
/// Phase 2: will be replaced by SimplicityVerifier.
pub trait ScriptVerifier: Send + Sync {
    fn verify_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Result<(), ScriptError>;
}

/// Script verifier backed by Bitcoin Core's libconsensus via FFI.
pub struct ConsensusVerifier;

impl ScriptVerifier for ConsensusVerifier {
    fn verify_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);
        let script_pubkey = prev_output.script_pubkey.as_bytes();
        let amount = prev_output.value.to_sat();

        // Pre-taproot verification flags
        let flags = bitcoinconsensus::VERIFY_P2SH
            | bitcoinconsensus::VERIFY_DERSIG
            | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
            | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
            | bitcoinconsensus::VERIFY_WITNESS
            | bitcoinconsensus::VERIFY_NULLDUMMY;

        bitcoinconsensus::verify_with_flags(
            script_pubkey,
            amount,
            &tx_bytes,
            None,
            input_index,
            flags,
        )
        .map_err(|e| ScriptError::VerifyFailed(format!("{:?}", e)))
    }
}

/// No-op verifier for tests that don't need script checking.
pub struct NoopVerifier;

impl ScriptVerifier for NoopVerifier {
    fn verify_input(
        &self,
        _tx: &Transaction,
        _input_index: usize,
        _prev_output: &TxOut,
    ) -> Result<(), ScriptError> {
        Ok(())
    }
}
