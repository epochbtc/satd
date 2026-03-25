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
    /// Verify all inputs of a transaction against their previous outputs.
    /// `prev_outputs` must have one entry per input, in the same order.
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError>;
}

/// Script verifier backed by Bitcoin Core's libconsensus via FFI.
/// Supports all consensus rules including taproot.
pub struct ConsensusVerifier;

impl ScriptVerifier for ConsensusVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);

        // Full verification flags including taproot
        let flags = bitcoinconsensus::VERIFY_P2SH
            | bitcoinconsensus::VERIFY_DERSIG
            | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
            | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
            | bitcoinconsensus::VERIFY_WITNESS
            | bitcoinconsensus::VERIFY_NULLDUMMY
            | bitcoinconsensus::VERIFY_TAPROOT;

        // Build spent outputs array for taproot (needed for signature hash)
        let script_bytes: Vec<Vec<u8>> = prev_outputs
            .iter()
            .map(|o| o.script_pubkey.as_bytes().to_vec())
            .collect();

        let utxos: Vec<bitcoinconsensus::Utxo> = prev_outputs
            .iter()
            .enumerate()
            .map(|(i, o)| bitcoinconsensus::Utxo {
                script_pubkey: script_bytes[i].as_ptr(),
                script_pubkey_len: script_bytes[i].len() as u32,
                value: o.value.to_sat() as i64,
            })
            .collect();

        for (input_index, prev_out) in prev_outputs.iter().enumerate().take(tx.input.len()) {
            let script_pubkey = prev_out.script_pubkey.as_bytes();
            let amount = prev_out.value.to_sat();

            bitcoinconsensus::verify_with_flags(
                script_pubkey,
                amount,
                &tx_bytes,
                Some(&utxos),
                input_index,
                flags,
            )
            .map_err(|e| ScriptError::VerifyFailed(format!("input {}: {:?}", input_index, e)))?;
        }

        Ok(())
    }
}

/// No-op verifier for tests that don't need script checking.
pub struct NoopVerifier;

impl ScriptVerifier for NoopVerifier {
    fn verify_transaction(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shadow consensus: Rust-native verifier + shadow mode comparator
// ---------------------------------------------------------------------------

/// Script verifier backed by the pure Rust `consensus` crate.
pub struct RustVerifier;

impl ScriptVerifier for RustVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);

        let flags = consensus::VERIFY_P2SH
            | consensus::VERIFY_DERSIG
            | consensus::VERIFY_CHECKLOCKTIMEVERIFY
            | consensus::VERIFY_CHECKSEQUENCEVERIFY
            | consensus::VERIFY_WITNESS
            | consensus::VERIFY_NULLDUMMY
            | consensus::VERIFY_TAPROOT;

        let script_bytes: Vec<Vec<u8>> = prev_outputs
            .iter()
            .map(|o| o.script_pubkey.as_bytes().to_vec())
            .collect();

        let utxos: Vec<consensus::Utxo> = prev_outputs
            .iter()
            .enumerate()
            .map(|(i, o)| consensus::Utxo {
                script_pubkey: script_bytes[i].as_ptr(),
                script_pubkey_len: script_bytes[i].len() as u32,
                value: o.value.to_sat() as i64,
            })
            .collect();

        for (input_index, prev_out) in prev_outputs.iter().enumerate().take(tx.input.len()) {
            let script_pubkey = prev_out.script_pubkey.as_bytes();
            let amount = prev_out.value.to_sat();

            consensus::verify_with_flags(
                script_pubkey,
                amount,
                &tx_bytes,
                Some(&utxos),
                input_index,
                flags,
            )
            .map_err(|e| {
                ScriptError::VerifyFailed(format!("rust input {}: {}", input_index, e))
            })?;
        }

        Ok(())
    }
}

/// Shadow verifier: runs two engines, compares results, returns the
/// primary engine's result. Mismatches are logged at ERROR level.
///
/// Use `ShadowVerifier::new(primary, shadow)` to configure which engine
/// is authoritative and which runs in shadow mode.
pub struct ShadowVerifier {
    primary: Box<dyn ScriptVerifier>,
    shadow: Box<dyn ScriptVerifier>,
}

impl ShadowVerifier {
    pub fn new(primary: Box<dyn ScriptVerifier>, shadow: Box<dyn ScriptVerifier>) -> Self {
        Self { primary, shadow }
    }
}

impl ScriptVerifier for ShadowVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError> {
        let primary_result = self.primary.verify_transaction(tx, prev_outputs);
        let shadow_result = self.shadow.verify_transaction(tx, prev_outputs);

        match (&primary_result, &shadow_result) {
            (Ok(()), Ok(())) | (Err(_), Err(_)) => {} // agree
            (Ok(()), Err(e)) => {
                tracing::error!(
                    "SHADOW MISMATCH: primary accepted but shadow REJECTED: {} (txid={})",
                    e,
                    tx.compute_txid(),
                );
            }
            (Err(e), Ok(())) => {
                tracing::error!(
                    "SHADOW MISMATCH: primary REJECTED but shadow accepted: {} (txid={})",
                    e,
                    tx.compute_txid(),
                );
            }
        }

        primary_result
    }
}
