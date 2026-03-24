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

/// Shadow verifier: runs both C++ FFI and Rust engines, compares results,
/// always returns the C++ result for consensus safety.
///
/// Any mismatch is logged at ERROR level with full transaction details
/// for offline debugging.
pub struct ShadowVerifier;

impl ScriptVerifier for ShadowVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
    ) -> Result<(), ScriptError> {
        // Run C++ FFI (authoritative)
        let cpp_result = ConsensusVerifier.verify_transaction(tx, prev_outputs);

        // Run Rust engine (shadow)
        let rust_result = RustVerifier.verify_transaction(tx, prev_outputs);

        // Compare results
        match (&cpp_result, &rust_result) {
            (Ok(()), Ok(())) => {} // Both agree: valid
            (Err(_), Err(_)) => {} // Both agree: invalid
            (Ok(()), Err(e)) => {
                // CRITICAL: Rust engine rejected something C++ accepted
                tracing::error!(
                    "SHADOW MISMATCH: C++ accepted but Rust REJECTED: {} (txid={})",
                    e,
                    tx.compute_txid(),
                );
            }
            (Err(e), Ok(())) => {
                // Rust engine accepted something C++ rejected
                tracing::error!(
                    "SHADOW MISMATCH: C++ REJECTED but Rust accepted: {} (txid={})",
                    e,
                    tx.compute_txid(),
                );
            }
        }

        // Always return C++ result for consensus safety
        cpp_result
    }
}
