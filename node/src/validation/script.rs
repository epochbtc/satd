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
    /// `height` is used to determine which softfork rules are active.
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        height: u32,
    ) -> Result<(), ScriptError>;

    /// If this verifier runs in shadow mode, return the shadow engine.
    /// `connect_block` uses this to run primary and shadow in parallel at
    /// the block level instead of sequentially per transaction.
    fn shadow_verifier(&self) -> Option<&dyn ScriptVerifier> {
        None
    }
}

/// Softfork activation heights (mainnet). Verification flags are cumulative.
const BIP16_HEIGHT: u32 = 173_805;  // P2SH
const BIP66_HEIGHT: u32 = 363_725;  // Strict DER signatures
const BIP65_HEIGHT: u32 = 388_381;  // CHECKLOCKTIMEVERIFY
const BIP112_HEIGHT: u32 = 419_328; // CHECKSEQUENCEVERIFY
const SEGWIT_HEIGHT: u32 = 481_824; // Segregated Witness + NULLDUMMY
const TAPROOT_HEIGHT: u32 = 709_632; // Taproot

/// Script verifier backed by Bitcoin Core's libconsensus via FFI.
/// Supports all consensus rules including taproot.
pub struct ConsensusVerifier;

impl ScriptVerifier for ConsensusVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        height: u32,
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);

        // Compute verification flags based on softfork activation heights
        let mut flags = 0u32;
        if height >= BIP16_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_P2SH;
        }
        if height >= BIP66_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_DERSIG;
        }
        if height >= BIP65_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if height >= BIP112_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;
        }
        if height >= SEGWIT_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_WITNESS
                | bitcoinconsensus::VERIFY_NULLDUMMY;
        }
        if height >= TAPROOT_HEIGHT {
            flags |= bitcoinconsensus::VERIFY_TAPROOT;
        }

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
        _height: u32,
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
        height: u32,
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);

        let mut flags = 0u32;
        if height >= BIP16_HEIGHT {
            flags |= consensus::VERIFY_P2SH;
        }
        if height >= BIP66_HEIGHT {
            flags |= consensus::VERIFY_DERSIG;
        }
        if height >= BIP65_HEIGHT {
            flags |= consensus::VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if height >= BIP112_HEIGHT {
            flags |= consensus::VERIFY_CHECKSEQUENCEVERIFY;
        }
        if height >= SEGWIT_HEIGHT {
            flags |= consensus::VERIFY_WITNESS | consensus::VERIFY_NULLDUMMY;
        }
        if height >= TAPROOT_HEIGHT {
            flags |= consensus::VERIFY_TAPROOT;
        }

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

/// Shadow verifier: exposes primary and shadow engines so `connect_block`
/// can run them in parallel at the block level (not per-transaction).
///
/// `verify_transaction()` only runs the primary engine. The shadow engine
/// is returned by `shadow_verifier()` for parallel execution in connect_block.
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
        height: u32,
    ) -> Result<(), ScriptError> {
        // Only run primary — shadow runs in parallel at the block level
        self.primary.verify_transaction(tx, prev_outputs, height)
    }

    fn shadow_verifier(&self) -> Option<&dyn ScriptVerifier> {
        Some(&*self.shadow)
    }
}
