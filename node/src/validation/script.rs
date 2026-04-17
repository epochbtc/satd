use bitcoin::{Transaction, TxOut};

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("script-verify-failed: {0}")]
    VerifyFailed(String),
}

/// Identifies which concrete verifier backs the authoritative (primary)
/// decision path. Used so components like the prefetch pipeline can match
/// whichever engine the user's config selected as primary — otherwise a
/// prefetch worker's "script OK" say-so (which lets the connect thread
/// skip primary verify) would override the user's chosen authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrimaryEngine {
    /// Bitcoin Core's libbitcoinconsensus (C++ FFI).
    Cpp,
    /// Pure Rust consensus engine.
    Rust,
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
    /// Currently unused — ShadowVerifier handles async dispatch internally.
    fn shadow_verifier(&self) -> Option<&dyn ScriptVerifier> {
        None
    }

    /// Dispatch a transaction for shadow-only verification (no primary).
    /// Called for speculatively pre-verified transactions that were already
    /// verified by the primary engine on a prefetch worker. The shadow
    /// engine still needs to see them for mismatch detection.
    /// Default: no-op (non-shadow verifiers have nothing to dispatch).
    fn dispatch_shadow(&self, _tx: &Transaction, _prev_outputs: &[TxOut], _height: u32) {}

    /// Which concrete engine performs authoritative verification.
    /// Default: `Cpp`. `RustVerifier` overrides; `ShadowVerifier` delegates
    /// to its inner primary.
    fn primary_engine(&self) -> PrimaryEngine {
        PrimaryEngine::Cpp
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

        // Batch API: passes &Transaction so we don't re-deserialize per
        // input, and shares a single SighashCache across inputs (BIP143
        // hashPrevouts / hashSequence / hashOutputs are tx-wide).
        consensus::verify_transaction(tx, prev_outputs, flags).map_err(|(idx, e)| {
            ScriptError::VerifyFailed(format!("rust input {idx}: {e}"))
        })
    }

    fn primary_engine(&self) -> PrimaryEngine {
        PrimaryEngine::Rust
    }
}

/// Shadow verifier: runs the primary engine synchronously in the hot path,
/// dispatches shadow verification to a background thread pool asynchronously.
///
/// The connect thread never blocks on shadow results. Mismatches are logged
/// by the background workers. This makes shadow mode essentially free in
/// wall-clock terms — shadow uses spare CPU but doesn't slow block connection.
pub struct ShadowVerifier {
    primary: Box<dyn ScriptVerifier>,
    shadow_tx: crossbeam_channel::Sender<ShadowWork>,
    queue_size: usize,
    _workers: Vec<std::thread::JoinHandle<()>>,
}

/// Work item for the shadow verification background pool.
struct ShadowWork {
    tx_bytes: Vec<u8>,
    prev_outputs: Vec<TxOut>,
    height: u32,
    txid: bitcoin::Txid,
}

impl ShadowVerifier {
    /// Create a new shadow verifier.
    /// `primary_name` / `shadow_name` are used in mismatch log messages
    /// (e.g. "cpp", "rust").
    pub fn new(
        primary: Box<dyn ScriptVerifier>,
        shadow: Box<dyn ScriptVerifier>,
        primary_name: &str,
        shadow_name: &str,
        queue_size: usize,
        num_workers: usize,
    ) -> Self {
        let (tx, rx) = crossbeam_channel::bounded::<ShadowWork>(queue_size);
        let shadow = std::sync::Arc::new(shadow);
        let primary_label = primary_name.to_string();
        let shadow_label = shadow_name.to_string();

        tracing::info!(
            queue_size,
            num_workers,
            "Shadow verification pool started"
        );
        let mut workers = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let w_rx = rx.clone();
            let w_shadow = shadow.clone();
            let w_primary_label = primary_label.clone();
            let w_shadow_label = shadow_label.clone();
            workers.push(std::thread::spawn(move || {
                while let Ok(work) = w_rx.recv() {
                    let tx: Transaction = match bitcoin::consensus::deserialize(&work.tx_bytes) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if let Err(e) = w_shadow.verify_transaction(&tx, &work.prev_outputs, work.height) {
                        // Identify which input(s) failed and log details
                        let mut failed_inputs = Vec::new();
                        for (idx, prev_out) in work.prev_outputs.iter().enumerate() {
                            let script_type = if prev_out.script_pubkey.is_p2pkh() {
                                "P2PKH"
                            } else if prev_out.script_pubkey.is_p2sh() {
                                "P2SH"
                            } else if prev_out.script_pubkey.is_p2wpkh() {
                                "P2WPKH"
                            } else if prev_out.script_pubkey.is_p2wsh() {
                                "P2WSH"
                            } else if prev_out.script_pubkey.is_p2tr() {
                                "P2TR"
                            } else {
                                "other"
                            };
                            failed_inputs.push(format!(
                                "input[{}]: {} sats, {} ({}B script)",
                                idx,
                                prev_out.value.to_sat(),
                                script_type,
                                prev_out.script_pubkey.len(),
                            ));
                        }
                        tracing::error!(
                            "SHADOW MISMATCH at height {}: {} (authoritative) accepted but {} (shadow) REJECTED\n  \
                             txid: {}\n  \
                             error: {}\n  \
                             inputs: {} total, witnesses: {}\n  \
                             details: [{}]",
                            work.height,
                            w_primary_label,
                            w_shadow_label,
                            work.txid,
                            e,
                            tx.input.len(),
                            tx.input.iter().filter(|i| !i.witness.is_empty()).count(),
                            failed_inputs.join(", "),
                        );
                    }
                }
            }));
        }

        Self {
            primary,
            shadow_tx: tx,
            queue_size,
            _workers: workers,
        }
    }
}

impl ScriptVerifier for ShadowVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        height: u32,
    ) -> Result<(), ScriptError> {
        // Run primary synchronously — this is the hot path
        let result = self.primary.verify_transaction(tx, prev_outputs, height);

        // On primary success, dispatch shadow verification asynchronously.
        if result.is_ok() {
            let work = ShadowWork {
                tx_bytes: bitcoin::consensus::serialize(tx),
                prev_outputs: prev_outputs.to_vec(),
                height,
                txid: tx.compute_txid(),
            };
            if let Err(crossbeam_channel::TrySendError::Full(_)) = self.shadow_tx.try_send(work) {
                tracing::warn!(
                    height,
                    queue_size = self.queue_size,
                    "Shadow verification queue full — dropping tx. \
                     Shadow workers may be falling behind."
                );
            }
        }

        result
    }

    fn dispatch_shadow(&self, tx: &Transaction, prev_outputs: &[TxOut], height: u32) {
        let work = ShadowWork {
            tx_bytes: bitcoin::consensus::serialize(tx),
            prev_outputs: prev_outputs.to_vec(),
            height,
            txid: tx.compute_txid(),
        };
        if let Err(crossbeam_channel::TrySendError::Full(_)) = self.shadow_tx.try_send(work) {
            tracing::warn!(
                height,
                queue_size = self.queue_size,
                "Shadow verification queue full on dispatch_shadow — dropping tx."
            );
        }
    }

    fn primary_engine(&self) -> PrimaryEngine {
        // Delegate to the inner primary so callers see the real authoritative
        // engine, not "Cpp" just because ShadowVerifier is the outer type.
        self.primary.primary_engine()
    }
}

impl Drop for ShadowVerifier {
    fn drop(&mut self) {
        // Drop the sender to signal workers to exit
        // Workers will drain remaining items and stop on recv error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PrimaryEngine identifies the authoritative engine so prefetch can
    // match it. Regression: ShadowVerifier must report its *inner* primary,
    // not the default (Cpp) that would come from the trait's base impl.
    #[test]
    fn test_primary_engine_reports_correct_authority() {
        assert_eq!(ConsensusVerifier.primary_engine(), PrimaryEngine::Cpp);
        assert_eq!(RustVerifier.primary_engine(), PrimaryEngine::Rust);
        assert_eq!(NoopVerifier.primary_engine(), PrimaryEngine::Cpp);

        // rust-shadow layout: cpp authoritative, rust shadow -> Cpp
        let rust_shadow = ShadowVerifier::new(
            Box::new(ConsensusVerifier),
            Box::new(RustVerifier),
            "cpp",
            "rust",
            16,
            1,
        );
        assert_eq!(rust_shadow.primary_engine(), PrimaryEngine::Cpp);

        // cpp-shadow layout: rust authoritative, cpp shadow -> Rust
        let cpp_shadow = ShadowVerifier::new(
            Box::new(RustVerifier),
            Box::new(ConsensusVerifier),
            "rust",
            "cpp",
            16,
            1,
        );
        assert_eq!(cpp_shadow.primary_engine(), PrimaryEngine::Rust);
    }
}

