use bitcoin::{Network, Transaction, TxOut};

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

/// Trait abstracting script/transaction verification. Implemented by
/// `ConsensusVerifier` (bitcoinconsensus FFI), `RustVerifier` (native), and
/// `ShadowVerifier` (parity-checked dual-engine).
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

/// Per-network softfork activation heights for script-verification flags.
/// Verification flags are cumulative: once a fork's height is reached its
/// flag stays on for all later blocks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ActivationHeights {
    /// BIP 16 (P2SH).
    pub p2sh: u32,
    /// BIP 66 (strict DER signatures).
    pub dersig: u32,
    /// BIP 65 (CHECKLOCKTIMEVERIFY).
    pub cltv: u32,
    /// BIP 112 (CHECKSEQUENCEVERIFY).
    pub csv: u32,
    /// BIP 141/143 (segregated witness) + BIP 147 (NULLDUMMY).
    pub segwit: u32,
    /// BIP 341/342 (taproot).
    pub taproot: u32,
}

/// Softfork activation heights for `network`, mirroring Bitcoin Core's
/// buried-deployment heights (`chainparams.cpp`).
///
/// Core's modern `GetBlockScriptFlags` applies P2SH/WITNESS/TAPROOT to every
/// block on every network and carves out the three historical violators by
/// hash (`script_flag_exceptions`). The height-gating used here reproduces
/// that without per-hash carve-outs: each P2SH/taproot gate sits just above
/// its network's exception block (mainnet BIP16 exception at 170_060 <
/// 173_805, mainnet taproot exception at 692_261 < 709_632, testnet3 BIP16
/// exception at 394 < 395), and the canonical chains contain no other
/// violations below the gates — Core itself validates them flags-on.
///
/// Signet, testnet4, and regtest activate everything from genesis (all of
/// Core's buried heights there are <= 1, and the genesis block is never
/// script-verified), so a P2WPKH or P2TR output is NEVER anyone-can-spend
/// on those networks.
pub fn activation_heights(network: Network) -> ActivationHeights {
    match network {
        Network::Bitcoin => ActivationHeights {
            p2sh: 173_805,
            dersig: 363_725,
            cltv: 388_381,
            csv: 419_328,
            segwit: 481_824,
            taproot: 709_632,
        },
        // Testnet3. Taproot is gated with segwit rather than at 0: a taproot
        // spend is a witness spend, so the flag is inert below the witness
        // gate, and libconsensus rejects TAPROOT-without-WITNESS flag sets.
        Network::Testnet => ActivationHeights {
            p2sh: 395,
            dersig: 330_776,
            cltv: 581_885,
            csv: 770_112,
            segwit: 834_624,
            taproot: 834_624,
        },
        // Signet, Testnet4, Regtest: always active.
        _ => ActivationHeights {
            p2sh: 0,
            dersig: 0,
            cltv: 0,
            csv: 0,
            segwit: 0,
            taproot: 0,
        },
    }
}

// The two engines must agree on flag bit values for `script_verify_flags`
// to feed either one. Both mirror Core's script-flag bits; pin it at
// compile time.
const _: () = {
    assert!(consensus::VERIFY_P2SH == bitcoinconsensus::VERIFY_P2SH);
    assert!(consensus::VERIFY_DERSIG == bitcoinconsensus::VERIFY_DERSIG);
    assert!(consensus::VERIFY_NULLDUMMY == bitcoinconsensus::VERIFY_NULLDUMMY);
    assert!(
        consensus::VERIFY_CHECKLOCKTIMEVERIFY == bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
    );
    assert!(
        consensus::VERIFY_CHECKSEQUENCEVERIFY == bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
    );
    assert!(consensus::VERIFY_WITNESS == bitcoinconsensus::VERIFY_WITNESS);
    assert!(consensus::VERIFY_TAPROOT == bitcoinconsensus::VERIFY_TAPROOT);
};

/// Script-verification flags for a block at `height` on `network`.
/// Shared by both engines (flag bit values are identical — pinned above).
pub fn script_verify_flags(network: Network, height: u32) -> u32 {
    let h = activation_heights(network);
    let mut flags = 0u32;
    if height >= h.p2sh {
        flags |= consensus::VERIFY_P2SH;
    }
    if height >= h.dersig {
        flags |= consensus::VERIFY_DERSIG;
    }
    if height >= h.cltv {
        flags |= consensus::VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= h.csv {
        flags |= consensus::VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= h.segwit {
        flags |= consensus::VERIFY_WITNESS | consensus::VERIFY_NULLDUMMY;
    }
    if height >= h.taproot {
        flags |= consensus::VERIFY_TAPROOT;
    }
    flags
}

/// Script verifier backed by Bitcoin Core's libconsensus via FFI.
/// Supports all consensus rules including taproot.
pub struct ConsensusVerifier {
    network: Network,
}

impl ConsensusVerifier {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

impl ScriptVerifier for ConsensusVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        height: u32,
    ) -> Result<(), ScriptError> {
        let tx_bytes = bitcoin::consensus::serialize(tx);

        let flags = script_verify_flags(self.network, height);

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
pub struct RustVerifier {
    network: Network,
}

impl RustVerifier {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

impl ScriptVerifier for RustVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        height: u32,
    ) -> Result<(), ScriptError> {
        let flags = script_verify_flags(self.network, height);

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
    /// Counts shadow txs dropped because the queue was full. Rate-limited
    /// reporter (see `report_drop`) consumes this and logs an aggregated
    /// WARN at most once per 5s — a per-drop WARN at IBD verify rates can
    /// burn tens of percent of wall-clock on tracing+stdout alone.
    dropped: std::sync::atomic::AtomicU64,
    /// Unix-epoch seconds of the last aggregated drop-report WARN emitted.
    last_drop_log_epoch: std::sync::atomic::AtomicU64,
}

/// Minimum seconds between aggregated drop-report WARN emissions.
const SHADOW_DROP_LOG_INTERVAL_SECS: u64 = 5;

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
        for n in 0..num_workers {
            let w_rx = rx.clone();
            let w_shadow = shadow.clone();
            let w_primary_label = primary_label.clone();
            let w_shadow_label = shadow_label.clone();
            // Thread names ensure /proc/self/task dumps attribute these
            // workers as `shadow-N` rather than the default `satd`. See
            // node/src/stall_watchdog.rs for the consumer.
            workers.push(
                std::thread::Builder::new()
                    .name(format!("shadow-{}", n))
                    .spawn(move || {
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
                    })
                    .expect("failed to spawn shadow verification worker"),
            );
        }

        Self {
            primary,
            shadow_tx: tx,
            queue_size,
            _workers: workers,
            dropped: std::sync::atomic::AtomicU64::new(0),
            last_drop_log_epoch: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Rate-limited drop reporter. Counts every drop, and emits a single
    /// aggregated WARN at most once per SHADOW_DROP_LOG_INTERVAL_SECS with
    /// the accumulated count since the last log. The per-call path is
    /// just two atomic ops on the hot path — no formatting, no string
    /// allocation, no stdout contention — which matters when primary is
    /// much faster than shadow (e.g. Rust-authoritative + C++-shadow)
    /// and drops happen at ten-million-per-minute rates.
    fn report_drop(&self, height: u32) {
        use std::sync::atomic::Ordering;
        use std::time::{SystemTime, UNIX_EPOCH};

        self.dropped.fetch_add(1, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_drop_log_epoch.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SHADOW_DROP_LOG_INTERVAL_SECS {
            return;
        }
        // CAS so only one thread wins the logging race per interval.
        if self
            .last_drop_log_epoch
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let total = self.dropped.swap(0, Ordering::Relaxed);
        if total > 0 {
            tracing::warn!(
                height,
                queue_size = self.queue_size,
                dropped = total,
                interval_secs = SHADOW_DROP_LOG_INTERVAL_SECS,
                "Shadow verification queue full — dropping tx (aggregated). \
                 Consider increasing --shadowworkers or --shadowqueuesize, \
                 or using --consensus=rust if the shadow engine isn't needed."
            );
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
                self.report_drop(height);
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
            self.report_drop(height);
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
        let cpp = ConsensusVerifier::new(Network::Bitcoin);
        let rust = RustVerifier::new(Network::Bitcoin);
        assert_eq!(cpp.primary_engine(), PrimaryEngine::Cpp);
        assert_eq!(rust.primary_engine(), PrimaryEngine::Rust);
        assert_eq!(NoopVerifier.primary_engine(), PrimaryEngine::Cpp);

        // rust-shadow layout: cpp authoritative, rust shadow -> Cpp
        let rust_shadow = ShadowVerifier::new(
            Box::new(ConsensusVerifier::new(Network::Bitcoin)),
            Box::new(RustVerifier::new(Network::Bitcoin)),
            "cpp",
            "rust",
            16,
            1,
        );
        assert_eq!(rust_shadow.primary_engine(), PrimaryEngine::Cpp);

        // cpp-shadow layout: rust authoritative, cpp shadow -> Rust
        let cpp_shadow = ShadowVerifier::new(
            Box::new(RustVerifier::new(Network::Bitcoin)),
            Box::new(ConsensusVerifier::new(Network::Bitcoin)),
            "rust",
            "cpp",
            16,
            1,
        );
        assert_eq!(cpp_shadow.primary_engine(), PrimaryEngine::Rust);
    }

    // Pin the per-network activation heights against Bitcoin Core's
    // chainparams.cpp buried-deployment heights. Round-tripping our own
    // table proves nothing; these literals were checked against Core.
    #[test]
    fn activation_heights_match_core_chainparams() {
        let main = activation_heights(Network::Bitcoin);
        assert_eq!(main.p2sh, 173_805);
        assert_eq!(main.dersig, 363_725);
        assert_eq!(main.cltv, 388_381);
        assert_eq!(main.csv, 419_328);
        assert_eq!(main.segwit, 481_824);
        assert_eq!(main.taproot, 709_632);

        let t3 = activation_heights(Network::Testnet);
        assert_eq!(t3.dersig, 330_776); // Core BIP66Height
        assert_eq!(t3.cltv, 581_885); // Core BIP65Height
        assert_eq!(t3.csv, 770_112); // Core CSVHeight
        assert_eq!(t3.segwit, 834_624); // Core SegwitHeight
        // P2SH gate sits just above testnet3's BIP16 exception block
        // 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
        // at height 394.
        assert_eq!(t3.p2sh, 395);

        for net in [Network::Signet, Network::Testnet4, Network::Regtest] {
            assert_eq!(
                activation_heights(net),
                ActivationHeights { p2sh: 0, dersig: 0, cltv: 0, csv: 0, segwit: 0, taproot: 0 },
                "{net}: every softfork must be active from genesis"
            );
        }
    }

    #[test]
    fn script_verify_flags_height_gates() {
        // Mainnet pre-P2SH: nothing on.
        assert_eq!(script_verify_flags(Network::Bitcoin, 0), 0);
        // Mainnet at segwit activation: witness + nulldummy join the set.
        let at_segwit = script_verify_flags(Network::Bitcoin, 481_824);
        assert_ne!(at_segwit & consensus::VERIFY_WITNESS, 0);
        assert_ne!(at_segwit & consensus::VERIFY_NULLDUMMY, 0);
        assert_eq!(at_segwit & consensus::VERIFY_TAPROOT, 0);
        // Mainnet at taproot activation: everything on.
        let all = consensus::VERIFY_P2SH
            | consensus::VERIFY_DERSIG
            | consensus::VERIFY_CHECKLOCKTIMEVERIFY
            | consensus::VERIFY_CHECKSEQUENCEVERIFY
            | consensus::VERIFY_WITNESS
            | consensus::VERIFY_NULLDUMMY
            | consensus::VERIFY_TAPROOT;
        assert_eq!(script_verify_flags(Network::Bitcoin, 709_632), all);
        // Always-active networks: everything on from the first block.
        for net in [Network::Signet, Network::Testnet4, Network::Regtest] {
            assert_eq!(script_verify_flags(net, 0), all, "{net}");
            assert_eq!(script_verify_flags(net, 1), all, "{net}");
        }
        // WITNESS implies P2SH and TAPROOT implies WITNESS at every height
        // on every network — libconsensus rejects flag sets violating this.
        for net in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            for height in [0, 394, 395, 400_000, 834_623, 834_624, 1_000_000] {
                let f = script_verify_flags(net, height);
                if f & consensus::VERIFY_WITNESS != 0 {
                    assert_ne!(f & consensus::VERIFY_P2SH, 0, "{net} h={height}");
                }
                if f & consensus::VERIFY_TAPROOT != 0 {
                    assert_ne!(f & consensus::VERIFY_WITNESS, 0, "{net} h={height}");
                }
            }
        }
    }

    /// Build a tx spending a P2WPKH prevout with an empty scriptSig and an
    /// empty witness — i.e. completely unsigned. Returns (tx, prevouts).
    fn unsigned_p2wpkh_spend() -> (Transaction, Vec<TxOut>) {
        use bitcoin::hashes::Hash as _;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness, absolute::LockTime,
            transaction::Version,
        };
        let wpkh = bitcoin::WPubkeyHash::from_slice(&[0x42; 20]).unwrap();
        let prev = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "6cf504882427ef10e78990b15c8f16bee6f4235fb5d653a791e5518ad69f0e59"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
            }],
        };
        (tx, vec![prev])
    }

    // Regression for the signet dogfood incident (2026-06-09): an unsigned
    // P2WPKH spend was accepted because the verifier applied MAINNET
    // activation heights on signet — at signet height 308_124 < 481_824 the
    // WITNESS flag was off, making witness programs anyone-can-spend. With
    // per-network heights, witness rules are active from genesis on signet,
    // testnet4, and regtest, and BOTH engines must reject this tx at any
    // height there.
    #[test]
    fn unsigned_p2wpkh_spend_rejected_on_always_active_networks() {
        let (tx, prevs) = unsigned_p2wpkh_spend();
        for net in [Network::Signet, Network::Testnet4, Network::Regtest] {
            for height in [1, 308_124, 481_824] {
                assert!(
                    ConsensusVerifier::new(net).verify_transaction(&tx, &prevs, height).is_err(),
                    "cpp engine accepted unsigned P2WPKH spend on {net} at {height}"
                );
                assert!(
                    RustVerifier::new(net).verify_transaction(&tx, &prevs, height).is_err(),
                    "rust engine accepted unsigned P2WPKH spend on {net} at {height}"
                );
            }
        }
        // Pin the mainnet height-gate, which reproduces Core's historical
        // acceptance: below the segwit gate witness programs are
        // anyone-can-spend (this is why mainnet stays height-gated and the
        // other networks must not be).
        assert!(
            ConsensusVerifier::new(Network::Bitcoin)
                .verify_transaction(&tx, &prevs, 308_124)
                .is_ok()
        );
        assert!(
            ConsensusVerifier::new(Network::Bitcoin)
                .verify_transaction(&tx, &prevs, 481_824)
                .is_err()
        );
    }
}

