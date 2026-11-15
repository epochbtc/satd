use bitcoin::{BlockHash, Network, Transaction, TxOut};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// Verification failed on one input.
    ///
    /// The index is carried apart from the reason because Bitcoin Core
    /// reports the two separately: `reason` is the script error on its own
    /// ("Non-canonical DER signature"), which goes inside the reject reason,
    /// while the input it failed on names the transaction's place in Core's
    /// debug string (`input %i of %s (wtxid %s), spending %s:%i`). Folding
    /// the index into the reason string, as this used to, put satd's wording
    /// where Core puts the bare script error.
    #[error("script-verify-failed: input {input}: {reason}")]
    VerifyFailed { input: usize, reason: String },
}

impl ScriptError {
    /// The script error alone, as Core's `ScriptErrorString` renders it.
    pub fn reason(&self) -> &str {
        match self {
            ScriptError::VerifyFailed { reason, .. } => reason,
        }
    }

    /// Which input failed.
    pub fn input(&self) -> usize {
        match self {
            ScriptError::VerifyFailed { input, .. } => *input,
        }
    }

    /// Core's `CScriptCheck::operator()` debug string for a failed input:
    /// `input %i of %s (wtxid %s), spending %s:%i` (`validation.cpp`). It is
    /// the detail half of the validation state, and what `testmempoolaccept`
    /// reports in `reject-details`.
    pub fn core_debug_string(&self, tx: &Transaction) -> Option<String> {
        let input = self.input();
        let txin = tx.input.get(input)?;
        Some(format!(
            "input {input} of {} (wtxid {}), spending {}:{}",
            tx.compute_txid(),
            tx.compute_wtxid(),
            txin.previous_output.txid,
            txin.previous_output.vout,
        ))
    }
}

/// Identifies which concrete verifier backs the authoritative (primary)
/// decision path. Used so components like the prefetch pipeline can match
/// whichever engine the user's config selected as primary — otherwise a
/// prefetch worker's "script OK" say-so (which lets the connect thread
/// skip primary verify) would override the user's chosen authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrimaryEngine {
    /// Bitcoin Core's script interpreter, through libbitcoinkernel (C++ FFI).
    Cpp,
    /// Pure Rust consensus engine.
    Rust,
}

/// Trait abstracting script/transaction verification. Implemented by
/// `ConsensusVerifier` (libbitcoinkernel FFI), `RustVerifier` (native), and
/// `ShadowVerifier` (parity-checked dual-engine).
pub trait ScriptVerifier: Send + Sync {
    /// Verify all inputs of a transaction against their previous outputs.
    /// `prev_outputs` must have one entry per input, in the same order.
    /// `at` says which block the transaction is checked for, and so which
    /// script flags apply.
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError>;

    /// [`verify_transaction`](Self::verify_transaction), except that a
    /// failure may come back with a coarse reason. Pass it to
    /// [`name_failure`](Self::name_failure) for the specific one. Finding
    /// that name can mean running a second script engine over the input, so
    /// a caller holding a lock can verify with this, release the lock, and
    /// name the failure afterwards.
    fn verify_transaction_unnamed(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        self.verify_transaction(tx, prev_outputs, at)
    }

    /// Whether this verifier accepts every script without looking at it, as
    /// [`NoopVerifier`] does below `-assumevalid`. `connect_block` then
    /// queues nothing for it and starts no verification threads: dispatching
    /// a block's transactions to a scope of threads, each created for the
    /// block, cost more than the rest of an early block's connect.
    fn checks_nothing(&self) -> bool {
        false
    }

    /// Give a failure from
    /// [`verify_transaction_unnamed`](Self::verify_transaction_unnamed) its
    /// specific reason. The verdict never changes; only the reason can.
    fn name_failure(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
        _at: ScriptContext,
        err: ScriptError,
    ) -> ScriptError {
        err
    }

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
    fn dispatch_shadow(&self, _tx: &Transaction, _prev_outputs: &[TxOut], _at: ScriptContext) {}

    /// Which concrete engine performs authoritative verification.
    /// Default: `Cpp`. `RustVerifier` overrides; `ShadowVerifier` delegates
    /// to its inner primary.
    fn primary_engine(&self) -> PrimaryEngine {
        PrimaryEngine::Cpp
    }

    /// The mempool's policy pass over `tx`'s inputs: Core's
    /// `PolicyScriptChecks`, under [`STANDARD_SCRIPT_VERIFY_FLAGS`]. Every
    /// engine runs it on the Rust interpreter; see [`verify_policy_scripts`].
    fn verify_policy(&self, tx: &Transaction, prev_outputs: &[TxOut]) -> Result<(), ScriptError> {
        verify_policy_scripts(tx, prev_outputs)
    }
}

/// Per-network buried softfork activation heights, Core's `BIP34Height`,
/// `BIP66Height`, `BIP65Height`, `CSVHeight` and `SegwitHeight`. Once a
/// fork's height is reached its rule stays on for all later blocks.
///
/// P2SH, WITNESS and TAPROOT have no height here: Core's
/// `GetBlockScriptFlags` turns their script flags on for every block but
/// its exceptions (see [`block_script_flags`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ActivationHeights {
    /// BIP 34 (height in coinbase).
    pub bip34: u32,
    /// BIP 66 (strict DER signatures).
    pub dersig: u32,
    /// BIP 65 (CHECKLOCKTIMEVERIFY).
    pub cltv: u32,
    /// BIP 112 (CHECKSEQUENCEVERIFY).
    pub csv: u32,
    /// BIP 141's block rules (witness commitment, `unexpected-witness`) and
    /// BIP 147 (NULLDUMMY). Not the WITNESS script flag, which is on for
    /// every block.
    pub segwit: u32,
    /// The height taproot activated at, as `getdeploymentinfo` reports it
    /// and the silent-payment index starts from. Not a script-flag gate:
    /// TAPROOT is on for every block.
    pub taproot: u32,
}

/// Softfork activation heights for `network`, mirroring Bitcoin Core's
/// buried-deployment heights (`chainparams.cpp`).
///
/// Signet, testnet4, and regtest activate everything from genesis (all of
/// Core's buried heights there are <= 1, and the genesis block is never
/// script-verified).
pub fn activation_heights(network: Network) -> ActivationHeights {
    let heights = match network {
        Network::Bitcoin => ActivationHeights {
            bip34: 227_931,
            dersig: 363_725,
            cltv: 388_381,
            csv: 419_328,
            segwit: 481_824,
            taproot: 709_632,
        },
        // Testnet3. Taproot is reported from segwit's height (#724 tracks
        // the real activation height); it gates no script flag.
        Network::Testnet => ActivationHeights {
            bip34: 21_111,
            dersig: 330_776,
            cltv: 581_885,
            csv: 770_112,
            segwit: 834_624,
            taproot: 834_624,
        },
        // Signet, Testnet4, Regtest: always active.
        //
        // Core's chainparams say `SegwitHeight = 1` for signet and testnet4
        // (regtest is 0), not 0. The difference is only the genesis block, and
        // it changes no verdict: genesis carries no witness data and no
        // commitment output, so `check_witness_rules` routes it to the
        // `unexpected-witness` scan and passes under either gate. Kept at 0 so
        // the whole table reads "everything from genesis" — but the segwit row
        // now gates a consensus rule (BIP 141 witness checks), not just script
        // flags, so the discrepancy is recorded rather than left to be
        // rediscovered.
        _ => ActivationHeights {
            // Height 1, not 0: the height-in-coinbase rule is meaningless
            // for genesis, and this preserves `bip34_activation_height`'s
            // long-standing value for these networks.
            bip34: 1,
            dersig: 0,
            cltv: 0,
            csv: 0,
            segwit: 0,
            taproot: 0,
        },
    };
    if network == Network::Regtest
        && let Some(overrides) = TEST_ACTIVATION_OVERRIDES.get()
    {
        return heights.with_overrides(overrides);
    }
    heights
}

/// Regtest-only overrides for the buried-deployment heights, Core's
/// `-testactivationheight=name@height` (#548). Core supports exactly five
/// names (`GetBuriedDeployment`): bip34, dersig, cltv, csv, segwit.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TestActivationOverrides {
    pub bip34: Option<u32>,
    pub dersig: Option<u32>,
    pub cltv: Option<u32>,
    pub csv: Option<u32>,
    pub segwit: Option<u32>,
}

static TEST_ACTIVATION_OVERRIDES: std::sync::OnceLock<TestActivationOverrides> =
    std::sync::OnceLock::new();

/// Install `-testactivationheight` overrides. Called once at daemon startup,
/// before any validation runs, and only when the chain is regtest — the
/// config layer rejects the option on every other network, and
/// [`activation_heights`] only consults the overrides for
/// [`Network::Regtest`]. Returns `Err` if overrides were already installed.
pub fn set_test_activation_overrides(o: TestActivationOverrides) -> Result<(), &'static str> {
    TEST_ACTIVATION_OVERRIDES
        .set(o)
        .map_err(|_| "test activation overrides already set")
}

impl ActivationHeights {
    /// Apply `-testactivationheight` overrides to a base table. Pure, so the
    /// merge is testable without touching the process-wide override slot.
    fn with_overrides(mut self, o: &TestActivationOverrides) -> ActivationHeights {
        if let Some(h) = o.bip34 {
            self.bip34 = h;
        }
        if let Some(h) = o.dersig {
            self.dersig = h;
        }
        if let Some(h) = o.cltv {
            self.cltv = h;
        }
        if let Some(h) = o.csv {
            self.csv = h;
        }
        if let Some(h) = o.segwit {
            // Moves BIP 141's block rules and NULLDUMMY, as in Core. The
            // WITNESS and TAPROOT script flags stay on (#1244), and taproot
            // stays always active, as Core's regtest has it.
            self.segwit = h;
        }
        self
    }
}

// The two engines must agree on flag bit values for `script_verify_flags`
// to feed either one. Both mirror Core's script-flag bits; pin it at
// compile time.
const _: () = {
    assert!(consensus::VERIFY_P2SH == bitcoinkernel::VERIFY_P2SH);
    assert!(consensus::VERIFY_DERSIG == bitcoinkernel::VERIFY_DERSIG);
    assert!(consensus::VERIFY_NULLDUMMY == bitcoinkernel::VERIFY_NULLDUMMY);
    assert!(consensus::VERIFY_CHECKLOCKTIMEVERIFY == bitcoinkernel::VERIFY_CHECKLOCKTIMEVERIFY);
    assert!(consensus::VERIFY_CHECKSEQUENCEVERIFY == bitcoinkernel::VERIFY_CHECKSEQUENCEVERIFY);
    assert!(consensus::VERIFY_WITNESS == bitcoinkernel::VERIFY_WITNESS);
    assert!(consensus::VERIFY_TAPROOT == bitcoinkernel::VERIFY_TAPROOT);
};

/// Core's `script_flag_exceptions` (`kernel/chainparams.cpp`): the blocks
/// that broke a rule before it activated, each with the P2SH, WITNESS and
/// TAPROOT flags it is checked under instead of all three.
const SCRIPT_FLAG_EXCEPTIONS: &[(Network, &str, u32)] = &[
    // Mainnet height 170,060: BIP 16 exception.
    (Network::Bitcoin, "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22", 0),
    // Mainnet height 692,261: taproot exception.
    (
        Network::Bitcoin,
        "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
        consensus::VERIFY_P2SH | consensus::VERIFY_WITNESS,
    ),
    // Testnet3 height 394: BIP 16 exception.
    (Network::Testnet, "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105", 0),
];

/// Script-verification flags for the block `hash` at `height` on `network`:
/// Core's `GetBlockScriptFlags`. P2SH, WITNESS and TAPROOT are on for every
/// block except those in [`SCRIPT_FLAG_EXCEPTIONS`]; DERSIG, CLTV, CSV and
/// NULLDUMMY come on at their buried heights. Shared by both engines (flag
/// bit values are identical, pinned above).
pub fn block_script_flags(network: Network, height: u32, hash: &BlockHash) -> u32 {
    static EXCEPTIONS: std::sync::LazyLock<Vec<(Network, BlockHash, u32)>> =
        std::sync::LazyLock::new(|| {
            SCRIPT_FLAG_EXCEPTIONS
                .iter()
                .map(|(net, hash, flags)| (*net, hash.parse().expect("exception hash"), *flags))
                .collect()
        });
    let base = EXCEPTIONS
        .iter()
        .find(|(net, h, _)| *net == network && h == hash)
        .map_or(ALWAYS_ON_FLAGS, |(_, _, flags)| *flags);
    base | buried_flags(network, height)
}

/// [`block_script_flags`] for a block that is not mined yet: the mempool's,
/// a template's. No exception can apply to it.
pub fn script_verify_flags(network: Network, height: u32) -> u32 {
    ALWAYS_ON_FLAGS | buried_flags(network, height)
}

/// The flags Core gives every block but its exceptions.
const ALWAYS_ON_FLAGS: u32 = consensus::VERIFY_P2SH | consensus::VERIFY_WITNESS | consensus::VERIFY_TAPROOT;

/// The flags of the buried deployments active at `height`.
fn buried_flags(network: Network, height: u32) -> u32 {
    let h = activation_heights(network);
    let mut flags = 0u32;
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
        flags |= consensus::VERIFY_NULLDUMMY;
    }
    flags
}

/// Where a transaction's scripts are checked: the height of the block that
/// holds it and, once the block exists, its hash, which can make it one of
/// Core's script-flag exceptions. Each verifier turns it into flags for its
/// own network.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScriptContext {
    pub height: u32,
    block: Option<BlockHash>,
}

impl ScriptContext {
    /// A transaction in the block `hash` at `height`.
    pub fn block(height: u32, hash: BlockHash) -> Self {
        ScriptContext { height, block: Some(hash) }
    }

    /// A transaction for a block not mined yet, at `height`: the mempool's,
    /// a template's.
    pub fn unmined(height: u32) -> Self {
        ScriptContext { height, block: None }
    }

    /// The script flags on `network`.
    pub fn flags(&self, network: Network) -> u32 {
        match &self.block {
            Some(hash) => block_script_flags(network, self.height, hash),
            None => script_verify_flags(network, self.height),
        }
    }
}

/// Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (`src/policy/policy.h`): the
/// consensus flags and the policy flags a standard transaction also obeys.
/// They hold back upgrade hooks (unknown witness versions, taproot leaf
/// versions, `OP_SUCCESS`, upgradable NOPs and public key types) and
/// malleable or wasteful encodings from the mempool, so a future soft fork
/// cannot be front-run into blocks. Not a block rule.
pub const STANDARD_SCRIPT_VERIFY_FLAGS: u32 = {
    use consensus::flags::*;
    VERIFY_P2SH
        | VERIFY_DERSIG
        | VERIFY_NULLDUMMY
        | VERIFY_CHECKLOCKTIMEVERIFY
        | VERIFY_CHECKSEQUENCEVERIFY
        | VERIFY_WITNESS
        | VERIFY_TAPROOT
        | VERIFY_STRICTENC
        | VERIFY_MINIMALDATA
        | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
        | VERIFY_CLEANSTACK
        | VERIFY_MINIMALIF
        | VERIFY_NULLFAIL
        | VERIFY_LOW_S
        | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        | VERIFY_WITNESS_PUBKEYTYPE
        | VERIFY_CONST_SCRIPTCODE
        | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
        | VERIFY_DISCOURAGE_OP_SUCCESS
        | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
};

/// Core's `PolicyScriptChecks`: every input under
/// [`STANDARD_SCRIPT_VERIFY_FLAGS`]. It runs on the Rust engine whatever
/// `-consensus` selects, because libbitcoinkernel's verify call refuses any
/// flag outside the consensus set (`btck_ScriptVerificationFlags_ALL`). The node's own
/// verifier then checks the same inputs under the block's flags, as Core's
/// `ConsensusScriptChecks` does, and stays the authority on validity.
pub fn verify_policy_scripts(tx: &Transaction, prev_outputs: &[TxOut]) -> Result<(), ScriptError> {
    consensus::verify_transaction(tx, prev_outputs, STANDARD_SCRIPT_VERIFY_FLAGS)
        .map_err(|(idx, e)| ScriptError::VerifyFailed { input: idx, reason: e.to_string() })
}

/// Script inputs the connect path has verified since startup.
///
/// The stall watchdog reads it as a progress signal (#1216). One
/// transaction with thousands of inputs can keep the connector inside a
/// single block's verification for minutes, with no block connected in
/// the meantime, and the watchdog must not mistake that for a wedge.
///
/// Only verification run inside [`counting_progress`] is counted, which
/// the connect path does for its own block. Mempool admission, block
/// prefetch and the shadow engine verify outside it: a steady stream of
/// relayed or submitted transactions must not keep a wedged connector
/// looking alive.
static SCRIPT_INPUTS_VERIFIED: AtomicU64 = AtomicU64::new(0);

std::thread_local! {
    /// Where this thread counts the inputs it verifies, if anywhere.
    static PROGRESS_COUNTER: std::cell::Cell<Option<&'static AtomicU64>> =
        const { std::cell::Cell::new(None) };
}

/// Read [`SCRIPT_INPUTS_VERIFIED`]. Only its change over time matters.
pub fn script_inputs_verified() -> u64 {
    SCRIPT_INPUTS_VERIFIED.load(Ordering::Relaxed)
}

/// Run `f`, counting the script inputs it verifies on this thread into
/// [`SCRIPT_INPUTS_VERIFIED`].
pub fn counting_progress<R>(f: impl FnOnce() -> R) -> R {
    counting_into(&SCRIPT_INPUTS_VERIFIED, f)
}

fn counting_into<R>(counter: &'static AtomicU64, f: impl FnOnce() -> R) -> R {
    // Restores the previous target on drop, so a panic in `f` cannot leave
    // this thread counting.
    struct Restore(Option<&'static AtomicU64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            PROGRESS_COUNTER.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(PROGRESS_COUNTER.with(|c| c.replace(Some(counter))));
    f()
}

fn count_inputs_verified(n: usize) {
    PROGRESS_COUNTER.with(|c| {
        if let Some(counter) = c.get() {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
    });
}

/// Script verifier backed by Bitcoin Core's script interpreter through
/// libbitcoinkernel's C API. Supports all consensus rules including taproot.
///
/// Like Core's `CheckInputScripts`, it parses the transaction and builds its
/// `PrecomputedTransactionData` (txid, wtxid, and the BIP 143 / BIP 341
/// hashes of prevouts, amounts, scripts, sequences and outputs) once, and
/// every input's check reuses them. libbitcoinconsensus, which this replaced,
/// redid all of that for every input, so a transaction cost time quadratic in
/// its input count (#874).
pub struct ConsensusVerifier {
    network: Network,
}

impl ConsensusVerifier {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

/// Name the script error behind a libbitcoinkernel rejection.
///
/// The C API cannot tell us: `btck_script_pubkey_verify` reports a bare
/// failure (surfaced here as a coarse `ERR_SCRIPT`) and the `ScriptError_t`
/// that VerifyScript actually produced never crosses the FFI boundary. Bitcoin Core, calling
/// VerifyScript directly, puts that specific name in the rejection —
/// `mempool-script-verify-flag-failed (Non-canonical DER signature)` — and
/// every client and test that reads a rejection reads the name.
///
/// So the native engine, which computes the same thing and carries Core's
/// `ScriptErrorString` table, is asked for the name. The *verdict* is not
/// revisited: the kernel has already rejected this input and that stands.
/// This runs only on the failure path, and only to write the message.
///
/// Only the input that failed is run. The kernel has already passed every
/// input before it, so running those again would repeat that work for
/// nothing.
///
/// If the two engines disagree about this input — the native one finding it
/// valid — there is no name to borrow, and `None` leaves the coarse error as
/// it was. That disagreement is a parity bug worth knowing about, so it is
/// logged rather than papered over.
fn name_script_failure(
    tx: &Transaction,
    prev_outputs: &[TxOut],
    flags: u32,
    input: usize,
) -> Option<String> {
    let prev = prev_outputs.get(input)?;
    let precomputed = consensus::PrecomputedTransactionData::new(tx, prev_outputs).ok()?;
    match consensus::verify(&prev.script_pubkey, prev.value, tx, input, flags, &precomputed) {
        Err(consensus::Error::ErrScript(e)) => Some(e.as_str().to_string()),
        Err(_) => None,
        Ok(()) => {
            tracing::debug!(
                input,
                "the native engine does not agree that this input fails; \
                 reporting the coarse error"
            );
            None
        }
    }
}

impl ScriptVerifier for ConsensusVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        self.verify_transaction_unnamed(tx, prev_outputs, at)
            .map_err(|e| self.name_failure(tx, prev_outputs, at, e))
    }

    /// libbitcoinkernel alone. A failure carries its coarse `ERR_SCRIPT`.
    fn verify_transaction_unnamed(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        // One spent output per input, as the Rust engine requires
        // (`ErrSpentOutputsMismatch`) and Core's `PrecomputedTransactionData`
        // assumes. The loop below stops at the shorter of the two, so a short
        // or empty `prev_outputs` would verify only the inputs it covers and
        // pass the rest unchecked. No caller passes one today.
        if prev_outputs.len() != tx.input.len() {
            return Err(ScriptError::VerifyFailed {
                input: 0,
                reason: "spent outputs count mismatch".to_string(),
            });
        }

        let flags = at.flags(self.network);
        kernel_verify_transaction(tx, prev_outputs, flags)?;
        count_inputs_verified(tx.input.len());
        Ok(())
    }

    fn name_failure(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
        err: ScriptError,
    ) -> ScriptError {
        let input = err.input();
        let flags = at.flags(self.network);
        match name_script_failure(tx, prev_outputs, flags, input) {
            Some(reason) => ScriptError::VerifyFailed { input, reason },
            None => err,
        }
    }
}

/// Verify every input of `tx` with libbitcoinkernel under `flags`, parsing the
/// transaction and building its precomputed data once. The caller has checked
/// that `prev_outputs` has one entry per input.
pub(crate) fn kernel_verify_transaction(
    tx: &Transaction,
    prev_outputs: &[TxOut],
    flags: u32,
) -> Result<(), ScriptError> {
    use bitcoinkernel::prelude::TxOutExt;
    use bitcoinkernel::{PrecomputedTransactionData, ScriptPubkey};

    let setup = |reason: &str| ScriptError::VerifyFailed { input: 0, reason: reason.to_string() };
    let ktx = bitcoinkernel::Transaction::new(&bitcoin::consensus::serialize(tx))
        .map_err(|_| setup("ERR_TX_DESERIALIZE"))?;
    let mut spent = Vec::with_capacity(prev_outputs.len());
    for out in prev_outputs {
        let spk = ScriptPubkey::new(out.script_pubkey.as_bytes())
            .map_err(|_| setup("ERR_TX_DESERIALIZE"))?;
        spent.push(bitcoinkernel::TxOut::new(&spk, out.value.to_sat() as i64));
    }
    // Every spent output goes in whatever the flags: BIP 341's signature
    // hash commits to all of them, and the other sighash forms ignore them.
    let txdata = PrecomputedTransactionData::new(&ktx, &spent)
        .map_err(|_| setup("ERR_SPENT_OUTPUTS_MISMATCH"))?;

    for (input, out) in spent.iter().enumerate() {
        let spk = out.script_pubkey();
        bitcoinkernel::verify(&spk, Some(out.value()), &ktx, input, Some(flags), &txdata).map_err(
            |e| ScriptError::VerifyFailed { input, reason: kernel_error_name(&e).to_string() },
        )?;
    }
    Ok(())
}

/// The libbitcoinconsensus-style name for a libbitcoinkernel verify error, so
/// log lines and coarse rejection reasons keep the names they had.
fn kernel_error_name(e: &bitcoinkernel::KernelError) -> &'static str {
    use bitcoinkernel::{KernelError, ScriptVerifyError};
    match e {
        KernelError::ScriptVerify(ScriptVerifyError::Invalid) => "ERR_SCRIPT",
        KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex) => "ERR_TX_INDEX",
        KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags)
        | KernelError::ScriptVerify(ScriptVerifyError::InvalidFlagsCombination) => {
            "ERR_INVALID_FLAGS"
        }
        KernelError::ScriptVerify(ScriptVerifyError::SpentOutputsRequired) => {
            "ERR_SPENT_OUTPUTS_REQUIRED"
        }
        KernelError::MismatchedOutputsSize => "ERR_SPENT_OUTPUTS_MISMATCH",
        _ => "ERR_SCRIPT",
    }
}

/// No-op verifier for tests that don't need script checking.
pub struct NoopVerifier;

impl ScriptVerifier for NoopVerifier {
    fn checks_nothing(&self) -> bool {
        true
    }

    fn verify_transaction(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
        _at: ScriptContext,
    ) -> Result<(), ScriptError> {
        Ok(())
    }

    fn verify_policy(&self, _tx: &Transaction, _prev_outputs: &[TxOut]) -> Result<(), ScriptError> {
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
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        let flags = at.flags(self.network);

        // Batch API: passes &Transaction so we don't re-deserialize per
        // input, and shares a single SighashCache across inputs (BIP143
        // hashPrevouts / hashSequence / hashOutputs are tx-wide).
        consensus::verify_transaction(tx, prev_outputs, flags)
            .map_err(|(idx, e)| ScriptError::VerifyFailed { input: idx, reason: e.to_string() })?;
        count_inputs_verified(tx.input.len());
        Ok(())
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
    /// `None` once `drop` has closed the queue.
    shadow_tx: Option<crossbeam_channel::Sender<ShadowWork>>,
    queue_size: usize,
    /// The most bytes the queued work may hold (`-shadowqueuemb`); `0` for
    /// no byte bound, leaving only the entry count (#1145).
    queue_bytes: usize,
    /// Bytes held by queued work: charged on enqueue, released by the worker
    /// that dequeues it.
    queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Set by `drop`: a worker discards what is still queued and exits.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    /// Counts shadow txs dropped because the queue was full. Rate-limited
    /// reporter (see `report_drop`) consumes this and logs an aggregated
    /// WARN at most once per 5s — a per-drop WARN at IBD verify rates can
    /// burn tens of percent of wall-clock on tracing+stdout alone.
    dropped: std::sync::atomic::AtomicU64,
    /// Unix-epoch seconds of the last aggregated drop-report WARN emitted.
    last_drop_log_epoch: std::sync::atomic::AtomicU64,
    /// Every drop since start, never reset (`dropped` is, by the reporter).
    dropped_total: std::sync::atomic::AtomicU64,
}

/// Minimum seconds between aggregated drop-report WARN emissions.
const SHADOW_DROP_LOG_INTERVAL_SECS: u64 = 5;

/// Default byte budget of the shadow queue (`-shadowqueuemb`), in MiB.
pub const DEFAULT_SHADOW_QUEUE_MB: usize = 128;

/// Work item for the shadow verification background pool.
struct ShadowWork {
    tx_bytes: Vec<u8>,
    prev_outputs: Vec<TxOut>,
    at: ScriptContext,
    txid: bitcoin::Txid,
    /// What [`ShadowWork::cost`] charged the byte budget on enqueue.
    charge: usize,
}

impl ShadowWork {
    fn new(tx: &Transaction, prev_outputs: &[TxOut], at: ScriptContext, charge: usize) -> Self {
        ShadowWork {
            tx_bytes: bitcoin::consensus::serialize(tx),
            prev_outputs: prev_outputs.to_vec(),
            at,
            txid: tx.compute_txid(),
            charge,
        }
    }

    /// The bytes an item for `tx` holds while it waits: the serialized
    /// transaction, the prevout vector and each prevout's script. Computed
    /// from the inputs, so a drop costs no allocation.
    fn cost(tx: &Transaction, prev_outputs: &[TxOut]) -> usize {
        std::mem::size_of::<ShadowWork>()
            + tx.total_size()
            + std::mem::size_of_val(prev_outputs)
            + prev_outputs.iter().map(|o| o.script_pubkey.len()).sum::<usize>()
    }
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
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let queued_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
            let w_stop = stop.clone();
            let w_queued_bytes = queued_bytes.clone();
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
                    w_queued_bytes.fetch_sub(work.charge, std::sync::atomic::Ordering::Relaxed);
                    if w_stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let tx: Transaction = match bitcoin::consensus::deserialize(&work.tx_bytes) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if let Err(e) = w_shadow.verify_transaction(&tx, &work.prev_outputs, work.at) {
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
                            work.at.height,
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
            shadow_tx: Some(tx),
            queue_size,
            queue_bytes: DEFAULT_SHADOW_QUEUE_MB << 20,
            queued_bytes,
            stop,
            workers,
            dropped: std::sync::atomic::AtomicU64::new(0),
            last_drop_log_epoch: std::sync::atomic::AtomicU64::new(0),
            dropped_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Bound the queued work to `bytes` (`-shadowqueuemb`); `0` leaves only
    /// the entry count. [`DEFAULT_SHADOW_QUEUE_MB`] until set.
    pub fn with_queue_bytes(mut self, bytes: usize) -> Self {
        self.queue_bytes = bytes;
        tracing::info!(queue_bytes = bytes, "Shadow verification queue byte budget");
        self
    }

    /// Bytes the queued work holds now.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Every transaction dropped since start because the queue was full.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queue `work` for the shadow pool, counting it as dropped when the
    /// queue is full: by entry count, or by bytes (#1145). An empty queue
    /// takes any one item, so a transaction larger than the budget is still
    /// checked when the shadow engine has caught up.
    ///
    /// The byte check runs before the item is built, so a full queue costs
    /// the hot path no serialization or prevout copy.
    fn enqueue(&self, tx: &Transaction, prev_outputs: &[TxOut], at: ScriptContext) {
        use std::sync::atomic::Ordering;
        let Some(shadow_tx) = &self.shadow_tx else {
            return;
        };
        let charge = ShadowWork::cost(tx, prev_outputs);
        let before = self.queued_bytes.fetch_add(charge, Ordering::Relaxed);
        if self.queue_bytes != 0 && before != 0 && before.saturating_add(charge) > self.queue_bytes {
            self.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
            self.report_drop(at.height);
            return;
        }
        match shadow_tx.try_send(ShadowWork::new(tx, prev_outputs, at, charge)) {
            Ok(()) => {}
            Err(crossbeam_channel::TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
                self.report_drop(at.height);
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
            }
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
        self.dropped_total.fetch_add(1, Ordering::Relaxed);

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
            let queued = self.shadow_tx.as_ref().map_or(0, |t| t.len());
            tracing::warn!(
                height,
                queued,
                queue_size = self.queue_size,
                queued_bytes = self.queued_bytes(),
                queue_bytes = self.queue_bytes,
                dropped = total,
                interval_secs = SHADOW_DROP_LOG_INTERVAL_SECS,
                "Shadow verification queue full — dropping tx (aggregated). \
                 The shadow engine is not keeping up; consider increasing \
                 --shadowworkers (or --shadowqueuemb on a host with memory to \
                 spare), or using --consensus=rust if the shadow engine isn't \
                 needed."
            );
        }
    }
}

impl ScriptVerifier for ShadowVerifier {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        // Run primary synchronously — this is the hot path
        let result = self.primary.verify_transaction(tx, prev_outputs, at);

        // On primary success, dispatch shadow verification asynchronously.
        if result.is_ok() {
            self.enqueue(tx, prev_outputs, at);
        }

        result
    }

    /// The primary engine's unnamed verify, with the same shadow dispatch.
    fn verify_transaction_unnamed(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
    ) -> Result<(), ScriptError> {
        let result = self.primary.verify_transaction_unnamed(tx, prev_outputs, at);
        if result.is_ok() {
            self.dispatch_shadow(tx, prev_outputs, at);
        }
        result
    }

    fn name_failure(
        &self,
        tx: &Transaction,
        prev_outputs: &[TxOut],
        at: ScriptContext,
        err: ScriptError,
    ) -> ScriptError {
        self.primary.name_failure(tx, prev_outputs, at, err)
    }

    fn dispatch_shadow(&self, tx: &Transaction, prev_outputs: &[TxOut], at: ScriptContext) {
        self.enqueue(tx, prev_outputs, at);
    }

    fn primary_engine(&self) -> PrimaryEngine {
        // Delegate to the inner primary so callers see the real authoritative
        // engine, not "Cpp" just because ShadowVerifier is the outer type.
        self.primary.primary_engine()
    }
}

impl Drop for ShadowVerifier {
    /// Stop the workers and wait for them. Left running, a worker can still
    /// be inside the shadow engine, the C++ one included, when the process
    /// exits and destroys that engine's statics (#868). What is still queued
    /// is discarded rather than verified first: shadow checks are
    /// best-effort, and a full queue drops work already.
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Closing the queue wakes the workers parked in `recv`.
        drop(self.shadow_tx.take());
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
#[path = "script_naming_tests.rs"]
mod naming_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (`src/policy/policy.h`) is every
    /// flag of `script_verify_flag_name` (`src/script/interpreter.h`, bits 0
    /// to 20) except SIGPUSHONLY, bit 5. A literal, so the check does not
    /// repeat the expression it pins.
    #[test]
    fn standard_flags_are_cores() {
        assert_eq!(STANDARD_SCRIPT_VERIFY_FLAGS, 0x1f_ffdf);
    }

    /// satd's BIP 322 extension flag is never part of a block or policy flag
    /// set. The consensus crate's entry points refuse it anyway; this pins the
    /// node side, so the flag cannot drift into validation.
    #[test]
    fn block_and_policy_flags_never_set_the_bip322_extension() {
        let ext = consensus::flags::VERIFY_MINIMALIF_BASE;
        assert_eq!(STANDARD_SCRIPT_VERIFY_FLAGS & ext, 0);
        for network in [Network::Bitcoin, Network::Testnet, Network::Testnet4, Network::Signet, Network::Regtest] {
            for height in [0, 1, 227_931, 481_824, 709_632, u32::MAX] {
                assert_eq!(script_verify_flags(network, height) & ext, 0, "{network} {height}");
            }
        }
    }

    /// The cpp engine refuses a `prev_outputs` that does not have one entry
    /// per input, as the Rust engine does. It used to verify only the inputs
    /// the slice covered, so an empty one passed every input unchecked.
    /// Perturbation: drop the length check and the empty and short cases pass.
    #[test]
    fn the_cpp_engine_needs_one_spent_output_per_input() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness, absolute::LockTime, transaction};
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        let input = |vout| TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([7; 32]), vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![input(0), input(1)],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: op_true.clone() }],
        };
        let spent = TxOut { value: Amount::from_sat(5000), script_pubkey: op_true };
        let cpp = ConsensusVerifier::new(Network::Regtest);
        assert!(
            cpp.verify_transaction(&tx, &[spent.clone(), spent.clone()], ScriptContext::unmined(200)).is_ok(),
            "one spent output per input: anyone-can-spend inputs verify"
        );
        assert!(cpp.verify_transaction(&tx, std::slice::from_ref(&spent), ScriptContext::unmined(200)).is_err(), "one short");
        assert!(cpp.verify_transaction(&tx, &[], ScriptContext::unmined(200)).is_err(), "none at all");
        assert!(cpp.verify_transaction(&tx, &[spent.clone(), spent.clone(), spent], ScriptContext::unmined(200)).is_err(), "one extra");
    }

    /// Both engines count every input they verify inside
    /// `counting_progress`, which the stall watchdog reads as progress inside
    /// a long block (#1216), and nothing outside it: mempool admission must
    /// not keep a wedged connector looking alive. Each case counts into a
    /// counter of its own, which no concurrent test touches.
    /// Perturbation: drop either engine's count, or leave the scope set
    /// after it ends, and an assertion fails.
    #[test]
    fn both_engines_count_the_inputs_they_verify() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness, absolute::LockTime, transaction};
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        let input = |vout| TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([9; 32]), vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![input(0), input(1), input(2)],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: op_true.clone() }],
        };
        let spent = vec![TxOut { value: Amount::from_sat(5000), script_pubkey: op_true }; 3];
        let engines: [(&str, Box<dyn ScriptVerifier>); 2] = [
            ("cpp", Box::new(ConsensusVerifier::new(Network::Regtest))),
            ("rust", Box::new(RustVerifier::new(Network::Regtest))),
        ];
        for (name, engine) in engines {
            let counter: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));
            counting_into(counter, || engine.verify_transaction(&tx, &spent, ScriptContext::unmined(200)))
                .expect("anyone-can-spend inputs verify");
            assert_eq!(counter.load(Ordering::Relaxed), 3, "{name}: three inputs verified");
            engine.verify_transaction(&tx, &spent, ScriptContext::unmined(200)).expect("verifies again");
            assert_eq!(counter.load(Ordering::Relaxed), 3, "{name}: outside the scope, nothing counts");
            assert!(PROGRESS_COUNTER.with(|c| c.get()).is_none(), "{name}: the scope is restored");
        }
    }

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

    /// Three spends from mainnet block 974,146, with the outputs they spend:
    /// two P2TR inputs; six inputs mixing P2WSH and P2SH; two P2PKH inputs.
    fn mainnet_spends() -> Vec<(Transaction, Vec<TxOut>)> {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("testdata/mainnet_974146_spends.json")).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|t| {
                let hex = t["hex"].as_str().unwrap();
                let tx = bitcoin::consensus::encode::deserialize_hex(hex).unwrap();
                let prevs = t["prevouts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| TxOut {
                        value: bitcoin::Amount::from_sat(p[1].as_u64().unwrap()),
                        script_pubkey: bitcoin::ScriptBuf::from_hex(p[0].as_str().unwrap())
                            .unwrap(),
                    })
                    .collect();
                (tx, prevs)
            })
            .collect()
    }

    /// The kernel engine accepts real mainnet spends of every input type, and
    /// agrees with the Rust engine on them.
    #[test]
    fn kernel_engine_accepts_mainnet_spends() {
        let cpp = ConsensusVerifier::new(Network::Bitcoin);
        let rust = RustVerifier::new(Network::Bitcoin);
        for (tx, prevs) in mainnet_spends() {
            let txid = tx.compute_txid();
            if let Err(e) = cpp.verify_transaction(&tx, &prevs, ScriptContext::unmined(974_146)) {
                panic!("kernel rejects {txid}: {e:?}");
            }
            if let Err(e) = rust.verify_transaction(&tx, &prevs, ScriptContext::unmined(974_146)) {
                panic!("rust rejects {txid}: {e:?}");
            }
        }
    }

    /// A spent amount one satoshi off breaks the signatures that commit to
    /// it, and the failure is reported against the first of them. A segwit v0
    /// signature commits to its own input's amount (BIP 143); a taproot one
    /// commits to every input's (BIP 341). This pins that each input is
    /// checked against its own spent output out of the shared
    /// per-transaction data.
    #[test]
    fn kernel_engine_reports_the_input_whose_amount_changed() {
        let cpp = ConsensusVerifier::new(Network::Bitcoin);
        for (tx, prevs) in mainnet_spends() {
            for k in 0..prevs.len() {
                let first_broken = (0..prevs.len()).find(|&i| {
                    let taproot = prevs[i].script_pubkey.is_p2tr();
                    // Native or P2SH-wrapped segwit v0.
                    let v0 = !taproot && !tx.input[i].witness.is_empty();
                    taproot || (i == k && v0)
                });
                let mut bad = prevs.clone();
                bad[k].value += bitcoin::Amount::from_sat(1);
                let got = cpp.verify_transaction_unnamed(&tx, &bad, ScriptContext::unmined(974_146));
                let txid = tx.compute_txid();
                if let Some(want) = first_broken {
                    match got {
                        Err(ScriptError::VerifyFailed { input, reason }) => {
                            let got = (input, reason.as_str());
                            assert_eq!(got, (want, "ERR_SCRIPT"), "{txid} input {k}");
                        }
                        other => panic!("{txid} input {k}: changed amount gave {other:?}"),
                    }
                } else if prevs[k].script_pubkey.is_p2pkh() {
                    // A legacy signature does not commit to the amount.
                    assert!(got.is_ok(), "{txid} input {k}: {got:?}");
                }
            }
        }
    }

    // Pin the per-network activation heights against Bitcoin Core's
    // chainparams.cpp buried-deployment heights. Round-tripping our own
    // table proves nothing; these literals were checked against Core.
    #[test]
    fn test_activation_overrides_merge() {
        let base = activation_heights(Network::Regtest);
        // No overrides: identity.
        assert_eq!(base.with_overrides(&TestActivationOverrides::default()), base);

        // Each name moves exactly its own height.
        let o = TestActivationOverrides {
            bip34: Some(500),
            dersig: Some(102),
            cltv: Some(111),
            csv: Some(432),
            segwit: None,
        };
        let h = base.with_overrides(&o);
        assert_eq!(h.bip34, 500);
        assert_eq!(h.dersig, 102);
        assert_eq!(h.cltv, 111);
        assert_eq!(h.csv, 432);
        assert_eq!(h.segwit, base.segwit);
        assert_eq!(h.taproot, base.taproot);

        // Moving segwit moves segwit alone: taproot stays always active,
        // as Core's regtest has it, and gates no flag (#1244).
        let o = TestActivationOverrides { segwit: Some(300), ..Default::default() };
        let h = base.with_overrides(&o);
        assert_eq!(h.segwit, 300);
        assert_eq!(h.taproot, base.taproot);
    }

    #[test]
    fn activation_heights_match_core_chainparams() {
        let main = activation_heights(Network::Bitcoin);
        assert_eq!(main.bip34, 227_931);
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

        // Core has `SegwitHeight = 1` for signet and testnet4 (0 for regtest);
        // see the note in `activation_heights` for why 0 is equivalent here.
        for net in [Network::Signet, Network::Testnet4, Network::Regtest] {
            assert_eq!(
                activation_heights(net),
                ActivationHeights { bip34: 1, dersig: 0, cltv: 0, csv: 0, segwit: 0, taproot: 0 },
                "{net}: every softfork must be active from genesis"
            );
        }
    }

    /// Core's `GetBlockScriptFlags`: P2SH, WITNESS and TAPROOT on every
    /// block from genesis, the buried flags at their heights.
    #[test]
    fn script_verify_flags_turn_p2sh_witness_taproot_on_from_genesis() {
        let always = consensus::VERIFY_P2SH | consensus::VERIFY_WITNESS | consensus::VERIFY_TAPROOT;
        let all = always
            | consensus::VERIFY_DERSIG
            | consensus::VERIFY_CHECKLOCKTIMEVERIFY
            | consensus::VERIFY_CHECKSEQUENCEVERIFY
            | consensus::VERIFY_NULLDUMMY;
        // Mainnet before every buried deployment: the three alone.
        assert_eq!(script_verify_flags(Network::Bitcoin, 0), always);
        assert_eq!(script_verify_flags(Network::Bitcoin, 363_724), always);
        assert_eq!(
            script_verify_flags(Network::Bitcoin, 363_725),
            always | consensus::VERIFY_DERSIG
        );
        // NULLDUMMY comes on with segwit's block rules.
        assert_eq!(script_verify_flags(Network::Bitcoin, 481_823) & consensus::VERIFY_NULLDUMMY, 0);
        assert_eq!(script_verify_flags(Network::Bitcoin, 481_824), all);
        assert_eq!(script_verify_flags(Network::Testnet, 0), always);
        assert_eq!(script_verify_flags(Network::Testnet, 834_624), all);
        for net in [Network::Signet, Network::Testnet4, Network::Regtest] {
            assert_eq!(script_verify_flags(net, 0), all, "{net}");
            assert_eq!(script_verify_flags(net, 1), all, "{net}");
        }
    }

    /// Core's `script_flag_exceptions`: the mainnet BIP 16 block (no flags),
    /// the mainnet taproot block (P2SH and WITNESS) and the testnet3 BIP 16
    /// block (no flags). Any other block at the same height, and the same
    /// hash on another network, gets all three.
    #[test]
    fn block_script_flags_carve_out_cores_exceptions_by_hash() {
        let always = consensus::VERIFY_P2SH | consensus::VERIFY_WITNESS | consensus::VERIFY_TAPROOT;
        let hash = |h: &str| -> BlockHash { h.parse().unwrap() };
        let bip16 = hash("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        let taproot = hash("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad");
        let t3_bip16 = hash("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        let other = hash("00000000000000000000000000000000000000000000000000000000000000aa");

        assert_eq!(block_script_flags(Network::Bitcoin, 170_060, &bip16), 0);
        assert_eq!(block_script_flags(Network::Bitcoin, 170_060, &other), always);
        assert_eq!(
            block_script_flags(Network::Bitcoin, 692_261, &taproot),
            script_verify_flags(Network::Bitcoin, 692_261) & !consensus::VERIFY_TAPROOT
        );
        assert_eq!(
            block_script_flags(Network::Bitcoin, 692_261, &other),
            script_verify_flags(Network::Bitcoin, 692_261)
        );
        assert_eq!(block_script_flags(Network::Testnet, 394, &t3_bip16), 0);
        assert_eq!(block_script_flags(Network::Testnet, 394, &bip16), always);
        assert_eq!(block_script_flags(Network::Bitcoin, 394, &t3_bip16), always);

        assert_eq!(ScriptContext::block(170_060, bip16).flags(Network::Bitcoin), 0);
        assert_eq!(ScriptContext::unmined(170_060).flags(Network::Bitcoin), always);
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

    // Regression for the signet incident (2026-06-09): an unsigned
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
                    ConsensusVerifier::new(net).verify_transaction(&tx, &prevs, ScriptContext::unmined(height)).is_err(),
                    "cpp engine accepted unsigned P2WPKH spend on {net} at {height}"
                );
                assert!(
                    RustVerifier::new(net).verify_transaction(&tx, &prevs, ScriptContext::unmined(height)).is_err(),
                    "rust engine accepted unsigned P2WPKH spend on {net} at {height}"
                );
            }
        }
        // Mainnet and testnet3 too, below their segwit heights: Core checks
        // WITNESS on every block, so a witness output was never spendable
        // without its witness (#1244). Only an exception block is spared.
        for net in [Network::Bitcoin, Network::Testnet] {
            for height in [1, 308_124, 481_824] {
                for engine in [&ConsensusVerifier::new(net) as &dyn ScriptVerifier, &RustVerifier::new(net)] {
                    assert!(
                        engine.verify_transaction(&tx, &prevs, ScriptContext::unmined(height)).is_err(),
                        "{net} at {height} accepted an unsigned P2WPKH spend"
                    );
                }
            }
        }
        let bip16: BlockHash =
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22".parse().unwrap();
        for engine in [
            &ConsensusVerifier::new(Network::Bitcoin) as &dyn ScriptVerifier,
            &RustVerifier::new(Network::Bitcoin),
        ] {
            assert!(engine.verify_transaction(&tx, &prevs, ScriptContext::block(170_060, bip16)).is_ok());
        }
    }

    /// A shadow engine that takes 200 ms a transaction, counts the
    /// verifications it starts, and records when it is dropped.
    struct SlowShadow {
        started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl ScriptVerifier for SlowShadow {
        fn verify_transaction(
            &self,
            _tx: &Transaction,
            _prev_outputs: &[TxOut],
            _at: ScriptContext,
        ) -> Result<(), ScriptError> {
            self.started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(200));
            Ok(())
        }
    }

    impl Drop for SlowShadow {
        fn drop(&mut self) {
            self.dropped.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Dropping a `ShadowVerifier` stops its workers and waits for them, so
    /// none is left inside the shadow engine when the process exits (#868),
    /// and it discards the queue rather than verifying it first.
    ///
    /// The workers hold the only references to the shadow engine, so the
    /// engine is dropped exactly when the last worker has exited.
    ///
    /// Perturbations: without the join, `drop` returns while the worker is
    /// still in its first verification and the engine is not yet dropped;
    /// without the stop flag, the join waits for all five and `started` is 5.
    #[test]
    fn dropping_the_shadow_verifier_stops_and_joins_its_workers() {
        use std::sync::atomic::Ordering::SeqCst;
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let verifier = ShadowVerifier::new(
            Box::new(NoopVerifier),
            Box::new(SlowShadow { started: started.clone(), dropped: dropped.clone() }),
            "noop",
            "slow",
            16,
            1,
        );
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut::NULL],
        };
        for _ in 0..5 {
            verifier.verify_transaction(&tx, &[], ScriptContext::unmined(1)).expect("the primary accepts");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while started.load(SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(started.load(SeqCst), 1, "fixture: the worker must be busy with the first");

        drop(verifier);
        assert!(
            dropped.load(SeqCst),
            "drop must return only after every worker has exited"
        );
        assert_eq!(started.load(SeqCst), 1, "the four still queued must be discarded");
    }

    /// A shadow engine that blocks every verification until the test
    /// releases the gate, counting the ones it starts.
    struct GatedShadow {
        gate: std::sync::Arc<parking_lot::Mutex<()>>,
        started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ScriptVerifier for GatedShadow {
        fn verify_transaction(
            &self,
            _tx: &Transaction,
            _prev_outputs: &[TxOut],
            _at: ScriptContext,
        ) -> Result<(), ScriptError> {
            self.started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(self.gate.lock());
            Ok(())
        }
    }

    fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The shadow queue is bounded by bytes as well as entries (#1145).
    /// With the one worker stuck in the shadow engine and a budget of three
    /// items, the fourth and fifth are dropped although the entry cap has
    /// room for a thousand. The worker releases each item's bytes when it
    /// takes it, so the queue drains back to zero and takes work again.
    ///
    /// Perturbation: without the byte check in `enqueue`, nothing is
    /// dropped and the queue holds five items' bytes.
    #[test]
    fn shadow_queue_drops_work_past_its_byte_budget() {
        use std::sync::atomic::Ordering::SeqCst;
        let gate = std::sync::Arc::new(parking_lot::Mutex::new(()));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let prevs = vec![TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51; 200]),
        }];
        let cost = ShadowWork::cost(&tx, &prevs);
        let verifier = ShadowVerifier::new(
            Box::new(NoopVerifier),
            Box::new(GatedShadow { gate: gate.clone(), started: started.clone() }),
            "noop",
            "gated",
            1_000,
            1,
        )
        .with_queue_bytes(3 * cost);

        let held = gate.lock();
        verifier.verify_transaction(&tx, &prevs, ScriptContext::unmined(1)).expect("the primary accepts");
        wait_for("the worker to take the first item", || started.load(SeqCst) == 1);
        assert_eq!(verifier.queued_bytes(), 0, "a dequeued item no longer counts");

        for _ in 0..5 {
            verifier.verify_transaction(&tx, &prevs, ScriptContext::unmined(1)).expect("the primary accepts");
        }
        assert_eq!(verifier.dropped_total(), 2, "two items past the byte budget are dropped");
        assert_eq!(verifier.queued_bytes(), 3 * cost);

        drop(held);
        wait_for("the queue to drain", || started.load(SeqCst) == 4 && verifier.queued_bytes() == 0);
        verifier.verify_transaction(&tx, &prevs, ScriptContext::unmined(1)).expect("the primary accepts");
        wait_for("the drained queue to take work again", || started.load(SeqCst) == 5);
        assert_eq!(verifier.dropped_total(), 2);
    }

    /// `-shadowqueuemb=0` leaves only the entry count, as before #1145.
    #[test]
    fn a_zero_byte_budget_leaves_only_the_entry_cap() {
        let gate = std::sync::Arc::new(parking_lot::Mutex::new(()));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let verifier = ShadowVerifier::new(
            Box::new(NoopVerifier),
            Box::new(GatedShadow { gate: gate.clone(), started: started.clone() }),
            "noop",
            "gated",
            4,
            1,
        )
        .with_queue_bytes(0);
        let held = gate.lock();
        verifier.verify_transaction(&tx, &[], ScriptContext::unmined(1)).expect("the primary accepts");
        wait_for("the worker to take the first item", || {
            started.load(std::sync::atomic::Ordering::SeqCst) == 1
        });
        for _ in 0..6 {
            verifier.verify_transaction(&tx, &[], ScriptContext::unmined(1)).expect("the primary accepts");
        }
        assert_eq!(verifier.dropped_total(), 2, "only the entry cap of 4 applies");
        drop(held);
    }
}
