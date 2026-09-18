//! A typed, read-only view over a version 2 [`RawPsbt`].
//!
//! Nothing here mutates. The raw layer owns the bytes; this layer only reads
//! fields out of them and says precisely which field was wrong when one is.
//! Accessors are strict about lengths, because a caller that gets a value at
//! all should be able to trust it; `decodepsbt` reaches past this view to the
//! raw map when it wants to *show* a malformed field rather than refuse it.

use bitcoin::secp256k1::PublicKey;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version as TxVersion,
};

use crate::error::{MapId, PsbtError};
use crate::keys::{self, LOCKTIME_THRESHOLD, modifiable};
use crate::raw::{PsbtVersion, RawMap, RawPair, RawPsbt};

/// A BIP 375 ECDH share, with the scan key it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpShare {
    pub scan_key: [u8; 33],
    pub share: [u8; 33],
}

/// A BIP 374 DLEQ proof, with the scan key it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpProof {
    pub scan_key: [u8; 33],
    pub proof: [u8; 64],
}

/// A silent payment recipient, as carried by `PSBT_OUT_SP_V0_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpV0Info {
    pub scan_key: PublicKey,
    pub spend_key: PublicKey,
}

/// A version 2 PSBT, seen through its fields.
#[derive(Debug, Clone, Copy)]
pub struct V2View<'a> {
    raw: &'a RawPsbt,
}

impl<'a> V2View<'a> {
    /// Wrap a PSBT that declares version 2.
    pub fn new(raw: &'a RawPsbt) -> Result<Self, PsbtError> {
        match raw.version()? {
            PsbtVersion::V2 => Ok(V2View { raw }),
            PsbtVersion::V0 => Err(PsbtError::UnsupportedVersion(0)),
        }
    }

    pub fn raw(&self) -> &'a RawPsbt {
        self.raw
    }

    pub fn input_count(&self) -> usize {
        self.raw.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.raw.outputs.len()
    }

    pub fn input(&self, index: usize) -> Option<InputView<'a>> {
        self.raw
            .inputs
            .get(index)
            .map(|map| InputView { map, index })
    }

    pub fn output(&self, index: usize) -> Option<OutputView<'a>> {
        self.raw
            .outputs
            .get(index)
            .map(|map| OutputView { map, index })
    }

    pub fn inputs(&self) -> impl Iterator<Item = InputView<'a>> + '_ {
        self.raw
            .inputs
            .iter()
            .enumerate()
            .map(|(index, map)| InputView { map, index })
    }

    pub fn outputs(&self) -> impl Iterator<Item = OutputView<'a>> + '_ {
        self.raw
            .outputs
            .iter()
            .enumerate()
            .map(|(index, map)| OutputView { map, index })
    }

    pub fn tx_version(&self) -> Result<u32, PsbtError> {
        let raw = self
            .raw
            .global
            .get_single(keys::global::TX_VERSION)
            .ok_or(PsbtError::MissingGlobal("PSBT_GLOBAL_TX_VERSION"))?;
        le_u32(raw, MapId::Global, keys::global::TX_VERSION)
    }

    pub fn fallback_locktime(&self) -> Result<Option<u32>, PsbtError> {
        match self.raw.global.get_single(keys::global::FALLBACK_LOCKTIME) {
            None => Ok(None),
            Some(raw) => le_u32(raw, MapId::Global, keys::global::FALLBACK_LOCKTIME).map(Some),
        }
    }

    /// `PSBT_GLOBAL_TX_MODIFIABLE`. Absent means no bits set.
    pub fn tx_modifiable(&self) -> Result<u8, PsbtError> {
        match self.raw.global.get_single(keys::global::TX_MODIFIABLE) {
            None => Ok(0),
            Some(raw) if raw.len() == 1 => Ok(raw[0]),
            Some(raw) => Err(PsbtError::BadFieldLength {
                map: MapId::Global,
                key_type: keys::global::TX_MODIFIABLE,
                len: raw.len(),
                expected: "1",
            }),
        }
    }

    pub fn inputs_modifiable(&self) -> Result<bool, PsbtError> {
        Ok(self.tx_modifiable()? & modifiable::INPUTS != 0)
    }

    pub fn outputs_modifiable(&self) -> Result<bool, PsbtError> {
        Ok(self.tx_modifiable()? & modifiable::OUTPUTS != 0)
    }

    pub fn has_sighash_single(&self) -> Result<bool, PsbtError> {
        Ok(self.tx_modifiable()? & modifiable::HAS_SIGHASH_SINGLE != 0)
    }

    /// The global ECDH shares, one per scan key.
    pub fn sp_ecdh_shares(&self) -> Result<Vec<SpShare>, PsbtError> {
        sp_shares(&self.raw.global, MapId::Global, keys::global::SP_ECDH_SHARE)
    }

    /// The global DLEQ proofs, one per scan key.
    pub fn sp_dleq_proofs(&self) -> Result<Vec<SpProof>, PsbtError> {
        sp_proofs(&self.raw.global, MapId::Global, keys::global::SP_DLEQ)
    }

    /// Every distinct scan key named by a silent payment output, in the order
    /// it is first seen.
    pub fn sp_scan_keys(&self) -> Result<Vec<PublicKey>, PsbtError> {
        let mut out: Vec<PublicKey> = Vec::new();
        for output in self.outputs() {
            if let Some(info) = output.sp_v0_info()?
                && !out.contains(&info.scan_key)
            {
                out.push(info.scan_key);
            }
        }
        Ok(out)
    }

    /// Whether any output is a silent payment output.
    pub fn has_sp_outputs(&self) -> bool {
        self.raw
            .outputs
            .iter()
            .any(|m| m.contains_type(keys::output::SP_V0_INFO))
    }

    /// The transaction lock time, by BIP 370's determination rules.
    ///
    /// Inputs that name no lock time accept either kind; the kind chosen is
    /// the one every input that *does* name one can accept, and the value is
    /// the largest of that kind. A height lock time wins a tie, so that
    /// signers cannot disagree about which they committed to.
    pub fn lock_time(&self) -> Result<LockTime, PsbtError> {
        let mut any_required = false;
        let mut height_max: u32 = 0;
        let mut time_max: u32 = 0;
        let mut without_height: Option<usize> = None;
        let mut without_time: Option<usize> = None;

        for input in self.inputs() {
            let height = input.height_locktime()?;
            let time = input.time_locktime()?;
            if height.is_none() && time.is_none() {
                continue;
            }
            any_required = true;
            match height {
                Some(h) => height_max = height_max.max(h),
                None => {
                    without_height.get_or_insert(input.index());
                }
            }
            match time {
                Some(t) => time_max = time_max.max(t),
                None => {
                    without_time.get_or_insert(input.index());
                }
            }
        }

        if !any_required {
            let fallback = self.fallback_locktime()?.unwrap_or(0);
            return LockTime::from_consensus(fallback).into_ok();
        }
        if without_height.is_none() {
            return LockTime::from_consensus(height_max).into_ok();
        }
        if without_time.is_none() {
            return LockTime::from_consensus(time_max).into_ok();
        }
        // Some input can only take a height and some other only a time.
        Err(PsbtError::ConflictingLockTimes(
            without_time.unwrap_or(0),
            without_height.unwrap_or(0),
        ))
    }

    /// The transaction this PSBT describes, unsigned.
    ///
    /// Fails by name if any output's script has not been computed, which for
    /// a BIP 375 PSBT means the Signer has not finished its work.
    pub fn unsigned_tx(&self) -> Result<Transaction, PsbtError> {
        self.build_tx(false)
    }

    /// BIP 370's unique identifier: the transaction id of the unsigned
    /// transaction with every sequence set to zero, so that an Updater's
    /// sequence change does not make two copies of one PSBT look different.
    ///
    /// BIP 375 amends it: a silent payment output has no script to commit to
    /// while it is still being computed, so `0x00 || scan || spend` stands in
    /// for the script.
    pub fn unique_id(&self) -> Result<Txid, PsbtError> {
        let mut tx = self.build_tx(true)?;
        for (index, output) in self.outputs().enumerate() {
            if let Some(info) = output.sp_v0_info()? {
                let mut bytes = Vec::with_capacity(67);
                bytes.push(0x00);
                bytes.extend_from_slice(&info.scan_key.serialize());
                bytes.extend_from_slice(&info.spend_key.serialize());
                if let Some(out) = tx.output.get_mut(index) {
                    out.script_pubkey = ScriptBuf::from_bytes(bytes);
                }
            }
        }
        Ok(tx.compute_txid())
    }

    fn build_tx(&self, sp_placeholder: bool) -> Result<Transaction, PsbtError> {
        let version = TxVersion(self.tx_version()? as i32);
        let lock_time = self.lock_time()?;

        let mut input = Vec::with_capacity(self.input_count());
        for view in self.inputs() {
            input.push(TxIn {
                previous_output: view.outpoint()?,
                script_sig: ScriptBuf::new(),
                // The unique identifier zeroes sequences (BIP 370); the
                // unsigned transaction uses the real ones.
                sequence: if sp_placeholder {
                    Sequence::ZERO
                } else {
                    view.sequence()?
                },
                witness: Witness::new(),
            });
        }

        let mut output = Vec::with_capacity(self.output_count());
        for view in self.outputs() {
            let script = match view.script()? {
                Some(script) => script,
                None if sp_placeholder => ScriptBuf::new(),
                None => return Err(PsbtError::OutputScriptNotComputed(view.index())),
            };
            output.push(TxOut {
                value: view.amount()?,
                script_pubkey: script,
            });
        }

        Ok(Transaction {
            version,
            lock_time,
            input,
            output,
        })
    }

    /// Rebuild this PSBT as a version 0 one, so that code written against
    /// `bitcoin::Psbt` can finish the job.
    ///
    /// The version 2 and BIP 375 fields do not survive, by construction: they
    /// have no version 0 encoding. Everything else — signatures, scripts,
    /// derivations, unknown pairs — is carried across in place.
    pub fn to_v0(&self) -> Result<bitcoin::Psbt, PsbtError> {
        let tx = self.unsigned_tx()?;

        let mut global = RawMap::new();
        global.set(RawPair::new(
            keys::global::UNSIGNED_TX,
            Vec::new(),
            bitcoin::consensus::serialize(&tx),
        ));
        for pair in self.raw.global.pairs() {
            let drop = pair.key_type == keys::global::UNSIGNED_TX
                || pair.key_type == keys::global::VERSION
                || pair.key_type == keys::global::SP_ECDH_SHARE
                || pair.key_type == keys::global::SP_DLEQ
                || keys::global::V2_ONLY.contains(&pair.key_type);
            if !drop {
                global.set(pair.clone());
            }
        }

        let strip = |map: &RawMap, dropped: &[u64]| -> RawMap {
            map.pairs()
                .iter()
                .filter(|p| !dropped.contains(&p.key_type))
                .cloned()
                .collect()
        };

        let mut dropped_in = keys::input::V2_ONLY.to_vec();
        dropped_in.push(keys::input::SP_ECDH_SHARE);
        dropped_in.push(keys::input::SP_DLEQ);
        let mut dropped_out = keys::output::V2_ONLY.to_vec();
        dropped_out.push(keys::output::SP_V0_INFO);
        dropped_out.push(keys::output::SP_V0_LABEL);

        let v0 = RawPsbt {
            global,
            inputs: self.raw.inputs.iter().map(|m| strip(m, &dropped_in)).collect(),
            outputs: self
                .raw
                .outputs
                .iter()
                .map(|m| strip(m, &dropped_out))
                .collect(),
        };

        bitcoin::Psbt::deserialize(&v0.serialize())
            .map_err(|e| PsbtError::V0Roundtrip(e.to_string()))
    }
}

/// One input's fields.
#[derive(Debug, Clone, Copy)]
pub struct InputView<'a> {
    map: &'a RawMap,
    index: usize,
}

impl<'a> InputView<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn map(&self) -> &'a RawMap {
        self.map
    }

    fn id(&self) -> MapId {
        MapId::Input(self.index)
    }

    pub fn previous_txid(&self) -> Result<Txid, PsbtError> {
        let raw = self
            .map
            .get_single(keys::input::PREVIOUS_TXID)
            .ok_or(PsbtError::MissingField {
                map: self.id(),
                field: "PSBT_IN_PREVIOUS_TXID",
            })?;
        if raw.len() != 32 {
            return Err(PsbtError::BadFieldLength {
                map: self.id(),
                key_type: keys::input::PREVIOUS_TXID,
                len: raw.len(),
                expected: "32",
            });
        }
        bitcoin::consensus::deserialize(raw).map_err(|_| PsbtError::BadFieldLength {
            map: self.id(),
            key_type: keys::input::PREVIOUS_TXID,
            len: raw.len(),
            expected: "32",
        })
    }

    pub fn output_index(&self) -> Result<u32, PsbtError> {
        let raw = self
            .map
            .get_single(keys::input::OUTPUT_INDEX)
            .ok_or(PsbtError::MissingField {
                map: self.id(),
                field: "PSBT_IN_OUTPUT_INDEX",
            })?;
        le_u32(raw, self.id(), keys::input::OUTPUT_INDEX)
    }

    pub fn outpoint(&self) -> Result<OutPoint, PsbtError> {
        Ok(OutPoint {
            txid: self.previous_txid()?,
            vout: self.output_index()?,
        })
    }

    /// Absent means final (`0xffffffff`), as BIP 370 says.
    pub fn sequence(&self) -> Result<Sequence, PsbtError> {
        match self.map.get_single(keys::input::SEQUENCE) {
            None => Ok(Sequence::MAX),
            Some(raw) => Ok(Sequence(le_u32(raw, self.id(), keys::input::SEQUENCE)?)),
        }
    }

    pub fn time_locktime(&self) -> Result<Option<u32>, PsbtError> {
        match self.map.get_single(keys::input::REQUIRED_TIME_LOCKTIME) {
            None => Ok(None),
            Some(raw) => {
                let v = le_u32(raw, self.id(), keys::input::REQUIRED_TIME_LOCKTIME)?;
                if v < LOCKTIME_THRESHOLD {
                    return Err(PsbtError::TimeLockTimeTooSmall(self.index));
                }
                Ok(Some(v))
            }
        }
    }

    pub fn height_locktime(&self) -> Result<Option<u32>, PsbtError> {
        match self.map.get_single(keys::input::REQUIRED_HEIGHT_LOCKTIME) {
            None => Ok(None),
            Some(raw) => {
                let v = le_u32(raw, self.id(), keys::input::REQUIRED_HEIGHT_LOCKTIME)?;
                if v == 0 {
                    return Err(PsbtError::HeightLockTimeZero(self.index));
                }
                if v >= LOCKTIME_THRESHOLD {
                    return Err(PsbtError::HeightLockTimeTooLarge(self.index));
                }
                Ok(Some(v))
            }
        }
    }

    pub fn witness_utxo(&self) -> Result<Option<TxOut>, PsbtError> {
        match self.map.get_single(keys::input::WITNESS_UTXO) {
            None => Ok(None),
            Some(raw) => bitcoin::consensus::deserialize(raw)
                .map(Some)
                .map_err(|_| PsbtError::BadFieldLength {
                    map: self.id(),
                    key_type: keys::input::WITNESS_UTXO,
                    len: raw.len(),
                    expected: "a serialized transaction output",
                }),
        }
    }

    pub fn non_witness_utxo(&self) -> Result<Option<Transaction>, PsbtError> {
        match self.map.get_single(keys::input::NON_WITNESS_UTXO) {
            None => Ok(None),
            Some(raw) => bitcoin::consensus::deserialize(raw)
                .map(Some)
                .map_err(|_| PsbtError::BadFieldLength {
                    map: self.id(),
                    key_type: keys::input::NON_WITNESS_UTXO,
                    len: raw.len(),
                    expected: "a serialized transaction",
                }),
        }
    }

    /// The output this input spends, by Bitcoin Core's `GetInputUTXO` rule: a
    /// full previous transaction wins over a bare output, and its txid must be
    /// the one the input names. A PSBT's author writes both fields, so trusting
    /// the bare one without that check would let the author claim any prevout
    /// it liked — which for a taproot input is the same as claiming any
    /// public key.
    pub fn prevout(&self) -> Result<Option<TxOut>, PsbtError> {
        if let Some(tx) = self.non_witness_utxo()? {
            let txid = self.previous_txid()?;
            if tx.compute_txid() != txid {
                return Err(PsbtError::structure(format!(
                    "input {}: PSBT_IN_NON_WITNESS_UTXO is not the transaction named by \
                     PSBT_IN_PREVIOUS_TXID",
                    self.index
                )));
            }
            let vout = self.output_index()? as usize;
            return match tx.output.get(vout) {
                Some(out) => Ok(Some(out.clone())),
                None => Err(PsbtError::structure(format!(
                    "input {}: PSBT_IN_OUTPUT_INDEX is past the end of \
                     PSBT_IN_NON_WITNESS_UTXO",
                    self.index
                ))),
            };
        }
        self.witness_utxo()
    }

    pub fn sighash_type(&self) -> Result<Option<u32>, PsbtError> {
        match self.map.get_single(keys::input::SIGHASH_TYPE) {
            None => Ok(None),
            Some(raw) => le_u32(raw, self.id(), keys::input::SIGHASH_TYPE).map(Some),
        }
    }

    pub fn redeem_script(&self) -> Result<Option<ScriptBuf>, PsbtError> {
        Ok(self
            .map
            .get_single(keys::input::REDEEM_SCRIPT)
            .map(|raw| ScriptBuf::from_bytes(raw.to_vec())))
    }

    /// `(public key, derivation blob)` for every `PSBT_IN_BIP32_DERIVATION`.
    pub fn bip32_derivations(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.map.get_all(keys::input::BIP32_DERIVATION)
    }

    /// `(public key, signature)` for every `PSBT_IN_PARTIAL_SIG`.
    pub fn partial_sigs(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.map.get_all(keys::input::PARTIAL_SIG)
    }

    pub fn tap_internal_key(&self) -> Result<Option<[u8; 32]>, PsbtError> {
        match self.map.get_single(keys::input::TAP_INTERNAL_KEY) {
            None => Ok(None),
            Some(raw) if raw.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(raw);
                Ok(Some(out))
            }
            Some(raw) => Err(PsbtError::BadFieldLength {
                map: self.id(),
                key_type: keys::input::TAP_INTERNAL_KEY,
                len: raw.len(),
                expected: "32",
            }),
        }
    }

    pub fn tap_key_sig(&self) -> Option<&'a [u8]> {
        self.map.get_single(keys::input::TAP_KEY_SIG)
    }

    pub fn final_script_witness(&self) -> Option<&'a [u8]> {
        self.map.get_single(keys::input::FINAL_SCRIPTWITNESS)
    }

    pub fn sp_ecdh_shares(&self) -> Result<Vec<SpShare>, PsbtError> {
        sp_shares(self.map, self.id(), keys::input::SP_ECDH_SHARE)
    }

    pub fn sp_dleq_proofs(&self) -> Result<Vec<SpProof>, PsbtError> {
        sp_proofs(self.map, self.id(), keys::input::SP_DLEQ)
    }
}

/// One output's fields.
#[derive(Debug, Clone, Copy)]
pub struct OutputView<'a> {
    map: &'a RawMap,
    index: usize,
}

impl<'a> OutputView<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn map(&self) -> &'a RawMap {
        self.map
    }

    fn id(&self) -> MapId {
        MapId::Output(self.index)
    }

    pub fn amount(&self) -> Result<Amount, PsbtError> {
        let raw = self
            .map
            .get_single(keys::output::AMOUNT)
            .ok_or(PsbtError::MissingField {
                map: self.id(),
                field: "PSBT_OUT_AMOUNT",
            })?;
        if raw.len() != 8 {
            return Err(PsbtError::BadFieldLength {
                map: self.id(),
                key_type: keys::output::AMOUNT,
                len: raw.len(),
                expected: "8",
            });
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(raw);
        let sats = i64::from_le_bytes(b);
        if sats < 0 || sats > bitcoin::Amount::MAX_MONEY.to_sat() as i64 {
            return Err(PsbtError::OutputAmountOutOfRange(self.index));
        }
        Ok(Amount::from_sat(sats as u64))
    }

    /// `None` when the script has not been computed yet, which BIP 375 allows
    /// only for a silent payment output.
    pub fn script(&self) -> Result<Option<ScriptBuf>, PsbtError> {
        Ok(self
            .map
            .get_single(keys::output::SCRIPT)
            .map(|raw| ScriptBuf::from_bytes(raw.to_vec())))
    }

    pub fn sp_v0_info(&self) -> Result<Option<SpV0Info>, PsbtError> {
        let raw = match self.map.get_single(keys::output::SP_V0_INFO) {
            None => return Ok(None),
            Some(raw) => raw,
        };
        if raw.len() != 66 {
            return Err(PsbtError::BadFieldLength {
                map: self.id(),
                key_type: keys::output::SP_V0_INFO,
                len: raw.len(),
                expected: "66",
            });
        }
        let scan_key = PublicKey::from_slice(&raw[..33]).map_err(|_| PsbtError::BadPublicKey {
            map: self.id(),
            key_type: keys::output::SP_V0_INFO,
        })?;
        let spend_key = PublicKey::from_slice(&raw[33..]).map_err(|_| PsbtError::BadPublicKey {
            map: self.id(),
            key_type: keys::output::SP_V0_INFO,
        })?;
        Ok(Some(SpV0Info {
            scan_key,
            spend_key,
        }))
    }

    pub fn sp_v0_label(&self) -> Result<Option<u32>, PsbtError> {
        match self.map.get_single(keys::output::SP_V0_LABEL) {
            None => Ok(None),
            Some(raw) => le_u32(raw, self.id(), keys::output::SP_V0_LABEL).map(Some),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared field readers
// ---------------------------------------------------------------------------

fn le_u32(raw: &[u8], map: MapId, key_type: u64) -> Result<u32, PsbtError> {
    if raw.len() != 4 {
        return Err(PsbtError::BadFieldLength {
            map,
            key_type,
            len: raw.len(),
            expected: "4",
        });
    }
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn scan_key_of(key_data: &[u8], map: MapId, key_type: u64) -> Result<[u8; 33], PsbtError> {
    if key_data.len() != 33 {
        return Err(PsbtError::BadKeyDataLength {
            map,
            key_type,
            len: key_data.len(),
            expected: "a 33-byte scan key",
        });
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(key_data);
    Ok(out)
}

fn sp_shares(map: &RawMap, id: MapId, key_type: u64) -> Result<Vec<SpShare>, PsbtError> {
    let mut out = Vec::new();
    for (key_data, value) in map.get_all(key_type) {
        let scan_key = scan_key_of(key_data, id, key_type)?;
        if value.len() != 33 {
            return Err(PsbtError::BadFieldLength {
                map: id,
                key_type,
                len: value.len(),
                expected: "33",
            });
        }
        let mut share = [0u8; 33];
        share.copy_from_slice(value);
        out.push(SpShare { scan_key, share });
    }
    Ok(out)
}

fn sp_proofs(map: &RawMap, id: MapId, key_type: u64) -> Result<Vec<SpProof>, PsbtError> {
    let mut out = Vec::new();
    for (key_data, value) in map.get_all(key_type) {
        let scan_key = scan_key_of(key_data, id, key_type)?;
        if value.len() != 64 {
            return Err(PsbtError::BadFieldLength {
                map: id,
                key_type,
                len: value.len(),
                expected: "64",
            });
        }
        let mut proof = [0u8; 64];
        proof.copy_from_slice(value);
        out.push(SpProof { scan_key, proof });
    }
    Ok(out)
}

/// Small helper so the lock-time arms read as one line each.
trait IntoOk<T> {
    fn into_ok(self) -> Result<T, PsbtError>;
}

impl IntoOk<LockTime> for LockTime {
    fn into_ok(self) -> Result<LockTime, PsbtError> {
        Ok(self)
    }
}
