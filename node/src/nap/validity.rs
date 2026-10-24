//! Validity at an evaluation tip, and supersession.
//!
//! [`evaluate`] applies the rules cheapest first:
//!
//! 1. The anchor is the active chain's block at its height.
//! 2. Fresh: `tip_height - anchor_height < FRESHNESS_WINDOW`.
//! 3. The coin is in the UTXO set at the tip, and holds at least
//!    [`MIN_COIN_VALUE`].
//! 4. The coin confirmed at or below `anchor_height - min_coin_age`:
//!    [`MIN_COIN_AGE`] on mainnet, [`TEST_MIN_COIN_AGE`] on the test
//!    networks, and at least [`COINBASE_MATURITY`] for a coinbase coin.
//! 5. The signature verifies over the message text against the coin's
//!    scriptPubKey: BIP 322 for formats 0 and 1, Bitcoin Core's
//!    `verifymessage` for format 2 (P2PKH only). BIP 322 *inconclusive* is
//!    invalid.
//! 6. A full proof's `to_sign` locktime and sequence are met as if `to_sign`
//!    were in the block after the tip (D11): the locktime against that
//!    height and the tip's median time past, the BIP 68 relative lock
//!    against the coin's confirmation. A proof that fails only here is not
//!    yet valid, and becomes valid when the chain reaches it.
//!
//! [`check_chain`], [`verify_signature`] and [`check_timelocks`] are those
//! steps apart. A signature's result depends only on the coin's
//! scriptPubKey, which never changes for an outpoint, so a publisher that
//! re-evaluates at every tip verifies each signature once.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence};

use super::{
    Attestation, COINBASE_MATURITY, FRESHNESS_WINDOW, MIN_COIN_AGE, MIN_COIN_VALUE, NapSignature,
    TEST_MIN_COIN_AGE,
};
use crate::bip322::{self, Proof, Verification};
use crate::rpc::signmessage;

/// A coin in the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    /// The height of the block that confirmed it.
    pub height: u32,
    /// Whether it is a coinbase output.
    pub coinbase: bool,
}

/// The chain state an evaluation reads. All of it is the active chain at
/// one tip; a pruned node has all of it.
pub trait ChainView {
    /// The network, which sets the minimum coin age.
    fn network(&self) -> Network;
    fn tip_height(&self) -> u32;
    /// The active chain's block at `height`, if the chain reaches it.
    fn block_hash(&self, height: u32) -> Option<BlockHash>;
    /// The median time of the 11 blocks below `height` (Core's
    /// `GetAncestor(height - 1)->GetMedianTimePast()`): the MTP a block at
    /// `height` is judged by. `height` is at most `tip_height + 1`.
    fn median_time_past(&self, height: u32) -> u32;
    /// The coin at `outpoint` in the UTXO set at the tip. Never an
    /// unconfirmed output.
    fn coin(&self, outpoint: &OutPoint) -> Option<Coin>;
}

/// Why an attestation is not valid at a tip, naming the rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    #[error("anchor block is not on the active chain")]
    AnchorNotOnChain,
    #[error("anchor is {age} blocks below the tip; attestations expire at {FRESHNESS_WINDOW}")]
    Stale { age: u32 },
    #[error("coin is not in the UTXO set")]
    CoinNotFound,
    #[error("coin holds {value} sats, less than the {min} an attesting coin needs")]
    CoinTooSmall { value: u64, min: u64 },
    #[error(
        "coin confirmed at height {coin_height}, less than {min_age} blocks before the anchor at {anchor_height}"
    )]
    CoinTooYoung { coin_height: u32, anchor_height: u32, min_age: u32 },
    #[error("signature format does not apply to this output: {0}")]
    WrongFormat(&'static str),
    #[error("signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("signature is inconclusive: {0}")]
    SignatureInconclusive(String),
    #[error("proof is not yet valid: {0}")]
    NotYetValid(&'static str),
}

impl Rejection {
    /// The rule's stable name, as RPCs report it.
    pub fn rule(&self) -> &'static str {
        match self {
            Rejection::AnchorNotOnChain => "anchor-not-on-chain",
            Rejection::Stale { .. } => "stale",
            Rejection::CoinNotFound => "coin-not-found",
            Rejection::CoinTooSmall { .. } => "coin-too-small",
            Rejection::CoinTooYoung { .. } => "coin-too-young",
            Rejection::WrongFormat(_) => "wrong-format",
            Rejection::SignatureInvalid(_) => "signature-invalid",
            Rejection::SignatureInconclusive(_) => "signature-inconclusive",
            Rejection::NotYetValid(_) => "not-yet-valid",
        }
    }

    /// Whether the attestation may become valid, or was valid, at another
    /// tip: a peer whose tip differs can serve it honestly. Every other
    /// rejection is wrong at every tip.
    pub fn is_chain_state(&self) -> bool {
        matches!(
            self,
            Rejection::AnchorNotOnChain
                | Rejection::Stale { .. }
                | Rejection::CoinNotFound
                | Rejection::CoinTooYoung { .. }
                | Rejection::NotYetValid(_)
        )
    }
}

/// What a verified signature leaves for the chain to judge: `to_sign`'s
/// version, locktime and input sequence. All zero for simple and legacy
/// signatures, which no timelock can hold back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timelocks {
    pub version: i32,
    pub lock_time: u32,
    pub sequence: u32,
}

/// Evaluate `att` at `view`'s tip. A valid attestation's weight is the
/// returned coin's value.
pub fn evaluate(att: &Attestation, view: &dyn ChainView) -> Result<Coin, Rejection> {
    let coin = check_chain(att, view)?;
    let locks = verify_signature(att, &coin.script_pubkey)?;
    check_timelocks(view, &coin, &locks)?;
    Ok(coin)
}

/// Rules 1–4: the anchor, freshness, and the coin, its value and its age.
/// Returns the coin.
pub fn check_chain(att: &Attestation, view: &dyn ChainView) -> Result<Coin, Rejection> {
    let tip = view.tip_height();
    if view.block_hash(att.anchor_height()) != Some(att.anchor_hash()) {
        return Err(Rejection::AnchorNotOnChain);
    }
    let age = tip.saturating_sub(att.anchor_height());
    if age >= FRESHNESS_WINDOW {
        return Err(Rejection::Stale { age });
    }
    let coin = view.coin(&att.outpoint()).ok_or(Rejection::CoinNotFound)?;
    check_coin_value(&coin)?;
    check_coin_age(view.network(), &coin, att.anchor_height())?;
    Ok(coin)
}

/// Rule 3's floor alone: `coin` holds at least [`MIN_COIN_VALUE`]. An
/// outpoint's value never changes, so this holds or fails at every tip.
pub fn check_coin_value(coin: &Coin) -> Result<(), Rejection> {
    if coin.value < MIN_COIN_VALUE {
        return Err(Rejection::CoinTooSmall { value: coin.value.to_sat(), min: MIN_COIN_VALUE.to_sat() });
    }
    Ok(())
}

/// The age `coin` must have at the anchor on `network`.
pub fn min_coin_age(network: Network, coin: &Coin) -> u32 {
    // No wildcard arm: a network rust-bitcoin adds must be placed here,
    // not given the short age by default.
    let age = match network {
        Network::Bitcoin => MIN_COIN_AGE,
        Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => TEST_MIN_COIN_AGE,
    };
    if coin.coinbase { age.max(COINBASE_MATURITY) } else { age }
}

/// Rule 4 alone: `coin` confirmed at least [`min_coin_age`] blocks below
/// `anchor_height`.
pub fn check_coin_age(network: Network, coin: &Coin, anchor_height: u32) -> Result<(), Rejection> {
    let min_age = min_coin_age(network, coin);
    if u64::from(coin.height) + u64::from(min_age) > u64::from(anchor_height) {
        return Err(Rejection::CoinTooYoung { coin_height: coin.height, anchor_height, min_age });
    }
    Ok(())
}

/// Rule 5: the signature over the message text against `script`, the coin's
/// scriptPubKey. The result holds at every tip.
pub fn verify_signature(att: &Attestation, script: &ScriptBuf) -> Result<Timelocks, Rejection> {
    let message = att.message();
    let proof = match att.signature() {
        NapSignature::Legacy(sig) => {
            verify_legacy(script, &message, sig)?;
            return Ok(Timelocks::default());
        }
        NapSignature::Simple(_) if !script.is_witness_program() => {
            return Err(Rejection::WrongFormat(
                "a simple signature is for a native segwit output only; sign a full proof",
            ));
        }
        NapSignature::Simple(w) => Proof::Simple(w.clone()),
        NapSignature::Full(tx) => Proof::Full(tx.clone()),
    };
    match bip322::verify(script, message.as_bytes(), &proof) {
        Verification::Valid { version, lock_time, sequence } => {
            Ok(Timelocks { version, lock_time, sequence })
        }
        Verification::Inconclusive(reason) => Err(Rejection::SignatureInconclusive(reason)),
        Verification::Invalid(reason) => Err(Rejection::SignatureInvalid(reason)),
    }
}

/// Format 2: Core's `verifymessage` against a P2PKH coin.
fn verify_legacy(script: &ScriptBuf, message: &str, sig: &[u8]) -> Result<(), Rejection> {
    if !script.is_p2pkh() {
        return Err(Rejection::WrongFormat("a legacy signature is for a P2PKH output only"));
    }
    let key = signmessage::recover_compact(&signmessage::message_hash(message), sig)
        .ok_or_else(|| Rejection::SignatureInvalid("no public key recovers from it".into()))?;
    if ScriptBuf::new_p2pkh(&key.pubkey_hash()) != *script {
        return Err(Rejection::SignatureInvalid("signed by another key".into()));
    }
    Ok(())
}

/// Rule 6 (D11): `to_sign`'s locktime and input sequence, as if it were in
/// the block after `view`'s tip. The arithmetic is consensus's
/// (`IsFinalTx`, `SequenceLocks`), with `coin` standing for `to_sign`'s
/// prevout.
pub fn check_timelocks(view: &dyn ChainView, coin: &Coin, locks: &Timelocks) -> Result<(), Rejection> {
    let Timelocks { version, lock_time, sequence } = *locks;
    let next = view.tip_height() + 1;
    let tip_mtp = view.median_time_past(next);

    // IsFinalTx: a locktime is met when strictly below the cutoff, and
    // ignored when the (only) input's sequence is final.
    if lock_time != 0 && sequence != Sequence::MAX.0 {
        let (cutoff, which) = if lock_time < bitcoin::absolute::LOCK_TIME_THRESHOLD {
            (next, "its locktime height is not reached")
        } else {
            (tip_mtp, "its locktime time is not reached")
        };
        if lock_time >= cutoff {
            return Err(Rejection::NotYetValid(which));
        }
    }

    // BIP 68, for version 2 and up, unless the disable flag is set.
    const DISABLE_FLAG: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    const MASK: u32 = 0x0000_ffff;
    if (version as u32) < 2 || sequence & DISABLE_FLAG != 0 {
        return Ok(());
    }
    if sequence & TYPE_FLAG != 0 {
        let required = u64::from(sequence & MASK) << 9;
        let coin_mtp = u64::from(view.median_time_past(coin.height));
        if u64::from(tip_mtp).saturating_sub(coin_mtp) < required {
            return Err(Rejection::NotYetValid("its relative time lock is not reached"));
        }
    } else if next.saturating_sub(coin.height) < sequence & MASK {
        return Err(Rejection::NotYetValid("its relative height lock is not reached"));
    }
    Ok(())
}

/// Whether `a` counts over `b` for the same `(outpoint, key)`: the higher
/// anchor, then the lower [`Attestation::id`] (compared as bytes).
pub fn supersedes(a: &Attestation, b: &Attestation) -> bool {
    (a.anchor_height(), std::cmp::Reverse(a.id().to_byte_array()))
        > (b.anchor_height(), std::cmp::Reverse(b.id().to_byte_array()))
}

/// The attestation that counts for each `(outpoint, key)` among `valid`,
/// which the caller has already evaluated at one tip.
pub fn select<'a>(
    valid: impl IntoIterator<Item = &'a Attestation>,
) -> BTreeMap<(OutPoint, &'a str), &'a Attestation> {
    let mut out: BTreeMap<(OutPoint, &'a str), &'a Attestation> = BTreeMap::new();
    for att in valid {
        out.entry((att.outpoint(), att.key()))
            .and_modify(|cur| {
                if supersedes(att, cur) {
                    *cur = att;
                }
            })
            .or_insert(att);
    }
    out
}

