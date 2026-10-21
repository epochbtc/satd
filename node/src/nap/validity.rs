//! Validity at an evaluation tip, and supersession.
//!
//! [`evaluate`] applies the rules cheapest first:
//!
//! 1. The anchor is the active chain's block at its height.
//! 2. Fresh: `tip_height - anchor_height < FRESHNESS_WINDOW`.
//! 3. The coin is in the UTXO set at the tip.
//! 4. The coin confirmed at or below `anchor_height - MIN_COIN_AGE`.
//! 5. The signature verifies over the message text against the coin's
//!    scriptPubKey: BIP 322 for formats 0 and 1, Bitcoin Core's
//!    `verifymessage` for format 2 (P2PKH only). BIP 322 *inconclusive* is
//!    invalid.
//! 6. A full proof's `to_sign` locktime and sequence are met as if `to_sign`
//!    were in the block after the tip (D11): the locktime against that
//!    height and the tip's median time past, the BIP 68 relative lock
//!    against the coin's confirmation. A proof that fails only here is not
//!    yet valid, and becomes valid when the chain reaches it.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Sequence};

use super::{Attestation, FRESHNESS_WINDOW, MIN_COIN_AGE, NapSignature};
use crate::bip322::{self, Proof, Verification};
use crate::rpc::signmessage;

/// A coin in the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    /// The height of the block that confirmed it.
    pub height: u32,
}

/// The chain state an evaluation reads. All of it is the active chain at
/// one tip; a pruned node has all of it.
pub trait ChainView {
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
    #[error(
        "coin confirmed at height {coin_height}, less than {MIN_COIN_AGE} blocks before the anchor at {anchor_height}"
    )]
    CoinTooYoung { coin_height: u32, anchor_height: u32 },
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

/// Evaluate `att` at `view`'s tip. A valid attestation's weight is the
/// returned coin's value.
pub fn evaluate(att: &Attestation, view: &dyn ChainView) -> Result<Coin, Rejection> {
    let tip = view.tip_height();
    if view.block_hash(att.anchor_height()) != Some(att.anchor_hash()) {
        return Err(Rejection::AnchorNotOnChain);
    }
    let age = tip.saturating_sub(att.anchor_height());
    if age >= FRESHNESS_WINDOW {
        return Err(Rejection::Stale { age });
    }
    let coin = view.coin(&att.outpoint()).ok_or(Rejection::CoinNotFound)?;
    if u64::from(coin.height) + u64::from(MIN_COIN_AGE) > u64::from(att.anchor_height()) {
        return Err(Rejection::CoinTooYoung {
            coin_height: coin.height,
            anchor_height: att.anchor_height(),
        });
    }

    let message = att.message();
    let proof = match att.signature() {
        NapSignature::Legacy(sig) => {
            verify_legacy(&coin.script_pubkey, &message, sig)?;
            return Ok(coin);
        }
        NapSignature::Simple(w) => Proof::Simple(w.clone()),
        NapSignature::Full(tx) => Proof::Full(tx.clone()),
    };
    match bip322::verify(&coin.script_pubkey, message.as_bytes(), &proof) {
        Verification::Valid { version, lock_time, sequence } => {
            check_timelocks(view, tip, &coin, version, lock_time, sequence)?;
            Ok(coin)
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

/// D11: `to_sign`'s locktime and input sequence, as if it were in the block
/// after `tip`. The arithmetic is consensus's (`IsFinalTx`,
/// `SequenceLocks`), with the coin standing for `to_sign`'s prevout.
fn check_timelocks(
    view: &dyn ChainView,
    tip: u32,
    coin: &Coin,
    version: i32,
    lock_time: u32,
    sequence: u32,
) -> Result<(), Rejection> {
    let next = tip + 1;
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

