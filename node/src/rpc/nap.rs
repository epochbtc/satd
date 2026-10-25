//! The NAP RPCs, satd's own. The publisher's, `createnapattestation`,
//! `submitnapattestation`, `listnapattestations` and
//! `removenapattestation`, answer an error unless the node runs with
//! `-nap=1`; the aggregator's, `listnapaggregate`, `getnapreport` and
//! `exportnapsnapshot`, unless it runs with `-napaggregator=1`.
//! `replaynapsnapshot` reports on a snapshot file and needs only the chain.

use std::path::Path;
use std::str::FromStr as _;

use base64::Engine as _;

use bitcoin::{OutPoint, ScriptBuf};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};

use crate::bip322;
use crate::chain::state::ChainState;
use crate::nap::publisher::{Published, encode_signature};
use crate::nap::publisher::ChainSource as _;
use crate::nap::report;
use crate::nap::validity::Timelocks;
use crate::nap::{Attestation, NapSignature, PublishError, Publisher};
use crate::rpc::amounts::{annotate_units, default_unit, format_amount};
use crate::rpc::error::RpcError;

/// The publisher, or the error every NAP RPC answers without `-nap=1`.
pub fn enabled(nap: Option<&Publisher>) -> Result<&Publisher, ErrorObjectOwned> {
    nap.ok_or_else(|| {
        RpcError::new(-1, "network.disabled", "NAP is disabled")
            .with_suggestion("Start satd with -nap=1 to publish attestations.")
            .into_error_object()
    })
}

/// The aggregator, or the error `listnapaggregate` answers without
/// `-napaggregator=1`.
pub fn aggregator_enabled(
    aggregator: Option<&crate::nap::pull::Puller>,
) -> Result<&crate::nap::pull::Puller, ErrorObjectOwned> {
    aggregator.ok_or_else(|| {
        RpcError::new(-1, "network.disabled", "the NAP aggregator is disabled")
            .with_suggestion("Start satd with -napaggregator=1 to collect attestations.")
            .into_error_object()
    })
}

/// `listnapaggregate`: the attestations that count at the tip the set was
/// last judged at, one per `(outpoint, key)`, ordered by outpoint and key,
/// with the collection's statistics.
pub fn list_aggregate(p: &crate::nap::pull::Puller, chain: &ChainState) -> Value {
    let unit = default_unit();
    let collector = p.collector();
    let aggregate = collector.aggregate();
    let counting = aggregate.counting();
    let stats = p.stats();
    let attestations: Vec<Value> = counting
        .iter()
        .map(|h| {
            let att = &h.attestation;
            json!({
                "id": att.id().to_string(),
                "outpoint": att.outpoint().to_string(),
                "key": att.key(),
                "value": att.value(),
                "anchor_height": att.anchor_height(),
                "anchor_hash": att.anchor_hash().to_string(),
                "amount": format_amount(h.status.as_ref().map_or(0, |a| a.to_sat()), unit),
                "source": h.source,
            })
        })
        .collect();
    let mut out = json!({
        "height": chain.tip_height(),
        "held": aggregate.len(),
        "counting": counting.len(),
        "deferred": collector.deferred_len(),
        "pulls": {
            "active": p.active(),
            "completed": stats.pulls_completed,
            "timed_out": stats.pulls_timed_out,
            "pages": stats.pages,
        },
        "misbehaving": stats.misbehaving,
        "unsolicited": stats.unsolicited,
        "key_limit": stats.key_limit,
        "full": stats.full,
        "attestations": attestations,
    });
    annotate_units(&mut out, unit);
    out
}

/// The tip moved through every read of a report or a snapshot.
fn tip_kept_changing() -> ErrorObjectOwned {
    RpcError::new(-1, "node.busy", "the chain tip kept changing while the NAP set was judged")
        .with_suggestion("Ask again.")
        .into_error_object()
}

/// `getnapreport`: the report on the aggregator's own set, every
/// attestation held judged at the tip, with the digest of the set. The
/// signatures verified when the attestations were collected, so this reads
/// only the chain. It is computed once per tip and set, and served again
/// until either changes, or for [`report::REPORT_REUSE`] on the same tip
/// while collection keeps changing the set, so asking often costs nothing.
pub fn report(p: &crate::nap::pull::Puller, chain: &ChainState) -> Result<Value, ErrorObjectOwned> {
    let aggregate = p.collector().aggregate();
    // Read before the set is: a change meanwhile is computed again next time.
    let changes = aggregate.changes();
    let tip = chain.read(&|v| v.block_hash(v.tip_height())).flatten().ok_or_else(tip_kept_changing)?;
    p.report_cache().get_or(tip, changes, std::time::Instant::now(), || {
        let held: Vec<(Attestation, Timelocks)> =
            aggregate.all().into_iter().map(|h| (h.attestation, h.locks)).collect();
        let set = report::canonical(held.iter().map(|(a, _)| a.clone()));
        let digest = report::digest(&set);
        let (tip, counting) = chain.read(&|v| report::counting_at(&held, v)).ok_or_else(tip_kept_changing)?;
        Ok((tip.hash, report::report(tip, digest, set.len(), 0, &counting)))
    })
}

/// `replaynapsnapshot`: the report on a snapshot file. Each signature is
/// verified against its coin, and the set judged at this node's tip, as the
/// aggregator that exported it would at the same tip ([`report::replay`]). `max` bounds the
/// attestations read (0 is no limit).
pub fn report_snapshot(chain: &ChainState, path: &Path, max: usize) -> Result<Value, ErrorObjectOwned> {
    let snapshot = report::read_snapshot(path, max)
        .map_err(|e| RpcError::new(-8, "rpc.input.parse", e).into_error_object())?;
    let replay = report::replay(chain, &snapshot.attestations).ok_or_else(tip_kept_changing)?;
    let digest = report::digest(&snapshot.attestations);
    Ok(report::report(replay.tip, digest, snapshot.attestations.len(), replay.invalid, &replay.counting))
}

/// `exportnapsnapshot`: write every attestation the aggregator holds to
/// `path` as a snapshot. An existing file is not overwritten.
pub fn export_snapshot(
    p: &crate::nap::pull::Puller,
    chain: &ChainState,
    path: &Path,
) -> Result<Value, ErrorObjectOwned> {
    let set = report::canonical(p.collector().aggregate().all().into_iter().map(|h| h.attestation));
    let (height, hash) = chain
        .read(&|v| {
            let h = v.tip_height();
            (h, v.block_hash(h).expect("the active chain holds its tip"))
        })
        .ok_or_else(tip_kept_changing)?;
    report::write_new(path, &report::encode_snapshot(height, hash, &set)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            RpcError::new(-8, "storage.exists", format!("refusing to overwrite existing file: {}", path.display()))
        } else {
            RpcError::new(-1, "storage.io", format!("writing {}: {e}", path.display()))
        }
        .into_error_object()
    })?;
    Ok(json!({
        "path": path.to_string_lossy(),
        "height": height,
        "hash": hash.to_string(),
        "attestations": set.len(),
        "digest": report::digest(&set).to_string(),
    }))
}

/// `"<txid>:<vout>"`, as `createnapattestation` and `removenapattestation`
/// take it.
pub fn parse_outpoint(s: &str) -> Result<OutPoint, ErrorObjectOwned> {
    OutPoint::from_str(s).map_err(|_| {
        RpcError::new(-8, "rpc.input.parse", format!("outpoint must be \"<txid>:<vout>\", not \"{s}\""))
            .into_error_object()
    })
}

/// A publisher refusal as an RPC error. A rejection is -26, as Core reports
/// a transaction that fails verification, and names its rule in the message
/// and, with extended errors, in `data.debug.rule`.
pub fn error(e: PublishError) -> ErrorObjectOwned {
    let (code, category) = match &e {
        PublishError::Format(_) => (-8, "rpc.input.parse"),
        PublishError::NotFound => (-8, "storage.not_found"),
        PublishError::ChainTooShort | PublishError::Busy => (-1, "node.initializing"),
        PublishError::Io(_) => (-1, "storage.io"),
        PublishError::Rejected(_)
        | PublishError::Superseded { .. }
        | PublishError::KeyLimit
        | PublishError::StoreFull { .. } => {
            (-26, "nap.rejected")
        }
    };
    let message = match code {
        -26 => format!("rejected ({}): {e}", e.rule()),
        _ => e.to_string(),
    };
    RpcError::new(code, category, message).with_debug(json!({ "rule": e.rule() })).into_error_object()
}

/// An unusable descriptor is -5, as Core reports one; one that does not
/// derive the coin is -8.
fn descriptor_error(e: bip322::psbt::DescriptorError) -> ErrorObjectOwned {
    use bip322::psbt::DescriptorError as E;
    let code = match e {
        E::Parse(_) | E::TooManyBranches(_) | E::HardenedDerivation => -5,
        E::NoMatch | E::Update(_) | E::NoUtxo => -8,
    };
    RpcError::new(code, "rpc.input.parse", e.to_string()).into_error_object()
}

fn format_name(signature: &NapSignature) -> &'static str {
    match signature {
        NapSignature::Simple(_) => "simple",
        NapSignature::Full(_) => "full",
        NapSignature::Legacy(_) => "legacy",
    }
}

/// The signature formats a coin's script takes (D13, D9).
fn formats_for(script: &ScriptBuf) -> Vec<&'static str> {
    if script.is_witness_program() {
        vec!["simple", "full"]
    } else if script.is_p2pkh() {
        vec!["legacy", "full"]
    } else {
        vec!["full"]
    }
}

/// `createnapattestation "outpoint" "key" "value" ( "descriptor" )`. A
/// descriptor adds key origins and scripts to the PSBT for signers.
pub fn create(
    nap: &Publisher,
    chain: &ChainState,
    outpoint: &str,
    key: &str,
    value: &str,
    descriptor: Option<&str>,
) -> Result<Value, ErrorObjectOwned> {
    let outpoint = parse_outpoint(outpoint)?;
    let mut draft = nap.create(chain, outpoint, key, value).map_err(error)?;
    if let Some(descriptor) = descriptor {
        bip322::psbt::add_descriptor(&mut draft.psbt, descriptor).map_err(descriptor_error)?;
    }
    let unit = default_unit();
    let mut out = json!({
        "message": draft.message,
        "outpoint": outpoint.to_string(),
        "key": key,
        "value": value,
        "anchor_height": draft.anchor_height,
        "anchor_hash": draft.anchor_hash.to_string(),
        "amount": format_amount(draft.coin.value.to_sat(), unit),
        "formats": formats_for(&draft.coin.script_pubkey),
        "psbt": base64::engine::general_purpose::STANDARD.encode(draft.psbt.serialize()),
        "warnings": draft.warnings,
    });
    if let Ok(address) = bitcoin::Address::from_script(&draft.coin.script_pubkey, chain.network) {
        out["address"] = json!(address.to_string());
    }
    annotate_units(&mut out, unit);
    Ok(out)
}

/// `submitnapattestation "message" "signature"`. The signature may be a
/// signed BIP 322 PSBT of the message, which is finalized, or the signed
/// `to_sign` transaction in hex.
pub fn submit(
    nap: &Publisher,
    chain: &ChainState,
    message: &str,
    signature: &str,
) -> Result<Value, ErrorObjectOwned> {
    let (published, replaced) = nap.submit(chain, message, signature).map_err(error)?;
    let mut out = describe(&published);
    out["replaced"] = json!(replaced.map(|id| id.to_string()));
    Ok(out)
}

/// `listnapattestations`.
pub fn list(nap: &Publisher, chain: &ChainState) -> Value {
    Value::Array(nap.list(chain).iter().map(describe).collect())
}

/// `removenapattestation "outpoint" "key"`.
pub fn remove(nap: &Publisher, outpoint: &str, key: &str) -> Result<Value, ErrorObjectOwned> {
    let outpoint = parse_outpoint(outpoint)?;
    let att = nap.remove(outpoint, key).map_err(error)?;
    Ok(json!({ "id": att.id().to_string() }))
}

/// One stored attestation as the RPCs report it.
fn describe(p: &Published) -> Value {
    let att = &p.attestation;
    let unit = default_unit();
    let mut out = json!({
        "id": att.id().to_string(),
        "outpoint": att.outpoint().to_string(),
        "key": att.key(),
        "value": att.value(),
        "anchor_height": att.anchor_height(),
        "anchor_hash": att.anchor_hash().to_string(),
        "format": format_name(att.signature()),
        "signature": encode_signature(att.signature()),
        "message": att.message(),
    });
    match &p.status {
        Some(Ok(amount)) => {
            out["status"] = json!("valid");
            out["amount"] = format_amount(amount.to_sat(), unit);
        }
        Some(Err(r)) => {
            out["status"] = json!(r.rule());
            out["reason"] = json!(r.to_string());
        }
        None => {
            out["status"] = json!("unknown");
            out["reason"] = json!("not judged yet: the chain tip kept changing; ask again");
        }
    }
    annotate_units(&mut out, unit);
    out
}
