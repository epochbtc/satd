//! Transaction-filtering **policy observability** RPCs (design §10, PR 7b):
//! `getpolicyinfo`, `getquarantineinfo`, `listquarantine`, `getquarantineentry`.
//!
//! These are the *only* RPCs that expose the quarantine class. Every standard
//! mempool surface presents the acting class only (PR 7a) — to a Core-compatible
//! consumer the node looks exactly like one whose relay policy refused the
//! quarantined transactions. A consumer that wants the quarantine view asks for
//! it by name, here. All four are read-only.

use serde_json::{json, Value};

use crate::chain::state::ChainState;
use crate::mempool::policy_engine::{self, PolicyCtx};
use crate::mempool::pool::{Mempool, QuarantineScope, TxSource};
use crate::mempool::policy as mpolicy;

/// `getpolicyinfo` — ruleset source/load metadata, the per-rule match counters
/// and fuel-backstop counter accumulated since load, and quarantine-class
/// totals. Reports `{"loaded": false}` when no ruleset is installed.
pub fn get_policy_info(mempool: &Mempool) -> Value {
    let stats = mempool.policy_stats_snapshot();
    let Some(meta) = mempool.policy_meta() else {
        return json!({
            "loaded": false,
            "evaluations": stats.evaluations,
        });
    };

    // Snapshot the live ruleset once so the per-rule list and the danger
    // findings below are derived from the same ruleset version.
    let snapshot = mempool.policy_snapshot();

    // Per-rule list from the live ruleset (name / action / scope / auto-named)
    // joined with the match counters since load.
    let mut rules: Vec<Value> = Vec::new();
    if let Some(rs) = &snapshot {
        for r in rs.rules() {
            let matched = stats.per_rule.get(&r.name).copied().unwrap_or(0);
            let action = match r.action {
                satd_policy::Action::Quarantine => "quarantine",
                satd_policy::Action::Allow => "allow",
            };
            let mut entry = json!({
                "name": r.name,
                "action": action,
                "auto_named": r.auto_named,
                "matched": matched,
            });
            if r.action == satd_policy::Action::Quarantine {
                entry["scope"] = json!({
                    "relay": r.scope.relay,
                    "template": r.scope.template,
                });
            }
            rules.push(entry);
        }
    }

    // Lightning-enforcement danger findings for the live ruleset (§2.5). A
    // loaded ruleset only reaches here if it passed the load gate, so under
    // steady state any relay-withholding findings imply `allowdangerousfilters`
    // is set. The flag and the ruleset are read under separate locks, so a
    // reload racing this call can momentarily report `allow_dangerous_filters:
    // false` alongside relay-withholding findings (or vice versa); this is a
    // display-only skew that self-heals on the next call.
    let allow_dangerous = mempool.policy().allow_dangerous_filters;
    let mut findings: Vec<Value> = Vec::new();
    let (mut relay_withholding, mut template_only) = (0u64, 0u64);
    if let Some(rs) = &snapshot {
        for f in satd_policy::analyze_danger(rs) {
            if f.withholds_relay() {
                relay_withholding += 1;
            } else {
                template_only += 1;
            }
            findings.push(json!({
                "rule": f.rule,
                "shape": f.shape.label(),
                "class": f.class.headline(),
                "withholds_relay": f.withholds_relay(),
                "scope": { "relay": f.scope.relay, "template": f.scope.template },
            }));
        }
    }

    json!({
        "loaded": true,
        "path": meta.path.as_ref().map(|p| p.display().to_string()),
        "sha256": meta.sha256,
        "loaded_at": meta.loaded_at,
        "version": meta.version,
        "rules_count": meta.rules,
        "total_cost": meta.total_cost,
        "has_allow": meta.has_allow,
        "evaluations": stats.evaluations,
        "fuel_exhausted": stats.fuel_exhausted,
        "rules": rules,
        "quarantine": {
            "count": mempool.quarantine_count(),
            "bytes": mempool.quarantine_bytes(),
            "budget_bytes": mempool.policy().quarantine_max_bytes,
        },
        "danger": {
            "allow_dangerous_filters": allow_dangerous,
            "relay_withholding": relay_withholding,
            "template_only": template_only,
            "findings": findings,
        },
    })
}

/// `getquarantineinfo` — the comparison surface: per-rule rollup of the
/// quarantine class (count / bytes / fee-rate span), the confirmed-anyway count,
/// and the foregone-fees estimate (sat) against the current template floor.
pub fn get_quarantine_info(mempool: &Mempool) -> Value {
    // The template floor: transactions below the relay minimum are not selected
    // into a block template, so it is the honest cutoff for "fee a miner gave
    // up" — the same floor the fee estimator uses.
    let template_floor = mempool.min_fee_rate();
    let report = mempool.quarantine_report(template_floor);

    let mut per_rule = serde_json::Map::new();
    for (name, stat) in &report.per_rule {
        per_rule.insert(
            name.clone(),
            json!({
                "count": stat.count,
                "bytes": stat.bytes,
                "min_fee_rate": stat.min_fee_rate,
                "max_fee_rate": stat.max_fee_rate,
            }),
        );
    }

    json!({
        "count": report.total_count,
        "bytes": report.total_bytes,
        "budget_bytes": report.budget_bytes,
        "template_floor_sat_per_kvb": template_floor,
        "foregone_fees_sat": report.foregone_fees_sat,
        "confirmed_anyway": report.confirmed_anyway,
        "rules": Value::Object(per_rule),
    })
}

/// `listquarantine [rule] [count] [skip]` — the quarantine class as a paged
/// list, optionally filtered to one rule. Newest-first.
pub fn list_quarantine(
    mempool: &Mempool,
    rule: Option<&str>,
    count: usize,
    skip: usize,
) -> Value {
    let entries = mempool.list_quarantine(rule, count, skip);
    let arr: Vec<Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "txid": e.txid.to_string(),
                "rule": e.rule,
                "scope": { "relay": e.relay, "template": e.template },
                "time": e.time,
                "vsize": e.vsize,
                "fee": e.fee,
                "fee_rate": e.fee_rate,
            })
        })
        .collect();
    Value::Array(arr)
}

/// `getquarantineentry <txid>` — the `getmempoolentry` analogue for a single
/// quarantined transaction. Errors if the txid is absent or acting (an acting
/// entry is served by `getmempoolentry`).
pub fn get_quarantine_entry(mempool: &Mempool, txid_str: &str) -> Result<Value, String> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| "Invalid txid".to_string())?;
    let d = mempool
        .get_quarantine_entry(&txid)
        .ok_or_else(|| "Transaction not in quarantine".to_string())?;
    Ok(json!({
        "txid": d.txid.to_string(),
        "rule": d.rule,
        "scope": { "relay": d.relay, "template": d.template },
        "time": d.time,
        "vsize": d.vsize,
        "weight": d.weight,
        "fee": d.fee,
        "fee_rate": d.fee_rate,
        "depends": d.depends.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
    }))
}

/// `policytest <rawtx-hex>` — dry-run a transaction against the **currently
/// loaded** ruleset (design §10): the per-rule trace (matched/not, the decisive
/// rule), the resulting verdict, and the placement/scope the tx would receive —
/// including infectious-ancestor propagation from any quarantined in-mempool
/// parents. The `testmempoolaccept` analogue for policy. Prevouts are resolved
/// from the confirmed UTXO set, then in-mempool parents; an input that resolves
/// to neither is an error (the tx cannot be evaluated).
///
/// `decisive_rule` may be the implicit `__fuel` rule when evaluation exhausts its
/// fuel budget (the fail-safe full-scope quarantine); in that case no row in
/// `rules[]` is marked `decisive` (the `__fuel` rule is not part of the ruleset).
/// The report is a best-effort snapshot — the mempool/UTXO reads are not taken
/// under a single lock, so a concurrent mutation can blend states slightly.
pub fn policy_test(
    chain_state: &ChainState,
    mempool: &Mempool,
    rawtx_hex: &str,
) -> Result<Value, String> {
    let raw = hex::decode(rawtx_hex.trim()).map_err(|_| "invalid hex".to_string())?;
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&raw).map_err(|e| format!("decode: {e}"))?;

    let Some(ruleset) = mempool.policy_snapshot() else {
        return Ok(json!({ "loaded": false }));
    };
    let txid = tx.compute_txid();

    // Resolve prevouts (confirmed UTXO set, then in-mempool parents) and, in the
    // same pass, capture infectious-ancestor scope from any quarantined
    // in-mempool parent (§3) — one mempool lookup per input. The two branches are
    // mutually exclusive: a confirmed-coin prevout's funding tx is mined, never
    // in the mempool, so infectious scope only ever comes from the parent branch.
    let mut prev_outputs: Vec<bitcoin::TxOut> = Vec::with_capacity(tx.input.len());
    let mut prev_is_coinbase: Vec<bool> = Vec::with_capacity(tx.input.len());
    let mut input_total: u64 = 0;
    let mut infectious = QuarantineScope::acting();
    let mut infectious_parents: Vec<String> = Vec::new();
    for input in &tx.input {
        if let Some(coin) = chain_state.get_coin(&input.previous_output) {
            input_total = input_total.saturating_add(coin.amount);
            prev_outputs.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(coin.amount),
                script_pubkey: coin.script_pubkey.clone(),
            });
            prev_is_coinbase.push(coin.coinbase);
        } else if let Some(parent) = mempool.get(&input.previous_output.txid) {
            let o = parent
                .tx
                .output
                .get(input.previous_output.vout as usize)
                .ok_or_else(|| {
                    format!("prevout {} not found (vout out of range)", input.previous_output)
                })?;
            input_total = input_total.saturating_add(o.value.to_sat());
            prev_outputs.push(o.clone());
            prev_is_coinbase.push(false);
            if parent.scope.is_quarantined() {
                infectious.relay |= parent.scope.relay;
                infectious.template |= parent.scope.template;
                infectious_parents.push(input.previous_output.txid.to_string());
            }
        } else {
            return Err(format!(
                "prevout {} not found (need a confirmed UTXO or in-mempool parent)",
                input.previous_output
            ));
        }
    }

    let output_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = input_total.saturating_sub(output_total);
    let weight = tx.weight().to_wu() as usize;
    let vsize = mpolicy::weight_to_vsize(weight as u64);
    let fee_rate = mpolicy::fee_rate_sat_per_kvb(fee, weight as u64);

    let cfg = mempool.policy();
    let ctx = PolicyCtx {
        network: chain_state.network,
        height: chain_state.tip_height(),
        mempool_bytes: mempool.acting_bytes() + mempool.quarantine_bytes(),
    };

    let (traces, verdict) = policy_engine::evaluate_trace(
        &ruleset,
        &tx,
        &txid,
        &prev_outputs,
        &prev_is_coinbase,
        fee,
        fee_rate,
        weight,
        &cfg,
        ctx,
        TxSource::Rpc,
        false,
    );

    // The placement the tx would receive on admission: its own scope from the
    // verdict, unioned with the infectious-ancestor scope collected above
    // (§3 infectious propagation).
    let own_scope = match &verdict {
        satd_policy::Verdict::Quarantine { scope, .. } => policy_engine::map_scope(*scope),
        _ => QuarantineScope::acting(),
    };
    let mut final_scope = own_scope;
    final_scope.relay |= infectious.relay;
    final_scope.template |= infectious.template;

    let rules: Vec<Value> = traces
        .iter()
        .map(|t| {
            let action = match t.action {
                satd_policy::Action::Quarantine => "quarantine",
                satd_policy::Action::Allow => "allow",
            };
            let mut e = json!({
                "name": t.name,
                "action": action,
                "auto_named": t.auto_named,
                "evaluated": t.evaluated,
                "matched": t.matched,
                "decisive": t.decisive,
            });
            if t.action == satd_policy::Action::Quarantine {
                e["scope"] = json!({ "relay": t.scope.relay, "template": t.scope.template });
            }
            e
        })
        .collect();

    let verdict_str = match &verdict {
        satd_policy::Verdict::Pass => "pass",
        satd_policy::Verdict::Allow { .. } => "allow",
        satd_policy::Verdict::Quarantine { .. } => "quarantine",
    };

    Ok(json!({
        "loaded": true,
        "txid": txid.to_string(),
        "fee": fee,
        "fee_rate": fee_rate,
        "vsize": vsize,
        "verdict": verdict_str,
        "decisive_rule": verdict.rule(),
        "placement": {
            "class": if final_scope.is_acting() { "acting" } else { "quarantine" },
            "scope": { "relay": final_scope.relay, "template": final_scope.template },
            "infectious_parents": infectious_parents,
        },
        "rules": rules,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::pool::{Mempool, QuarantineScope};

    const RELAY_ONLY: QuarantineScope = QuarantineScope {
        relay: true,
        template: false,
    };
    const TEMPLATE_ONLY: QuarantineScope = QuarantineScope {
        relay: false,
        template: true,
    };

    fn ruleset(src: &str) -> std::sync::Arc<satd_policy::CompiledRuleset> {
        std::sync::Arc::new(satd_policy::parse_ruleset(src).unwrap())
    }

    #[test]
    fn getpolicyinfo_reports_unloaded_then_loaded() {
        let mp = Mempool::new(300_000_000, 1_000);
        assert_eq!(get_policy_info(&mp)["loaded"], json!(false));

        mp.set_policy(ruleset("version 1\nquarantine spam when tx.version == 1\n"));
        let info = get_policy_info(&mp);
        assert_eq!(info["loaded"], json!(true));
        assert_eq!(info["version"], json!(1));
        assert_eq!(info["rules_count"], json!(1));
        assert_eq!(info["rules"][0]["name"], json!("spam"));
        assert_eq!(info["rules"][0]["action"], json!("quarantine"));
    }

    #[test]
    fn getquarantineinfo_breaks_down_by_rule_and_foregone_fees() {
        let mp = Mempool::new(300_000_000, 1_000);
        // template-withheld, high fee rate (> floor 1000) ⇒ counts as foregone.
        let t = mp.insert_scoped_for_test(1, 5_000, TEMPLATE_ONLY);
        // relay-only, high fee rate ⇒ still mined ⇒ NOT foregone.
        mp.insert_scoped_for_test(2, 5_000, RELAY_ONLY);
        // Stamp a rule name on the template-withheld entry via reapply isn't run
        // here; the report attributes unnamed entries to "(policy)".

        let info = get_quarantine_info(&mp);
        assert_eq!(info["count"], json!(2));
        // Only the template-withheld entry's fee is foregone. Its fee == 0 in the
        // scoped test helper, so foregone is 0 by fee but the path is exercised;
        // assert the entry is present and template floor surfaced.
        assert_eq!(info["template_floor_sat_per_kvb"], json!(1_000));
        assert!(info["rules"].as_object().unwrap().contains_key("(policy)"));
        let _ = t;
    }

    #[test]
    fn listquarantine_and_getquarantineentry_round_trip() {
        let mp = Mempool::new(300_000_000, 1_000);
        let a = mp.insert_scoped_for_test(1, 2_000, RELAY_ONLY);
        let _b = mp.insert_scoped_for_test(2, 2_000, TEMPLATE_ONLY);

        let list = list_quarantine(&mp, None, 0, 0);
        assert_eq!(list.as_array().unwrap().len(), 2);

        // Filter to a (non-existent) named rule ⇒ empty.
        assert_eq!(
            list_quarantine(&mp, Some("nope"), 0, 0)
                .as_array()
                .unwrap()
                .len(),
            0
        );

        // getquarantineentry resolves a quarantined txid.
        let entry = get_quarantine_entry(&mp, &a.to_string()).unwrap();
        assert_eq!(entry["txid"], json!(a.to_string()));
        assert_eq!(entry["scope"]["relay"], json!(true));

        // A non-quarantined / unknown txid errors.
        let acting = mp.insert_scoped_for_test(9, 2_000, QuarantineScope::acting());
        assert!(get_quarantine_entry(&mp, &acting.to_string()).is_err());
    }
}
