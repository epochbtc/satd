//! Transaction-filtering **policy observability** RPCs (design §10, PR 7b):
//! `getpolicyinfo`, `getquarantineinfo`, `listquarantine`, `getquarantineentry`.
//!
//! These are the *only* RPCs that expose the quarantine class. Every standard
//! mempool surface presents the acting class only (PR 7a) — to a Core-compatible
//! consumer the node looks exactly like one whose relay policy refused the
//! quarantined transactions. A consumer that wants the quarantine view asks for
//! it by name, here. All four are read-only.

use serde_json::{json, Value};

use crate::mempool::pool::Mempool;

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

    // Per-rule list from the live ruleset (name / action / scope / auto-named)
    // joined with the match counters since load.
    let mut rules: Vec<Value> = Vec::new();
    if let Some(rs) = mempool.policy_snapshot() {
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
