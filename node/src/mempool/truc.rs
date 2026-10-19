//! BIP 431 TRUC ("topologically restricted until confirmation") policy for
//! version 3 transactions: Core's `src/policy/truc_policy.cpp`.
//!
//! An unconfirmed TRUC transaction may have one unconfirmed parent or one
//! unconfirmed child, never more, and the child is small. That bounds what a
//! counterparty can attach to a shared transaction to pin it, which is what
//! Lightning's TRUC commitments rely on. Both functions here report what Core
//! reports, in Core's words: the debug string goes after `TRUC-violation, `.
//!
//! The mempool is reached through [`TrucView`] so the rules can be checked
//! against a hand-built graph.

use std::collections::HashSet;

use bitcoin::{Transaction, Txid};

/// The version that opts a transaction into these rules.
pub const TRUC_VERSION: i32 = 3;
/// A TRUC transaction and its unconfirmed ancestors, together.
pub const TRUC_ANCESTOR_LIMIT: usize = 2;
/// An unconfirmed transaction and its descendants, together, when it is TRUC.
pub const TRUC_DESCENDANT_LIMIT: usize = 2;
/// Sigop-adjusted vsize ceiling of any TRUC transaction.
pub const TRUC_MAX_VSIZE: u64 = 10_000;
/// Sigop-adjusted vsize ceiling of a TRUC transaction with an unconfirmed
/// parent.
pub const TRUC_CHILD_MAX_VSIZE: u64 = 1_000;

// Both functions are written for these limits, as Core's are.
const _: () = assert!(TRUC_ANCESTOR_LIMIT == 2 && TRUC_DESCENDANT_LIMIT == 2);

/// The parts of the mempool the TRUC rules read.
pub(crate) trait TrucView {
    /// A transaction in the mempool.
    fn mempool_tx(&self, txid: &Txid) -> Option<&Transaction>;
    /// `txid` and its in-mempool ancestors, counted up to `cap`: Core's
    /// `GetAncestorCount`.
    fn ancestor_count(&self, txid: &Txid, cap: usize) -> usize;
    /// The in-mempool descendants of `txid`, itself excluded, up to `cap` of
    /// them.
    fn descendants(&self, txid: &Txid, cap: usize) -> Vec<Txid>;
    /// Whether `ancestor` is an in-mempool ancestor of `txid`.
    fn descends_from(&self, txid: &Txid, ancestor: &Txid) -> bool;
}

fn is_truc(tx: &Transaction) -> bool {
    tx.version.0 == TRUC_VERSION
}

/// A refusal from [`single_truc_checks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SingleTrucFailure {
    /// Core's debug string.
    pub detail: String,
    /// The one other child of the transaction's parent, when the only thing
    /// wrong is that there would be two: the caller may evict it under the
    /// replacement rules instead of refusing (sibling eviction).
    pub sibling: Option<Txid>,
}

/// Core's `SingleTRUCChecks`, for every transaction entering the mempool
/// except one a reorg returns. `mempool_parents` are the transaction's direct
/// parents in the mempool, `direct_conflicts` what it replaces, and `vsize` is
/// sigop-adjusted.
pub(crate) fn single_truc_checks(
    view: &impl TrucView,
    tx: &Transaction,
    vsize: u64,
    mempool_parents: &[Txid],
    direct_conflicts: &HashSet<Txid>,
) -> Option<SingleTrucFailure> {
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    let fail = |detail: String| Some(SingleTrucFailure { detail, sibling: None });

    // Inheritance: a TRUC transaction spends only TRUC parents, and the
    // reverse.
    for parent_txid in mempool_parents {
        let Some(parent) = view.mempool_tx(parent_txid) else { continue };
        if is_truc(tx) != is_truc(parent) {
            let (child, parent_kind) = if is_truc(tx) {
                ("version=3", "non-version=3")
            } else {
                ("non-version=3", "version=3")
            };
            return fail(format!(
                "{child} tx {txid} (wtxid={wtxid}) cannot spend from {parent_kind} tx {parent_txid} (wtxid={})",
                parent.compute_wtxid()
            ));
        }
    }

    if !is_truc(tx) {
        return None;
    }

    if vsize > TRUC_MAX_VSIZE {
        return fail(format!(
            "version=3 tx {txid} (wtxid={wtxid}) is too big: {vsize} > {TRUC_MAX_VSIZE} virtual bytes"
        ));
    }

    if mempool_parents.len() + 1 > TRUC_ANCESTOR_LIMIT {
        return fail(format!("tx {txid} (wtxid={wtxid}) would have too many ancestors"));
    }

    let parent_txid = mempool_parents.first()?;
    // The parent may not have unconfirmed ancestors of its own.
    if view.ancestor_count(parent_txid, TRUC_ANCESTOR_LIMIT + 1) + 1 > TRUC_ANCESTOR_LIMIT {
        return fail(format!("tx {txid} (wtxid={wtxid}) would have too many ancestors"));
    }
    if vsize > TRUC_CHILD_MAX_VSIZE {
        return fail(format!(
            "version=3 child tx {txid} (wtxid={wtxid}) is too big: {vsize} > {TRUC_CHILD_MAX_VSIZE} virtual bytes"
        ));
    }

    // This is the parent's only child. A reorg can leave it with more, so
    // more is handled too. A child this transaction replaces does not count:
    // any descendant of a TRUC transaction is a direct child. Asked of the
    // conflicts rather than of the descendants, which are counted only as
    // far as the limit needs: a reorg can leave any number.
    let descendants = view.descendants(parent_txid, TRUC_DESCENDANT_LIMIT + 1);
    let child_will_be_replaced = direct_conflicts.iter().any(|c| view.descends_from(c, parent_txid));
    if descendants.len() + 2 > TRUC_DESCENDANT_LIMIT && !child_will_be_replaced {
        // Sibling eviction is on offer only when the parent has exactly one
        // child and that child has no other ancestors, so there is no choice
        // of which to evict.
        let sibling = match descendants.as_slice() {
            [only] if view.ancestor_count(only, TRUC_ANCESTOR_LIMIT + 1) == 2 => Some(*only),
            _ => None,
        };
        let parent_wtxid = view
            .mempool_tx(parent_txid)
            .map(|p| p.compute_wtxid().to_string())
            .unwrap_or_default();
        return Some(SingleTrucFailure {
            detail: format!(
                "tx {parent_txid} (wtxid={parent_wtxid}) would exceed descendant count limit"
            ),
            sibling,
        });
    }
    None
}

/// Core's `PackageTRUCChecks`, for each transaction a package evaluates
/// together (`submitpackage`'s combined evaluation, a multi-transaction
/// `testmempoolaccept`). `package` is every transaction so evaluated, in
/// package order; `mempool_parents` are `tx`'s direct parents in the mempool.
pub(crate) fn package_truc_checks(
    view: &impl TrucView,
    tx: &Transaction,
    vsize: u64,
    package: &[&Transaction],
    mempool_parents: &[Txid],
) -> Option<String> {
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();

    // The members ahead of `tx` that it spends: a sorted package puts every
    // parent first.
    let spent: HashSet<Txid> = tx.input.iter().map(|i| i.previous_output.txid).collect();
    let in_package_parents: Vec<&Transaction> = package
        .iter()
        .take_while(|p| p.compute_txid() != txid)
        .filter(|p| spent.contains(&p.compute_txid()))
        .copied()
        .collect();

    if !is_truc(tx) {
        // A non-TRUC transaction has no TRUC parent.
        let mempool = mempool_parents.iter().filter_map(|t| view.mempool_tx(t));
        for parent in mempool.chain(in_package_parents.iter().copied()) {
            if is_truc(parent) {
                return Some(format!(
                    "non-version=3 tx {txid} (wtxid={wtxid}) cannot spend from version=3 tx {} (wtxid={})",
                    parent.compute_txid(),
                    parent.compute_wtxid()
                ));
            }
        }
        return None;
    }

    // `single_truc_checks` refuses this first; Core keeps it as an assertion.
    if vsize > TRUC_MAX_VSIZE {
        return Some(format!(
            "version=3 tx {txid} (wtxid={wtxid}) is too big: {vsize} > {TRUC_MAX_VSIZE} virtual bytes"
        ));
    }

    let too_many_ancestors = || Some(format!("tx {txid} (wtxid={wtxid}) would have too many ancestors"));
    if mempool_parents.len() + in_package_parents.len() + 1 > TRUC_ANCESTOR_LIMIT {
        return too_many_ancestors();
    }
    if let Some(parent) = mempool_parents.first()
        && view.ancestor_count(parent, TRUC_ANCESTOR_LIMIT + 1) + in_package_parents.len() + 1
            > TRUC_ANCESTOR_LIMIT
    {
        return too_many_ancestors();
    }

    // Exactly one parent, in the mempool or in the package.
    let (parent, parent_has_mempool_descendant) = if let Some(parent_txid) = mempool_parents.first() {
        let parent = view.mempool_tx(parent_txid)?;
        (parent, !view.descendants(parent_txid, 1).is_empty())
    } else if let Some(parent) = in_package_parents.first() {
        (*parent, false)
    } else {
        return None;
    };

    if vsize > TRUC_CHILD_MAX_VSIZE {
        return Some(format!(
            "version=3 child tx {txid} (wtxid={wtxid}) is too big: {vsize} > {TRUC_CHILD_MAX_VSIZE} virtual bytes"
        ));
    }

    let parent_txid = parent.compute_txid();
    let parent_wtxid = parent.compute_wtxid();
    if !is_truc(parent) {
        return Some(format!(
            "version=3 tx {txid} (wtxid={wtxid}) cannot spend from non-version=3 tx {parent_txid} (wtxid={parent_wtxid})"
        ));
    }

    let exceeds_descendants =
        || Some(format!("tx {parent_txid} (wtxid={parent_wtxid}) would exceed descendant count limit"));
    for other in package.iter().filter(|p| p.compute_txid() != txid) {
        for input in &other.input {
            // Another member with the same parent. Whether it replaces
            // anything does not matter inside one package.
            if input.previous_output.txid == parent_txid {
                return exceeds_descendants();
            }
            // A transaction with a parent cannot also have a child here.
            if input.previous_output.txid == txid {
                return Some(format!(
                    "tx {} (wtxid={}) would have too many ancestors",
                    other.compute_txid(),
                    other.compute_wtxid()
                ));
            }
        }
    }

    if parent_has_mempool_descendant {
        return exceeds_descendants();
    }
    None
}

#[cfg(test)]
#[path = "truc_tests.rs"]
mod tests;
