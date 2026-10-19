//! Whole-mempool cluster work that Core v31's `TxGraph` does and satd's
//! per-transaction admission does not: the order `getrawmempool` lists
//! (`CTxMemPool::GetSortedScoreWithTopology`), and the trim that cuts back a
//! cluster a reorg has grown past the cluster limits (`TxGraph::Trim`).
//!
//! Both work on a [`Graph`] the caller builds from the mempool: each
//! transaction's txid, fee and size as a [`FeeFrac`], and its parents among
//! the graph's transactions.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use bitcoin::Txid;

use crate::mempool::feefrac::{feerate_compare, linearize, FeeFrac, MAX_CHUNKED_CLUSTER};

/// Transactions and the spends between them. `ff[i]` is the modified fee
/// and sigop-adjusted weight of `txids[i]`; `parents[i]` the indices of the
/// graph's transactions it spends.
pub struct Graph {
    pub txids: Vec<Txid>,
    pub ff: Vec<FeeFrac>,
    pub parents: Vec<Vec<usize>>,
}

impl Graph {
    fn children(&self) -> Vec<Vec<usize>> {
        let mut kids = vec![Vec::new(); self.txids.len()];
        for (child, parents) in self.parents.iter().enumerate() {
            for &p in parents {
                kids[p].push(child);
            }
        }
        kids
    }

    /// The connected groups of `members` through the spends `linked` keeps
    /// (`linked(parent, child)`), each in txid order, the groups in the
    /// order of their lowest txid.
    fn components(&self, kids: &[Vec<usize>], members: &[usize], linked: impl Fn(usize, usize) -> bool) -> Vec<Vec<usize>> {
        let mut inside = vec![false; self.txids.len()];
        for &m in members {
            inside[m] = true;
        }
        let mut seen = vec![false; self.txids.len()];
        let mut sorted = members.to_vec();
        sorted.sort_by_key(|&i| self.txids[i]);
        let mut out = Vec::new();
        for start in sorted {
            if seen[start] {
                continue;
            }
            seen[start] = true;
            let mut group = vec![start];
            let mut at = 0;
            while at < group.len() {
                let n = group[at];
                at += 1;
                let up = self.parents[n].iter().filter(|&&p| linked(p, n));
                let down = kids[n].iter().filter(|&&c| linked(n, c));
                for &m in up.chain(down) {
                    if inside[m] && !seen[m] {
                        seen[m] = true;
                        group.push(m);
                    }
                }
            }
            group.sort_by_key(|&i| self.txids[i]);
            out.push(group);
        }
        out
    }

    /// A linearization of `group` (in txid order), as graph indices:
    /// [`linearize`]'s when the group fits in its bitsets. A larger group,
    /// which the cluster limits leave only to a reorg, is laid out
    /// topologically, the best-paying ready transaction first.
    fn linearize_group(&self, group: &[usize]) -> Vec<usize> {
        if group.len() <= MAX_CHUNKED_CLUSTER {
            let local: std::collections::HashMap<usize, usize> =
                group.iter().enumerate().map(|(i, &g)| (g, i)).collect();
            let txs: Vec<(FeeFrac, u64)> = group
                .iter()
                .map(|&g| {
                    let mask = self.parents[g].iter().filter_map(|p| local.get(p)).fold(0u64, |m, &i| m | (1u64 << i));
                    (self.ff[g], mask)
                })
                .collect();
            return linearize(&txs).into_iter().map(|i| group[i]).collect();
        }
        let mut inside = vec![false; self.txids.len()];
        for &g in group {
            inside[g] = true;
        }
        let kids = self.children();
        let mut waiting: Vec<usize> = vec![0; self.txids.len()];
        let mut ready = BinaryHeap::new();
        for &g in group {
            waiting[g] = self.parents[g].iter().filter(|&&p| inside[p]).count();
            if waiting[g] == 0 {
                ready.push(Best { ff: self.ff[g], txid: self.txids[g], index: g });
            }
        }
        let mut order = Vec::with_capacity(group.len());
        while let Some(Best { index, .. }) = ready.pop() {
            order.push(index);
            for &c in &kids[index] {
                if inside[c] {
                    waiting[c] -= 1;
                    if waiting[c] == 0 {
                        ready.push(Best { ff: self.ff[c], txid: self.txids[c], index: c });
                    }
                }
            }
        }
        order
    }

    /// The chunks of `order`: a transaction that pays more than the chunk
    /// before it joins that chunk.
    fn chunks(&self, order: &[usize]) -> Vec<(Vec<usize>, FeeFrac)> {
        let mut chunks: Vec<(Vec<usize>, FeeFrac)> = Vec::new();
        for &i in order {
            let (mut txs, mut ff) = (vec![i], self.ff[i]);
            while let Some((_, last)) = chunks.last()
                && feerate_compare(ff, *last) == Ordering::Greater
            {
                let (mut prev, last) = chunks.pop().expect("checked");
                prev.append(&mut txs);
                txs = prev;
                ff = ff + last;
            }
            chunks.push((txs, ff));
        }
        chunks
    }
}

/// A heap entry: the higher feerate first, then the smaller size, then the
/// lower txid.
struct Best {
    ff: FeeFrac,
    txid: Txid,
    index: usize,
}

impl Ord for Best {
    fn cmp(&self, other: &Self) -> Ordering {
        feerate_compare(self.ff, other.ff)
            .then_with(|| other.ff.size.cmp(&self.ff.size))
            .then_with(|| other.txid.cmp(&self.txid))
    }
}

impl PartialOrd for Best {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Best {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Best {}

/// Core's `GetSortedScoreWithTopology` (`TxGraphImpl::CompareMainOrder`):
/// every chunk of every cluster, by
/// 1. chunk feerate, highest first;
/// 2. the size of the run of equal-feerate chunks of its cluster that ends
///    with it, smallest first, which keeps a cluster's equal-feerate chunks
///    in their order;
/// 3. the highest txid in the chunk, lowest first (Core's fallback order
///    compares txids as `uint256`, byte for byte, as `Txid`'s `Ord` does);
///
/// and within a chunk, the cluster's linearization.
///
/// The order is a function of the transactions alone, so a reorg that
/// returns the same set gives the same list. It is Core's exactly where
/// [`linearize`] finds the linearization Core does, which it does for
/// chains and other simple shapes.
pub fn mining_order(g: &Graph) -> Vec<usize> {
    let kids = g.children();
    let all: Vec<usize> = (0..g.txids.len()).collect();
    // (feerate, equal-feerate prefix size, highest txid, transactions)
    let mut chunks: Vec<(FeeFrac, i64, Txid, Vec<usize>)> = Vec::new();
    for cluster in g.components(&kids, &all, |_, _| true) {
        let order = g.linearize_group(&cluster);
        let mut run = FeeFrac::default();
        for (txs, ff) in g.chunks(&order) {
            if run.is_empty() || feerate_compare(ff, run) == Ordering::Less {
                run = ff;
            } else {
                run = run + ff;
            }
            let top = txs.iter().map(|&i| g.txids[i]).max().expect("a chunk is not empty");
            chunks.push((ff, run.size, top, txs));
        }
    }
    chunks.sort_by(|a, b| feerate_compare(b.0, a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    chunks.into_iter().flat_map(|(_, _, _, txs)| txs).collect()
}

/// Core's `TxGraph::Trim` after a reorg (v31.1 `txgraph.cpp`), which
/// `UpdateTransactionsFromBlock` calls once the transactions a reorg
/// returned are linked to the mempool transactions already spending them.
/// Returns the transactions to remove so every cluster is within
/// `max_count` transactions and `max_weight`.
///
/// `returned[i]` says `txids[i]` came back from a disconnected block. Each
/// cluster past a limit is cut as Core cuts it. Its pieces are the clusters
/// it was before the reorg joined them: the returned transactions, and the
/// mempool's own, apart. Each piece keeps its linearization, read as a
/// chain, so a piece is kept up to some point and lost after it. The
/// pieces are merged best chunk feerate first, a transaction joining once
/// everything before it in its piece and every returned parent has joined.
/// A transaction whose partition would pass a limit is left out, and so is
/// everything that waits on it.
pub fn trim(g: &Graph, returned: &[bool], max_count: usize, max_weight: u64) -> Vec<usize> {
    let n = g.txids.len();
    let kids = g.children();
    let all: Vec<usize> = (0..n).collect();
    let mut removed = Vec::new();
    // Union-find over included transactions: parent, count, weight.
    let mut uf_parent: Vec<usize> = (0..n).collect();
    let mut uf_count: Vec<usize> = vec![1; n];
    let mut uf_weight: Vec<u64> = g.ff.iter().map(|f| f.size.max(0) as u64).collect();
    fn find(uf: &mut [usize], mut i: usize) -> usize {
        while uf[i] != i {
            uf[i] = uf[uf[i]];
            i = uf[i];
        }
        i
    }
    for cluster in g.components(&kids, &all, |_, _| true) {
        let weight: u64 = cluster.iter().map(|&i| g.ff[i].size.max(0) as u64).sum();
        if cluster.len() <= max_count && weight <= max_weight {
            continue;
        }
        // The pieces, apart: a returned transaction's link to a mempool
        // spender is what the reorg adds. Nothing in the mempool can be a
        // returned transaction's parent, so the other links stay in pieces.
        let added = |p: usize, c: usize| returned[p] && !returned[c];
        let mut chunk_ff = vec![FeeFrac::default(); n];
        // What each transaction waits on, and what waits on it.
        let mut waits: Vec<usize> = vec![0; n];
        let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut next: Vec<Vec<usize>> = vec![Vec::new(); n];
        for piece in g.components(&kids, &cluster, |p, c| !added(p, c)) {
            let order = g.linearize_group(&piece);
            for (txs, ff) in g.chunks(&order) {
                for i in txs {
                    chunk_ff[i] = ff;
                }
            }
            for pair in order.windows(2) {
                deps[pair[1]].push(pair[0]);
                next[pair[0]].push(pair[1]);
            }
        }
        for &c in &cluster {
            for &p in &g.parents[c] {
                if added(p, c) {
                    deps[c].push(p);
                    next[p].push(c);
                }
            }
            waits[c] = deps[c].len();
        }
        let mut heap = BinaryHeap::new();
        for &i in &cluster {
            if waits[i] == 0 {
                heap.push(Best { ff: chunk_ff[i], txid: g.txids[i], index: i });
            }
        }
        let mut included = vec![false; n];
        while let Some(Best { index: i, .. }) = heap.pop() {
            let mut roots: Vec<usize> = deps[i].iter().map(|&d| find(&mut uf_parent, d)).collect();
            roots.sort_unstable();
            roots.dedup();
            let count = 1 + roots.iter().map(|&r| uf_count[r]).sum::<usize>();
            let weight = uf_weight[i] + roots.iter().map(|&r| uf_weight[r]).sum::<u64>();
            if count > max_count || weight > max_weight {
                continue;
            }
            for r in roots {
                uf_parent[r] = i;
                uf_count[i] += uf_count[r];
                uf_weight[i] += uf_weight[r];
            }
            included[i] = true;
            for &c in &next[i] {
                waits[c] -= 1;
                if waits[c] == 0 {
                    heap.push(Best { ff: chunk_ff[c], txid: g.txids[c], index: c });
                }
            }
        }
        removed.extend(cluster.into_iter().filter(|&i| !included[i]));
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn id(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    /// A graph of `(id, fee, size, parents)`, parents by id.
    fn graph(txs: &[(u8, i64, i64, &[u8])]) -> Graph {
        let index = |n: u8| txs.iter().position(|t| t.0 == n).expect("a parent in the graph");
        Graph {
            txids: txs.iter().map(|t| id(t.0)).collect(),
            ff: txs.iter().map(|t| FeeFrac::new(t.1, t.2)).collect(),
            parents: txs.iter().map(|t| t.3.iter().map(|&p| index(p)).collect()).collect(),
        }
    }

    fn ids(g: &Graph, order: &[usize]) -> Vec<u8> {
        order.iter().map(|&i| g.txids[i].to_byte_array()[0]).collect()
    }

    /// A child that pays for its parent is mined with it, ahead of a
    /// transaction that pays more than the parent alone.
    #[test]
    fn a_child_paying_for_its_parent_lists_them_together_first() {
        let g = graph(&[(1, 100, 100, &[]), (2, 1_000, 100, &[1]), (3, 300, 100, &[])]);
        assert_eq!(ids(&g, &mining_order(&g)), vec![1, 2, 3]);
    }

    /// Equal-feerate chunks of distinct clusters go by their highest txid,
    /// lowest first; within one cluster, by the linearization.
    #[test]
    fn equal_feerates_go_by_the_chunks_highest_txid() {
        let g = graph(&[(9, 100, 100, &[]), (4, 100, 100, &[]), (7, 100, 100, &[4])]);
        // Cluster {4, 7} chunks as [4], [7] (equal feerates do not merge);
        // their run sizes 100 and 200 put 7 after 9, whose run is 100.
        assert_eq!(ids(&g, &mining_order(&g)), vec![4, 9, 7]);
    }

    /// The order depends on the transactions only, not on the order the
    /// graph lists them in. Iterating the mempool's map, it did.
    #[test]
    fn the_order_does_not_depend_on_the_graphs_order() {
        let txs: Vec<(u8, i64, i64, &[u8])> =
            vec![(1, 500, 100, &[]), (2, 500, 100, &[1]), (3, 500, 100, &[]), (4, 700, 200, &[3]), (5, 50, 100, &[])];
        let forward = graph(&txs);
        let mut reversed = txs.clone();
        reversed.reverse();
        let backward = graph(&reversed);
        assert_eq!(ids(&forward, &mining_order(&forward)), ids(&backward, &mining_order(&backward)));
    }

    /// A cluster within the limits is not touched, whatever it holds.
    #[test]
    fn a_cluster_within_the_limits_is_left_alone() {
        let g = graph(&[(1, 100, 100, &[]), (2, 100, 100, &[1]), (3, 100, 100, &[2])]);
        assert!(trim(&g, &[true, false, false], 3, 300).is_empty());
    }

    /// A returned chain whose spenders take it past the count keeps the
    /// best-paying transactions that fit, in each piece's order: the
    /// returned piece pays more, so it stays whole and the mempool's
    /// piece is cut after its first transaction.
    #[test]
    fn the_better_paying_piece_is_kept_and_the_other_cut() {
        // Returned 1 -> 2; the mempool's 3 -> 4 -> 5 spends 2.
        let g = graph(&[
            (1, 1_000, 100, &[]),
            (2, 1_000, 100, &[1]),
            (3, 200, 100, &[2]),
            (4, 100, 100, &[3]),
            (5, 100, 100, &[4]),
        ]);
        let removed = trim(&g, &[true, true, false, false, false], 3, u64::MAX);
        assert_eq!(ids(&g, &removed), vec![4, 5]);
    }

    /// A transaction left out takes everything after it in its piece's
    /// linearization, even what does not spend it and would fit: a piece
    /// is kept up to a point and lost after it, as in Core.
    #[test]
    fn what_follows_a_dropped_transaction_in_its_piece_goes_with_it() {
        // Returned 1; the mempool's 2 spends it; 3 (big) and 4 (small)
        // both spend 2, and 3 pays the better feerate, so it comes first.
        let g = graph(&[(1, 1_000, 100, &[]), (2, 1_000, 100, &[1]), (3, 600, 1_000, &[2]), (4, 5, 10, &[2])]);
        let removed = trim(&g, &[true, false, false, false], 10, 500);
        assert_eq!(ids(&g, &removed), vec![3, 4]);
    }

    /// The size limit cuts as the count does.
    #[test]
    fn a_cluster_is_cut_back_to_its_size() {
        let g = graph(&[(1, 1_000, 100, &[]), (2, 100, 100, &[1]), (3, 100, 100, &[2])]);
        let removed = trim(&g, &[true, false, false], 64, 200);
        assert_eq!(ids(&g, &removed), vec![3]);
    }

    /// The returned piece goes second when the mempool's pays more: its
    /// spender needs it first, so only what fits behind it is kept.
    #[test]
    fn a_spender_waits_for_the_returned_parent() {
        // Returned 1 -> 2 (cheap); the mempool's 3 spends 2 and pays well.
        let g = graph(&[(1, 10, 100, &[]), (2, 10, 100, &[1]), (3, 10_000, 100, &[2])]);
        let removed = trim(&g, &[true, true, false], 2, u64::MAX);
        assert_eq!(ids(&g, &removed), vec![3]);
    }
}
