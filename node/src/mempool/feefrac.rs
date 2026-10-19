//! Feerate diagrams, ported from Bitcoin Core's `src/util/feefrac.{h,cpp}`.
//!
//! A *chunk* is a group of transactions a miner would take or leave together;
//! a *diagram* is the chunks of a mempool region sorted by feerate, read as a
//! cumulative fee-against-size curve. Core's RBF rule is that the replacement
//! must produce a diagram that is **no worse anywhere and better somewhere**
//! than the one it displaces (`ImprovesFeerateDiagram`, `policy/rbf.cpp`).
//!
//! Why this rather than comparing feerates directly: a replacement can pay
//! more than a conflicting transaction and still be worse for a miner, because
//! that transaction may be carrying a high-feerate child. Comparing against
//! the conflict's own feerate misses the child entirely, which is issue #660.
//!
//! Every comparison here is exact integer arithmetic on cross-products, never
//! a division: `FeeRateCompare` compares `a.fee * b.size` against
//! `b.fee * a.size`. Dividing first rounds, and a rounded feerate makes the
//! answer depend on transaction size in a way no policy intends.

use std::cmp::Ordering;

/// A (fee, size) pair — Core's `FeeFrac`. `size` is virtual bytes; `fee` is
/// satoshis and may be negative, since a diagram point can be a *difference*
/// of two chunks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeFrac {
    pub fee: i64,
    pub size: i64,
}

impl FeeFrac {
    pub fn new(fee: i64, size: i64) -> Self {
        Self { fee, size }
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl std::ops::Add for FeeFrac {
    type Output = FeeFrac;
    fn add(self, rhs: FeeFrac) -> FeeFrac {
        FeeFrac {
            fee: self.fee + rhs.fee,
            size: self.size + rhs.size,
        }
    }
}

impl std::ops::Sub for FeeFrac {
    type Output = FeeFrac;
    fn sub(self, rhs: FeeFrac) -> FeeFrac {
        FeeFrac {
            fee: self.fee - rhs.fee,
            size: self.size - rhs.size,
        }
    }
}

/// Core's `FeeRateCompare`: order two fee/size pairs by *feerate*, exactly.
///
/// `a.fee / a.size` against `b.fee / b.size`, evaluated as the cross-product
/// `a.fee * b.size` against `b.fee * a.size` so nothing is rounded. Widened to
/// `i128` first: mainnet fees and sizes both fit in `i64`, but their product
/// does not — a 21-million-BTC fee times a 4-million-vbyte size overflows, and
/// on a release build that wraps silently into the wrong verdict.
pub fn feerate_compare(a: FeeFrac, b: FeeFrac) -> Ordering {
    let lhs = (a.fee as i128) * (b.size as i128);
    let rhs = (b.fee as i128) * (a.size as i128);
    lhs.cmp(&rhs)
}

/// The result of comparing two diagrams. Core returns a
/// `std::partial_ordering`, which has a fourth state Rust's `Ordering` does
/// not: two diagrams can each be better somewhere, and then neither is
/// preferable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagramOrdering {
    /// The first diagram is better somewhere and worse nowhere.
    Better,
    /// The second is better somewhere and worse nowhere.
    Worse,
    /// Neither is better anywhere: the diagrams coincide.
    Equal,
    /// Each is better somewhere. Core's `unordered`.
    Incomparable,
}

/// Core's `CompareChunks` (`util/feefrac.cpp`), verbatim in structure.
///
/// Both inputs must already be sorted by descending feerate — that is what
/// makes the cumulative curve concave, and the comparison assumes it.
///
/// The two curves are walked together. At each step the side whose next point
/// comes first in *size* is advanced, and that point `P` is tested against the
/// line `AB` joining the other curve's previous and next points: above means
/// this side is better there, below means the other side is. If both end up
/// better somewhere, they are incomparable.
pub fn compare_chunks(chunks0: &[FeeFrac], chunks1: &[FeeFrac]) -> DiagramOrdering {
    let chunk = [chunks0, chunks1];
    let mut next_index = [0usize, 0usize];
    let mut accum = [FeeFrac::default(), FeeFrac::default()];
    let mut better_somewhere = [false, false];

    loop {
        let done = [
            next_index[0] == chunk[0].len(),
            next_index[1] == chunk[1].len(),
        ];
        if done[0] && done[1] {
            break;
        }

        // The side with the first unprocessed point, by size. If one side is
        // finished, use the other — only one can be, by the check above.
        let unproc: usize = if done[0] || done[1] {
            usize::from(done[0])
        } else {
            let p0 = chunk[0][next_index[0]] + accum[0];
            let p1 = chunk[1][next_index[1]] + accum[1];
            usize::from(p0.size > p1.size)
        };
        let other = 1 - unproc;

        let point_p = chunk[unproc][next_index[unproc]] + accum[unproc];
        let point_a = accum[other];
        let slope_ap = point_p - point_a;

        let cmp = if done[0] || done[1] {
            // One side has nothing left: treat AB as having a slope of zero,
            // i.e. the finished diagram earns nothing more.
            feerate_compare(slope_ap, FeeFrac::new(0, 1))
        } else {
            let point_b = chunk[other][next_index[other]] + accum[other];
            let slope_ab = point_b - point_a;
            let c = feerate_compare(slope_ap, slope_ab);
            // If B and P are at the same size, B is compared too and can be
            // marked processed alongside P.
            if point_b.size == point_p.size {
                accum[other] = accum[other] + chunk[other][next_index[other]];
                next_index[other] += 1;
            }
            c
        };

        match cmp {
            Ordering::Greater => better_somewhere[unproc] = true,
            Ordering::Less => better_somewhere[other] = true,
            Ordering::Equal => {}
        }
        accum[unproc] = accum[unproc] + chunk[unproc][next_index[unproc]];
        next_index[unproc] += 1;

        if better_somewhere[0] && better_somewhere[1] {
            return DiagramOrdering::Incomparable;
        }
    }

    match (better_somewhere[0], better_somewhere[1]) {
        (true, false) => DiagramOrdering::Better,
        (false, true) => DiagramOrdering::Worse,
        _ => DiagramOrdering::Equal,
    }
}

/// One transaction of the set a replacement would evict, as the old diagram
/// sees it.
#[derive(Clone, Copy, Debug)]
pub struct EvictedTx {
    /// This transaction's own modified fee and vsize.
    pub individual: FeeFrac,
    /// Its single in-mempool parent, if it has one.
    pub parent: Option<FeeFrac>,
    /// Whether it has an in-mempool descendant.
    pub has_descendant: bool,
}

/// Build the diagram of the mempool region a replacement would displace —
/// Core's old-diagram half of `CalculateChunksForRBF`.
///
/// A transaction with a descendant contributes nothing on its own: it is
/// accounted for when that descendant is considered, and emitting it here too
/// would count its fee twice and add a spurious low-feerate chunk.
///
/// A transaction with a parent is either one chunk with it — when the child
/// out-pays the pair, so a miner takes them together — or two points, the
/// parent's first.
pub fn old_diagram(evicted: &[EvictedTx]) -> Vec<FeeFrac> {
    let mut chunks: Vec<FeeFrac> = Vec::new();
    for tx in evicted {
        if tx.has_descendant {
            continue;
        }
        match tx.parent {
            Some(parent) => {
                let package = tx.individual + parent;
                if feerate_compare(tx.individual, package) == Ordering::Greater {
                    chunks.push(package);
                } else {
                    chunks.push(package - tx.individual);
                    chunks.push(tx.individual);
                }
            }
            None => chunks.push(tx.individual),
        }
    }
    sort_chunks(&mut chunks);
    chunks
}

/// The most transactions [`cluster_chunks`] takes: Core's
/// `MAX_CLUSTER_COUNT_LIMIT`, and one bit each in a `u64`.
pub const MAX_CHUNKED_CLUSTER: usize = 64;

/// A cluster for the functions below: `txs[i]` is a transaction's fee and
/// size and the bitmask of its parents among `txs`. At most
/// [`MAX_CHUNKED_CLUSTER`] transactions.
pub type ClusterTxs = [(FeeFrac, u64)];

/// Each transaction's ancestors within the cluster, itself included.
fn ancestor_masks(txs: &ClusterTxs) -> Vec<u64> {
    let n = txs.len();
    let mut anc: Vec<u64> = (0..n).map(|i| (1u64 << i) | txs[i].1).collect();
    loop {
        let mut changed = false;
        for i in 0..n {
            let mut grown = anc[i];
            let mut rest = anc[i] & !(1u64 << i);
            while rest != 0 {
                let p = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                grown |= anc[p];
            }
            if grown != anc[i] {
                anc[i] = grown;
                changed = true;
            }
        }
        if !changed {
            return anc;
        }
    }
}

fn sum_of(txs: &ClusterTxs, set: u64) -> FeeFrac {
    let mut total = FeeFrac::default();
    let mut rest = set;
    while rest != 0 {
        let i = rest.trailing_zeros() as usize;
        rest &= rest - 1;
        total = total + txs[i].0;
    }
    total
}

fn all_of(n: usize) -> u64 {
    if n == 64 { u64::MAX } else { (1u64 << n) - 1 }
}

/// A cluster's linearization by ancestor-set feerate, as Core mined before
/// the cluster mempool: the remaining transaction whose remaining ancestors
/// pay the best feerate goes next, with them. Each chosen set is laid out
/// by the same rule, its ancestors first and the transaction it was chosen
/// for last. Laying a set out as one block folded a cheap tail into the
/// chunk ahead of it.
pub fn linearize(txs: &ClusterTxs) -> Vec<usize> {
    let n = txs.len();
    assert!(n <= MAX_CHUNKED_CLUSTER);
    let anc = ancestor_masks(txs);
    // The best ancestor set within `within`: highest feerate, then the
    // smaller, then the lower index, so the order is deterministic.
    let best_set = |within: u64| -> (u64, usize) {
        let mut best: Option<(u64, usize, FeeFrac)> = None;
        let mut rest = within;
        while rest != 0 {
            let i = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            let set = anc[i] & within;
            let ff = sum_of(txs, set);
            let better = match best {
                None => true,
                Some((_, _, b)) => match feerate_compare(ff, b) {
                    Ordering::Greater => true,
                    Ordering::Equal => ff.size < b.size,
                    Ordering::Less => false,
                },
            };
            if better {
                best = Some((set, i, ff));
            }
        }
        let (set, top, _) = best.expect("within is not empty");
        (set, top)
    };
    let mut order: Vec<usize> = Vec::with_capacity(n);
    // (mask still to lay out, the transaction to place once it is empty)
    let mut stack: Vec<(u64, Option<usize>)> = vec![(all_of(n), None)];
    while let Some((mask, then)) = stack.pop() {
        if mask == 0 {
            order.extend(then);
            continue;
        }
        let (set, top) = best_set(mask);
        // The rest of `mask` after this set, then this set without its top,
        // then the top: pushed in reverse.
        stack.push((mask & !set, then));
        stack.push((set & !(1u64 << top), Some(top)));
    }
    order
}

/// The chunks of `order` restricted to `todo`, with their sets: a
/// transaction that pays more than the chunk before it joins that chunk.
fn chunk_sets(txs: &ClusterTxs, order: &[usize], todo: u64) -> Vec<(u64, FeeFrac)> {
    let mut chunks: Vec<(u64, FeeFrac)> = Vec::new();
    for &i in order {
        if todo & (1u64 << i) == 0 {
            continue;
        }
        let (mut set, mut ff) = (1u64 << i, txs[i].0);
        while let Some(&(last_set, last_ff)) = chunks.last()
            && feerate_compare(ff, last_ff) == Ordering::Greater
        {
            set |= last_set;
            ff = ff + last_ff;
            chunks.pop();
        }
        chunks.push((set, ff));
    }
    chunks
}

/// The chunks of a linearization, in descending feerate.
pub fn chunk_order(txs: &ClusterTxs, order: &[usize]) -> Vec<FeeFrac> {
    chunk_sets(txs, order, all_of(txs.len())).into_iter().map(|(_, ff)| ff).collect()
}

/// Core's `MergeLinearizations` (v29 `cluster_linearize.h`): a
/// linearization whose diagram is at least as good as both inputs'
/// everywhere. Each step takes the better of the two first remaining
/// chunks, cut down to its shortest intersection with the other order's
/// chunk prefixes that pays no less (`IntersectPrefixes`).
///
/// Core v31 dropped it because its linearizer starts from the existing
/// order and only improves it. satd starts afresh, so it merges the fresh
/// order with the old one instead: a replacement that improves on what it
/// replaces in place can then never chunk worse than the original.
pub fn merge_linearizations(txs: &ClusterTxs, lin1: &[usize], lin2: &[usize]) -> Vec<usize> {
    let n = txs.len();
    let anc = ancestor_masks(txs);
    // Shortest intersection of `subset` with prefixes of `chunks` paying
    // no less than `subset`.
    let intersect = |chunks: &[(u64, FeeFrac)], subset: (u64, FeeFrac)| -> (u64, FeeFrac) {
        let mut acc = (0u64, FeeFrac::default());
        for &(chunk, _) in chunks {
            let to_add = chunk & subset.0;
            if to_add == 0 {
                continue;
            }
            acc.0 |= to_add;
            if acc.0 == subset.0 {
                break;
            }
            acc.1 = acc.1 + sum_of(txs, to_add);
            if feerate_compare(acc.1, subset.1) != Ordering::Less {
                return acc;
            }
        }
        subset
    };
    let mut todo = all_of(n);
    let mut out: Vec<usize> = Vec::with_capacity(n);
    while todo != 0 {
        let c1 = chunk_sets(txs, lin1, todo);
        let c2 = chunk_sets(txs, lin2, todo);
        let best = if feerate_compare(c2[0].1, c1[0].1) == Ordering::Greater {
            intersect(&c1, c2[0])
        } else {
            intersect(&c2, c1[0])
        };
        // Core's `AppendTopo`: by ancestor count, then index.
        let mut picked: Vec<usize> = (0..n).filter(|i| best.0 & (1u64 << i) != 0).collect();
        picked.sort_by_key(|&i| (anc[i].count_ones(), i));
        out.extend(picked);
        todo &= !best.0;
    }
    out
}

/// The chunks of one cluster's [`linearize`] order, in descending feerate,
/// or `None` past [`MAX_CHUNKED_CLUSTER`] transactions.
pub fn cluster_chunks(txs: &ClusterTxs) -> Option<Vec<FeeFrac>> {
    if txs.len() > MAX_CHUNKED_CLUSTER {
        return None;
    }
    Some(chunk_order(txs, &linearize(txs)))
}

/// Sort a diagram the way `CompareChunks` requires: descending feerate.
pub fn sort_chunks(chunks: &mut [FeeFrac]) {
    // Core sorts with `std::greater()` on `FeeFrac`, whose ordering is
    // feerate-first with size as the tiebreak (a bigger chunk at the same
    // feerate sorts first). Reproduced rather than approximated: the order
    // decides which point the walk above tests against which line.
    chunks.sort_by(|a, b| match feerate_compare(*b, *a) {
        Ordering::Equal => b.size.cmp(&a.size),
        other => other,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ff(fee: i64, size: i64) -> FeeFrac {
        FeeFrac::new(fee, size)
    }

    /// A parent with one child that pays for it is one chunk; a second,
    /// poorer child is a chunk of its own.
    #[test]
    fn a_child_that_pays_for_its_parent_shares_its_chunk() {
        let chunks = cluster_chunks(&[(ff(100, 100), 0), (ff(3_000, 100), 0b1), (ff(200, 100), 0b1)]).unwrap();
        assert_eq!(chunks, vec![ff(3_100, 200), ff(200, 100)]);
    }

    /// A richer parent goes first on its own, and children that pay less
    /// follow, best first.
    #[test]
    fn a_rich_parent_is_its_own_chunk() {
        let chunks = cluster_chunks(&[(ff(5_000, 100), 0), (ff(100, 100), 0b1), (ff(300, 100), 0b1)]).unwrap();
        assert_eq!(chunks, vec![ff(5_000, 100), ff(300, 100), ff(100, 100)]);
    }

    /// A grandchild's ancestors come with it, through the child: a poor
    /// parent and child are pulled up by a rich grandchild.
    #[test]
    fn ancestors_are_taken_transitively() {
        let chunks = cluster_chunks(&[(ff(0, 100), 0), (ff(0, 100), 0b1), (ff(9_000, 100), 0b10)]).unwrap();
        assert_eq!(chunks, vec![ff(9_000, 300)]);
    }

    /// A later segment that pays more than the chunk before it joins that
    /// chunk, so the chunks come out in descending feerate.
    #[test]
    fn a_later_richer_segment_merges_into_the_chunk_before() {
        // P pays nothing; C1 pays 300 and C2 200, each over 100. P goes with
        // C1 first ({P, C1} at 1.5 beats {P, C2} at 1.0); then C2 alone pays
        // 2.0, more than that chunk, and joins it.
        let chunks = cluster_chunks(&[(ff(0, 100), 0), (ff(300, 100), 0b1), (ff(200, 100), 0b1)]).unwrap();
        assert_eq!(chunks, vec![ff(500, 300)]);
        for pair in chunks.windows(2) {
            assert_ne!(feerate_compare(pair[0], pair[1]), Ordering::Less);
        }
    }

    /// A diamond: A parents B and C, and D spends both. Bumping only D's fee
    /// must not chunk worse than before. Laying out D's ancestor set as one
    /// block made it a single chunk, (7000, 6400), which at 4000 pays 4375
    /// against the original's 4600.
    #[test]
    fn a_fee_bump_of_a_diamonds_tail_chunks_no_worse() {
        let diamond = |d_fee| {
            [(ff(600, 1600), 0), (ff(2600, 1600), 0b1), (ff(1400, 800), 0b1), (ff(d_fee, 2400), 0b110)]
        };
        let before = cluster_chunks(&diamond(1400)).unwrap();
        let after = cluster_chunks(&diamond(2400)).unwrap();
        assert_eq!(before, vec![ff(4600, 4000), ff(1400, 2400)]);
        assert_eq!(after, vec![ff(4600, 4000), ff(2400, 2400)]);
        assert_eq!(compare_chunks(&after, &before), DiagramOrdering::Better);
    }

    /// Devin's tree: A parents B and C, D spends B. Bumping only D's fee
    /// reorders the fresh linearization (A, B, D, C) into one chunk that,
    /// at 3200, pays less than the original order did. Merged with the old
    /// order carrying the bump, it is no worse anywhere.
    #[test]
    fn merging_with_the_old_order_keeps_a_fee_bump_no_worse() {
        let tree = |d_fee| [(ff(800, 2000), 0), (ff(1800, 800), 0b1), (ff(1300, 400), 0b1), (ff(d_fee, 2000), 0b10)];
        let before = tree(500);
        let after = tree(2400);
        let old_order = linearize(&before);
        assert_eq!(chunk_order(&before, &old_order), vec![ff(3900, 3200), ff(500, 2000)]);
        // Fresh, the bump comes out worse than the original.
        let fresh = linearize(&after);
        assert_ne!(compare_chunks(&chunk_order(&after, &fresh), &chunk_order(&before, &old_order)), DiagramOrdering::Better);
        // Merged with the original order, it is better.
        let merged = merge_linearizations(&after, &fresh, &old_order);
        assert_eq!(compare_chunks(&chunk_order(&after, &merged), &chunk_order(&before, &old_order)), DiagramOrdering::Better);
    }

    /// A merge is no worse than either input anywhere, and keeps every
    /// parent ahead of its children.
    #[test]
    fn a_merge_is_at_least_as_good_as_both_and_topological() {
        let txs = [(ff(100, 100), 0), (ff(900, 100), 0b1), (ff(50, 100), 0), (ff(700, 100), 0b100), (ff(300, 100), 0b1010)];
        let a = vec![0, 1, 2, 3, 4];
        let b = vec![2, 3, 0, 1, 4];
        let m = merge_linearizations(&txs, &a, &b);
        for lin in [&a, &b] {
            assert!(matches!(
                compare_chunks(&chunk_order(&txs, &m), &chunk_order(&txs, lin)),
                DiagramOrdering::Better | DiagramOrdering::Equal
            ));
        }
        let pos = |i: usize| m.iter().position(|&x| x == i).unwrap();
        for (i, (_, parents)) in txs.iter().enumerate() {
            for p in 0..txs.len() {
                if parents & (1 << p) != 0 {
                    assert!(pos(p) < pos(i));
                }
            }
        }
    }

    #[test]
    fn a_cluster_past_sixty_four_is_not_chunked() {
        let txs: Vec<(FeeFrac, u64)> = (0..65).map(|_| (ff(1, 1), 0)).collect();
        assert!(cluster_chunks(&txs).is_none());
        assert_eq!(cluster_chunks(&txs[..64]).unwrap().len(), 64, "equal feerates are not merged");
    }

    /// Feerates are compared by cross-product, so no division rounds a
    /// verdict. 1/3 and 2/6 are the same rate however they are written.
    #[test]
    fn feerates_compare_without_dividing() {
        assert_eq!(feerate_compare(ff(1, 3), ff(2, 6)), Ordering::Equal);
        assert_eq!(feerate_compare(ff(2, 3), ff(1, 3)), Ordering::Greater);
        assert_eq!(feerate_compare(ff(1, 3), ff(1, 2)), Ordering::Less);
        // Rounding a division would call these equal; they are not.
        assert_eq!(feerate_compare(ff(1_000_001, 1_000), ff(1_000_000, 1_000)), Ordering::Greater);
    }

    /// The cross-product overflows `i64` at realistic values — a
    /// 21-million-BTC fee against a 4-million-vbyte size — and on a release
    /// build, where there are no overflow checks, that wraps silently into
    /// the wrong verdict. The arithmetic is therefore done in 128 bits.
    #[test]
    fn the_cross_product_is_computed_in_128_bits() {
        let max_money = 21_000_000i64 * 100_000_000;
        let big_block = 4_000_000i64;
        assert!(
            max_money.checked_mul(big_block).is_none(),
            "the premise: a mainnet-scale fee times a block-scale size does \
             not fit in i64"
        );
        // Same feerate at wildly different scales, both products over the
        // i64 ceiling.
        assert_eq!(
            feerate_compare(ff(max_money, big_block), ff(max_money / 2, big_block / 2)),
            Ordering::Equal
        );

        // A pair chosen so the wrap is *visible*: the true products are 2^63
        // and 2^62, so in i64 the larger one wraps negative and the
        // comparison inverts. Computed in i128 it is simply Greater.
        let a = ff(1i64 << 61, 4);
        let b = ff(1i64 << 60, 4);
        assert!(
            a.fee.checked_mul(b.size).is_none(),
            "the premise: this product wraps in i64"
        );
        assert_eq!(
            (a.fee.wrapping_mul(b.size)).cmp(&b.fee.wrapping_mul(a.size)),
            Ordering::Less,
            "the premise: wrapped, the verdict inverts"
        );
        assert_eq!(
            feerate_compare(a, b),
            Ordering::Greater,
            "the higher feerate is the higher feerate"
        );
    }

    /// A diagram is compared against itself as equal, and against a uniformly
    /// higher-paying one as worse.
    #[test]
    fn a_strictly_better_diagram_wins_everywhere() {
        let old = vec![ff(1_000, 100)];
        let new = vec![ff(2_000, 100)];
        assert_eq!(compare_chunks(&new, &old), DiagramOrdering::Better);
        assert_eq!(compare_chunks(&old, &new), DiagramOrdering::Worse);
        assert_eq!(compare_chunks(&old, &old), DiagramOrdering::Equal);
    }

    /// The case issue #660 is about, in diagram form: a cheap parent carrying
    /// an expensive child. A replacement that beats the *parent's* feerate but
    /// not the pair's is worse for a miner, and the diagram says so where a
    /// per-conflict feerate comparison does not.
    #[test]
    fn a_replacement_that_only_beats_the_parent_is_worse() {
        // Parent 1000 sat / 1000 vB (1 sat/vB) with a child that lifts the
        // pair to 11000 sat / 2000 vB (5.5 sat/vB): one chunk, since a miner
        // takes them together.
        let old = vec![ff(11_000, 2_000)];
        // A replacement paying 2 sat/vB — better than the parent alone, far
        // worse than the pair.
        let new = vec![ff(2_000, 1_000)];
        assert_eq!(
            compare_chunks(&new, &old),
            DiagramOrdering::Worse,
            "beating the parent is not beating the chunk"
        );
        // Paying more than the whole chunk does win.
        let new = vec![ff(12_000, 1_000)];
        assert_eq!(compare_chunks(&new, &old), DiagramOrdering::Better);
    }

    /// Two diagrams can cross: one better at small sizes, the other better at
    /// large. Core calls that unordered, and a replacement is only accepted
    /// when it is strictly greater — so an incomparable result is a refusal.
    #[test]
    fn crossing_diagrams_are_incomparable() {
        // A: one small, very high feerate chunk.
        let a = vec![ff(10_000, 100)];
        // B: one large, moderate chunk that eventually earns more in total.
        let b = vec![ff(20_000, 1_000)];
        assert_eq!(
            compare_chunks(&a, &b),
            DiagramOrdering::Incomparable,
            "A wins early, B wins late"
        );
        assert_eq!(compare_chunks(&b, &a), DiagramOrdering::Incomparable);
    }

    /// Multi-chunk diagrams, walked point by point. Splitting one chunk into
    /// two of the same total at *decreasing* feerate is worse: the miner gets
    /// less for the first bytes.
    #[test]
    fn splitting_a_chunk_into_a_declining_pair_is_worse() {
        let combined = vec![ff(4_000, 2_000)];
        let mut split = vec![ff(1_000, 1_000), ff(3_000, 1_000)];
        sort_chunks(&mut split);
        assert_eq!(split[0], ff(3_000, 1_000), "descending feerate");
        assert_eq!(
            compare_chunks(&split, &combined),
            DiagramOrdering::Better,
            "taking the better half first is worth more early and the same in total"
        );
        assert_eq!(compare_chunks(&combined, &split), DiagramOrdering::Worse);
    }

    /// An empty diagram is worse than anything that pays, and equal to
    /// another empty one — the degenerate cases the walk has to survive.
    #[test]
    fn empty_diagrams_are_handled() {
        let empty: Vec<FeeFrac> = Vec::new();
        let some = vec![ff(1_000, 100)];
        assert_eq!(compare_chunks(&some, &empty), DiagramOrdering::Better);
        assert_eq!(compare_chunks(&empty, &some), DiagramOrdering::Worse);
        assert_eq!(compare_chunks(&empty, &empty), DiagramOrdering::Equal);
    }

    /// `sort_chunks` puts the highest feerate first and breaks ties by size,
    /// as Core's `std::greater<FeeFrac>` does. The order is not cosmetic: the
    /// walk assumes a concave curve.
    #[test]
    fn chunks_sort_by_feerate_then_size() {
        let mut chunks = vec![ff(100, 100), ff(300, 100), ff(200, 200), ff(400, 400)];
        sort_chunks(&mut chunks);
        assert_eq!(chunks[0], ff(300, 100), "3 sat/vB first");
        // 1 sat/vB three ways; the largest comes first.
        assert_eq!(chunks[1], ff(400, 400));
        assert_eq!(chunks[2], ff(200, 200));
        assert_eq!(chunks[3], ff(100, 100));
    }

    /// The old diagram is where double-counting hides. A transaction with a
    /// descendant contributes nothing on its own — it is accounted for when
    /// that descendant is considered — and emitting it anyway adds its fee a
    /// second time plus a spurious low-feerate chunk.
    #[test]
    fn a_transaction_with_a_descendant_is_counted_only_through_it() {
        let parent = FeeFrac::new(1_000, 110);
        let child = FeeFrac::new(500_000, 110);
        let evicted = [
            EvictedTx { individual: parent, parent: None, has_descendant: true },
            EvictedTx { individual: child, parent: Some(parent), has_descendant: false },
        ];
        let chunks = old_diagram(&evicted);
        assert_eq!(
            chunks,
            vec![FeeFrac::new(501_000, 220)],
            "one chunk carrying both fees, once"
        );
        let total: i64 = chunks.iter().map(|c| c.fee).sum();
        assert_eq!(total, 501_000, "the parent's fee is not double-counted");
    }

    /// A child that out-pays the pair is chunked *with* its parent: a miner
    /// takes them together. That is what makes "beat the parent" the wrong
    /// question.
    #[test]
    fn a_child_that_outpays_the_pair_chunks_with_its_parent() {
        let parent = FeeFrac::new(1_000, 100);
        let child = FeeFrac::new(9_000, 100);
        let chunks = old_diagram(&[EvictedTx {
            individual: child,
            parent: Some(parent),
            has_descendant: false,
        }]);
        assert_eq!(chunks, vec![FeeFrac::new(10_000, 200)], "one chunk");
    }

    /// A child that pays *less* than its parent does not lift it, so the two
    /// are separate points with the parent first.
    #[test]
    fn a_cheaper_child_is_a_separate_point_after_its_parent() {
        let parent = FeeFrac::new(9_000, 100);
        let child = FeeFrac::new(1_000, 100);
        let chunks = old_diagram(&[EvictedTx {
            individual: child,
            parent: Some(parent),
            has_descendant: false,
        }]);
        assert_eq!(
            chunks,
            vec![FeeFrac::new(9_000, 100), FeeFrac::new(1_000, 100)],
            "parent first, then the child at its own rate"
        );
    }

    /// A transaction with no relatives is its own chunk.
    #[test]
    fn a_lone_transaction_is_one_chunk() {
        let chunks = old_diagram(&[EvictedTx {
            individual: FeeFrac::new(5_000, 250),
            parent: None,
            has_descendant: false,
        }]);
        assert_eq!(chunks, vec![FeeFrac::new(5_000, 250)]);
    }
}
