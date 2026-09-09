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
