use super::*;
use bitcoin::hashes::Hash;

/// A chain of blocks with a hurdle each; `None` hurdle = no observation,
/// `missing` heights cannot be read (pruned).
struct FakeChain {
    blocks: Vec<(BlockHash, Option<u64>)>,
    missing_below: u32,
    ibd: bool,
    /// The block at this height has no parent in the index.
    broken_parent: Option<u32>,
}

fn hash(height: u32, salt: u8) -> BlockHash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&height.to_le_bytes());
    b[4] = salt;
    BlockHash::from_byte_array(b)
}

impl FakeChain {
    fn new(hurdles: &[u64]) -> Self {
        let blocks = hurdles.iter().enumerate().map(|(h, &r)| (hash(h as u32, 0), Some(r))).collect();
        Self { blocks, missing_below: 0, ibd: false, broken_parent: None }
    }
    fn push(&mut self, hurdle: u64, salt: u8) {
        let h = self.blocks.len() as u32;
        self.blocks.push((hash(h, salt), Some(hurdle)));
    }
    /// Replace the top `depth` blocks with a branch of `hurdles`.
    fn reorg(&mut self, depth: usize, hurdles: &[u64], salt: u8) {
        self.blocks.truncate(self.blocks.len() - depth);
        for &r in hurdles {
            self.push(r, salt);
        }
    }
    fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.blocks.iter().position(|(h, _)| h == hash).map(|i| i as u32)
    }
}

impl HurdleSource for FakeChain {
    fn in_initial_block_download(&self) -> bool {
        self.ibd
    }
    fn tip(&self) -> (BlockHash, u32) {
        let h = self.blocks.len() as u32 - 1;
        (self.blocks[h as usize].0, h)
    }
    fn parent(&self, hash: &BlockHash) -> Option<BlockHash> {
        let h = self.height_of(hash)?;
        if self.broken_parent == Some(h) {
            return None;
        }
        (h > 0).then(|| self.blocks[h as usize - 1].0)
    }
    fn hurdle(&self, hash: &BlockHash, _min_relay: u64) -> Result<Option<u64>, Unreadable> {
        let h = self.height_of(hash).ok_or(Unreadable)?;
        if h < self.missing_below {
            return Err(Unreadable);
        }
        Ok(self.blocks[h as usize].1)
    }
}

/// Sync until the backfill has nothing left to read.
fn sync_full(hist: &mut HurdleHistory, chain: &FakeChain) {
    for _ in 0..100 {
        if !hist.sync(chain, 0, 1_000) {
            return;
        }
    }
    panic!("the backfill never ends");
}

/// A calm market around 1,000 sat/kvB, with a little variation so that
/// quantiles are not all one value.
fn calm(n: usize, seed: usize) -> Vec<u64> {
    (0..n).map(|i| 900 + ((i * 37 + seed * 11) % 200) as u64).collect()
}

/// 3,200 blocks: calm, a 400-block spike at 50,000 in the middle, calm
/// again for the last 1,400.
fn history_with_past_spike() -> Vec<u64> {
    let mut v = calm(1_400, 1);
    v.extend(std::iter::repeat_n(50_000, 400));
    v.extend(calm(1_400, 2));
    v
}

/// The point of analog windows: a spike earlier in the history does not
/// raise the answer once the market is calm again. Paired with the plain
/// quantile over the same windows, which does.
#[test]
fn a_past_spike_does_not_raise_a_calm_market_estimate() {
    let hurdles = history_with_past_spike();
    let e = estimate_from_hurdles(&hurdles, 6).unwrap();
    assert_eq!(e.source, HistorySource::Analog);
    assert!(e.economical < 1_200, "analog estimate followed the old spike: {e:?}");
    // Paired: the same windows, read as a plain quantile, are steered by it.
    let mut plain = window_outcomes(&hurdles, lookback(6), 6);
    plain.sort_unstable();
    assert!(log_quantile(&plain, 0.95) >= 50_000);
}

/// And a spike in progress is answered from the past windows that started
/// inside a spike, so the estimate rises at once.
#[test]
fn a_spike_in_progress_raises_the_estimate() {
    let mut hurdles = history_with_past_spike();
    let n = hurdles.len();
    for h in &mut hurdles[n - 10..] {
        *h = 50_000;
    }
    let e = estimate_from_hurdles(&hurdles, 6).unwrap();
    assert_eq!(e.source, HistorySource::Analog);
    assert!(e.economical >= 40_000, "estimate did not follow the spike: {e:?}");
}

/// When fewer than 200 windows sit within ×1.25 of now, the 200 nearest by
/// before-level are used; when the band holds enough, exactly the band.
#[test]
fn the_200_nearest_windows_stand_in_for_a_thin_band() {
    let levels: Vec<u64> = (0..1_000).map(|i| i * 10).collect();
    let outcomes: Vec<u64> = (0..1_000).collect();
    let mut far = select_analogs(&levels, &outcomes, 20_000);
    far.sort_unstable();
    assert_eq!(far, (800..1_000).collect::<Vec<u64>>());
    // Within ×1.25 of 5,000: levels 4,000 ..= 6,250, i.e. 226 windows.
    let mut band = select_analogs(&levels, &outcomes, 5_000);
    band.sort_unstable();
    assert_eq!(band.len(), 226);
    assert_eq!((band[0], band[225]), (400, 625));
}

/// The store built one block at a time equals the store rebuilt at once.
#[test]
fn an_incremental_update_equals_a_rebuild() {
    let all: Vec<u64> = history_with_past_spike().into_iter().chain(calm(30, 3)).collect();
    let mut chain = FakeChain::new(&all[..3_200]);
    let mut inc = HurdleHistory::new();
    sync_full(&mut inc, &chain);
    for &r in &all[3_200..] {
        chain.push(r, 0);
        sync_full(&mut inc, &chain);
    }
    let mut rebuilt = HurdleHistory::new();
    sync_full(&mut rebuilt, &chain);
    assert_eq!(inc.rows, rebuilt.rows);
    assert_eq!(inc.table, rebuilt.table);
    assert_eq!(inc.len(), FEE_HISTORY_BLOCKS);
    assert_eq!(inc.newest().unwrap().0, all.len() as u32 - 1);
}

/// A reorg drops the rows of the abandoned branch and reads the new one,
/// found by the hash walk alone; no event is involved.
#[test]
fn a_reorg_replaces_the_abandoned_rows() {
    let mut chain = FakeChain::new(&calm(500, 1));
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    let old_tip = hist.newest().unwrap().1;
    chain.reorg(3, &[7_000, 8_000, 9_000, 10_000], 9);
    sync_full(&mut hist, &chain);
    let (h, newest) = hist.newest().unwrap();
    assert_eq!((h, newest), (chain.tip().1, chain.tip().0));
    assert!(hist.rows.iter().all(|r| r.hash != old_tip));
    let top: Vec<Option<u64>> = hist.rows.iter().rev().take(4).map(|r| r.hurdle).collect();
    assert_eq!(top, vec![Some(10_000), Some(9_000), Some(8_000), Some(7_000)]);
    // Still contiguous below the fork.
    assert!(hist.rows.iter().zip(hist.rows.iter().skip(1)).all(|(a, b)| b.height == a.height + 1));
}

/// Blocks connected while the task saw no event (an IBD catch-up, a lagged
/// receiver) are all picked up by the next pass.
#[test]
fn blocks_connected_without_an_event_are_picked_up() {
    let mut chain = FakeChain::new(&calm(100, 1));
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    for i in 0..5 {
        chain.push(2_000 + i, 0);
    }
    assert!(!hist.sync(&chain, 0, 0));
    assert_eq!(hist.len(), 105);
    assert_eq!(hist.newest().unwrap(), (104, chain.tip().0));
}

/// No rows are gathered during IBD.
#[test]
fn nothing_is_gathered_during_ibd() {
    let mut chain = FakeChain::new(&calm(100, 1));
    chain.ibd = true;
    let mut hist = HurdleHistory::new();
    assert!(!hist.sync(&chain, 0, 1_000));
    assert!(hist.is_empty());
    chain.ibd = false;
    sync_full(&mut hist, &chain);
    assert_eq!(hist.len(), 100);
}

/// The backfill reads newest first and stops for good at a block it
/// cannot read (pruned), keeping what it has.
#[test]
fn the_backfill_stops_at_a_pruned_block() {
    let mut chain = FakeChain::new(&calm(400, 1));
    chain.missing_below = 250;
    let mut hist = HurdleHistory::new();
    assert!(hist.sync(&chain, 0, 10), "more to read after one chunk");
    assert_eq!(hist.len(), 11, "the tip and ten below it");
    sync_full(&mut hist, &chain);
    assert_eq!(hist.len(), 150);
    assert_eq!(hist.rows.front().unwrap().height, 250);
    assert!(!hist.sync(&chain, 0, 1_000));
}

/// The store keeps at most its capacity, dropping the oldest rows.
#[test]
fn the_store_keeps_its_capacity() {
    let mut chain = FakeChain::new(&calm(60, 1));
    let mut hist = HurdleHistory::with_capacity(50);
    sync_full(&mut hist, &chain);
    assert_eq!(hist.len(), 50);
    chain.push(5_000, 0);
    sync_full(&mut hist, &chain);
    assert_eq!(hist.len(), 50);
    assert_eq!(hist.rows.front().unwrap().height, 11);
}

/// A target answers nothing until it has a complete window, a plain
/// quantile while it has fewer than 2,000, and analog windows from 2,000.
#[test]
fn readiness_goes_none_then_plain_then_analog() {
    // N = 6, L = 3: windows = len − 8.
    assert_eq!(estimate_from_hurdles(&calm(8, 1), 6), None);
    assert_eq!(estimate_from_hurdles(&calm(9, 1), 6).unwrap().source, HistorySource::Plain);
    assert_eq!(estimate_from_hurdles(&calm(2_007, 1), 6).unwrap().source, HistorySource::Plain);
    assert_eq!(estimate_from_hurdles(&calm(2_008, 1), 6).unwrap().source, HistorySource::Analog);
}

/// Blocks with no hurdle are not observations: they are skipped, not
/// counted as windows nobody could beat. N = 6 needs nine hurdles.
#[test]
fn blocks_without_a_hurdle_are_skipped() {
    let mut chain = FakeChain::new(&calm(9, 1));
    chain.blocks[4].1 = None;
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    assert_eq!(hist.len(), 9);
    assert_eq!(hist.estimate(6), None, "eight hurdles are not a window");
    chain.push(1_000, 0);
    sync_full(&mut hist, &chain);
    assert!(hist.estimate(6).is_some());
}

/// A longer target never answers more than a shorter one, conservative is
/// never below economical, and a target between ladder steps answers the
/// step below it.
#[test]
fn the_answers_are_monotone_across_targets() {
    let mut chain = FakeChain::new(&history_with_past_spike());
    // A rising tail, so that raw estimates would go up with the target.
    for i in 0..50 {
        chain.push(1_000 + i * 400, 0);
    }
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    let mut prev = (u64::MAX, u64::MAX);
    for t in 1..=MAX_TARGET {
        let Some(e) = hist.estimate(t) else { continue };
        assert!(e.economical <= prev.0 && e.conservative <= prev.1, "target {t}: {e:?}");
        assert!(e.conservative >= e.economical, "target {t}: {e:?}");
        prev = (e.economical, e.conservative);
    }
    assert_eq!(hist.estimate(11), hist.estimate(10));
    assert_eq!(hist.estimate(5_000), hist.estimate(1_008));
}

#[test]
fn the_log_quantile_interpolates_between_neighbours() {
    assert_eq!(log_quantile(&[100, 400], 0.5), 200);
    assert_eq!(log_quantile(&[0, 400], 0.5), 200);
    assert_eq!(log_quantile(&[7, 7, 7], 0.95), 7);
    assert_eq!(log_quantile(&[1, 2, 3, 4], 1.0), 4);
}

/// `fee_rate_estimator=block_policy` answers from the chain history once it
/// has a window, and so does `auto` with no mempool side (the default, F8).
#[test]
fn block_policy_and_auto_read_the_chain_history() {
    use crate::mempool::estimate::{EstimateMode, FeeRateEstimator, estimate_smart_fee};
    let est = crate::mempool::fee::FeeEstimator::new();
    est.record_block(&[5_000; 50]); // the flat percentile says 5,000
    let mempool = crate::mempool::pool::Mempool::new(300_000_000, 1_000);
    let ask = |e: FeeRateEstimator| {
        estimate_smart_fee(&mempool, &est, 6, EstimateMode::Historical, e, false)
            .unwrap()
            .feerate_sat_per_kvb
    };
    assert_eq!(ask(FeeRateEstimator::BlockPolicy), 5_000, "no window yet: the flat percentile");
    let chain = FakeChain::new(&[2_000; 100]);
    sync_full(&mut est.history().write(), &chain);
    assert_eq!(ask(FeeRateEstimator::BlockPolicy), 2_000);
    assert_eq!(ask(FeeRateEstimator::Auto), 2_000);
}

const MAGIC: [u8; 4] = [0x1c, 0x16, 0x3f, 0x28];

/// A restart keeps the history: the file loads every row, and the first
/// pass reads only the blocks connected since, with no backfill.
#[test]
fn a_restart_keeps_the_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FEE_HISTORY_FILE);
    let mut chain = FakeChain::new(&history_with_past_spike());
    let mut before = HurdleHistory::new();
    sync_full(&mut before, &chain);
    before.save(&path, MAGIC).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() < 150_000);

    chain.push(3_000, 0);
    chain.push(3_100, 0);
    let mut after = HurdleHistory::new();
    assert_eq!(after.load(&path, MAGIC).unwrap(), FEE_HISTORY_BLOCKS);
    assert_eq!(after.estimate(6), before.estimate(6), "answers as soon as it loads");
    // Two new blocks at the top, nothing below to read: one pass, no
    // backfill.
    assert!(!after.sync(&chain, 0, 0));
    let mut rebuilt = HurdleHistory::new();
    sync_full(&mut rebuilt, &chain);
    assert_eq!(after.rows, rebuilt.rows);
    assert_eq!(after.table, rebuilt.table);
}

/// A damaged file, one written for another network and one of another
/// version are refused, leave an empty store, and the history is read
/// again from the blocks. A good file loads (the paired must-succeed).
#[test]
fn a_damaged_or_foreign_file_is_rebuilt() {
    let chain = FakeChain::new(&calm(300, 1));
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    let good = hist.serialize(MAGIC);
    assert_eq!(HurdleHistory::new().load_bytes(&good, MAGIC), Ok(300));

    let mut flipped = good.clone();
    flipped[100] ^= 1;
    let mut version = good.clone();
    version[4] = 2;
    let truncated = &good[..good.len() - 1];
    for (bytes, net, why) in [
        (&flipped[..], MAGIC, "checksum"),
        (&good[..], [0xfa, 0xbf, 0xb5, 0xda], "network"),
        (&version[..], MAGIC, "version"),
        (truncated, MAGIC, "bytes for"),
        (&b"not a fee history"[..], MAGIC, "not a satd"),
    ] {
        let mut h = HurdleHistory::new();
        let err = h.load_bytes(bytes, net).unwrap_err();
        assert!(err.contains(why), "{why}: {err}");
        assert!(h.is_empty());
        sync_full(&mut h, &chain);
        assert_eq!(h.rows, hist.rows, "{why}: rebuilt from the blocks");
    }
}

/// Rows whose heights skip are refused even under a valid checksum.
#[test]
fn a_file_with_a_gap_is_refused() {
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &FakeChain::new(&calm(20, 1)));
    hist.rows.remove(5);
    let bytes = hist.serialize(MAGIC);
    assert!(HurdleHistory::new().load_bytes(&bytes, MAGIC).unwrap_err().contains("consecutive"));
}

/// A reorg while the node was down: the loaded rows of the abandoned
/// branch are dropped at the first pass, the rows below the fork kept.
#[test]
fn a_reorg_while_down_drops_the_stale_rows() {
    let mut chain = FakeChain::new(&calm(400, 1));
    let mut before = HurdleHistory::new();
    sync_full(&mut before, &chain);
    let bytes = before.serialize(MAGIC);
    chain.reorg(5, &[9_000; 8], 7);

    let mut after = HurdleHistory::new();
    after.load_bytes(&bytes, MAGIC).unwrap();
    sync_full(&mut after, &chain);
    let mut rebuilt = HurdleHistory::new();
    sync_full(&mut rebuilt, &chain);
    assert_eq!(after.rows, rebuilt.rows);
    assert_eq!(after.newest().unwrap(), (chain.tip().1, chain.tip().0));
    assert_eq!(after.rows.iter().filter(|r| r.hurdle == Some(9_000)).count(), 8);
}

/// A pruned node keeps the file's rows it could no longer read from the
/// blocks: its history goes back further than its block files.
#[test]
fn a_pruned_node_keeps_file_rows_it_cannot_reread() {
    let mut chain = FakeChain::new(&calm(1_000, 1));
    let mut before = HurdleHistory::new();
    sync_full(&mut before, &chain);
    let bytes = before.serialize(MAGIC);
    chain.missing_below = 900;
    chain.push(4_000, 0);

    let mut after = HurdleHistory::new();
    after.load_bytes(&bytes, MAGIC).unwrap();
    sync_full(&mut after, &chain);
    assert_eq!(after.len(), 1_001);
    assert_eq!(after.rows.front().unwrap().height, 0);
    // Paired: with no file, the same node reads only what it stores.
    let mut fresh = HurdleHistory::new();
    sync_full(&mut fresh, &chain);
    assert_eq!(fresh.len(), 101);
}

/// Heights in the file older than the history's span (a node down for
/// more than 3,200 blocks) are dropped and read again from the tip down.
#[test]
fn a_file_older_than_the_span_starts_again_at_the_tip() {
    let mut chain = FakeChain::new(&calm(100, 1));
    let mut small = HurdleHistory::with_capacity(50);
    sync_full(&mut small, &chain);
    let bytes = small.serialize(MAGIC);
    for _ in 0..60 {
        chain.push(2_000, 0);
    }
    let mut after = HurdleHistory::with_capacity(50);
    after.load_bytes(&bytes, MAGIC).unwrap();
    assert!(after.sync(&chain, 0, 0), "the backfill has the rest to read");
    assert_eq!(after.len(), 1);
    sync_full(&mut after, &chain);
    assert_eq!(after.rows.front().unwrap().height, 110);
}

/// [`ChainState`] as a source, with IBD forced off (the test chain's
/// timestamps are years old).
struct Synced<'a>(&'a ChainState);

impl HurdleSource for Synced<'_> {
    fn in_initial_block_download(&self) -> bool {
        false
    }
    fn tip(&self) -> (BlockHash, u32) {
        HurdleSource::tip(self.0)
    }
    fn parent(&self, hash: &BlockHash) -> Option<BlockHash> {
        HurdleSource::parent(self.0, hash)
    }
    fn hurdle(&self, hash: &BlockHash, min_relay: u64) -> Result<Option<u64>, Unreadable> {
        HurdleSource::hurdle(self.0, hash, min_relay)
    }
}

/// Read from a real chain: block and undo data price the one spend, the
/// coinbase-only blocks and the genesis block have no hurdle, every height
/// down to genesis is held, and the live IBD check holds the store empty.
#[test]
fn the_chain_state_source_prices_blocks_from_undo_data() {
    use crate::chain::state::tests::{build_test_block, build_test_block_spending, make_chain_state};
    use bitcoin::{Network, OutPoint};
    let (cs, dir) = make_chain_state();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks: Vec<bitcoin::Block> = Vec::new();
    for h in 1..=103u32 {
        let time = 1_300_000_000 + h * 600;
        let b = if h == 102 {
            let spend = OutPoint { txid: blocks[0].txdata[0].compute_txid(), vout: 0 };
            build_test_block_spending(parent, h, time, spend)
        } else {
            build_test_block(parent, h, time)
        };
        cs.accept_block(&b).expect("the test block connects");
        parent = b.block_hash();
        blocks.push(b);
    }
    let spend = &blocks[101].txdata[1];
    let funding = blocks[0].txdata[0].output[0].value.to_sat();
    let fee = funding - spend.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let rate = crate::mempool::policy::fee_rate_sat_per_kvb(fee, spend.weight().to_wu());

    let mut live = HurdleHistory::new();
    assert!(!live.sync(&cs, 0, 1_000), "the old test chain counts as IBD");
    assert!(live.is_empty());

    let mut hist = HurdleHistory::new();
    for _ in 0..100 {
        if !hist.sync(&Synced(&cs), 0, 1_000) {
            break;
        }
    }
    assert_eq!(hist.len(), 104);
    assert_eq!(hist.newest(), Some((103, blocks[102].block_hash())));
    let hurdles: Vec<(u32, Option<u64>)> = hist.rows.iter().map(|r| (r.height, r.hurdle)).collect();
    assert_eq!(hurdles[102], (102, Some(rate)));
    assert!(hurdles.iter().filter(|(h, _)| *h != 102).all(|(_, r)| r.is_none()));
    let _ = std::fs::remove_dir_all(dir);
}

/// A file with more rows than the store holds keeps the newest.
#[test]
fn a_load_keeps_the_newest_rows_that_fit() {
    let mut big = HurdleHistory::new();
    sync_full(&mut big, &FakeChain::new(&calm(20, 1)));
    let mut small = HurdleHistory::with_capacity(10);
    assert_eq!(small.load_bytes(&big.serialize(MAGIC), MAGIC), Ok(10));
    assert_eq!(small.rows.front().unwrap().height, 10);
}

/// The file is saved every 144 blocks, and when a backfill finishes; not
/// while a backfill runs.
#[test]
fn the_file_is_saved_every_144_blocks_and_after_a_backfill() {
    assert!(save_due(Some(244), Some(100), false, false));
    assert!(!save_due(Some(243), Some(100), false, false));
    assert!(save_due(Some(90), Some(100), false, false), "a reorg below the saved tip");
    assert!(save_due(Some(5), None, false, false), "never saved");
    assert!(save_due(Some(101), Some(100), true, false), "a backfill just finished");
    assert!(!save_due(Some(400), Some(100), true, true), "a backfill still runs");
    assert!(!save_due(None, None, false, false));
}

/// A walk that meets a block with no parent in the index starts again at
/// the tip rather than joining the new blocks to rows it cannot connect
/// them to.
#[test]
fn a_walk_that_loses_the_parent_starts_again_at_the_tip() {
    let mut chain = FakeChain::new(&calm(100, 1));
    let mut hist = HurdleHistory::new();
    sync_full(&mut hist, &chain);
    for _ in 0..5 {
        chain.push(3_000, 0);
    }
    chain.broken_parent = Some(102);
    sync_full(&mut hist, &chain);
    assert_eq!(hist.newest().unwrap(), (104, chain.tip().0));
    assert!(hist.rows.iter().zip(hist.rows.iter().skip(1)).all(|(a, b)| b.height == a.height + 1));
    assert_eq!(hist.rows.front().unwrap().height, 102);
}

/// The clamp lowers a longer target that answered more than a shorter one,
/// and passes over targets with no answer.
#[test]
fn a_longer_target_is_lowered_to_the_shorter_ones_answer() {
    let e = |economical, conservative| Some(HistoryEstimate { economical, conservative, source: HistorySource::Analog });
    let mut table = [e(5_000, 9_000), None, e(6_000, 8_000), e(2_000, 9_500)];
    clamp_monotone(&mut table);
    assert_eq!(table, [e(5_000, 9_000), None, e(5_000, 8_000), e(2_000, 8_000)]);
}

/// While the store has windows for short targets but not a deep one, the
/// deep target's flat-percentile fallback is held at or below the deepest
/// short target's analog answer, so the history answer never rises with
/// the target, and `conservative` under the default never drops below it.
#[test]
fn a_flat_fallback_never_rises_above_a_shorter_analog_answer() {
    use crate::mempool::estimate::{EstimateMode, FeeRateEstimator, estimate_smart_fee, history_rate};
    let est = crate::mempool::fee::FeeEstimator::new();
    est.record_block(&[50_000; 50]); // the flat percentile says 50,000
    let chain = FakeChain::new(&[2_000; 100]); // windows for 6 blocks, none for 144
    sync_full(&mut est.history().write(), &chain);
    assert!(est.history_estimate(6, true).is_some());
    assert_eq!(est.history_estimate(144, true), None);
    for conservative in [false, true] {
        let short = history_rate(&est, 6, conservative).unwrap();
        assert_eq!(history_rate(&est, 144, conservative), Some(short), "flat 50,000 capped");
    }
    let mempool = crate::mempool::pool::Mempool::new(300_000_000, 1_000);
    let ask = |t: u32, e: FeeRateEstimator| {
        estimate_smart_fee(&mempool, &est, t, EstimateMode::Blend, e, true).unwrap().feerate_sat_per_kvb
    };
    assert!(ask(144, FeeRateEstimator::Auto) >= ask(144, FeeRateEstimator::BlockPolicy));
}
