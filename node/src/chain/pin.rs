//! A request pinned to one block: the tip it started at, or an `asof` block.
//!
//! The query surfaces (Esplora, Electrum) answer a chain-reading request for
//! one block. A request takes a [`ChainView`] before it reads and answers for
//! a [`Pin`] of it: nothing above the pin's height is confirmed, and a
//! transaction confirmed above it is the unconfirmed one it was when the
//! request started. Blocks that connect on top of the pin while the request
//! runs leave everything at and below it as it was, so the answer stands.
//! Only a disconnect can change what the pinned heights hold: then the answer
//! is discarded and the request run again, up to [`VIEW_ATTEMPTS`] times.
//!
//! An `asof` request pins a block below the tip instead, while it is on the
//! best chain, and answers with confirmed data only.

use std::time::{Duration, Instant};

use bitcoin::BlockHash;

use super::state::{ChainState, ChainView, ViewChange};

/// How many runs a request gets before a chain that retreated under every
/// one is answered with [`CHAIN_VIEW_MOVED`]. The same budget as
/// `ChainState::coherent_read`.
pub const VIEW_ATTEMPTS: usize = 8;

/// How long to wait for a chain mutation in flight to finish, before a run
/// and after one, as `ChainState::coherent_read` waits.
pub const VIEW_WAIT: Duration = Duration::from_millis(500);

/// The error for a chain that retreated under every run.
pub const CHAIN_VIEW_MOVED: &str = "chain view moved";

/// The block a request answers for. Every chain read the request makes is
/// bounded to it: nothing above `height` is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub hash: BlockHash,
    pub height: u32,
    /// The answer includes the mempool: a live request pinned to the tip.
    /// `false` for `asof`, which answers with confirmed data only, and
    /// treats a transaction confirmed above the pin as unknown rather than
    /// unconfirmed.
    pub mempool: bool,
}

impl Pin {
    /// A live request's pin: the view's tip, with the mempool.
    pub fn at_tip(view: &ChainView) -> Self {
        Self {
            hash: view.tip_hash,
            height: view.tip_height,
            mempool: true,
        }
    }

    /// A block at `height` is confirmed as of this pin.
    pub fn covers(&self, height: u32) -> bool {
        height <= self.height
    }

    /// The pinned chain's block at `height`, from the height index. The
    /// index row for a height at or below the pin is the pinned chain's
    /// until a disconnect, which reruns the request.
    pub fn hash_at_height(&self, chain: &ChainState, height: u32) -> Option<BlockHash> {
        if !self.covers(height) {
            return None;
        }
        if height == self.height {
            return Some(self.hash);
        }
        chain.get_block_hash_by_height(height)
    }
}

/// The pin for `asof` `hash`: the block, if it is on the best chain at or
/// below `view`'s tip.
///
/// Membership is the height index row alone, two point reads, as
/// [`Pin::hash_at_height`] reads it. `ChainState::active_chain_contains`
/// would walk parent pointers back from the tip for a hash the row does not
/// name, and this runs for any hash a client sends: a stale block deep in
/// the chain would cost one read per block above it.
pub fn asof_pin(chain: &ChainState, view: &ChainView, hash: BlockHash) -> Option<Pin> {
    let entry = chain.get_block_index(&hash)?;
    if entry.height > view.tip_height || chain.get_block_hash_by_height(entry.height) != Some(hash)
    {
        return None;
    }
    Some(Pin {
        hash,
        height: entry.height,
        mempool: false,
    })
}

/// How [`run_pinned`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Pinned<T> {
    /// The run's answer, and the pin it answers for.
    Answered(T, Pin),
    /// The `asof` block is not on the best chain, now or after a retreat.
    /// There is no retry onto another block at its height.
    NotOnChain,
    /// The chain retreated under every run, or a mutation stayed in flight
    /// past [`VIEW_WAIT`].
    Moved,
}

/// Run `read` pinned to the current tip, or to the `asof` block, and rerun
/// it while a disconnect lands under it. For a caller that may block its
/// thread: the waits for a mutation in flight sleep.
pub fn run_pinned<T>(
    chain: &ChainState,
    asof: Option<BlockHash>,
    mut read: impl FnMut(&Pin) -> T,
) -> Pinned<T> {
    for _ in 0..VIEW_ATTEMPTS {
        let Some(view) = settled_view(chain) else {
            return Pinned::Moved;
        };
        let pin = match asof {
            Some(hash) => match asof_pin(chain, &view, hash) {
                Some(pin) => pin,
                None => return Pinned::NotOnChain,
            },
            None => Pin::at_tip(&view),
        };
        let answer = read(&pin);
        match settled_change(chain, &view) {
            Some(ViewChange::Unchanged | ViewChange::Extended) => {
                return Pinned::Answered(answer, pin);
            }
            Some(ViewChange::Retreated) => continue,
            Some(ViewChange::InFlight) | None => return Pinned::Moved,
        }
    }
    Pinned::Moved
}

/// A view of a settled chainstate, waiting out a mutation already in flight.
/// `None` when one stays in flight past [`VIEW_WAIT`].
fn settled_view(chain: &ChainState) -> Option<ChainView> {
    let deadline = Instant::now() + VIEW_WAIT;
    loop {
        if let Some(view) = chain.begin_view() {
            return Some(view);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// How the chain changed since `view`, waiting out a mutation in flight: a
/// mutation that has committed but not yet finished may be a disconnect.
/// `None` when one stays in flight past [`VIEW_WAIT`].
fn settled_change(chain: &ChainState, view: &ChainView) -> Option<ViewChange> {
    let deadline = Instant::now() + VIEW_WAIT;
    loop {
        let change = chain.view_change(view);
        if change != ViewChange::InFlight {
            return Some(change);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::chain::state::tests::{build_test_block, make_chain_state};

    fn extend(chain: &ChainState, time: u32) -> BlockHash {
        let (tip, height) = chain.tip_snapshot();
        let block = build_test_block(tip, height + 1, time);
        chain.accept_block(&block).unwrap();
        block.block_hash()
    }

    /// Blocks connected while the read runs leave it pinned to the tip it
    /// started at: one run, answered for that tip.
    #[test]
    fn an_extension_mid_read_leaves_the_answer_pinned() {
        let (cs, dir) = make_chain_state();
        let one = extend(&cs, 1_708_000_600);
        let runs = Cell::new(0);
        let got = run_pinned(&cs, None, |pin| {
            runs.set(runs.get() + 1);
            extend(&cs, 1_708_001_200);
            *pin
        });
        let want = Pin { hash: one, height: 1, mempool: true };
        assert_eq!(got, Pinned::Answered(want, want));
        assert_eq!(runs.get(), 1, "an extension does not rerun");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A disconnect while the read runs discards the answer and reruns the
    /// read at the new tip.
    #[test]
    fn a_disconnect_mid_read_reruns_it_at_the_new_tip() {
        let (cs, dir) = make_chain_state();
        let one = extend(&cs, 1_708_000_600);
        let two = extend(&cs, 1_708_001_200);
        let runs = Cell::new(0);
        let got = run_pinned(&cs, None, |pin| {
            runs.set(runs.get() + 1);
            if runs.get() == 1 {
                cs.invalidate_block(two).unwrap();
            }
            pin.hash
        });
        let want = Pin { hash: one, height: 1, mempool: true };
        assert_eq!(got, Pinned::Answered(one, want));
        assert_eq!(runs.get(), 2, "the first run was discarded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A chain that retreats under every run is refused once the attempts
    /// run out.
    #[test]
    fn a_chain_retreating_under_every_run_is_refused() {
        let (cs, dir) = make_chain_state();
        let mut time = 1_708_000_600;
        for _ in 0..VIEW_ATTEMPTS + 1 {
            extend(&cs, time);
            time += 600;
        }
        let runs = Cell::new(0);
        let got = run_pinned(&cs, None, |_| {
            runs.set(runs.get() + 1);
            cs.invalidate_block(cs.tip_hash()).unwrap();
        });
        assert_eq!(got, Pinned::Moved);
        assert_eq!(runs.get(), VIEW_ATTEMPTS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An `asof` block on the best chain pins the read without the mempool;
    /// one that is not on it, or leaves it, is refused with no retry.
    #[test]
    fn asof_pins_a_best_chain_block_and_refuses_any_other() {
        let (cs, dir) = make_chain_state();
        let one = extend(&cs, 1_708_000_600);
        let two = extend(&cs, 1_708_001_200);
        let got = run_pinned(&cs, Some(one), |pin| *pin);
        let want = Pin { hash: one, height: 1, mempool: false };
        assert_eq!(got, Pinned::Answered(want, want));

        let unknown = build_test_block(two, 3, 1_708_001_800).block_hash();
        assert_eq!(run_pinned(&cs, Some(unknown), |_| ()), Pinned::NotOnChain);

        let runs = Cell::new(0);
        let got = run_pinned(&cs, Some(two), |_| {
            runs.set(runs.get() + 1);
            cs.invalidate_block(two).unwrap();
        });
        assert_eq!(got, Pinned::NotOnChain, "a disconnected asof block is not retried");
        assert_eq!(runs.get(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
