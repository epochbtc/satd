//! An order-keeping parallel map for the NAP's set-wide work: reports,
//! snapshots and replays, whose items are independent. It runs on scoped
//! threads of its own, not rayon's global pool, which block connection
//! uses.

/// The most threads one map uses, so a report or a replay leaves cores to
/// the rest of the node.
const MAX_THREADS: usize = 8;
/// The fewest items worth a thread of their own: below this the map runs
/// on the caller's thread.
const MIN_PER_THREAD: usize = 1_024;

#[cfg(test)]
thread_local! {
    /// Tests run a map over this many threads whatever its size.
    static THREADS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// `items.iter().map(f).collect()`, in the same order, the items split
/// between threads. A thread the system will not start runs its share on
/// the caller's thread; a panic in `f` is raised again here.
pub(super) fn map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = threads_for(items.len());
    if threads <= 1 || items.is_empty() {
        return items.iter().map(f).collect();
    }
    let f = &f;
    std::thread::scope(|s| {
        let shares: Vec<_> = items
            .chunks(items.len().div_ceil(threads))
            .map(|share| {
                std::thread::Builder::new()
                    .name("nap-par".into())
                    .spawn_scoped(s, move || share.iter().map(f).collect::<Vec<R>>())
                    .map_err(|_| share)
            })
            .collect();
        let mut out = Vec::with_capacity(items.len());
        for share in shares {
            match share {
                Ok(handle) => out.extend(handle.join().unwrap_or_else(|p| std::panic::resume_unwind(p))),
                Err(share) => out.extend(share.iter().map(f)),
            }
        }
        out
    })
}

fn threads_for(items: usize) -> usize {
    #[cfg(test)]
    if let Some(n) = THREADS.with(std::cell::Cell::get) {
        return n;
    }
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    cores.min(MAX_THREADS).min(items / MIN_PER_THREAD).max(1)
}

/// Run `f` with maps on this thread over `n` threads, whatever their size.
#[cfg(test)]
pub(super) fn with_threads<R>(n: usize, f: impl FnOnce() -> R) -> R {
    let before = THREADS.with(|t| t.replace(Some(n)));
    let out = f();
    THREADS.with(|t| t.set(before));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Perturbation: join the shares in reverse and this fails.
    #[test]
    fn a_map_keeps_the_order_of_its_items() {
        let items: Vec<u32> = (0..10_000).collect();
        for n in [1, 2, 3, 7, 64] {
            assert_eq!(with_threads(n, || map(&items, |x| x * 2)), items.iter().map(|x| x * 2).collect::<Vec<_>>(), "{n}");
        }
        assert!(with_threads(4, || map(&[] as &[u32], |x| *x)).is_empty());
    }

    #[test]
    fn a_large_map_uses_more_than_one_thread() {
        let items: Vec<u32> = (0..(MIN_PER_THREAD * 4) as u32).collect();
        let names = map(&items, |_| std::thread::current().name().map(str::to_owned));
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if cores > 1 {
            assert!(names.iter().all(|n| n.as_deref() == Some("nap-par")), "every share on a thread of its own");
        }
        let small = map(&items[..MIN_PER_THREAD], |_| std::thread::current().id());
        assert!(small.iter().all(|id| *id == std::thread::current().id()), "a small map stays on the caller's thread");
    }

    #[test]
    #[should_panic(expected = "item 5000")]
    fn a_panic_in_a_share_is_raised_to_the_caller() {
        let items: Vec<u32> = (0..10_000).collect();
        with_threads(4, || map(&items, |x| assert_ne!(*x, 5_000, "item {x}")));
    }
}
