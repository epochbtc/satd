//! Reconnect, replay, and lag-recovery layer over [`StreamClient::subscribe`].
//!
//! A raw [`EventStream`](crate::EventStream) stops at the first transport error
//! or server close, and a [`Lagged`](crate::Event::Lagged) notice leaves it to
//! the consumer to reconnect with the resume cursor. [`ResilientSubscription`]
//! wraps the firehose so the consumer just calls [`next`](ResilientSubscription::next)
//! in a loop and the SDK handles:
//!
//! - **Reconnect with backoff** — transport errors and server-side closes
//!   trigger an exponential-backoff reconnect from the last persisted cursor.
//! - **Cursor persistence** — confirmed-side cursors are written to a
//!   [`CursorStore`] so a resume survives both reconnects and process restarts.
//! - **Lag recovery** — a `Lagged` notice is, by default
//!   ([`LagPolicy::AutoResume`]), transparently turned into a reconnect from the
//!   notice's `resume_cursor`; [`LagPolicy::Surface`] hands it to the caller.
//! - **Replay-truncation detection** — the server clamps a far-behind cursor's
//!   replay to the most recent `MAX_REPLAY_BLOCKS` (10,000) blocks. When the
//!   first replayed confirmed height jumps past `cursor.height + 1`, a synthetic
//!   [`Event::ReplayGap`](crate::Event::ReplayGap) is emitted before the block so
//!   the consumer can full-resync the skipped range from another source.
//! - **`instance_id` handling** — the full cursor (including `instance_id`) is
//!   replayed verbatim; the server discards a stale `mempool_seq` on an
//!   instance mismatch (daemon restart) while confirmed replay is unaffected.

use std::sync::Arc;
use std::time::Duration;

use crate::client::{StreamClient, SubscribeOptions};
use crate::error::StreamError;
use crate::event::{Cursor, Event};

/// Persists the durable resume [`Cursor`] across reconnects and process
/// restarts. The resilience loop loads it on (re)connect and saves it as
/// confirmed events advance.
///
/// Implementations must be cheap to call and may be invoked once per confirmed
/// event; back them with interior mutability (the methods take `&self`). A
/// failing `save` is surfaced to the caller of
/// [`next`](ResilientSubscription::next) rather than silently swallowed — a
/// store that cannot persist would otherwise replay from a stale anchor after a
/// crash.
pub trait CursorStore: Send + Sync {
    /// Load the last persisted cursor, or `None` if none has been saved.
    fn load(&self) -> Result<Option<Cursor>, StreamError>;
    /// Persist `cursor` as the new resume anchor.
    fn save(&self, cursor: Cursor) -> Result<(), StreamError>;
}

/// A [`CursorStore`] that persists nothing: `load` is always `None`, `save` is a
/// no-op. The default — reconnects still resume from the in-memory last cursor,
/// but a process restart starts forward-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCursorStore;

impl CursorStore for NoopCursorStore {
    fn load(&self) -> Result<Option<Cursor>, StreamError> {
        Ok(None)
    }
    fn save(&self, _cursor: Cursor) -> Result<(), StreamError> {
        Ok(())
    }
}

/// A [`CursorStore`] backed by a single file, written atomically (temp file +
/// rename) so a crash mid-write never leaves a torn cursor. The on-disk format
/// is one line of four whitespace-separated integers —
/// `height tx_index mempool_seq instance_id` — stable and trivially
/// inspectable. A missing file loads as `None`.
#[derive(Debug, Clone)]
pub struct FileCursorStore {
    path: std::path::PathBuf,
}

impl FileCursorStore {
    /// Back the store with `path`. The file is created on the first `save`; a
    /// missing file is a clean "no cursor yet".
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        FileCursorStore { path: path.into() }
    }
}

impl CursorStore for FileCursorStore {
    fn load(&self) -> Result<Option<Cursor>, StreamError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StreamError::Decode(format!("cursor store read: {e}"))),
        };
        parse_cursor_line(&text)
            .map(Some)
            .map_err(StreamError::Decode)
    }

    fn save(&self, cursor: Cursor) -> Result<(), StreamError> {
        let line = format!(
            "{} {} {} {}\n",
            cursor.height, cursor.tx_index, cursor.mempool_seq, cursor.instance_id
        );
        // Write to a sibling temp file then rename: rename is atomic on the same
        // filesystem, so a reader never observes a partial line.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, line.as_bytes())
            .map_err(|e| StreamError::Decode(format!("cursor store write: {e}")))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| StreamError::Decode(format!("cursor store rename: {e}")))?;
        Ok(())
    }
}

/// Parse the four-integer cursor line written by [`FileCursorStore`].
fn parse_cursor_line(text: &str) -> Result<Cursor, String> {
    let mut it = text.split_whitespace();
    let mut next_u64 = |field: &str| -> Result<u64, String> {
        it.next()
            .ok_or_else(|| format!("cursor store: missing {field}"))?
            .parse::<u64>()
            .map_err(|e| format!("cursor store: bad {field}: {e}"))
    };
    let height = next_u64("height")? as u32;
    let tx_index = next_u64("tx_index")? as u32;
    let mempool_seq = next_u64("mempool_seq")?;
    let instance_id = next_u64("instance_id")?;
    Ok(Cursor { height, tx_index, mempool_seq, instance_id })
}

/// What the resilience loop does with a [`Lagged`](crate::Event::Lagged) notice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LagPolicy {
    /// Transparently reconnect from the notice's `resume_cursor` and rejoin
    /// live; the `Lagged` event is not surfaced. The default.
    #[default]
    AutoResume,
    /// Hand the `Lagged` event to the caller unchanged; the caller decides
    /// whether to keep consuming or to re-anchor. The loop keeps running on the
    /// same connection afterward.
    Surface,
}

/// Exponential reconnect backoff. Delays grow `initial * multiplier^attempt`,
/// capped at `max`. No jitter is applied (a single client reconnecting to a
/// single node needs none); add it externally if fanning many clients at one
/// server.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// Delay before the first retry.
    pub initial: Duration,
    /// Upper bound on any single delay.
    pub max: Duration,
    /// Per-attempt growth factor.
    pub multiplier: f64,
    /// Give up after this many consecutive failed reconnects, surfacing the last
    /// error from [`next`](ResilientSubscription::next). `None` retries forever.
    pub max_retries: Option<u32>,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
            multiplier: 2.0,
            max_retries: None,
        }
    }
}

impl Backoff {
    /// Delay before retry `attempt` (0-based: `attempt = 0` is the first retry).
    pub fn delay_for(&self, attempt: u32) -> Duration {
        // Compute in f64 then clamp; saturate rather than overflow on a large
        // attempt count. Clamp the exponent before the `as i32` cast: a raw
        // `u32::MAX as i32` wraps to -1 (which would *shrink* the delay), and 64
        // doublings already dwarf any sane `max` so the result clamps anyway.
        let exp = attempt.min(64) as i32;
        let scaled = self.initial.as_secs_f64() * self.multiplier.powi(exp);
        let capped = scaled.min(self.max.as_secs_f64());
        if capped.is_finite() && capped >= 0.0 {
            Duration::from_secs_f64(capped).min(self.max)
        } else {
            self.max
        }
    }
}

/// Bundles the resilience knobs for [`StreamClient::resilient_subscribe`].
pub struct ResilientConfig {
    /// Reconnect backoff schedule.
    pub backoff: Backoff,
    /// What to do with `Lagged` notices.
    pub lag_policy: LagPolicy,
    /// Where the resume cursor is persisted.
    pub cursor_store: Arc<dyn CursorStore>,
}

impl Default for ResilientConfig {
    fn default() -> Self {
        ResilientConfig {
            backoff: Backoff::default(),
            lag_policy: LagPolicy::AutoResume,
            cursor_store: Arc::new(NoopCursorStore),
        }
    }
}

impl std::fmt::Debug for ResilientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResilientConfig")
            .field("backoff", &self.backoff)
            .field("lag_policy", &self.lag_policy)
            .field("cursor_store", &"<dyn CursorStore>")
            .finish()
    }
}

impl ResilientConfig {
    /// Start from the defaults (forever-retry backoff, [`LagPolicy::AutoResume`],
    /// no persistence).
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist the resume cursor through `store`.
    pub fn cursor_store(mut self, store: Arc<dyn CursorStore>) -> Self {
        self.cursor_store = store;
        self
    }

    /// Override the reconnect backoff.
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Override the lag policy.
    pub fn lag_policy(mut self, policy: LagPolicy) -> Self {
        self.lag_policy = policy;
        self
    }
}

/// A firehose that reconnects, replays from a persisted cursor, and recovers
/// from lag on the consumer's behalf. Construct it with
/// [`StreamClient::resilient_subscribe`] and drive it by calling
/// [`next`](Self::next) in a loop.
///
/// The first [`next`](Self::next) connects lazily. Each subsequent call yields
/// the next [`Event`], reconnecting underneath as needed; it only returns `Err`
/// when reconnect retries are exhausted (see [`Backoff::max_retries`]) or a
/// non-retryable error occurs (bad endpoint/token, `PERMISSION_DENIED`, a
/// failed cursor `save`).
pub struct ResilientSubscription {
    client: StreamClient,
    base: SubscribeOptions,
    config: ResilientConfig,
    stream: Option<crate::client::EventStream>,
    /// Resume anchor for the next (re)connect: the most recent confirmed cursor,
    /// seeded from the store / base options.
    resume: Option<Cursor>,
    /// `cursor.height + 1` captured at the last (re)connect — the height the
    /// first replayed confirmed event should carry if the replay was not
    /// clamped. `None` once the first confirmed event after a resume has been
    /// checked (live blocks are contiguous; we only test the replay seam).
    expect_first_height: Option<u32>,
    /// An event held back so a synthetic [`Event::ReplayGap`] can be delivered
    /// ahead of the block that triggered it.
    pending: Option<Event>,
}

impl ResilientSubscription {
    pub(crate) fn new(
        client: StreamClient,
        base: SubscribeOptions,
        config: ResilientConfig,
    ) -> Self {
        ResilientSubscription {
            client,
            base,
            config,
            stream: None,
            resume: None,
            expect_first_height: None,
            pending: None,
        }
    }

    /// The resume cursor that the next reconnect would use. Updated as confirmed
    /// events advance; useful for diagnostics or an external checkpoint.
    pub fn resume_cursor(&self) -> Option<&Cursor> {
        self.resume.as_ref()
    }

    /// Yield the next event, reconnecting and replaying underneath as needed.
    ///
    /// Loops internally: a transient failure becomes a backoff + reconnect, an
    /// auto-resumed `Lagged` becomes a re-anchor, and only a real event (or a
    /// surfaced `Lagged`, or a synthetic `ReplayGap`) returns to the caller.
    pub async fn next(&mut self) -> Result<Event, StreamError> {
        if let Some(ev) = self.pending.take() {
            return Ok(ev);
        }
        loop {
            if self.stream.is_none() {
                self.connect().await?;
            }
            // `connect` guarantees `self.stream` is `Some`.
            let stream = self.stream.as_mut().expect("connected");
            match stream.message().await {
                Ok(Some(ev)) => {
                    if let Some(out) = self.handle_event(ev).await? {
                        return Ok(out);
                    }
                    // Event consumed internally (auto-resumed lag): loop.
                }
                Ok(None) => {
                    // Server closed the stream cleanly; reconnect from resume.
                    self.stream = None;
                }
                Err(e) if e.is_retryable() => {
                    self.stream = None;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Process one inbound event. Returns `Ok(Some(ev))` to hand to the caller,
    /// `Ok(None)` if it was handled internally (auto-resume), or an error to
    /// propagate (a failed cursor `save`).
    async fn handle_event(&mut self, ev: Event) -> Result<Option<Event>, StreamError> {
        // Capture and persist the advancing confirmed cursor.
        if let Some(stream) = self.stream.as_ref()
            && let Some(c) = stream.cursor()
            && self.resume.as_ref() != Some(c)
        {
            let c = *c;
            self.resume = Some(c);
            self.config.cursor_store.save(c)?;
        }

        // Replay-truncation check: only on the first confirmed-height event after
        // a resume. A `BlockConnected` whose height exceeds the expected next
        // height means the server clamped the replay window.
        if let Some(expect) = self.expect_first_height
            && let Event::BlockConnected { height, .. } = ev
        {
            self.expect_first_height = None;
            if height > expect {
                // Hand back the gap notice now; deliver the block next call.
                self.pending = Some(ev);
                return Ok(Some(Event::ReplayGap {
                    resume_height: expect,
                    first_height: height,
                }));
            }
        }

        match ev {
            Event::Lagged { resume_cursor, .. } if self.config.lag_policy == LagPolicy::AutoResume => {
                // Re-anchor from the notice's cursor (if any), then reconnect.
                if let Some(c) = resume_cursor {
                    self.resume = Some(c);
                    self.config.cursor_store.save(c)?;
                }
                self.stream = None;
                Ok(None)
            }
            other => Ok(Some(other)),
        }
    }

    /// (Re)connect with backoff, replaying from the resume cursor.
    async fn connect(&mut self) -> Result<(), StreamError> {
        // Effective resume = in-memory anchor, else the persisted one, else the
        // caller's base `from_cursor`.
        if self.resume.is_none() {
            self.resume = self.config.cursor_store.load()?.or(self.base.from_cursor);
        }

        let mut attempt: u32 = 0;
        loop {
            let mut opts = self.base.clone();
            opts.from_cursor = self.resume;
            match self.client.subscribe(opts).await {
                Ok(stream) => {
                    self.stream = Some(stream);
                    // Arm the truncation check for the first confirmed event of
                    // this resume (only when we actually asked to replay).
                    self.expect_first_height =
                        self.resume.map(|c| c.height.saturating_add(1));
                    return Ok(());
                }
                Err(e) if e.is_retryable() => {
                    if let Some(max) = self.config.backoff.max_retries
                        && attempt >= max
                    {
                        return Err(e);
                    }
                    tokio::time::sleep(self.config.backoff.delay_for(attempt)).await;
                    attempt = attempt.saturating_add(1);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn backoff_grows_then_caps() {
        let b = Backoff {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
            multiplier: 2.0,
            max_retries: None,
        };
        assert_eq!(b.delay_for(0), Duration::from_millis(500));
        assert_eq!(b.delay_for(1), Duration::from_secs(1));
        assert_eq!(b.delay_for(2), Duration::from_secs(2));
        // 500ms * 2^10 = 512s, clamped to the 30s ceiling.
        assert_eq!(b.delay_for(10), Duration::from_secs(30));
        // A huge attempt count saturates to the cap rather than overflowing.
        assert_eq!(b.delay_for(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn defaults_are_autoresume_and_noop() {
        let cfg = ResilientConfig::default();
        assert_eq!(cfg.lag_policy, LagPolicy::AutoResume);
        assert!(cfg.cursor_store.load().unwrap().is_none());
        assert_eq!(LagPolicy::default(), LagPolicy::AutoResume);
    }

    #[test]
    fn noop_store_roundtrips_to_none() {
        let s = NoopCursorStore;
        s.save(Cursor { height: 9, tx_index: 1, mempool_seq: 2, instance_id: 3 })
            .unwrap();
        assert!(s.load().unwrap().is_none());
    }

    #[test]
    fn file_store_roundtrips_and_missing_is_none() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("satd-sdk-cursor-test-{}.cur", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = FileCursorStore::new(&path);

        // Missing file loads cleanly as None.
        assert!(store.load().unwrap().is_none());

        let c = Cursor { height: 951_577, tx_index: 4, mempool_seq: 1234, instance_id: 99 };
        store.save(c).unwrap();
        let got = store.load().unwrap().expect("cursor present after save");
        assert_eq!(got, c);

        // Overwrite is atomic and reflects the latest.
        let c2 = Cursor { height: 951_578, tx_index: 0, mempool_seq: 5, instance_id: 99 };
        store.save(c2).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), c2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[test]
    fn file_store_rejects_garbage() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("satd-sdk-cursor-bad-{}.cur", std::process::id()));
        std::fs::write(&path, b"not a cursor").unwrap();
        let store = FileCursorStore::new(&path);
        assert!(matches!(store.load(), Err(StreamError::Decode(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_cursor_line_exact() {
        let c = parse_cursor_line("951577 4 1234 99\n").unwrap();
        assert_eq!(c, Cursor { height: 951_577, tx_index: 4, mempool_seq: 1234, instance_id: 99 });
        assert!(parse_cursor_line("1 2 3").is_err()); // missing field
    }

    /// A store we can assert against from tests.
    #[derive(Default)]
    struct MemStore(Mutex<Option<Cursor>>);
    impl CursorStore for MemStore {
        fn load(&self) -> Result<Option<Cursor>, StreamError> {
            Ok(*self.0.lock().unwrap())
        }
        fn save(&self, cursor: Cursor) -> Result<(), StreamError> {
            *self.0.lock().unwrap() = Some(cursor);
            Ok(())
        }
    }

    #[test]
    fn mem_store_observes_saves() {
        let s = MemStore::default();
        assert!(s.load().unwrap().is_none());
        let c = Cursor { height: 1, tx_index: 0, mempool_seq: 0, instance_id: 7 };
        s.save(c).unwrap();
        assert_eq!(s.load().unwrap(), Some(c));
    }
}
