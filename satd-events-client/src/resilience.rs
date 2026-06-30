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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::client::{StreamClient, SubscribeOptions};
use crate::error::StreamError;
use crate::event::{Cursor, Event};

/// Persists the durable resume [`Cursor`] across reconnects and process
/// restarts. The resilience loop loads it on (re)connect and persists it
/// **commit-on-poll**: a delivered event's cursor is written only on the *next*
/// [`next`](ResilientSubscription::next) call, i.e. once the caller has come
/// back for the following event (an implicit ack). The store therefore never
/// advances past an event the caller has not yet received, so a crash
/// mid-processing replays that event on resume — at-least-once, not at-most-once.
/// (A consumer that needs exactly-once still dedups on its own side keyed by the
/// `(height, hash)` it processes.)
///
/// Implementations must be cheap to call and may be invoked roughly once per
/// delivered confirmed cursor (redundant writes for unchanged cursors are
/// elided by the loop); back them with interior mutability (the methods take
/// `&self`). A failing `save` is surfaced to the caller of
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
        // Write to a *unique* sibling temp file then rename: rename is atomic on
        // the same filesystem, so a reader never observes a partial line. The
        // temp name is qualified by pid + a process-local counter so two writers
        // sharing one cursor path (two subscriptions, or two processes) cannot
        // clobber each other's in-flight temp and rename a foreign/partial file.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .path
            .with_extension(format!("tmp.{}.{n}", std::process::id()));
        let res = std::fs::write(&tmp, line.as_bytes())
            .map_err(|e| StreamError::Decode(format!("cursor store write: {e}")))
            .and_then(|()| {
                std::fs::rename(&tmp, &self.path)
                    .map_err(|e| StreamError::Decode(format!("cursor store rename: {e}")))
            });
        if res.is_err() {
            // Best-effort cleanup of the temp on a failed rename.
            let _ = std::fs::remove_file(&tmp);
        }
        res
    }
}

/// Parse the four-integer cursor line written by [`FileCursorStore`]. Each field
/// is parsed at its real width — `height`/`tx_index` as `u32`, not `u64`-then-
/// truncate — so a corrupt out-of-range value is a clean `Decode` error rather
/// than a silently truncated cursor that resumes from the wrong height.
fn parse_cursor_line(text: &str) -> Result<Cursor, String> {
    let mut it = text.split_whitespace();
    let mut next_field = |field: &str| -> Result<&str, String> {
        it.next().ok_or_else(|| format!("cursor store: missing {field}"))
    };
    let parse = |s: &str, field: &str| -> Result<u64, String> {
        s.parse::<u64>().map_err(|e| format!("cursor store: bad {field}: {e}"))
    };
    let parse32 = |s: &str, field: &str| -> Result<u32, String> {
        s.parse::<u32>().map_err(|e| format!("cursor store: bad {field}: {e}"))
    };
    let height = parse32(next_field("height")?, "height")?;
    let tx_index = parse32(next_field("tx_index")?, "tx_index")?;
    let mempool_seq = parse(next_field("mempool_seq")?, "mempool_seq")?;
    let instance_id = parse(next_field("instance_id")?, "instance_id")?;
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
    /// Give up after this many *consecutive* reconnect attempts produce no event,
    /// surfacing the last error from [`next`](ResilientSubscription::next). The
    /// initial connect is not counted; a connection that delivers any event
    /// resets the count. `None` retries forever.
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
    /// ahead of the block that triggered it, paired with that block's cursor
    /// (applied to the high-water only when the block is actually delivered, so
    /// the commit never runs ahead of delivery).
    pending: Option<(Event, Option<Cursor>)>,
    /// The high-water cursor of the most recently *delivered* event, to be
    /// persisted on the next [`next`](Self::next) call. Commit-on-poll: the
    /// caller returning for the next event is its ack of the previous one, so the
    /// store never advances past an event the caller has not yet had in hand —
    /// giving at-least-once delivery across a crash rather than at-most-once.
    commit_next: Option<Cursor>,
    /// The cursor last written to the store, to skip redundant writes (e.g. a run
    /// of mempool events that do not move the confirmed high-water).
    committed: Option<Cursor>,
    /// Count of consecutive reconnects that have produced **no** event yet. Reset
    /// to 0 the moment a connection delivers any event ("made progress"), and
    /// incremented every time a connection fails to establish or ends without
    /// progress. Drives both the backoff delay and the `max_retries` give-up
    /// bound, so a server that accepts a subscribe and then immediately closes it
    /// cannot induce a no-delay reconnect storm.
    reconnect_attempts: u32,
    /// The most recent retryable error, surfaced if `max_retries` is exhausted.
    last_error: Option<StreamError>,
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
            commit_next: None,
            committed: None,
            reconnect_attempts: 0,
            last_error: None,
        }
    }

    /// The resume cursor that the next reconnect would use. Updated as confirmed
    /// events advance; useful for diagnostics or an external checkpoint.
    pub fn resume_cursor(&self) -> Option<&Cursor> {
        self.resume.as_ref()
    }

    /// Persist the most-recently-delivered event's cursor now, rather than
    /// waiting for the implicit ack on the next [`next`](Self::next). Call this
    /// before a clean shutdown so the last event the caller durably processed is
    /// not replayed on the next start. Idempotent — a no-op when nothing new is
    /// armed or the store already holds the armed cursor. A failing store `save`
    /// is surfaced.
    pub fn commit(&mut self) -> Result<(), StreamError> {
        self.commit_due()
    }

    /// Commit-on-poll flush: persist the armed high-water cursor (the previously
    /// delivered event's) if it differs from what the store already holds. The
    /// single point on the delivery path where the store advances, called at the
    /// top of every [`next`](Self::next) (and by [`commit`](Self::commit)); it
    /// therefore can never run ahead of an event the caller has received.
    fn commit_due(&mut self) -> Result<(), StreamError> {
        if let Some(c) = self.commit_next.take()
            && self.committed != Some(c)
        {
            self.config.cursor_store.save(c)?;
            self.committed = Some(c);
        }
        Ok(())
    }

    /// Deliver a block stashed behind a synthetic [`Event::ReplayGap`]: advance
    /// the high-water to the block's cursor and arm *that* cursor for commit on
    /// the following poll (never before — the gap notice itself committed only
    /// the pre-gap anchor). Returns the stashed event, or `None` if none is held.
    fn take_pending(&mut self) -> Option<Event> {
        let (ev, cur) = self.pending.take()?;
        if let Some(c) = cur {
            self.resume = Some(c);
        }
        self.arm_commit();
        Some(ev)
    }

    /// Arm the just-delivered event's high-water cursor for commit on the next
    /// poll (commit-on-poll). The `ReplayGap` path leaves `resume` unchanged and
    /// stashes the triggering block, so calling this after a gap notice arms only
    /// the pre-gap anchor; the block's own cursor is armed when it is delivered.
    fn arm_commit(&mut self) {
        self.commit_next = self.resume;
    }

    /// Yield the next event, reconnecting and replaying underneath as needed.
    ///
    /// Loops internally: a transient failure becomes a backoff + reconnect, an
    /// auto-resumed `Lagged` becomes a re-anchor, and only a real event (or a
    /// surfaced `Lagged`, or a synthetic `ReplayGap`) returns to the caller.
    ///
    /// Backoff is applied before **every** reconnect that follows a connection
    /// which produced no event — whether it failed to establish, closed cleanly,
    /// or errored — not only the subscribe-error path. A connection that delivers
    /// an event resets the counter, so a healthy stream that occasionally drops
    /// reconnects promptly while a flapping server is backed off and eventually
    /// bounded by `max_retries`.
    pub async fn next(&mut self) -> Result<Event, StreamError> {
        // Commit-on-poll: persist the previously-delivered event's high-water
        // cursor now that the caller has come back for the next one (an implicit
        // ack). A crash mid-processing leaves the store at the prior event, which
        // the server replays on resume — at-least-once, not at-most-once.
        self.commit_due()?;
        // A block stashed behind a synthetic `ReplayGap` is delivered first.
        if let Some(ev) = self.take_pending() {
            return Ok(ev);
        }
        loop {
            if self.stream.is_none() {
                // Back off before reconnecting if the previous connection made no
                // progress (failed to establish, or established and immediately
                // ended). The first connect (`reconnect_attempts == 0`) is
                // immediate.
                if self.reconnect_attempts > 0 {
                    if let Some(max) = self.config.backoff.max_retries
                        && self.reconnect_attempts > max
                    {
                        return Err(self
                            .last_error
                            .take()
                            .unwrap_or(StreamError::ControlClosed));
                    }
                    let delay = self.config.backoff.delay_for(self.reconnect_attempts - 1);
                    tokio::time::sleep(delay).await;
                }
                match self.connect_once().await {
                    Ok(()) => {}
                    Err(e) if e.is_retryable() => {
                        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                        self.last_error = Some(e);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            // `connect_once` guarantees `self.stream` is `Some`.
            let stream = self.stream.as_mut().expect("connected");
            match stream.message().await {
                Ok(Some(ev)) => {
                    // A delivered event is progress: clear the backoff counter so
                    // the next reconnect (if any) starts fresh.
                    self.reconnect_attempts = 0;
                    self.last_error = None;
                    // Capture the cursor this message carries before handling it,
                    // so `handle_event` can decide the gap seam without advancing
                    // the high-water prematurely.
                    let cur = self.stream.as_ref().and_then(|s| s.cursor().copied());
                    if let Some(out) = self.handle_event(ev, cur).await? {
                        // Arm the delivered event's high-water for commit on the
                        // next poll (the ReplayGap path leaves `resume` unchanged
                        // and stashes the block, so its cursor commits only when
                        // the block itself is delivered).
                        self.arm_commit();
                        return Ok(out);
                    }
                    // Event consumed internally (auto-resumed lag): loop.
                }
                Ok(None) => {
                    // Server closed the stream cleanly; reconnect from resume,
                    // backing off since this connection yielded nothing new.
                    self.stream = None;
                    self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                }
                Err(e) if e.is_retryable() => {
                    self.stream = None;
                    self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                    self.last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Process one inbound event, given the cursor (`cur`) the carrying message
    /// advanced the stream to. Returns `Ok(Some(ev))` to hand to the caller,
    /// `Ok(None)` if it was handled internally (auto-resume), or an error to
    /// propagate (a failed cursor `save`).
    ///
    /// The confirmed high-water (`self.resume`) is advanced here but **not**
    /// persisted — persistence is deferred to the next [`next`](Self::next) poll
    /// (commit-on-poll). The gap check runs *before* the advance so a clamped
    /// replay stashes the triggering block without moving the high-water past it.
    async fn handle_event(
        &mut self,
        ev: Event,
        cur: Option<Cursor>,
    ) -> Result<Option<Event>, StreamError> {
        // Replay-truncation check: only on the first confirmed-height event after
        // a resume. A `BlockConnected` whose height exceeds the expected next
        // height means the server clamped the replay window. Stash the block with
        // its cursor and emit the gap notice first — the high-water is advanced to
        // this block only when it is actually delivered (next poll), so the commit
        // never runs ahead of delivery.
        if let Some(expect) = self.expect_first_height
            && let Event::BlockConnected { height, .. } = ev
        {
            self.expect_first_height = None;
            if height > expect {
                self.pending = Some((ev, cur));
                return Ok(Some(Event::ReplayGap {
                    resume_height: expect,
                    first_height: height,
                }));
            }
        }

        // Advance the in-memory high-water (used for live reconnect); not yet
        // persisted.
        if let Some(c) = cur {
            self.resume = Some(c);
        }

        match ev {
            Event::Lagged { resume_cursor, .. } if self.config.lag_policy == LagPolicy::AutoResume => {
                // Re-anchor from the notice's cursor (if any), then reconnect. A
                // lag re-anchor is a recovery point the server handed us, not
                // caller-delivered data, so persist it immediately (and supersede
                // any deferred commit) — a crash then resumes from the same place
                // the live re-anchor would.
                if let Some(c) = resume_cursor {
                    self.resume = Some(c);
                    self.config.cursor_store.save(c)?;
                    self.committed = Some(c);
                    self.commit_next = None;
                }
                self.stream = None;
                Ok(None)
            }
            // Deterministic re-anchor acks (#441) are a `Watch`-only signal — a
            // `set_cursor` is never sent on the `Subscribe` firehose this layer
            // wraps, so they cannot arrive here today. Match them explicitly so a
            // future carrier that did surface them could not have them mistaken
            // for confirmed data: they carry no durable cursor, so the high-water
            // (advanced above only from a message's own cursor) is untouched, and
            // they pass straight through to the caller.
            e @ (Event::CursorAccepted { .. } | Event::CursorRejected { .. }) => Ok(Some(e)),
            other => Ok(Some(other)),
        }
    }

    /// Establish the resume anchor on the first connect (no I/O): effective
    /// `resume` = in-memory anchor, else the persisted cursor, else the caller's
    /// base `from_cursor`. A cursor read back from the store is by definition
    /// already durably committed, so it also seeds `committed` — that way the
    /// commit-on-poll write-elision recognizes it and the first post-restart
    /// commit of an unchanged anchor is a no-op, not a redundant write.
    fn seed_resume(&mut self) -> Result<(), StreamError> {
        if self.resume.is_none() {
            let loaded = self.config.cursor_store.load()?;
            if let Some(c) = loaded {
                self.committed.get_or_insert(c);
            }
            self.resume = loaded.or(self.base.from_cursor);
        }
        Ok(())
    }

    /// Open a single subscription, replaying from the resume cursor. Backoff and
    /// retry accounting live in [`next`](Self::next); this performs exactly one
    /// `subscribe` attempt and returns its result (a retryable `Err` is the
    /// signal for `next` to back off and try again).
    async fn connect_once(&mut self) -> Result<(), StreamError> {
        self.seed_resume()?;
        let mut opts = self.base.clone();
        opts.from_cursor = self.resume;
        let stream = self.client.subscribe(opts).await?;
        self.stream = Some(stream);
        // Arm the truncation check for the first confirmed event of this resume
        // (only when we actually asked to replay).
        //
        // Detection depends on the server replaying confirmed history as
        // `BlockConnected` events in height order ahead of the live tail — see
        // `build_cursor_replay` in `node/src/events/replay.rs`, which synthesizes
        // only `BlockConnected` for the confirmed span. The check below therefore
        // matches `BlockConnected`; if a future carrier reordered replay this
        // would need to key on the first confirmed-cursor-bearing event instead.
        self.expect_first_height = self.resume.map(|c| c.height.saturating_add(1));
        Ok(())
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

    #[test]
    fn parse_cursor_line_rejects_out_of_range_height() {
        // A corrupt height beyond u32::MAX must be a clean error, not a silent
        // truncation to a wrong (small) height that resumes from the wrong place.
        let too_big = (u32::MAX as u64) + 1; // 4_294_967_296
        assert!(parse_cursor_line(&format!("{too_big} 0 0 0")).is_err());
        // u64-width fields still accept large values.
        let c = parse_cursor_line(&format!("1 0 {too_big} {too_big}")).unwrap();
        assert_eq!(c.mempool_seq, too_big);
        assert_eq!(c.instance_id, too_big);
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

    // --- commit-on-poll semantics ---------------------------------------------
    //
    // `next()` is welded to a live transport, so these drive the same extracted
    // steps it calls (`commit_due` / `take_pending` / `handle_event` /
    // `arm_commit`) in the same order, with the test standing in for the poll
    // loop. They assert the durability contract the commit-on-poll fix
    // introduced: the store advances only on the poll *after* delivery.

    fn sub_with(store: &Arc<MemStore>) -> ResilientSubscription {
        ResilientSubscription::new(
            StreamClient::for_test(),
            SubscribeOptions::default(),
            ResilientConfig::new().cursor_store(store.clone()),
        )
    }

    fn cur(height: u32) -> Cursor {
        Cursor { height, tx_index: 0, mempool_seq: 0, instance_id: 1 }
    }

    #[tokio::test]
    async fn commit_on_poll_defers_store_write_until_next_poll() {
        let store = Arc::new(MemStore::default());
        let mut sub = sub_with(&store);
        let (c100, c101) = (cur(100), cur(101));

        // Poll 1: nothing armed, no stash; deliver block@100.
        sub.commit_due().unwrap();
        assert!(sub.take_pending().is_none());
        let out = sub
            .handle_event(Event::BlockConnected { hash: vec![0xaa], height: 100 }, Some(c100))
            .await
            .unwrap();
        assert!(matches!(out, Some(Event::BlockConnected { height: 100, .. })));
        sub.arm_commit();
        // The caller holds block@100 but has not returned: the store must NOT have
        // advanced — a crash here replays block@100 (at-least-once).
        assert_eq!(store.load().unwrap(), None, "cursor must not commit before the next poll");

        // Poll 2: returning for the next event acks block@100; deliver block@101.
        sub.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(c100), "block@100 committed only on the next poll");
        assert!(sub.take_pending().is_none());
        let out = sub
            .handle_event(Event::BlockConnected { hash: vec![0xbb], height: 101 }, Some(c101))
            .await
            .unwrap();
        assert!(out.is_some());
        sub.arm_commit();
        assert_eq!(store.load().unwrap(), Some(c100), "block@101 still not committed");

        // Poll 3: acks block@101.
        sub.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(c101));
    }

    #[tokio::test]
    async fn explicit_commit_checkpoints_last_delivered_event() {
        let store = Arc::new(MemStore::default());
        let mut sub = sub_with(&store);
        let c = cur(10);
        sub.handle_event(Event::BlockConnected { hash: vec![1], height: 10 }, Some(c))
            .await
            .unwrap();
        sub.arm_commit();
        assert_eq!(store.load().unwrap(), None);
        // A clean shutdown checkpoints the last delivered event so it is not
        // replayed on the next start.
        sub.commit().unwrap();
        assert_eq!(store.load().unwrap(), Some(c));
        // Idempotent: a second commit writes nothing new.
        sub.commit().unwrap();
        assert_eq!(store.load().unwrap(), Some(c));
    }

    #[tokio::test]
    async fn lag_autoresume_persists_immediately_and_supersedes_deferred_commit() {
        let store = Arc::new(MemStore::default());
        let mut sub = sub_with(&store); // AutoResume is the default
        // A prior delivered event has armed a deferred commit.
        let armed = cur(50);
        sub.resume = Some(armed);
        sub.commit_next = Some(armed);

        let recover = cur(75);
        let out = sub
            .handle_event(
                Event::Lagged { dropped_count: 3, resume_cursor: Some(recover) },
                None,
            )
            .await
            .unwrap();
        assert!(out.is_none(), "an auto-resumed lag is consumed internally");
        // The re-anchor is a recovery point, persisted now (not deferred), and it
        // supersedes the armed commit so the deferred write cannot clobber it.
        assert_eq!(store.load().unwrap(), Some(recover), "lag re-anchor persisted immediately");
        assert_eq!(sub.committed, Some(recover));
        assert!(sub.commit_next.is_none(), "deferred commit superseded");
        assert!(sub.stream.is_none(), "stream torn down for reconnect");
    }

    #[tokio::test]
    async fn replay_gap_defers_commit_until_stashed_block_delivered() {
        let store = Arc::new(MemStore::default());
        let mut sub = sub_with(&store);
        // State just after resuming from height 100, with the store already at the
        // pre-gap anchor.
        let pre = cur(100);
        store.save(pre).unwrap();
        sub.resume = Some(pre);
        sub.committed = Some(pre);
        sub.expect_first_height = Some(101);

        // The server clamped replay: first confirmed block jumps to 5000.
        let gap_cur = cur(5000);
        let out = sub
            .handle_event(Event::BlockConnected { hash: vec![0xcc], height: 5000 }, Some(gap_cur))
            .await
            .unwrap();
        // `resume_height` is the height the cursor expected next (`100 + 1`).
        assert!(
            matches!(out, Some(Event::ReplayGap { resume_height: 101, first_height: 5000 })),
            "a clamped replay surfaces a ReplayGap before the block"
        );
        sub.arm_commit(); // next() arms after delivering the gap notice
        assert_eq!(sub.resume, Some(pre), "high-water stays at the pre-gap anchor across the gap");

        // Next poll: commit the pre-gap anchor (not the post-gap block), then
        // deliver the stashed block.
        sub.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(pre), "must not commit past the gap");
        let blk = sub.take_pending().expect("the stashed block is delivered next");
        assert!(matches!(blk, Event::BlockConnected { height: 5000, .. }));
        assert_eq!(sub.resume, Some(gap_cur), "high-water advances to the delivered block");

        // The poll after that acks the post-gap block.
        sub.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(gap_cur));
    }

    #[tokio::test]
    async fn committed_seeded_from_store_on_first_connect() {
        let store = Arc::new(MemStore::default());
        let persisted = cur(900);
        store.save(persisted).unwrap();
        let mut sub = sub_with(&store);
        // The first connect loads the persisted cursor and treats it as already
        // committed, so re-arming the same anchor elides the redundant write.
        sub.seed_resume().unwrap();
        assert_eq!(sub.resume, Some(persisted));
        assert_eq!(sub.committed, Some(persisted), "loaded cursor seeds `committed`");
        // Re-arming the seeded anchor and polling writes nothing new.
        sub.arm_commit();
        sub.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(persisted));
    }
}
