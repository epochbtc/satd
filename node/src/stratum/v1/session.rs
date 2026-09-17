//! One Stratum V1 connection.
//!
//! The expected exchange: `mining.configure` (optional, for version rolling),
//! `mining.subscribe`, `mining.suggest_difficulty` (optional),
//! `mining.authorize`. After a successful authorize the server sends
//! `mining.set_difficulty` and a `mining.notify`, and from then on a new
//! notify whenever the work changes; the miner answers with `mining.submit`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::BlockHash;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, WriteHalf};
use tokio::sync::watch;
use tokio::time::Instant;

use super::{
    EXTRANONCE1_LEN, EXTRANONCE2_LEN, MAX_LINE_BYTES, Request, StratumError, VERSION_ROLLING_MASK,
    error_response, notification, notify_params, parse_difficulty, parse_hex_u32, parse_request,
    response,
};
use crate::stratum::config::{Payout, resolve_payout};
use crate::stratum::job::{Job, JobManager};
use crate::stratum::miner::{self, MinerTally, format_difficulty, format_hashrate};
use crate::stratum::server::{CountGuard, ShareOutcome, Shared, submit_found_block};
use crate::stratum::share::{
    ShareResult, effective_share_target, hash_difficulty, network_difficulty, validate_share,
};
use crate::stratum::template::{ActiveTemplate, Work};
use crate::stratum::vardiff::Vardiff;

/// A connection that sends nothing for this long is dropped.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// A write that cannot complete in this long drops the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often vardiff is reconsidered, independent of share arrival — a
/// miner that has gone quiet must still have its difficulty lowered.
const VARDIFF_TICK: Duration = Duration::from_secs(10);
/// Bound on remembered solutions, in case a tip stays put for a long time.
const MAX_SEEN_SHARES: usize = 100_000;

/// The connection must close.
struct Close;

type SeenKey = (u32, [u8; EXTRANONCE2_LEN], u32, u32, i32);

struct Session<S> {
    peer: SocketAddr,
    shared: Arc<Shared>,
    writer: WriteHalf<S>,
    extranonce1: [u8; EXTRANONCE1_LEN],
    version_mask: u32,
    payout: Option<Payout>,
    vardiff: Vardiff,
    jobs: JobManager,
    /// The previous-block hash of the last job issued. A job on a different
    /// one is a clean job: everything before it is stale.
    job_prev_hash: Option<BlockHash>,
    seen: HashSet<SeenKey>,
    /// Counts this connection as a channel once authorized.
    channel: Option<CountGuard>,
    /// What the miner called itself in `mining.subscribe`, made safe to log.
    user_agent: Option<String>,
    tally: MinerTally,
}

/// A share that was not accepted, with what the log line needs.
struct Refusal {
    error: StratumError,
    reason: &'static str,
    job_id: Option<u32>,
    /// The difficulty the job was issued at, once the job is known.
    difficulty: Option<u64>,
    /// What the header achieved, once it was hashed.
    hash_difficulty: Option<f64>,
}

impl Refusal {
    fn new(error: StratumError, reason: &'static str) -> Self {
        Self { error, reason, job_id: None, difficulty: None, hash_difficulty: None }
    }

    fn on(mut self, job: &Job) -> Self {
        self.job_id = Some(job.template.job_id);
        self.difficulty = Some(job.difficulty);
        self
    }
}

/// Serve one connection until it closes, idles out, or the node shuts down.
pub(crate) async fn run<S>(
    stream: S,
    peer: SocketAddr,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!(target: "node::stratum", %peer, "Stratum connection opened");
    let _connection = shared.stats.connection();
    let (read_half, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut buf = Vec::with_capacity(512);
    let mut work_rx = shared.work.subscribe();
    let config = shared.config.clone();
    let mut session = Session {
        peer,
        extranonce1: shared.next_extranonce1(),
        shared,
        writer,
        version_mask: 0,
        payout: None,
        vardiff: Vardiff::new(config.vardiff.clone(), config.initial_difficulty, std::time::Instant::now()),
        jobs: JobManager::new(),
        job_prev_hash: None,
        seen: HashSet::new(),
        channel: None,
        user_agent: None,
        tally: MinerTally::new(std::time::Instant::now()),
    };
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut vardiff_tick = tokio::time::interval(VARDIFF_TICK);
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut reason = "server closed the connection";
    loop {
        let authorized = session.payout.is_some();
        // New work and the vardiff tick come before the miner's own lines.
        // They are rare, so they cannot starve the reader; the other way
        // round, a miner that submits without pause (on regtest every share
        // is a block) would never be sent the next job or a higher difficulty.
        let result = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                reason = "node shutting down";
                break;
            }
            changed = work_rx.changed(), if authorized => {
                if changed.is_err() {
                    reason = "node shutting down";
                    break;
                }
                let work = work_rx.borrow_and_update().clone();
                match work {
                    Some(work) => session.issue_job(work).await,
                    None => Ok(()),
                }
            }
            _ = vardiff_tick.tick(), if authorized => {
                session.log_status();
                session.check_vardiff().await
            }
            line = read_line_bounded(&mut reader, &mut buf) => {
                let line = match line {
                    Ok(line) => line,
                    Err(why) => {
                        reason = why;
                        break;
                    }
                };
                buf.clear();
                idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                session.handle_line(&line, &mut work_rx).await
            }
            _ = &mut idle => {
                reason = "idle";
                break;
            }
        };
        if result.is_err() {
            break;
        }
    }
    session.log_close(reason);
    let _ = session.writer.shutdown().await;
}

/// Read one `\n`-terminated line of at most [`MAX_LINE_BYTES`].
///
/// Cancel-safe: a partial line stays in `buf` when `select!` drops this
/// future, so the caller clears `buf` only after taking a returned line.
async fn read_line_bounded<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> Result<String, &'static str> {
    loop {
        let chunk = reader.fill_buf().await.map_err(|_| "read error")?;
        if chunk.is_empty() {
            return Err("end of stream");
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > MAX_LINE_BYTES {
                return Err("line too long");
            }
            buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            break;
        }
        if buf.len() + chunk.len() > MAX_LINE_BYTES {
            return Err("line too long");
        }
        buf.extend_from_slice(chunk);
        let n = chunk.len();
        reader.consume(n);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf.clone()).map_err(|_| "invalid UTF-8")
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Session<S> {
    async fn write(&mut self, line: String) -> Result<(), Close> {
        let write = async {
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await
        };
        match tokio::time::timeout(WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                tracing::debug!(target: "node::stratum", peer = %self.peer, "Stratum write failed; closing");
                Err(Close)
            }
        }
    }

    async fn handle_line(
        &mut self,
        line: &str,
        work_rx: &mut watch::Receiver<Option<Arc<Work>>>,
    ) -> Result<(), Close> {
        if line.trim().is_empty() {
            return Ok(());
        }
        let Some(req) = parse_request(line) else {
            return self.write(error_response(&Value::Null, StratumError::Other, Some("Malformed request"))).await;
        };
        match req.method.as_str() {
            "mining.subscribe" => {
                self.user_agent = req.params.first().and_then(Value::as_str).map(miner::label).filter(|ua| !ua.is_empty());
                tracing::debug!(
                    target: "node::stratum",
                    peer = %self.peer,
                    user_agent = self.user_agent.as_deref().unwrap_or(""),
                    extranonce1 = %hex::encode(self.extranonce1),
                    "Stratum miner subscribed"
                );
                let subid = hex::encode(self.extranonce1);
                let result = json!([
                    [["mining.set_difficulty", subid], ["mining.notify", subid]],
                    hex::encode(self.extranonce1),
                    EXTRANONCE2_LEN,
                ]);
                self.write(response(&req.id, result)).await
            }
            "mining.configure" => self.configure(&req).await,
            "mining.authorize" => self.authorize(&req, work_rx).await,
            "mining.suggest_difficulty" => self.suggest_difficulty(&req).await,
            "mining.submit" => self.submit(&req).await,
            "mining.extranonce.subscribe" => self.write(response(&req.id, json!(true))).await,
            "mining.ping" => self.write(response(&req.id, json!("pong"))).await,
            _ => self.write(error_response(&req.id, StratumError::UnknownMethod, None)).await,
        }
    }

    /// BIP 310 `mining.configure`. Only version rolling is supported; the
    /// mask granted is the intersection of what the miner asked for and the
    /// BIP 320 bits.
    async fn configure(&mut self, req: &Request) -> Result<(), Close> {
        let extensions: Vec<&str> = req
            .params
            .first()
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut result = serde_json::Map::new();
        if extensions.contains(&"version-rolling") {
            let requested = req
                .params
                .get(1)
                .and_then(|o| o.get("version-rolling.mask"))
                .and_then(parse_hex_u32)
                .unwrap_or(u32::MAX);
            self.version_mask = requested & VERSION_ROLLING_MASK;
            // A miner that rolls bits outside the granted mask has every
            // share rejected as low difficulty; this line is how to see it.
            tracing::debug!(
                target: "node::stratum",
                peer = %self.peer,
                requested = %format!("{requested:08x}"),
                granted = %format!("{:08x}", self.version_mask),
                "Stratum version rolling negotiated"
            );
            result.insert("version-rolling".into(), json!(self.version_mask != 0));
            result.insert("version-rolling.mask".into(), json!(format!("{:08x}", self.version_mask)));
        }
        result.insert("minimum-difficulty".into(), json!(false));
        result.insert("subscribe-extranonce".into(), json!(false));
        self.write(response(&req.id, Value::Object(result))).await
    }

    async fn authorize(
        &mut self,
        req: &Request,
        work_rx: &mut watch::Receiver<Option<Arc<Work>>>,
    ) -> Result<(), Close> {
        let username = req.params.first().and_then(Value::as_str).unwrap_or("");
        let config = &self.shared.config;
        let payout = match resolve_payout(username, config.network, config.fallback_address.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    username,
                    "Stratum authorize refused: {e}"
                );
                let detail = format!("{}: {e}", StratumError::Unauthorized.message());
                return self
                    .write(error_response(&req.id, StratumError::Unauthorized, Some(&detail)))
                    .await;
            }
        };
        tracing::info!(
            target: "node::stratum",
            peer = %self.peer,
            address = payout.address.as_deref().unwrap_or("<--stratumaddress>"),
            worker = payout.worker.as_deref().unwrap_or(""),
            script = %payout.script.to_hex_string(),
            user_agent = self.user_agent.as_deref().unwrap_or(""),
            difficulty = self.vardiff.difficulty(),
            "Stratum miner authorized"
        );
        let first = self.payout.is_none();
        self.payout = Some(payout);
        if first {
            self.channel = Some(CountGuard::new(self.shared.stats.clone(), |s| &s.channels));
        }
        self.write(response(&req.id, json!(true))).await?;
        if first {
            self.write(notification("mining.set_difficulty", json!([self.vardiff.difficulty()])))
                .await?;
            // Mark it seen, so the select loop does not issue the same work
            // again as a change.
            let work = work_rx.borrow_and_update().clone();
            if let Some(work) = work {
                self.issue_job(work).await?;
            }
        }
        Ok(())
    }

    async fn suggest_difficulty(&mut self, req: &Request) -> Result<(), Close> {
        let Some(d) = req.params.first().and_then(parse_difficulty) else {
            let params = miner::label(&json!(req.params).to_string());
            tracing::debug!(
                target: "node::stratum",
                peer = %self.peer,
                %params,
                "Stratum suggest_difficulty refused: not a difficulty"
            );
            return self.write(error_response(&req.id, StratumError::InvalidParams, None)).await;
        };
        let adopted = self.vardiff.suggest(d, std::time::Instant::now());
        tracing::debug!(
            target: "node::stratum",
            peer = %self.peer,
            suggested = d,
            adopted,
            "Stratum miner suggested a difficulty; it is now the vardiff floor"
        );
        self.write(response(&req.id, json!(true))).await?;
        if self.payout.is_some() {
            self.difficulty_changed(adopted).await?;
        }
        Ok(())
    }

    /// Tell the miner its new difficulty and give it a job at that difficulty.
    async fn difficulty_changed(&mut self, difficulty: u64) -> Result<(), Close> {
        self.write(notification("mining.set_difficulty", json!([difficulty]))).await?;
        let work = self.jobs.latest().map(|j| j.template.work.clone());
        match work {
            Some(work) => self.issue_job(work).await,
            None => Ok(()),
        }
    }

    async fn check_vardiff(&mut self) -> Result<(), Close> {
        let Some(latest) = self.jobs.latest() else { return Ok(()) };
        let ceiling = network_difficulty(&latest.template.work.block_target);
        match self.vardiff.retarget(std::time::Instant::now(), ceiling) {
            Some(d) => {
                tracing::debug!(target: "node::stratum", peer = %self.peer, difficulty = d, "Stratum vardiff retarget");
                self.difficulty_changed(d).await
            }
            None => Ok(()),
        }
    }

    /// Build a job on `work` for this miner and send it.
    async fn issue_job(&mut self, work: Arc<Work>) -> Result<(), Close> {
        let Some(payout) = self.payout.as_ref() else { return Ok(()) };
        let clean = self.job_prev_hash != Some(work.prev_hash);
        if clean {
            self.jobs.mark_all_stale();
            self.seen.clear();
            self.job_prev_hash = Some(work.prev_hash);
        }
        let job_id = self.jobs.next_job_id();
        let extranonce_len = EXTRANONCE1_LEN + EXTRANONCE2_LEN;
        let template = match ActiveTemplate::build(work, job_id, payout.script.clone(), extranonce_len) {
            Ok(t) => t,
            Err(e) => {
                // Unreachable with the fixed SV1 extranonce length; if it ever
                // is reached, no job can be issued on this connection.
                tracing::error!(target: "node::stratum", peer = %self.peer, error = %e, "Stratum job build failed");
                return Err(Close);
            }
        };
        let difficulty = self.vardiff.difficulty();
        let share_target = effective_share_target(difficulty, &template.work.block_target);
        let params = notify_params(&template, clean);
        tracing::trace!(
            target: "node::stratum",
            peer = %self.peer,
            job_id = %format!("{job_id:x}"),
            height = template.work.height,
            difficulty,
            clean,
            "Stratum job issued"
        );
        self.jobs.push(Job { template: Arc::new(template), difficulty, share_target });
        self.write(notification("mining.notify", params)).await
    }

    async fn submit(&mut self, req: &Request) -> Result<(), Close> {
        let reply = self.judge_submit(req).await;
        let outcome = match &reply {
            Ok(()) => ShareOutcome::Accepted,
            Err(r) if r.error == StratumError::JobNotFound => ShareOutcome::Stale,
            Err(_) => ShareOutcome::Rejected,
        };
        self.shared.stats.share(outcome);
        let line = match reply {
            Ok(()) => response(&req.id, json!(true)),
            Err(refusal) => {
                self.tally.refuse(outcome);
                self.log_refusal(&refusal);
                error_response(&req.id, refusal.error, None)
            }
        };
        self.write(line).await
    }

    /// Every refused submit is logged here, so no path can refuse one
    /// silently: a counter that rises with no line to explain it is the
    /// failure this exists to prevent.
    fn log_refusal(&self, refusal: &Refusal) {
        tracing::warn!(
            target: "node::stratum",
            peer = %self.peer,
            worker = self.worker(),
            job_id = %refusal.job_id.map(|id| format!("{id:x}")).unwrap_or_default(),
            reason = refusal.reason,
            difficulty = refusal.difficulty.unwrap_or(0),
            share_difficulty = refusal.hash_difficulty.map(format_difficulty).unwrap_or(0),
            "Stratum share rejected"
        );
    }

    async fn judge_submit(&mut self, req: &Request) -> Result<(), Refusal> {
        let Some(payout) = self.payout.clone() else {
            return Err(Refusal::new(StratumError::Unauthorized, "submit before authorize"));
        };
        let malformed = |reason| Refusal::new(StratumError::InvalidParams, reason);
        let p = &req.params;
        let job_id = p
            .get(1)
            .and_then(Value::as_str)
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .ok_or_else(|| malformed("malformed job id"))?;
        let extranonce2: [u8; EXTRANONCE2_LEN] = p
            .get(2)
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| malformed("malformed extranonce2"))?;
        let ntime = p.get(3).and_then(parse_hex_u32).ok_or_else(|| malformed("malformed ntime"))?;
        let nonce = p.get(4).and_then(parse_hex_u32).ok_or_else(|| malformed("malformed nonce"))?;
        let Some(job) = self.jobs.get(job_id).cloned() else {
            let mut refusal = Refusal::new(StratumError::JobNotFound, "stale or unknown job");
            refusal.job_id = Some(job_id);
            return Err(refusal);
        };
        let base = job.template.work.version as u32;
        // Miners send the rolled bits either as the full version or as the
        // XOR against the job's; with no mask bits set in the job's version
        // the two agree, and taking only the masked bits enforces that
        // nothing outside the negotiated mask changes.
        let version = match p.get(5).and_then(parse_hex_u32) {
            Some(bits) if self.version_mask != 0 => {
                ((base & !self.version_mask) | (bits & self.version_mask)) as i32
            }
            _ => base as i32,
        };
        let key = (job_id, extranonce2, ntime, nonce, version);
        if self.seen.contains(&key) {
            return Err(Refusal::new(StratumError::Duplicate, "duplicate").on(&job));
        }
        let mut extranonce = [0u8; EXTRANONCE1_LEN + EXTRANONCE2_LEN];
        extranonce[..EXTRANONCE1_LEN].copy_from_slice(&self.extranonce1);
        extranonce[EXTRANONCE1_LEN..].copy_from_slice(&extranonce2);
        let now = crate::time::now_secs();
        let result = validate_share(&job.template, &extranonce, ntime, nonce, version, &job.share_target, now)
            .map_err(|_| Refusal::new(StratumError::InvalidParams, "malformed extranonce").on(&job))?;
        match result {
            ShareResult::Block(block) => {
                self.accepted(key, job.difficulty, hash_difficulty(&block.block_hash()));
                submit_found_block(&self.shared, *block, job.template.work.height, &payout, self.peer).await;
                Ok(())
            }
            ShareResult::Share { hash_difficulty } => {
                self.accepted(key, job.difficulty, hash_difficulty);
                tracing::debug!(
                    target: "node::stratum",
                    peer = %self.peer,
                    worker = self.worker(),
                    job_id = %format!("{job_id:x}"),
                    difficulty = job.difficulty,
                    share_difficulty = format_difficulty(hash_difficulty),
                    "Stratum share accepted"
                );
                Ok(())
            }
            ShareResult::LowDifficulty { hash_difficulty } => {
                let mut refusal = Refusal::new(StratumError::LowDifficulty, "low difficulty").on(&job);
                refusal.hash_difficulty = Some(hash_difficulty);
                Err(refusal)
            }
            ShareResult::Stale => Err(Refusal::new(StratumError::JobNotFound, "stale ntime").on(&job)),
            ShareResult::Duplicate => Err(Refusal::new(StratumError::Duplicate, "duplicate").on(&job)),
            ShareResult::BadTime => Err(Refusal::new(StratumError::InvalidTime, "ntime out of range").on(&job)),
        }
    }

    fn accepted(&mut self, key: SeenKey, difficulty: u64, hash_difficulty: f64) {
        if self.seen.len() >= MAX_SEEN_SHARES {
            self.seen.clear();
        }
        self.seen.insert(key);
        self.vardiff.record_share();
        self.tally.accept(std::time::Instant::now(), difficulty, hash_difficulty);
    }

    fn worker(&self) -> &str {
        self.payout.as_ref().and_then(|p| p.worker.as_deref()).unwrap_or("")
    }

    /// The periodic `-debug=stratum` reading: is this miner still hashing,
    /// and at what rate.
    fn log_status(&mut self) {
        let Some(report) = self.tally.status_due(std::time::Instant::now()) else { return };
        tracing::debug!(
            target: "node::stratum",
            peer = %self.peer,
            worker = self.worker(),
            difficulty = self.vardiff.difficulty(),
            accepted = report.shares.accepted,
            rejected = report.shares.rejected,
            stale = report.shares.stale,
            hashrate = %format_hashrate(report.hashrate),
            last_share_secs = report.last_share_secs.map(|s| s.to_string()).unwrap_or_else(|| "never".into()),
            "Stratum miner status"
        );
    }

    /// One line when the connection ends. A miner that authorized gets it at
    /// info, beside its "authorized" line, so a device that keeps dropping is
    /// visible without `-debug=stratum`.
    fn log_close(&mut self, reason: &str) {
        let now = std::time::Instant::now();
        let Some(payout) = self.payout.as_ref() else {
            tracing::debug!(target: "node::stratum", peer = %self.peer, reason, "Stratum connection closed");
            return;
        };
        let hashrate = format_hashrate(self.tally.hashrate(now));
        let total = self.tally.total();
        tracing::info!(
            target: "node::stratum",
            peer = %self.peer,
            address = payout.address.as_deref().unwrap_or("<--stratumaddress>"),
            worker = payout.worker.as_deref().unwrap_or(""),
            reason,
            connected_secs = self.tally.connected_secs(now),
            accepted = total.accepted,
            rejected = total.rejected,
            stale = total.stale,
            best_share = format_difficulty(self.tally.best_share()),
            %hashrate,
            "Stratum miner disconnected"
        );
    }
}
