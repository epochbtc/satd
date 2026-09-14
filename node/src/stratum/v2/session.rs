//! One Stratum V2 connection.
//!
//! The exchange: Noise handshake; `SetupConnection` (Mining Protocol, version
//! 2); one or more `OpenStandardMiningChannel` / `OpenExtendedMiningChannel`,
//! each answered with its success message and then a future job plus the
//! `SetNewPrevHash` that activates it. From then on a tip change sends every
//! channel a new future job and `SetNewPrevHash`; a refresh on the same tip
//! sends a job with `min_ntime` set, active at once; a difficulty change sends
//! `SetTarget`. Shares are answered with `SubmitSharesSuccess` or
//! `SubmitSharesError`.
//!
//! A standard channel has no extranonce for the miner: the server's
//! per-channel prefix fills the whole coinbase hole and the job carries the
//! merkle root. An extended channel gets the split coinbase, the merkle path
//! and an extranonce range after the prefix.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use stratum_core::noise_sv2::NoiseCodec;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::noise::{self, TransportError};
use super::wire;
use crate::stratum::config::{Payout, resolve_payout};
use crate::stratum::job::{Job, JobManager};
use crate::stratum::server::{Shared, submit_found_block};
use crate::stratum::share::{ShareResult, effective_share_target, network_difficulty, validate_share};
use crate::stratum::template::{ActiveTemplate, MAX_EXTRANONCE_LEN, Work};
use crate::stratum::v1::VERSION_ROLLING_MASK;
use crate::stratum::vardiff::Vardiff;

/// The handshake must finish within this; miner firmware gives up after ten
/// seconds of its own.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection that sends nothing for this long is dropped.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const VARDIFF_TICK: Duration = Duration::from_secs(10);
const MAX_SEEN_SHARES: usize = 100_000;
/// Bytes of server-assigned extranonce per channel: the connection's four
/// bytes, then the channel id. Unique across every channel on the node.
pub const EXTRANONCE_PREFIX_LEN: usize = 8;

/// The key the server authenticates with, and the per-connection limits.
pub(crate) struct V2Context {
    pub authority_public: [u8; 32],
    pub authority_private: zeroize::Zeroizing<[u8; 32]>,
    pub max_channels: usize,
}

/// The connection must close.
struct Close;

type SeenKey = (u32, u32, u32, i32, Vec<u8>);

struct Channel {
    id: u32,
    /// The miner's extranonce size on an extended channel; `None` on a
    /// standard one.
    extended: Option<usize>,
    prefix: [u8; EXTRANONCE_PREFIX_LEN],
    payout: Payout,
    vardiff: Vardiff,
    /// The easiest target the miner accepts, big-endian.
    max_target: [u8; 32],
    jobs: JobManager,
    /// The previous-block hash the channel's jobs build on.
    prev_hash: Option<BlockHash>,
    seen: HashSet<SeenKey>,
}

impl Channel {
    fn target(&self, block_target: &[u8; 32]) -> [u8; 32] {
        effective_share_target(self.vardiff.difficulty(), block_target).min(self.max_target)
    }

    fn hole_len(&self) -> usize {
        EXTRANONCE_PREFIX_LEN + self.extended.unwrap_or(0)
    }
}

struct Session {
    peer: SocketAddr,
    shared: Arc<Shared>,
    writer: OwnedWriteHalf,
    codec: NoiseCodec,
    extranonce: [u8; 4],
    setup: bool,
    channels: HashMap<u32, Channel>,
    next_channel_id: u32,
    max_channels: usize,
}

/// Serve one connection until it closes, idles out, or the node shuts down.
pub(crate) async fn run(
    mut stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
    ctx: Arc<V2Context>,
    mut shutdown: watch::Receiver<bool>,
) {
    let handshake = noise::handshake(&mut stream, &ctx.authority_public, &ctx.authority_private);
    let codec = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(codec)) => codec,
        Ok(Err(e)) => {
            tracing::debug!(target: "node::stratum", %peer, error = %e, "Stratum V2 handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(target: "node::stratum", %peer, "Stratum V2 handshake timed out");
            return;
        }
    };
    tracing::debug!(target: "node::stratum", %peer, "Stratum V2 connection opened");

    let (mut reader, writer) = stream.into_split();
    // A frame read is several `read_exact`s and cannot be cancelled half way,
    // so it runs on its own task and hands whole messages over. The two
    // codec copies share nothing: one only decrypts, the other only encrypts.
    let (frames_tx, mut frames) = mpsc::channel::<Result<(u8, Vec<u8>), TransportError>>(16);
    let mut read_codec = codec.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = noise::read_frame(&mut reader, &mut read_codec).await;
            let failed = frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    });

    let mut work_rx = shared.work.subscribe();
    let mut session = Session {
        peer,
        extranonce: shared.next_extranonce1(),
        shared,
        writer,
        codec,
        setup: false,
        channels: HashMap::new(),
        next_channel_id: 1,
        max_channels: ctx.max_channels.max(1),
    };
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut vardiff_tick = tokio::time::interval(VARDIFF_TICK);
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let has_channels = !session.channels.is_empty();
        // New work and the vardiff tick come before the miner's frames, as on
        // the V1 listener: they are rare, and a miner that submits without
        // pause would otherwise never be sent the next job.
        let result = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            changed = work_rx.changed(), if has_channels => {
                if changed.is_err() {
                    break;
                }
                let work = work_rx.borrow_and_update().clone();
                match work {
                    Some(work) => session.issue_all(&work).await,
                    None => Ok(()),
                }
            }
            _ = vardiff_tick.tick(), if has_channels => session.check_vardiff().await,
            frame = frames.recv() => match frame {
                Some(Ok((msg_type, payload))) => {
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    session.handle(msg_type, &payload, &mut work_rx).await
                }
                Some(Err(e)) => {
                    tracing::debug!(target: "node::stratum", %peer, error = %e, "Stratum V2 connection closed");
                    break;
                }
                None => break,
            },
            _ = &mut idle => {
                tracing::debug!(target: "node::stratum", %peer, "Stratum V2 connection idle; closing");
                break;
            }
        };
        if result.is_err() {
            break;
        }
    }
    reader_task.abort();
    let _ = session.writer.shutdown().await;
}

impl Session {
    async fn send(&mut self, msg_type: u8, payload: &[u8]) -> Result<(), Close> {
        let bytes = noise::encode_frame(&mut self.codec, msg_type, payload).map_err(|e| {
            tracing::debug!(target: "node::stratum", peer = %self.peer, error = %e, "Stratum V2 encrypt failed");
            Close
        })?;
        match tokio::time::timeout(WRITE_TIMEOUT, self.writer.write_all(&bytes)).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                tracing::debug!(target: "node::stratum", peer = %self.peer, "Stratum V2 write failed; closing");
                Err(Close)
            }
        }
    }

    async fn handle(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        work_rx: &mut watch::Receiver<Option<Arc<Work>>>,
    ) -> Result<(), Close> {
        if !self.setup && msg_type != wire::SETUP_CONNECTION {
            tracing::debug!(
                target: "node::stratum",
                peer = %self.peer,
                msg_type,
                "Stratum V2 message before SetupConnection; closing"
            );
            return Err(Close);
        }
        match msg_type {
            wire::SETUP_CONNECTION => self.setup_connection(payload).await,
            wire::OPEN_STANDARD_MINING_CHANNEL => {
                let req = self.decode(wire::decode_open_standard_mining_channel(payload))?;
                self.open_channel(req.request_id, &req.user_identity, req.max_target, None, work_rx)
                    .await
            }
            wire::OPEN_EXTENDED_MINING_CHANNEL => {
                let req = self.decode(wire::decode_open_extended_mining_channel(payload))?;
                let size = usize::from(req.min_extranonce_size);
                self.open_channel(req.request_id, &req.user_identity, req.max_target, Some(size), work_rx)
                    .await
            }
            wire::SUBMIT_SHARES_STANDARD => {
                let s = self.decode(wire::decode_submit_shares_standard(payload))?;
                self.submit(s.channel_id, s.sequence_number, s.job_id, s.nonce, s.ntime, s.version, None)
                    .await
            }
            wire::SUBMIT_SHARES_EXTENDED => {
                let s = self.decode(wire::decode_submit_shares_extended(payload))?;
                self.submit(
                    s.channel_id,
                    s.sequence_number,
                    s.job_id,
                    s.nonce,
                    s.ntime,
                    s.version,
                    Some(s.extranonce),
                )
                .await
            }
            other => {
                tracing::debug!(target: "node::stratum", peer = %self.peer, msg_type = other, "Stratum V2 message ignored");
                Ok(())
            }
        }
    }

    fn decode<T>(&self, decoded: Result<T, wire::DecodeError>) -> Result<T, Close> {
        decoded.map_err(|e| {
            tracing::debug!(target: "node::stratum", peer = %self.peer, error = %e, "Stratum V2 malformed message; closing");
            Close
        })
    }

    async fn setup_connection(&mut self, payload: &[u8]) -> Result<(), Close> {
        let req = self.decode(wire::decode_setup_connection(payload))?;
        let refusal = if req.protocol != wire::PROTOCOL_MINING {
            Some((0, "unsupported-protocol"))
        } else if req.min_version > wire::PROTOCOL_VERSION || req.max_version < wire::PROTOCOL_VERSION {
            Some((0, "protocol-version-mismatch"))
        } else if req.flags & wire::REQUIRES_WORK_SELECTION != 0 {
            Some((wire::REQUIRES_WORK_SELECTION, "unsupported-feature-flags"))
        } else {
            None
        };
        if let Some((flags, code)) = refusal {
            tracing::warn!(
                target: "node::stratum",
                peer = %self.peer,
                protocol = req.protocol,
                flags = req.flags,
                code,
                "Stratum V2 SetupConnection refused"
            );
            self.send(wire::SETUP_CONNECTION_ERROR, &wire::setup_connection_error(flags, code)).await?;
            return Err(Close);
        }
        tracing::debug!(
            target: "node::stratum",
            peer = %self.peer,
            vendor = %req.vendor,
            hardware = %req.hardware_version,
            firmware = %req.firmware,
            "Stratum V2 SetupConnection"
        );
        self.setup = true;
        // No REQUIRES_FIXED_VERSION: miners may roll the version bits.
        self.send(wire::SETUP_CONNECTION_SUCCESS, &wire::setup_connection_success(wire::PROTOCOL_VERSION, 0))
            .await
    }

    async fn open_channel(
        &mut self,
        request_id: u32,
        user_identity: &str,
        max_target_le: [u8; 32],
        extended: Option<usize>,
        work_rx: &mut watch::Receiver<Option<Arc<Work>>>,
    ) -> Result<(), Close> {
        let config = self.shared.config.clone();
        let refusal = if self.channels.len() >= self.max_channels {
            Some("max-channels-reached")
        } else if extended.is_some_and(|size| EXTRANONCE_PREFIX_LEN + size > MAX_EXTRANONCE_LEN) {
            Some("unsupported-min-extranonce-size")
        } else {
            None
        };
        let payout = match refusal {
            Some(code) => Err(code),
            None => resolve_payout(user_identity, config.network, config.fallback_address.as_ref())
                .map_err(|_| "unknown-user"),
        };
        let payout = match payout {
            Ok(p) => p,
            Err(code) => {
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    user_identity,
                    code,
                    "Stratum V2 channel refused"
                );
                return self
                    .send(wire::OPEN_MINING_CHANNEL_ERROR, &wire::open_mining_channel_error(request_id, code))
                    .await;
            }
        };

        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1).max(1);
        let mut prefix = [0u8; EXTRANONCE_PREFIX_LEN];
        prefix[..4].copy_from_slice(&self.extranonce);
        prefix[4..].copy_from_slice(&id.to_be_bytes());
        let mut max_target = max_target_le;
        max_target.reverse();
        let channel = Channel {
            id,
            extended,
            prefix,
            vardiff: Vardiff::new(config.vardiff.clone(), config.initial_difficulty, std::time::Instant::now()),
            payout,
            max_target,
            jobs: JobManager::new(),
            prev_hash: None,
            seen: HashSet::new(),
        };
        let work = work_rx.borrow_and_update().clone();
        // Before any work exists (initial block download), advertise the
        // share target alone; jobs follow when work does.
        let block_target = work.as_ref().map(|w| w.block_target).unwrap_or([0xff; 32]);
        let mut target_le = channel.target(&block_target);
        target_le.reverse();
        tracing::info!(
            target: "node::stratum",
            peer = %self.peer,
            channel_id = id,
            kind = if extended.is_some() { "extended" } else { "standard" },
            address = channel.payout.address.as_deref().unwrap_or("<--stratumaddress>"),
            worker = channel.payout.worker.as_deref().unwrap_or(""),
            "Stratum V2 channel opened"
        );
        let reply = match extended {
            None => (
                wire::OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                wire::open_standard_mining_channel_success(request_id, id, &target_le, &prefix, 0),
            ),
            Some(size) => (
                wire::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                wire::open_extended_mining_channel_success(request_id, id, &target_le, size as u16, &prefix, 0),
            ),
        };
        self.channels.insert(id, channel);
        self.send(reply.0, &reply.1).await?;
        match work {
            Some(work) => self.issue_job(id, &work).await,
            None => Ok(()),
        }
    }

    async fn issue_all(&mut self, work: &Arc<Work>) -> Result<(), Close> {
        let mut ids: Vec<u32> = self.channels.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            self.issue_job(id, work).await?;
        }
        Ok(())
    }

    /// Send channel `id` a job on `work`: a future job and `SetNewPrevHash`
    /// when the previous block changed (or the channel has none yet), a job
    /// active at once otherwise.
    async fn issue_job(&mut self, id: u32, work: &Arc<Work>) -> Result<(), Close> {
        let Some(ch) = self.channels.get_mut(&id) else { return Ok(()) };
        let activate = ch.prev_hash != Some(work.prev_hash);
        if activate {
            ch.jobs.mark_all_stale();
            ch.seen.clear();
            ch.prev_hash = Some(work.prev_hash);
        }
        let job_id = ch.jobs.next_job_id();
        let template = match ActiveTemplate::build(work.clone(), job_id, ch.payout.script.clone(), ch.hole_len()) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(target: "node::stratum", peer = %self.peer, error = %e, "Stratum V2 job build failed");
                return Err(Close);
            }
        };
        let share_target = ch.target(&work.block_target);
        let min_ntime = (!activate).then_some(work.cur_time);
        let job_msg = match ch.extended {
            None => {
                let merkle_root = template.merkle_root(&ch.prefix).to_byte_array();
                (
                    wire::NEW_MINING_JOB,
                    wire::new_mining_job(id, job_id, min_ntime, work.version, &merkle_root),
                )
            }
            Some(_) => (
                wire::NEW_EXTENDED_MINING_JOB,
                wire::new_extended_mining_job(
                    id,
                    job_id,
                    min_ntime,
                    work.version,
                    true,
                    &work.merkle_branch,
                    &template.coinbase_prefix,
                    &template.coinbase_suffix,
                ),
            ),
        };
        ch.jobs.push(Job {
            template: Arc::new(template),
            difficulty: ch.vardiff.difficulty(),
            share_target,
        });
        self.send(job_msg.0, &job_msg.1).await?;
        if activate {
            let prev = work.prev_hash.to_byte_array();
            let msg = wire::set_new_prev_hash(id, job_id, &prev, work.cur_time, work.bits.to_consensus());
            self.send(wire::SET_NEW_PREV_HASH, &msg).await?;
        }
        Ok(())
    }

    async fn check_vardiff(&mut self) -> Result<(), Close> {
        let now = std::time::Instant::now();
        let mut changes = Vec::new();
        for ch in self.channels.values_mut() {
            let Some(latest) = ch.jobs.latest() else { continue };
            let block_target = latest.template.work.block_target;
            if let Some(d) = ch.vardiff.retarget(now, network_difficulty(&block_target)) {
                let target = ch.target(&block_target);
                ch.jobs.relax_share_targets(&target, d);
                let mut target_le = target;
                target_le.reverse();
                changes.push((ch.id, d, target_le));
            }
        }
        for (id, difficulty, target_le) in changes {
            tracing::debug!(target: "node::stratum", peer = %self.peer, channel_id = id, difficulty, "Stratum V2 vardiff retarget");
            self.send(wire::SET_TARGET, &wire::set_target(id, &target_le)).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit(
        &mut self,
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
        miner_extranonce: Option<Vec<u8>>,
    ) -> Result<(), Close> {
        let outcome = self.judge(channel_id, job_id, nonce, ntime, version, miner_extranonce);
        match outcome {
            Judged::Accepted { difficulty, block } => {
                if let Some((block, height, payout)) = block {
                    submit_found_block(&self.shared, block, height, &payout, self.peer).await;
                }
                self.send(
                    wire::SUBMIT_SHARES_SUCCESS,
                    &wire::submit_shares_success(channel_id, sequence_number, 1, difficulty),
                )
                .await
            }
            Judged::Rejected(code) => {
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    channel_id,
                    job_id,
                    reason = code,
                    "Stratum share rejected"
                );
                self.send(
                    wire::SUBMIT_SHARES_ERROR,
                    &wire::submit_shares_error(channel_id, sequence_number, code),
                )
                .await
            }
        }
    }

    fn judge(
        &mut self,
        channel_id: u32,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
        miner_extranonce: Option<Vec<u8>>,
    ) -> Judged {
        let Some(ch) = self.channels.get_mut(&channel_id) else {
            return Judged::Rejected("invalid-channel-id");
        };
        let mut extranonce = ch.prefix.to_vec();
        match (ch.extended, miner_extranonce) {
            (None, None) => {}
            (Some(size), Some(miner)) if miner.len() == size => extranonce.extend_from_slice(&miner),
            _ => return Judged::Rejected("invalid-share"),
        }
        let Some(job) = ch.jobs.get(job_id).cloned() else {
            return Judged::Rejected("stale-share");
        };
        let base = job.template.work.version as u32;
        let version = ((base & !VERSION_ROLLING_MASK) | (version & VERSION_ROLLING_MASK)) as i32;
        let key = (job_id, nonce, ntime, version, extranonce[EXTRANONCE_PREFIX_LEN..].to_vec());
        if ch.seen.contains(&key) {
            return Judged::Rejected("duplicate-share");
        }
        let now = crate::time::now_secs();
        let result = match validate_share(&job.template, &extranonce, ntime, nonce, version, &job.share_target, now) {
            Ok(r) => r,
            Err(_) => return Judged::Rejected("invalid-share"),
        };
        let accept = |ch: &mut Channel, key| {
            if ch.seen.len() >= MAX_SEEN_SHARES {
                ch.seen.clear();
            }
            ch.seen.insert(key);
            ch.vardiff.record_share();
        };
        match result {
            ShareResult::Block(block) => {
                accept(ch, key);
                Judged::Accepted {
                    difficulty: job.difficulty,
                    block: Some((*block, job.template.work.height, ch.payout.clone())),
                }
            }
            ShareResult::Share => {
                accept(ch, key);
                tracing::debug!(target: "node::stratum", peer = %self.peer, channel_id, job_id, "Stratum share accepted");
                Judged::Accepted { difficulty: job.difficulty, block: None }
            }
            ShareResult::LowDifficulty => Judged::Rejected("difficulty-too-low"),
            ShareResult::Stale => Judged::Rejected("stale-share"),
            ShareResult::Duplicate => Judged::Rejected("duplicate-share"),
            ShareResult::BadTime => Judged::Rejected("invalid-timestamp"),
        }
    }
}

enum Judged {
    Accepted { difficulty: u64, block: Option<(bitcoin::Block, u32, Payout)> },
    Rejected(&'static str),
}
