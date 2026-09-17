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

use std::collections::{HashMap, HashSet, VecDeque};
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

use super::jd::{self, DeclaredJob, JobDeclaration};
use super::noise::{self, TransportError};
use super::wire;
use crate::stratum::config::{Payout, resolve_payout};
use crate::stratum::job::{Job, JobManager};
use crate::stratum::miner::{self, MinerTally, format_difficulty, format_hashrate};
use crate::stratum::server::{CountGuard, ShareOutcome, Shared, submit_found_block};
use crate::stratum::share::{
    ShareResult, effective_share_target, hash_difficulty, network_difficulty, validate_share,
};
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
/// Declared jobs a Job Declaration connection keeps for `PushSolution`.
const DECLARED_JOB_HISTORY: usize = 8;
/// Bytes of server-assigned extranonce per channel: the connection's four
/// bytes, then the channel id. Unique across every channel on the node.
pub const EXTRANONCE_PREFIX_LEN: usize = 8;

/// The key the server authenticates with, and the per-connection limits.
pub(crate) struct V2Context {
    pub authority_public: [u8; 32],
    pub authority_private: zeroize::Zeroizing<[u8; 32]>,
    pub max_channels: usize,
    /// Job Declaration state, when Job Declaration is enabled.
    pub jd: Option<Arc<JobDeclaration>>,
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
    tally: MinerTally,
    _count: CountGuard,
}

impl Channel {
    fn target(&self, block_target: &[u8; 32]) -> [u8; 32] {
        effective_share_target(self.vardiff.difficulty(), block_target).min(self.max_target)
    }

    fn hole_len(&self) -> usize {
        EXTRANONCE_PREFIX_LEN + self.extended.unwrap_or(0)
    }

    fn worker(&self) -> &str {
        self.payout.worker.as_deref().unwrap_or("")
    }
}

struct Session {
    peer: SocketAddr,
    shared: Arc<Shared>,
    writer: OwnedWriteHalf,
    codec: NoiseCodec,
    extranonce: [u8; 4],
    setup: bool,
    /// The `SetupConnection.protocol` this connection speaks.
    protocol: u8,
    /// A mining connection that set `REQUIRES_WORK_SELECTION`: it may send
    /// `SetCustomMiningJob`.
    work_selection: bool,
    channels: HashMap<u32, Channel>,
    next_channel_id: u32,
    max_channels: usize,
    jd: Option<Arc<JobDeclaration>>,
    /// Jobs this Job Declaration connection declared, newest last.
    declared: VecDeque<Arc<DeclaredJob>>,
    /// Vendor, hardware and firmware from `SetupConnection`, made safe to log.
    device: String,
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
    let _connection = shared.stats.connection();

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
        protocol: wire::PROTOCOL_MINING,
        work_selection: false,
        channels: HashMap::new(),
        next_channel_id: 1,
        max_channels: ctx.max_channels.max(1),
        jd: ctx.jd.clone(),
        declared: VecDeque::new(),
        device: String::new(),
    };
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut vardiff_tick = tokio::time::interval(VARDIFF_TICK);
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut reason = "server closed the connection";
    loop {
        let has_channels = !session.channels.is_empty();
        // New work and the vardiff tick come before the miner's frames, as on
        // the V1 listener: they are rare, and a miner that submits without
        // pause would otherwise never be sent the next job.
        let result = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                reason = "node shutting down";
                break;
            }
            changed = work_rx.changed(), if has_channels => {
                if changed.is_err() {
                    reason = "node shutting down";
                    break;
                }
                let work = work_rx.borrow_and_update().clone();
                match work {
                    Some(work) => session.issue_all(&work).await,
                    None => Ok(()),
                }
            }
            _ = vardiff_tick.tick(), if has_channels => {
                session.log_status();
                session.check_vardiff().await
            }
            frame = frames.recv() => match frame {
                Some(Ok((msg_type, payload))) => {
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    session.handle(msg_type, &payload, &mut work_rx).await
                }
                Some(Err(e)) => {
                    tracing::debug!(target: "node::stratum", %peer, error = %e, "Stratum V2 read failed");
                    reason = "read failed";
                    break;
                }
                None => {
                    reason = "read failed";
                    break;
                }
            },
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
        if msg_type == wire::SETUP_CONNECTION {
            if self.setup {
                tracing::debug!(target: "node::stratum", peer = %self.peer, "Stratum V2 second SetupConnection; closing");
                return Err(Close);
            }
            return self.setup_connection(payload).await;
        }
        if self.protocol == wire::PROTOCOL_JOB_DECLARATION {
            return match msg_type {
                wire::ALLOCATE_MINING_JOB_TOKEN => self.allocate_token(payload).await,
                wire::DECLARE_MINING_JOB => self.declare_job(payload).await,
                wire::PUSH_SOLUTION => self.push_solution(payload).await,
                other => {
                    tracing::debug!(target: "node::stratum", peer = %self.peer, msg_type = other, "Stratum V2 Job Declaration message ignored");
                    Ok(())
                }
            };
        }
        match msg_type {
            wire::SET_CUSTOM_MINING_JOB => self.set_custom_job(payload).await,
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
        let jd = self.jd.is_some();
        let refusal = if !(req.protocol == wire::PROTOCOL_MINING
            || (req.protocol == wire::PROTOCOL_JOB_DECLARATION && jd))
        {
            Some((0, "unsupported-protocol"))
        } else if req.min_version > wire::PROTOCOL_VERSION || req.max_version < wire::PROTOCOL_VERSION {
            Some((0, "protocol-version-mismatch"))
        } else if req.protocol == wire::PROTOCOL_MINING
            && req.flags & wire::REQUIRES_WORK_SELECTION != 0
            && !jd
        {
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
        self.device = miner::label(&format!("{} {} {}", req.vendor, req.hardware_version, req.firmware));
        tracing::debug!(
            target: "node::stratum",
            peer = %self.peer,
            protocol = req.protocol,
            flags = req.flags,
            device = %self.device,
            device_id = %miner::label(&req.device_id),
            "Stratum V2 SetupConnection"
        );
        self.setup = true;
        self.protocol = req.protocol;
        self.work_selection =
            req.protocol == wire::PROTOCOL_MINING && req.flags & wire::REQUIRES_WORK_SELECTION != 0;
        // No REQUIRES_FIXED_VERSION: miners may roll the version bits. Job
        // Declaration flags ask nothing of the server that it must refuse.
        self.send(wire::SETUP_CONNECTION_SUCCESS, &wire::setup_connection_success(wire::PROTOCOL_VERSION, 0))
            .await
    }

    /// This connection, as the owner of the job tokens it is issued.
    fn owner(&self) -> u32 {
        u32::from_be_bytes(self.extranonce)
    }

    /// `AllocateMiningJobToken`: issue a token for the address the user
    /// identifier names. There is no error reply in the protocol, so a
    /// request that names no usable address closes the connection.
    async fn allocate_token(&mut self, payload: &[u8]) -> Result<(), Close> {
        let req = self.decode(wire::decode_allocate_mining_job_token(payload))?;
        let Some(jd) = self.jd.clone() else { return Err(Close) };
        let config = self.shared.config.clone();
        let payout = match resolve_payout(&req.user_identifier, config.network, config.fallback_address.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    user_identifier = %req.user_identifier,
                    "Stratum V2 job token refused: {e}; closing"
                );
                return Err(Close);
            }
        };
        let outputs = jd::coinbase_outputs(&payout.script);
        let Some(token) = jd.tokens.allocate(self.owner(), payout) else {
            tracing::warn!(
                target: "node::stratum",
                peer = %self.peer,
                "Stratum V2 job token refused: the token table is full of other connections' declared jobs; closing"
            );
            return Err(Close);
        };
        self.send(
            wire::ALLOCATE_MINING_JOB_TOKEN_SUCCESS,
            &wire::allocate_mining_job_token_success(req.request_id, &token, &outputs),
        )
        .await
    }

    /// `DeclareMiningJob`: check the declared transaction set against the
    /// mempool and the current work.
    async fn declare_job(&mut self, payload: &[u8]) -> Result<(), Close> {
        let req = self.decode(wire::decode_declare_mining_job(payload))?;
        let Some(jd) = self.jd.clone() else { return Err(Close) };
        let request_id = req.request_id;
        let Some(payout) = jd.tokens.take_allocated(&req.mining_job_token) else {
            return self
                .declare_error(request_id, "invalid-mining-job-token", "the token is unknown, expired or already used")
                .await;
        };
        let Some(work) = self.shared.work.borrow().clone() else {
            return self
                .declare_error(
                    request_id,
                    "invalid-job-param-value-coinbase_tx_prefix",
                    "the node is not issuing work (initial block download)",
                )
                .await;
        };
        let mempool = self.shared.mempool.clone();
        let network = self.shared.config.network;
        let shared_jd = jd.clone();
        let checked = tokio::task::spawn_blocking(move || {
            let view = jd::MempoolView::for_declaration(&mempool, &shared_jd.wtxids, &req.wtxid_list);
            let subsidy = crate::chain::connect::block_subsidy(network, work.height);
            jd::check_declaration(&req, payout, &work, subsidy, &view)
        })
        .await;
        match checked {
            Ok(Ok(job)) => {
                let job = Arc::new(job);
                let Some(token) = jd.tokens.declare(self.owner(), job.clone()) else {
                    return self
                        .declare_error(
                            request_id,
                            "invalid-mining-job-token",
                            "the server holds as many declared jobs as it can; try again later",
                        )
                        .await;
                };
                tracing::info!(
                    target: "node::stratum",
                    peer = %self.peer,
                    height = job.height,
                    txs = job.txdata.len(),
                    fees = job.fees,
                    "Stratum V2 mining job declared"
                );
                if self.declared.len() == DECLARED_JOB_HISTORY {
                    self.declared.pop_front();
                }
                self.declared.push_back(job);
                self.send(wire::DECLARE_MINING_JOB_SUCCESS, &wire::declare_mining_job_success(request_id, &token))
                    .await
            }
            Ok(Err(refusal)) => self.declare_error(request_id, refusal.code, &refusal.details).await,
            Err(e) => {
                tracing::error!(target: "node::stratum", peer = %self.peer, error = %e, "Stratum V2 declaration check panicked");
                Err(Close)
            }
        }
    }

    async fn declare_error(&mut self, request_id: u32, code: &str, details: &str) -> Result<(), Close> {
        tracing::warn!(target: "node::stratum", peer = %self.peer, code, details, "Stratum V2 mining job declaration refused");
        self.send(wire::DECLARE_MINING_JOB_ERROR, &wire::declare_mining_job_error(request_id, code, details))
            .await
    }

    /// `PushSolution`: a block found on a job this connection declared.
    async fn push_solution(&mut self, payload: &[u8]) -> Result<(), Close> {
        let msg = self.decode(wire::decode_push_solution(payload))?;
        let found = self.declared.iter().rev().find_map(|job| {
            let block = jd::solution_block(job, &msg.extranonce, &msg.prev_hash, msg.ntime, msg.nonce, msg.nbits, msg.version)?;
            Some((block, job.height, job.payout.clone()))
        });
        match found {
            Some((block, height, payout)) => submit_found_block(&self.shared, block, height, &payout, self.peer).await,
            None => tracing::warn!(
                target: "node::stratum",
                peer = %self.peer,
                "Stratum V2 pushed solution matches no declared job on this connection"
            ),
        }
        Ok(())
    }

    /// `SetCustomMiningJob`: a job on a declared transaction set, for an
    /// extended channel on a connection that asked for work selection.
    async fn set_custom_job(&mut self, payload: &[u8]) -> Result<(), Close> {
        let msg = self.decode(wire::decode_set_custom_mining_job(payload))?;
        let (channel_id, request_id) = (msg.channel_id, msg.request_id);
        let outcome = self.check_custom_job(&msg);
        match outcome {
            Ok(job_id) => {
                tracing::info!(target: "node::stratum", peer = %self.peer, channel_id, job_id, "Stratum V2 custom mining job set");
                self.send(
                    wire::SET_CUSTOM_MINING_JOB_SUCCESS,
                    &wire::set_custom_mining_job_success(channel_id, request_id, job_id),
                )
                .await
            }
            Err(refusal) => {
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    channel_id,
                    code = refusal.code,
                    details = %refusal.details,
                    "Stratum V2 custom mining job refused"
                );
                self.send(
                    wire::SET_CUSTOM_MINING_JOB_ERROR,
                    &wire::set_custom_mining_job_error(channel_id, request_id, refusal.code),
                )
                .await
            }
        }
    }

    fn check_custom_job(&mut self, msg: &wire::SetCustomMiningJob) -> Result<u32, jd::Refusal> {
        let refuse = |code: &'static str, details: &str| jd::Refusal { code, details: details.to_string() };
        let Some(jd) = self.jd.clone().filter(|_| self.work_selection) else {
            return Err(refuse("invalid-mining-job-token", "this connection did not negotiate work selection"));
        };
        let job = jd
            .tokens
            .declared(&msg.token)
            .ok_or_else(|| refuse("invalid-mining-job-token", "the token names no declared job"))?;
        let work = self
            .shared
            .work
            .borrow()
            .clone()
            .ok_or_else(|| refuse("invalid-job-param-value-prev_hash", "the node is not issuing work"))?;
        let ch = self
            .channels
            .get_mut(&msg.channel_id)
            .filter(|c| c.extended.is_some())
            .ok_or_else(|| refuse("invalid-channel-id", "no extended channel with that id"))?;
        let custom = jd::check_custom_job(msg, &job, &work, ch.hole_len())?;
        let job_id = ch.jobs.next_job_id();
        let template = ActiveTemplate::from_parts(
            custom.work,
            job_id,
            job.payout.script.clone(),
            custom.coinbase_prefix,
            custom.coinbase_suffix,
            ch.hole_len(),
        );
        ch.jobs.push(Job {
            template: Arc::new(template),
            difficulty: ch.vardiff.difficulty(),
            share_target: ch.target(&work.block_target),
        });
        Ok(job_id)
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
            tally: MinerTally::new(std::time::Instant::now()),
            _count: CountGuard::new(self.shared.stats.clone(), |s| &s.channels),
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
            worker = channel.worker(),
            device = %self.device,
            difficulty = channel.vardiff.difficulty(),
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
        let judged = self.judge(channel_id, job_id, nonce, ntime, version, miner_extranonce);
        let outcome = match &judged {
            Judged::Accepted { .. } => ShareOutcome::Accepted,
            Judged::Rejected { code: "stale-share", .. } => ShareOutcome::Stale,
            Judged::Rejected { .. } => ShareOutcome::Rejected,
        };
        self.shared.stats.share(outcome);
        match judged {
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
            Judged::Rejected { code, difficulty, hash_difficulty } => {
                // Every refusal is logged here, including one for a channel
                // that does not exist, which has no tally to count it in.
                let worker = match self.channels.get_mut(&channel_id) {
                    Some(ch) => {
                        ch.tally.refuse(outcome);
                        ch.worker().to_string()
                    }
                    None => String::new(),
                };
                tracing::warn!(
                    target: "node::stratum",
                    peer = %self.peer,
                    worker,
                    channel_id,
                    job_id,
                    reason = code,
                    difficulty = difficulty.unwrap_or(0),
                    share_difficulty = hash_difficulty.map(format_difficulty).unwrap_or(0),
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
            return Judged::refused("invalid-channel-id", None);
        };
        let mut extranonce = ch.prefix.to_vec();
        match (ch.extended, miner_extranonce) {
            (None, None) => {}
            (Some(size), Some(miner)) if miner.len() == size => extranonce.extend_from_slice(&miner),
            _ => return Judged::refused("invalid-share", None),
        }
        let Some(job) = ch.jobs.get(job_id).cloned() else {
            return Judged::refused("stale-share", None);
        };
        let base = job.template.work.version as u32;
        let version = ((base & !VERSION_ROLLING_MASK) | (version & VERSION_ROLLING_MASK)) as i32;
        let key = (job_id, nonce, ntime, version, extranonce[EXTRANONCE_PREFIX_LEN..].to_vec());
        if ch.seen.contains(&key) {
            return Judged::refused("duplicate-share", Some(&job));
        }
        let now = crate::time::now_secs();
        let result = match validate_share(&job.template, &extranonce, ntime, nonce, version, &job.share_target, now) {
            Ok(r) => r,
            Err(_) => return Judged::refused("invalid-share", Some(&job)),
        };
        let accept = |ch: &mut Channel, key, hash_difficulty| {
            if ch.seen.len() >= MAX_SEEN_SHARES {
                ch.seen.clear();
            }
            ch.seen.insert(key);
            ch.vardiff.record_share();
            ch.tally.accept(std::time::Instant::now(), job.difficulty, hash_difficulty);
        };
        match result {
            ShareResult::Block(block) => {
                accept(ch, key, hash_difficulty(&block.block_hash()));
                Judged::Accepted {
                    difficulty: job.difficulty,
                    block: Some((*block, job.template.work.height, ch.payout.clone())),
                }
            }
            ShareResult::Share { hash_difficulty } => {
                accept(ch, key, hash_difficulty);
                tracing::debug!(
                    target: "node::stratum",
                    peer = %self.peer,
                    worker = ch.worker(),
                    channel_id,
                    job_id,
                    difficulty = job.difficulty,
                    share_difficulty = format_difficulty(hash_difficulty),
                    "Stratum share accepted"
                );
                Judged::Accepted { difficulty: job.difficulty, block: None }
            }
            ShareResult::LowDifficulty { hash_difficulty } => Judged::Rejected {
                code: "difficulty-too-low",
                difficulty: Some(job.difficulty),
                hash_difficulty: Some(hash_difficulty),
            },
            ShareResult::Stale => Judged::refused("stale-share", Some(&job)),
            ShareResult::Duplicate => Judged::refused("duplicate-share", Some(&job)),
            ShareResult::BadTime => Judged::refused("invalid-timestamp", Some(&job)),
        }
    }

    /// The periodic `-debug=stratum` reading for every channel.
    fn log_status(&mut self) {
        let now = std::time::Instant::now();
        for ch in self.channels.values_mut() {
            let Some(report) = ch.tally.status_due(now) else { continue };
            tracing::debug!(
                target: "node::stratum",
                peer = %self.peer,
                channel_id = ch.id,
                worker = ch.worker(),
                difficulty = ch.vardiff.difficulty(),
                accepted = report.shares.accepted,
                rejected = report.shares.rejected,
                stale = report.shares.stale,
                hashrate = %format_hashrate(report.hashrate),
                last_share_secs = report.last_share_secs.map(|s| s.to_string()).unwrap_or_else(|| "never".into()),
                "Stratum miner status"
            );
        }
    }

    /// One line per channel when the connection ends, at info, beside the
    /// "channel opened" line; a connection that opened none gets a debug line.
    fn log_close(&mut self, reason: &str) {
        let now = std::time::Instant::now();
        if self.channels.is_empty() {
            tracing::debug!(target: "node::stratum", peer = %self.peer, reason, "Stratum V2 connection closed");
            return;
        }
        let mut ids: Vec<u32> = self.channels.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let Some(ch) = self.channels.get_mut(&id) else { continue };
            let hashrate = format_hashrate(ch.tally.hashrate(now));
            let total = ch.tally.total();
            tracing::info!(
                target: "node::stratum",
                peer = %self.peer,
                channel_id = id,
                address = ch.payout.address.as_deref().unwrap_or("<--stratumaddress>"),
                worker = ch.worker(),
                reason,
                connected_secs = ch.tally.connected_secs(now),
                accepted = total.accepted,
                rejected = total.rejected,
                stale = total.stale,
                best_share = format_difficulty(ch.tally.best_share()),
                %hashrate,
                "Stratum V2 channel closed"
            );
        }
    }
}

enum Judged {
    Accepted { difficulty: u64, block: Option<(bitcoin::Block, u32, Payout)> },
    Rejected {
        code: &'static str,
        /// The difficulty the job was issued at, once the job is known.
        difficulty: Option<u64>,
        /// What the header achieved, once it was hashed.
        hash_difficulty: Option<f64>,
    },
}

impl Judged {
    fn refused(code: &'static str, job: Option<&Job>) -> Self {
        Judged::Rejected { code, difficulty: job.map(|j| j.difficulty), hash_difficulty: None }
    }
}
