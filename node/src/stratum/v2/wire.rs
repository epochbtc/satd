//! Stratum V2 message payloads: the encoders for what the server sends and
//! the decoders for what it receives.
//!
//! Each function handles only the payload. The 6-byte frame header
//! (`extension_type: u16 | msg_type: u8 | msg_length: u24`, little-endian) is
//! added by the transport in [`super::noise`]. Layouts follow the Stratum V2
//! specification; the tests decode every encoder's output — and encode every
//! decoder's input — with the reference `binary_sv2` types, so a layout that
//! drifts from the specification fails here rather than on a miner.
//!
//! Integers are little-endian. `U256` is 32 bytes little-endian, `Str0255` and
//! `B032` are a 1-byte length then the bytes, `B064K` a 2-byte length then the
//! bytes, `Sv2Option<u32>` a count byte (0 or 1) then the value.

/// Message types, Common Protocol.
pub const SETUP_CONNECTION: u8 = 0x00;
pub const SETUP_CONNECTION_SUCCESS: u8 = 0x01;
pub const SETUP_CONNECTION_ERROR: u8 = 0x02;

/// Message types, Mining Protocol.
pub const OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
pub const OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
pub const OPEN_MINING_CHANNEL_ERROR: u8 = 0x12;
pub const OPEN_EXTENDED_MINING_CHANNEL: u8 = 0x13;
pub const OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: u8 = 0x14;
pub const NEW_MINING_JOB: u8 = 0x15;
pub const SUBMIT_SHARES_STANDARD: u8 = 0x1a;
pub const SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
pub const SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
pub const SUBMIT_SHARES_ERROR: u8 = 0x1d;
pub const NEW_EXTENDED_MINING_JOB: u8 = 0x1f;
pub const SET_NEW_PREV_HASH: u8 = 0x20;
pub const SET_TARGET: u8 = 0x21;
pub const SET_CUSTOM_MINING_JOB: u8 = 0x22;
pub const SET_CUSTOM_MINING_JOB_SUCCESS: u8 = 0x23;
pub const SET_CUSTOM_MINING_JOB_ERROR: u8 = 0x24;

/// Message types, Job Declaration Protocol.
pub const ALLOCATE_MINING_JOB_TOKEN: u8 = 0x50;
pub const ALLOCATE_MINING_JOB_TOKEN_SUCCESS: u8 = 0x51;
pub const DECLARE_MINING_JOB: u8 = 0x57;
pub const DECLARE_MINING_JOB_SUCCESS: u8 = 0x58;
pub const DECLARE_MINING_JOB_ERROR: u8 = 0x59;
pub const PUSH_SOLUTION: u8 = 0x60;

/// `SetupConnection.protocol` for the Mining Protocol.
pub const PROTOCOL_MINING: u8 = 0;
/// `SetupConnection.protocol` for the Job Declaration Protocol.
pub const PROTOCOL_JOB_DECLARATION: u8 = 1;
/// The only Stratum V2 protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
/// `SetupConnection.flags` (Mining Protocol): the client wants to select its
/// own work, which needs Job Declaration.
pub const REQUIRES_WORK_SELECTION: u32 = 1 << 1;

/// Whether a message type carries the `channel_msg` bit (the top bit of
/// `extension_type`): set on every message addressed to a specific channel.
pub fn is_channel_message(msg_type: u8) -> bool {
    matches!(
        msg_type,
        NEW_MINING_JOB
            | NEW_EXTENDED_MINING_JOB
            | SET_NEW_PREV_HASH
            | SET_TARGET
            | SUBMIT_SHARES_STANDARD
            | SUBMIT_SHARES_EXTENDED
            | SUBMIT_SHARES_SUCCESS
            | SUBMIT_SHARES_ERROR
    )
}

/// A payload that could not be decoded.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct DecodeError(String);

/// Cursor over a payload.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < self.pos + n {
            return Err(DecodeError(format!(
                "truncated at offset {} (need {n} more bytes, have {})",
                self.pos,
                self.buf.len() - self.pos
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn f32(&mut self) -> Result<f32, DecodeError> {
        Ok(f32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn u256(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn str0255(&mut self) -> Result<String, DecodeError> {
        let n = self.u8()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn b0255(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u8()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn b064k(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u16()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    /// `Seq064K<U256>`: a 2-byte count, then 32 bytes each.
    fn seq064k_u256(&mut self) -> Result<Vec<[u8; 32]>, DecodeError> {
        let n = self.u16()? as usize;
        (0..n).map(|_| self.u256()).collect()
    }

    /// `Seq0255<U256>`: a 1-byte count, then 32 bytes each.
    fn seq0255_u256(&mut self) -> Result<Vec<[u8; 32]>, DecodeError> {
        let n = self.u8()? as usize;
        (0..n).map(|_| self.u256()).collect()
    }

    fn b032(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u8()? as usize;
        if n > 32 {
            return Err(DecodeError(format!("B032 length {n} exceeds 32")));
        }
        Ok(self.take(n)?.to_vec())
    }
}

fn push_str0255(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(255);
    out.push(n as u8);
    out.extend_from_slice(&bytes[..n]);
}

/// `SetupConnection` (0x00), the fields the server uses.
#[derive(Debug, Clone, PartialEq)]
pub struct SetupConnection {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

pub fn decode_setup_connection(payload: &[u8]) -> Result<SetupConnection, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(SetupConnection {
        protocol: r.u8()?,
        min_version: r.u16()?,
        max_version: r.u16()?,
        flags: r.u32()?,
        endpoint_host: r.str0255()?,
        endpoint_port: r.u16()?,
        vendor: r.str0255()?,
        hardware_version: r.str0255()?,
        firmware: r.str0255()?,
        device_id: r.str0255()?,
    })
}

/// `SetupConnectionSuccess` (0x01): `used_version: u16`, `flags: u32`.
pub fn setup_connection_success(used_version: u16, flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&used_version.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out
}

/// `SetupConnectionError` (0x02): `flags: u32`, `error_code: Str0255`.
pub fn setup_connection_error(flags: u32, error_code: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + error_code.len());
    out.extend_from_slice(&flags.to_le_bytes());
    push_str0255(&mut out, error_code);
    out
}

/// `OpenStandardMiningChannel` (0x10).
#[derive(Debug, Clone, PartialEq)]
pub struct OpenStandardMiningChannel {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// Little-endian, as on the wire.
    pub max_target: [u8; 32],
}

pub fn decode_open_standard_mining_channel(
    payload: &[u8],
) -> Result<OpenStandardMiningChannel, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(OpenStandardMiningChannel {
        request_id: r.u32()?,
        user_identity: r.str0255()?,
        nominal_hash_rate: r.f32()?,
        max_target: r.u256()?,
    })
}

/// `OpenExtendedMiningChannel` (0x13).
#[derive(Debug, Clone, PartialEq)]
pub struct OpenExtendedMiningChannel {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// Little-endian, as on the wire.
    pub max_target: [u8; 32],
    pub min_extranonce_size: u16,
}

pub fn decode_open_extended_mining_channel(
    payload: &[u8],
) -> Result<OpenExtendedMiningChannel, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(OpenExtendedMiningChannel {
        request_id: r.u32()?,
        user_identity: r.str0255()?,
        nominal_hash_rate: r.f32()?,
        max_target: r.u256()?,
        min_extranonce_size: r.u16()?,
    })
}

/// `OpenStandardMiningChannelSuccess` (0x11): `request_id`, `channel_id`,
/// `target: U256`, `extranonce_prefix: B032`, `group_channel_id`.
pub fn open_standard_mining_channel_success(
    request_id: u32,
    channel_id: u32,
    target_le: &[u8; 32],
    extranonce_prefix: &[u8],
    group_channel_id: u32,
) -> Vec<u8> {
    assert!(extranonce_prefix.len() <= 32, "extranonce_prefix must fit in B032");
    let mut out = Vec::with_capacity(45 + extranonce_prefix.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(target_le);
    out.push(extranonce_prefix.len() as u8);
    out.extend_from_slice(extranonce_prefix);
    out.extend_from_slice(&group_channel_id.to_le_bytes());
    out
}

/// `OpenExtendedMiningChannelSuccess` (0x14): `request_id`, `channel_id`,
/// `target: U256`, `extranonce_size: u16`, `extranonce_prefix: B032`,
/// `group_channel_id`.
pub fn open_extended_mining_channel_success(
    request_id: u32,
    channel_id: u32,
    target_le: &[u8; 32],
    extranonce_size: u16,
    extranonce_prefix: &[u8],
    group_channel_id: u32,
) -> Vec<u8> {
    assert!(extranonce_prefix.len() <= 32, "extranonce_prefix must fit in B032");
    let mut out = Vec::with_capacity(47 + extranonce_prefix.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(target_le);
    out.extend_from_slice(&extranonce_size.to_le_bytes());
    out.push(extranonce_prefix.len() as u8);
    out.extend_from_slice(extranonce_prefix);
    out.extend_from_slice(&group_channel_id.to_le_bytes());
    out
}

/// `OpenMiningChannelError` (0x12): `request_id`, `error_code: Str0255`.
pub fn open_mining_channel_error(request_id: u32, error_code: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + error_code.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    push_str0255(&mut out, error_code);
    out
}

/// `NewMiningJob` (0x15): `channel_id`, `job_id`, `min_ntime:
/// Sv2Option<u32>`, `version`, `merkle_root: U256`. No `min_ntime` makes it a
/// future job, activated by a later `SetNewPrevHash`.
pub fn new_mining_job(
    channel_id: u32,
    job_id: u32,
    min_ntime: Option<u32>,
    version: i32,
    merkle_root: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(49);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());
    push_option_u32(&mut out, min_ntime);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(merkle_root);
    out
}

/// `NewExtendedMiningJob` (0x1f): `channel_id`, `job_id`, `min_ntime:
/// Sv2Option<u32>`, `version`, `version_rolling_allowed: bool`, `merkle_path:
/// Seq0_255<U256>`, `coinbase_tx_prefix: B064K`, `coinbase_tx_suffix: B064K`.
///
/// The miner's coinbase is `coinbase_tx_prefix ++ extranonce_prefix ++
/// extranonce ++ coinbase_tx_suffix`, where `extranonce_prefix` came with
/// the channel and `extranonce` is the miner's own.
#[allow(clippy::too_many_arguments)]
pub fn new_extended_mining_job(
    channel_id: u32,
    job_id: u32,
    min_ntime: Option<u32>,
    version: i32,
    version_rolling_allowed: bool,
    merkle_path: &[[u8; 32]],
    coinbase_tx_prefix: &[u8],
    coinbase_tx_suffix: &[u8],
) -> Vec<u8> {
    assert!(merkle_path.len() <= 255, "merkle_path must fit in Seq0_255");
    assert!(coinbase_tx_prefix.len() <= u16::MAX as usize, "prefix must fit in B064K");
    assert!(coinbase_tx_suffix.len() <= u16::MAX as usize, "suffix must fit in B064K");
    let mut out = Vec::with_capacity(
        23 + merkle_path.len() * 32 + coinbase_tx_prefix.len() + coinbase_tx_suffix.len(),
    );
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());
    push_option_u32(&mut out, min_ntime);
    out.extend_from_slice(&version.to_le_bytes());
    out.push(u8::from(version_rolling_allowed));
    out.push(merkle_path.len() as u8);
    for sibling in merkle_path {
        out.extend_from_slice(sibling);
    }
    out.extend_from_slice(&(coinbase_tx_prefix.len() as u16).to_le_bytes());
    out.extend_from_slice(coinbase_tx_prefix);
    out.extend_from_slice(&(coinbase_tx_suffix.len() as u16).to_le_bytes());
    out.extend_from_slice(coinbase_tx_suffix);
    out
}

fn push_option_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_le_bytes());
        }
    }
}

/// `SetNewPrevHash` (0x20): `channel_id`, `job_id`, `prev_hash: U256` (the
/// header's byte order), `min_ntime`, `nbits`.
pub fn set_new_prev_hash(
    channel_id: u32,
    job_id: u32,
    prev_hash: &[u8; 32],
    min_ntime: u32,
    nbits: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());
    out.extend_from_slice(prev_hash);
    out.extend_from_slice(&min_ntime.to_le_bytes());
    out.extend_from_slice(&nbits.to_le_bytes());
    out
}

/// `SetTarget` (0x21): `channel_id`, `maximum_target: U256`.
pub fn set_target(channel_id: u32, max_target_le: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(max_target_le);
    out
}

/// `SubmitSharesStandard` (0x1a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesStandard {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

pub fn decode_submit_shares_standard(payload: &[u8]) -> Result<SubmitSharesStandard, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(SubmitSharesStandard {
        channel_id: r.u32()?,
        sequence_number: r.u32()?,
        job_id: r.u32()?,
        nonce: r.u32()?,
        ntime: r.u32()?,
        version: r.u32()?,
    })
}

/// `SubmitSharesExtended` (0x1b): the standard fields plus `extranonce: B032`
/// (the miner's part only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesExtended {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
    pub extranonce: Vec<u8>,
}

pub fn decode_submit_shares_extended(payload: &[u8]) -> Result<SubmitSharesExtended, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(SubmitSharesExtended {
        channel_id: r.u32()?,
        sequence_number: r.u32()?,
        job_id: r.u32()?,
        nonce: r.u32()?,
        ntime: r.u32()?,
        version: r.u32()?,
        extranonce: r.b032()?,
    })
}

/// `SubmitSharesSuccess` (0x1c): `channel_id`, `last_sequence_number`,
/// `new_submits_accepted_count`, `new_shares_sum: u64`.
pub fn submit_shares_success(
    channel_id: u32,
    last_sequence_number: u32,
    new_submits_accepted_count: u32,
    new_shares_sum: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&last_sequence_number.to_le_bytes());
    out.extend_from_slice(&new_submits_accepted_count.to_le_bytes());
    out.extend_from_slice(&new_shares_sum.to_le_bytes());
    out
}

/// `SubmitSharesError` (0x1d): `channel_id`, `sequence_number`, `error_code:
/// Str0255`.
pub fn submit_shares_error(channel_id: u32, sequence_number: u32, error_code: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + error_code.len());
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&sequence_number.to_le_bytes());
    push_str0255(&mut out, error_code);
    out
}

fn push_b0255(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() <= 255, "B0255 holds at most 255 bytes");
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn push_b064k(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() <= u16::MAX as usize, "B064K holds at most 65535 bytes");
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// `SetCustomMiningJob` (0x22), Mining Protocol: a job built on a transaction
/// set the miner declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCustomMiningJob {
    pub channel_id: u32,
    pub request_id: u32,
    pub token: Vec<u8>,
    pub version: u32,
    /// The header's byte order.
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
    pub coinbase_tx_version: u32,
    /// At most 8 bytes, placed at the start of the coinbase scriptSig ahead of
    /// the extranonce.
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_input_n_sequence: u32,
    /// The coinbase outputs, consensus-serialized with their count.
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
}

pub fn decode_set_custom_mining_job(payload: &[u8]) -> Result<SetCustomMiningJob, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(SetCustomMiningJob {
        channel_id: r.u32()?,
        request_id: r.u32()?,
        token: r.b0255()?,
        version: r.u32()?,
        prev_hash: r.u256()?,
        min_ntime: r.u32()?,
        nbits: r.u32()?,
        coinbase_tx_version: r.u32()?,
        coinbase_prefix: r.b0255()?,
        coinbase_tx_input_n_sequence: r.u32()?,
        coinbase_tx_outputs: r.b064k()?,
        coinbase_tx_locktime: r.u32()?,
        merkle_path: r.seq0255_u256()?,
    })
}

/// `SetCustomMiningJobSuccess` (0x23): `channel_id`, `request_id`, `job_id`.
pub fn set_custom_mining_job_success(channel_id: u32, request_id: u32, job_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());
    out
}

/// `SetCustomMiningJobError` (0x24): `channel_id`, `request_id`, `error_code:
/// Str0255`.
pub fn set_custom_mining_job_error(channel_id: u32, request_id: u32, error_code: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + error_code.len());
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    push_str0255(&mut out, error_code);
    out
}

/// `AllocateMiningJobToken` (0x50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateMiningJobToken {
    pub user_identifier: String,
    pub request_id: u32,
}

pub fn decode_allocate_mining_job_token(payload: &[u8]) -> Result<AllocateMiningJobToken, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(AllocateMiningJobToken { user_identifier: r.str0255()?, request_id: r.u32()? })
}

/// `AllocateMiningJobTokenSuccess` (0x51): `request_id`, `mining_job_token:
/// B0255`, `coinbase_outputs: B064K`.
pub fn allocate_mining_job_token_success(request_id: u32, token: &[u8], coinbase_outputs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + token.len() + coinbase_outputs.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    push_b0255(&mut out, token);
    push_b064k(&mut out, coinbase_outputs);
    out
}

/// `DeclareMiningJob` (0x57).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclareMiningJob {
    pub request_id: u32,
    pub mining_job_token: Vec<u8>,
    pub version: u32,
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    /// The template's transactions by wtxid, in block order, without the
    /// coinbase.
    pub wtxid_list: Vec<[u8; 32]>,
    pub excess_data: Vec<u8>,
}

pub fn decode_declare_mining_job(payload: &[u8]) -> Result<DeclareMiningJob, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(DeclareMiningJob {
        request_id: r.u32()?,
        mining_job_token: r.b0255()?,
        version: r.u32()?,
        coinbase_tx_prefix: r.b064k()?,
        coinbase_tx_suffix: r.b064k()?,
        wtxid_list: r.seq064k_u256()?,
        excess_data: r.b064k()?,
    })
}

/// `DeclareMiningJobSuccess` (0x58): `request_id`, `new_mining_job_token`.
pub fn declare_mining_job_success(request_id: u32, new_token: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + new_token.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    push_b0255(&mut out, new_token);
    out
}

/// `DeclareMiningJobError` (0x59): `request_id`, `error_code: Str0255`,
/// `error_details: B064K`.
pub fn declare_mining_job_error(request_id: u32, error_code: &str, details: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + error_code.len() + details.len());
    out.extend_from_slice(&request_id.to_le_bytes());
    push_str0255(&mut out, error_code);
    push_b064k(&mut out, details.as_bytes());
    out
}

/// `PushSolution` (0x60).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSolution {
    /// The full extranonce: everything between the declared coinbase prefix
    /// and suffix.
    pub extranonce: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub ntime: u32,
    pub nonce: u32,
    pub nbits: u32,
    pub version: u32,
}

pub fn decode_push_solution(payload: &[u8]) -> Result<PushSolution, DecodeError> {
    let mut r = Reader::new(payload);
    Ok(PushSolution {
        extranonce: r.b032()?,
        prev_hash: r.u256()?,
        ntime: r.u32()?,
        nonce: r.u32()?,
        nbits: r.u32()?,
        version: r.u32()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::{self, B032, Str0255, U256};
    use stratum_core::common_messages_sv2::{
        Protocol, SetupConnection as RefSetupConnection, SetupConnectionError,
        SetupConnectionSuccess,
    };
    use stratum_core::mining_sv2::{
        NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannel as RefOpenExtended,
        OpenExtendedMiningChannelSuccess, OpenMiningChannelError,
        OpenStandardMiningChannel as RefOpenStandard, OpenStandardMiningChannelSuccess,
        SetNewPrevHash, SetTarget, SubmitSharesError, SubmitSharesExtended as RefExtended,
        SubmitSharesStandard as RefStandard, SubmitSharesSuccess,
    };

    #[test]
    fn message_types_and_channel_bits_match_the_reference() {
        use stratum_core::common_messages_sv2 as c;
        use stratum_core::mining_sv2 as m;
        assert_eq!(SETUP_CONNECTION, c::MESSAGE_TYPE_SETUP_CONNECTION);
        assert_eq!(SETUP_CONNECTION_SUCCESS, c::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
        assert_eq!(SETUP_CONNECTION_ERROR, c::MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
        let table = [
            (OPEN_STANDARD_MINING_CHANNEL, m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, m::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL),
            (OPEN_STANDARD_MINING_CHANNEL_SUCCESS, m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, m::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS),
            (OPEN_MINING_CHANNEL_ERROR, m::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, m::CHANNEL_BIT_OPEN_MINING_CHANNEL_ERROR),
            (OPEN_EXTENDED_MINING_CHANNEL, m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, m::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL),
            (OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, m::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS),
            (NEW_MINING_JOB, m::MESSAGE_TYPE_NEW_MINING_JOB, m::CHANNEL_BIT_NEW_MINING_JOB),
            (SUBMIT_SHARES_STANDARD, m::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, m::CHANNEL_BIT_SUBMIT_SHARES_STANDARD),
            (SUBMIT_SHARES_EXTENDED, m::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, m::CHANNEL_BIT_SUBMIT_SHARES_EXTENDED),
            (SUBMIT_SHARES_SUCCESS, m::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, m::CHANNEL_BIT_SUBMIT_SHARES_SUCCESS),
            (SUBMIT_SHARES_ERROR, m::MESSAGE_TYPE_SUBMIT_SHARES_ERROR, m::CHANNEL_BIT_SUBMIT_SHARES_ERROR),
            (NEW_EXTENDED_MINING_JOB, m::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, m::CHANNEL_BIT_NEW_EXTENDED_MINING_JOB),
            (SET_NEW_PREV_HASH, m::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, m::CHANNEL_BIT_MINING_SET_NEW_PREV_HASH),
            (SET_TARGET, m::MESSAGE_TYPE_SET_TARGET, m::CHANNEL_BIT_SET_TARGET),
        ];
        for (ours, reference, bit) in table {
            assert_eq!(ours, reference);
            assert_eq!(is_channel_message(ours), bit, "channel bit for {ours:#04x}");
        }
    }

    #[test]
    fn setup_connection_decodes_the_reference_encoding() {
        let msg = RefSetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0b100,
            endpoint_host: Str0255::try_from("192.168.1.50".to_string()).unwrap(),
            endpoint_port: 3336,
            vendor: Str0255::try_from("bitaxe".to_string()).unwrap(),
            hardware_version: Str0255::try_from("gamma".to_string()).unwrap(),
            firmware: Str0255::try_from("2.15.0".to_string()).unwrap(),
            device_id: Str0255::try_from("".to_string()).unwrap(),
        };
        let bytes = binary_sv2::to_bytes(msg).unwrap();
        let got = decode_setup_connection(&bytes).unwrap();
        assert_eq!(got.protocol, PROTOCOL_MINING);
        assert_eq!((got.min_version, got.max_version, got.flags), (2, 2, 0b100));
        assert_eq!(got.endpoint_host, "192.168.1.50");
        assert_eq!(got.endpoint_port, 3336);
        assert_eq!(got.vendor, "bitaxe");
        assert_eq!(got.firmware, "2.15.0");
        assert!(decode_setup_connection(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn setup_connection_replies_decode_with_the_reference_types() {
        let mut bytes = setup_connection_success(2, 0);
        let decoded: SetupConnectionSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!((decoded.used_version, decoded.flags), (2, 0));

        let mut bytes = setup_connection_error(REQUIRES_WORK_SELECTION, "unsupported-feature-flags");
        let decoded: SetupConnectionError = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.flags, REQUIRES_WORK_SELECTION);
        assert_eq!(decoded.error_code.inner_as_ref(), b"unsupported-feature-flags");
    }

    #[test]
    fn open_channel_requests_decode_the_reference_encoding() {
        let max_target = [0x77u8; 32];
        let standard = RefOpenStandard {
            request_id: 5u32.into(),
            user_identity: Str0255::try_from("bcrt1q.rig".to_string()).unwrap(),
            nominal_hash_rate: 1.2e12,
            max_target: U256::from(max_target),
        };
        let bytes = binary_sv2::to_bytes(standard).unwrap();
        let got = decode_open_standard_mining_channel(&bytes).unwrap();
        assert_eq!(got.request_id, 5);
        assert_eq!(got.user_identity, "bcrt1q.rig");
        assert_eq!(got.nominal_hash_rate, 1.2e12);
        assert_eq!(got.max_target, max_target);

        let extended = RefOpenExtended {
            request_id: 1,
            user_identity: Str0255::try_from("worker.1".to_string()).unwrap(),
            nominal_hash_rate: 1_000_000.0,
            max_target: U256::from(max_target),
            min_extranonce_size: 8,
        };
        let bytes = binary_sv2::to_bytes(extended).unwrap();
        let got = decode_open_extended_mining_channel(&bytes).unwrap();
        assert_eq!(got.request_id, 1);
        assert_eq!(got.user_identity, "worker.1");
        assert_eq!(got.max_target, max_target);
        assert_eq!(got.min_extranonce_size, 8);
    }

    #[test]
    fn open_channel_replies_decode_with_the_reference_types() {
        let target = [0xAAu8; 32];
        let mut bytes = open_standard_mining_channel_success(42, 7, &target, &[1, 2, 3], 0);
        let decoded: OpenStandardMiningChannelSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.get_request_id_as_u32(), 42);
        assert_eq!(decoded.channel_id, 7);
        assert_eq!(decoded.target.inner_as_ref(), &target[..]);
        assert_eq!(decoded.extranonce_prefix.inner_as_ref(), &[1, 2, 3]);

        let prefix = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut bytes = open_extended_mining_channel_success(99, 7, &target, 8, &prefix, 0);
        let decoded: OpenExtendedMiningChannelSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.request_id, 99);
        assert_eq!(decoded.extranonce_size, 8);
        assert_eq!(decoded.extranonce_prefix.inner_as_ref(), &prefix[..]);

        let mut bytes = open_mining_channel_error(42, "unknown-user");
        let decoded: OpenMiningChannelError = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.error_code.inner_as_ref(), b"unknown-user");
    }

    #[test]
    fn jobs_decode_with_the_reference_types() {
        let merkle = [0x33u8; 32];
        let mut bytes = new_mining_job(1, 99, None, 0x2000_0000, &merkle);
        let decoded: NewMiningJob = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert!(decoded.is_future());
        assert_eq!((decoded.channel_id, decoded.job_id, decoded.version), (1, 99, 0x2000_0000));
        assert_eq!(decoded.merkle_root.inner_as_ref(), &merkle[..]);
        let mut bytes = new_mining_job(1, 100, Some(1_700_000_000), 0x2000_0000, &merkle);
        let decoded: NewMiningJob = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert!(!decoded.is_future());

        let path = [[1u8; 32], [2u8; 32]];
        let mut bytes =
            new_extended_mining_job(7, 42, None, 0x2000_0000, true, &path, b"prefix", b"suffix");
        let decoded: NewExtendedMiningJob = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert!(decoded.is_future());
        assert!(decoded.version_rolling_allowed);
        assert_eq!(decoded.merkle_path.inner_as_ref().len(), 2);
        assert_eq!(decoded.coinbase_tx_prefix.inner_as_ref(), b"prefix");
        assert_eq!(decoded.coinbase_tx_suffix.inner_as_ref(), b"suffix");

        let prev = [0x55u8; 32];
        let mut bytes = set_new_prev_hash(7, 99, &prev, 1_700_000_000, 0x1d00ffff);
        let decoded: SetNewPrevHash = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.prev_hash.inner_as_ref(), &prev[..]);
        assert_eq!((decoded.min_ntime, decoded.nbits), (1_700_000_000, 0x1d00ffff));

        let mut bytes = set_target(11, &[0x77; 32]);
        let decoded: SetTarget = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.channel_id, 11);
        assert_eq!(decoded.maximum_target.inner_as_ref(), &[0x77; 32]);
    }

    #[test]
    fn job_declaration_messages_match_the_reference_types() {
        use stratum_core::binary_sv2::{B0255, B064K, Seq0255, Seq064K};
        use stratum_core::job_declaration_sv2::{
            AllocateMiningJobToken as RefAllocate, AllocateMiningJobTokenSuccess,
            DeclareMiningJob as RefDeclare, DeclareMiningJobError, DeclareMiningJobSuccess,
            PushSolution as RefPush,
        };
        use stratum_core::mining_sv2::{
            SetCustomMiningJob as RefCustom, SetCustomMiningJobError, SetCustomMiningJobSuccess,
        };
        {
            use stratum_core::job_declaration_sv2 as j;
            use stratum_core::mining_sv2 as m;
            assert_eq!(ALLOCATE_MINING_JOB_TOKEN, j::MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN);
            assert_eq!(ALLOCATE_MINING_JOB_TOKEN_SUCCESS, j::MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS);
            assert_eq!(DECLARE_MINING_JOB, j::MESSAGE_TYPE_DECLARE_MINING_JOB);
            assert_eq!(DECLARE_MINING_JOB_SUCCESS, j::MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS);
            assert_eq!(DECLARE_MINING_JOB_ERROR, j::MESSAGE_TYPE_DECLARE_MINING_JOB_ERROR);
            assert_eq!(PUSH_SOLUTION, j::MESSAGE_TYPE_PUSH_SOLUTION);
            assert_eq!(SET_CUSTOM_MINING_JOB, m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB);
            assert_eq!(SET_CUSTOM_MINING_JOB_SUCCESS, m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS);
            assert_eq!(SET_CUSTOM_MINING_JOB_ERROR, m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR);
            for (t, bit) in [
                (SET_CUSTOM_MINING_JOB, m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB),
                (SET_CUSTOM_MINING_JOB_SUCCESS, m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_SUCCESS),
                (SET_CUSTOM_MINING_JOB_ERROR, m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_ERROR),
            ] {
                assert_eq!(is_channel_message(t), bit, "{t:#04x}");
            }
        }

        let bytes = binary_sv2::to_bytes(RefAllocate {
            user_identifier: Str0255::try_from("bcrt1q.rig".to_string()).unwrap(),
            request_id: 4,
        })
        .unwrap();
        assert_eq!(
            decode_allocate_mining_job_token(&bytes).unwrap(),
            AllocateMiningJobToken { user_identifier: "bcrt1q.rig".into(), request_id: 4 }
        );
        let mut bytes = allocate_mining_job_token_success(4, &[9; 16], b"outputs");
        let decoded: AllocateMiningJobTokenSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.request_id, 4);
        assert_eq!(decoded.mining_job_token.inner_as_ref(), &[9; 16]);
        assert_eq!(decoded.coinbase_outputs.inner_as_ref(), b"outputs");

        let wtxids = vec![[1u8; 32], [2u8; 32]];
        let bytes = binary_sv2::to_bytes(RefDeclare {
            request_id: 5,
            mining_job_token: B0255::try_from(vec![7u8; 16]).unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix: B064K::try_from(b"pre".to_vec()).unwrap(),
            coinbase_tx_suffix: B064K::try_from(b"suf".to_vec()).unwrap(),
            wtxid_list: Seq064K::new(wtxids.iter().map(|w| U256::from(*w)).collect()).unwrap(),
            excess_data: B064K::try_from(Vec::new()).unwrap(),
        })
        .unwrap();
        let got = decode_declare_mining_job(&bytes).unwrap();
        assert_eq!((got.request_id, got.version), (5, 0x2000_0000));
        assert_eq!(got.mining_job_token, vec![7u8; 16]);
        assert_eq!((got.coinbase_tx_prefix.as_slice(), got.coinbase_tx_suffix.as_slice()), (&b"pre"[..], &b"suf"[..]));
        assert_eq!(got.wtxid_list, wtxids);

        let mut bytes = declare_mining_job_success(5, &[8; 16]);
        let decoded: DeclareMiningJobSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.new_mining_job_token.inner_as_ref(), &[8; 16]);
        let mut bytes = declare_mining_job_error(5, "invalid-mining-job-token", "unknown token");
        let decoded: DeclareMiningJobError = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.error_code.inner_as_ref(), b"invalid-mining-job-token");
        assert_eq!(decoded.error_details.inner_as_ref(), b"unknown token");

        let bytes = binary_sv2::to_bytes(RefPush {
            extranonce: B032::try_from(vec![3u8; 10]).unwrap(),
            prev_hash: U256::from([4u8; 32]),
            ntime: 11,
            nonce: 12,
            nbits: 13,
            version: 14,
        })
        .unwrap();
        let got = decode_push_solution(&bytes).unwrap();
        assert_eq!(got.extranonce, vec![3u8; 10]);
        assert_eq!((got.ntime, got.nonce, got.nbits, got.version), (11, 12, 13, 14));

        let bytes = binary_sv2::to_bytes(RefCustom {
            channel_id: 2,
            request_id: 3,
            token: B0255::try_from(vec![5u8; 16]).unwrap(),
            version: 0x2000_0000,
            prev_hash: U256::from([6u8; 32]),
            min_ntime: 100,
            nbits: 0x207fffff,
            coinbase_tx_version: 2,
            coinbase_prefix: B0255::try_from(vec![1, 2, 3]).unwrap(),
            coinbase_tx_input_n_sequence: 0xffff_ffff,
            coinbase_tx_outputs: B064K::try_from(b"outs".to_vec()).unwrap(),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255::new(vec![U256::from([7u8; 32])]).unwrap(),
        })
        .unwrap();
        let got = decode_set_custom_mining_job(&bytes).unwrap();
        assert_eq!((got.channel_id, got.request_id, got.min_ntime), (2, 3, 100));
        assert_eq!(got.prev_hash, [6u8; 32]);
        assert_eq!(got.coinbase_prefix, vec![1, 2, 3]);
        assert_eq!(got.coinbase_tx_outputs, b"outs".to_vec());
        assert_eq!(got.merkle_path, vec![[7u8; 32]]);

        let mut bytes = set_custom_mining_job_success(2, 3, 99);
        let decoded: SetCustomMiningJobSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!((decoded.channel_id, decoded.request_id, decoded.job_id), (2, 3, 99));
        let mut bytes = set_custom_mining_job_error(2, 3, "invalid-mining-job-token");
        let decoded: SetCustomMiningJobError = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.error_code.inner_as_ref(), b"invalid-mining-job-token");
    }

    #[test]
    fn shares_round_trip_with_the_reference_types() {
        let standard = RefStandard {
            channel_id: 7,
            sequence_number: 42,
            job_id: 99,
            nonce: 0xDEAD_BEEF,
            ntime: 1_700_000_000,
            version: 0x2000_0000,
        };
        let bytes = binary_sv2::to_bytes(standard).unwrap();
        assert_eq!(
            decode_submit_shares_standard(&bytes).unwrap(),
            SubmitSharesStandard {
                channel_id: 7,
                sequence_number: 42,
                job_id: 99,
                nonce: 0xDEAD_BEEF,
                ntime: 1_700_000_000,
                version: 0x2000_0000,
            }
        );

        let extranonce: Vec<u8> = (0u8..8).collect();
        let extended = RefExtended {
            channel_id: 7,
            sequence_number: 43,
            job_id: 99,
            nonce: 1,
            ntime: 1_700_000_001,
            version: 0x2000_0000,
            extranonce: B032::try_from(extranonce.clone()).unwrap(),
        };
        let bytes = binary_sv2::to_bytes(extended).unwrap();
        let got = decode_submit_shares_extended(&bytes).unwrap();
        assert_eq!(got.sequence_number, 43);
        assert_eq!(got.extranonce, extranonce);

        let mut bytes = submit_shares_success(7, 42, 1, 1_000);
        let decoded: SubmitSharesSuccess = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!((decoded.last_sequence_number, decoded.new_shares_sum), (42, 1_000));
        let mut bytes = submit_shares_error(7, 42, "stale-share");
        let decoded: SubmitSharesError = binary_sv2::from_bytes(&mut bytes).unwrap();
        assert_eq!(decoded.error_code.inner_as_ref(), b"stale-share");
    }
}
