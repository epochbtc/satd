//! Headers presync: Bitcoin Core's `HeadersSyncState` (v32.1
//! `src/headerssync.{h,cpp}`).
//!
//! A `headers` message tells us nothing about the work on the rest of the
//! peer's chain. Storing every header that passes proof of work would let a
//! peer fill the block index with a long chain of cheap headers. Core
//! instead downloads a chain that has not yet shown enough work twice:
//!
//! - **PRESYNC.** Headers are checked for linkage, proof of work (by the
//!   caller) and permitted difficulty transitions, and their work is summed.
//!   Nothing is kept but a salted one-bit commitment every
//!   `commitment_period` headers, so memory per peer stays small.
//! - **REDOWNLOAD.** Once the chain reaches the work threshold the same
//!   headers are asked for again from the start, checked against the
//!   commitments, and buffered. A header leaves the buffer for the block
//!   index once `redownload_buffer_size` headers are behind it, or as soon as
//!   the redownloaded chain itself reaches the threshold.
//!
//! The state lives in memory only, one per peer, held by the peer manager.
//! The caller builds the `getheaders` locator from
//! [`HeadersSyncState::next_request_start`] and the chain start.

use std::collections::VecDeque;

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, CompactTarget, Network, TxMerkleNode};

use crate::chain::state::compare_u256;
use crate::net::peer::PeerId;
use crate::storage::blockindex::{BlockIndexEntry, add_u256, work_for_bits};
use crate::validation::pow::{MAX_FUTURE_BLOCK_TIME, permitted_difficulty_transition};

/// Core's `HeadersSyncParams` (`kernel/chainparams.h`): how often a
/// commitment is kept, and how many redownloaded headers stay buffered
/// before release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadersSyncParams {
    pub commitment_period: usize,
    pub redownload_buffer_size: usize,
}

impl HeadersSyncParams {
    /// Core v32.1's values (`kernel/chainparams.cpp`). A custom signet takes
    /// the default signet's, as Core's `SigNetParams` does.
    pub fn for_network(network: Network) -> Self {
        let (commitment_period, redownload_buffer_size) = match network {
            Network::Bitcoin => (649, 15400),
            Network::Testnet => (682, 14613),
            Network::Testnet4 => (616, 16199),
            Network::Signet => (629, 15885),
            _ => (275, 7017),
        };
        Self { commitment_period, redownload_buffer_size }
    }
}

/// The block in our index that the peer's headers build on: Core's
/// `m_chain_start`.
#[derive(Clone, Debug)]
pub struct ChainStart {
    pub hash: BlockHash,
    pub height: u32,
    pub chainwork: [u8; 32],
    pub header: Header,
    /// The block's median time past.
    pub median_time_past: u32,
}

impl ChainStart {
    pub fn new(hash: BlockHash, entry: &BlockIndexEntry, median_time_past: u32) -> Self {
        Self {
            hash,
            height: entry.height,
            chainwork: entry.chainwork,
            header: entry.header,
            median_time_past,
        }
    }
}

/// Core's `SystemClockError`: the clock is more than
/// [`MAX_FUTURE_BLOCK_TIME`] behind the chain start's median time past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemClockError {
    pub now: u64,
    pub chain_start_mtp: u32,
}

impl std::fmt::Display for SystemClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "System clock is more than {} minutes behind chain start MTP ({} vs {}).",
            MAX_FUTURE_BLOCK_TIME / 60,
            crate::time::format_iso8601(self.now),
            crate::time::format_iso8601(u64::from(self.chain_start_mtp)),
        )
    }
}

/// Core's `HeadersSyncState::State`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Presync,
    Redownload,
    Final,
}

/// Core's `ProcessingResult`.
#[derive(Debug, Default)]
pub struct ProcessingResult {
    /// Headers that have passed the work threshold and may now be fully
    /// validated and stored.
    pub pow_validated_headers: Vec<Header>,
    pub success: bool,
    /// Send another `getheaders`, from [`HeadersSyncState::next_request_start`].
    pub request_more: bool,
}

/// A header without its `prev_blockhash`: Core's `CompressedHeader`, 48
/// bytes.
#[derive(Clone, Copy, Debug)]
struct CompressedHeader {
    version: i32,
    merkle_root: [u8; 32],
    time: u32,
    bits: u32,
    nonce: u32,
}

impl CompressedHeader {
    fn new(h: &Header) -> Self {
        Self {
            version: h.version.to_consensus(),
            merkle_root: h.merkle_root.to_byte_array(),
            time: h.time,
            bits: h.bits.to_consensus(),
            nonce: h.nonce,
        }
    }

    fn full_header(&self, prev: BlockHash) -> Header {
        Header {
            version: Version::from_consensus(self.version),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(self.merkle_root),
            time: self.time,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
        }
    }
}

/// A queue of bits, packed 64 to a word: Core's `bitdeque`. Bits are only
/// pushed during PRESYNC and only popped during REDOWNLOAD, so a read
/// cursor over a growing vector does; its memory is bounded by
/// `max_commitments` and freed when the sync ends.
#[derive(Debug, Default)]
struct BitQueue {
    words: Vec<u64>,
    len: usize,
    head: usize,
}

impl BitQueue {
    fn push_back(&mut self, bit: bool) {
        let (word, offset) = (self.len / 64, self.len % 64);
        if word == self.words.len() {
            self.words.push(0);
        }
        if bit {
            self.words[word] |= 1 << offset;
        }
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<bool> {
        if self.head == self.len {
            return None;
        }
        let bit = self.words[self.head / 64] >> (self.head % 64) & 1 == 1;
        self.head += 1;
        Some(bit)
    }

    fn size(&self) -> usize {
        self.len - self.head
    }

    fn heap_bytes(&self) -> usize {
        self.words.capacity() * 8
    }
}

/// One peer's low-work headers sync. See the module documentation.
#[derive(Debug)]
pub struct HeadersSyncState {
    id: PeerId,
    network: Network,
    params: HeadersSyncParams,
    /// Commitments are kept at heights `h` where
    /// `h % commitment_period == commit_offset`. Secret, so the peer cannot
    /// tell which headers are checked.
    commit_offset: usize,
    /// The salt of the one-bit commitment hash: Core's `SaltedUint256Hasher`.
    hash_keys: (u64, u64),
    chain_start: ChainStart,
    minimum_required_work: [u8; 32],
    current_chain_work: [u8; 32],
    header_commitments: BitQueue,
    /// The longest a consensus-valid chain could be right now, in
    /// commitments: six blocks a second (the fastest the MTP rule allows)
    /// since the chain start, plus two hours.
    max_commitments: u64,
    last_header_received: Header,
    /// Hash of `last_header_received`, cached.
    last_header_hash: BlockHash,
    current_height: i64,
    redownloaded_headers: VecDeque<CompressedHeader>,
    redownload_buffer_last_height: i64,
    redownload_buffer_last_hash: BlockHash,
    redownload_buffer_first_prev_hash: BlockHash,
    redownload_chain_work: [u8; 32],
    process_all_remaining_headers: bool,
    state: State,
}

impl HeadersSyncState {
    /// Core's constructor. `now` is the current time, seconds since the
    /// epoch. Fails, as Core throws, when the clock is more than
    /// [`MAX_FUTURE_BLOCK_TIME`] behind the chain start's median time past.
    pub fn new(
        id: PeerId,
        network: Network,
        params: HeadersSyncParams,
        chain_start: ChainStart,
        minimum_required_work: [u8; 32],
        now: u64,
    ) -> Result<Self, SystemClockError> {
        use rand::Rng as _;
        assert!(params.commitment_period > 0, "commitment_period must be non-zero");
        let mut rng = rand::thread_rng();
        let commit_offset = rng.gen_range(0..params.commitment_period);
        let hash_keys = (rng.r#gen(), rng.r#gen());
        Self::with_salt(id, network, params, chain_start, minimum_required_work, now, commit_offset, hash_keys)
    }

    /// [`Self::new`] with the offset and salt given, for tests.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_salt(
        id: PeerId,
        network: Network,
        params: HeadersSyncParams,
        chain_start: ChainStart,
        minimum_required_work: [u8; 32],
        now: u64,
        commit_offset: usize,
        hash_keys: (u64, u64),
    ) -> Result<Self, SystemClockError> {
        let max_seconds_since_start =
            now as i64 - i64::from(chain_start.median_time_past) + MAX_FUTURE_BLOCK_TIME as i64;
        if max_seconds_since_start < 0 {
            return Err(SystemClockError { now, chain_start_mtp: chain_start.median_time_past });
        }
        let max_commitments = 6 * max_seconds_since_start as u64 / params.commitment_period as u64;
        tracing::debug!(
            peer = id,
            height = chain_start.height,
            max_commitments,
            min_work = %hex::encode(minimum_required_work),
            "Initial headers sync started with peer={id}: height={}, max_commitments={max_commitments}",
            chain_start.height,
        );
        Ok(Self {
            id,
            network,
            params,
            commit_offset,
            hash_keys,
            current_chain_work: chain_start.chainwork,
            minimum_required_work,
            header_commitments: BitQueue::default(),
            max_commitments,
            last_header_received: chain_start.header,
            last_header_hash: chain_start.hash,
            current_height: i64::from(chain_start.height),
            redownloaded_headers: VecDeque::new(),
            redownload_buffer_last_height: 0,
            redownload_buffer_last_hash: BlockHash::all_zeros(),
            redownload_buffer_first_prev_hash: BlockHash::all_zeros(),
            redownload_chain_work: [0u8; 32],
            process_all_remaining_headers: false,
            state: State::Presync,
            chain_start,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The height reached in PRESYNC: Core's `GetPresyncHeight`.
    pub fn presync_height(&self) -> i64 {
        self.current_height
    }

    /// The timestamp of the last PRESYNC header: Core's `GetPresyncTime`.
    pub fn presync_time(&self) -> u32 {
        self.last_header_received.time
    }

    /// The work on the chain seen in PRESYNC: Core's `GetPresyncWork`.
    pub fn presync_work(&self) -> [u8; 32] {
        self.current_chain_work
    }

    /// The height the redownload has reached.
    pub fn redownload_height(&self) -> i64 {
        self.redownload_buffer_last_height
    }

    /// The chain start the peer's headers build on.
    pub fn chain_start(&self) -> &ChainStart {
        &self.chain_start
    }

    /// Bytes of per-peer state beyond the struct itself: the commitment
    /// bits and the redownload buffer.
    pub fn heap_bytes(&self) -> usize {
        self.header_commitments.heap_bytes()
            + self.redownloaded_headers.capacity() * std::mem::size_of::<CompressedHeader>()
    }

    fn commitment_bit(&self, hash: &BlockHash) -> bool {
        bitcoin::hashes::siphash24::Hash::hash_to_u64_with_keys(
            self.hash_keys.0,
            self.hash_keys.1,
            hash.as_byte_array(),
        ) & 1
            == 1
    }

    /// Core's `Finalize`: drop all state; the object is not used again.
    fn finalize(&mut self) {
        self.header_commitments = BitQueue::default();
        self.redownloaded_headers = VecDeque::new();
        self.redownload_buffer_last_hash = BlockHash::all_zeros();
        self.redownload_buffer_first_prev_hash = BlockHash::all_zeros();
        self.process_all_remaining_headers = false;
        self.current_height = 0;
        self.state = State::Final;
    }

    /// Core's `ProcessNextHeaders`. `headers` must be non-empty, continuous,
    /// and meet the proof of work they claim; `full_message` is whether the
    /// message held the most headers one may.
    pub fn process_next_headers(&mut self, headers: &[Header], full_message: bool) -> ProcessingResult {
        let mut ret = ProcessingResult::default();
        if headers.is_empty() || self.state == State::Final {
            return ret;
        }
        let id = self.id;
        match self.state {
            State::Presync => {
                ret.success = self.validate_and_store_headers_commitments(headers);
                if ret.success {
                    if full_message || self.state == State::Redownload {
                        ret.request_more = true;
                    } else {
                        tracing::debug!(
                            "Initial headers sync aborted with peer={id}: incomplete headers message at height={} (presync phase)",
                            self.current_height
                        );
                    }
                }
            }
            State::Redownload => {
                ret.success = headers.iter().all(|h| self.validate_and_store_redownloaded_header(h));
                if ret.success {
                    ret.pow_validated_headers = self.pop_headers_ready_for_acceptance();
                    if self.redownloaded_headers.is_empty() && self.process_all_remaining_headers {
                        tracing::debug!(
                            "Initial headers sync complete with peer={id}: releasing all at height={} (redownload phase)",
                            self.redownload_buffer_last_height
                        );
                    } else if full_message {
                        ret.request_more = true;
                    } else {
                        tracing::debug!(
                            "Initial headers sync aborted with peer={id}: incomplete headers message at height={} (redownload phase)",
                            self.redownload_buffer_last_height
                        );
                    }
                }
            }
            State::Final => {}
        }
        if !(ret.success && ret.request_more) {
            self.finalize();
        }
        ret
    }

    fn validate_and_store_headers_commitments(&mut self, headers: &[Header]) -> bool {
        let id = self.id;
        if headers[0].prev_blockhash != self.last_header_hash {
            tracing::debug!(
                "Initial headers sync aborted with peer={id}: non-continuous headers at height={} (presync phase)",
                self.current_height
            );
            return false;
        }
        for h in headers {
            if !self.validate_and_process_single_header(h) {
                return false;
            }
        }
        if compare_u256(&self.current_chain_work, &self.minimum_required_work) >= 0 {
            self.redownloaded_headers.clear();
            self.redownload_buffer_last_height = i64::from(self.chain_start.height);
            self.redownload_buffer_first_prev_hash = self.chain_start.hash;
            self.redownload_buffer_last_hash = self.chain_start.hash;
            self.redownload_chain_work = self.chain_start.chainwork;
            self.state = State::Redownload;
            tracing::debug!(
                "Initial headers sync transition with peer={id}: reached sufficient work at height={}, redownloading from height={}",
                self.current_height,
                self.redownload_buffer_last_height
            );
        }
        true
    }

    fn validate_and_process_single_header(&mut self, current: &Header) -> bool {
        let id = self.id;
        let next_height = self.current_height + 1;
        if !permitted_difficulty_transition(
            self.network,
            next_height as u32,
            self.last_header_received.bits.to_consensus(),
            current.bits.to_consensus(),
        ) {
            tracing::debug!(
                "Initial headers sync aborted with peer={id}: invalid difficulty transition at height={next_height} (presync phase)"
            );
            return false;
        }
        let hash = current.block_hash();
        if next_height as usize % self.params.commitment_period == self.commit_offset {
            let bit = self.commitment_bit(&hash);
            self.header_commitments.push_back(bit);
            if self.header_commitments.size() as u64 > self.max_commitments {
                tracing::debug!(
                    "Initial headers sync aborted with peer={id}: exceeded max commitments at height={next_height} (presync phase)"
                );
                return false;
            }
        }
        self.current_chain_work = add_u256(&self.current_chain_work, &work_for_bits(current.bits));
        self.last_header_received = *current;
        self.last_header_hash = hash;
        self.current_height = next_height;
        true
    }

    fn validate_and_store_redownloaded_header(&mut self, header: &Header) -> bool {
        let id = self.id;
        let next_height = self.redownload_buffer_last_height + 1;
        if header.prev_blockhash != self.redownload_buffer_last_hash {
            tracing::debug!(
                "Initial headers sync aborted with peer={id}: non-continuous headers at height={next_height} (redownload phase)"
            );
            return false;
        }
        let previous_bits = match self.redownloaded_headers.back() {
            Some(h) => h.bits,
            None => self.chain_start.header.bits.to_consensus(),
        };
        if !permitted_difficulty_transition(self.network, next_height as u32, previous_bits, header.bits.to_consensus()) {
            tracing::debug!(
                "Initial headers sync aborted with peer={id}: invalid difficulty transition at height={next_height} (redownload phase)"
            );
            return false;
        }
        self.redownload_chain_work = add_u256(&self.redownload_chain_work, &work_for_bits(header.bits));
        if compare_u256(&self.redownload_chain_work, &self.minimum_required_work) >= 0 {
            self.process_all_remaining_headers = true;
        }
        let hash = header.block_hash();
        // Once the target is reached the commitments are not checked: the
        // peer's chain may have grown since the first pass.
        if !self.process_all_remaining_headers
            && next_height as usize % self.params.commitment_period == self.commit_offset
        {
            let Some(expected) = self.header_commitments.pop_front() else {
                tracing::debug!(
                    "Initial headers sync aborted with peer={id}: commitment overrun at height={next_height} (redownload phase)"
                );
                return false;
            };
            if self.commitment_bit(&hash) != expected {
                tracing::debug!(
                    "Initial headers sync aborted with peer={id}: commitment mismatch at height={next_height} (redownload phase)"
                );
                return false;
            }
        }
        self.redownloaded_headers.push_back(CompressedHeader::new(header));
        self.redownload_buffer_last_height = next_height;
        self.redownload_buffer_last_hash = hash;
        true
    }

    fn pop_headers_ready_for_acceptance(&mut self) -> Vec<Header> {
        let mut ret = Vec::new();
        if self.state != State::Redownload {
            return ret;
        }
        while self.redownloaded_headers.len() > self.params.redownload_buffer_size
            || (!self.redownloaded_headers.is_empty() && self.process_all_remaining_headers)
        {
            let Some(front) = self.redownloaded_headers.pop_front() else { break };
            let header = front.full_header(self.redownload_buffer_first_prev_hash);
            self.redownload_buffer_first_prev_hash = header.block_hash();
            ret.push(header);
        }
        ret
    }

    /// The first locator entry of the next `getheaders`: Core's
    /// `NextHeadersRequestLocator` puts this before the chain start's own
    /// locator. `None` once the sync is over.
    pub fn next_request_start(&self) -> Option<BlockHash> {
        match self.state {
            State::Presync => Some(self.last_header_hash),
            State::Redownload => Some(self.redownload_buffer_last_hash),
            State::Final => None,
        }
    }
}

#[cfg(test)]
#[path = "headerssync_tests.rs"]
mod tests;
