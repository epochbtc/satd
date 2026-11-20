//! `HeadersSyncState` on regtest header chains: Core's
//! `headers_sync_chainwork_tests.cpp` cases, and the bounds on what a peer
//! can make it hold.

use super::*;
use crate::validation::pow::check_proof_of_work;

const KEYS: (u64, u64) = (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);

fn regtest_genesis() -> (BlockHash, BlockIndexEntry) {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let entry = BlockIndexEntry {
        header: genesis.header,
        height: 0,
        status: crate::storage::blockindex::BlockStatus::Valid,
        num_tx: 1,
        file_number: 0,
        data_pos: 0,
        chainwork: work_for_bits(genesis.header.bits),
    };
    (genesis.block_hash(), entry)
}

fn chain_start() -> ChainStart {
    let (hash, entry) = regtest_genesis();
    ChainStart::new(hash, &entry, entry.header.time)
}

/// `n` regtest headers on `prev`, `tag` telling chains apart.
fn chain_on(prev: BlockHash, n: usize, time_base: u32, tag: u8) -> Vec<Header> {
    let mut parent = prev;
    (0..n)
        .map(|i| {
            let mut h = Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: parent,
                merkle_root: TxMerkleNode::from_byte_array([tag; 32]),
                time: time_base + i as u32,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            while check_proof_of_work(&h).is_err() {
                h.nonce += 1;
            }
            parent = h.block_hash();
            h
        })
        .collect()
}

fn genesis_chain(n: usize, tag: u8) -> Vec<Header> {
    chain_on(regtest_genesis().0, n, 1_600_000_000, tag)
}

/// The work of `n` regtest headers on top of genesis.
fn work_at(n: usize) -> [u8; 32] {
    let one = work_for_bits(CompactTarget::from_consensus(0x207f_ffff));
    (0..=n).fold([0u8; 32], |acc, _| add_u256(&acc, &one))
}

fn state(min_work: [u8; 32]) -> HeadersSyncState {
    HeadersSyncState::with_salt(
        1,
        Network::Regtest,
        HeadersSyncParams::for_network(Network::Regtest),
        chain_start(),
        min_work,
        1_700_000_000,
        7,
        KEYS,
    )
    .unwrap()
}

/// Feed `headers` in full messages of 2000, the last one short if it is.
fn feed(sync: &mut HeadersSyncState, headers: &[Header]) -> (Vec<Header>, Vec<ProcessingResult>) {
    let mut released = Vec::new();
    let mut results = Vec::new();
    for batch in headers.chunks(2000) {
        let mut r = sync.process_next_headers(batch, batch.len() == 2000);
        released.append(&mut r.pow_validated_headers);
        results.push(r);
    }
    (released, results)
}

#[test]
fn params_follow_cores_chainparams() {
    let p = |n| {
        let p = HeadersSyncParams::for_network(n);
        (p.commitment_period, p.redownload_buffer_size)
    };
    assert_eq!(p(Network::Bitcoin), (649, 15400));
    assert_eq!(p(Network::Testnet), (682, 14613));
    assert_eq!(p(Network::Testnet4), (616, 16199));
    assert_eq!(p(Network::Signet), (629, 15885));
    assert_eq!(p(Network::Regtest), (275, 7017));
}

/// A chain that never reaches the threshold releases nothing, asks for more
/// on every full message, and ends on the first short one.
#[test]
fn a_low_work_chain_is_never_released() {
    let chain = genesis_chain(4100, 1);
    let mut sync = state(work_at(100_000));
    let (released, results) = feed(&mut sync, &chain);
    assert!(released.is_empty());
    assert!(results[0].success && results[0].request_more);
    assert!(results[1].success && results[1].request_more);
    assert!(results[2].success && !results[2].request_more, "a short message ends the sync");
    assert_eq!(sync.state(), State::Final);
}

/// Core's happy path: the chain reaches the threshold in PRESYNC, the same
/// headers come back in REDOWNLOAD, and every one of them is released in
/// order, the buffered tail once the redownloaded work reaches the target.
#[test]
fn a_chain_that_reaches_the_threshold_is_released_on_redownload() {
    let chain = genesis_chain(10_000, 2);
    let mut sync = state(work_at(9_000));
    let first_pass = &chain[..10_000];
    let (released, results) = feed(&mut sync, first_pass);
    assert!(released.is_empty(), "nothing is released in PRESYNC");
    assert!(results.iter().all(|r| r.success && r.request_more));
    assert_eq!(sync.state(), State::Redownload);
    assert_eq!(sync.next_request_start(), Some(chain_start().hash), "redownload starts over");

    let mut all = Vec::new();
    for (i, batch) in chain.chunks(2000).enumerate() {
        let r = sync.process_next_headers(batch, true);
        assert!(r.success);
        // Until the target is passed, only headers more than the buffer
        // behind the newest one come out.
        let received = (i + 1) * 2000;
        if received < 9_000 {
            assert_eq!(all.len() + r.pow_validated_headers.len(), received.saturating_sub(7017));
        }
        all.extend(r.pow_validated_headers);
    }
    assert_eq!(all, chain, "every header released, in order");
    assert_eq!(sync.state(), State::Final);
}

/// Core's `SneakyRedownload`: a peer that shows one chain's work in PRESYNC
/// and serves a different chain in REDOWNLOAD is caught by the commitments
/// before the swapped chain is released.
#[test]
fn a_peer_that_switches_chains_between_the_passes_is_caught() {
    let honest = genesis_chain(10_000, 3);
    let sneaky = genesis_chain(10_000, 4);
    let mut sync = state(work_at(9_000));
    feed(&mut sync, &honest);
    assert_eq!(sync.state(), State::Redownload);

    let mut released = 0;
    let mut failed = false;
    for batch in sneaky.chunks(2000) {
        let r = sync.process_next_headers(batch, true);
        released += r.pow_validated_headers.len();
        if !r.success {
            failed = true;
            break;
        }
    }
    assert!(failed, "the switched chain was not caught");
    assert_eq!(released, 0, "nothing from the switched chain was released");
    assert_eq!(sync.state(), State::Final);
}

/// A PRESYNC message that does not follow on from the last header ends the
/// sync, as Core's does (the peer may have reorged).
#[test]
fn non_continuous_presync_headers_end_the_sync() {
    let chain = genesis_chain(4000, 5);
    let mut sync = state(work_at(100_000));
    assert!(sync.process_next_headers(&chain[..2000], true).success);
    let r = sync.process_next_headers(&chain[..2000], true);
    assert!(!r.success);
    assert_eq!(sync.state(), State::Final);
}

/// Per-peer memory: a PRESYNC of 20,000 headers keeps one bit per
/// commitment period, a few hundred bytes, however long the chain.
#[test]
fn presync_memory_stays_bounded() {
    let chain = genesis_chain(20_000, 6);
    let mut sync = state(work_at(1_000_000));
    feed(&mut sync, &chain);
    assert_eq!(sync.state(), State::Presync);
    assert_eq!(sync.presync_height(), 20_000);
    // 20,000 / 275 = 72 bits: two words.
    assert!(sync.heap_bytes() <= 64, "presync holds {} bytes", sync.heap_bytes());
}

/// A chain longer than the MTP rule lets one exist since the chain start
/// is given up on, which bounds the commitments a peer can make us keep.
#[test]
fn a_chain_longer_than_possible_is_given_up() {
    let start = chain_start();
    let now = u64::from(start.median_time_past) + 1;
    let mut sync = HeadersSyncState::with_salt(
        1,
        Network::Regtest,
        HeadersSyncParams::for_network(Network::Regtest),
        start,
        work_at(1_000_000),
        now,
        7,
        KEYS,
    )
    .unwrap();
    // 6 blocks/s for 2 h is 43,200 blocks, 157 commitments; 44,000 exceed it.
    let chain = genesis_chain(44_000, 7);
    let (_, results) = feed(&mut sync, &chain);
    assert!(!results.last().unwrap().success);
    assert_eq!(sync.state(), State::Final);
}

/// Core throws `SystemClockError` when the clock is more than two hours
/// behind the chain start's median time past.
#[test]
fn a_clock_far_behind_the_chain_start_is_an_error() {
    let start = chain_start();
    let mtp = u64::from(start.median_time_past);
    let params = HeadersSyncParams::for_network(Network::Regtest);
    let err = HeadersSyncState::new(1, Network::Regtest, params, start.clone(), [0; 32], mtp - 7201).unwrap_err();
    assert!(err.to_string().starts_with("System clock is more than 120 minutes behind chain start MTP"), "{err}");
    assert!(HeadersSyncState::new(1, Network::Regtest, params, start, [0; 32], mtp - 7200).is_ok());
}
