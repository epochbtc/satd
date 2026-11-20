//! Inbound peer eviction: Bitcoin Core's `SelectNodeToEvict` and
//! `ProtectEvictionCandidatesByRatio` (v32.1 `src/node/eviction.cpp`).
//!
//! The selection first protects peers with distinct characteristics that are
//! hard to forge (netgroup, ping time, useful transactions and blocks, uptime,
//! privacy networks), then evicts the youngest peer of the network group with
//! the most connections among those left. `None` means every candidate is
//! protected.
//!
//! One satd addition: under `-peerflagpolicy=evict` a candidate the manager
//! marks [`EvictionCandidate::flagged`] gets none of those protections and is
//! evicted before any other. Under the default `observe` no candidate is
//! marked and the selection is Core's, step for step.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::net::peer::PeerId;
use crate::net::reachable::Network;

/// One peer as the eviction logic sees it: Core's `NodeEvictionCandidate`.
#[derive(Debug, Clone)]
pub struct EvictionCandidate {
    pub id: PeerId,
    /// Unix seconds the connection was made (`m_connected`).
    pub connected: u64,
    /// Best round trip in microseconds; `u64::MAX` when never measured
    /// (`m_min_ping_time`, which Core starts at its maximum).
    pub min_ping_us: u64,
    /// Unix seconds of the last novel block from this peer, 0 = never.
    pub last_block_time: u64,
    /// Unix seconds of the last transaction from this peer accepted into the
    /// mempool, 0 = never.
    pub last_tx_time: u64,
    /// The peer offers every service we want from it (`fRelevantServices`,
    /// Core's `HasAllDesirableServiceFlags`).
    pub relevant_services: bool,
    /// The peer asked for transaction relay (`m_relay_txs`).
    pub relay_txs: bool,
    /// The peer loaded a BIP 37 filter (`fBloomFilter`). satd does not offer
    /// `NODE_BLOOM`, so this is always false in the node.
    pub bloom_filter: bool,
    /// The peer's network group under a per-node secret key
    /// (`nKeyedNetGroup`).
    pub keyed_net_group: u64,
    /// Evict this peer before the others (`prefer_evict`). Core sets it for
    /// a discouraged inbound peer; satd refuses banned peers outright and has
    /// no discouraged state, so it is false in the node.
    pub prefer_evict: bool,
    /// Loopback or `0.0.0.0/8` (`m_is_local`, Core's `CNetAddr::IsLocal`).
    pub is_local: bool,
    /// The network the connection came through (`m_network`); `None` for an
    /// address that is not publicly routable (Core's `NET_UNROUTABLE`).
    pub network: Option<Network>,
    /// `noban` permission (`m_noban`).
    pub noban: bool,
    /// An inbound connection; every other type is protected
    /// (`m_conn_type == ConnectionType::INBOUND`).
    pub inbound: bool,
    /// satd: the peer carries a flag `-peerflagpolicy=evict` acts on (`C`,
    /// `S` or `F`) and no permission that exempts it. Always false under
    /// `observe`. Not in Core.
    pub flagged: bool,
}

/// A strict-weak "less than" turned into the `Ordering` Rust's sort takes.
fn ordering(less: impl Fn(&EvictionCandidate, &EvictionCandidate) -> bool, a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    if less(a, b) {
        Ordering::Less
    } else if less(b, a) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn reverse_compare_node_min_ping_time(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    a.min_ping_us > b.min_ping_us
}

fn reverse_compare_node_time_connected(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    a.connected > b.connected
}

fn compare_net_group_keyed(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    a.keyed_net_group < b.keyed_net_group
}

fn compare_node_block_time(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    // A fall-through, as many peers have not yet relayed a block.
    if a.last_block_time != b.last_block_time {
        return a.last_block_time < b.last_block_time;
    }
    if a.relevant_services != b.relevant_services {
        return b.relevant_services;
    }
    a.connected > b.connected
}

fn compare_node_tx_time(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    // A fall-through, as many peers have not yet relayed a transaction.
    if a.last_tx_time != b.last_tx_time {
        return a.last_tx_time < b.last_tx_time;
    }
    if a.relay_txs != b.relay_txs {
        return b.relay_txs;
    }
    if a.bloom_filter != b.bloom_filter {
        return a.bloom_filter;
    }
    a.connected > b.connected
}

/// Picks out the potential block-relay-only peers and sorts them by the time
/// of their last novel block.
fn compare_node_block_relay_only_time(a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
    if a.relay_txs != b.relay_txs {
        return a.relay_txs;
    }
    if a.last_block_time != b.last_block_time {
        return a.last_block_time < b.last_block_time;
    }
    if a.relevant_services != b.relevant_services {
        return b.relevant_services;
    }
    a.connected > b.connected
}

/// A disadvantaged class [`protect_eviction_candidates_by_ratio`] reserves
/// protection for: localhost, or one privacy network.
#[derive(Clone, Copy)]
enum Disadvantaged {
    Local,
    Net(Network),
}

impl Disadvantaged {
    fn matches(self, c: &EvictionCandidate) -> bool {
        match self {
            Self::Local => c.is_local,
            Self::Net(net) => c.network == Some(net),
        }
    }

    /// Core's `CompareNodeNetworkTime`: candidates outside the class first,
    /// then those in it, each by increasing uptime.
    fn less(self, a: &EvictionCandidate, b: &EvictionCandidate) -> bool {
        let is_local = matches!(self, Self::Local);
        if is_local && a.is_local != b.is_local {
            return b.is_local;
        }
        let net = match self {
            Self::Local => None,
            Self::Net(net) => Some(net),
        };
        let (a_in, b_in) = (net.is_some() && a.network == net, net.is_some() && b.network == net);
        if a_in != b_in {
            return b_in;
        }
        a.connected > b.connected
    }
}

/// Core's `EraseLastKElements`: sort by `less`, then drop the elements among
/// the last `k` for which `predicate` holds.
fn erase_last_k_elements(
    elements: &mut Vec<EvictionCandidate>,
    less: impl Fn(&EvictionCandidate, &EvictionCandidate) -> bool,
    k: usize,
    predicate: impl Fn(&EvictionCandidate) -> bool,
) {
    elements.sort_by(|a, b| ordering(&less, a, b));
    let erase_size = k.min(elements.len());
    let start = elements.len() - erase_size;
    let mut tail: Vec<EvictionCandidate> = elements.split_off(start);
    tail.retain(|c| !predicate(c));
    elements.extend(tail);
}

/// Core's `ProtectEvictionCandidatesByRatio`: protect the half of the
/// candidates connected the longest, reserving up to half of those places for
/// CJDNS, I2P, localhost and onion peers, which lose out on ping time.
pub fn protect_eviction_candidates_by_ratio(candidates: &mut Vec<EvictionCandidate>) {
    let initial_size = candidates.len();
    let total_protect_size = initial_size / 2;

    // In the case of equal counts, earlier members have the first
    // opportunity to recover unused slots from the previous iteration.
    let mut networks: Vec<(Disadvantaged, usize)> = [
        Disadvantaged::Net(Network::Cjdns),
        Disadvantaged::Net(Network::I2p),
        Disadvantaged::Local,
        Disadvantaged::Net(Network::Onion),
    ]
    .into_iter()
    .map(|n| (n, candidates.iter().filter(|c| n.matches(c)).count()))
    .collect();
    // Ascending candidate count, stable, as Core's `std::stable_sort`.
    networks.sort_by_key(|(_, count)| *count);

    // Protect up to 25% of the candidates by disadvantaged network.
    let max_protect_by_network = total_protect_size / 2;
    let mut num_protected = 0usize;

    while num_protected < max_protect_by_network {
        let num_networks = networks.iter().filter(|(_, count)| *count > 0).count();
        if num_networks == 0 {
            break;
        }
        let disadvantaged_to_protect = max_protect_by_network - num_protected;
        let protect_per_network = (disadvantaged_to_protect / num_networks).max(1);
        let mut protected_at_least_one = false;

        for (net, count) in networks.iter_mut() {
            if *count == 0 {
                continue;
            }
            let net = *net;
            let before = candidates.len();
            erase_last_k_elements(candidates, |a, b| net.less(a, b), protect_per_network, |c| net.matches(c));
            let after = candidates.len();
            if before > after {
                protected_at_least_one = true;
                let delta = before - after;
                num_protected += delta;
                if num_protected >= max_protect_by_network {
                    break;
                }
                *count -= delta;
            }
        }
        if !protected_at_least_one {
            break;
        }
    }

    // Protect the rest by uptime alone.
    debug_assert_eq!(num_protected, initial_size - candidates.len());
    let remaining_to_protect = total_protect_size - num_protected;
    erase_last_k_elements(candidates, reverse_compare_node_time_connected, remaining_to_protect, |_| true);
}

/// Core's `SelectNodeToEvict`: the peer to evict once the protected ones are
/// set aside, or `None` if every candidate is protected.
pub fn select_node_to_evict(mut candidates: Vec<EvictionCandidate>) -> Option<PeerId> {
    // `ProtectNoBanConnections`, `ProtectOutboundConnections`.
    candidates.retain(|c| !c.noban && c.inbound);

    // satd, `-peerflagpolicy=evict`: flagged candidates lose the protections
    // below and go first. The two above still hold, so a flagged `noban` or
    // outbound peer is never chosen. Among the flagged, Core's last step
    // picks: the youngest of the network group with the most of them.
    if candidates.iter().any(|c| c.flagged) {
        candidates.retain(|c| c.flagged);
        candidates.sort_by(|a, b| ordering(reverse_compare_node_time_connected, a, b));
        return youngest_of_largest_group(&candidates);
    }

    // Four peers by keyed netgroup: an attacker cannot predict which.
    erase_last_k_elements(&mut candidates, compare_net_group_keyed, 4, |_| true);
    // The eight with the lowest minimum ping: hard to fake without moving.
    erase_last_k_elements(&mut candidates, reverse_compare_node_min_ping_time, 8, |_| true);
    // The four that most recently sent us transactions the mempool accepted.
    erase_last_k_elements(&mut candidates, compare_node_tx_time, 4, |_| true);
    // Up to eight non-tx-relay peers that sent us novel blocks.
    erase_last_k_elements(&mut candidates, compare_node_block_relay_only_time, 8, |c| {
        !c.relay_txs && c.relevant_services
    });
    // The four that most recently sent us novel blocks.
    erase_last_k_elements(&mut candidates, compare_node_block_time, 4, |_| true);

    protect_eviction_candidates_by_ratio(&mut candidates);

    if candidates.is_empty() {
        return None;
    }

    // If any remaining peers are preferred for eviction, consider only them.
    if candidates.iter().any(|c| c.prefer_evict) {
        candidates.retain(|c| c.prefer_evict);
    }

    // `candidates` is sorted by reverse connect time (youngest first) by the
    // last step of the ratio protection.
    youngest_of_largest_group(&candidates)
}

/// The last step of Core's `SelectNodeToEvict`: the network group with the
/// most connections (on a tie, the one whose youngest member is youngest),
/// and its youngest member. `candidates` must be sorted youngest first.
fn youngest_of_largest_group(candidates: &[EvictionCandidate]) -> Option<PeerId> {
    let mut groups: HashMap<u64, Vec<&EvictionCandidate>> = HashMap::new();
    let mut most_connections = 0usize;
    let mut most_connections_time = 0u64;
    let mut most_connections_group = 0u64;
    for c in candidates {
        let group = groups.entry(c.keyed_net_group).or_default();
        group.push(c);
        let group_time = group[0].connected;
        if group.len() > most_connections || (group.len() == most_connections && group_time > most_connections_time) {
            most_connections = group.len();
            most_connections_time = group_time;
            most_connections_group = c.keyed_net_group;
        }
    }
    // Its youngest member.
    groups.get(&most_connections_group).map(|g| g[0].id)
}

#[cfg(test)]
mod tests {
    //! Ported from Core v32.1 `src/test/net_peer_eviction_tests.cpp`.
    use super::*;
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng};
    use std::collections::HashSet;

    /// Core's `GetRandomNodeEvictionCandidates` (`src/test/util/net.cpp`).
    fn random_candidates(n: usize, rng: &mut rand::rngs::StdRng) -> Vec<EvictionCandidate> {
        const NETS: [Network; 5] = [Network::Ipv4, Network::Ipv6, Network::Onion, Network::I2p, Network::Cjdns];
        (0..n)
            .map(|id| EvictionCandidate {
                id: id as PeerId,
                connected: rng.gen_range(0..u32::MAX as u64),
                min_ping_us: rng.gen_range(0..u32::MAX as u64),
                last_block_time: rng.gen_range(0..u32::MAX as u64),
                last_tx_time: rng.gen_range(0..u32::MAX as u64),
                relevant_services: rng.r#gen(),
                relay_txs: rng.r#gen(),
                bloom_filter: rng.r#gen(),
                keyed_net_group: rng.gen_range(0..u32::MAX as u64),
                prefer_evict: rng.r#gen(),
                is_local: rng.r#gen(),
                network: Some(NETS[rng.gen_range(0..NETS.len())]),
                noban: false,
                inbound: true,
                flagged: false,
            })
            .collect()
    }

    fn is_protected(
        n: usize,
        setup: impl Fn(&mut EvictionCandidate),
        protected: &[PeerId],
        unprotected: &[PeerId],
        rng: &mut rand::rngs::StdRng,
    ) -> bool {
        let mut candidates = random_candidates(n, rng);
        candidates.iter_mut().for_each(&setup);
        candidates.shuffle(rng);
        let expected = n - n / 2;
        protect_eviction_candidates_by_ratio(&mut candidates);
        assert_eq!(candidates.len(), expected);
        let left: HashSet<PeerId> = candidates.iter().map(|c| c.id).collect();
        protected.iter().all(|id| !left.contains(id)) && unprotected.iter().all(|id| left.contains(id))
    }

    #[test]
    fn peer_protection_test() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        // Half of the peers with the greatest uptime.
        assert!(is_protected(
            12,
            |c| {
                c.connected = c.id;
                c.is_local = false;
                c.network = Some(Network::Ipv4);
            },
            &[0, 1, 2, 3, 4, 5],
            &[6, 7, 8, 9, 10, 11],
            &mut rng,
        ));
        // A quarter onion peers and a quarter by uptime.
        assert!(is_protected(
            12,
            |c| {
                c.connected = c.id;
                c.is_local = false;
                c.network = Some(if c.id == 3 || c.id > 7 { Network::Onion } else { Network::Ipv6 });
            },
            &[0, 1, 2, 3, 8, 9],
            &[4, 5, 6, 7, 10, 11],
            &mut rng,
        ));
        // A quarter localhost peers and a quarter by uptime.
        assert!(is_protected(
            12,
            |c| {
                c.connected = c.id;
                c.is_local = c.id > 6;
                c.network = Some(Network::Ipv6);
            },
            &[0, 1, 2, 7, 8, 9],
            &[3, 4, 5, 6, 10, 11],
            &mut rng,
        ));
        // 6 CJDNS, 1 I2P, 1 localhost and 4 onion peers of 24: 2 CJDNS, the
        // I2P, the localhost and 2 onion peers, plus 6 by uptime.
        assert!(is_protected(
            24,
            |c| {
                c.connected = c.id;
                c.is_local = c.id == 13;
                c.network = Some(if c.id > 17 {
                    Network::Cjdns
                } else if c.id == 17 {
                    Network::I2p
                } else if [12, 14, 15, 16].contains(&c.id) {
                    Network::Onion
                } else {
                    Network::Ipv6
                });
            },
            &[0, 1, 2, 3, 4, 5, 12, 13, 14, 17, 18, 19],
            &[6, 7, 8, 9, 10, 11, 15, 16, 20, 21, 22, 23],
            &mut rng,
        ));
    }

    fn is_evicted(n: usize, setup: impl Fn(&mut EvictionCandidate, usize), ids: &[PeerId], rng: &mut rand::rngs::StdRng) -> bool {
        let mut candidates = random_candidates(n, rng);
        candidates.iter_mut().for_each(|c| setup(c, n));
        candidates.shuffle(rng);
        select_node_to_evict(candidates).is_some_and(|id| ids.contains(&id))
    }

    #[test]
    fn peer_eviction_test() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        for n in 0..200usize {
            let first = |k: u64| (0..k).collect::<Vec<PeerId>>();
            assert!(!is_evicted(n, |c, n| c.keyed_net_group = n as u64 - c.id, &first(4), &mut rng));
            assert!(!is_evicted(n, |c, _| c.min_ping_us = c.id, &first(8), &mut rng));
            assert!(!is_evicted(n, |c, n| c.last_tx_time = n as u64 - c.id, &first(4), &mut rng));
            assert!(!is_evicted(
                n,
                |c, n| {
                    c.last_block_time = n as u64 - c.id;
                    if c.id <= 7 {
                        c.relay_txs = false;
                        c.relevant_services = true;
                    }
                },
                &first(8),
                &mut rng
            ));
            assert!(!is_evicted(n, |c, n| c.last_block_time = n as u64 - c.id, &first(4), &mut rng));
            assert!(!is_evicted(
                n,
                |c, n| {
                    c.keyed_net_group = n as u64 - c.id;
                    c.min_ping_us = c.id;
                    c.last_tx_time = n as u64 - c.id;
                    c.last_block_time = n as u64 - c.id;
                },
                &first(20),
                &mut rng
            ));
            // At least 29 random candidates always yield an eviction; at most
            // 20 never do.
            if n >= 29 {
                assert!(select_node_to_evict(random_candidates(n, &mut rng)).is_some(), "{n}");
            }
            if n <= 20 {
                assert!(select_node_to_evict(random_candidates(n, &mut rng)).is_none(), "{n}");
            }
        }
    }

    /// Noban and non-inbound candidates are never chosen.
    #[test]
    fn noban_and_outbound_are_never_evicted() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        for _ in 0..50 {
            let mut candidates = random_candidates(60, &mut rng);
            for c in candidates.iter_mut() {
                c.noban = c.id % 3 == 0;
                c.inbound = c.id % 3 != 1;
            }
            if let Some(id) = select_node_to_evict(candidates) {
                assert_eq!(id % 3, 2, "evicted a noban or outbound candidate: {id}");
            }
        }
    }

    /// The youngest member of the network group with the most connections,
    /// not the youngest peer overall.
    #[test]
    fn the_youngest_of_the_largest_group_is_evicted() {
        let base = |id: PeerId, group: u64, connected: u64| EvictionCandidate {
            id,
            connected,
            min_ping_us: u64::MAX,
            last_block_time: 0,
            last_tx_time: 0,
            relevant_services: true,
            relay_txs: true,
            bloom_filter: false,
            keyed_net_group: group,
            prefer_evict: false,
            is_local: false,
            network: Some(Network::Ipv4),
            noban: false,
            inbound: true,
            flagged: false,
        };
        let mut candidates = Vec::new();
        // Twenty peers the fixed protections take: four by netgroup, eight by
        // ping, four by transactions, four by blocks.
        for id in 100..120u64 {
            let mut c = base(id, 50 + id, 1_000 + id);
            match id {
                100..=103 => c.keyed_net_group = 1_000 + id,
                104..=111 => c.min_ping_us = id,
                112..=115 => c.last_tx_time = 100,
                _ => c.last_block_time = 100,
            }
            candidates.push(c);
        }
        // Group 2: ten peers, nine old and one the youngest of all.
        for id in 10..19u64 {
            candidates.push(base(id, 2, 100 + id));
        }
        candidates.push(base(19, 2, 500));
        // Group 1: four peers.
        for id in 1..=4u64 {
            candidates.push(base(id, 1, 200 + id));
        }
        // The ratio step keeps the seven oldest of the 14 left (group 2's
        // first seven), leaving three of group 2 and all four of group 1.
        assert_eq!(select_node_to_evict(candidates), Some(4));
    }

    /// `-peerflagpolicy=evict`: a flagged candidate is chosen even when each
    /// of Core's protections would keep it, and with twenty candidates, a
    /// set Core never evicts from.
    #[test]
    fn a_flagged_candidate_loses_every_protection() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        for n in 1..=40usize {
            let first = |c: &EvictionCandidate| c.id == 0;
            let setups: [&dyn Fn(&mut EvictionCandidate, usize); 7] = [
                &|c, n| c.keyed_net_group = n as u64 - c.id,
                &|c, _| c.min_ping_us = c.id,
                &|c, n| c.last_tx_time = n as u64 - c.id,
                &|c, n| {
                    c.last_block_time = n as u64 - c.id;
                    c.relay_txs = false;
                    c.relevant_services = true;
                },
                &|c, n| c.last_block_time = n as u64 - c.id,
                &|c, _| c.connected = c.id,
                &|c, _| c.network = Some(if c.id == 0 { Network::Onion } else { Network::Ipv4 }),
            ];
            for setup in setups {
                let mut candidates = random_candidates(n, &mut rng);
                for c in candidates.iter_mut() {
                    setup(c, n);
                    c.flagged = first(c);
                }
                candidates.shuffle(&mut rng);
                assert_eq!(select_node_to_evict(candidates), Some(0), "{n}");
            }
        }
    }

    /// The protections Core never lifts still hold for a flagged candidate:
    /// a flagged `noban` or outbound peer is never chosen, and Core's own
    /// selection runs among the rest.
    #[test]
    fn a_flagged_noban_or_outbound_candidate_is_never_evicted() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        for _ in 0..50 {
            let mut candidates = random_candidates(60, &mut rng);
            for c in candidates.iter_mut() {
                c.noban = c.id % 3 == 0;
                c.inbound = c.id % 3 != 1;
                c.flagged = c.id % 3 != 2;
            }
            let unflagged: Vec<EvictionCandidate> =
                candidates.iter().cloned().map(|c| EvictionCandidate { flagged: false, ..c }).collect();
            assert_eq!(select_node_to_evict(candidates), select_node_to_evict(unflagged));
        }
    }

    /// Among several flagged candidates Core's last step picks: the youngest
    /// of the network group with the most of them. Unflagged peers, older or
    /// younger, are left alone.
    #[test]
    fn among_the_flagged_the_youngest_of_the_largest_group_goes() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(6);
        let mut candidates = random_candidates(60, &mut rng);
        for c in candidates.iter_mut() {
            c.prefer_evict = false;
            c.connected = 1_000 + c.id;
            match c.id {
                10..=12 => {
                    c.flagged = true;
                    c.keyed_net_group = 7;
                }
                20 | 21 => {
                    c.flagged = true;
                    c.keyed_net_group = 8;
                }
                _ => {}
            }
        }
        candidates.shuffle(&mut rng);
        assert_eq!(select_node_to_evict(candidates), Some(12));
    }
}
