//! Behaviour flags (`crate::net::flags`) against a live `PeerManager`. For
//! each flag, a scripted peer makes it fire with the expected evidence, and
//! a peer of the same family behaving honestly does not. Each peer starts
//! from a committed handshake capture, so its fingerprint is real. Every
//! test holds the node clock (`MockClock`), since sessions are timed by it.

use std::time::SystemTime;

use super::p1c_tests::pm_with_coins;
use super::txrequest_tests::{add_peer_with, MockClock};
use super::*;
use crate::net::behavior::replay_fixture;
use crate::net::fingerprint::{Confidence, Family, Fingerprint};
use crate::net::flags::{Flag, Value};
use crate::net::flow::InFlight;

/// A peer replaying the handshake of capture `fixture`, at `addr`, connected
/// `session_secs` ago.
fn scripted(pm: &PeerManager, id: PeerId, fixture: &str, addr: &str, session_secs: u64) -> mpsc::Receiver<NetworkMessage> {
    let r = replay_fixture(fixture);
    let direction = if r.inbound { Direction::Inbound } else { Direction::Outbound };
    let rx = add_peer_with(pm, id, direction, |info| {
        info.addr = addr.parse().unwrap();
        if direction == Direction::Inbound {
            info.conn_type = ConnType::Inbound;
        }
        info.conn_time = SystemTime::UNIX_EPOCH + Duration::from_secs(crate::time::now_secs() - session_secs);
        info.behavior.handshake = r.capture.clone();
        info.behavior.version = r.version.clone();
    });
    pm.start_tx_relay(id);
    rx
}

fn deliver(pm: &PeerManager, id: PeerId, msg: NetworkMessage) {
    pm.handle_message(id, msg, InFlight::new(None));
}

fn with_behavior(pm: &PeerManager, id: PeerId, f: impl FnOnce(&mut crate::net::behavior::PeerBehavior)) {
    f(&mut pm.peers.write().get_mut(&id).unwrap().info.behavior);
}

/// The flags `id` carries after an evaluation pass, with their evidence.
fn flags_of(pm: &PeerManager, id: PeerId) -> Vec<(Flag, Vec<(&'static str, Value)>)> {
    pm.evaluate_peer_flags();
    pm.peers.read()[&id].info.flags.flags.clone()
}

fn codes(flags: &[(Flag, Vec<(&'static str, Value)>)]) -> String {
    flags.iter().map(|(f, _)| f.code()).collect()
}

fn evidence(flags: &[(Flag, Vec<(&'static str, Value)>)], flag: Flag) -> Vec<(&'static str, Value)> {
    flags.iter().find(|(f, _)| *f == flag).unwrap_or_else(|| panic!("{flag:?} not raised: {flags:?}")).1.clone()
}

fn n(v: u64) -> Value {
    Value::Num(v)
}

fn getheaders(pm: &PeerManager) -> NetworkMessage {
    NetworkMessage::GetHeaders(bitcoin::p2p::message_blockdata::GetHeadersMessage::new(
        vec![pm.chain_state.tip_hash()],
        bitcoin::BlockHash::all_zeros(),
    ))
}

/// Three earlier inbound connections from one network group, counted as
/// the node counts each when its handshake finishes.
fn busy_netgroup(pm: &PeerManager) {
    for id in 101..=102 {
        let _rx = scripted(pm, id, "core-31.2-inbound", &format!("11.22.{id}.1:8333"), 0);
        pm.note_inbound_netgroup(id);
        pm.disconnect_peer(id, "test");
    }
}

/// Every capture's peer, doing nothing past its handshake, carries no
/// flag: the shapes themselves are honest.
#[test]
fn no_capture_raises_a_flag_by_its_handshake_alone() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    for (i, name) in crate::net::behavior::fixture_names().iter().enumerate() {
        let id = 200 + i as PeerId;
        let _rx = scripted(&pm, id, name, &format!("11.{i}.0.1:8333"), 30);
        assert_eq!(codes(&flags_of(&pm, id)), "", "{name}");
    }
}

/// `C`: a seeder-shaped peer that sent `getaddr` and nothing else, a few
/// seconds in, from a group that keeps connecting.
#[test]
fn crawler_fires_on_a_short_getaddr_session_from_a_busy_netgroup() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 7, "bitcoin-seeder-92d2b46-inbound", "11.22.7.7:8333", 4);
    pm.note_inbound_netgroup(7);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "C");
    assert_eq!(
        evidence(&flags, Flag::Crawler),
        [("session_secs", n(4)), ("getaddr_in", n(1)), ("headers_req", n(0)), ("blocks_req", n(0)), ("netgroup_seen", n(3))]
    );
    assert_eq!(pm.peers.read()[&7].info.flags.fingerprint.observed(), Some(Family::BitcoinSeeder));
}

/// `C`, honest: Core dialing us from the same busy group sends `getaddr`
/// and `getheaders`; it syncs, so it is no crawler.
#[test]
fn crawler_spares_an_honest_core_peer_from_a_busy_netgroup() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 4);
    pm.note_inbound_netgroup(7);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    deliver(&pm, 7, getheaders(&pm));
    assert_eq!(codes(&flags_of(&pm, 7)), "");
}

/// `C` needs the group to repeat: one seeder alone in its group is not
/// flagged, nor is one past the session bound.
#[test]
fn crawler_needs_a_repeating_netgroup_and_a_short_session() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "bitcoin-seeder-92d2b46-inbound", "11.22.7.7:8333", 4);
    pm.note_inbound_netgroup(7);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    assert_eq!(codes(&flags_of(&pm, 7)), "", "alone in its group");

    busy_netgroup(&pm);
    let _rx = scripted(&pm, 8, "bitcoin-seeder-92d2b46-inbound", "11.22.8.8:8333", 600);
    pm.note_inbound_netgroup(8);
    deliver(&pm, 8, NetworkMessage::GetAddr);
    assert_eq!(codes(&flags_of(&pm, 8)), "", "ten minutes in");
}

/// `C`, honest, in the group's first seconds: a Core peer that has sent
/// nothing yet, or `getaddr` and a block request (a peer catching up by
/// block, not by header).
#[test]
fn crawler_spares_a_core_peer_that_has_not_asked_for_addresses_or_asks_for_blocks() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 2);
    pm.note_inbound_netgroup(7);
    assert_eq!(codes(&flags_of(&pm, 7)), "", "no getaddr");
    deliver(&pm, 7, NetworkMessage::GetAddr);
    let block = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([3; 32]));
    deliver(&pm, 7, NetworkMessage::GetData(vec![block]));
    assert_eq!(codes(&flags_of(&pm, 7)), "", "asks for a block");
}

/// `C` is never an outbound peer: we chose to dial it. Even one counted in
/// a busy group, sending `getaddr` and nothing else, is spared.
#[test]
fn crawler_is_never_an_outbound_peer() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 9, "core-31.2-inbound", "11.22.9.9:8333", 2);
    pm.note_inbound_netgroup(9);
    let key = pm.peers.read()[&9].info.flags.netgroup;
    assert!(key.is_some());
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 2);
    pm.peers.write().get_mut(&7).unwrap().info.flags.netgroup = key;
    deliver(&pm, 7, NetworkMessage::GetAddr);
    assert_eq!(codes(&flags_of(&pm, 7)), "");
    assert_eq!(codes(&flags_of(&pm, 9)), "", "and the inbound one has not asked for addresses");
}

/// Sessions are measured by the node clock, which `conn_time` is set
/// from: under a mock time years in the past, a crawler four seconds in is
/// still four seconds in, and a fresh peer is no spy.
#[test]
fn sessions_are_timed_by_the_node_clock() {
    let _clock = MockClock::install();
    crate::time::set_mock_time(Some(1_600_000_000));
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 7, "bitcoin-seeder-92d2b46-inbound", "11.22.7.7:8333", 4);
    pm.note_inbound_netgroup(7);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "C");
    assert_eq!(evidence(&flags, Flag::Crawler)[0], ("session_secs", n(4)));
    assert_eq!(pm.get_peer_behavior(Some(7)).unwrap()[0]["session_secs"], 4);
}

/// `C` on a peer gone before the next pass: it is judged as it leaves.
#[test]
fn a_crawler_gone_before_the_timer_is_judged_as_it_leaves() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    busy_netgroup(&pm);
    let _rx = scripted(&pm, 7, "bitcoin-seeder-92d2b46-inbound", "11.22.7.7:8333", 2);
    pm.note_inbound_netgroup(7);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    pm.disconnect_peer(7, "test");
    let retired = pm.retired_flags.lock();
    let (_, set) = retired.iter().find(|(id, _)| *id == 7).unwrap();
    assert_eq!(set.to_string(), "C");
}

/// Announce `count` transactions to peer `id`, and have it ask for each
/// `delay` later, as it would by `getdata`.
fn announce_and_request(pm: &PeerManager, id: PeerId, count: u32, delay: Duration) {
    let t0 = Instant::now() - Duration::from_secs(10);
    for i in 0..count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&i.to_le_bytes());
        with_behavior(pm, id, |b| {
            b.note_tx_announced(&hash, t0);
            let getdata = NetworkMessage::GetData(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(hash))]);
            b.note_received(&getdata, t0 + delay);
        });
    }
}

/// `S`: hours connected, asks for every transaction we announce within a
/// millisecond, announces none, asks for no block.
#[test]
fn spy_fires_on_a_fast_one_way_transaction_listener() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 3 * 3_600);
    announce_and_request(&pm, 7, 600, Duration::from_micros(400));
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "S");
    assert_eq!(
        evidence(&flags, Flag::Spy),
        [
            ("inv_tx_announced_to", n(600)),
            ("getdata_tx_in", n(600)),
            ("getdata_permille", n(1_000)),
            ("getdata_p10_ms", n(1)),
            ("inv_tx_in", n(0)),
            ("blocks_req", n(0)),
            ("session_secs", n(3 * 3_600)),
        ]
    );
}

/// `S`, honest: a Core peer just as quick to ask, connected as long, that
/// relays transactions of its own and asks for blocks.
#[test]
fn spy_spares_an_honest_relaying_core_peer() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 3 * 3_600);
    announce_and_request(&pm, 7, 600, Duration::from_micros(400));
    deliver(&pm, 7, NetworkMessage::Inv(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array([9; 32]))]));
    assert_eq!(codes(&flags_of(&pm, 7)), "", "it announces transactions");
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 3 * 3_600);
    announce_and_request(&pm, 7, 600, Duration::from_micros(400));
    let block = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([3; 32]));
    deliver(&pm, 7, NetworkMessage::GetData(vec![block]));
    assert_eq!(codes(&flags_of(&pm, 7)), "", "it asks for blocks");
}

/// `S` needs each of its other conditions: hours connected, most of what
/// we announce asked for, a fast 10th percentile, `relay`, enough
/// announcements.
#[test]
fn spy_needs_every_condition() {
    let _clock = MockClock::install();
    let cases: [(&str, u64, u32, Duration, bool); 5] = [
        ("an hour connected", 3_600, 600, Duration::from_micros(400), true),
        ("too few announcements", 3 * 3_600, 100, Duration::from_micros(400), true),
        ("slow to ask", 3 * 3_600, 600, Duration::from_millis(80), true),
        ("relay off", 3 * 3_600, 600, Duration::from_micros(400), false),
        ("asks for half", 3 * 3_600, 300, Duration::from_micros(400), true),
    ];
    for (why, session, asked, delay, relay) in cases {
        let (pm, _dir) = pm_with_coins(&[]);
        let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", session);
        if why == "asks for half" {
            announce_and_request(&pm, 7, asked, delay);
            with_behavior(&pm, 7, |b| {
                for i in 0..300u32 {
                    let mut hash = [0xffu8; 32];
                    hash[..4].copy_from_slice(&i.to_le_bytes());
                    b.note_tx_announced(&hash, Instant::now());
                }
            });
        } else {
            announce_and_request(&pm, 7, asked, delay);
        }
        with_behavior(&pm, 7, |b| b.version.as_mut().unwrap().relay = relay);
        assert_eq!(codes(&flags_of(&pm, 7)), "", "{why}");
    }
}

/// `F`: btcd's handshake under Core's user agent.
#[test]
fn fingerprint_mismatch_fires_on_a_borrowed_user_agent() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "btcd-0.27.0-inbound", "11.22.7.7:8333", 30);
    with_behavior(&pm, 7, |b| b.version.as_mut().unwrap().user_agent = "/Satoshi:31.2.0/".into());
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "F");
    assert_eq!(
        evidence(&flags, Flag::FingerprintMismatch),
        [("claimed", Value::Name("core")), ("observed", Value::Name("btcd"))]
    );
}

/// `F`, honest: btcd under its own user agent.
#[test]
fn fingerprint_mismatch_spares_btcd_under_its_own_agent() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "btcd-0.27.0-inbound", "11.22.7.7:8333", 30);
    assert_eq!(codes(&flags_of(&pm, 7)), "");
    assert_eq!(pm.peers.read()[&7].info.flags.fingerprint, Fingerprint::Known(Family::Btcd, Confidence::Low));
}

/// `A`: a second `getaddr` in one connection.
#[test]
fn addr_abuse_fires_on_repeated_getaddr() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 120);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "A");
    assert_eq!(evidence(&flags, Flag::AddrAbuse), [("getaddr_in", n(2)), ("addr_in", n(0)), ("addr_rate_limited", n(0))]);
}

/// `A`: addresses past what the token bucket takes.
#[test]
fn addr_abuse_fires_on_addresses_past_the_rate_limit() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 120);
    pm.peers.write().get_mut(&7).unwrap().info.addr_rate.rate_limited = 1_001;
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "A");
    assert_eq!(evidence(&flags, Flag::AddrAbuse)[2], ("addr_rate_limited", n(1_001)));
}

/// `A`, honest: one `getaddr`, and some addresses dropped by the limit.
#[test]
fn addr_abuse_spares_one_getaddr_and_a_few_dropped_addresses() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-inbound", "11.22.7.7:8333", 120);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    pm.peers.write().get_mut(&7).unwrap().info.addr_rate.rate_limited = 40;
    assert_eq!(codes(&flags_of(&pm, 7)), "");
}

/// `H`: claimed a chain 100 blocks taller than it served.
#[test]
fn height_lie_fires_on_a_claim_it_would_not_serve() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    with_behavior(&pm, 7, |b| {
        b.version.as_mut().unwrap().start_height = 1_000;
        b.claim_above_tip = true;
        b.note_headers_served(900);
    });
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "H");
    assert_eq!(evidence(&flags, Flag::HeightLie), [("height_claim_gap", n(100)), ("start_height", n(1_000))]);
}

/// `H`, honest: served what it claimed, or a block short (a tip that moved).
#[test]
fn height_lie_spares_a_peer_that_served_its_claim() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    with_behavior(&pm, 7, |b| {
        b.version.as_mut().unwrap().start_height = 1_000;
        b.claim_above_tip = true;
        b.note_headers_served(999);
    });
    assert_eq!(codes(&flags_of(&pm, 7)), "");
}

fn announce_from_peer(pm: &PeerManager, id: PeerId, count: u8) {
    let invs: Vec<Inventory> = (0..count).map(|i| Inventory::WTx(bitcoin::Wtxid::from_byte_array([i; 32]))).collect();
    deliver(pm, id, NetworkMessage::Inv(invs));
}

/// `N`: twenty of fifty announced transactions answered `notfound`.
#[test]
fn notfound_pattern_fires_on_announcements_it_does_not_serve() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    announce_from_peer(&pm, 7, 50);
    with_behavior(&pm, 7, |b| b.note_notfound_after_inv(20));
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "N");
    assert_eq!(
        evidence(&flags, Flag::NotfoundPattern),
        [("notfound_after_inv", n(20)), ("inv_tx_in", n(50)), ("notfound_permille", n(400))]
    );
}

/// `N`, honest: a couple of `notfound`, for transactions that left its
/// mempool between the announcement and our request; or many, out of a
/// great many announced.
#[test]
fn notfound_pattern_spares_an_occasional_notfound() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    announce_from_peer(&pm, 7, 50);
    with_behavior(&pm, 7, |b| b.note_notfound_after_inv(2));
    assert_eq!(codes(&flags_of(&pm, 7)), "");
    with_behavior(&pm, 7, |b| {
        b.inv_tx_in = 10_000;
        b.note_notfound_after_inv(18);
    });
    assert_eq!(codes(&flags_of(&pm, 7)), "", "20 of 10,000");

    // Half of a few announcements: too few to say anything.
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    announce_from_peer(&pm, 7, 10);
    with_behavior(&pm, 7, |b| b.note_notfound_after_inv(5));
    assert_eq!(codes(&flags_of(&pm, 7)), "", "5 of 10");
}

/// `T`: three block-download stalls.
#[test]
fn stalling_fires_on_repeated_stalls() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    pm.note_stalls([7, 7, 7]);
    let flags = flags_of(&pm, 7);
    assert_eq!(codes(&flags), "T");
    assert_eq!(evidence(&flags, Flag::Stalling), [("stalls", n(3))]);
}

/// `T`, honest: one stall, as any peer may have on a slow link.
#[test]
fn stalling_spares_a_single_stall() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    pm.note_stalls([7]);
    assert_eq!(codes(&flags_of(&pm, 7)), "");
}

/// A flag is logged once per connection, and the counts metrics and the
/// status page read follow the last pass.
#[test]
fn flags_are_counted_per_connected_peer() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    pm.evaluate_peer_flags();
    // The fixture's own peers, with no transcript.
    let before = pm.peer_flag_counts();
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    let _rx = scripted(&pm, 8, "btcd-0.27.0-inbound", "11.22.8.8:8333", 120);
    pm.note_stalls([7, 7, 7]);
    pm.evaluate_peer_flags();
    pm.evaluate_peer_flags();
    assert_eq!(pm.peers.read()[&7].info.flags.ever.to_string(), "T");
    let counts = pm.peer_flag_counts();
    assert_eq!(counts.flagged, [0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(counts.families[0], 1, "core");
    assert_eq!(counts.families[1], 1, "btcd");
    assert_eq!(counts.unknown, before.unknown, "no new unknown");
}

/// `getpeerbehavior`'s object: id, fingerprint, flags with evidence, raw
/// counters, and no address anywhere in it.
#[test]
fn getpeerbehavior_reports_a_peer_without_its_address() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = scripted(&pm, 7, "core-31.2-outbound", "11.22.7.7:8333", 120);
    pm.note_stalls([7, 7, 7]);
    pm.evaluate_peer_flags();
    let all = pm.get_peer_behavior(None).unwrap();
    assert_eq!(all.len(), pm.peers.read().len());
    assert!(all.windows(2).all(|w| w[0]["id"].as_u64() < w[1]["id"].as_u64()), "ordered by id");
    let one = &pm.get_peer_behavior(Some(7)).unwrap()[0];
    assert!(all.contains(one));
    assert_eq!(one["id"], 7);
    assert_eq!(one["fingerprint"]["result"], "known");
    assert_eq!(one["fingerprint"]["family"], "core");
    assert_eq!(one["fingerprint"]["handshake"][0], "version");
    assert_eq!(one["flag_codes"], "T");
    assert_eq!(one["flags"][0]["evidence"]["stalls"], 3);
    assert_eq!(one["counters"]["stalls"], 3);
    assert!(!one.to_string().contains("11.22"), "no address: {one}");
    assert!(pm.get_peer_behavior(Some(99)).is_none());
}
