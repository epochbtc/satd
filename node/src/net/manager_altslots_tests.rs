//! Alt-slots (`-altslots`) and `-maxoutboundfullrelay`: the slot
//! accounting, the trial and fallback dials, the judgement of a settled
//! peer, the reload, and that none of it changes anything with
//! `-altslots=0`.

use super::*;
use crate::net::altslots::{AltConfig, AltRole, Rule, Trust, UaTrust};
use crate::net::fingerprint::{Confidence, Family, Fingerprint};

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let store = Box::new(InMemoryStore::new());
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::new(
        chain_state,
        mempool,
        fee_estimator,
        Network::Regtest,
        shutdown_rx,
    );
    // Out of IBD: the target is the full-relay count.
    pm.headers_tip.store(1, Ordering::Relaxed);
    assert!(!pm.is_ibd());
    (pm, dir)
}

fn add_peer(pm: &PeerManager, info: PeerInfo) {
    let (tx, _rx) = mpsc::channel::<NetworkMessage>(8);
    pm.peers.write().insert(
        info.id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            header_sync: Default::default(),
            last_mempool_served: None,
            tx_relay: Default::default(),
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
}

/// An address in a /16 of its own for each `i`.
fn own_group(i: usize) -> SocketAddr {
    SocketAddr::from(([60 + (i / 200) as u8, (i % 200) as u8, 1, 1], 8333))
}

fn learn(pm: &PeerManager, addrs: &[SocketAddr]) {
    let now = now_unix_secs();
    let mut book = pm.addrman.write();
    for a in addrs {
        assert!(book.add(*a, now), "fixture: the book takes {a}");
    }
}

/// A connected outbound full-relay peer, past the handshake for a minute,
/// whose fingerprint has settled as `fp` with user agent `ua`.
fn settled(
    id: PeerId,
    addr: SocketAddr,
    alt: Option<AltRole>,
    fp: Fingerprint,
    ua: &str,
) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.state = PeerState::Connected;
    info.conn_type = ConnType::OutboundFullRelay;
    info.conn_time -= Duration::from_secs(60);
    info.alt = alt;
    info.behavior.version = Some(crate::net::behavior::VersionFields {
        protocol_version: 70016,
        services: 1 | 8 | 1024,
        relay: true,
        start_height: 0,
        user_agent: ua.to_string(),
    });
    info.flags.update(fp, true, Vec::new());
    info
}

fn known(f: Family) -> Fingerprint {
    Fingerprint::Known(f, Confidence::High)
}

const BTCD: &str = "/btcwire:0.5.0/btcd:0.24.2/";
const CORE: &str = "/Satoshi:28.1.0/";
const KNOTS: &str = "/Satoshi:28.1.0/Knots:20250305/";

fn alt(pm: &PeerManager, slots: usize, rules: &[&str], trust: UaTrust) {
    pm.set_alt_slots(AltConfig::new(
        slots,
        rules.iter().map(|r| Rule::parse(r).unwrap()).collect(),
        trust,
        Duration::from_secs(600),
    ));
}

fn role(pm: &PeerManager, id: PeerId) -> Option<AltRole> {
    pm.peers.read().get(&id).and_then(|h| h.info.alt.clone())
}

fn connected(pm: &PeerManager, id: PeerId) -> bool {
    pm.peers.read().contains_key(&id)
}

fn dialled(pm: &Arc<PeerManager>) -> Vec<PeerAddr> {
    pm.reserve_automatic_dials(Instant::now(), &[])
        .into_iter()
        .map(|(a, _slot)| a)
        .collect()
}

// ---- -altslots=0: exactly as before ----

/// With the defaults, and with alt-slot rules set but `-altslots=0`, every
/// limit derived from the full-relay count is the one the constant 8 gave,
/// for every `-maxconnections`, nothing is reserved, a pass dials all eight
/// slots as ordinary peers, and the alt-slot half of the pass dials nothing.
#[test]
fn altslots_zero_leaves_outbound_selection_as_it_was() {
    for configured in [false, true] {
        let (pm, _dir) = mk_pm();
        if configured {
            alt(&pm, 0, &["family:btcd@2", "ua:/Knots:*"], UaTrust::Strict);
        }
        for mc in 0..=20usize {
            pm.set_max_connections(mc);
            assert_eq!(pm.automatic_outbound_target(), mc.min(8), "mc={mc}");
            assert_eq!(pm.max_automatic_outbound(), 11usize.min(mc), "mc={mc}");
            assert_eq!(
                pm.max_outbound_block_relay(),
                2usize.min(mc - mc.min(8)),
                "mc={mc}"
            );
            assert_eq!(pm.max_inbound(), mc - 11usize.min(mc), "mc={mc}");
        }
        pm.set_max_connections(DEFAULT_MAX_PEER_CONNECTIONS);
        learn(&pm, &(0..20).map(own_group).collect::<Vec<_>>());
        assert_eq!(pm.alt_slots_reserved(&pm.dials_in_flight.lock()), 0);
        assert_eq!(dialled(&pm).len(), MAX_OUTBOUND);
        assert!(pm.open_alt_slot_peers(Instant::now(), &[]).is_empty());
        assert_eq!(pm.alt_slot_counts(), AltSlotCounts::default());
    }
}

// ---- -maxoutboundfullrelay ----

#[test]
fn maxoutboundfullrelay_sets_the_full_relay_target_and_the_limits_it_drives() {
    let (pm, _dir) = mk_pm();
    pm.set_max_outbound_full_relay(12);
    assert_eq!(pm.automatic_outbound_target(), 12);
    assert_eq!(
        pm.max_automatic_outbound(),
        15,
        "12 + 2 block-relay-only + 1 feeler"
    );
    assert_eq!(pm.max_inbound(), DEFAULT_MAX_PEER_CONNECTIONS - 15);
    learn(&pm, &(0..20).map(own_group).collect::<Vec<_>>());
    assert_eq!(dialled(&pm).len(), 12);
    // `-maxconnections` still caps it, and leaves the block-relay-only
    // slots what is past it.
    pm.set_max_connections(13);
    assert_eq!(pm.automatic_outbound_target(), 12);
    assert_eq!(pm.max_outbound_block_relay(), 1);
    // IBD stays at 64.
    pm.set_max_connections(DEFAULT_MAX_PEER_CONNECTIONS);
    pm.headers_tip.store(1000, Ordering::Relaxed);
    assert_eq!(pm.automatic_outbound_target(), MAX_OUTBOUND_IBD);
}

// ---- Slot accounting ----

/// Empty alt-slots are kept from ordinary dials: with three, a pass dials
/// five ordinary peers, and the block-relay-only dials still see the
/// full-relay target as met.
#[test]
fn ordinary_dials_leave_the_alt_slots_empty() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 3, &[], UaTrust::Consistent);
    learn(&pm, &(0..20).map(own_group).collect::<Vec<_>>());
    let dials = pm.reserve_automatic_dials(Instant::now(), &[]);
    assert_eq!(dials.len(), MAX_OUTBOUND - 3);
    let in_flight = pm.dials_in_flight.lock();
    assert_eq!(pm.alt_slots_reserved(&in_flight), 3);
    assert!(pm.automatic_open(&in_flight) >= pm.automatic_outbound_target());
}

/// One trial at a time, and none once every slot is matched; a fallback
/// does not fill a slot for the trial's purposes.
#[test]
fn one_trial_at_a_time_while_a_slot_is_not_matched() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 2, &[], UaTrust::Consistent);
    assert!(pm.check_alt_trial(&pm.dials_in_flight.lock()).is_ok());
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Trial),
            Fingerprint::Unknown,
            "",
        ),
    );
    assert!(
        pm.check_alt_trial(&pm.dials_in_flight.lock()).is_err(),
        "a trial is being judged"
    );
    pm.peers.write().remove(&1);
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            Some(AltRole::Fallback),
            known(Family::Core),
            CORE,
        ),
    );
    add_peer(
        &pm,
        settled(
            3,
            own_group(3),
            Some(AltRole::Fallback),
            known(Family::Core),
            CORE,
        ),
    );
    assert!(
        pm.check_alt_trial(&pm.dials_in_flight.lock()).is_ok(),
        "fallbacks leave room for a trial"
    );
    for (id, a) in [(2, 2), (3, 3)] {
        pm.peers.write().remove(&id);
        let m = AltRole::Matched {
            rule: "family:non-core".into(),
            trust: Trust::Verified,
        };
        add_peer(
            &pm,
            settled(id, own_group(a), Some(m), known(Family::Btcd), BTCD),
        );
    }
    assert!(
        pm.check_alt_trial(&pm.dials_in_flight.lock()).is_err(),
        "every slot is matched"
    );
}

// ---- Judgement ----

#[test]
fn a_trial_that_matches_takes_the_slot_and_one_that_does_not_is_disconnected() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 2, &["family:btcd"], UaTrust::Consistent);
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            Some(AltRole::Trial),
            known(Family::Core),
            CORE,
        ),
    );
    pm.judge_alt_slot_peers();
    assert_eq!(
        role(&pm, 1),
        Some(AltRole::Matched {
            rule: "family:btcd".into(),
            trust: Trust::Verified
        })
    );
    assert!(!connected(&pm, 2), "no rule matched");
    assert!(
        pm.retired_behavior
            .lock()
            .contains(&(2, Some("alt-slot-no-match")))
    );
    // The next trial waits its turn.
    let next = pm.alt_slots_next_trial().expect("set");
    assert!(next > Instant::now() + Duration::from_secs(25));
    let counts = pm.alt_slot_counts();
    assert_eq!(
        (
            counts.configured,
            counts.matched,
            counts.fallback,
            counts.empty
        ),
        (2, 1, 0, 1)
    );
}

/// A trial is judged only once its fingerprint has settled.
#[test]
fn an_unsettled_trial_waits() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &[], UaTrust::Consistent);
    let mut info = settled(
        1,
        own_group(1),
        Some(AltRole::Trial),
        Fingerprint::Unknown,
        "",
    );
    info.flags.settled = false;
    add_peer(&pm, info);
    pm.judge_alt_slot_peers();
    assert_eq!(role(&pm, 1), Some(AltRole::Trial));
}

/// A `ua:` rule against a verified, an unverified and a contradicted
/// candidate under each `-altuatrust`.
#[test]
fn each_ua_trust_mode_against_scripted_peers() {
    let contradicted = Fingerprint::Mismatch {
        claimed: Family::Core,
        observed: Family::Btcd,
    };
    for (mode, want) in [
        (UaTrust::Strict, [true, false, false]),
        (UaTrust::Consistent, [true, true, false]),
        (UaTrust::Any, [true, true, true]),
    ] {
        let (pm, _dir) = mk_pm();
        alt(&pm, 3, &["ua:*Knots*"], mode);
        add_peer(
            &pm,
            settled(
                1,
                own_group(1),
                Some(AltRole::Trial),
                known(Family::Core),
                KNOTS,
            ),
        );
        add_peer(
            &pm,
            settled(
                2,
                own_group(2),
                Some(AltRole::Trial),
                Fingerprint::Unknown,
                KNOTS,
            ),
        );
        add_peer(
            &pm,
            settled(3, own_group(3), Some(AltRole::Trial), contradicted, KNOTS),
        );
        pm.judge_alt_slot_peers();
        let got = [1, 2, 3].map(|id| matches!(role(&pm, id), Some(AltRole::Matched { .. })));
        assert_eq!(got, want, "{mode:?}");
        let trust = [Trust::Verified, Trust::Unverified, Trust::Contradicted];
        for (id, t) in [1, 2, 3].into_iter().zip(trust) {
            if let Some(AltRole::Matched { trust, .. }) = role(&pm, id) {
                assert_eq!(trust, t, "{mode:?} peer={id}");
            }
        }
    }
}

/// A peer flagged `C`, `S` or `F` never fills a slot, except under `any`.
#[test]
fn a_flagged_peer_never_fills() {
    for flag in [
        crate::net::flags::Flag::Crawler,
        crate::net::flags::Flag::Spy,
    ] {
        for (mode, fills) in [
            (UaTrust::Strict, false),
            (UaTrust::Consistent, false),
            (UaTrust::Any, true),
        ] {
            let (pm, _dir) = mk_pm();
            alt(&pm, 1, &["family:btcd"], mode);
            let mut info = settled(
                1,
                own_group(1),
                Some(AltRole::Trial),
                known(Family::Btcd),
                BTCD,
            );
            info.flags.flags = vec![(flag, Vec::new())];
            add_peer(&pm, info);
            pm.judge_alt_slot_peers();
            assert_eq!(
                matches!(role(&pm, 1), Some(AltRole::Matched { .. })),
                fills,
                "{flag:?} {mode:?}"
            );
            assert_eq!(connected(&pm, 1), fills, "{flag:?} {mode:?}");
        }
    }
}

#[test]
fn caps_and_rule_order_hold() {
    let (pm, _dir) = mk_pm();
    alt(
        &pm,
        3,
        &["family:btcd@1", "family:non-core"],
        UaTrust::Consistent,
    );
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    pm.judge_alt_slot_peers();
    assert!(matches!(role(&pm, 1), Some(AltRole::Matched { rule, .. }) if rule == "family:btcd@1"));
    assert!(
        matches!(role(&pm, 2), Some(AltRole::Matched { rule, .. }) if rule == "family:non-core")
    );
}

// ---- Fallback ----

/// A match arriving while a fallback holds the slot takes it, and the
/// fallback is disconnected; a fallback that itself matches takes the slot
/// without anyone leaving.
#[test]
fn a_match_replaces_the_fallback() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Fallback),
            known(Family::Core),
            CORE,
        ),
    );
    pm.judge_alt_slot_peers();
    assert_eq!(
        role(&pm, 1),
        Some(AltRole::Fallback),
        "an unmatched fallback stays"
    );
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    pm.judge_alt_slot_peers();
    assert!(matches!(role(&pm, 2), Some(AltRole::Matched { .. })));
    assert!(!connected(&pm, 1));
    assert!(
        pm.retired_behavior
            .lock()
            .contains(&(1, Some("alt-slot-fallback-replaced")))
    );

    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Fallback),
            known(Family::Btcd),
            BTCD,
        ),
    );
    pm.judge_alt_slot_peers();
    assert!(
        matches!(role(&pm, 1), Some(AltRole::Matched { .. })),
        "the fallback matched"
    );
}

/// A trial is dialled at once; the fallback only once a slot has been empty
/// for `-altfillwait`, and then into a slot the trial does not hold.
#[tokio::test]
async fn the_fallback_waits_for_altfillwait() {
    let (pm, _dir) = mk_pm();
    learn(&pm, &(0..20).map(own_group).collect::<Vec<_>>());
    alt(&pm, 2, &[], UaTrust::Consistent);
    let now = Instant::now();
    let first = pm.open_alt_slot_peers(now, &[]);
    assert_eq!(first.len(), 1, "a trial, no fallback yet: {first:?}");
    assert_eq!(
        pm.alt_slots
            .state
            .lock()
            .dials
            .iter()
            .filter(|(_, r)| *r == AltRole::Fallback)
            .count(),
        0
    );
    let later = now + Duration::from_secs(601);
    let second = pm.open_alt_slot_peers(later, &first);
    assert!(
        pm.alt_slots
            .state
            .lock()
            .dials
            .iter()
            .any(|(a, r)| *r == AltRole::Fallback && second.contains(a)),
        "the fallback is dialled after -altfillwait: {second:?}"
    );
}

// ---- Network groups ----

/// With every full-relay slot an alt-slot, the trial still takes no
/// network group an outbound peer is in, whether it comes from the store
/// or the book.
#[test]
fn netgroup_rule_holds_with_eight_alt_slots() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 8, &[], UaTrust::Consistent);
    // Seven matched peers in groups 0..7.
    for i in 0..7 {
        let m = AltRole::Matched {
            rule: "family:non-core".into(),
            trust: Trust::Verified,
        };
        add_peer(
            &pm,
            settled(
                i as PeerId + 1,
                own_group(i),
                Some(m),
                known(Family::Btcd),
                BTCD,
            ),
        );
    }
    // The store says btcd at another address in each taken group, and at
    // one in a free group; the book holds the same.
    let taken: Vec<SocketAddr> = (0..7)
        .map(|i| SocketAddr::from(([60, i as u8, 2, 2], 8333)))
        .collect();
    let free = own_group(150);
    let now = crate::time::now_secs();
    {
        let mut st = pm.alt_slots.state.lock();
        for a in taken.iter().chain([&free]) {
            st.results.insert(
                PeerAddr::Socket(*a),
                crate::net::survey::SurveyRecord {
                    fingerprint: known(Family::Btcd),
                    user_agent: BTCD.into(),
                    protocol_version: 70016,
                    services: 1 | 8 | 1024,
                    v2: false,
                    asn: None,
                    first_seen: now,
                    last_seen: now,
                    probes: Default::default(),
                    shape: None,
                    verdict: Default::default(),
                    retry: Default::default(),
                },
                now,
            );
        }
    }
    let config = pm.alt_slot_config();
    assert_eq!(
        pm.pick_alt_trial(Instant::now(), &[], &config),
        None,
        "records the book no longer holds"
    );
    learn(&pm, &taken);
    learn(&pm, &[free]);
    for _ in 0..20 {
        assert_eq!(
            pm.pick_alt_trial(Instant::now(), &[], &config),
            Some(PeerAddr::Socket(free))
        );
    }
    // From the book, with the store's records gone.
    pm.alt_slots.state.lock().results = crate::net::survey::SurveyStore::default();
    for _ in 0..20 {
        assert_eq!(
            pm.pick_alt_trial(Instant::now(), &[], &config),
            Some(PeerAddr::Socket(free))
        );
    }
}

/// Store candidates come verified first under `consistent`, and an address
/// whose record matches no rule is never drawn from the book.
#[test]
fn verified_store_candidates_first_and_known_misses_skipped() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 2, &["ua:*Knots*"], UaTrust::Consistent);
    let verified = own_group(1);
    let unverified = own_group(2);
    let core = own_group(3);
    let now = crate::time::now_secs();
    let rec = |fp, ua: &str| crate::net::survey::SurveyRecord {
        fingerprint: fp,
        user_agent: ua.into(),
        protocol_version: 70016,
        services: 1 | 8 | 1024,
        v2: false,
        asn: None,
        first_seen: now,
        last_seen: now,
        probes: Default::default(),
        shape: None,
        verdict: Default::default(),
        retry: Default::default(),
    };
    {
        let mut st = pm.alt_slots.state.lock();
        st.results.insert(
            PeerAddr::Socket(unverified),
            rec(Fingerprint::Unknown, KNOTS),
            now,
        );
        st.results.insert(
            PeerAddr::Socket(verified),
            rec(known(Family::Core), KNOTS),
            now,
        );
        st.results
            .insert(PeerAddr::Socket(core), rec(known(Family::Core), CORE), now);
    }
    learn(&pm, &[verified, unverified, core]);
    let config = pm.alt_slot_config();
    for _ in 0..10 {
        assert_eq!(
            pm.pick_alt_trial(Instant::now(), &[], &config),
            Some(PeerAddr::Socket(verified))
        );
    }
    pm.alt_slots.state.lock().results.insert(
        PeerAddr::Socket(verified),
        rec(known(Family::Core), CORE),
        now,
    );
    pm.alt_slots.state.lock().results.insert(
        PeerAddr::Socket(unverified),
        rec(known(Family::Core), CORE),
        now,
    );
    assert_eq!(
        pm.pick_alt_trial(Instant::now(), &[], &config),
        None,
        "every book entry is a known miss"
    );
}

/// A fake or closed-early survey record is no family for the alt-slot
/// rules, as an unknown one is not: under `family:core` neither is a store
/// candidate, and each is a known miss that is not drawn from the book.
#[test]
fn fake_and_closed_early_records_match_no_family_rule() {
    use crate::net::survey::Verdict;
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:core"], UaTrust::Consistent);
    let fake = own_group(1);
    let early = own_group(2);
    let core = own_group(3);
    let now = crate::time::now_secs();
    let rec = |fp, ua: &str, verdict| crate::net::survey::SurveyRecord {
        fingerprint: fp,
        user_agent: ua.into(),
        protocol_version: 70016,
        services: 1 | 8 | 1024,
        v2: false,
        asn: None,
        first_seen: now,
        last_seen: now,
        probes: Default::default(),
        shape: None,
        verdict,
        retry: Default::default(),
    };
    {
        let mut st = pm.alt_slots.state.lock();
        let claimed = Fingerprint::Known(Family::Core, Confidence::Claimed);
        st.results.insert(
            PeerAddr::Socket(fake),
            rec(claimed, "/Satoshi:25.0.0/", Verdict::Fake(Family::Core)),
            now,
        );
        st.results.insert(
            PeerAddr::Socket(early),
            rec(Fingerprint::Unknown, CORE, Verdict::ClosedEarly),
            now,
        );
        st.results.insert(
            PeerAddr::Socket(core),
            rec(known(Family::Core), CORE, Verdict::Classified),
            now,
        );
    }
    learn(&pm, &[fake, early, core]);
    let config = pm.alt_slot_config();
    for _ in 0..20 {
        assert_eq!(
            pm.pick_alt_trial(Instant::now(), &[], &config),
            Some(PeerAddr::Socket(core))
        );
    }
    // A closed-early result never replaces a settled one (the store keeps
    // the earlier fingerprint); a fake one does.
    let claimed = Fingerprint::Known(Family::Core, Confidence::Claimed);
    pm.alt_slots.state.lock().results.insert(
        PeerAddr::Socket(core),
        rec(claimed, CORE, Verdict::Fake(Family::Core)),
        now,
    );
    assert_eq!(
        pm.pick_alt_trial(Instant::now(), &[], &config),
        None,
        "every book entry is a known miss"
    );
}

// ---- Reload ----

/// Lowering `-altslots` turns the excess into ordinary peers, fallbacks
/// first, and disconnects nobody; new rules re-judge the matched ones.
#[test]
fn lowering_altslots_disconnects_nobody() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 3, &[], UaTrust::Consistent);
    let m = || {
        Some(AltRole::Matched {
            rule: "family:non-core".into(),
            trust: Trust::Verified,
        })
    };
    add_peer(
        &pm,
        settled(1, own_group(1), m(), known(Family::Btcd), BTCD),
    );
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            m(),
            known(Family::Floresta),
            "/Floresta:0.7.0/",
        ),
    );
    add_peer(
        &pm,
        settled(
            3,
            own_group(3),
            Some(AltRole::Fallback),
            known(Family::Core),
            CORE,
        ),
    );
    alt(&pm, 2, &[], UaTrust::Consistent);
    assert_eq!(role(&pm, 3), None, "the fallback goes first");
    assert!(role(&pm, 1).is_some() && role(&pm, 2).is_some());
    alt(&pm, 2, &["family:floresta"], UaTrust::Consistent);
    assert_eq!(role(&pm, 1), None, "btcd matches no rule now");
    assert!(
        matches!(role(&pm, 2), Some(AltRole::Matched { rule, .. }) if rule == "family:floresta")
    );
    alt(&pm, 0, &[], UaTrust::Consistent);
    assert_eq!(role(&pm, 2), None);
    assert!(
        (1..=3).all(|id| connected(&pm, id)),
        "nobody was disconnected"
    );
}

// ---- Eviction ----

/// A surplus full-relay peer is never one in an alt-slot by its rules, and
/// a trial does not count toward the surplus.
#[test]
fn surplus_eviction_spares_matched_and_trial_peers() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &[], UaTrust::Consistent);
    for i in 0..8 {
        add_peer(
            &pm,
            settled(
                i as PeerId + 1,
                own_group(i),
                None,
                known(Family::Core),
                CORE,
            ),
        );
    }
    add_peer(
        &pm,
        settled(
            9,
            own_group(9),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    assert_eq!(
        pm.evict_extra_outbound_peer(),
        None,
        "a trial is not surplus"
    );
    pm.peers.write().get_mut(&9).unwrap().info.alt = Some(AltRole::Matched {
        rule: "family:non-core".into(),
        trust: Trust::Verified,
    });
    let evicted = pm.evict_extra_outbound_peer().expect("one over the target");
    assert_ne!(evicted, 9, "never the matched peer");
}

// ---- Dial tagging ----

#[test]
fn spawn_peer_takes_the_role_of_its_dial() {
    let (pm, _dir) = mk_pm();
    let a = own_group(4);
    pm.alt_slots
        .state
        .lock()
        .dials
        .push((PeerAddr::Socket(a), AltRole::Fallback));
    assert_eq!(pm.take_alt_dial(&own_group(5), None), None);
    assert_eq!(pm.take_alt_dial(&a, None), Some(AltRole::Fallback));
    assert_eq!(pm.take_alt_dial(&a, None), None, "taken once");
}

/// A reload leaves the `-altfillwait` clock running: a periodic reload
/// cannot hold the fallback off for ever.
#[test]
fn a_reload_does_not_restart_the_fill_wait() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 2, &[], UaTrust::Consistent);
    let since = Instant::now() - Duration::from_secs(300);
    pm.alt_slots.state.lock().empty_since = Some(since);
    alt(&pm, 2, &[], UaTrust::Consistent);
    assert_eq!(pm.alt_slots.state.lock().empty_since, Some(since));
}

/// The extra peer for an unreached network (Core's
/// `MaybePickPreferredNetwork`) counts empty alt-slots as held, as the
/// automatic target does, so it is not held off for `-altfillwait`.
#[test]
fn the_extra_network_peer_counts_empty_alt_slots_as_held() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 2, &[], UaTrust::Consistent);
    for i in 0..6 {
        add_peer(
            &pm,
            settled(
                i as PeerId + 1,
                own_group(i),
                None,
                known(Family::Core),
                CORE,
            ),
        );
    }
    for i in 6..8 {
        let mut info = settled(
            i as PeerId + 1,
            own_group(i),
            None,
            known(Family::Core),
            CORE,
        );
        info.conn_type = ConnType::BlockRelay;
        add_peer(&pm, info);
    }
    assert!(pm.reserve_dial(DialBudget::ExtraNetwork).is_ok());
}

/// A trial that matched the rule's terms but was kept out by its flags is
/// not drawn again, though its record still matches.
#[test]
fn a_rejected_trial_is_not_drawn_again() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    let addr = own_group(1);
    learn(&pm, &[addr]);
    let mut info = settled(1, addr, Some(AltRole::Trial), known(Family::Btcd), BTCD);
    info.flags.flags = vec![(crate::net::flags::Flag::Crawler, Vec::new())];
    add_peer(&pm, info);
    pm.judge_alt_slot_peers();
    assert!(!connected(&pm, 1));
    assert!(
        pm.alt_slots
            .state
            .lock()
            .results
            .get(&PeerAddr::Socket(addr))
            .is_some(),
        "its record matches"
    );
    let config = pm.alt_slot_config();
    assert_eq!(pm.pick_alt_trial(Instant::now(), &[], &config), None);
}

/// With no candidate, the next look waits the trial interval.
#[test]
fn no_candidate_waits_the_trial_interval() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &[], UaTrust::Consistent);
    assert!(pm.open_alt_slot_peers(Instant::now(), &[]).is_empty());
    assert!(
        pm.alt_slots_next_trial()
            .is_some_and(|t| t > Instant::now() + Duration::from_secs(25))
    );
}

/// A dial's entry goes when the dial ends, however it ends.
#[test]
fn an_alt_dial_entry_goes_with_its_dial() {
    let (pm, _dir) = mk_pm();
    let a = own_group(4);
    let entry = pm.alt_dial_entry(PeerAddr::Socket(a), AltRole::Trial);
    assert_eq!(pm.alt_slots.state.lock().dials.len(), 1);
    drop(entry);
    assert!(pm.alt_slots.state.lock().dials.is_empty());
    assert_eq!(pm.take_alt_dial(&a, None), None);
}

/// A trial that leaves before it is judged is passed over too.
#[test]
fn a_trial_gone_before_judgement_is_not_drawn_again() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    let addr = own_group(1);
    learn(&pm, &[addr]);
    let mut info = settled(1, addr, Some(AltRole::Trial), Fingerprint::Unknown, BTCD);
    info.flags.settled = false;
    add_peer(&pm, info);
    let config = pm.alt_slot_config();
    pm.disconnect_peer(1, "peer-closed");
    assert_eq!(pm.pick_alt_trial(Instant::now(), &[], &config), None);
    pm.alt_slots.state.lock().rejected.clear();
    assert_eq!(
        pm.pick_alt_trial(Instant::now(), &[], &config),
        Some(PeerAddr::Socket(addr)),
        "otherwise drawn"
    );
}

/// A trial never takes the connection count past `-maxconnections`.
#[test]
fn a_trial_stays_under_maxconnections() {
    let (pm, _dir) = mk_pm();
    pm.set_max_connections(1);
    alt(&pm, 1, &[], UaTrust::Consistent);
    assert!(pm.check_alt_trial(&pm.dials_in_flight.lock()).is_ok());
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Fallback),
            known(Family::Core),
            CORE,
        ),
    );
    assert!(pm.check_alt_trial(&pm.dials_in_flight.lock()).is_err());
}

/// A trial and a fallback that both match with one slot: the trial takes
/// it and the fallback goes. A trial with no slot left is not passed over.
#[test]
fn a_trial_is_judged_before_a_fallback() {
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    add_peer(
        &pm,
        settled(
            1,
            own_group(1),
            Some(AltRole::Fallback),
            known(Family::Btcd),
            BTCD,
        ),
    );
    add_peer(
        &pm,
        settled(
            2,
            own_group(2),
            Some(AltRole::Trial),
            known(Family::Btcd),
            BTCD,
        ),
    );
    pm.judge_alt_slot_peers();
    assert!(matches!(role(&pm, 2), Some(AltRole::Matched { .. })));
    assert!(!connected(&pm, 1), "the fallback is surplus");

    let m = AltRole::Matched {
        rule: "family:btcd".into(),
        trust: Trust::Verified,
    };
    let (pm, _dir) = mk_pm();
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    add_peer(
        &pm,
        settled(1, own_group(1), Some(m), known(Family::Btcd), BTCD),
    );
    let addr = own_group(2);
    learn(&pm, &[addr]);
    add_peer(
        &pm,
        settled(2, addr, Some(AltRole::Trial), known(Family::Btcd), BTCD),
    );
    pm.judge_alt_slot_peers();
    assert!(!connected(&pm, 2));
    assert!(
        pm.retired_behavior
            .lock()
            .contains(&(2, Some("alt-slot-filled")))
    );
    assert!(
        pm.alt_slots.state.lock().rejected.is_empty(),
        "not passed over"
    );
}

/// A trial's record keeps the probe outcomes a survey connection stored.
#[test]
fn a_trial_result_keeps_the_survey_probes() {
    let (pm, _dir) = mk_pm();
    pm.enable_survey(SurveyConfig {
        interval: Duration::from_secs(60),
        probes: true,
        path: None,
    });
    alt(&pm, 1, &["family:btcd"], UaTrust::Consistent);
    let addr = own_group(1);
    let now = crate::time::now_secs();
    let mut probes = crate::net::survey::ProbeResults::default();
    probes.set(
        crate::net::survey::Probe::Ping,
        crate::net::survey::ProbeOutcome::Answered(12),
    );
    let record = crate::net::survey::SurveyRecord {
        fingerprint: known(Family::Btcd),
        user_agent: BTCD.into(),
        protocol_version: 70016,
        services: 1 | 8 | 1024,
        v2: false,
        asn: None,
        first_seen: now,
        last_seen: now,
        probes,
        shape: None,
        verdict: Default::default(),
        retry: Default::default(),
    };
    assert!(pm.insert_survey_record(PeerAddr::Socket(addr), record, now));
    add_peer(
        &pm,
        settled(1, addr, Some(AltRole::Trial), known(Family::Btcd), BTCD),
    );
    pm.judge_alt_slot_peers();
    let kept = pm
        .read_survey_store(|s| s.get(&PeerAddr::Socket(addr)).map(|r| r.probes))
        .flatten();
    assert_eq!(kept, Some(probes));
}
