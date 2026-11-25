//! The network survey's connections (`survey_conn`) against a live
//! `PeerManager` and scripted peers on loopback.

use super::*;
use crate::net::fingerprint::{Confidence, Family, Fingerprint};
use crate::net::survey::{Probe, ProbeOutcome, Verdict};
use bitcoin::p2p::Magic;
use bitcoin::p2p::address::Address;

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    mk_pm_with(None)
}

/// A regtest manager; with `proxy`, onions are reachable through it.
pub(super) fn mk_pm_with(proxy: Option<&str>) -> (Arc<PeerManager>, tempfile::TempDir) {
    let (pm, dir, _shutdown) = mk_pm_live(proxy);
    (pm, dir)
}

/// [`mk_pm_with`], and the sender of its shutdown signal, which a task the
/// manager runs (a loop that ends at shutdown) needs alive.
pub(super) fn mk_pm_live(proxy: Option<&str>) -> (Arc<PeerManager>, tempfile::TempDir, tokio::sync::watch::Sender<bool>) {
    mk_pm_proxies(None, proxy)
}

/// A regtest manager under `-proxy`: every routable dial goes through it.
pub(super) fn mk_pm_proxied(proxy: &str) -> (Arc<PeerManager>, tempfile::TempDir) {
    let (pm, dir, _shutdown) = mk_pm_proxies(Some(proxy), None);
    (pm, dir)
}

fn mk_pm_proxies(
    proxy: Option<&str>,
    onion_proxy: Option<&str>,
) -> (Arc<PeerManager>, tempfile::TempDir, tokio::sync::watch::Sender<bool>) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::with_config(
        chain_state,
        Arc::new(Mempool::new(1_000_000, 0)),
        Arc::new(FeeEstimator::new()),
        Network::Regtest,
        shutdown_rx,
        0,
        125,
        DEFAULT_MAX_INBOUND_PER_IP,
        86400,
        proxy.map(str::to_string),
        onion_proxy.map(str::to_string),
        1,
        50_000,
        0,
        None,
    );
    (pm, dir, shutdown_tx)
}

fn enable(pm: &PeerManager, probes: bool) {
    pm.enable_survey(SurveyConfig { interval: Duration::from_secs(60), probes, path: None });
}

fn add_handle(pm: &PeerManager, info: PeerInfo) {
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

fn outbound(id: PeerId, addr: SocketAddr, conn_type: ConnType, state: PeerState) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.conn_type = conn_type;
    info.state = state;
    info
}

pub(super) fn book_add(pm: &PeerManager, addr: SocketAddr) {
    pm.addrman.write().add_from(addr, now_unix_secs(), 1 | 8, "198.51.100.7".parse::<IpAddr>().unwrap());
}

pub(super) const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

// ---- Budgets and visibility ----

/// A survey connection takes no outbound slot or grant: with the
/// automatic connections one short of Core's `semOutbound` limit, an
/// open survey connection leaves room for the last one, and it counts
/// toward neither the automatic target nor the sockets the grant holds.
#[test]
fn a_survey_connection_takes_no_outbound_slot_or_grant() {
    let (pm, _dir) = mk_pm();
    pm.set_max_connections(125);
    let limit = pm.max_automatic_outbound();
    for i in 0..limit - 1 {
        let addr = SocketAddr::from(([203, 0, 113, i as u8 + 1], 8333));
        add_handle(&pm, outbound(1000 + i as PeerId, addr, ConnType::OutboundFullRelay, PeerState::Connected));
    }
    let before = (pm.automatic_outbound_peers(), pm.automatic_sockets_open(&pm.dials_in_flight.lock()));
    add_handle(&pm, outbound(1, SocketAddr::from(([198, 51, 100, 9], 8333)), ConnType::Survey, PeerState::Connecting));
    let after = (pm.automatic_outbound_peers(), pm.automatic_sockets_open(&pm.dials_in_flight.lock()));
    assert_eq!(before, after, "the survey connection is in no count");
    let in_flight = pm.dials_in_flight.lock();
    let pending = pm.pending_typed_dials.read();
    assert!(
        pm.check_outbound_limit_for(ConnType::AddrFetch, &pending, &in_flight).is_ok(),
        "the last grant is still free"
    );
    assert!(pm.check_outbound_limit_for(ConnType::Survey, &pending, &in_flight).is_err(), "addconnection cannot open one");
}

/// `getpeerinfo`, `getconnectioncount` and `getpeerbehavior` leave a
/// survey connection out, and agree with each other.
#[test]
fn peer_lists_leave_survey_connections_out() {
    let (pm, _dir) = mk_pm();
    add_handle(&pm, outbound(1, SocketAddr::from(([198, 51, 100, 1], 8333)), ConnType::OutboundFullRelay, PeerState::Connected));
    add_handle(&pm, outbound(2, SocketAddr::from(([198, 51, 100, 2], 8333)), ConnType::Survey, PeerState::Connecting));
    assert_eq!(pm.connection_count(), 1);
    let info = pm.get_peer_info();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0]["id"], 1);
    assert_eq!(pm.get_peer_behavior(None).unwrap().len(), 1);
    assert!(pm.get_peer_behavior(Some(2)).is_none(), "not by id either");
}

// ---- The draw ----

/// Every reachable address, tried or new, is drawn with the same odds.
#[test]
fn the_survey_draws_uniformly_from_new_and_tried() {
    let (pm, _dir) = mk_pm();
    let addrs: Vec<SocketAddr> = (0..4).map(|i| SocketAddr::from(([1 + i as u8, 2, 3, 4], 8333))).collect();
    for a in &addrs {
        book_add(&pm, *a);
    }
    pm.addrman.write().mark_good(PeerAddr::Socket(addrs[0]), now_unix_secs());
    pm.addrman.write().mark_good(PeerAddr::Socket(addrs[1]), now_unix_secs());
    assert_eq!(pm.addrman.read().counts_by_network()["ipv4"].tried, 2, "fixture: two tried, two new");
    let mut seen = HashMap::new();
    for _ in 0..4_000 {
        *seen.entry(pm.draw_survey_target().unwrap()).or_insert(0usize) += 1;
    }
    assert_eq!(seen.len(), 4);
    for (addr, n) in seen {
        assert!((800..1_200).contains(&n), "{addr} drawn {n} times of 4000");
    }
}

/// A node that reaches only Tor surveys only onions: a clearnet address
/// is never drawn, and with only clearnet in the book no survey dial
/// starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_only_node_never_surveys_clearnet() {
    let (pm, _dir) = mk_pm_with(Some("127.0.0.1:1"));
    pm.set_reachable(crate::net::reachable::ReachableNets {
        ipv4: false,
        ipv6: false,
        onion: true,
        ..Default::default()
    });
    enable(&pm, false);
    for i in 0..20 {
        book_add(&pm, SocketAddr::from(([1 + i as u8, 2, 3, 4], 8333)));
    }
    assert_eq!(pm.draw_survey_target(), None, "only clearnet in the book");
    assert_eq!(pm.survey_tick(), None);
    assert!(pm.pending_connections.read().is_empty(), "no clearnet dial");

    let onion = PeerAddr::Onion { host: ONION.to_string(), port: 8333 };
    pm.addrman.write().add_manual(onion.clone(), false, crate::time::now_secs()).unwrap();
    for _ in 0..200 {
        assert_eq!(pm.draw_survey_target(), Some(onion.clone()));
    }
    // Under `-onion=0` not even that.
    pm.set_onion_disabled(true);
    assert_eq!(pm.draw_survey_target(), None);
}

/// The draw passes over what an automatic dial passes over: a peer the
/// operator named, a banned address, one already connected and a bad
/// port.
#[test]
fn the_survey_passes_over_named_banned_connected_and_bad_port_addresses() {
    let (pm, _dir) = mk_pm();
    let named = SocketAddr::from(([1, 1, 1, 1], 8333));
    let banned = SocketAddr::from(([2, 2, 2, 2], 8333));
    let connected = SocketAddr::from(([3, 3, 3, 3], 8333));
    let bad_port = SocketAddr::from(([4, 4, 4, 4], 22));
    for a in [named, banned, connected, bad_port] {
        book_add(&pm, a);
    }
    pm.manual_addrs.write().insert(named);
    let _ = pm.ban_list.write().add(
        &crate::net::ban::BanTarget::Net(ipnet::IpNet::from(banned.ip())),
        crate::time::now_secs(),
        crate::time::now_secs() + 3_600,
    );
    add_handle(&pm, outbound(1, connected, ConnType::OutboundFullRelay, PeerState::Connected));
    for _ in 0..200 {
        assert_eq!(pm.draw_survey_target(), None);
    }
    let fine = SocketAddr::from(([5, 5, 5, 5], 8333));
    book_add(&pm, fine);
    assert_eq!(pm.draw_survey_target(), Some(PeerAddr::Socket(fine)));
}

/// At most one survey connection: none is dialled while one is open, and
/// none under `-connect` or with networking off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_survey_connection_at_a_time() {
    let (pm, _dir) = mk_pm();
    enable(&pm, false);
    book_add(&pm, SocketAddr::from(([5, 5, 5, 5], 8333)));
    add_handle(&pm, outbound(1, SocketAddr::from(([6, 6, 6, 6], 8333)), ConnType::Survey, PeerState::Connecting));
    assert_eq!(pm.survey_tick(), None, "one is open");
    pm.peers.write().clear();
    pm.set_automatic_outbound(false);
    assert_eq!(pm.survey_tick(), None, "-connect");
    pm.set_automatic_outbound(true);
    pm.network_active.store(false, Ordering::Relaxed);
    assert_eq!(pm.survey_tick(), None, "networking off");
    pm.network_active.store(true, Ordering::Relaxed);
    assert!(pm.survey_tick().is_some());
    assert_eq!(pm.survey_tick(), None, "the first is still being dialled");
}

/// With the survey off nothing about it runs: no dial, and
/// `getpeersurvey` says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_survey_off_nothing_is_dialled() {
    let (pm, _dir) = mk_pm();
    book_add(&pm, SocketAddr::from(([5, 5, 5, 5], 8333)));
    assert!(!pm.survey_enabled());
    assert_eq!(pm.survey_tick(), None);
    pm.spawn_survey();
    assert!(pm.pending_connections.read().is_empty());
    let json = pm.get_peer_survey(true);
    assert_eq!(json["enabled"], false);
    assert_eq!(json["addresses"], 0);
    assert!(pm.survey_metrics().is_none());
    assert!(json.get("connections").is_none(), "no connection counts with the survey off");
}

// ---- The session ----

/// How a scripted peer behaves once dialled.
#[derive(Clone)]
struct Script {
    user_agent: &'static str,
    /// Sent between our `version` and its `verack`.
    negotiation: Vec<NetworkMessage>,
    /// Sent once our `verack` arrives.
    after_verack: Vec<NetworkMessage>,
    /// Answer `getheaders` and `getdata` as Core does.
    answer: bool,
    /// Close the connection on an unknown message.
    close_on_unknown: bool,
    /// How long the connection is served before the peer hangs up.
    hold: Duration,
}

/// Core 31.2 as the capture `core-31.2-outbound` shows it when dialled.
fn core_script() -> Script {
    Script {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![
            NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct { send_compact: false, version: 2 }),
            NetworkMessage::Ping(77),
        ],
        answer: true,
        close_on_unknown: false,
        hold: Duration::from_secs(30),
    }
}

/// Serve `scripts.len()` connections on `listener`, one after the other,
/// each by its script, returning what each received.
async fn serve(listener: tokio::net::TcpListener, scripts: Vec<Script>) -> Vec<Vec<NetworkMessage>> {
    let mut all = Vec::new();
    for script in scripts {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = Connection::with_magic(stream, Magic::REGTEST);
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + script.hold;
        loop {
            let msg = match tokio::time::timeout_at(deadline, conn.recv()).await {
                Ok(Ok(m)) => m,
                _ => break,
            };
            got.push(msg.clone());
            match msg {
                NetworkMessage::Version(_) => {
                    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                    let _ = conn
                        .send(NetworkMessage::Version(VersionMessage {
                            version: 70016,
                            services,
                            timestamp: crate::time::now_secs() as i64,
                            receiver: Address::new(&zero, ServiceFlags::NONE),
                            sender: Address::new(&zero, services),
                            nonce: 0x5eed,
                            user_agent: script.user_agent.into(),
                            start_height: 0,
                            relay: true,
                        }))
                        .await;
                    for m in &script.negotiation {
                        let _ = conn.send(m.clone()).await;
                    }
                    let _ = conn.send(NetworkMessage::Verack).await;
                }
                NetworkMessage::Verack => {
                    for m in &script.after_verack {
                        let _ = conn.send(m.clone()).await;
                    }
                }
                NetworkMessage::Ping(n) => {
                    let _ = conn.send(NetworkMessage::Pong(n)).await;
                }
                NetworkMessage::GetHeaders(_) if script.answer => {
                    let _ = conn.send(NetworkMessage::Headers(Vec::new())).await;
                }
                NetworkMessage::GetData(inv) if script.answer => {
                    let _ = conn.send(NetworkMessage::NotFound(inv)).await;
                }
                NetworkMessage::Unknown { .. } if script.close_on_unknown => break,
                _ => {}
            }
        }
        all.push(got);
    }
    all
}

async fn wait_for(cond: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Dial one survey connection to a scripted peer and wait for it to end.
/// Returns what the peer received and the manager.
async fn survey_one(script: Script, probes: Option<Vec<Probe>>) -> (Vec<NetworkMessage>, Arc<PeerManager>, SocketAddr, tempfile::TempDir) {
    let (pm, dir) = mk_pm();
    enable(&pm, probes.is_some());
    if let Some(p) = probes {
        *pm.survey.get().unwrap().forced_probes.lock() = Some(p);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    book_add(&pm, target);
    let server = tokio::spawn(serve(listener, vec![script]));
    assert_eq!(pm.survey_tick(), Some(PeerAddr::Socket(target)));
    let run = || pm.survey_metrics().unwrap();
    wait_for(|| run().completed + run().failed == 1, "the survey connection ends").await;
    let got = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap().remove(0);
    (got, pm, target, dir)
}

fn commands(msgs: &[NetworkMessage]) -> Vec<String> {
    msgs.iter().map(|m| crate::net::behavior::wire_command(m).to_string()).collect()
}

/// A survey connection's handshake is a full-relay outbound's, byte for
/// byte but the `version`'s nonce and time: the same `version` (`relay`
/// set), negotiation, `verack`, `sendheaders`, `sendcmpct` and
/// `feefilter`. What a full-relay outbound sends past those (`getaddr`,
/// `getheaders`, our addresses, its pings) the survey does not send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_survey_handshake_is_a_full_relay_outbounds() {
    let (pm, _dir) = mk_pm();
    enable(&pm, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    book_add(&pm, target);
    // The full-relay outbound's peer hangs up after 3 s: the manager loop
    // does not run here, so nothing else would close that connection
    // before the survey dials.
    let first = Script { hold: Duration::from_secs(3), ..core_script() };
    let server = tokio::spawn(serve(listener, vec![first, core_script()]));

    // A full-relay outbound, held for a few seconds, then the survey.
    pm.connect_outbound_inner(target, None, None, false).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let id = *pm.peers.read().keys().next().unwrap();
    assert_eq!(pm.conn_type_of(id), ConnType::OutboundFullRelay);
    pm.disconnect_peer(id, "test");
    wait_for(|| pm.peers.read().is_empty() && pm.pending_connections.read().is_empty(), "the first connection closes").await;
    assert!(pm.survey_tick().is_some());
    wait_for(|| pm.survey_metrics().unwrap().completed == 1, "the survey ends").await;
    let mut got = tokio::time::timeout(Duration::from_secs(40), server).await.unwrap().unwrap();
    let (survey, normal) = (got.pop().unwrap(), got.pop().unwrap());

    let past_handshake = ["getaddr", "getheaders", "addr", "addrv2", "ping", "inv"];
    let expected: Vec<&NetworkMessage> = normal
        .iter()
        .filter(|m| !past_handshake.contains(&crate::net::behavior::wire_command(m)))
        .collect();
    assert_eq!(
        commands(&survey),
        ["version", "wtxidrelay", "sendaddrv2", "verack", "sendheaders", "sendcmpct", "feefilter", "pong"],
        "normal: {:?}",
        commands(&normal)
    );
    for (s, n) in survey.iter().zip(&expected) {
        match (s, n) {
            (NetworkMessage::Version(a), NetworkMessage::Version(b)) => {
                let mut b = b.clone();
                b.nonce = a.nonce;
                b.timestamp = a.timestamp;
                assert_eq!(*a, b, "the version, nonce and time aside");
                assert!(a.relay, "relay set, as a full-relay outbound sets it");
            }
            (NetworkMessage::FeeFilter(_), NetworkMessage::FeeFilter(_)) => {}
            (a, b) => assert_eq!(a, *b),
        }
    }
    assert!(commands(&normal).contains(&"getaddr".to_string()), "fixture: the full-relay outbound asked for addresses");
}

/// The survey records what the peer showed (its fingerprint, user agent,
/// services) once the passive wait ends, marks the address good in the
/// book as a feeler does, and closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_survey_records_the_peer_and_marks_its_address_good() {
    let (_got, pm, target, _dir) = survey_one(core_script(), None).await;
    let addr = PeerAddr::Socket(target);
    let store = pm.survey_store().unwrap();
    let r = store.get(&addr).expect("a record");
    assert_eq!(r.fingerprint, Fingerprint::Known(Family::Core, Confidence::High));
    assert_eq!(r.user_agent, "/Satoshi:32.1.0/");
    assert_eq!(r.services, (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64());
    assert!(!r.v2);
    assert!(!r.probes.any(), "probes off");
    assert!(pm.addrman.read().tried_bucket(&addr).is_some(), "moved to tried, as a feeler's answer moves it");
    assert!(pm.peers.read().is_empty(), "closed and gone");
    let json = pm.get_peer_survey(false);
    assert_eq!(json["families"]["core"]["count"], 1);
    assert_eq!(json["connections"]["completed"], 1);
    assert_eq!(json["connections"]["last"]["result"], "completed");
    let when = json["connections"]["last"]["time"].as_u64().unwrap();
    assert!(crate::time::now_secs().abs_diff(when) < 60, "{json}");
}

/// A peer whose shape no row matches, under a user agent naming a family,
/// is recorded at `claimed`: under its family in `claimed`, never in
/// `families` (as observed or unknown), with its raw shape kept in the
/// record and shown by `getpeersurvey true`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_survey_of_a_shape_no_row_matches_is_claimed_and_keeps_its_shape() {
    let mut script = core_script();
    script.user_agent = "/Satoshi:25.1.0/";
    // An `inv` straight after `verack`: no captured release sends that.
    script.after_verack = vec![NetworkMessage::Inv(Vec::new())];
    let (_got, pm, target, _dir) = survey_one(script, None).await;
    let r = pm.survey_store().unwrap().get(&PeerAddr::Socket(target)).cloned().expect("a record");
    assert_eq!(r.fingerprint, Fingerprint::Known(Family::Core, Confidence::Claimed));
    let shape = r.shape.expect("the raw shape is kept");
    assert_eq!(shape.commands, ["version", "wtxidrelay", "sendaddrv2", "verack", "inv"]);
    assert!(shape.relay);
    assert_eq!(r.verdict, Verdict::Classified, "it said more than `verack`: no fake");
    let json = pm.get_peer_survey(false);
    assert_eq!(json["families"]["core"]["count"], 0, "a claim is never an observed family");
    assert_eq!(json["families"]["unknown"]["count"], 0, "nor unknown");
    assert_eq!(json["claimed"]["core"]["count"], 1);
    let metrics = pm.survey_metrics().unwrap();
    assert_eq!((metrics.families[0], metrics.unknown, metrics.claimed[0]), (0, 0, 1));
    let verbose = pm.get_peer_survey(true);
    let row = &verbose["peers"][0];
    assert_eq!(row["fingerprint"], "core/claimed");
    assert_eq!(row["family"], serde_json::Value::Null);
    assert_eq!(row["claimed"], "core");
    assert_eq!(row["handshake"], serde_json::json!(["version", "wtxidrelay", "sendaddrv2", "verack", "inv"]));
}

/// Each probe sends its message and records the answer: the `pong`'s
/// round trip, the `notfound` naming our transaction, and silence after
/// the unknown message. At genesis the `getheaders` probe is not sent: no
/// stop hash lies past the locator, so a peer would answer with 2,000
/// headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probes_send_the_vetted_messages_and_record_the_answers() {
    let order = vec![Probe::Unknown, Probe::GetData, Probe::GetHeaders, Probe::Ping];
    let (got, pm, target, _dir) = survey_one(core_script(), Some(order)).await;
    assert_eq!(pm.chain_state.tip_height(), 0, "fixture: at genesis");
    let cmds = commands(&got);
    let tail: Vec<&str> = cmds.iter().map(String::as_str).skip_while(|c| *c != "pong").skip(1).collect();
    assert_eq!(tail.len(), 3, "{cmds:?}");
    assert!(tail[0].len() >= 6 && tail[0].bytes().all(|b| b.is_ascii_lowercase()), "an unknown type: {tail:?}");
    assert_eq!(&tail[1..], ["getdata", "ping"]);
    let r = pm.survey_store().unwrap().get(&PeerAddr::Socket(target)).cloned().unwrap();
    assert_eq!(r.probes.get(Probe::Unknown), Some(ProbeOutcome::Silent));
    assert_eq!(r.probes.get(Probe::GetData), Some(ProbeOutcome::Answered(1)));
    assert_eq!(r.probes.get(Probe::GetHeaders), None, "not sent at genesis");
    assert!(matches!(r.probes.get(Probe::Ping), Some(ProbeOutcome::Answered(_))));
    let m = pm.survey_metrics().unwrap();
    assert_eq!(m.probe_outcomes[0][0], 1, "ping answered");
    assert_eq!(m.probe_outcomes[3][1], 1, "unknown silent");
}

/// A peer that closes over a probe ends the probing: it is recorded as
/// disconnected and nothing more is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_closes_over_a_probe_gets_no_more() {
    let script = Script { answer: false, close_on_unknown: true, ..core_script() };
    let (got, pm, target, _dir) = survey_one(script, Some(vec![Probe::GetData, Probe::Unknown, Probe::Ping])).await;
    let cmds = commands(&got);
    assert!(!cmds.iter().skip_while(|c| *c != "getdata").any(|c| c == "ping"), "{cmds:?}");
    let r = pm.survey_store().unwrap().get(&PeerAddr::Socket(target)).cloned().unwrap();
    assert_eq!(r.probes.get(Probe::GetData), Some(ProbeOutcome::Silent));
    assert_eq!(r.probes.get(Probe::Unknown), Some(ProbeOutcome::Disconnected));
    assert_eq!(r.probes.get(Probe::Ping), None);
    // Its transcript had settled before it closed: judged as it is.
    assert_eq!(r.verdict, Verdict::Classified);
    assert_eq!(r.fingerprint, Fingerprint::Known(Family::Core, Confidence::High));
}

/// A peer that closes the connection during the passive wait, its
/// transcript still open (a node with full inbound slots evicting the
/// survey connection, its newest), gets no fingerprint: the record keeps
/// the `version`'s fields, is closed early, and is counted on that tally
/// alone. It still counts as a completed survey connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_closes_during_the_passive_wait_is_closed_early() {
    let script = Script { after_verack: vec![], hold: Duration::from_secs(1), ..core_script() };
    let (_got, pm, target, _dir) = survey_one(script, Some(Probe::ALL.to_vec())).await;
    let r = pm.survey_store().unwrap().get(&PeerAddr::Socket(target)).cloned().expect("a record");
    assert_eq!(r.verdict, Verdict::ClosedEarly);
    assert_eq!(r.fingerprint, Fingerprint::Unknown, "no fingerprint");
    assert_eq!(r.user_agent, "/Satoshi:32.1.0/");
    assert_eq!(r.protocol_version, 70016);
    assert!(!r.probes.any(), "no probe after the close");
    let json = pm.get_peer_survey(false);
    assert_eq!(json["closed_early"]["count"], 1);
    assert_eq!(json["closed_early"]["share"], 1.0);
    for family in ["core", "unknown"] {
        assert_eq!(json["families"][family]["count"], 0, "{family}: {json}");
    }
    assert_eq!(json["claimed"]["core"]["count"], 0);
    assert_eq!(json["fake"]["core"]["count"], 0);
    assert_eq!(json["connections"]["completed"], 1);
    let m = pm.survey_metrics().unwrap();
    assert_eq!((m.closed_early, m.unknown, m.claimed[0], m.fake[0]), (1, 0, 0, 0));
    assert_eq!(pm.get_peer_survey(true)["peers"][0]["fingerprint"], "closed-early");
}

/// A peer claiming Core at protocol 70016 that sends `version` and
/// `verack` and then nothing, the connection open through the whole
/// passive wait, is fake: counted on its own tally under Core, never as
/// Core, a claim or unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_peer_claiming_core_is_fake() {
    let script = Script { user_agent: "/Satoshi:25.0.0/", negotiation: vec![], after_verack: vec![], ..core_script() };
    let (_got, pm, target, _dir) = survey_one(script, None).await;
    let r = pm.survey_store().unwrap().get(&PeerAddr::Socket(target)).cloned().expect("a record");
    assert_eq!(r.verdict, Verdict::Fake(Family::Core));
    assert_eq!(r.fingerprint, Fingerprint::Known(Family::Core, Confidence::Claimed));
    assert_eq!(r.shape.as_ref().map(|s| s.commands.clone()), Some(vec!["version".to_string(), "verack".to_string()]));
    let json = pm.get_peer_survey(false);
    assert_eq!(json["fake"]["core"]["count"], 1);
    for family in ["core", "unknown"] {
        assert_eq!(json["families"][family]["count"], 0, "{family}: {json}");
    }
    assert_eq!(json["claimed"]["core"]["count"], 0);
    assert_eq!(json["closed_early"]["count"], 0);
    let m = pm.survey_metrics().unwrap();
    assert_eq!((m.fake[0], m.claimed[0], m.unknown, m.closed_early), (1, 0, 0, 0));
    let row = &pm.get_peer_survey(true)["peers"][0];
    assert_eq!(row["fingerprint"], "fake/core");
    assert_eq!(row["claimed"], "core");
}

/// A survey dial that fails counts as failed and marks an attempt on the
/// address, as any automatic dial's failure does, and records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_survey_dial_records_nothing() {
    let (pm, _dir) = mk_pm();
    enable(&pm, true);
    // Bound and closed: nothing listens.
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    book_add(&pm, target);
    assert!(pm.survey_tick().is_some());
    wait_for(|| pm.survey_metrics().unwrap().failed == 1, "the dial fails").await;
    wait_for(|| !pm.survey_open(), "the dial ends").await;
    assert!(pm.survey_store().unwrap().is_empty());
    assert!(pm.reconnect_backoff.read().get(&target).is_some_and(|s| s.attempts > 0));
    assert_eq!(pm.get_peer_survey(false)["connections"]["last"]["result"], "failed");
}

/// A survey connection the node closes (`disconnectnode`, a ban,
/// `setnetworkactive false`, shutdown) closes there and then: no probe
/// follows, and nothing is recorded. Its handle going made the transcript
/// read as closed, which once sent the session on into its probes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_survey_connection_the_node_closes_ends_at_once() {
    let (pm, _dir) = mk_pm();
    enable(&pm, true);
    *pm.survey.get().unwrap().forced_probes.lock() = Some(Probe::ALL.to_vec());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    book_add(&pm, target);
    // btcd's shape: nothing after `verack`, so the passive wait runs its
    // full ten seconds unless the node ends it.
    let script = Script { negotiation: vec![NetworkMessage::SendAddrV2], after_verack: vec![], ..core_script() };
    let server = tokio::spawn(serve(listener, vec![script]));
    assert!(pm.survey_tick().is_some());
    wait_for(|| pm.peers.read().values().any(|h| h.info.behavior.handshake.len() >= 3), "the handshake").await;
    let id = *pm.peers.read().keys().next().unwrap();
    let closed_at = Instant::now();
    assert!(pm.disconnect_peer(id, "test"));
    let got = tokio::time::timeout(Duration::from_secs(5), server).await.expect("the socket closes at once").unwrap().remove(0);
    assert!(closed_at.elapsed() < Duration::from_secs(5));
    let cmds = commands(&got);
    for probe in ["ping", "getheaders", "getdata"] {
        assert!(!cmds.iter().any(|c| c == probe), "no {probe} after the close: {cmds:?}");
    }
    assert!(pm.survey_store().unwrap().is_empty(), "nothing recorded");
}

/// Past genesis the `getheaders` probe's locator is the tip's parent and
/// its stop the tip, so a peer on our chain answers with one header.
#[test]
fn the_getheaders_probe_asks_for_one_header_past_genesis() {
    use crate::chain::state::tests::{build_test_block, make_chain_state};
    let (cs, _dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let pm = PeerManager::new(
        Arc::new(cs),
        Arc::new(Mempool::new(1_000_000, 0)),
        Arc::new(FeeEstimator::new()),
        Network::Regtest,
        tokio::sync::watch::channel(false).1,
    );
    assert_eq!(pm.survey_locator(), None, "none at genesis");
    let time = (crate::time::now_secs() - 600) as u32;
    let block = build_test_block(genesis, 1, time);
    let tip = pm.chain_state.accept_block(&block).expect("connect fixture block").hash();
    assert_eq!(pm.survey_locator(), Some((genesis, tip)));
}
