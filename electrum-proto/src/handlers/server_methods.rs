//! `server.*` method handlers.
//!
//! Static or near-static metadata endpoints: version negotiation,
//! ping, banner, donation address, feature dict, and the
//! always-empty-list `peers.subscribe`.

use serde_json::{Value, json};

use crate::PROTOCOL_ASOF;
use crate::error::JsonRpcError;
use crate::state::ElectrumState;
use crate::version::{Negotiated, PROTOCOL_MAX, PROTOCOL_MIN, negotiate};

/// `server.version([client_name, protocol_version, ...])` — returns
/// `[server_name, protocol_version]`, the version agreed on by the spec's
/// rule (see [`crate::version`]). rbitcoin's dialect [`PROTOCOL_ASOF`] is
/// accepted too and answered with that string.
///
/// This is the stateless half: the per-connection rules (only the first
/// `server.version` is accepted, and a failed one closes the connection)
/// are applied by [`crate::dispatch::dispatch_session`].
pub fn version(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let negotiated = negotiate(&params).ok_or_else(no_common_version)?;
    Ok(version_answer(state, &negotiated))
}

/// `server.version`'s result for what was agreed.
pub fn version_answer(state: &ElectrumState, negotiated: &Negotiated) -> Value {
    json!([server_name(state), negotiated.answer])
}

/// The error for a `server.version` with no version in common.
pub fn no_common_version() -> JsonRpcError {
    let supported = if PROTOCOL_MIN == PROTOCOL_MAX {
        PROTOCOL_MAX.to_string()
    } else {
        format!("{PROTOCOL_MIN} to {PROTOCOL_MAX}")
    };
    JsonRpcError::bad_request(format!(
        "unsupported protocol version; server speaks {supported}"
    ))
}

/// The error for a second `server.version` on a connection, ElectrumX's
/// (spec 1.4: only the first `server.version` message is accepted).
pub fn version_already_sent() -> JsonRpcError {
    JsonRpcError::bad_request("server.version already sent")
}

/// `server.ping()` — returns `null`.
pub fn ping() -> Result<Value, JsonRpcError> {
    Ok(Value::Null)
}

/// `server.banner()` — returns the configured banner or a default
/// composed at request time.
pub fn banner(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let s = state.config.banner.clone().unwrap_or_else(|| {
        format!(
            "powered by satd {}\nhttps://github.com/epochbtc/satd",
            env!("CARGO_PKG_VERSION")
        )
    });
    Ok(Value::String(s))
}

/// `server.donation_address()` — returns the configured donation
/// address (empty string by default).
pub fn donation_address(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    Ok(Value::String(state.config.donation_address.clone()))
}

/// `server.features()` — small descriptor dict consumed by some
/// clients: genesis hash, supported protocol min/max ([`PROTOCOL_MIN`],
/// [`PROTOCOL_MAX`]), server name, and the
/// `hosts` map populated with `tcp_port` (and `ssl_port` when TLS is
/// bound) so peer-discovery clients can distinguish service ports.
///
/// `hosts` follows the Electrum spec — `{"<host>": {"tcp_port": N}}` —
/// rather than `romanz/electrs`, which emits a flat `{"tcp_port": N}`
/// with no host level.
pub fn features(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let genesis_hash = state
        .chain
        .get_block_hash_by_height(0)
        .map(|h| h.to_string())
        .unwrap_or_default();
    let mut host_entry = serde_json::Map::new();
    host_entry.insert("tcp_port".into(), json!(state.config.bind.port()));
    if let Some(tls) = state.config.tls_bind {
        host_entry.insert("ssl_port".into(), json!(tls.port()));
    }
    let mut hosts = serde_json::Map::new();
    // Use the bind host as the dictionary key. Real electrs
    // deployments key on the public hostname; here we only know the
    // bound socket, which is good enough for clients that round-trip
    // the structure (Sparrow, Electrum desktop) and don't validate
    // hostnames.
    hosts.insert(
        state.config.bind.ip().to_string(),
        Value::Object(host_entry),
    );
    Ok(json!({
        "genesis_hash": genesis_hash,
        "hosts": hosts,
        "protocol_max": PROTOCOL_MAX,
        "protocol_min": PROTOCOL_MIN,
        "pruning": serde_json::Value::Null,
        "server_version": server_name(state),
        "hash_function": "sha256",
        // Whether `blockchain.tweaks.subscribe` can actually be served on this
        // node right now. Deliberately the same test `TweakSource::from_state`
        // makes — index present AND complete — not merely "the operator turned
        // the index on". A node whose backfill is still running has the index
        // configured and refuses every subscribe, so reporting `true` there
        // would send a wallet to a backend that cannot answer it for hours.
        "tweaks": state.sp_index.as_ref().is_some_and(|i| i.is_complete()),
        // rbitcoin's keys: the answers of the stamped methods name the block
        // they were read at, and take a trailing `asof:<blockhash>`. The
        // dialect is `asof_protocol`, which satd accepts but does not
        // require before `asof:`.
        "chain_tip": true,
        "asof": true,
        "asof_protocol": PROTOCOL_ASOF,
    }))
}

/// The default server name, before `/<version>`. See [`server_name`].
pub const DEFAULT_SERVER_NAME_PREFIX: &str = "satd-electrs-electrumx-compatible";

/// The name reported to clients, as `server.version`'s first element and
/// `server.features.server_version`.
///
/// Defaults to `satd-electrs-electrumx-compatible/<version>`: identity first,
/// then compatibility tokens, on the same principle that keeps `Mozilla` at the front
/// of every browser user-agent long after it stopped meaning anything about who
/// wrote the browser. The token is load-bearing rather than decorative: Cake
/// Wallet decides whether to probe `blockchain.tweaks.subscribe` by testing
/// this string for the substring `electrs` (case-insensitively), and will not
/// probe at all without it. Spelling it `electrum` would read the same to a
/// human and signal nothing to the client.
///
/// The `electrumx` token is for Sparrow, which batches requests, and calls
/// `blockchain.scripthash.unsubscribe` and `server.features`, only for a name
/// it recognises; a name that contains `electrumx` is one (#1069). Without it
/// Sparrow sends one request per script hash, and a wallet scan is far slower.
/// satd serves all three. Sparrow pages its `get_merkle` batches at 250, which
/// is why the default batch cap is 345.
///
/// (`server.features` is used as a capability channel too -- Frigate
/// advertises `silent_payments` there and Sparrow reads it. Cake and Sparrow
/// are the clients that gate on the version string.)
///
/// **Both halves of the shape matter.** Leading with `satd-` is not just an
/// identity preference: several clients test `starts_with("electrs")` rather
/// than `contains`, and BlueWallet uses that test to decide a server needs
/// batching disabled. A name *beginning* with `electrs` would permanently
/// disable BlueWallet's request batching; one that merely contains it does not
/// match any of those prefix tests, so nothing outside Cake changes behaviour.
///
/// It is a claim about the protocol satd speaks, not about the software it is:
/// the name leads with `satd`, and the P2P surface is untouched -- peers see
/// `node::USER_AGENT` (`/satd:<version>/`), which this cannot change.
///
/// An operator can override it with `electrumservername` -- to drop the
/// compatibility token, or to adopt a different one if another client gates on
/// a different string. An override should still not *begin* with `electrs`,
/// for the BlueWallet reason above.
fn server_name(state: &ElectrumState) -> String {
    state
        .config
        .server_name
        .clone()
        .unwrap_or_else(|| format!("{DEFAULT_SERVER_NAME_PREFIX}/{}", env!("CARGO_PKG_VERSION")))
}

/// `server.peers.subscribe()` — always returns `[]`. We're not part of
/// the Electrum-server peer mesh; future-work flag in the plan.
pub fn peers_subscribe() -> Result<Value, JsonRpcError> {
    Ok(Value::Array(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default name satisfies every client that reads it (#1069). The
    /// rules are ported from each client's source:
    /// - Sparrow (`ElectrumServer.getServerCapability`): batching, unsubscribe
    ///   and `server.features` for a lowercased name containing `electrumx`.
    /// - BlueWallet (`BlueElectrum.ts`): batching off for a name starting
    ///   with `ElectrumPersonalServer`, `electrs` or `Fulcrum`.
    /// - Cake Wallet (`electrum_wallet.dart`, `getNodeIsElectrs`): tweak
    ///   probing only for a lowercased name containing `electrs`.
    #[test]
    fn the_default_server_name_suits_sparrow_bluewallet_and_cake() {
        let name = format!("{DEFAULT_SERVER_NAME_PREFIX}/{}", env!("CARGO_PKG_VERSION"));
        let lower = name.to_lowercase();
        assert!(
            lower.contains("electrumx"),
            "Sparrow batches only for electrumx: {name}"
        );
        assert!(
            !["ElectrumPersonalServer", "electrs", "Fulcrum"]
                .iter()
                .any(|p| name.starts_with(p)),
            "BlueWallet turns batching off for this prefix: {name}"
        );
        assert!(
            lower.contains("electrs"),
            "Cake probes tweaks only for electrs: {name}"
        );
        assert!(name.starts_with("satd-"), "identity first: {name}");
    }

    /// Sparrow pages `blockchain.transaction.get_merkle` at 250 requests per
    /// batch; a smaller cap refuses the page whole (#1069).
    #[test]
    fn the_default_batch_cap_holds_sparrows_largest_page() {
        const { assert!(crate::config::DEFAULT_MAX_BATCH_REQUESTS >= 250) };
    }
}
