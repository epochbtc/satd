//! Electrum wire-protocol types — the JSON shapes returned by the
//! `blockchain.*` / `mempool.*` / `server.*` methods.
//!
//! ## Display-order hex on the wire
//!
//! Per the Electrum spec, every 32-byte hash on the wire — txid,
//! blockhash, **scripthash** — is encoded in display order, i.e. the
//! reverse of the natural internal byte order. `romanz/electrs` enforces
//! this with `#[hash_newtype(backward)]` on its `ScriptHash` type
//! (electrs `src/types.rs`). Real wallet clients (Sparrow, BlueWallet,
//! Electrum desktop) send the reversed hex; lookups against unreversed
//! hex would silently miss every entry.
//!
//! [`ScripthashHex`] holds the scripthash in **natural sha256 order**
//! internally so it can be passed directly to the index (which keys on
//! the natural-order bytes). Its serde impls — and the
//! [`scripthash_to_wire_hex`] / [`parse_wire_scripthash`] helpers —
//! reverse on the wire boundary.
//!
//! Index storage stays in natural order; this is purely a
//! presentation-layer reversal.

use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

use crate::error::JsonRpcError;

/// 32-byte scripthash, stored in **natural sha256 byte order** —
/// i.e. exactly what `sha256(scriptPubKey)` produces. The wire
/// representation is byte-reversed (display order); the serde impls
/// below handle the reversal transparently. Inside the crate (handler
/// argument, index lookup key) you always see natural order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScripthashHex(pub [u8; 32]);

impl Serialize for ScripthashHex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&scripthash_to_wire_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for ScripthashHex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: &str = serde::Deserialize::deserialize(d)?;
        parse_wire_scripthash(s)
            .map(ScripthashHex)
            .map_err(|e| serde::de::Error::custom(e.message))
    }
}

impl From<[u8; 32]> for ScripthashHex {
    fn from(v: [u8; 32]) -> Self {
        ScripthashHex(v)
    }
}

/// Format a scripthash for the wire: reverses the natural-order bytes
/// and hex-encodes the result. Pair with [`parse_wire_scripthash`] for
/// inbound parsing.
pub fn scripthash_to_wire_hex(sh: &[u8; 32]) -> String {
    let mut reversed = *sh;
    reversed.reverse();
    hex::encode(reversed)
}

/// Parse a wire (display-order) scripthash hex string into the natural
/// sha256-byte-order array used internally. Surfaces a JSON-RPC error
/// shape so handlers can `?` it without mapping.
pub fn parse_wire_scripthash(s: &str) -> Result<[u8; 32], JsonRpcError> {
    let bytes =
        hex::decode(s).map_err(|e| JsonRpcError::invalid_params(format!("bad scripthash: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsonRpcError::invalid_params(
            "scripthash must be 64 hex chars (32 bytes)",
        ));
    }
    let mut natural = [0u8; 32];
    // Wire is reversed; flip back to natural order for index lookup.
    for (i, b) in bytes.iter().rev().enumerate() {
        natural[i] = *b;
    }
    Ok(natural)
}

/// Display-order txid hex. Wraps `bitcoin::Txid::to_string()` /
/// `parse::<Txid>()` so handler signatures speak in Electrum-spec terms
/// rather than rust-bitcoin types. Serialized as a 64-char lowercase
/// hex string per the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxidHex(pub Txid);

impl Serialize for TxidHex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for TxidHex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: &str = serde::Deserialize::deserialize(d)?;
        s.parse::<Txid>()
            .map(TxidHex)
            .map_err(serde::de::Error::custom)
    }
}

impl From<Txid> for TxidHex {
    fn from(v: Txid) -> Self {
        TxidHex(v)
    }
}

/// `blockchain.scripthash.get_history` entry. `height` is signed:
/// - positive: confirmed block height
/// - 0: unconfirmed mempool tx with no unconfirmed inputs
/// - -1: unconfirmed tx that spends an unconfirmed parent
///
/// `fee` is present (in sats) only for unconfirmed entries (`height <= 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub height: i64,
    pub tx_hash: TxidHex,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

/// `blockchain.scripthash.listunspent` entry. `height` is signed to
/// match electrs's wire shape: 0 for unconfirmed-no-deps, -1 for
/// unconfirmed-with-deps, positive for confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListUnspentEntry {
    pub height: i64,
    pub tx_hash: TxidHex,
    pub tx_pos: u32,
    pub value: u64,
}

/// `blockchain.scripthash.get_balance` response. `unconfirmed` is
/// signed (a tx that spends more than it funds shows negative) per the
/// protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub confirmed: u64,
    pub unconfirmed: i64,
}

/// `blockchain.transaction.get_merkle` response. `merkle` is the
/// bottom-up sibling sequence in display-order hex. `pos` is the tx's
/// 0-indexed position within its block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetMerkleResponse {
    pub merkle: Vec<TxidHex>,
    pub block_height: u32,
    pub pos: u32,
}

/// `blockchain.block.headers` response. `count` is the number of
/// headers actually returned (may be less than requested if `start`
/// runs past tip). `hex` is the concatenation of `count` raw 80-byte
/// headers, hex-encoded. `max` is the server's per-call cap (clients
/// page by it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersResponse {
    pub count: u32,
    pub hex: String,
    pub max: u32,
}

/// `mempool.get_fee_histogram` returns an array of `[fee_per_vbyte,
/// total_vbytes]` pairs in descending fee-rate order. We model one row;
/// the response is `Vec<FeeHistogramEntry>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeHistogramEntry(pub u64, pub u64);

/// Helper: render a `BlockHash` in Electrum display-order hex.
pub fn block_hash_hex(h: &BlockHash) -> String {
    h.to_string()
}

/// Helper: parse an Electrum display-order hex string into a `BlockHash`.
pub fn parse_block_hash(s: &str) -> Result<BlockHash, bitcoin::hashes::hex::HexToArrayError> {
    s.parse::<BlockHash>()
}

/// Convert raw 32-byte big-endian sibling hashes (as produced by
/// [`crate::merkle::compute_merkle_branch`]) into the display-order hex
/// strings the protocol expects.
pub fn sibling_bytes_to_hex(bytes: &[u8; 32]) -> String {
    // Bitcoin's display-order is the byte-reversed internal order.
    let mut reversed = *bytes;
    reversed.reverse();
    hex::encode(reversed)
}

/// Convert a `bitcoin::TxMerkleNode` to display-order hex. Used when
/// constructing `GetMerkleResponse` from the merkle helper output.
pub fn merkle_node_to_hex(node: &bitcoin::TxMerkleNode) -> String {
    node.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn scripthash_hex_round_trip_reverses_on_wire() {
        // Natural-order bytes: [01, 02, 03, ..., 32]. On the wire we
        // expect the reversed sequence — i.e. the spec-mandated
        // display-order encoding (electrs's `#[hash_newtype(backward)]`).
        let mut natural = [0u8; 32];
        for (i, b) in natural.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let sh = ScripthashHex(natural);
        let json = serde_json::to_string(&sh).unwrap();

        // Wire hex: 64 chars, the byte-reversed natural order.
        let mut expected_wire_bytes = natural;
        expected_wire_bytes.reverse();
        let expected = format!("\"{}\"", hex::encode(expected_wire_bytes));
        assert_eq!(json, expected);

        // Round trip: deserialize the wire form and confirm we get
        // natural order back.
        let back: ScripthashHex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.0, natural);
    }

    #[test]
    fn scripthash_hex_constant_byte_round_trip() {
        // Constant-byte input is a degenerate case — reversal is a
        // no-op — so the JSON looks like 64 'ab' chars. Useful guard
        // that we didn't break the symmetric path.
        let sh = ScripthashHex([0xab; 32]);
        let json = serde_json::to_string(&sh).unwrap();
        assert_eq!(json, "\"".to_string() + &"ab".repeat(32) + "\"");
        let back: ScripthashHex = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sh);
    }

    #[test]
    fn scripthash_hex_rejects_wrong_length() {
        let bad = "\"deadbeef\"";
        let parsed: Result<ScripthashHex, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn scripthash_to_wire_hex_matches_electrs_fixture() {
        // From electrs `src/types.rs::test_scripthash`:
        //   addr "1KVNjD3AAnQ3gTMqoTKcWFeqSFujq9gTBT" yields scripthash
        //   "00dfb264221d07712a144bda338e89237d1abd2db4086057573895ea2659766a"
        // (parsed by electrs in display order; electrs's
        // `Display for ScriptHash` reverses bytes — so the natural
        // sha256 bytes are the *reversed* hex).
        let display_hex = "00dfb264221d07712a144bda338e89237d1abd2db4086057573895ea2659766a";
        let mut natural = [0u8; 32];
        let raw = hex::decode(display_hex).unwrap();
        for (i, b) in raw.iter().rev().enumerate() {
            natural[i] = *b;
        }
        // Round trip via our serde must produce the same display hex.
        let sh = ScripthashHex(natural);
        let json = serde_json::to_string(&sh).unwrap();
        assert_eq!(json, format!("\"{display_hex}\""));
    }

    #[test]
    fn parse_wire_scripthash_reverses_into_natural() {
        let display_hex = "00dfb264221d07712a144bda338e89237d1abd2db4086057573895ea2659766a";
        let parsed = parse_wire_scripthash(display_hex).unwrap();
        // First display byte (0x00) lands at the END of natural order;
        // last display byte (0x6a) lands at the START.
        assert_eq!(parsed[0], 0x6a);
        assert_eq!(parsed[31], 0x00);
    }

    #[test]
    fn txid_hex_round_trip() {
        let txid = fixture_txid(0x01);
        let wrapper = TxidHex(txid);
        let json = serde_json::to_string(&wrapper).unwrap();
        // Display order is the reversed internal byte order; for the
        // all-`01` fixture the reversal is a no-op so all 64 chars are
        // "01".
        assert_eq!(json, "\"".to_string() + &"01".repeat(32) + "\"");
        let back: TxidHex = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wrapper);
    }

    #[test]
    fn history_entry_confirmed_omits_fee() {
        let e = HistoryEntry {
            height: 700_000,
            tx_hash: TxidHex(fixture_txid(0x42)),
            fee: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(
            !json.contains("fee"),
            "confirmed entry must skip fee field: {json}"
        );
        assert!(json.contains("\"height\":700000"));
    }

    #[test]
    fn history_entry_unconfirmed_includes_fee() {
        let e = HistoryEntry {
            height: 0,
            tx_hash: TxidHex(fixture_txid(0x42)),
            fee: Some(2400),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"fee\":2400"), "{json}");
        assert!(json.contains("\"height\":0"));
    }

    #[test]
    fn history_entry_unconfirmed_with_deps_emits_minus_one() {
        let e = HistoryEntry {
            height: -1,
            tx_hash: TxidHex(fixture_txid(0x42)),
            fee: Some(1234),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"height\":-1"), "{json}");
    }

    #[test]
    fn balance_round_trip() {
        let b = BalanceResponse {
            confirmed: 12345,
            unconfirmed: -678,
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"confirmed\":12345"));
        assert!(json.contains("\"unconfirmed\":-678"));
        let back: BalanceResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn list_unspent_round_trip() {
        let u = ListUnspentEntry {
            height: 100,
            tx_hash: TxidHex(fixture_txid(0x55)),
            tx_pos: 7,
            value: 100_000,
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: ListUnspentEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn fee_histogram_entry_serializes_as_array_pair() {
        let h = FeeHistogramEntry(120, 500_000);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "[120,500000]");
    }

    #[test]
    fn sibling_bytes_to_hex_reverses() {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        b[31] = 0xff;
        let hex_str = sibling_bytes_to_hex(&b);
        // After reverse, b[31] = 0x01 becomes the last hex pair, and
        // b[0] = 0xff becomes the first.
        assert_eq!(&hex_str[..2], "ff");
        assert_eq!(&hex_str[62..], "01");
    }
}
