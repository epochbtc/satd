//! Electrum wire-protocol types — the JSON shapes returned by the
//! `blockchain.*` / `mempool.*` / `server.*` methods.
//!
//! Hex-encoded fields use Bitcoin RPC display order (the on-chain
//! byte order reversed) for txid / block hash / scripthash. That
//! matches every existing Electrum client and `romanz/electrs`'s
//! upstream behaviour. Conversion helpers live in
//! [`crate::status`] / [`crate::merkle`] so handlers don't have to
//! reverse bytes at every call site.

use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

/// 32-byte scripthash as 64-character lowercase hex. The Electrum
/// protocol interchanges scripthash in straight hex (no byte reversal —
/// distinct from txid/block hash). New-typing it makes that contract
/// explicit at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScripthashHex(pub [u8; 32]);

impl Serialize for ScripthashHex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ScripthashHex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: &str = serde::Deserialize::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(
                "scripthash must be 64 hex chars (32 bytes)",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(ScripthashHex(arr))
    }
}

impl From<[u8; 32]> for ScripthashHex {
    fn from(v: [u8; 32]) -> Self {
        ScripthashHex(v)
    }
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

/// `blockchain.scripthash.listunspent` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListUnspentEntry {
    pub height: u32,
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
    fn scripthash_hex_round_trip() {
        let sh = ScripthashHex([0xab; 32]);
        let json = serde_json::to_string(&sh).unwrap();
        // 64 chars of "ab" + the surrounding quotes.
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
