//! Electrum scripthash status helper.
//!
//! [`compute_status_hash`] returns the current Electrum-canonical
//! status hash for a scripthash given an [`AddressIndex`] read surface
//! and a [`Mempool`] reference (needed to distinguish
//! unconfirmed-no-deps from unconfirmed-with-unconfirmed-parents per
//! electrs's `Height` enum).
//!
//! It's the value `blockchain.scripthash.subscribe` returns
//! synchronously on first call; future updates ride the broadcast
//! channel from
//! [`AddressIndex::subscribe`](node_index::AddressIndex::subscribe)
//! and carry an already-computed hash, so this helper is only needed
//! for the initial response.

use node::mempool::pool::Mempool;
use node_index::{AddressIndex, IndexError, status_hash};

use crate::handlers::blockchain::mempool_tx_has_unconfirmed_inputs;
use crate::types::ScripthashHex;

/// Compute the current status hash for `sh` from the live index.
///
/// Returns `Ok([0u8; 32])` for an empty history (Electrum's canonical
/// "no data" sentinel — the all-zero hash, NOT `null`).
/// `Err(IndexError::Disabled)` when `--addressindex=0` so the caller
/// can surface a JSON-RPC error rather than silently returning the
/// empty-history sentinel.
///
/// `mempool` is required for height-tagging unconfirmed entries:
/// `0` for unconfirmed-no-deps, `-1` for unconfirmed-with-deps.
/// Mirrors `romanz/electrs`'s `Height::as_i64`.
pub fn compute_status_hash(
    idx: &dyn AddressIndex,
    mempool: &Mempool,
    sh: ScripthashHex,
) -> Result<[u8; 32], IndexError> {
    let confirmed = idx.confirmed_history(&sh.0)?;

    // Adapt to the (height, txid) shape `node_index::status_hash`
    // expects. Funding and spending entries that share `(height, txid)`
    // collapse to a single entry per the Electrum spec — the status
    // hash sees one row per `(height, txid)` regardless of how many
    // funding / spending rows exist within it.
    let mut pairs: Vec<(i64, bitcoin::Txid)> = confirmed
        .iter()
        .map(|e| (e.height() as i64, e.txid()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    pairs.dedup();

    // Mempool entries — tag with -1 if they spend an unconfirmed
    // parent, 0 otherwise (electrs `Height::Unconfirmed`).
    for mp in idx.mempool_history(&sh.0) {
        let height = match mempool.get(&mp.txid) {
            Some(entry) => {
                if mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool) {
                    -1
                } else {
                    0
                }
            }
            // Tx left mempool between mempool_history and our get;
            // best-effort fallback to unconfirmed-no-deps. The next
            // `LeaveConfirmed` / `LeaveEvicted` event will trigger a
            // recompute so this value is short-lived.
            None => 0,
        };
        pairs.push((height, mp.txid));
    }

    Ok(status_hash(&pairs))
}

/// Render a 32-byte status hash as the protocol-canonical JSON value.
/// Per the Electrum spec, an empty-history scripthash subscribes with
/// JSON `null` — NOT the all-zero hex string. Distinct callers need
/// different shapes (the all-zero array as a value, the `null` for the
/// JSON wire), so we expose both.
///
/// `Some(hex_string)` for nonempty status, `None` for the all-zero
/// sentinel.
pub fn status_hash_to_json(h: [u8; 32]) -> Option<String> {
    if h == [0u8; 32] {
        None
    } else {
        Some(hex::encode(h))
    }
}

/// Parse an optional hex-encoded status hash back into bytes (used when
/// the client sends back a known status; not strictly used by the v1
/// method set but exposed for symmetry / completeness).
pub fn parse_status_hash(s: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{OutPoint, Txid};
    use node::mempool::pool::Mempool;
    use node_index::{
        AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, StatusUpdate,
        SubscribeError, Utxo,
    };
    use parking_lot::Mutex;
    use tokio::sync::broadcast;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    fn empty_mempool() -> Mempool {
        Mempool::new(8 * 1024 * 1024, 1)
    }

    /// Tiny in-memory `AddressIndex` for unit-testing the helper without
    /// pulling in the chainstate-backed implementation.
    #[derive(Default)]
    struct FakeIndex {
        confirmed: Mutex<Vec<HistoryEntry>>,
        mempool: Mutex<Vec<MempoolHistoryEntry>>,
        disabled: bool,
    }

    impl AddressIndex for FakeIndex {
        fn confirmed_history(&self, _sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            if self.disabled {
                return Err(IndexError::Disabled);
            }
            Ok(self.confirmed.lock().clone())
        }
        fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            if self.disabled {
                return Vec::new();
            }
            self.mempool.lock().clone()
        }
        fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            if self.disabled {
                return Err(IndexError::Disabled);
            }
            Ok((0, 0))
        }
        fn utxos(&self, _sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            if self.disabled {
                return Err(IndexError::Disabled);
            }
            Ok(Vec::new())
        }
        fn subscribe(
            &self,
            _sh: Scripthash,
        ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            // Not exercised by status_hash tests.
            let (tx, rx) = broadcast::channel(1);
            std::mem::forget(tx);
            Ok(rx)
        }
    }

    #[test]
    fn empty_history_returns_zero_sentinel() {
        let idx = FakeIndex::default();
        let mp = empty_mempool();
        let h = compute_status_hash(&idx, &mp, ScripthashHex([0xab; 32])).unwrap();
        assert_eq!(h, [0u8; 32]);
        assert!(status_hash_to_json(h).is_none());
    }

    #[test]
    fn confirmed_only_status_matches_status_hash_helper() {
        let idx = FakeIndex::default();
        let mp = empty_mempool();
        let txid = fixture_txid(0x42);
        idx.confirmed.lock().push(HistoryEntry::Funding {
            height: 100,
            txid,
            vout: 0,
            amount_sat: 1000,
        });

        let got = compute_status_hash(&idx, &mp, ScripthashHex([0xab; 32])).unwrap();
        let expected = node_index::status_hash(&[(100, txid)]);
        assert_eq!(got, expected);
        assert!(status_hash_to_json(got).is_some());
    }

    #[test]
    fn mempool_entry_without_deps_uses_height_zero() {
        let idx = FakeIndex::default();
        let mp = empty_mempool();
        let txid_mp = fixture_txid(0x30);
        idx.mempool
            .lock()
            
            .push(MempoolHistoryEntry { txid: txid_mp });

        let got = compute_status_hash(&idx, &mp, ScripthashHex([0xcc; 32])).unwrap();
        // mempool tx not in `mp.get(...)` — fallback path tags it as 0.
        let expected = node_index::status_hash(&[(0, txid_mp)]);
        assert_eq!(got, expected);
    }

    #[test]
    fn dedupes_funding_plus_spending_within_same_tx() {
        // A scripthash that sees both a funding output and a spending
        // input within the SAME tx (e.g., a CoinJoin participant) must
        // contribute exactly one row to the status hash, not two.
        let idx = FakeIndex::default();
        let mp = empty_mempool();
        let txid = fixture_txid(0x55);
        idx.confirmed.lock().extend([
            HistoryEntry::Funding {
                height: 200,
                txid,
                vout: 0,
                amount_sat: 5000,
            },
            HistoryEntry::Spending {
                height: 200,
                txid,
                vin: 0,
                prev_outpoint: OutPoint {
                    txid: fixture_txid(0xaa),
                    vout: 0,
                },
            },
        ]);

        let got = compute_status_hash(&idx, &mp, ScripthashHex([0xee; 32])).unwrap();
        let single = node_index::status_hash(&[(200, txid)]);
        let double = node_index::status_hash(&[(200, txid), (200, txid)]);
        assert_eq!(got, single, "(height, txid) should dedupe to one row");
        assert_ne!(got, double, "no dedupe would produce a different hash");
    }

    #[test]
    fn disabled_index_surfaces_error() {
        let idx = FakeIndex {
            disabled: true,
            ..Default::default()
        };
        let mp = empty_mempool();
        let result = compute_status_hash(&idx, &mp, ScripthashHex([0; 32]));
        assert!(matches!(result, Err(IndexError::Disabled)));
    }

    #[test]
    fn parse_status_hash_round_trip() {
        let bytes = [0x42u8; 32];
        let s = hex::encode(bytes);
        assert_eq!(parse_status_hash(&s).unwrap(), bytes);
    }

    #[test]
    fn parse_status_hash_rejects_short() {
        assert!(parse_status_hash("deadbeef").is_err());
    }
}
