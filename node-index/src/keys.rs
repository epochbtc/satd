//! Key/row encoding for the address-history index column families.
//!
//! All multi-byte integer fields are big-endian so RocksDB byte-order
//! iteration ascends by `(scripthash, height, txid, vout/vin)` for a
//! fixed scripthash prefix. The 32-byte scripthash leads every key so
//! a `prefix_iterator_cf` over a single scripthash produces a sorted
//! stream of that script's history without an in-memory sort step.
//!
//! Schema layout:
//!
//! ```text
//! addr_funding   key: scripthash[32] || height_be[4] || txid[32] || vout_be[4]    (72 bytes)
//!                value: amount_sat_be[8]                                          (8 bytes)
//!
//! addr_spending  key: scripthash[32] || height_be[4] || txid[32] || vin_be[4]     (72 bytes)
//!                value: prev_outpoint_txid[32] || prev_outpoint_vout_be[4]        (36 bytes)
//! ```

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{OutPoint, Script, Txid};

/// `sha256(scriptPubKey)`. Modern Electrum convention; we do not
/// implement the legacy `hash160` variant.
pub type Scripthash = [u8; 32];

/// Encoded length of a funding/spending key.
pub const KEY_LEN: usize = 72;

/// Encoded length of a funding value.
pub const FUNDING_VALUE_LEN: usize = 8;

/// Encoded length of a spending value.
pub const SPENDING_VALUE_LEN: usize = 36;

const SCRIPTHASH_LEN: usize = 32;
const HEIGHT_LEN: usize = 4;
const TXID_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddrFundingKey {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Clone, Debug)]
pub struct AddrFundingRow {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vout: u32,
    pub amount_sat: u64,
}

impl AddrFundingRow {
    pub fn key(&self) -> AddrFundingKey {
        AddrFundingKey {
            scripthash: self.scripthash,
            height: self.height,
            txid: self.txid,
            vout: self.vout,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddrSpendingKey {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
}

#[derive(Clone, Debug)]
pub struct AddrSpendingRow {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
    pub prev_outpoint: OutPoint,
}

impl AddrSpendingRow {
    pub fn key(&self) -> AddrSpendingKey {
        AddrSpendingKey {
            scripthash: self.scripthash,
            height: self.height,
            txid: self.txid,
            vin: self.vin,
        }
    }
}

#[inline]
pub fn scripthash_of(spk: &Script) -> Scripthash {
    sha256::Hash::hash(spk.as_bytes()).to_byte_array()
}

pub fn encode_funding_key(k: &AddrFundingKey) -> [u8; KEY_LEN] {
    let mut buf = [0u8; KEY_LEN];
    buf[..SCRIPTHASH_LEN].copy_from_slice(&k.scripthash);
    buf[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]
        .copy_from_slice(k.txid.as_ref());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].copy_from_slice(&k.vout.to_be_bytes());
    buf
}

pub fn decode_funding_key(b: &[u8]) -> Option<AddrFundingKey> {
    if b.len() != KEY_LEN {
        return None;
    }
    let mut scripthash = [0u8; SCRIPTHASH_LEN];
    scripthash.copy_from_slice(&b[..SCRIPTHASH_LEN]);
    let height = u32::from_be_bytes(
        b[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN]
            .try_into()
            .ok()?,
    );
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vout = u32::from_be_bytes(b[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].try_into().ok()?);
    Some(AddrFundingKey {
        scripthash,
        height,
        txid,
        vout,
    })
}

pub fn encode_spending_key(k: &AddrSpendingKey) -> [u8; KEY_LEN] {
    // Same layout as funding; vin replaces vout. Encode via the funding
    // helper to avoid duplicate code, then patch the trailing 4 bytes.
    let mut buf = [0u8; KEY_LEN];
    buf[..SCRIPTHASH_LEN].copy_from_slice(&k.scripthash);
    buf[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]
        .copy_from_slice(k.txid.as_ref());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].copy_from_slice(&k.vin.to_be_bytes());
    buf
}

pub fn decode_spending_key(b: &[u8]) -> Option<AddrSpendingKey> {
    if b.len() != KEY_LEN {
        return None;
    }
    let mut scripthash = [0u8; SCRIPTHASH_LEN];
    scripthash.copy_from_slice(&b[..SCRIPTHASH_LEN]);
    let height = u32::from_be_bytes(
        b[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN]
            .try_into()
            .ok()?,
    );
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vin = u32::from_be_bytes(b[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].try_into().ok()?);
    Some(AddrSpendingKey {
        scripthash,
        height,
        txid,
        vin,
    })
}

pub fn encode_funding_value(amount_sat: u64) -> [u8; FUNDING_VALUE_LEN] {
    amount_sat.to_be_bytes()
}

pub fn decode_funding_value(b: &[u8]) -> Option<u64> {
    if b.len() != FUNDING_VALUE_LEN {
        return None;
    }
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

pub fn encode_spending_value(prev: &OutPoint) -> [u8; SPENDING_VALUE_LEN] {
    let mut buf = [0u8; SPENDING_VALUE_LEN];
    buf[..TXID_LEN].copy_from_slice(prev.txid.as_ref());
    buf[TXID_LEN..].copy_from_slice(&prev.vout.to_be_bytes());
    buf
}

pub fn decode_spending_value(b: &[u8]) -> Option<OutPoint> {
    if b.len() != SPENDING_VALUE_LEN {
        return None;
    }
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[..TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vout = u32::from_be_bytes(b[TXID_LEN..].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    fn fixture_scripthash(byte: u8) -> Scripthash {
        [byte; 32]
    }

    #[test]
    fn test_address_index_funding_key_roundtrip() {
        let key = AddrFundingKey {
            scripthash: fixture_scripthash(0xab),
            height: 700_000,
            txid: fixture_txid(0xcd),
            vout: 3,
        };
        let encoded = encode_funding_key(&key);
        assert_eq!(encoded.len(), KEY_LEN);
        let decoded = decode_funding_key(&encoded).expect("decode");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_address_index_spending_key_roundtrip() {
        let key = AddrSpendingKey {
            scripthash: fixture_scripthash(0x11),
            height: 800_000,
            txid: fixture_txid(0x22),
            vin: 17,
        };
        let encoded = encode_spending_key(&key);
        assert_eq!(encoded.len(), KEY_LEN);
        let decoded = decode_spending_key(&encoded).expect("decode");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_address_index_funding_value_roundtrip() {
        let amount: u64 = 5_000_000_000;
        let encoded = encode_funding_value(amount);
        assert_eq!(decode_funding_value(&encoded), Some(amount));
    }

    #[test]
    fn test_address_index_spending_value_roundtrip() {
        let outpoint = OutPoint {
            txid: fixture_txid(0x55),
            vout: 99,
        };
        let encoded = encode_spending_value(&outpoint);
        let decoded = decode_spending_value(&encoded).expect("decode");
        assert_eq!(decoded, outpoint);
    }

    #[test]
    fn test_address_index_funding_key_sort_order_height_ascending() {
        // For a fixed scripthash, byte-order sorts must mirror height-ascending.
        let sh = fixture_scripthash(0x42);
        let keys = [10u32, 5, 7, 1_000_000, 1].map(|h| AddrFundingKey {
            scripthash: sh,
            height: h,
            txid: fixture_txid(0),
            vout: 0,
        });
        let mut encoded: Vec<[u8; KEY_LEN]> = keys.iter().map(encode_funding_key).collect();
        encoded.sort();
        let decoded_heights: Vec<u32> = encoded
            .iter()
            .map(|k| decode_funding_key(k).unwrap().height)
            .collect();
        assert_eq!(decoded_heights, vec![1, 5, 7, 10, 1_000_000]);
    }

    #[test]
    fn test_address_index_funding_key_sort_within_height_by_txid_then_vout() {
        let sh = fixture_scripthash(0xff);
        let h = 100u32;
        let keys = [
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0xaa),
                vout: 5,
            },
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0xaa),
                vout: 1,
            },
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0x01),
                vout: 0,
            },
        ];
        let mut encoded: Vec<[u8; KEY_LEN]> = keys.iter().map(encode_funding_key).collect();
        encoded.sort();
        // Expect: txid 0x01 first, then 0xaa with vout 1, then 0xaa with vout 5.
        let decoded: Vec<AddrFundingKey> = encoded
            .iter()
            .map(|k| decode_funding_key(k).unwrap())
            .collect();
        assert_eq!(decoded[0].txid, fixture_txid(0x01));
        assert_eq!(decoded[1].txid, fixture_txid(0xaa));
        assert_eq!(decoded[1].vout, 1);
        assert_eq!(decoded[2].vout, 5);
    }

    #[test]
    fn test_address_index_funding_key_prefix_isolates_scripthash() {
        // Two different scripthashes' rows must never interleave under
        // a 32-byte prefix iterator.
        let sh_a = fixture_scripthash(0x10);
        let sh_b = fixture_scripthash(0x20);
        let mut all = Vec::new();
        for h in [1u32, 2, 3] {
            all.push(encode_funding_key(&AddrFundingKey {
                scripthash: sh_a,
                height: h,
                txid: fixture_txid(0),
                vout: 0,
            }));
            all.push(encode_funding_key(&AddrFundingKey {
                scripthash: sh_b,
                height: h,
                txid: fixture_txid(0),
                vout: 0,
            }));
        }
        all.sort();
        // First three rows are sh_a; next three are sh_b.
        for k in &all[..3] {
            assert_eq!(&k[..SCRIPTHASH_LEN], &sh_a[..]);
        }
        for k in &all[3..] {
            assert_eq!(&k[..SCRIPTHASH_LEN], &sh_b[..]);
        }
    }

    #[test]
    fn test_address_index_decode_rejects_wrong_length() {
        assert!(decode_funding_key(&[0u8; 71]).is_none());
        assert!(decode_funding_key(&[0u8; 73]).is_none());
        assert!(decode_spending_key(&[0u8; 0]).is_none());
        assert!(decode_funding_value(&[0u8; 7]).is_none());
        assert!(decode_spending_value(&[0u8; 35]).is_none());
    }

    #[test]
    fn test_address_index_scripthash_of_p2wpkh_known_vector() {
        // P2WPKH scriptPubKey: OP_0 <20-byte pubkey-hash>. We pick a
        // fixed pubkey-hash so the hash is reproducible. Compute the
        // expected sha256 with the same library so the test verifies
        // the helper is doing sha256(serialized_script) and not, e.g.,
        // sha256d or hash160.
        let pkh = [0x42u8; 20];
        let mut spk_bytes = vec![0x00, 0x14]; // OP_0 PUSH(20)
        spk_bytes.extend_from_slice(&pkh);
        let spk = ScriptBuf::from(spk_bytes.clone());

        let got = scripthash_of(&spk);
        let expected = sha256::Hash::hash(&spk_bytes).to_byte_array();
        assert_eq!(got, expected);
    }
}
