//! Key encoding for the BIP 158 filter-index column families.
//!
//! Layout (per the implementation plan):
//!
//! ```text
//! cf_filter         key: filter_type[1] || height_be[4]    (5 bytes)
//!                   value: filter_bytes (variable; raw GCS-encoded blob)
//!
//! cf_filter_header  key: filter_type[1] || height_be[4]    (5 bytes)
//!                   value: filter_header[32]               (32 bytes)
//! ```
//!
//! `(type, height)` keying with big-endian heights so byte-order
//! iteration ascends by height for a fixed filter type. `getcfheaders`
//! and `getcfilters` resolve `stop_hash` to a height up front and then
//! iterate the height range as point lookups, so we do not need a
//! prefix extractor on the CF.

/// Encoded length of a filter / filter-header key (`type[1] || height_be[4]`).
pub const FILTER_KEY_LEN: usize = 5;

/// BIP 158 SCRIPT_FILTER (basic filter) type byte. The only filter type
/// the spec defines today; we accept this and reject every other
/// incoming filter-type byte at the P2P boundary with a silent drop
/// (per BIP 157).
pub const FILTER_TYPE_BASIC: u8 = 0x00;

const TYPE_LEN: usize = 1;
const HEIGHT_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FilterKey {
    pub filter_type: u8,
    pub height: u32,
}

#[inline]
pub fn encode_filter_key(key: &FilterKey) -> [u8; FILTER_KEY_LEN] {
    let mut out = [0u8; FILTER_KEY_LEN];
    out[0] = key.filter_type;
    out[TYPE_LEN..TYPE_LEN + HEIGHT_LEN].copy_from_slice(&key.height.to_be_bytes());
    out
}

#[inline]
pub fn decode_filter_key(buf: &[u8]) -> Option<FilterKey> {
    if buf.len() != FILTER_KEY_LEN {
        return None;
    }
    let height = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Some(FilterKey {
        filter_type: buf[0],
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_key_roundtrip() {
        for (ty, h) in [(0u8, 0u32), (0, 1), (0, 700_000), (0, u32::MAX), (1, 42)] {
            let key = FilterKey {
                filter_type: ty,
                height: h,
            };
            let buf = encode_filter_key(&key);
            assert_eq!(buf.len(), FILTER_KEY_LEN);
            let decoded = decode_filter_key(&buf).expect("decode");
            assert_eq!(decoded, key);
        }
    }

    #[test]
    fn test_filter_key_sort_order_height_ascending_for_fixed_type() {
        // Within a single filter_type, byte-order must mirror height-ascending.
        let heights = [10u32, 5, 7, 1_000_000, 1, u32::MAX];
        let mut encoded: Vec<[u8; FILTER_KEY_LEN]> = heights
            .iter()
            .map(|&h| {
                encode_filter_key(&FilterKey {
                    filter_type: FILTER_TYPE_BASIC,
                    height: h,
                })
            })
            .collect();
        encoded.sort();
        let decoded_heights: Vec<u32> = encoded
            .iter()
            .map(|k| decode_filter_key(k).unwrap().height)
            .collect();
        assert_eq!(decoded_heights, vec![1, 5, 7, 10, 1_000_000, u32::MAX]);
    }

    #[test]
    fn test_filter_key_type_prefix_isolates_types() {
        // Different filter_types must never interleave under byte-order
        // iteration. All type-0 keys precede all type-1 keys.
        let mut all = Vec::new();
        for h in [1u32, 2, 3] {
            all.push(encode_filter_key(&FilterKey {
                filter_type: 0,
                height: h,
            }));
            all.push(encode_filter_key(&FilterKey {
                filter_type: 1,
                height: h,
            }));
        }
        all.sort();
        for k in &all[..3] {
            assert_eq!(k[0], 0);
        }
        for k in &all[3..] {
            assert_eq!(k[0], 1);
        }
    }

    #[test]
    fn test_decode_rejects_wrong_length() {
        assert!(decode_filter_key(&[]).is_none());
        assert!(decode_filter_key(&[0u8; 4]).is_none());
        assert!(decode_filter_key(&[0u8; 6]).is_none());
    }
}
