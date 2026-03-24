/// Bitcoin script number — sign-magnitude encoded integers.
///
/// Matches Bitcoin Core's `CScriptNum` exactly. Numeric opcodes operate on
/// 4-byte integers. Operands must be in [-2^31+1, 2^31-1], but results may
/// overflow (valid as long as they are not used as a subsequent numeric operand).
/// Internally stored as i64, and serialized to/from sign-magnitude byte vectors.
///
/// Error when script number decoding fails (overflow or non-minimal encoding).
#[derive(Debug, Clone)]
pub struct ScriptNumError;

impl std::fmt::Display for ScriptNumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("script number error")
    }
}

/// Default maximum byte length for script numbers (4 bytes = ±2^31-1).
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

/// A Bitcoin script number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptNum {
    value: i64,
}

impl ScriptNum {
    /// Create from an i64 value directly.
    pub fn new(n: i64) -> Self {
        Self { value: n }
    }

    /// Decode from a sign-magnitude byte vector on the stack.
    ///
    /// If `require_minimal` is true, non-minimally encoded numbers are rejected.
    /// `max_num_size` is typically 4 (or 5 for CLTV/CSV).
    pub fn from_bytes(
        data: &[u8],
        require_minimal: bool,
        max_num_size: usize,
    ) -> Result<Self, ScriptNumError> {
        if data.len() > max_num_size {
            return Err(ScriptNumError);
        }

        if require_minimal && !data.is_empty() {
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. This also rejects negative-zero (0x80).
            if (data[data.len() - 1] & 0x7f) == 0 {
                // Exception: if there's more than one byte and the MSB of the
                // second-most-significant-byte is set, the zero byte is needed
                // to prevent sign confusion.
                if data.len() <= 1 || (data[data.len() - 2] & 0x80) == 0 {
                    return Err(ScriptNumError);
                }
            }
        }

        Ok(Self {
            value: decode_bytes(data),
        })
    }

    /// Decode with default 4-byte limit.
    pub fn from_bytes_default(data: &[u8], require_minimal: bool) -> Result<Self, ScriptNumError> {
        Self::from_bytes(data, require_minimal, DEFAULT_MAX_NUM_SIZE)
    }

    /// Get the internal i64 value.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Get as i32 with clamping (matches CScriptNum::getint()).
    pub fn getint(&self) -> i32 {
        if self.value > i32::MAX as i64 {
            i32::MAX
        } else if self.value < i32::MIN as i64 {
            i32::MIN
        } else {
            self.value as i32
        }
    }

    /// Serialize to sign-magnitude byte vector (matches CScriptNum::getvch()).
    pub fn serialize(&self) -> Vec<u8> {
        serialize_i64(self.value)
    }

    /// Negate the value. Panics on i64::MIN (matches C++ assert).
    pub fn negate(self) -> Self {
        assert!(
            self.value != i64::MIN,
            "cannot negate i64::MIN in ScriptNum"
        );
        Self {
            value: -self.value,
        }
    }
}

/// Decode a sign-magnitude byte vector to i64.
fn decode_bytes(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }

    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    // If the MSB of the last byte is set, it's the sign bit.
    if data[data.len() - 1] & 0x80 != 0 {
        // Clear the sign bit from the result and negate.
        let mask = 0x80u64 << (8 * (data.len() - 1));
        return -((result as u64 & !mask) as i64);
    }

    result
}

/// Serialize an i64 to sign-magnitude byte vector.
pub fn serialize_i64(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let neg = value < 0;
    let mut absvalue = if neg {
        // Handle i64::MIN correctly using wrapping arithmetic
        (!(value as u64)).wrapping_add(1)
    } else {
        value as u64
    };

    let mut result = Vec::new();
    while absvalue > 0 {
        result.push((absvalue & 0xff) as u8);
        absvalue >>= 8;
    }

    // If the MSB is >= 0x80, we need an extra byte for the sign.
    if result[result.len() - 1] & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }

    result
}

// Arithmetic operations matching CScriptNum
impl std::ops::Add for ScriptNum {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.value + rhs.value)
    }
}

impl std::ops::Sub for ScriptNum {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.value - rhs.value)
    }
}

impl std::ops::BitAnd for ScriptNum {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self::new(self.value & rhs.value)
    }
}

impl std::ops::AddAssign for ScriptNum {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value;
    }
}

impl std::ops::SubAssign for ScriptNum {
    fn sub_assign(&mut self, rhs: Self) {
        self.value -= rhs.value;
    }
}

impl std::ops::Neg for ScriptNum {
    type Output = Self;
    fn neg(self) -> Self {
        self.negate()
    }
}

// Comparison with i64
impl PartialEq<i64> for ScriptNum {
    fn eq(&self, other: &i64) -> bool {
        self.value == *other
    }
}

impl PartialOrd<i64> for ScriptNum {
    fn partial_cmp(&self, other: &i64) -> Option<std::cmp::Ordering> {
        Some(self.value.cmp(other))
    }
}

impl From<i64> for ScriptNum {
    fn from(n: i64) -> Self {
        Self::new(n)
    }
}

impl From<bool> for ScriptNum {
    fn from(b: bool) -> Self {
        Self::new(if b { 1 } else { 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let n = ScriptNum::new(0);
        assert_eq!(n.serialize(), Vec::<u8>::new());
        assert_eq!(decode_bytes(&[]), 0);
    }

    #[test]
    fn test_positive() {
        let n = ScriptNum::new(1);
        assert_eq!(n.serialize(), vec![0x01]);

        let n = ScriptNum::new(127);
        assert_eq!(n.serialize(), vec![0x7f]);

        let n = ScriptNum::new(128);
        assert_eq!(n.serialize(), vec![0x80, 0x00]);

        let n = ScriptNum::new(255);
        assert_eq!(n.serialize(), vec![0xff, 0x00]);

        let n = ScriptNum::new(256);
        assert_eq!(n.serialize(), vec![0x00, 0x01]);
    }

    #[test]
    fn test_negative() {
        let n = ScriptNum::new(-1);
        assert_eq!(n.serialize(), vec![0x81]);

        let n = ScriptNum::new(-127);
        assert_eq!(n.serialize(), vec![0xff]);

        let n = ScriptNum::new(-128);
        assert_eq!(n.serialize(), vec![0x80, 0x80]);

        let n = ScriptNum::new(-255);
        assert_eq!(n.serialize(), vec![0xff, 0x80]);

        let n = ScriptNum::new(-256);
        assert_eq!(n.serialize(), vec![0x00, 0x81]);
    }

    #[test]
    fn test_roundtrip() {
        for val in [
            0i64,
            1,
            -1,
            127,
            -127,
            128,
            -128,
            255,
            -255,
            256,
            -256,
            32767,
            -32767,
            32768,
            -32768,
            65535,
            -65535,
            i32::MAX as i64,
            i32::MIN as i64 + 1,
        ] {
            let n = ScriptNum::new(val);
            let bytes = n.serialize();
            let decoded = ScriptNum::from_bytes(&bytes, false, 5).unwrap();
            assert_eq!(decoded.value(), val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_minimal_encoding_rejects_negative_zero() {
        // 0x80 is negative zero — must be rejected under minimal encoding
        assert!(ScriptNum::from_bytes(&[0x80], true, 4).is_err());
        // But allowed without minimal flag
        let n = ScriptNum::from_bytes(&[0x80], false, 4).unwrap();
        assert_eq!(n.value(), 0);
    }

    #[test]
    fn test_minimal_encoding_rejects_padded() {
        // 0x00 0x00 should be rejected (non-minimal encoding of 0)
        assert!(ScriptNum::from_bytes(&[0x00, 0x00], true, 4).is_err());
        // 0x01 0x00 should be rejected (non-minimal encoding of 1)
        assert!(ScriptNum::from_bytes(&[0x01, 0x00], true, 4).is_err());
    }

    #[test]
    fn test_minimal_encoding_accepts_valid() {
        // 0xff 0x00 is minimal encoding of 255 (needs the 0x00 because 0xff has sign bit set)
        assert!(ScriptNum::from_bytes(&[0xff, 0x00], true, 4).is_ok());
        // 0xff 0x80 is minimal encoding of -255
        assert!(ScriptNum::from_bytes(&[0xff, 0x80], true, 4).is_ok());
    }

    #[test]
    fn test_overflow() {
        // 5 bytes should fail with default 4-byte limit
        assert!(ScriptNum::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05], false, 4).is_err());
        // But succeed with 5-byte limit (for CLTV/CSV)
        assert!(ScriptNum::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05], false, 5).is_ok());
    }
}
