/// Script stack element type.
pub type StackItem = Vec<u8>;

/// Cast a stack element to boolean, matching Bitcoin Core's CastToBool().
///
/// An all-zeros vector is false. A negative zero (last byte 0x80, rest zero)
/// is also false. Everything else is true.
pub fn cast_to_bool(vch: &[u8]) -> bool {
    for (i, &byte) in vch.iter().enumerate() {
        if byte != 0 {
            // Negative zero: last byte is 0x80
            if i == vch.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Boolean constants as stack items.
pub const STACK_TRUE: &[u8] = &[1];
pub const STACK_FALSE: &[u8] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cast_to_bool() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0]));
        assert!(!cast_to_bool(&[0, 0]));
        assert!(!cast_to_bool(&[0x80])); // negative zero
        assert!(!cast_to_bool(&[0, 0x80])); // negative zero (2 bytes)
        assert!(cast_to_bool(&[1]));
        assert!(cast_to_bool(&[0, 1]));
        assert!(cast_to_bool(&[0x80, 0x00])); // 128, not negative zero
        assert!(cast_to_bool(&[0x01, 0x80])); // -1 in 2-byte encoding
    }
}
