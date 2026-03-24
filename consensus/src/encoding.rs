use crate::checker::SigVersion;
use crate::error::ScriptError;
use crate::flags;

/// Check if a DER-encoded signature is valid.
///
/// A canonical signature: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
/// This is consensus-critical since BIP66.
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Minimum and maximum size constraints.
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    // A signature is of type 0x30 (compound).
    if sig[0] != 0x30 {
        return false;
    }
    // Make sure the length covers the entire signature.
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }
    // Extract the length of the R element.
    let len_r = sig[3] as usize;
    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    }
    // Extract the length of the S element.
    let len_s = sig[5 + len_r] as usize;
    // Verify that the length of the signature matches the sum of the element lengths.
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    // Check whether the R element is an integer.
    if sig[2] != 0x02 {
        return false;
    }
    // Zero-length integers are not allowed for R.
    if len_r == 0 {
        return false;
    }
    // Negative numbers are not allowed for R.
    if sig[4] & 0x80 != 0 {
        return false;
    }
    // Null bytes at the start of R are not allowed, unless R would otherwise
    // be interpreted as a negative number.
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    // Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02 {
        return false;
    }
    // Zero-length integers are not allowed for S.
    if len_s == 0 {
        return false;
    }
    // Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    // Null bytes at the start of S are not allowed, unless S would otherwise
    // be interpreted as a negative number.
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// Check if the S value of a DER signature is low (≤ order/2).
///
/// Uses secp256k1 to verify the low-S property.
pub fn is_low_der_signature(sig: &[u8]) -> Result<(), ScriptError> {
    if !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    // Strip the hashtype byte and check low-S via secp256k1.
    let sig_without_hashtype = &sig[..sig.len() - 1];
    // Parse as DER and check if S is low
    match bitcoin::secp256k1::ecdsa::Signature::from_der(sig_without_hashtype) {
        Ok(mut parsed_sig) => {
            parsed_sig.normalize_s();
            // If normalize_s changed the signature, the original had high S
            let normalized_der = parsed_sig.serialize_der();
            if normalized_der.as_ref() != sig_without_hashtype {
                return Err(ScriptError::SigHighS);
            }
            Ok(())
        }
        Err(_) => Err(ScriptError::SigDer),
    }
}

/// Check if the hashtype byte of a signature is defined.
pub fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let hash_type = sig[sig.len() - 1] & !0x80; // strip ANYONECANPAY
    (1..=3).contains(&hash_type) // ALL=1, NONE=2, SINGLE=3
}

/// Full signature encoding check matching Bitcoin Core's CheckSignatureEncoding().
pub fn check_signature_encoding(sig: &[u8], script_flags: u32) -> Result<(), ScriptError> {
    // Empty signature is always allowed (provides compact invalid sig for CHECK(MULTI)SIG).
    if sig.is_empty() {
        return Ok(());
    }
    if flags::has_flag(
        script_flags,
        flags::VERIFY_DERSIG | flags::VERIFY_LOW_S | flags::VERIFY_STRICTENC,
    ) && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    }
    if flags::has_flag(script_flags, flags::VERIFY_LOW_S) {
        is_low_der_signature(sig)?;
    }
    if flags::has_flag(script_flags, flags::VERIFY_STRICTENC)
        && !is_defined_hashtype_signature(sig)
    {
        return Err(ScriptError::SigHashtype);
    }
    Ok(())
}

/// Check if a public key is compressed or uncompressed.
pub fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.len() < 33 {
        return false;
    }
    if pubkey[0] == 0x04 {
        pubkey.len() == 65
    } else if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
        pubkey.len() == 33
    } else {
        false
    }
}

/// Check if a public key is compressed.
pub fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Full public key encoding check matching Bitcoin Core's CheckPubKeyEncoding().
pub fn check_pubkey_encoding(
    pubkey: &[u8],
    script_flags: u32,
    sig_version: SigVersion,
) -> Result<(), ScriptError> {
    if flags::has_flag(script_flags, flags::VERIFY_STRICTENC)
        && !is_compressed_or_uncompressed_pubkey(pubkey)
    {
        return Err(ScriptError::PubkeyType);
    }
    // Only compressed keys are accepted in segwit v0
    if flags::has_flag(script_flags, flags::VERIFY_WITNESS_PUBKEYTYPE)
        && sig_version == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::WitnessPubkeyType);
    }
    Ok(())
}

/// Check if a push used the minimal encoding (matches Bitcoin Core's CheckMinimalPush).
///
/// `opcode` is the raw opcode byte (0x00..0x4e for push operations).
pub fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    if data.is_empty() {
        // Should have used OP_0.
        return opcode == 0x00; // OP_0
    }
    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        // Should have used OP_1 .. OP_16.
        return false;
    }
    if data.len() == 1 && data[0] == 0x81 {
        // Should have used OP_1NEGATE.
        return false;
    }
    if data.len() <= 75 {
        // Must have used a direct push (opcode == data length).
        return opcode as usize == data.len();
    }
    if data.len() <= 255 {
        // Must have used OP_PUSHDATA1.
        return opcode == 0x4c; // OP_PUSHDATA1
    }
    if data.len() <= 65535 {
        // Must have used OP_PUSHDATA2.
        return opcode == 0x4d; // OP_PUSHDATA2
    }
    true
}

/// FindAndDelete — remove all occurrences of `pattern` from `script` at
/// instruction boundaries.
///
/// Returns (modified_script, count_of_deletions).
pub fn find_and_delete(script: &[u8], pattern: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() || script.len() < pattern.len() {
        return (script.to_vec(), 0);
    }
    find_and_delete_exact(script, pattern)
}

/// Exact implementation of Bitcoin Core's FindAndDelete.
///
/// Iterates through `script` using GetOp semantics. Before processing each
/// opcode, copies bytes from the previous position, then checks for pattern
/// matches at the current position.
fn find_and_delete_exact(script: &[u8], pattern: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (script.to_vec(), 0);
    }

    let mut result = Vec::new();
    let mut count = 0;
    let mut pc: usize = 0;
    let mut pc2: usize = 0;

    loop {
        // Copy [pc2..pc] to result
        result.extend_from_slice(&script[pc2..pc]);

        // Skip consecutive pattern matches at pc
        while pc + pattern.len() <= script.len() && script[pc..pc + pattern.len()] == *pattern {
            pc += pattern.len();
            count += 1;
        }

        pc2 = pc;

        // GetOp: read one instruction, advancing pc
        if pc >= script.len() {
            break;
        }

        let opcode = script[pc];
        pc += 1;

        if opcode <= 75 {
            pc = (pc + opcode as usize).min(script.len());
        } else if opcode == 0x4c {
            // OP_PUSHDATA1
            if pc < script.len() {
                let n = script[pc] as usize;
                pc = (pc + 1 + n).min(script.len());
            }
        } else if opcode == 0x4d {
            // OP_PUSHDATA2
            if pc + 1 < script.len() {
                let n = script[pc] as usize | ((script[pc + 1] as usize) << 8);
                pc = (pc + 2 + n).min(script.len());
            } else {
                pc = script.len();
            }
        } else if opcode == 0x4e {
            // OP_PUSHDATA4
            if pc + 3 < script.len() {
                let n = script[pc] as usize
                    | ((script[pc + 1] as usize) << 8)
                    | ((script[pc + 2] as usize) << 16)
                    | ((script[pc + 3] as usize) << 24);
                pc = (pc + 4 + n).min(script.len());
            } else {
                pc = script.len();
            }
        }
        // Non-push opcodes: pc already advanced by 1
    }

    if count > 0 {
        // Copy remaining bytes
        result.extend_from_slice(&script[pc2..]);
        (result, count)
    } else {
        (script.to_vec(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_encoding_validation() {
        // Valid DER signature (minimal example)
        // 30 06 02 01 01 02 01 01 01 (hashtype)
        let valid = vec![
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
        ];
        assert!(is_valid_signature_encoding(&valid));

        // Too short
        assert!(!is_valid_signature_encoding(&[0x30, 0x06]));

        // Wrong type byte
        let mut bad = valid.clone();
        bad[0] = 0x31;
        assert!(!is_valid_signature_encoding(&bad));
    }

    #[test]
    fn test_compressed_pubkey() {
        assert!(is_compressed_pubkey(&[0x02; 33]));
        assert!(is_compressed_pubkey(&[0x03; 33]));
        assert!(!is_compressed_pubkey(&[0x04; 33]));
        assert!(!is_compressed_pubkey(&[0x02; 32]));
    }

    #[test]
    fn test_check_minimal_push() {
        // Empty data should use OP_0
        assert!(check_minimal_push(&[], 0x00));
        assert!(!check_minimal_push(&[], 0x01));

        // Single byte 1-16 should use OP_1..OP_16
        assert!(!check_minimal_push(&[1], 0x01));

        // Single byte 0x81 should use OP_1NEGATE
        assert!(!check_minimal_push(&[0x81], 0x01));

        // 2-byte data should use direct push (opcode = 2)
        assert!(check_minimal_push(&[0xff, 0x00], 0x02));
    }

    #[test]
    fn test_find_and_delete() {
        // Pattern: OP_NOP (0x61). Script: [OP_1 (0x51), OP_NOP (0x61), OP_2 (0x52)]
        let (result, count) = find_and_delete_exact(&[0x51, 0x61, 0x52], &[0x61]);
        assert_eq!(count, 1);
        assert_eq!(result, vec![0x51, 0x52]);

        // No match
        let (result, count) = find_and_delete_exact(&[0x51, 0x52], &[0x61]);
        assert_eq!(count, 0);
        assert_eq!(result, vec![0x51, 0x52]);

        // Empty script
        let (_, count) = find_and_delete_exact(&[], &[0x61]);
        assert_eq!(count, 0);

        // Empty pattern
        let (result, count) = find_and_delete(&[0x51], &[]);
        assert_eq!(count, 0);
        assert_eq!(result, vec![0x51]);
    }
}
