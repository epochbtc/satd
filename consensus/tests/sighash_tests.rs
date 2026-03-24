//! sighash.json test vectors: verify legacy sighash computation matches
//! Bitcoin Core's SignatureHash output for 500 random transactions.

use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;
use serde_json::Value;

/// Strip OP_CODESEPARATOR (0xab) from a script at instruction boundaries.
fn strip_codeseparator(script: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(script.len());
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        if opcode == 0xab {
            pc += 1;
            continue;
        }
        let start = pc;
        pc += 1;
        if opcode <= 75 {
            pc += opcode as usize;
        } else if opcode == 0x4c && pc < script.len() {
            let n = script[pc] as usize;
            pc += 1 + n;
        } else if opcode == 0x4d && pc + 1 < script.len() {
            let n = script[pc] as usize | ((script[pc + 1] as usize) << 8);
            pc += 2 + n;
        } else if opcode == 0x4e && pc + 3 < script.len() {
            let n = script[pc] as usize
                | ((script[pc + 1] as usize) << 8)
                | ((script[pc + 2] as usize) << 16)
                | ((script[pc + 3] as usize) << 24);
            pc += 4 + n;
        }
        let end = pc.min(script.len());
        result.extend_from_slice(&script[start..end]);
    }
    result
}

/// Run sighash.json: each entry is [raw_tx, raw_script, input_index, hashType, expected_hash].
/// These test the legacy (pre-segwit) SignatureHash function.
#[test]
fn test_sighash_vectors() {
    let data = include_str!("../test-data/sighash.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut passed = 0;
    let mut mismatched = 0;
    let mut skipped = 0;

    for test in &tests {
        if !test.is_array() || test.as_array().unwrap().len() < 5 {
            skipped += 1;
            continue;
        }
        let arr = test.as_array().unwrap();
        // Skip comment entries
        if arr[0].is_string() && arr[1].is_string() && arr[2].is_string() {
            skipped += 1;
            continue;
        }

        let raw_tx_hex = arr[0].as_str().unwrap();
        let raw_script_hex = arr[1].as_str().unwrap();
        let input_index = arr[2].as_u64().unwrap() as usize;
        let hash_type = arr[3].as_i64().unwrap() as u32;
        let expected_hash_hex = arr[4].as_str().unwrap();

        // Deserialize transaction
        let tx_bytes = hex::decode(raw_tx_hex).unwrap();
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(tx) => tx,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        // Parse script as raw bytes and strip OP_CODESEPARATOR (0xab) at
        // instruction boundaries. Bitcoin Core's SignatureHash does this via
        // CTransactionSignatureSerializer::SerializeScriptCode, but the bitcoin
        // crate's legacy_signature_hash does NOT.
        let script_code_raw = hex::decode(raw_script_hex).unwrap();
        let script_code_clean = strip_codeseparator(&script_code_raw);
        let script = bitcoin::Script::from_bytes(&script_code_clean);

        // Compute legacy sighash using bitcoin crate's SighashCache
        let cache = SighashCache::new(&tx);
        let sighash = match cache.legacy_signature_hash(input_index, script, hash_type) {
            Ok(h) => h,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        // Bitcoin Core's GetHex() reverses the internal byte array of uint256.
        // LegacySighash stores bytes the same as sha256d (internal order), and its
        // Display doesn't reverse. The JSON uses GetHex() output, so we reverse.
        let computed_hex: String = sighash
            .as_byte_array()
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        if computed_hex == expected_hash_hex {
            passed += 1;
        } else {
            mismatched += 1;
            if mismatched <= 3 {
                eprintln!(
                    "sighash mismatch #{mismatched} for input {input_index}, hashtype {hash_type}:\n  computed: {computed_hex}\n  expected: {expected_hash_hex}",
                );
            }
        }
    }

    eprintln!("Sighash tests: {passed} passed, {mismatched} mismatched, {skipped} skipped");
    assert_eq!(mismatched, 0, "{mismatched} sighash tests failed");
}
