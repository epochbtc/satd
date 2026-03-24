use consensus::error::ScriptError;
use consensus::flags;

/// Parse a comma-separated flag string from Bitcoin Core test vectors into our u32 bitfield.
///
/// Example: "P2SH,STRICTENC,DERSIG,WITNESS" -> corresponding u32
pub fn parse_flags(flag_str: &str) -> u32 {
    if flag_str.is_empty() {
        return flags::VERIFY_NONE;
    }

    let mut result = flags::VERIFY_NONE;
    for flag in flag_str.split(',') {
        let flag = flag.trim();
        result |= match flag {
            "NONE" => flags::VERIFY_NONE,
            "P2SH" => flags::VERIFY_P2SH,
            "STRICTENC" => flags::VERIFY_STRICTENC,
            "DERSIG" => flags::VERIFY_DERSIG,
            "LOW_S" => flags::VERIFY_LOW_S,
            "NULLDUMMY" => flags::VERIFY_NULLDUMMY,
            "SIGPUSHONLY" => flags::VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => flags::VERIFY_MINIMALDATA,
            "DISCOURAGE_UPGRADABLE_NOPS" => flags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => flags::VERIFY_CLEANSTACK,
            "CHECKLOCKTIMEVERIFY" => flags::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => flags::VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => flags::VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                flags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            }
            "MINIMALIF" => flags::VERIFY_MINIMALIF,
            "NULLFAIL" => flags::VERIFY_NULLFAIL,
            "WITNESS_PUBKEYTYPE" => flags::VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => flags::VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" => flags::VERIFY_TAPROOT,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                flags::VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            }
            "DISCOURAGE_OP_SUCCESS" => flags::VERIFY_DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => flags::VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            _ => panic!("Unknown flag: {flag}"),
        };
    }
    result
}

/// Parse a Bitcoin Core test vector error name to our ScriptError.
pub fn parse_expected_error(name: &str) -> ScriptError {
    ScriptError::from_test_name(name).unwrap_or_else(|| panic!("Unknown error name: {name}"))
}

/// Parse a human-readable script string from Bitcoin Core tests into raw bytes.
///
/// Handles:
/// - Decimal numbers as push data (e.g., "0", "1", "-1", "127")
/// - `0x` hex prefixes as raw bytes (e.g., "0x01020304")
/// - `'quoted'` strings as push data
/// - Opcode names (e.g., "DUP", "HASH160", "CHECKSIG", "OP_DUP")
pub fn parse_script(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let s = s.trim();
    if s.is_empty() {
        return result;
    }

    let mut chars = s.chars().peekable();
    let mut tokens: Vec<String> = Vec::new();

    // Tokenize
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '\'' {
            // Quoted string
            chars.next(); // consume opening quote
            let mut token = String::from("'");
            for ch in chars.by_ref() {
                if ch == '\'' {
                    break;
                }
                token.push(ch);
            }
            token.push('\'');
            tokens.push(token);
        } else {
            let mut token = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                token.push(c);
                chars.next();
            }
            tokens.push(token);
        }
    }

    for token in &tokens {
        if token.starts_with("'") && token.ends_with("'") && token.len() >= 2 {
            // Quoted string: push the bytes
            let inner = &token[1..token.len() - 1];
            let bytes = inner.as_bytes();
            push_data(&mut result, bytes);
        } else if token.starts_with("0x") || token.starts_with("0X") {
            // Raw hex bytes
            let hex_str = &token[2..];
            let bytes = hex::decode(hex_str).unwrap_or_else(|e| {
                panic!("Invalid hex in script token '{token}': {e}");
            });
            result.extend_from_slice(&bytes);
        } else if let Some(opcode) = opcode_from_name(token) {
            result.push(opcode);
        } else if let Ok(n) = token.parse::<i64>() {
            // Number: push as minimal script number
            if n == -1 {
                result.push(0x4f); // OP_1NEGATE
            } else if n == 0 {
                result.push(0x00); // OP_0
            } else if (1..=16).contains(&n) {
                result.push(0x50 + n as u8); // OP_1..OP_16
            } else {
                // Push as ScriptNum encoding
                let bytes = consensus::scriptnum::serialize_i64(n);
                push_data(&mut result, &bytes);
            }
        } else {
            panic!("Unknown script token: '{token}'");
        }
    }

    result
}

/// Push data onto the script with appropriate length prefix.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 65535 {
        script.push(0x4d); // OP_PUSHDATA2
        script.push(len as u8);
        script.push((len >> 8) as u8);
    } else {
        script.push(0x4e); // OP_PUSHDATA4
        script.push(len as u8);
        script.push((len >> 8) as u8);
        script.push((len >> 16) as u8);
        script.push((len >> 24) as u8);
    }
    script.extend_from_slice(data);
}

/// Map an opcode name (with or without "OP_" prefix) to its byte value.
fn opcode_from_name(name: &str) -> Option<u8> {
    // Strip OP_ prefix if present
    let name = name.strip_prefix("OP_").unwrap_or(name);
    match name {
        "0" | "FALSE" => Some(0x00),
        "PUSHDATA1" => Some(0x4c),
        "PUSHDATA2" => Some(0x4d),
        "PUSHDATA4" => Some(0x4e),
        "1NEGATE" => Some(0x4f),
        "RESERVED" => Some(0x50),
        "1" | "TRUE" => Some(0x51),
        "2" => Some(0x52),
        "3" => Some(0x53),
        "4" => Some(0x54),
        "5" => Some(0x55),
        "6" => Some(0x56),
        "7" => Some(0x57),
        "8" => Some(0x58),
        "9" => Some(0x59),
        "10" => Some(0x5a),
        "11" => Some(0x5b),
        "12" => Some(0x5c),
        "13" => Some(0x5d),
        "14" => Some(0x5e),
        "15" => Some(0x5f),
        "16" => Some(0x60),
        "NOP" => Some(0x61),
        "VER" => Some(0x62),
        "IF" => Some(0x63),
        "NOTIF" => Some(0x64),
        "VERIF" => Some(0x65),
        "VERNOTIF" => Some(0x66),
        "ELSE" => Some(0x67),
        "ENDIF" => Some(0x68),
        "VERIFY" => Some(0x69),
        "RETURN" => Some(0x6a),
        "TOALTSTACK" => Some(0x6b),
        "FROMALTSTACK" => Some(0x6c),
        "2DROP" => Some(0x6d),
        "2DUP" => Some(0x6e),
        "3DUP" => Some(0x6f),
        "2OVER" => Some(0x70),
        "2ROT" => Some(0x71),
        "2SWAP" => Some(0x72),
        "IFDUP" => Some(0x73),
        "DEPTH" => Some(0x74),
        "DROP" => Some(0x75),
        "DUP" => Some(0x76),
        "NIP" => Some(0x77),
        "OVER" => Some(0x78),
        "PICK" => Some(0x79),
        "ROLL" => Some(0x7a),
        "ROT" => Some(0x7b),
        "SWAP" => Some(0x7c),
        "TUCK" => Some(0x7d),
        "CAT" => Some(0x7e),
        "SUBSTR" | "SPLIT" => Some(0x7f),
        "LEFT" | "NUM2BIN" => Some(0x80),
        "RIGHT" | "BIN2NUM" => Some(0x81),
        "SIZE" => Some(0x82),
        "INVERT" => Some(0x83),
        "AND" => Some(0x84),
        "OR" => Some(0x85),
        "XOR" => Some(0x86),
        "EQUAL" => Some(0x87),
        "EQUALVERIFY" => Some(0x88),
        "RESERVED1" => Some(0x89),
        "RESERVED2" => Some(0x8a),
        "1ADD" => Some(0x8b),
        "1SUB" => Some(0x8c),
        "2MUL" => Some(0x8d),
        "2DIV" => Some(0x8e),
        "NEGATE" => Some(0x8f),
        "ABS" => Some(0x90),
        "NOT" => Some(0x91),
        "0NOTEQUAL" => Some(0x92),
        "ADD" => Some(0x93),
        "SUB" => Some(0x94),
        "MUL" => Some(0x95),
        "DIV" => Some(0x96),
        "MOD" => Some(0x97),
        "LSHIFT" => Some(0x98),
        "RSHIFT" => Some(0x99),
        "BOOLAND" => Some(0x9a),
        "BOOLOR" => Some(0x9b),
        "NUMEQUAL" => Some(0x9c),
        "NUMEQUALVERIFY" => Some(0x9d),
        "NUMNOTEQUAL" => Some(0x9e),
        "LESSTHAN" => Some(0x9f),
        "GREATERTHAN" => Some(0xa0),
        "LESSTHANOREQUAL" => Some(0xa1),
        "GREATERTHANOREQUAL" => Some(0xa2),
        "MIN" => Some(0xa3),
        "MAX" => Some(0xa4),
        "WITHIN" => Some(0xa5),
        "RIPEMD160" => Some(0xa6),
        "SHA1" => Some(0xa7),
        "SHA256" => Some(0xa8),
        "HASH160" => Some(0xa9),
        "HASH256" => Some(0xaa),
        "CODESEPARATOR" => Some(0xab),
        "CHECKSIG" => Some(0xac),
        "CHECKSIGVERIFY" => Some(0xad),
        "CHECKMULTISIG" => Some(0xae),
        "CHECKMULTISIGVERIFY" => Some(0xaf),
        "NOP1" => Some(0xb0),
        "CHECKLOCKTIMEVERIFY" | "NOP2" => Some(0xb1),
        "CHECKSEQUENCEVERIFY" | "NOP3" => Some(0xb2),
        "NOP4" => Some(0xb3),
        "NOP5" => Some(0xb4),
        "NOP6" => Some(0xb5),
        "NOP7" => Some(0xb6),
        "NOP8" => Some(0xb7),
        "NOP9" => Some(0xb8),
        "NOP10" => Some(0xb9),
        "CHECKSIGADD" => Some(0xba),
        "INVALIDOPCODE" => Some(0xff),
        _ => {
            // Try SUCCESS opcodes: OP_SUCCESS80..OP_SUCCESS255 etc
            // These are 0x50, 0x62, 0x7e-0x7f, 0x89-0x8a, 0x8d-0x8e, 0x95-0x99, 0xbb-0xfe
            if let Some(rest) = name.strip_prefix("SUCCESS") {
                if let Ok(n) = rest.parse::<u16>() {
                    return Some(n as u8);
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flags() {
        assert_eq!(parse_flags(""), flags::VERIFY_NONE);
        assert_eq!(parse_flags("P2SH"), flags::VERIFY_P2SH);
        assert_eq!(
            parse_flags("P2SH,DERSIG"),
            flags::VERIFY_P2SH | flags::VERIFY_DERSIG
        );
    }

    #[test]
    fn test_parse_script_opcodes() {
        let script = parse_script("OP_1 OP_2 OP_ADD OP_3 OP_EQUAL");
        assert_eq!(script, vec![0x51, 0x52, 0x93, 0x53, 0x87]);
    }

    #[test]
    fn test_parse_script_numbers() {
        let script = parse_script("0 1 -1 16");
        assert_eq!(script, vec![0x00, 0x51, 0x4f, 0x60]);
    }

    #[test]
    fn test_parse_script_hex() {
        let script = parse_script("0x0102");
        assert_eq!(script, vec![0x01, 0x02]);
    }

    #[test]
    fn test_parse_script_quoted() {
        let script = parse_script("'ab'");
        // Push 2 bytes: 0x02 'a' 'b'
        assert_eq!(script, vec![0x02, b'a', b'b']);
    }
}
