use serde_json::{json, Value};

use crate::rpc::address_decode::{decode_destination, Decoded};

/// `validateaddress` — Core's `src/rpc/output_script.cpp`.
///
/// `network` is not decoration: Core's `DecodeDestination` is network-scoped,
/// and satd used to parse `NetworkUnchecked` and call `assume_checked()`, so
/// it reported a mainnet address as valid on regtest.
///
/// A string that does not decode carries Core's `error` and, for a Bech32
/// checksum failure, the `error_locations` its error locator attributes.
pub fn validate_address(address: &str, network: bitcoin::Network) -> Value {
    match decode_destination(address, network) {
        Decoded::Valid(addr) => {
            let script = addr.script_pubkey();
            let witness_version = script.witness_version().map(|v| v.to_num());
            // A witness script is `<version opcode> <push length> <program>`.
            let witness_program: &[u8] = match witness_version {
                Some(_) => &script.as_bytes()[2..],
                None => &[],
            };
            // Core's `PayToAnchor`: witness v1 carrying exactly this two-byte
            // program (`script/solver.cpp`).
            const P2A_PROGRAM: [u8; 2] = [0x4e, 0x73];

            // Core describes each destination type in `DescribeAddressVisitor`
            // (`src/rpc/util.cpp`). `isscript` is `None` where Core omits the
            // key entirely, and the witness fields are emitted only for the
            // destinations Core emits them for -- notably not for an anchor,
            // whose program Core never reports.
            let (script_type, isscript, emit_witness_fields) = match witness_version {
                None if script.is_p2pkh() => ("pubkeyhash", Some(false), false),
                None if script.is_p2sh() => ("scripthash", Some(true), false),
                None => ("nonstandard", Some(false), false),
                Some(0) if witness_program.len() == 20 => {
                    ("witness_v0_keyhash", Some(false), true)
                }
                Some(0) if witness_program.len() == 32 => {
                    ("witness_v0_scripthash", Some(true), true)
                }
                Some(1) if witness_program.len() == 32 => {
                    ("witness_v1_taproot", Some(true), true)
                }
                Some(1) if witness_program == P2A_PROGRAM => ("anchor", Some(true), false),
                _ => ("witness_unknown", None, true),
            };

            let mut out = json!({
                "isvalid": true,
                // Core re-encodes the decoded destination rather than echoing
                // the input, so a mixed-case Bech32 address comes back
                // normalised.
                "address": addr.to_string(),
                "scriptPubKey": hex::encode(script.as_bytes()),
                "iswitness": witness_version.is_some(),
                // Not a Core field; satd reports the output type here as
                // `getaddressinfo` does.
                "type": script_type,
            });
            if let Some(isscript) = isscript {
                out["isscript"] = json!(isscript);
            }
            // Core declares both witness fields optional and omits them for
            // every non-witness destination -- there is no such thing as
            // witness version -1.
            if emit_witness_fields {
                out["witness_version"] = json!(witness_version);
                out["witness_program"] = json!(hex::encode(witness_program));
            }
            out
        }
        Decoded::Invalid { error, locations } => json!({
            "isvalid": false,
            // Core pushes `error_locations` first and `error` second; key
            // order is not significant to any client, but the fields are:
            // both are always present on a failure, `error_locations` empty
            // when nothing could be attributed.
            "error_locations": locations,
            "error": error,
        }),
    }
}

/// Parse a 256-bit hash argument the way Core's `ParseHashV`
/// (`src/rpc/util.cpp`) does: a wrong *length* is reported as a length error,
/// and a right-length string that is not hexadecimal is reported as such.
/// Returning the length message for both tells a caller who typed a non-hex
/// character to count their characters instead.
///
/// Six other call sites still build the length message unconditionally; they
/// should adopt this.
pub fn parse_hash_v<T: std::str::FromStr>(s: &str, name: &str) -> Result<T, (i32, String)> {
    if let Ok(v) = s.parse::<T>() {
        return Ok(v);
    }
    if s.len() != 64 {
        return Err((-8, format!("{name} must be of length 64 (not {}, for '{s}')", s.len())));
    }
    Err((-8, format!("{name} must be hexadecimal string (not '{s}')")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// Core's `DescribeAddressVisitor` (`src/rpc/util.cpp`) decides three
    /// things per destination type: whether `isscript` is true, false, or
    /// absent, and whether the two witness fields appear at all. Every field
    /// on `validateaddress` bar `isvalid` is declared optional precisely so
    /// they can be omitted.
    ///
    /// satd reported `isscript: false` for Taproot and for an anchor (both are
    /// script destinations to Core), emitted the anchor's witness program
    /// (Core reports neither witness field for it), and invented
    /// `witness_version: -1` for every non-witness address.
    #[test]
    fn destination_description_matches_core() {
        /// address, `isscript` (`None` = key absent), `iswitness`,
        /// `witness_version` (`None` = both witness fields absent), `type`.
        type Case = (&'static str, Option<bool>, bool, Option<i64>, &'static str);

        let cases: &[Case] = &[
            // P2PKH and P2SH: no witness fields at all.
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Some(false), false, None, "pubkeyhash"),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Some(true), false, None, "scripthash"),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                Some(false),
                true,
                Some(0),
                "witness_v0_keyhash",
            ),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                Some(true),
                true,
                Some(0),
                "witness_v0_scripthash",
            ),
            // Taproot is a script destination to Core.
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                Some(true),
                true,
                Some(1),
                "witness_v1_taproot",
            ),
            // PayToAnchor: a script destination, but Core reports neither
            // witness field for it.
            ("bc1pfeessrawgf", Some(true), true, None, "anchor"),
        ];

        for (addr, isscript, iswitness, witness_version, script_type) in cases {
            let v = validate_address(addr, Network::Bitcoin);
            assert_eq!(v["isvalid"], json!(true), "{addr}: {v}");
            assert_eq!(v["type"], json!(script_type), "{addr}: {v}");
            assert_eq!(v["iswitness"], json!(iswitness), "{addr}: {v}");
            match isscript {
                Some(b) => assert_eq!(v["isscript"], json!(b), "{addr}: {v}"),
                None => assert!(v.get("isscript").is_none(), "{addr}: {v}"),
            }
            match witness_version {
                Some(n) => {
                    assert_eq!(v["witness_version"], json!(n), "{addr}: {v}");
                    assert!(v.get("witness_program").is_some(), "{addr}: {v}");
                }
                None => {
                    assert!(
                        v.get("witness_version").is_none(),
                        "there is no witness version -1: {addr}: {v}"
                    );
                    assert!(v.get("witness_program").is_none(), "{addr}: {v}");
                }
            }
        }
    }

    /// A right-length string that is not hexadecimal is a hex error, not a
    /// length error -- telling a caller who typed `z` to count characters
    /// sends them the wrong way. Core splits the two in `ParseHashV`.
    #[test]
    fn a_64_character_non_hex_hash_is_a_hex_error() {
        let sixty_four_z = "z".repeat(64);
        let err = parse_hash_v::<bitcoin::BlockHash>(&sixty_four_z, "blockhash").unwrap_err();
        assert_eq!(err.0, -8);
        assert_eq!(err.1, format!("blockhash must be hexadecimal string (not '{sixty_four_z}')"));

        let short = "abc";
        let err = parse_hash_v::<bitcoin::BlockHash>(short, "blockhash").unwrap_err();
        assert_eq!(err.1, "blockhash must be of length 64 (not 3, for 'abc')");
    }
}
