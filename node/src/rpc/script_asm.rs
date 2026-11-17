//! Bitcoin Core's script disassembly, `ScriptToAsmStr` (`src/core_io.cpp`).
//!
//! Every RPC `asm` field uses it, as Core does. rust-bitcoin's `Display` for
//! `Script` is a different format (`OP_PUSHBYTES_20 <hex>`, `OP_PUSHNUM_1`,
//! `OP_0`, `OP_CSV`), so tools that split Core's `asm` (`OP_RETURN <hex>`,
//! `0 <program>`) read other tokens from it. Esplora's `*_asm` fields follow
//! Esplora's own format and do not use this.

/// Core's `MAX_SCRIPT_SIZE` (`src/script/script.h`).
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Core's `ScriptToAsmStr(script, fAttemptSighashDecode)`.
///
/// Pushes of at most four bytes print as the number they encode
/// (`CScriptNum(vch, false).getint()`, so non-minimal encodings and negative
/// zero print too), longer pushes as bare hex, and every other opcode by
/// Core's `GetOpName`. A push that runs past the end of the script prints
/// `[error]` and ends the output.
///
/// With `attempt_sighash_decode`, a push that is a strictly encoded DER
/// signature with a defined sighash type (`CheckSignatureEncoding` with
/// `SCRIPT_VERIFY_STRICTENC`) prints with its last byte replaced by the
/// decoded type, as in `<sig>[ALL|ANYONECANPAY]`, unless the script is
/// unspendable. Core passes `true` for a transaction input's scriptSig
/// (`TxToUniv`) and a PSBT's `final_scriptSig` (`decodepsbt`), and `false`
/// for every scriptPubKey, redeem script and witness script.
pub fn script_to_asm_str(script: &[u8], attempt_sighash_decode: bool) -> String {
    let mut out = String::new();
    let mut pc = 0;
    while pc < script.len() {
        if !out.is_empty() {
            out.push(' ');
        }
        let Some((opcode, data, next)) = get_script_op(script, pc) else {
            out.push_str("[error]");
            return out;
        };
        pc = next;
        if opcode <= OP_PUSHDATA4 {
            if data.len() <= 4 {
                out.push_str(&script_num(data).to_string());
            } else if let Some(name) = (attempt_sighash_decode && !is_unspendable(script))
                .then(|| signature_sighash_name(data))
                .flatten()
            {
                // The sighash byte is dropped and replaced by its name.
                out.push_str(&hex::encode(&data[..data.len() - 1]));
                out.push('[');
                out.push_str(name);
                out.push(']');
            } else {
                out.push_str(&hex::encode(data));
            }
        } else {
            out.push_str(op_name(opcode));
        }
    }
    out
}

/// `CScript::IsUnspendable`: starts with `OP_RETURN`, or is over
/// `MAX_SCRIPT_SIZE`. It keeps `OP_RETURN` data that happens to look like a
/// signature from being decoded.
fn is_unspendable(script: &[u8]) -> bool {
    script.first() == Some(&OP_RETURN) || script.len() > MAX_SCRIPT_SIZE
}

/// The sighash name Core's `mapSigHashTypes` gives `sig`'s last byte, when
/// `sig` passes `CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC)`:
/// strict DER (BIP 66) and `IsDefinedHashtypeSignature`.
fn signature_sighash_name(sig: &[u8]) -> Option<&'static str> {
    if !consensus::encoding::is_valid_signature_encoding(sig) {
        return None;
    }
    match *sig.last()? {
        0x01 => Some("ALL"),
        0x81 => Some("ALL|ANYONECANPAY"),
        0x02 => Some("NONE"),
        0x82 => Some("NONE|ANYONECANPAY"),
        0x03 => Some("SINGLE"),
        0x83 => Some("SINGLE|ANYONECANPAY"),
        _ => None,
    }
}

const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_RETURN: u8 = 0x6a;

/// Core's `GetScriptOp`: the opcode at `pc`, its pushed data, and the offset
/// of the next opcode. `None` when a push length or its data runs past the
/// end of the script.
fn get_script_op(script: &[u8], pc: usize) -> Option<(u8, &[u8], usize)> {
    let opcode = *script.get(pc)?;
    let mut pc = pc + 1;
    if opcode > OP_PUSHDATA4 {
        return Some((opcode, &[], pc));
    }
    let size = match opcode {
        OP_PUSHDATA1 => {
            let n = *script.get(pc)? as usize;
            pc += 1;
            n
        }
        OP_PUSHDATA2 => {
            let b = script.get(pc..pc + 2)?;
            pc += 2;
            u16::from_le_bytes([b[0], b[1]]) as usize
        }
        OP_PUSHDATA4 => {
            let b = script.get(pc..pc + 4)?;
            pc += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n => n as usize,
    };
    let end = pc.checked_add(size)?;
    let data = script.get(pc..end)?;
    Some((opcode, data, end))
}

/// `CScriptNum(vch, /*fRequireMinimal=*/false).getint()` for a push of at
/// most four bytes: little-endian magnitude, sign in the top bit of the last
/// byte. Four bytes never leave `getint`'s `int` range, so no clamping.
fn script_num(data: &[u8]) -> i64 {
    let Some(&last) = data.last() else {
        return 0;
    };
    let mut value: i64 = 0;
    for (i, b) in data.iter().enumerate() {
        value |= (*b as i64) << (8 * i);
    }
    if last & 0x80 != 0 {
        -(value & !(0x80i64 << (8 * (data.len() - 1))))
    } else {
        value
    }
}

/// Core's `GetOpName` (`src/script/script.cpp`) for an opcode that is not a
/// data push (`OP_0` and the `OP_PUSHDATA`s are printed as their data).
fn op_name(opcode: u8) -> &'static str {
    match opcode {
        0x4f => "-1",
        0x50 => "OP_RESERVED",
        0x51 => "1",
        0x52 => "2",
        0x53 => "3",
        0x54 => "4",
        0x55 => "5",
        0x56 => "6",
        0x57 => "7",
        0x58 => "8",
        0x59 => "9",
        0x5a => "10",
        0x5b => "11",
        0x5c => "12",
        0x5d => "13",
        0x5e => "14",
        0x5f => "15",
        0x60 => "16",
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        0xb0 => "OP_NOP1",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",
        0xb8 => "OP_NOP9",
        0xb9 => "OP_NOP10",
        0xba => "OP_CHECKSIGADD",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::script_to_asm_str;
    use serde_json::Value;

    /// Output of Bitcoin Core v32.1's `decodescript` and
    /// `decoderawtransaction`, taken from a regtest node.
    const CORE: &str = include_str!("testdata/core_v32_1_script_rpc.json");

    fn core() -> Value {
        serde_json::from_str(CORE).unwrap()
    }

    /// Every scriptPubKey `asm` matches Core's `ScriptToAsmStr(script)`:
    /// numbers for small pushes (negative, non-minimal and negative zero
    /// included), bare hex for longer ones, Core's opcode names (CSV, CLTV,
    /// CHECKSIGADD, OP_UNKNOWN), `[error]` for a truncated push, and no
    /// sighash decode outside a scriptSig. rust-bitcoin's `Display`, which
    /// these fields used before, fails nearly every vector.
    #[test]
    fn script_asm_matches_core_decodescript() {
        let core = core();
        let vectors = core["decodescript"].as_object().unwrap();
        assert!(vectors.len() >= 25);
        for (name, v) in vectors {
            let script = hex::decode(v["hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                script_to_asm_str(&script, false),
                v["core"]["asm"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    /// scriptSig `asm` decodes the sighash byte of a strictly encoded DER
    /// signature (all six defined types), leaves an undefined type (0x00,
    /// 0x04, 0x80, 0x84) and a non-DER push as hex, never decodes inside an
    /// `OP_RETURN` script, and stops at `[error]`; vout `asm` never decodes.
    /// Perturbation: drop the `is_unspendable` check and
    /// `op_return_scriptsig` fails.
    #[test]
    fn script_sig_asm_matches_core_decoderawtransaction() {
        let core = core();
        let tx = &core["decoderawtransaction"]["tx"];
        let raw = hex::decode(tx["hex"].as_str().unwrap()).unwrap();
        let decoded: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let names = tx["input_names"].as_array().unwrap();
        for (i, input) in decoded.input.iter().enumerate() {
            assert_eq!(
                script_to_asm_str(input.script_sig.as_bytes(), true),
                tx["core"]["vin"][i]["scriptSig"]["asm"].as_str().unwrap(),
                "{}",
                names[i]
            );
        }
        for (i, output) in decoded.output.iter().enumerate() {
            assert_eq!(
                script_to_asm_str(output.script_pubkey.as_bytes(), false),
                tx["core"]["vout"][i]["scriptPubKey"]["asm"].as_str().unwrap(),
                "vout {i}"
            );
        }
    }

    /// The RPC builders use it: `decoderawtransaction` / `getrawtransaction`
    /// / `getblock` (`decode_transaction_verbose_net`, prevouts included),
    /// `gettxout` (`script_pubkey_json`) and `decodescript` answer Core's
    /// `asm`. Perturbation: put `format!("{}", output.script_pubkey)` back
    /// in the vout builder, or pass `false` for the scriptSig, and this
    /// fails.
    #[test]
    fn rpc_asm_fields_match_core() {
        let core = core();
        let tx = &core["decoderawtransaction"]["tx"];
        let raw = hex::decode(tx["hex"].as_str().unwrap()).unwrap();
        let decoded: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        // Each input spends the output of the same index's script, so the
        // prevout path renders the vout scripts too.
        let undo: Vec<crate::storage::coinview::Coin> = (0..decoded.input.len())
            .map(|i| crate::storage::coinview::Coin {
                amount: 1000,
                script_pubkey: decoded.output[i % decoded.output.len()].script_pubkey.clone(),
                height: 1,
                coinbase: false,
                txseq: 0,
            })
            .collect();
        let got = crate::rpc::rawtx::decode_transaction_verbose_net(
            &decoded,
            None,
            Some(&undo),
            true,
            true,
            bitcoin::Network::Regtest,
        );
        let core_tx = &tx["core"];
        for i in 0..decoded.input.len() {
            assert_eq!(got["vin"][i]["scriptSig"]["asm"], core_tx["vin"][i]["scriptSig"]["asm"], "vin {i}");
            assert_eq!(
                got["vin"][i]["prevout"]["scriptPubKey"]["asm"],
                core_tx["vout"][i % decoded.output.len()]["scriptPubKey"]["asm"],
                "prevout {i}"
            );
        }
        for i in 0..decoded.output.len() {
            assert_eq!(got["vout"][i]["scriptPubKey"]["asm"], core_tx["vout"][i]["scriptPubKey"]["asm"], "vout {i}");
            let spk = crate::rpc::rawtx::script_pubkey_json(&decoded.output[i].script_pubkey, bitcoin::Network::Regtest);
            assert_eq!(spk["asm"], core_tx["vout"][i]["scriptPubKey"]["asm"], "gettxout {i}");
        }
        for (name, v) in core["decodescript"].as_object().unwrap() {
            let got = crate::rpc::rawtx::decode_script(v["hex"].as_str().unwrap(), bitcoin::Network::Regtest).unwrap();
            assert_eq!(got["asm"], v["core"]["asm"], "decodescript {name}");
        }
    }

    /// `decodescript` answers what Core's does, field for field: `asm`,
    /// `desc`, `address`, `type`, `p2sh`, and the `segwit` object with its
    /// own `asm`, `hex`, `type`, `address`, `desc` (`wsh(multi())` or a
    /// miniscript where the witness script infers, `addr()` otherwise) and
    /// `p2sh-segwit`. `segwit` is absent for an uncompressed key and for a
    /// script that is already a witness program, and present for a P2WPKH
    /// wrapping of a compressed P2PK or a P2PKH. Perturbation: drop `desc`
    /// from `decode_script`, or report `segwit` for every wrappable script,
    /// and this fails.
    #[test]
    fn decodescript_matches_core() {
        let core = core();
        for (name, v) in core["decodescript"].as_object().unwrap() {
            let got = crate::rpc::rawtx::decode_script(v["hex"].as_str().unwrap(), bitcoin::Network::Regtest).unwrap();
            assert_eq!(got, v["core"], "decodescript {name}");
        }
    }

    /// Every scriptPubKey object a transaction decodes to, vout and prevout,
    /// is Core's `ScriptToUniv(include_hex, include_address)`, `desc`
    /// included. Perturbation: drop `desc` from `script_pubkey_json` and
    /// this fails.
    #[test]
    fn tx_script_pubkeys_match_core() {
        let core = core();
        let tx = &core["decoderawtransaction"]["tx"];
        let raw = hex::decode(tx["hex"].as_str().unwrap()).unwrap();
        let decoded: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let n_out = decoded.output.len();
        let undo: Vec<crate::storage::coinview::Coin> = (0..decoded.input.len())
            .map(|i| crate::storage::coinview::Coin {
                amount: 1000,
                script_pubkey: decoded.output[i % n_out].script_pubkey.clone(),
                height: 1,
                coinbase: false,
                txseq: 0,
            })
            .collect();
        let got = crate::rpc::rawtx::decode_transaction_verbose_net(
            &decoded,
            None,
            Some(&undo),
            true,
            true,
            bitcoin::Network::Regtest,
        );
        let core_tx = &tx["core"];
        for i in 0..n_out {
            assert_eq!(got["vout"][i]["scriptPubKey"], core_tx["vout"][i]["scriptPubKey"], "vout {i}");
        }
        for i in 0..decoded.input.len() {
            assert_eq!(
                got["vin"][i]["prevout"]["scriptPubKey"],
                core_tx["vout"][i % n_out]["scriptPubKey"],
                "prevout {i}"
            );
        }
    }
}
