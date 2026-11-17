#!/usr/bin/env python3
"""Regenerate core_v32_1_script_rpc.json: Bitcoin Core v32.1's own
decodescript and decoderawtransaction output for the vectors below.

Start a throwaway regtest bitcoind v32.1 first, then run

    BITCOIN_CLI="bitcoin-cli -regtest -datadir=<dir>" \
    CORE_SRC=<bitcoin checkout with the v32.1 tag> \
    python3 gen_core_v32_1_script_rpc.py > core_v32_1_script_rpc.json
"""
import json, os, re, shlex, struct, subprocess, sys

CLI = shlex.split(os.environ.get("BITCOIN_CLI", "bitcoin-cli -regtest"))
CORE_SRC = os.environ["CORE_SRC"]

def cli(*args):
    return json.loads(subprocess.check_output(CLI + list(args)))

def core_file(path):
    return subprocess.check_output(["git", "-C", CORE_SRC, "show", f"v32.1:{path}"], text=True)

G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
G3 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
GU = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
XG = G[2:]
H20 = "751e76e8199196d454941c45d1b3a323f1433bd6"
H32 = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"

def push(h):
    n = len(h) // 2
    if n < 0x4c:
        return f"{n:02x}" + h
    if n <= 0xff:
        return "4c" + f"{n:02x}" + h
    return "4d" + struct.pack("<H", n).hex() + h

# DER signatures: 30 44 02 20 <r> 02 20 <s>, plus a sighash byte.
R = "11" * 32
S = "22" * 32
DER = "3044" + "0220" + R + "0220" + S
# r with the high bit set needs a 0x00 pad: 30 45 02 21 00 <r'> 02 20 <s>
DER_PAD = "3045" + "022100" + "81" * 32 + "0220" + S

scripts = {
    "empty": "",
    "p2pkh": f"76a914{H20}88ac",
    "p2wpkh": f"0014{H20}",
    "p2wsh": f"0020{H32}",
    "p2tr": f"5120{XG}",
    "p2sh": f"a914{H20}87",
    "p2pk": f"21{G}ac",
    "p2pk_uncompressed": f"41{GU}ac",
    "multisig_2of3": "52" + push(G) + push(G2) + push(G3) + "53ae",
    "multisig_uncompressed": "51" + push(G) + push(GU) + "52ae",
    "op_return": "6a0b68656c6c6f20776f726c64",
    "op_return_bare": "6a",
    "op_return_sig": "6a" + push(DER + "01"),
    "csv": "029000b275" + push(G) + "ac",
    "cltv": "0320a107b175" + push(G) + "ac",
    "csv_big": "03ffff40b275",
    "numbers": "4f00515f60" + "0181" + "0180" + "02ff00" + "02ff80" + "04ffffffff" + "04ffffff7f" + "050102030405" + "4c0100" + "4c00" + "4d0100ff" + "0100" + "03000080",
    "opcodes": "50b0b1b2b3b9ba61626566",
    "unknown_opcodes": "bbfeff",
    "truncated": f"76a914{H20[:6]}",
    "truncated_pushdata2": "4d01",
    "witness_v0_nonstandard": "0015" + H20 + "00",
    "witness_unknown": f"5214{H20}",
    "anchor": "51024e73",
    "tapscript_checksigadd": f"20{XG}ac20{XG}ba529c",
    "op_success": "50",
    "pkh_cltv": f"0320a107b17576a914{H20}88ac",
    "sig_in_spk": push(DER + "01") + push(G) + "ac",
    "large_push": push("ab" * 80),
    # OP_RETURN then non-push opcodes: nonstandard to Solver, but
    # IsUnspendable, so neither p2sh nor segwit.
    "op_return_nonpush": "6a61",
    "op_return_p2pkh": f"6a76a914{H20}88ac",
}

# Core's own decodescript inputs (test/functional/rpc_decodescript.py's
# miniscript cases and data/rpc_decodescript.json).
miniscript_inputs = re.findall(r'decodescript\("([0-9a-f]+)"\)', core_file("test/functional/rpc_decodescript.py"))
for i, h in enumerate(miniscript_inputs):
    scripts[f"core_miniscript_{i}"] = h
for i, (h, _) in enumerate(json.loads(core_file("test/functional/data/rpc_decodescript.json"))):
    scripts[f"core_datadriven_{i}"] = h
# Miniscript in P2WSH context: and_v(v:pk(K),older(144)) is sane;
# a pkh() by hash has no key to name; a sigless branch is not sane;
# or_d(pk,and_v(v:pk,older)) with two keys; repeated keys are not sane.
scripts["ms_pk_older"] = push(G) + "ad029000b2"
scripts["ms_pkh_hash"] = f"76a914{H20}88ad029000b2"
scripts["ms_sigless"] = "029000b2"
scripts["ms_or_d"] = push(G) + "ac736402" + "9000b2" + "68"
scripts["ms_or_d2"] = push(G) + "ac7364" + push(G2) + "ad029000b268"
scripts["ms_repeated"] = push(G) + "ad" + push(G) + "ac"
scripts["ms_uncompressed"] = push(GU) + "ad029000b2"
scripts["ms_thresh"] = push(G) + "ac7c" + push(G2) + "ac937c" + push(G3) + "ac9352" + "87"
scripts["ms_hash_timelock_mix"] = push(G) + "ad029000b2690320a107b1"

out = {"decodescript": {}, "decoderawtransaction": {}}
for name, h in scripts.items():
    out["decodescript"][name] = {"hex": h, "core": cli("decodescript", h)}

# A transaction covering the scriptSig sighash decode and the witness spends.
def txin(prev_byte, script_hex, seq="ffffffff"):
    return bytes([prev_byte]).hex() * 32 + "00000000" + varint(len(script_hex) // 2) + script_hex + seq

def varint(n):
    if n < 0xfd:
        return f"{n:02x}"
    return "fd" + struct.pack("<H", n).hex()

def txout(sats, spk):
    return struct.pack("<q", sats).hex() + varint(len(spk) // 2) + spk

def witness(items):
    return varint(len(items)) + "".join(varint(len(i) // 2) + i for i in items)

redeem = scripts["multisig_2of3"]
ins = [
    ("p2pkh_all", push(DER + "01") + push(G), []),
    ("p2pkh_single_acp", push(DER + "83") + push(G), []),
    ("p2pkh_none", push(DER_PAD + "02") + push(GU), []),
    ("p2pkh_all_acp", push(DER + "81") + push(G), []),
    ("p2pkh_none_acp", push(DER + "82") + push(G), []),
    ("p2pkh_single", push(DER + "03") + push(G), []),
    ("sighash_invalid_04", push(DER + "04") + push(G), []),
    ("sighash_invalid_00", push(DER + "00") + push(G), []),
    ("sighash_invalid_84", push(DER + "84") + push(G), []),
    ("sighash_invalid_80", push(DER + "80") + push(G), []),
    ("not_der", push("3044" + "0220" + R + "0221" + S + "01") + push(G), []),
    ("multisig_p2sh", "00" + push(DER + "01") + push(DER + "83") + push(redeem), []),
    ("p2wpkh", "", [DER + "01", G]),
    ("p2sh_p2wpkh", push(f"0014{H20}"), [DER + "01", G]),
    ("p2tr_keypath", "", ["33" * 64]),
    ("p2tr_keypath_sighash", "", ["33" * 64 + "83"]),
    ("op_return_scriptsig", "6a" + push(DER + "01"), []),
    ("numbers_scriptsig", "4f0051" + "0181" + push(DER + "01"), []),
    ("truncated_scriptsig", push(DER + "01") + "4c", []),
    ("p2wsh_witness", "", ["", DER + "01", DER + "83", redeem]),
]
outs = [
    (1000, scripts["p2pkh"]), (1000, scripts["p2wpkh"]), (1000, scripts["p2wsh"]),
    (1000, scripts["p2tr"]), (1000, scripts["p2sh"]), (1000, scripts["p2pk"]),
    (0, scripts["op_return"]), (1000, scripts["multisig_2of3"]), (1000, scripts["csv"]),
    (1000, scripts["cltv"]), (1000, scripts["anchor"]), (1000, scripts["witness_unknown"]),
    (1000, scripts["p2pk_uncompressed"]), (1000, scripts["numbers"]), (1000, scripts["truncated"]),
]
tx = "02000000" + "0001" + varint(len(ins)) + "".join(txin(i + 1, s) for i, (_, s, _) in enumerate(ins))
tx += varint(len(outs)) + "".join(txout(v, s) for v, s in outs)
tx += "".join(witness(w) for _, _, w in ins)
tx += "00000000"
out["decoderawtransaction"]["tx"] = {"hex": tx, "input_names": [n for n, _, _ in ins], "core": cli("decoderawtransaction", tx)}

json.dump(out, sys.stdout, indent=1)
print()
