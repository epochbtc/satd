#!/usr/bin/env python3
"""Regenerate core_v32_1_decodepsbt_fields.json: Bitcoin Core v32.1's
decodepsbt output for PSBTs carrying the fields its wallet does not write
(global xpubs, preimages, taproot script-path fields, MuSig2 fields,
proprietary and unknown pairs, a sighash Core cannot name, a negative fee).

Each PSBT is one of core_v32_1_decodepsbt.json's, with pairs added to its
maps. Start a throwaway, empty regtest bitcoind v32.1 (no wallet needed),
then run

    BITCOIN_CLI="bitcoin-cli -regtest -datadir=<dir>" \\
        ./gen_core_v32_1_decodepsbt_fields.py | jq --indent 1 . > core_v32_1_decodepsbt_fields.json

Core's answers are written as it printed them, so amounts keep their eight
decimals.
"""
import base64, hashlib, io, json, os, shlex, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = shlex.split(os.environ.get("BITCOIN_CLI", "bitcoin-cli -regtest"))
BASE = json.load(open(os.path.join(HERE, "core_v32_1_decodepsbt.json")))["decodepsbt"]

def rd_cs(b):
    n=b.read(1)[0]
    if n<0xfd: return n
    return int.from_bytes(b.read({0xfd:2,0xfe:4,0xff:8}[n]),'little')
def cs(n):
    if n<0xfd: return bytes([n])
    if n<=0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n<=0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')
def rd_map(b):
    m=[]
    while True:
        kl=rd_cs(b)
        if kl==0: return m
        k=b.read(kl); vl=rd_cs(b); v=b.read(vl); m.append((k,v))
def parse(b64, n_in, n_out):
    b=io.BytesIO(base64.b64decode(b64)); assert b.read(5)==b'psbt\xff'
    g=rd_map(b); ins=[rd_map(b) for _ in range(n_in)]; outs=[rd_map(b) for _ in range(n_out)]
    assert b.read()==b''
    return g,ins,outs
def ser(g,ins,outs):
    o=b'psbt\xff'
    for m in [g]+ins+outs:
        for k,v in m: o+=cs(len(k))+k+cs(len(v))+v
        o+=b'\x00'
    return base64.b64encode(o).decode()
def ripemd160(x): return hashlib.new('ripemd160',x).digest()
def sha256(x): return hashlib.sha256(x).digest()
def hash160(x): return ripemd160(sha256(x))
def hash256(x): return sha256(sha256(x))
def path(fpr_hex, *idx): return bytes.fromhex(fpr_hex)+b''.join(i.to_bytes(4,'little') for i in idx)
H=0x80000000
def b58(b):
    A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n=int.from_bytes(b,'big'); s=''
    while n: n,r=divmod(n,58); s=A[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\0')))+s
def b58dec(s):
    A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n=0
    for c in s: n=n*58+A.index(c)
    b=n.to_bytes((n.bit_length()+7)//8,'big')
    return b'\0'*(len(s)-len(s.lstrip('1')))+b

def decodepsbt(psbt):
    return subprocess.run(CLI + ["decodepsbt", psbt], check=True, capture_output=True, text=True).stdout.strip()

def maps(name):
    c = BASE[name]
    return parse(c["psbt"], len(c["core"]["inputs"]), len(c["core"]["outputs"]))

def prop(ident, sub, key):
    return b"\xfc" + cs(len(ident)) + ident + cs(sub) + key

def xpub(s):
    raw = b58dec(s)
    assert sha256(sha256(raw[:-4]))[:4] == raw[-4:] and len(raw) == 82
    return raw[:-4]

TPUB = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"
TPUB2 = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
# Three keys from the base corpus's derivations.
PK = sorted({bytes.fromhex(b["pubkey"]) for c in BASE.values() for i in c["core"]["inputs"]
             for b in i.get("bip32_derivs", [])})[:3]
X = [p[1:] for p in PK]
LEAF_SCRIPT = bytes([0x20]) + X[0] + bytes([0xac])
LEAF_HASH = sha256(b"leaf")

def all_fields(g, ins, outs):
    g.append((b"\x01" + xpub(TPUB), path("d34db33f", 44 | H, 1 | H, 0 | H)))
    g.append((prop(b"satd", 1, b"\x01\x02"), b"\xab\xcd"))
    g.append((b"\x0b\x42", b"\x99"))
    i = ins[0]
    i.append((b"\x03", (0x83).to_bytes(4, "little")))
    pre = b"satd preimage"
    for t, f in ((0x0a, ripemd160), (0x0b, sha256), (0x0c, hash160), (0x0d, hash256)):
        i.append((bytes([t]) + f(pre), pre))
    i.append((b"\x13", bytes(range(64))))
    i.append((b"\x14" + X[1] + LEAF_HASH, bytes(range(1, 65)) + b"\x81"))
    i.append((b"\x15" + b"\xc0" + X[0], LEAF_SCRIPT + b"\xc0"))
    i.append((b"\x16" + X[2], cs(1) + LEAF_HASH + path("a1b2c3d4", 86 | H, 1 | H, 0 | H, 0, 5)))
    i.append((b"\x17", X[0]))
    i.append((b"\x18", sha256(b"root")))
    i.append((b"\x1a" + PK[0], PK[1] + PK[2]))
    i.append((b"\x1b" + PK[1] + PK[0], bytes(range(66))))
    i.append((b"\x1b" + PK[2] + PK[0] + LEAF_HASH, bytes(range(2, 68))))
    i.append((b"\x1c" + PK[1] + PK[0], bytes(range(3, 35))))
    i.append((prop(b"satd", 2, b""), b"\x01"))
    i.append((b"\x40\x01", b"\x02"))
    o = outs[0]
    o.append((b"\x02" + PK[1], path("0badf00d", 84 | H, 1 | H, 0 | H, 1, 2)))
    o.append((b"\x05", X[1]))
    o.append((b"\x06", bytes([0, 0xc0]) + cs(len(LEAF_SCRIPT)) + LEAF_SCRIPT))
    o.append((b"\x07" + X[1], cs(0) + path("0badf00d", 86 | H, 1 | H, 0 | H, 1, 3)))
    o.append((b"\x08" + PK[0], PK[1] + PK[2]))
    o.append((prop(b"satd", 3, b"\x07"), b""))
    o.append((b"\x40\x02", b"\x03"))

def negative_fee_and_order(g, ins, outs):
    # The witness_utxo is worth 0.5 BTC, less than the 0.9999 BTC output.
    ins[0] = [(k, (50_000_000).to_bytes(8, "little") + v[8:]) if k == b"\x01" else (k, v) for k, v in ins[0]]
    # Xpubs and proprietary pairs listed out of Core's order.
    g.append((b"\x01" + xpub(TPUB), path("ffffffff", 1)))
    g.append((b"\x01" + xpub(TPUB2), path("00000001", 2, 3)))
    # One fingerprint, paths m/0/0 and m/1: Core's KeyOriginInfo orders a
    # shorter path first.
    g.append((b"\x01" + xpub(TPUB)[:45] + PK[0], path("00000002", 0, 0)))
    g.append((b"\x01" + xpub(TPUB)[:45] + PK[1], path("00000002", 1)))
    g.append((prop(b"zz", 5, b""), b"\x01"))
    g.append((prop(b"aa", 9, b"\x01"), b"\x02"))
    g.append((prop(b"aa", 1, b"\x02"), b"\x03"))

def sighash(value):
    def add(g, ins, outs):
        ins[0].append((b"\x03", value.to_bytes(4, "little")))
    return add

CASES = [
    ("EXTRA_all_fields", "WPKH_1_updated", all_fields),
    ("EXTRA_negative_fee_and_order", "TR_1_updated", negative_fee_and_order),
    ("EXTRA_sighash_default", "MS_0_created", sighash(0x00)),
    ("EXTRA_sighash_unknown", "MS_0_created", sighash(0x1234)),
]

rows = []
for v in ("v0", "v2"):
    for name, base, craft in CASES:
        g, ins, outs = maps(f"{v}_{base}")
        craft(g, ins, outs)
        psbt = ser(g, ins, outs)
        rows.append(f' "{v}_{name}": {{\n  "psbt": {json.dumps(psbt)},\n  "core": {decodepsbt(psbt)}\n }}')
print('{\n "bitcoin_core": "v32.1",\n "network": "regtest",\n "decodepsbt": {\n' + ",\n".join(rows) + "\n }\n}")
