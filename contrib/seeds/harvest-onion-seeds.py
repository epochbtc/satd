#!/usr/bin/env python3
"""
Harvest candidate Tor v3 onion Bitcoin nodes from live addrv2 gossip, then
verify each over Tor with a real handshake. Prints the ones that are live,
mainnet, NODE_NETWORK, and near the chain tip — suitable for the satd onion
seed list.

No third-party deps: raw sockets, manual SOCKS5, BIP155 parsing.
Tor SOCKS expected at 127.0.0.1:9050.
"""
import socket, struct, hashlib, base64, time, threading, queue, random

MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
DEFAULT_PORT = 8333
SOCKS = ("127.0.0.1", 9050)
NODE_NETWORK = 1 << 0
PROTOCOL_VERSION = 70016
# Reject oversized message-length headers from untrusted peers before we try to
# read the payload — otherwise a hostile node could announce a huge length and
# make recvn() block reading megabytes (slowloris). We only need small
# version/addr/addrv2 messages here. Matches Bitcoin Core's 32 MiB ceiling.
MAX_MSG_LEN = 32 * 1024 * 1024
HARVEST_SEEDS = [
    "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoin.sprovoost.nl",
    "seed.btc.petertodd.net", "dnsseed.emzy.de", "seed.bitcoin.wiz.biz",
    "seed.mainnet.achownodes.xyz",
]

# ---------- wire helpers ----------
def csize_read(b, off):
    n = b[off]; off += 1
    if n < 0xfd: return n, off
    if n == 0xfd: return struct.unpack_from("<H", b, off)[0], off + 2
    if n == 0xfe: return struct.unpack_from("<I", b, off)[0], off + 4
    return struct.unpack_from("<Q", b, off)[0], off + 8

def csize_write(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def msg(command, payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAINNET_MAGIC + command.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload)) + chk + payload

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk: raise ConnectionError("eof")
        buf += chunk
    return buf

def recv_msg(s):
    hdr = recvn(s, 24)
    if hdr[:4] != MAINNET_MAGIC: raise ValueError("bad magic")
    command = hdr[4:16].rstrip(b"\x00").decode(errors="replace")
    length = struct.unpack_from("<I", hdr, 16)[0]
    if length > MAX_MSG_LEN: raise ValueError(f"oversize message: {length}")
    payload = recvn(s, length) if length else b""
    return command, payload

def version_payload():
    addr = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", 0)
    p = struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time()))
    p += addr + addr + struct.pack("<Q", random.getrandbits(64))
    p += csize_write(0)  # empty user agent
    p += struct.pack("<i", 0) + b"\x00"  # start_height, relay=false
    return p

def handshake(s):
    """version/sendaddrv2/verack exchange; returns peer's version dict."""
    s.sendall(msg("version", version_payload()))
    s.sendall(msg("sendaddrv2", b""))
    peer = None
    deadline = time.time() + 20
    got_verack = False
    while time.time() < deadline and not (peer and got_verack):
        command, payload = recv_msg(s)
        if command == "version":
            peer = parse_version(payload)
            s.sendall(msg("verack", b""))
        elif command == "verack":
            got_verack = True
        elif command == "ping":
            s.sendall(msg("pong", payload))
    if not peer: raise ValueError("no version")
    return peer

def parse_version(p):
    ver, services, ts = struct.unpack_from("<iQq", p, 0)
    off = 20 + 26 + 26 + 8  # to user agent
    ualen, off = csize_read(p, off)
    ua = p[off:off+ualen].decode(errors="replace"); off += ualen
    height = struct.unpack_from("<i", p, off)[0]
    return {"version": ver, "services": services, "ua": ua, "height": height}

def torv3_onion(pubkey):
    ck = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + ck + b"\x03").decode().lower() + ".onion"

def parse_addrv2(p):
    out = []
    count, off = csize_read(p, 0)
    for _ in range(count):
        off += 4  # time
        _, off = csize_read(p, off)  # services
        netid = p[off]; off += 1
        alen, off = csize_read(p, off)
        addr = p[off:off+alen]; off += alen
        port = struct.unpack_from(">H", p, off)[0]; off += 2
        if netid == 0x04 and len(addr) == 32:  # TorV3
            out.append((torv3_onion(addr), port))
    return out

# ---------- SOCKS5 ----------
def socks5_onion(host, port, timeout=15):
    s = socket.create_connection(SOCKS, timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00": raise ConnectionError("socks auth")
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    rep = recvn(s, 4)
    if rep[1] != 0x00: raise ConnectionError(f"socks reply {rep[1]}")
    # consume bound addr
    atyp = rep[3]
    if atyp == 0x01: recvn(s, 4)
    elif atyp == 0x03: recvn(s, s.recv(1)[0])
    elif atyp == 0x04: recvn(s, 16)
    recvn(s, 2)
    return s

# ---------- harvest ----------
def harvest_from(ip, collect, lock, tip):
    try:
        s = socket.create_connection((ip, DEFAULT_PORT), timeout=10)
        s.settimeout(20)
        peer = handshake(s)
        with lock:
            tip[0] = max(tip[0], peer["height"])
        s.sendall(msg("getaddr", b""))
        end = time.time() + 20
        while time.time() < end:
            try:
                command, payload = recv_msg(s)
            except Exception:
                break
            if command == "addrv2":
                for host, port in parse_addrv2(payload):
                    with lock: collect.add((host, port))
            elif command == "ping":
                s.sendall(msg("pong", payload))
        s.close()
    except Exception as e:
        print(f"  harvest {ip}: {e}")

# ---------- verify ----------
def verify_onion(host, port, tip, results):
    try:
        s = socks5_onion(host, port)
        peer = handshake(s)
        s.close()
        ok = (peer["services"] & NODE_NETWORK) and peer["version"] >= 70015 \
             and peer["height"] >= tip - 5000
        if ok:
            results.append((host, port, peer))
            print(f"  LIVE  {host}:{port}  h={peer['height']} ua={peer['ua']}")
        else:
            print(f"  skip  {host}:{port}  services={peer['services']} h={peer['height']}")
    except Exception as e:
        print(f"  dead  {host}:{port}  ({e})")

def pool(fn, items, workers=24):
    q = queue.Queue()
    for it in items: q.put(it)
    def worker():
        while True:
            try: it = q.get_nowait()
            except queue.Empty: return
            fn(*it)
            q.task_done()
    ts = [threading.Thread(target=worker) for _ in range(workers)]
    for t in ts: t.start()
    for t in ts: t.join()

def main():
    # 1. bootstrap clearnet IPs from DNS seeds
    ips = set()
    for seed in HARVEST_SEEDS:
        try:
            for info in socket.getaddrinfo(seed, DEFAULT_PORT, socket.AF_INET):
                ips.add(info[4][0])
        except Exception as e:
            print(f"resolve {seed}: {e}")
    ips = list(ips)
    print(f"[1] {len(ips)} clearnet bootstrap IPs from DNS seeds")

    # 2. harvest onion candidates from gossip
    collect, lock, tip = set(), threading.Lock(), [0]
    pool(lambda ip: harvest_from(ip, collect, lock, tip), [(ip,) for ip in ips[:40]], workers=20)
    onions = sorted(collect)
    print(f"[2] harvested {len(onions)} unique onion candidates; tip~{tip[0]}")

    # 3. verify each over Tor
    print(f"[3] verifying {len(onions)} onions over Tor (this takes a few min)...")
    results = []
    pool(lambda h, p: verify_onion(h, p, tip[0], results), onions, workers=60)

    # 4. report
    results.sort(key=lambda r: -r[2]["height"])
    print(f"\n===== {len(results)} LIVE mainnet onion nodes =====")
    for host, port, peer in results:
        print(f'    ("{host}", {port}),   // {peer["ua"]} h={peer["height"]}')

if __name__ == "__main__":
    main()
