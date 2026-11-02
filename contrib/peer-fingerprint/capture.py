#!/usr/bin/env python3
"""
Record what a Bitcoin P2P implementation sends during and just after the
handshake, as a JSON fixture for satd's peer fingerprint classifier.

The recorder speaks v1 P2P and plays one side of a connection to the node
under test:

  --listen PORT   wait for the node to dial us (we see an inbound peer)
  --dial H:P      dial the node (we see an outbound peer)

A peer's opening messages partly answer what it is sent, so the recorder
greets it the way satd does, as measured from satd 0.7.0 itself (the
satd fixtures in this directory). The greeting differs by direction:

  --dial (satd as the dialer):
    - at once: version, wtxidrelay
    - on the peer's version: sendaddrv2, verack
    - on the peer's verack: sendheaders, getheaders, sendcmpct(0, 2),
      feefilter(100 sat/kvB), getaddr, ping
  --listen (satd accepting):
    - on the peer's version: version, wtxidrelay, sendaddrv2, verack
    - on the peer's verack: getheaders, sendcmpct(0, 2),
      feefilter(100 sat/kvB), ping

The version message carries protocol 70016, satd's services
(NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2), relay=1 and start_height 0, and
getheaders carries protocol 70001 and a one-hash locator (genesis), as
satd's do. The recorder only answers ping (pong) and getheaders (empty
headers); getaddr gets no reply. Re-measure the greeting when satd's
changes: capture satd against a recorder and compare its sends with
GREETING below.

Whether the node under test was in initial block download is recorded
(--peer-ibd, --peer-height), since some clients announce less while
syncing and most real peers are synced. Capture a node out of IBD where it
can mine a block; where it cannot, the fixture says so.

After the handshake it waits --wait seconds (default 10) and records every
message. Unless --no-probes is given it then runs the benign probes from
the peer behavior plan, one at a time, each with a --probe-wait window:
ping, getheaders from genesis, getdata for a random wtxid, and an unknown
message type. The unknown message goes last, since a peer may disconnect
on it.

A peer that opens with a v2 (BIP324) handshake is recorded as a v2
attempt and the connection closed; in --listen mode the recorder then
waits --v1-retry-wait seconds for the peer's v1 retry. A peer that never
retries gets a fixture with "v1_after_v2": false and no transcript, which is
all a v1-only node learns from it.

The fixture holds commands, sizes, timings and decoded fields. It never
holds an address: the version message's address fields and nonce are
dropped, and addr/addrv2 bodies are reduced to a count.

No third-party dependencies.
"""
import argparse, hashlib, json, os, random, socket, struct, sys, time

MAGIC = {
    "mainnet": "f9beb4d9",
    "testnet4": "1c163f28",
    "signet": "0a03cf40",
    "regtest": "fabfb5da",
}
GENESIS = {
    "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "testnet4": "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
    "signet": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    "regtest": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
}
PROTOCOL_VERSION = 70016
OUR_SERVICES = (1 << 0) | (1 << 3) | (1 << 10) | (1 << 11)  # NETWORK | WITNESS | NETWORK_LIMITED | P2P_V2, as satd 0.7.0
GETHEADERS_VERSION = 70001  # what satd 0.7.0 puts in getheaders
FEEFILTER = 100  # sat/kvB, satd 0.7.0's default on regtest
GREETING = "satd-0.7.0"
USER_AGENT = "/satd-fingerprint-capture:1/"
MAX_MSG_LEN = 4 * 1000 * 1000 + 1000  # Core's MAX_PROTOCOL_MESSAGE_LENGTH, plus header slack
CAPTURE_FORMAT = 1
INV_TYPES = {1: "tx", 2: "block", 3: "filtered_block", 4: "cmpct_block", 5: "wtx",
             0x40000001: "witness_tx", 0x40000002: "witness_block"}


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


class Closed(Exception):
    pass


class NotV1(Exception):
    pass


class Conn:
    def __init__(self, sock, magic):
        self.sock = sock
        self.magic = magic
        self.buf = b""
        self.first = True

    def send(self, command, payload=b""):
        chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        self.sock.sendall(self.magic + command.encode().ljust(12, b"\x00")
                          + struct.pack("<I", len(payload)) + chk + payload)

    def _fill(self, n, deadline):
        while len(self.buf) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise TimeoutError
            except (ConnectionResetError, BrokenPipeError):
                raise Closed
            if not chunk:
                raise Closed
            self.buf += chunk
            if self.first and len(self.buf) >= 4:
                self.first = False
                if self.buf[:4] != self.magic:
                    raise NotV1

    def recv(self, deadline):
        """Next (command, payload), TimeoutError at the deadline, Closed on EOF."""
        self._fill(24, deadline)
        hdr = self.buf[:24]
        if hdr[:4] != self.magic:
            raise ValueError("bad magic mid-stream")
        command = hdr[4:16].rstrip(b"\x00").decode(errors="replace")
        length = struct.unpack_from("<I", hdr, 16)[0]
        if length > MAX_MSG_LEN:
            raise ValueError(f"oversize message: {length}")
        self._fill(24 + length, deadline)
        payload = self.buf[24:24 + length]
        self.buf = self.buf[24 + length:]
        return command, payload


def version_payload():
    addr = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", 0)
    p = struct.pack("<iQq", PROTOCOL_VERSION, OUR_SERVICES, int(time.time()))
    p += addr + addr + struct.pack("<Q", random.getrandbits(64))
    ua = USER_AGENT.encode()
    p += csize_write(len(ua)) + ua
    p += struct.pack("<i", 0) + b"\x01"
    return p


def decode_version(p):
    ver, services, ts = struct.unpack_from("<iQq", p, 0)
    out = {"protocol_version": ver, "services": services,
           "services_hex": f"{services:016x}"}
    off = 20 + 26  # addr_recv
    if len(p) >= off + 26 + 8:
        off += 26 + 8  # addr_from, nonce
        ualen, off = csize_read(p, off)
        out["user_agent"] = p[off:off + ualen].decode(errors="replace"); off += ualen
        if len(p) >= off + 4:
            out["start_height"] = struct.unpack_from("<i", p, off)[0]; off += 4
        if len(p) > off:
            out["relay"] = bool(p[off]); off += 1
        out["trailing_bytes"] = len(p) - off
    out["timestamp_skew_s"] = int(ts - time.time())
    return out


def decode_invlike(p):
    count, off = csize_read(p, 0)
    kinds = {}
    for _ in range(count):
        if off + 36 > len(p):
            break
        t = struct.unpack_from("<I", p, off)[0]
        name = INV_TYPES.get(t, f"0x{t:x}")
        kinds[name] = kinds.get(name, 0) + 1
        off += 36
    return {"count": count, "types": kinds}


def decode(command, p):
    try:
        if command == "version":
            return decode_version(p)
        if command == "sendcmpct" and len(p) >= 9:
            return {"announce": bool(p[0]), "cmpct_version": struct.unpack_from("<Q", p, 1)[0]}
        if command == "feefilter" and len(p) >= 8:
            return {"feerate": struct.unpack_from("<q", p, 0)[0]}
        if command in ("ping", "pong"):
            return {"has_nonce": len(p) >= 8}
        if command in ("getheaders", "getblocks"):
            ver = struct.unpack_from("<I", p, 0)[0]
            n, off = csize_read(p, 4)
            stop = p[off + 32 * n: off + 32 * n + 32]
            return {"version": ver, "locator_len": n, "stop_zero": stop == bytes(32)}
        if command == "headers":
            return {"count": csize_read(p, 0)[0]}
        if command in ("inv", "getdata", "notfound"):
            return decode_invlike(p)
        if command in ("addr", "addrv2"):
            return {"count": csize_read(p, 0)[0]}
        if command == "sendtxrcncl" and len(p) >= 4:
            return {"txrcncl_version": struct.unpack_from("<I", p, 0)[0]}
        if command == "reject":
            n, off = csize_read(p, 0)
            msg = p[off:off + n].decode(errors="replace"); off += n
            code = p[off] if off < len(p) else None
            off += 1
            n2, off = csize_read(p, off) if off < len(p) else (0, off)
            return {"message": msg, "code": code, "reason": p[off:off + n2].decode(errors="replace")}
    except (struct.error, IndexError):
        return {"undecodable": True}
    return None


class Recorder:
    def __init__(self, conn, args):
        self.conn = conn
        self.args = args
        self.t0 = time.monotonic()
        self.received = []
        self.sent = []
        self.phase = "handshake"
        self.peer_version_seen = False
        self.peer_verack_seen = False
        self.closed = None

    def ms(self):
        return int((time.monotonic() - self.t0) * 1000)

    def send(self, command, payload=b""):
        self.conn.send(command, payload)
        self.sent.append({"t_ms": self.ms(), "phase": self.phase, "command": command})

    def getheaders_payload(self):
        genesis = bytes.fromhex(GENESIS[self.args.network])[::-1]
        return struct.pack("<I", GETHEADERS_VERSION) + csize_write(1) + genesis + bytes(32)

    def on_message(self, command, payload):
        entry = {"t_ms": self.ms(), "phase": self.phase, "command": command, "len": len(payload)}
        fields = decode(command, payload)
        if fields is not None:
            entry["fields"] = fields
        self.received.append(entry)
        dialer = self.args.dial is not None
        if command == "version" and not self.peer_version_seen:
            self.peer_version_seen = True
            if not dialer:
                self.send("version", version_payload())
                self.send("wtxidrelay")
            self.send("sendaddrv2")
            self.send("verack")
        elif command == "verack" and not self.peer_verack_seen:
            self.peer_verack_seen = True
            if dialer:
                self.send("sendheaders")
            self.send("getheaders", self.getheaders_payload())
            self.send("sendcmpct", b"\x00" + struct.pack("<Q", 2))
            self.send("feefilter", struct.pack("<q", FEEFILTER))
            if dialer:
                self.send("getaddr")
            self.send("ping", struct.pack("<Q", random.getrandbits(64)))
        elif command == "ping":
            self.send("pong", payload[:8])
        elif command == "getheaders":
            self.send("headers", csize_write(0))
        return entry

    def pump(self, until, stop_when=None):
        """Read and record messages until the deadline; stop early when
        stop_when(entry) is true. Returns the matching entry or None."""
        while True:
            try:
                command, payload = self.conn.recv(until)
            except TimeoutError:
                return None
            except Closed:
                self.closed = {"t_ms": self.ms(), "phase": self.phase}
                raise
            entry = self.on_message(command, payload)
            if stop_when and stop_when(entry):
                return entry

    def run(self):
        if self.args.dial:
            self.send("version", version_payload())
            self.send("wtxidrelay")
        hs_deadline = time.monotonic() + 30
        while not (self.peer_version_seen and self.peer_verack_seen):
            if self.pump(hs_deadline, lambda e: self.peer_version_seen and self.peer_verack_seen) is None:
                raise RuntimeError("handshake did not complete in 30 s")
        self.phase = "passive"
        self.pump(time.monotonic() + self.args.wait)
        probes = []
        if self.args.probes:
            self.phase = "probe"
            unknown = self.args.unknown_command
            plan = [
                ("ping", "ping", struct.pack("<Q", random.getrandbits(64)), "pong"),
                ("getheaders", "getheaders", self.getheaders_payload(), "headers"),
                ("getdata_unknown_wtx", "getdata",
                 csize_write(1) + struct.pack("<I", 0x40000001) + os.urandom(32), "notfound"),
                ("unknown_message", unknown, b"", None),
            ]
            for name, command, payload, expect in plan:
                start = len(self.received)
                sent_at = self.ms()
                self.send(command, payload)
                result = {"probe": name, "command": command, "expect": expect}
                try:
                    hit = self.pump(time.monotonic() + self.args.probe_wait,
                                    (lambda e, x=expect: e["command"] == x) if expect else None)
                except Closed:
                    result["disconnected"] = True
                    result["replies"] = [e["command"] for e in self.received[start:]]
                    probes.append(result)
                    break
                result["disconnected"] = False
                result["replies"] = [e["command"] for e in self.received[start:]]
                result["answered"] = hit is not None
                if hit is not None:
                    result["latency_ms"] = hit["t_ms"] - sent_at
                    if "fields" in hit:
                        result["reply_fields"] = hit["fields"]
                probes.append(result)
        return probes


def fixture_head(args, connection, v2_attempts):
    return {
        "capture_format": CAPTURE_FORMAT,
        "label": args.label,
        "implementation": args.implementation,
        "implementation_version": args.implementation_version,
        "network": args.network,
        "connection": connection,
        "peer_state": {"ibd": args.peer_ibd, "height": args.peer_height, "note": args.peer_note},
        "recorder": {"greeting": GREETING, "protocol_version": PROTOCOL_VERSION, "services": OUR_SERVICES,
                     "user_agent": USER_AGENT, "passive_wait_s": args.wait,
                     "probe_wait_s": args.probe_wait if args.probes else None},
        "v2_attempts_before_v1": v2_attempts,
    }


def no_v1_result(args, v2_attempts):
    d = fixture_head(args, "inbound", v2_attempts)
    d.update({"v1_after_v2": False, "version": None, "commands": [], "received": [], "sent": [],
              "probes": [], "closed_by_peer": None, "error": None})
    return d


def capture(args):
    magic = bytes.fromhex(MAGIC[args.network])
    v2_attempts = 0
    if args.listen is not None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", args.listen))
        srv.listen(4)
        srv.settimeout(args.accept_timeout)
        while True:
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                if v2_attempts:
                    # The peer tried v2 and did not come back over v1: that
                    # is the whole transcript a v1-only node gets.
                    srv.close()
                    return no_v1_result(args, v2_attempts)
                sys.exit(f"no connection on port {args.listen} within {args.accept_timeout} s")
            conn = Conn(sock, magic)
            try:
                conn._fill(4, time.monotonic() + 30)
                break
            except NotV1:
                v2_attempts += 1
                sock.close()
                srv.settimeout(args.v1_retry_wait)
                if v2_attempts > 2:
                    sys.exit("peer kept opening non-v1 connections")
            except (Closed, TimeoutError):
                sock.close()
        srv.close()
        connection = "inbound"
    else:
        host, port = args.dial.rsplit(":", 1)
        sock = socket.create_connection((host, int(port)), timeout=10)
        conn = Conn(sock, magic)
        connection = "outbound"

    rec = Recorder(conn, args)
    probes = []
    error = None
    try:
        probes = rec.run()
    except Closed:
        pass
    except (RuntimeError, ValueError) as e:
        error = str(e)
    except NotV1:
        error = "peer answered with a non-v1 stream"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    version = next((m.get("fields") for m in rec.received if m["command"] == "version"), None)
    handshake_cmds = []
    for m in rec.received:
        if m["phase"] != "handshake" and m["phase"] != "passive":
            break
        handshake_cmds.append(m["command"])
    d = fixture_head(args, connection, v2_attempts)
    d.update({
        "v1_after_v2": True if v2_attempts else None,
        "version": version,
        "commands": handshake_cmds,
        "received": rec.received,
        "sent": rec.sent,
        "probes": probes,
        "closed_by_peer": rec.closed,
        "error": error,
    })
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    side = ap.add_mutually_exclusive_group(required=True)
    side.add_argument("--listen", type=int, metavar="PORT", help="wait on 127.0.0.1:PORT for the node to dial in")
    side.add_argument("--dial", metavar="HOST:PORT", help="dial the node")
    ap.add_argument("--network", choices=sorted(MAGIC), default="regtest")
    ap.add_argument("--label", required=True, help="fixture label, e.g. core-31.2")
    ap.add_argument("--implementation", required=True, help="family, e.g. core, btcd")
    ap.add_argument("--implementation-version", required=True)
    ap.add_argument("--peer-ibd", required=True, choices=["yes", "no", "unknown"],
                    help="whether the node under test was in initial block download (its own RPC says)")
    ap.add_argument("--peer-height", type=int, required=True, help="the node's block height when captured")
    ap.add_argument("--peer-note", default="", help="free text, e.g. how the node left IBD")
    ap.add_argument("--wait", type=float, default=10.0, help="passive seconds after the handshake (default 10)")
    ap.add_argument("--no-probes", dest="probes", action="store_false")
    ap.add_argument("--probe-wait", type=float, default=5.0, help="seconds to wait for each probe's answer (default 5)")
    ap.add_argument("--unknown-command", default="fpprobe", help="command name for the unknown-message probe")
    ap.add_argument("--accept-timeout", type=float, default=120.0)
    ap.add_argument("--v1-retry-wait", type=float, default=30.0,
                    help="after a v2 attempt, how long to wait for the peer to retry over v1 (default 30)")
    ap.add_argument("--out", help="write the fixture here (default stdout)")
    args = ap.parse_args()
    result = capture(args)
    text = json.dumps(result, indent=2, sort_keys=False) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if result["error"]:
        print(f"capture error: {result['error']}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
