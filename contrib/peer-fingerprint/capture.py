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
ping, getheaders from genesis, getdata for a random txid (MSG_WITNESS_TX), and an unknown
message type. The unknown message goes last, since a peer may disconnect
on it.

With --v2 the recorder speaks BIP324 v2, using the pure-Python
implementation in Bitcoin Core's functional test framework
(--core-functional names Core's test/functional directory): it dials with
v2, and when listening it answers in whichever transport the peer opens
with. Without --v2 it speaks v1 only: a peer that opens with a v2
handshake is recorded as a v2 attempt and the connection closed; in --listen mode the recorder then
waits --v1-retry-wait seconds for the peer's v1 retry. A peer that never
retries gets a fixture with "v1_after_v2": false and no transcript, which is
all a v1-only node learns from it.

--crawl (with --dial) greets the node as an optional crawl mode would
instead: a declared crawler that asks for addresses and nothing else.

    - at once: version, wtxidrelay
    - on the peer's version: sendaddrv2, verack
    - nothing else unsolicited

The version message carries protocol 70016, services 0, relay=0,
start_height = the node's real tip (--start-height), a random nonce, a
dummy addr_from, and the user agent /satd:<version>(crawler)/, with the
version read from the workspace Cargo.toml (--crawl-version overrides).
After the handshake and the --wait window it sends one getaddr and waits
up to --getaddr-wait seconds (default 90) for the answer, then runs the
probes. The answer is summarised, never kept: message kind, entry count,
delay, networks, service bits, whether the node lists itself, and the
spread of the entries' nTime. With --v2 it also records the node's BIP324
transport (garbage length, decoy packets, its version packet, short or
12-byte message IDs), and when the v2 attempt fails, how it failed
(reset, end of stream or timeout, how many bytes came back first) before
it redials over v1, as a crawler falls back.

The fixture holds commands, sizes, timings and decoded fields. It never
holds an address: the version message's address fields and nonce are
dropped, and addr/addrv2 bodies are reduced to a count (in --crawl, to
the summary above).

No third-party dependencies.
"""
import argparse, hashlib, io, json, os, random, socket, struct, sys, time

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
CRAWL_SERVICES = 0
CRAWL_GREETING = "crawl"
NET_IDS = {1: "ipv4", 2: "ipv6", 3: "torv2", 4: "torv3", 5: "i2p", 6: "cjdns"}
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


class V2Conn:
    """BIP324 transport over a socket, using the pure-Python implementation
    in Bitcoin Core's functional test framework (--core-functional). Same
    interface as Conn: send(command, payload) and recv(deadline)."""

    def __init__(self, sock, network, initiating, prefix=b"", record=False):
        from test_framework.v2_p2p import EncryptedP2PState, SHORTID, MSGTYPE_TO_SHORTID
        self.sock = sock
        self.buf = prefix
        self.shortid = SHORTID
        self.to_shortid = MSGTYPE_TO_SHORTID
        self.state = EncryptedP2PState(initiating=initiating, net=network)
        # --crawl: what the peer does inside the transport, and, when the
        # handshake fails, how (see v2_failure()).
        self.record = record
        self.raw_in = len(prefix)
        self.raw_head = prefix[:24]
        self.fail_kind = None
        self.transport = None
        self.decoys_after = 0
        self.ids = {"short": 0, "long": 0}
        self.last_id = None

    def _more(self, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            self.fail_kind = "timeout"
            raise TimeoutError
        self.sock.settimeout(left)
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            self.fail_kind = "timeout"
            raise TimeoutError
        except (ConnectionResetError, BrokenPipeError):
            self.fail_kind = "reset"
            raise Closed
        if not chunk:
            self.fail_kind = "eof"
            raise Closed
        if len(self.raw_head) < 24:
            self.raw_head += chunk[:24 - len(self.raw_head)]
        self.raw_in += len(chunk)
        self.buf += chunk

    def _need(self, n, deadline):
        while len(self.buf) < n:
            self._more(deadline)

    def handshake(self, deadline):
        """Run the BIP324 handshake. A responder is built with the bytes
        already read (fewer than 16, or 16 that are not a v1 version
        header)."""
        st = self.state
        if st.initiating:
            self.sock.sendall(st.initiate_v2_handshake())
        else:
            used, ours = st.respond_v2_handshake(io.BytesIO(self.buf))
            if ours == -1 or ours == b"":
                raise ValueError("responder called without a v2 prefix")
            self.buf = self.buf[used:]
            self.sock.sendall(ours)
        need = 64 - len(st.received_prefix)
        self._need(need, deadline)
        used, out = st.complete_handshake(io.BytesIO(self.buf[:need]))
        self.buf = self.buf[used:]
        self.sock.sendall(out)
        if self.record:
            self._authenticate_recording(deadline)
            return
        while not st.tried_v2_handshake:
            try:
                used, ok = st.authenticate_handshake(self.buf)
            except AssertionError:
                raise ValueError("peer's v2 version packet is not empty")
            if not ok:
                raise ValueError("v2 handshake failed to authenticate")
            self.buf = self.buf[used:]
            if not st.tried_v2_handshake:
                self._more(deadline)

    def _authenticate_recording(self, deadline):
        """The peer's garbage, decoys and version packet, recorded as they
        are authenticated: what authenticate_handshake() does, keeping
        what it skips. BIP324 lets the version packet carry contents a
        receiver ignores, so a non-empty one is recorded, not refused."""
        from test_framework.v2_p2p import MAX_GARBAGE_LEN
        st = self.state
        term = st.peer["recv_garbage_terminator"]
        while True:
            at = self.buf.find(term)
            if 0 <= at <= MAX_GARBAGE_LEN:
                break
            if len(self.buf) >= MAX_GARBAGE_LEN + len(term):
                raise ValueError("no garbage terminator within 4095 bytes of garbage")
            self._more(deadline)
        aad = self.buf[:at]
        info = {"garbage_len": at, "decoys_before_version": []}
        self.buf = self.buf[at + len(term):]
        while True:
            used, contents = st.v2_receive_packet(self.buf, aad=aad)
            if used == -1:
                raise ValueError("v2 handshake failed to authenticate")
            if used == 0:
                self._more(deadline)
                continue
            self.buf = self.buf[used:]
            aad = b""
            if contents is None:
                # 3-byte length, 1-byte header, 16-byte tag around the contents
                info["decoys_before_version"].append(used - 20)
                continue
            info["version_packet_len"] = len(contents)
            info["version_packet_hex"] = contents[:64].hex()
            break
        st.tried_v2_handshake = True
        self.transport = info

    def transport_summary(self):
        if self.transport is None:
            return None
        return dict(self.transport, decoys_after_handshake=self.decoys_after, message_ids=dict(self.ids))

    def v2_failure(self, error, started):
        """How a v2 attempt failed, as a v1-only node fails it: by reset,
        end of stream or timeout, and what it sent back first (a byte
        count, and whether it looks like a v1 message; never the bytes)."""
        head = self.raw_head
        out = {"kind": self.fail_kind or type(error).__name__, "after_ms": int((time.monotonic() - started) * 1000),
               "bytes_returned": self.raw_in, "error": f"{type(error).__name__} {error}".strip()}
        if len(head) >= 4:
            out["v1_magic_returned"] = head[:4] == self.state_magic()
            if out["v1_magic_returned"] and len(head) >= 16:
                out["v1_command_returned"] = head[4:16].rstrip(b"\x00").decode(errors="replace")
        return out

    def state_magic(self):
        from test_framework.v2_p2p import MAGIC_BYTES
        return MAGIC_BYTES[self.state.net]

    def send(self, command, payload=b""):
        sid = self.to_shortid.get(command.encode())
        head = bytes([sid]) if sid else b"\x00" + command.encode().ljust(12, b"\x00")
        self.sock.sendall(self.state.v2_enc_packet(head + payload))

    def recv(self, deadline):
        while True:
            used, contents = self.state.v2_receive_packet(self.buf)
            if used == -1:
                raise ValueError("v2 packet failed to authenticate")
            if used == 0:
                self._more(deadline)
                continue
            self.buf = self.buf[used:]
            if contents is None:
                self.decoys_after += 1
                continue  # decoy
            if not contents:
                raise ValueError("empty v2 packet")
            if contents[0] == 0:
                self.ids["long"] += 1
                self.last_id = "long"
                return contents[1:13].rstrip(b"\x00").decode(errors="replace"), contents[13:]
            self.ids["short"] += 1
            self.last_id = "short"
            name = self.shortid.get(contents[0])
            return (name.decode() if name else f"shortid-{contents[0]}"), contents[1:]


def version_payload():
    addr = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", 0)
    p = struct.pack("<iQq", PROTOCOL_VERSION, OUR_SERVICES, int(time.time()))
    p += addr + addr + struct.pack("<Q", random.getrandbits(64))
    ua = USER_AGENT.encode()
    p += csize_write(len(ua)) + ua
    p += struct.pack("<i", 0) + b"\x01"
    return p


def ip16(host):
    """The 16-byte form of an IPv4 or IPv6 address, as addr and version carry it."""
    try:
        return b"\x00" * 10 + b"\xff\xff" + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        return socket.inet_pton(socket.AF_INET6, host)


def crawl_version_payload(args):
    """--crawl: services 0, relay 0, the node's real tip, a random nonce,
    the dialed address in addr_recv (services 0) and a dummy addr_from,
    as satd builds its version message."""
    host, port = args.dial.rsplit(":", 1)
    recv = struct.pack("<Q", 0) + ip16(host.strip("[]")) + struct.pack(">H", int(port))
    dummy = struct.pack("<Q", CRAWL_SERVICES) + bytes(16) + struct.pack(">H", 0)
    p = struct.pack("<iQq", PROTOCOL_VERSION, CRAWL_SERVICES, int(time.time()))
    p += recv + dummy + struct.pack("<Q", random.getrandbits(64))
    ua = crawl_user_agent(args).encode()
    p += csize_write(len(ua)) + ua
    p += struct.pack("<i", args.start_height) + b"\x00"
    return p


def crawl_user_agent(args):
    return f"/satd:{args.crawl_version}(crawler)/"


def workspace_version():
    """satd's version from the workspace Cargo.toml, as its user agent carries it."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Cargo.toml")
    try:
        with open(path) as f:
            section = None
            for line in f:
                line = line.strip()
                if line.startswith("["):
                    section = line
                elif section == "[workspace.package]" and line.startswith("version"):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return None


def addr_entries(command, p):
    """(nTime, services, network, ip bytes, port) for each entry of an addr
    or addrv2 body. Used only for summary numbers; nothing here is kept."""
    count, off = csize_read(p, 0)
    out = []
    for _ in range(count):
        if command == "addr":
            if off + 30 > len(p):
                break
            t, services = struct.unpack_from("<IQ", p, off)
            ip = p[off + 12:off + 28]
            port = struct.unpack_from(">H", p, off + 28)[0]
            net = "ipv4" if ip[:12] == b"\x00" * 10 + b"\xff\xff" else "ipv6"
            off += 30
        else:
            t = struct.unpack_from("<I", p, off)[0]
            services, off = csize_read(p, off + 4)
            netid = p[off]
            n, off = csize_read(p, off + 1)
            ip = p[off:off + n]
            off += n
            port = struct.unpack_from(">H", p, off)[0]
            off += 2
            net = NET_IDS.get(netid, f"net-{netid}")
            if net == "ipv4":
                ip = b"\x00" * 10 + b"\xff\xff" + ip
        out.append((t, services, net, ip, port))
    return count, out


def summarize_addr(command, p, target, delay_ms):
    """A getaddr answer as summary numbers, never addresses: kind, count,
    delay, networks, service bits, whether the node lists itself, and how
    old its entries' nTime are."""
    try:
        count, entries = addr_entries(command, p)
    except (struct.error, IndexError):
        return {"kind": command, "count": None, "delay_ms": delay_ms, "undecodable": True}
    now = int(time.time())
    ages = sorted(now - e[0] for e in entries)
    nets, services = {}, {}
    for e in entries:
        nets[e[2]] = nets.get(e[2], 0) + 1
        k = f"{e[1]:x}"
        services[k] = services.get(k, 0) + 1
    out = {"kind": command, "count": count, "delay_ms": delay_ms, "networks": nets,
           "services_hex": services, "lists_itself": any((e[3], e[4]) == target for e in entries)}
    if ages:
        out["ntime_age_s"] = {"min": ages[0], "median": ages[len(ages) // 2], "max": ages[-1],
                              "spread": ages[-1] - ages[0], "future": sum(1 for a in ages if a < 0)}
    return out


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
        self.probes = []
        self.target = None  # --crawl: the dialed (ip16, port), to tell whether the node lists itself
        self.getaddr = None
        self.getaddr_sent_ms = None
        self.addr_after_getaddr = []

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
        if self.args.crawl and getattr(self.conn, "last_id", None):
            entry["v2_id"] = self.conn.last_id
        self.received.append(entry)
        if self.args.crawl and command in ("addr", "addrv2") and self.getaddr_sent_ms is not None:
            delay = entry["t_ms"] - self.getaddr_sent_ms
            summary = summarize_addr(command, payload, self.target, delay)
            self.addr_after_getaddr.append({"kind": command, "count": summary["count"], "delay_ms": delay,
                                            "phase": self.phase})
            # The answer, as bitnodes takes it: the first addr with more
            # than one entry (a lone entry is usually a self-announcement).
            if self.getaddr is None and (summary["count"] or 0) > 1:
                self.getaddr = summary
                entry["getaddr_answer"] = True
        dialer = self.args.dial is not None
        if self.args.crawl:
            if command == "version" and not self.peer_version_seen:
                self.peer_version_seen = True
                self.send("sendaddrv2")
                self.send("verack")
            elif command == "verack":
                self.peer_verack_seen = True
            elif command == "ping":
                self.send("pong", payload[:8])
            elif command == "getheaders":
                self.send("headers", csize_write(0))
            return entry
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
            self.send("version", crawl_version_payload(self.args) if self.args.crawl else version_payload())
            self.send("wtxidrelay")
        hs_deadline = time.monotonic() + 30
        while not (self.peer_version_seen and self.peer_verack_seen):
            if self.pump(hs_deadline, lambda e: self.peer_version_seen and self.peer_verack_seen) is None:
                raise RuntimeError("handshake did not complete in 30 s")
        self.phase = "passive"
        self.pump(time.monotonic() + self.args.wait)
        if self.args.crawl:
            # One getaddr once the handshake has settled; wait for the
            # answer, which rides the address trickle (Core: about 30 s on
            # average), and stop as soon as it is in.
            self.phase = "getaddr"
            self.getaddr_sent_ms = self.ms()
            self.send("getaddr")
            self.pump(time.monotonic() + self.args.getaddr_wait, lambda e: e.get("getaddr_answer", False))
        probes = self.probes  # kept on self, so a failure mid-probe keeps what ran
        if self.args.probes:
            self.phase = "probe"
            unknown = self.args.unknown_command
            plan = [
                ("ping", "ping", struct.pack("<Q", random.getrandbits(64)), "pong"),
                ("getheaders", "getheaders", self.getheaders_payload(), "headers"),
                # MSG_WITNESS_TX: a txid the peer cannot have.
                ("getdata_unknown_tx", "getdata",
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
    } if not args.crawl else {
        "capture_format": CAPTURE_FORMAT,
        "shape": "crawl",
        "label": args.label,
        "implementation": args.implementation,
        "implementation_version": args.implementation_version,
        "network": args.network,
        "connection": connection,
        "peer_state": {"ibd": args.peer_ibd, "height": args.peer_height, "note": args.peer_note},
        "recorder": {"greeting": CRAWL_GREETING, "protocol_version": PROTOCOL_VERSION, "services": CRAWL_SERVICES,
                     "relay": False, "start_height": args.start_height, "user_agent": crawl_user_agent(args),
                     "passive_wait_s": args.wait, "getaddr_wait_s": args.getaddr_wait,
                     "probe_wait_s": args.probe_wait if args.probes else None},
    }


def no_v1_result(args, v2_attempts):
    d = fixture_head(args, "inbound", v2_attempts)
    d.update({"transport": None, "v1_after_v2": False, "version": None, "commands": [], "received": [], "sent": [],
              "probes": [], "closed_by_peer": None, "error": None})
    return d


def v1_prefix(args):
    return bytes.fromhex(MAGIC[args.network]) + b"version".ljust(12, b"\x00")


def accept_v2(args, srv):
    """--v2 listen: accept one connection and speak whichever transport the
    peer opens with, as satd does."""
    sock, _ = srv.accept()
    try:
        deadline = time.monotonic() + 30
        buf = b""
        prefix = v1_prefix(args)
        while len(buf) < 16 and buf == prefix[:len(buf)]:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            chunk = sock.recv(16 - len(buf))
            if not chunk:
                raise Closed
            buf += chunk
        if buf == prefix:
            conn = Conn(sock, bytes.fromhex(MAGIC[args.network]))
            conn.buf, conn.first = buf, False
            return sock, conn, "v1"
        conn = V2Conn(sock, args.network, initiating=False, prefix=buf)
        conn.handshake(deadline)
        return sock, conn, "v2"
    except (Closed, TimeoutError, ValueError, AssertionError, OSError) as e:
        # Neither a v1 version nor a v2 handshake that completes: a
        # fixture that says so, not a crashed recorder.
        sock.close()
        raise HandshakeFailed(f"{type(e).__name__} {e}".strip())


class HandshakeFailed(Exception):
    pass


def capture(args, srv=None):
    magic = bytes.fromhex(MAGIC[args.network])
    v2_attempts = 0
    transport = "v1"
    v2_failure = None
    if args.v2:
        sys.path.insert(0, args.core_functional)
    if args.crawl:
        # v2 first, then v1 if the v2 attempt fails, as a crawler dials.
        host, port = args.dial.rsplit(":", 1)
        conn = None
        if args.v2:
            started = time.monotonic()
            sock = socket.create_connection((host, int(port)), timeout=10)
            conn = V2Conn(sock, args.network, initiating=True, record=True)
            try:
                conn.handshake(time.monotonic() + 30)
                transport = "v2"
            except (Closed, TimeoutError, ValueError, OSError) as e:
                v2_failure = conn.v2_failure(e, started)
                sock.close()
                conn = None
        if conn is None:
            sock = socket.create_connection((host, int(port)), timeout=10)
            conn = Conn(sock, magic)
        connection = "outbound"
    elif args.v2 and args.listen is not None:
        srv.settimeout(args.accept_timeout)
        try:
            sock, conn, transport = accept_v2(args, srv)
        except socket.timeout:
            sys.exit(f"no connection on port {args.listen} within {args.accept_timeout} s")
        except HandshakeFailed as e:
            d = fixture_head(args, "inbound", 0)
            d.update({"transport": None, "inbound_handshake": f"failed: {e}",
                      "version": None, "commands": [], "received": [], "sent": [], "probes": [],
                      "closed_by_peer": None, "error": f"inbound handshake failed: {e}"})
            return d
        connection = "inbound"
    elif args.v2:
        host, port = args.dial.rsplit(":", 1)
        sock = socket.create_connection((host, int(port)), timeout=10)
        conn = V2Conn(sock, args.network, initiating=True)
        try:
            conn.handshake(time.monotonic() + 30)
        except (Closed, TimeoutError, ValueError, OSError) as e:
            sock.close()
            d = fixture_head(args, "outbound", 0)
            d.update({"transport": "v2", "v2_handshake": f"failed: {type(e).__name__} {e}".strip(),
                      "version": None, "commands": [], "received": [], "sent": [], "probes": [],
                      "closed_by_peer": None, "error": None})
            return d
        transport = "v2"
        connection = "outbound"
    elif args.listen is not None:
        srv.settimeout(args.accept_timeout)
        while True:
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                if v2_attempts:
                    # The peer tried v2 and did not come back over v1: that
                    # is the whole transcript a v1-only node gets.
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
        connection = "inbound"
    else:
        host, port = args.dial.rsplit(":", 1)
        sock = socket.create_connection((host, int(port)), timeout=10)
        conn = Conn(sock, magic)
        connection = "outbound"

    rec = Recorder(conn, args)
    if args.crawl:
        host, port = args.dial.rsplit(":", 1)
        rec.target = (ip16(host.strip("[]")), int(port))
    probes = []
    error = None
    try:
        probes = rec.run()
    except Closed:
        probes = rec.probes
    except (RuntimeError, ValueError) as e:
        probes, error = rec.probes, str(e)
    except NotV1:
        probes, error = rec.probes, "peer answered with a non-v1 stream"
    except (OSError, AssertionError) as e:
        # A reset while we send, or a v2 packet Core's decoder rejects:
        # a fixture with the error and everything recorded so far.
        probes, error = rec.probes, f"{type(e).__name__} {e}".strip()
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
    if args.crawl:
        d.update({
            "transport": transport,
            "v2_attempted": bool(args.v2),
            "v2_failure": v2_failure,
            "v2_transport": conn.transport_summary() if isinstance(conn, V2Conn) else None,
            "version": version,
            "commands": handshake_cmds,
            "getaddr": rec.getaddr,
            "addr_after_getaddr": rec.addr_after_getaddr,
            "received": rec.received,
            "sent": rec.sent,
            "probes": probes,
            "closed_by_peer": rec.closed,
            "error": error,
        })
        return d
    d.update({
        "transport": transport,
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
    ap.add_argument("--v2", action="store_true",
                    help="speak BIP324 v2: dial with v2, or accept either transport when listening")
    ap.add_argument("--core-functional", metavar="DIR",
                    help="Bitcoin Core's test/functional directory; --v2 imports its test_framework.v2_p2p")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="--listen address (default 127.0.0.1; a container's gateway address to reach a node in a container)")
    ap.add_argument("--sessions", type=int, default=1,
                    help="--listen: record this many connections in turn; session N>1 goes to OUT-sN.json")
    ap.add_argument("--next-session-wait", type=float, default=20.0,
                    help="seconds to wait for each connection after the first (default 20)")
    ap.add_argument("--v1-retry-wait", type=float, default=30.0,
                    help="after a v2 attempt, how long to wait for the peer to retry over v1 (default 30)")
    ap.add_argument("--crawl", action="store_true",
                    help="with --dial: greet as a declared crawler, send one getaddr, record the answer (see above)")
    ap.add_argument("--start-height", type=int, default=0,
                    help="--crawl: start_height in our version, the node's real tip (default 0)")
    ap.add_argument("--crawl-version", default=workspace_version(),
                    help="--crawl: the version in /satd:<version>(crawler)/ (default: the workspace Cargo.toml's)")
    ap.add_argument("--getaddr-wait", type=float, default=90.0,
                    help="--crawl: seconds to wait for the getaddr answer (default 90)")
    ap.add_argument("--out", help="write the fixture here (default stdout)")
    args = ap.parse_args()
    if args.v2 and not args.core_functional:
        ap.error("--v2 needs --core-functional")
    if args.crawl and not args.dial:
        ap.error("--crawl needs --dial: a crawler only dials")
    if args.crawl and not args.crawl_version:
        ap.error("--crawl: no version in the workspace Cargo.toml; give --crawl-version")
    srv = None
    if args.listen is not None:
        # One listening socket for every session, so a peer's next
        # connection queues while the previous one is still recorded.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, args.listen))
        srv.listen(4)
    failed = False
    for n in range(1, args.sessions + 1):
        if n > 1:
            args.accept_timeout = args.next_session_wait
        try:
            result = capture(args, srv)
        except SystemExit as e:
            if n == 1:
                raise
            print(f"session {n}: none ({e})", file=sys.stderr)
            break
        result["session"] = n
        text = json.dumps(result, indent=2, sort_keys=False) + "\n"
        out = args.out
        if out and n > 1:
            base, ext = os.path.splitext(out)
            out = f"{base}-s{n}{ext}"
        if out:
            with open(out, "w") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        if result["error"]:
            print(f"capture error (session {n}): {result['error']}", file=sys.stderr)
            failed = True
    if srv:
        srv.close()
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
