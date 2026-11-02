#!/usr/bin/env python3
"""
Run capture.py against each implementation on regtest, in both directions
where the implementation supports them, and write one fixture per
implementation and direction.

Every implementation is configured by an environment variable naming its
binary (or checkout); an implementation whose variable is unset is skipped.

  SATD           satd binary              SATCLI         sat-cli binary
  CORE_BIN       Core's bin/ directory    KNOTS_BIN      Knots' bin/ directory
  BTCD           btcd binary
  BCOIN          bcoin checkout (bin/bcoin), run with NODE_BACKEND=js
  RBITCOIN       rbitcoin-node binary
  FLORESTAD      florestad binary
  LIBBITCOIN_BS  libbitcoin-server's bs binary
  SEEDER         bitcoin-seeder's dnsseed binary
  BITNODES       bitnodes checkout     BITNODES_PYTHON  a Python with gevent + PySocks

Each node gets a fresh datadir under --workdir and binds to 127.0.0.1 only.
A node that can mine is given one block first, so it is out of initial block
download as most real peers are; the fixture records the state the node's
own RPC reports. Crawlers have no chain: their state is recorded as unknown.

Usage: run-captures.py --workdir DIR --out DIR [--only NAME[,NAME...]]
"""
import argparse, base64, json, os, shutil, signal, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.path.join(HERE, "capture.py")
REGTEST_P2PKH = "n2qxEYSYBgrHY7i2mkzakRR674xe6di61W"  # any regtest address; nothing is ever spent
NODE_P2P, NODE_RPC, RECORDER = 19601, 19602, 19603
# accept (120) + handshake (30) + passive (10) + probes (20) + a second
# session (20 + its own handshake, passive and probes), with room to spare
CAPTURE_TIMEOUT = 420


def rpc_http(url, user, password, method, params=None, timeout=10, bearer=None):
    auth = f"Bearer {bearer}" if bearer else "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, data=json.dumps(
        {"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}).encode(),
        headers={"Content-Type": "application/json", "Authorization": auth})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.load(r)
    if body.get("error"):
        raise RuntimeError(f"{method}: {body['error']}")
    return body["result"]


def wait_for(fn, what, timeout=60):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 -- a node that is still starting fails in many ways
            last = e
            time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {what}: {last}")


class Impl:
    """One implementation: how to start it, mine, read its state, stop it."""
    family = name = version = None
    listens = dials = True
    can_mine = True
    env = ()

    def __init__(self, workdir):
        self.dir = os.path.join(workdir, self.name)
        self.proc = None

    def available(self):
        return all(os.environ.get(e) for e in self.env)

    def argv(self, connect):
        raise NotImplementedError

    def start(self, connect=None):
        os.makedirs(self.dir, exist_ok=True)
        log = open(os.path.join(self.dir, "stdout.log"), "ab")
        self.proc = subprocess.Popen(self.argv(connect), stdout=log, stderr=subprocess.STDOUT,
                                     cwd=self.dir, env=self.child_env(), start_new_session=True)

    def child_env(self):
        # Each node's HOME is its own scratch dir, so nothing it writes by
        # default (config, certificates, app data) lands in the real home.
        e = os.environ.copy()
        e["HOME"] = self.dir
        return e

    def ready(self):
        self.state()

    def mine(self):
        pass

    def state(self):
        """(ibd 'yes'|'no'|'unknown', height)"""
        return "unknown", -1

    def stop(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        self.proc = None


class CoreLike(Impl):
    family = "core"
    bin_env = None

    @property
    def env(self):
        return (self.bin_env,)

    def cli(self, *args):
        out = subprocess.run([os.path.join(os.environ[self.bin_env], "bitcoin-cli"), "-regtest",
                              f"-datadir={self.dir}", f"-rpcport={NODE_RPC}", *args],
                             capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise RuntimeError(out.stderr.strip())
        return out.stdout.strip()

    def argv(self, connect):
        a = [os.path.join(os.environ[self.bin_env], "bitcoind"), "-regtest", f"-datadir={self.dir}",
             f"-port={NODE_P2P}", f"-rpcport={NODE_RPC}", "-bind=127.0.0.1", "-listen=1",
             "-dnsseed=0", "-fixedseeds=0", "-debug=net", "-printtoconsole=0"]
        if connect:
            a.append(f"-connect={connect}")
        return a

    def mine(self):
        self.cli("generatetodescriptor", "1", "raw(51)")

    def state(self):
        info = json.loads(self.cli("getblockchaininfo"))
        return ("yes" if info["initialblockdownload"] else "no"), info["blocks"]


class Core(CoreLike):
    name, bin_env = "core", "CORE_BIN"


class Knots(CoreLike):
    name, bin_env = "knots", "KNOTS_BIN"


class Satd(Impl):
    family = name = "satd"
    env = ("SATD", "SATCLI")

    def cli(self, *args):
        out = subprocess.run([os.environ["SATCLI"], "--regtest", f"--datadir={self.dir}",
                              f"--rpcport={NODE_RPC}", *args], capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise RuntimeError(out.stderr.strip())
        return out.stdout.strip()

    def argv(self, connect):
        a = [os.environ["SATD"], "--regtest", f"--datadir={self.dir}", f"--port={NODE_P2P}",
             f"--rpcport={NODE_RPC}", "--listen=1"]
        if connect:
            a.append(f"--connect={connect}")
        return a

    def mine(self):
        self.cli("generatetoaddress", "1", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")

    def state(self):
        info = json.loads(self.cli("getblockchaininfo"))
        return ("yes" if info["initialblockdownload"] else "no"), info["blocks"]


class Btcd(Impl):
    family = name = "btcd"
    env = ("BTCD",)

    # btcd 0.27.0 forgets a block mined with `generate` on regtest when it
    # restarts, so the inbound capture asks the running node to dial instead
    # of restarting it with --connect.
    def connect_live(self, addr):
        self.rpc("node", ["connect", addr, "temp"])

    def argv(self, connect):
        conf = os.path.join(self.dir, "btcd.conf")
        open(conf, "a").close()  # or btcd tries to create ~/.btcd/btcd.conf
        a = [os.environ["BTCD"], f"--configfile={conf}", "--regtest", f"--datadir={self.dir}/data", f"--logdir={self.dir}/logs",
             f"--listen=127.0.0.1:{NODE_P2P}", f"--rpclisten=127.0.0.1:{NODE_RPC}",
             "--rpcuser=fp", "--rpcpass=fp", "--notls",
             f"--rpccert={self.dir}/rpc.cert", f"--rpckey={self.dir}/rpc.key", f"--miningaddr={REGTEST_P2PKH}", "--nodnsseed"]
        if connect:
            a.append(f"--connect={connect}")
        return a

    def rpc(self, method, params=None):
        return rpc_http(f"http://127.0.0.1:{NODE_RPC}/", "fp", "fp", method, params, timeout=60)

    def mine(self):
        self.rpc("generate", [1])

    def start(self, connect=None):
        self.home_btcd_existed = os.path.exists(os.path.expanduser("~/.btcd"))
        super().start(connect)

    def stop(self):
        super().stop()
        # btcd creates ~/.btcd from the passwd entry whatever HOME and its
        # path flags say; remove it again if it is our empty leftover.
        home_btcd = os.path.expanduser("~/.btcd")
        if not self.home_btcd_existed and os.path.isdir(home_btcd) and not os.listdir(home_btcd):
            os.rmdir(home_btcd)

    def state(self):
        info = self.rpc("getblockchaininfo")
        # btcd reports no initialblockdownload field; its sync manager's
        # "current" needs a tip under 24 h old, which a fresh block is.
        ibd = info.get("initialblockdownload")
        return ("unknown" if ibd is None else "yes" if ibd else "no"), info["blocks"]


class Bcoin(Impl):
    family = name = "bcoin"
    env = ("BCOIN",)

    def child_env(self):
        e = super().child_env()
        e["NODE_BACKEND"] = "js"  # bcrypto's pure-JS backend: no native build
        return e

    # --memory=true keeps the chain in memory, so the mined block does not
    # survive a restart: dial from the running node.
    def connect_live(self, addr):
        self.rpc("addnode", [addr, "onetry"])

    def argv(self, connect):
        a = [os.path.join(os.environ["BCOIN"], "bin", "bcoin"), "--network=regtest",
             f"--prefix={self.dir}", f"--port={NODE_P2P}", "--host=127.0.0.1", "--listen=true",
             f"--http-port={NODE_RPC}", "--http-host=127.0.0.1", "--api-key=fp", "--no-wallet", "--memory=true"]
        if connect:
            a.append(f"--only={connect}")
        return a

    def rpc(self, method, params=None):
        return rpc_http(f"http://127.0.0.1:{NODE_RPC}/", "x", "fp", method, params, timeout=60)

    def mine(self):
        self.rpc("generatetoaddress", [1, REGTEST_P2PKH])

    def state(self):
        info = self.rpc("getblockchaininfo")
        ibd = info.get("initialblockdownload")
        return ("unknown" if ibd is None else "yes" if ibd else "no"), info["blocks"]


class Rbitcoin(Impl):
    family = name = "rbitcoin"
    env = ("RBITCOIN",)

    def argv(self, connect):
        a = [os.environ["RBITCOIN"], "--network", "regtest", "--datadir", self.dir,
             "--listen", f"127.0.0.1:{NODE_P2P}", "--rpc", "--rpc-listen", f"127.0.0.1:{NODE_RPC}",
             "--no-seeds", "--no-discover"]
        if connect:
            a += ["--connect", connect]
        return a

    def rpc(self, method, params=None):
        token = open(os.path.join(self.dir, "rpc.token")).read().strip()  # rbitcoin writes a bearer token
        return rpc_http(f"http://127.0.0.1:{NODE_RPC}/", "", "", method, params, timeout=60, bearer=token)

    def mine(self):
        self.rpc("generatetoaddress", [1, REGTEST_P2PKH])

    def state(self):
        info = self.rpc("getblockchaininfo")
        ibd = info.get("initialblockdownload")
        return ("unknown" if ibd is None else "yes" if ibd else "no"), info["blocks"]


class Floresta(Impl):
    family = name = "floresta"
    env = ("FLORESTAD",)
    listens = False  # florestad makes outbound connections only
    can_mine = False

    def argv(self, connect):
        a = [os.environ["FLORESTAD"], "--network", "regtest", "--data-dir", self.dir,
             "--rpc-address", f"127.0.0.1:{NODE_RPC}", "--electrum-address", f"127.0.0.1:{NODE_RPC + 10}",
             "--allow-v1-fallback"]
        if connect:
            a += ["--connect", connect]
        return a

    def rpc(self, method, params=None):
        return rpc_http(f"http://127.0.0.1:{NODE_RPC}/", "", "", method, params)

    def state(self):
        info = self.rpc("getblockchaininfo")
        ibd = info.get("ibd", info.get("initialblockdownload"))
        return ("unknown" if ibd is None else "yes" if ibd else "no"), info.get("height", info.get("blocks", -1))


class Seeder(Impl):
    family, name = "crawler", "bitcoin-seeder"
    env = ("SEEDER",)
    listens = False
    can_mine = False

    def argv(self, connect):
        host, port = connect.rsplit(":", 1)
        return [os.environ["SEEDER"], "--nodns", "-s", host, "--p2port", port, "--magic", "fabfb5da", "-t", "1"]

    def ready(self):
        pass


class Bitnodes(Impl):
    family, name = "crawler", "bitnodes"
    env = ("BITNODES", "BITNODES_PYTHON")
    listens = False
    can_mine = False

    def argv(self, connect):
        host, port = connect.rsplit(":", 1)
        # crawl.py's connect() and getaddr() with crawl.conf.default's
        # values, minus Redis: version, handshake, getaddr, wait for addr.
        code = f"""
import sys, socket; sys.path.insert(0, {os.environ['BITNODES']!r})
import gevent
from protocol import Connection, ProtocolError, ConnectionError
conn = Connection(({host!r}, {int(port)}), ("0.0.0.0", 0), magic_number=bytes.fromhex("fabfb5da"),
                  open_timeout=5, socket_timeout=30, protocol_version=70016, to_services=0,
                  from_services=0, user_agent="/bitnodes.io:0.3/", height=0, relay=0)
try:
    conn.open(); conn.handshake(); conn.getaddr(block=False)
    for _ in range(30):
        gevent.sleep(0.3)
        msgs = conn.get_messages(commands=[b"addr", b"addrv2"])
        if msgs and any(m["count"] > 1 for m in msgs):
            break
except (ProtocolError, ConnectionError, socket.error) as e:
    print("bitnodes:", e)
conn.close()
"""
        return [os.environ["BITNODES_PYTHON"], "-c", code]

    def ready(self):
        pass


class Libbitcoin(Impl):
    """libbitcoin-server's bs, run in a container: bs 3.8 cannot choose the
    address it listens on, so it gets a network namespace of its own with
    only its P2P port published to the host's loopback. bs cannot mine and
    has no RPC that reports its chain state."""
    family, name = "libbitcoin", "libbitcoin"
    env = ("LIBBITCOIN_BS",)
    can_mine = False
    image = "ubuntu:20.04"  # what bs was built on
    container = "fp-libbitcoin"

    def gateway(self):
        out = subprocess.run(["docker", "network", "inspect", "bridge", "--format",
                              "{{(index .IPAM.Config 0).Gateway}}"], capture_output=True, text=True, check=True)
        return out.stdout.strip()

    def recorder_bind(self):
        return self.gateway()

    def write_config(self, connect):
        lines = ["[network]", "identifier = 3669344250", f"inbound_port = {NODE_P2P}",
                 "inbound_connections = 8", "outbound_connections = 0", "host_pool_capacity = 0", "seed = 127.0.0.1:1",
                 "[database]", "directory = /data/blockchain", "block_table_buckets = 1000",
                 "transaction_table_buckets = 1000", "spend_table_buckets = 1000", "history_table_buckets = 1000",
                 "[blockchain]", "checkpoint = 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206:0",
                 "[fork]", "retarget = false",
                 "[log]", "archive_directory = /data/archive", "debug_file = /data/debug.log",
                 "error_file = /data/error.log",
                 "[server]", "query_workers = 0", "heartbeat_service_seconds = 0",
                 "block_service_enabled = false", "transaction_service_enabled = false"]
        if connect:
            host, port = connect.rsplit(":", 1)
            lines.insert(1, f"peer = {self.gateway()}:{port}")
        with open(os.path.join(self.dir, "bs.cfg"), "w") as f:
            f.write("\n".join(lines) + "\n")

    def docker(self, *bs_args, detach=False):
        return ["docker", "run", "--rm", "--name", self.container, "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{self.dir}:/data", "-v", f"{os.environ['LIBBITCOIN_BS']}:/bs:ro",
                "-p", f"127.0.0.1:{NODE_P2P}:{NODE_P2P}", self.image, "/bs", "-c", "/data/bs.cfg", *bs_args]

    def start(self, connect=None):
        os.makedirs(self.dir, exist_ok=True)
        self.write_config(connect)
        if not os.path.exists(os.path.join(self.dir, "blockchain")):
            subprocess.run(self.docker("-i"), check=True, capture_output=True)
        super().start(connect)

    def argv(self, connect):
        return self.docker()

    def ready(self):
        import socket as s
        s.create_connection(("127.0.0.1", NODE_P2P), 2).close()

    def stop(self):
        subprocess.run(["docker", "stop", "-t", "30", self.container], capture_output=True)
        super().stop()


IMPLS = [Satd, Core, Knots, Btcd, Bcoin, Rbitcoin, Floresta, Libbitcoin, Seeder, Bitnodes]


def capture(impl, direction, out, label, version, extra):
    bind = impl.recorder_bind() if hasattr(impl, "recorder_bind") else "127.0.0.1"
    args = [sys.executable, CAPTURE, "--label", label, "--implementation", impl.family,
            "--implementation-version", version, "--out", out, "--peer-ibd", "unknown", "--peer-height", "-1",
            *extra]
    if direction == "outbound":
        args += ["--dial", f"127.0.0.1:{NODE_P2P}"]
    else:
        # A second session shows whether the node dials again (rbitcoin
        # opens a short catch-up connection, then a separate one to follow
        # the tip).
        args += ["--listen", str(RECORDER), "--bind", bind, "--sessions", "2"]
    return subprocess.Popen(args)


def set_state(path, impl, note):
    """Write the node's state into the fixture and any later sessions'."""
    base, ext = os.path.splitext(path)
    ibd_height = set_state_one(path, impl, note)
    if os.path.exists(f"{base}-s2{ext}"):
        set_state_one(f"{base}-s2{ext}", impl, note)
    return ibd_height


def set_state_one(path, impl, note):
    try:
        ibd, height = impl.state()
    except Exception as e:  # noqa: BLE001
        ibd, height, note = "unknown", -1, f"{note}; state not readable: {e}".strip("; ")
    if ibd == "unknown" and impl.can_mine and height >= 1:
        note = "RPC reports no IBD state; its tip was mined seconds before the capture"
    with open(path) as f:
        d = json.load(f)
    d["peer_state"] = {"ibd": ibd, "height": height, "note": note}
    with open(path, "w") as f:
        f.write(json.dumps(d, indent=2) + "\n")
    return ibd, height


def run(impl, outdir, version, extra, suffix=""):
    shutil.rmtree(impl.dir, ignore_errors=True)
    results = []
    note = "" if impl.can_mine else "cannot mine on regtest; never left IBD" if impl.family != "crawler" else "crawler, no chain"
    if impl.can_mine or impl.listens:
        impl.start()
        try:
            wait_for(impl.ready, f"{impl.name} RPC")
            if impl.can_mine:
                impl.mine()
            if impl.listens:
                wait_for(lambda: __import__("socket").create_connection(("127.0.0.1", NODE_P2P), 2).close(),
                         f"{impl.name} P2P port")
                path = os.path.join(outdir, f"{impl.name}-{version}-outbound{suffix}.json")
                rc = capture(impl, "outbound", path, f"{impl.name}-{version}-outbound{suffix}", version, extra).wait()
                results.append(("outbound", rc, set_state(path, impl, note) if rc == 0 else None))
        finally:
            impl.stop()
    if impl.dials and hasattr(impl, "connect_live"):
        impl.start()
        try:
            wait_for(impl.ready, f"{impl.name} RPC")
            if impl.can_mine:
                impl.mine()
            path = os.path.join(outdir, f"{impl.name}-{version}-inbound{suffix}.json")
            cap = capture(impl, "inbound", path, f"{impl.name}-{version}-inbound{suffix}", version, extra)
            try:
                time.sleep(1)
                impl.connect_live(f"127.0.0.1:{RECORDER}")
                rc = cap.wait(timeout=CAPTURE_TIMEOUT)
                results.append(("inbound", rc, set_state(path, impl, note) if rc == 0 else None))
            except subprocess.TimeoutExpired:
                results.append(("inbound", "timeout", None))
            finally:
                # Never leave a recorder holding the port for the next capture.
                if cap.poll() is None:
                    cap.kill()
                    cap.wait()
        finally:
            impl.stop()
    elif impl.dials:
        path = os.path.join(outdir, f"{impl.name}-{version}-inbound{suffix}.json")
        cap = capture(impl, "inbound", path, f"{impl.name}-{version}-inbound{suffix}", version, extra)
        time.sleep(1)
        impl.start(connect=f"127.0.0.1:{RECORDER}")
        try:
            rc = cap.wait(timeout=CAPTURE_TIMEOUT)
            state = None
            if rc == 0:
                try:
                    wait_for(impl.ready, f"{impl.name} RPC", timeout=20)
                except RuntimeError:
                    pass
                state = set_state(path, impl, note)
            results.append(("inbound", rc, state))
        except subprocess.TimeoutExpired:
            results.append(("inbound", "timeout", None))
        finally:
            if cap.poll() is None:
                cap.kill()
                cap.wait()
            impl.stop()
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", help="comma-separated implementation names")
    ap.add_argument("--version", action="append", default=[], metavar="NAME=VERSION",
                    help="version string recorded for an implementation (required for each one run)")
    ap.add_argument("--capture-arg", action="append", default=[], help="extra argument passed to capture.py")
    ap.add_argument("--transport", default="v1", help="v1, v2 or v1,v2 (v2 fixtures get a -v2 suffix)")
    ap.add_argument("--core-functional", help="Bitcoin Core's test/functional directory, needed for v2")
    args = ap.parse_args()
    versions = dict(v.split("=", 1) for v in args.version)
    only = set(args.only.split(",")) if args.only else None
    os.makedirs(args.out, exist_ok=True)
    for cls in IMPLS:
        impl = cls(args.workdir)
        if only and impl.name not in only:
            continue
        if not impl.available():
            print(f"skip {impl.name}: set {', '.join(impl.env)}")
            continue
        if impl.name not in versions:
            sys.exit(f"--version {impl.name}=... is required")
        for transport in args.transport.split(","):
            extra, suffix = list(args.capture_arg), ""
            if transport == "v2":
                if not args.core_functional:
                    sys.exit("--transport v2 needs --core-functional")
                extra += ["--v2", "--core-functional", args.core_functional]
                suffix = "-v2"
            for direction, rc, state in run(impl, args.out, versions[impl.name], extra, suffix):
                print(f"{impl.name} {transport} {direction}: rc={rc} state={state}")


if __name__ == "__main__":
    main()
