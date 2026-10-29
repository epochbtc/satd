#!/usr/bin/env python3
"""Run satd against the real public network and check how its peers behave.

For each network (testnet4 and signet by default) this starts satd on a fresh
temporary datadir with default DNS seeding, `--listen=0`, no Esplora, Electrum
or Stratum, and `--debug=net`; lets it run for LIVE_PEERS_SECONDS; stops it
through RPC; and reads the log. The networks run side by side.

It fails on two things no test with a scripted peer catches, because only real
peers send them:

  decode   a `Read error:` that is a message decode failure, from at least
           LIVE_PEERS_DECODE_MIN_PEERS distinct peers on any one network. A
           message from a stock Bitcoin Core peer that satd cannot decode
           ends the connection: that is satd's bug, never the network's.
  churn    on EVERY network run: more than LIVE_PEERS_MAX_SHORT_RATIO of the
           peers that finished the handshake were gone within
           LIVE_PEERS_SHORT_SECONDS, or the node held fewer than
           LIVE_PEERS_MIN_MEAN_PEERS connected peers on average after the
           warm-up. A peer set that churns on one network alone can be that
           network's weather; on all of them it is satd.

Where the thresholds come from: three four-minute runs each of a build that
dropped every peer whose `addrv2` reply it could not decode, and of the fixed
build, from one IPv4-only host:

                       broken build              fixed build
  decode peers/network 5-19 (unambiguously       0
                       attributed)
  short-lived ratio    85-100%                   0-33% (>= 8 handshakes: 0-14%)
  mean peers testnet4  0.4-1.7                   3.9-8.6
  mean peers signet    10-16 (v1 peers survived) 23-27

Decode failures alone tell the two apart. Testnet4 has few reachable IPv4
nodes, so its mean peer count runs low even when healthy, and on signet the
v1 peers survived the broken build, so neither the short-lived ratio nor the
mean is judged on one network alone.

Exit status: 0 pass; 1 a finding (decode, churn, or satd exiting before its
run time); 2 inconclusive (satd could not be started, or no peer finished a
handshake on some network: the runner had no network, or the seeds were
down); 3 the script itself failed. A decode failure or an early exit on one
network is a finding even when another network was inconclusive. The printed report, also appended to
$GITHUB_STEP_SUMMARY when set, carries trend numbers that never fail the run:
addresses learned, distinct peers, the v1/v2 transport mix and undecodable
messages the reader skipped.

Environment (all optional):
  SATD_BIN                     satd binary (default: target/release/satd in
                               this checkout)
  LIVE_PEERS_NETWORKS          space-separated networks (default
                               "testnet4 signet"; "mainnet" works too)
  LIVE_PEERS_SECONDS           run time per network (default 240)
  LIVE_PEERS_WARMUP_SECONDS    left out of the mean peer count (default 60)
  LIVE_PEERS_WORKDIR           where datadirs and logs go (default: a new
                               directory under $RUNNER_TEMP or $TMPDIR); kept
                               afterwards so the logs can be uploaded
  LIVE_PEERS_RPCPORT_<NET>     RPC port for one network, e.g.
                               LIVE_PEERS_RPCPORT_SIGNET (default: a free
                               port on 127.0.0.1)
  LIVE_PEERS_EXTRA_ARGS        extra satd arguments, space-separated
  LIVE_PEERS_DECODE_MIN_PEERS  default 2
  LIVE_PEERS_SHORT_SECONDS     default 30
  LIVE_PEERS_MAX_SHORT_RATIO   default 0.5
  LIVE_PEERS_MIN_HANDSHAKES    fewer handshakes than this and the short-lived
                               ratio is not judged (default 8)
  LIVE_PEERS_MIN_MEAN_PEERS    default 2

Usage: scripts/live-peers/smoke.py [--analyze <log> [<log> ...]]
  --analyze re-reads logs from an earlier run instead of starting satd.
"""

import base64
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

NETWORK_FLAG = {"mainnet": None, "testnet4": "--testnet4", "signet": "--signet"}
# Subdirectory of the datadir that holds the cookie, as satd lays it out.
NETWORK_SUBDIR = {"mainnet": "", "testnet4": "testnet4", "signet": "signet"}


def env_num(kind, name, default):
    try:
        return kind(os.environ.get(name, default))
    except ValueError:
        # A bad setting is the caller's, never a finding (exit 1).
        print(f"error: {name} is not a number: {os.environ.get(name)!r}", file=sys.stderr)
        sys.exit(2)


def env_int(name, default):
    return env_num(int, name, default)


def env_float(name, default):
    return env_num(float, name, default)


SECONDS = env_int("LIVE_PEERS_SECONDS", 240)
WARMUP = env_int("LIVE_PEERS_WARMUP_SECONDS", 60)
DECODE_MIN_PEERS = env_int("LIVE_PEERS_DECODE_MIN_PEERS", 2)
SHORT_SECONDS = env_float("LIVE_PEERS_SHORT_SECONDS", 30)
MAX_SHORT_RATIO = env_float("LIVE_PEERS_MAX_SHORT_RATIO", 0.5)
MIN_HANDSHAKES = env_int("LIVE_PEERS_MIN_HANDSHAKES", 8)
MIN_MEAN_PEERS = env_float("LIVE_PEERS_MIN_MEAN_PEERS", 2)
# How long after a decode `Read error` its peer's task end may come.
ATTRIBUTE_SECONDS = 0.5

# A tracing line: `<rfc3339>Z  LEVEL target: message fields...`.
LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z\s+([A-Z]+)\s+(\S+): (.*)$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A read error that is the decoder refusing a message, not the socket.
DECODE = re.compile(
    r"deserializ|varint|truncated|unparseable|undecodable|unknown message|parse",
    re.IGNORECASE,
)
FIELD_ID = re.compile(r"\bid=(\d+)")
PEER_EQ = re.compile(r"\bpeer=(\d+)")
ADDR = re.compile(r"\baddr=(\S+)")


def parse_ts(s):
    # Python before 3.11 takes at most six fractional digits.
    if "." in s:
        head, frac = s.split(".")
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s).timestamp()


def analyze(log_path, network):
    """Read one satd log and return the report for its network."""
    start = shutdown = None
    connected = {}  # id -> (ts, addr, user_agent)
    disconnected = {}  # id -> ts
    addrfetch = set()
    v2_attempt = set()
    v1_retry = set()
    task_end = []  # (ts, id, addr, line)
    read_errors = []  # (ts, line, context)
    skipped = []
    addr_received = 0
    last_received = {}  # peer id -> its last `received:` line, for context
    last_received_any = None

    with open(log_path, errors="replace") as f:
        for raw in f:
            raw = ANSI.sub("", raw.rstrip("\n"))
            m = LINE.match(raw)
            if not m:
                continue
            ts = parse_ts(m.group(1))
            msg = m.group(4)
            if start is None:
                start = ts
            if msg.startswith("received: "):
                p = PEER_EQ.search(msg)
                if p:
                    last_received[p.group(1)] = raw
                last_received_any = raw
            elif msg.startswith("Read error: "):
                if DECODE.search(msg):
                    read_errors.append((ts, raw, dict(last_received), last_received_any))
            elif msg.startswith("Peer connected "):
                i = FIELD_ID.search(msg)
                a = ADDR.search(msg)
                ua = re.search(r"user_agent=(\S+)", msg)
                if i:
                    connected[i.group(1)] = (ts, a.group(1) if a else "?", ua.group(1) if ua else "?")
            elif msg.startswith("Peer disconnected "):
                i = FIELD_ID.search(msg)
                if i:
                    disconnected.setdefault(i.group(1), ts)
            elif msg.startswith("Peer task ended: "):
                i = FIELD_ID.search(msg)
                a = ADDR.search(msg)
                if i:
                    task_end.append((ts, i.group(1), a.group(1) if a else "?", raw))
            elif msg.startswith("addrfetch connection completed"):
                i = FIELD_ID.search(msg)
                if i:
                    addrfetch.add(i.group(1))
            elif msg.startswith("start sending v2 handshake"):
                p = PEER_EQ.search(msg)
                if p:
                    v2_attempt.add(p.group(1))
            elif msg.startswith("retrying with v1 transport"):
                p = PEER_EQ.search(msg)
                if p:
                    v1_retry.add(p.group(1))
            elif msg.startswith("Skipping unparseable message"):
                skipped.append(raw)
            elif msg.startswith("Received addr"):
                c = re.search(r"\bcount=(\d+)", msg)
                if c:
                    addr_received += int(c.group(1))
            elif msg.startswith("P2P manager shutting down") and shutdown is None:
                shutdown = ts

    end = shutdown
    if end is None:
        end = max([start or 0] + [t for t, *_ in task_end] + list(disconnected.values()))

    # The read error carries no peer id. Its reader task ending closes the
    # peer's channel, and the peer task ends at once with "connection
    # closed", so that line names the peer. Only an unambiguous match counts:
    # with no candidate, or more than one, inside ATTRIBUTE_SECONDS, the error
    # goes under "?", so a coincidental disconnect cannot pose as a second
    # decoding peer.
    decode_peers = {}
    claimed = set()
    for ts, line, seen, ctx in read_errors:
        cands = [
            (pid, addr)
            for t, pid, addr, raw in task_end
            if ts <= t < ts + ATTRIBUTE_SECONDS and pid not in claimed and "connection closed" in raw
        ]
        who = "?"
        if len(cands) == 1:
            pid, who = cands[0]
            claimed.add(pid)
            ctx = seen.get(pid, ctx)
        decode_peers.setdefault(who, []).append((line, ctx))
    # Distinct peers named; unattributed errors add one only when nothing
    # was attributed, so "?" can never be the second peer.
    named = [w for w in decode_peers if w != "?"]
    decode_distinct = len(named) or (1 if decode_peers else 0)

    # Peers that finished the handshake, address-fetch connections left out
    # (those end by design once they have their addresses).
    judged = {i: v for i, v in connected.items() if i not in addrfetch and (shutdown is None or v[0] < shutdown)}
    short = []
    for i, (t0, addr, ua) in judged.items():
        t1 = disconnected.get(i)
        if t1 is not None and (shutdown is None or t1 < shutdown) and t1 - t0 < SHORT_SECONDS:
            short.append((i, addr, ua, t1 - t0))
    handshakes = len(judged)
    short_ratio = len(short) / handshakes if handshakes else 0.0

    # Time-weighted mean of connected peers between the warm-up and shutdown.
    events = []
    for i, (t0, *_rest) in connected.items():
        if i in addrfetch:
            continue
        events.append((t0, 1))
        t1 = disconnected.get(i)
        if t1 is not None:
            events.append((t1, -1))
    events.sort()
    w0 = (start or 0) + WARMUP
    level, area, prev = 0, 0.0, None
    for t, d in events:
        if t > end:
            break
        if t > w0:
            lo = max(prev if prev is not None else w0, w0)
            area += level * (t - lo)
        level += d
        prev = t
    lo = max(prev if prev is not None else w0, w0)
    if end > lo:
        area += level * (end - lo)
    mean_peers = area / (end - w0) if end > w0 else 0.0

    transport = {"v2": 0, "v1": 0}
    for i in judged:
        transport["v2" if i in v2_attempt and i not in v1_retry else "v1"] += 1

    return {
        "network": network,
        "log": str(log_path),
        "run_seconds": round(end - start, 1) if start else 0,
        "handshakes": handshakes,
        "distinct_peers": len({v[1] for v in judged.values()}),
        "short_lived": len(short),
        "short_ratio": round(short_ratio, 3),
        "mean_peers": round(mean_peers, 2),
        "decode_errors": len(read_errors),
        "decode_peers": decode_distinct,
        "decode_detail": decode_peers,
        "skipped_unparseable": len(skipped),
        "skipped_detail": skipped[:5],
        "addr_received": addr_received,
        "transport": transport,
        "short_detail": sorted(short, key=lambda s: s[3])[:10],
    }


def judge(r):
    """Annotate one network's report with its verdicts."""
    r["decode_fail"] = r["decode_peers"] >= DECODE_MIN_PEERS
    reasons = []
    if r["handshakes"] >= MIN_HANDSHAKES and r["short_ratio"] > MAX_SHORT_RATIO:
        reasons.append(
            f"{r['short_lived']}/{r['handshakes']} handshaken peers gone within {SHORT_SECONDS:g}s"
        )
    if r["mean_peers"] < MIN_MEAN_PEERS:
        reasons.append(f"mean {r['mean_peers']} connected peers after warm-up (< {MIN_MEAN_PEERS:g})")
    r["churn_reasons"] = reasons
    r["churn"] = bool(reasons)
    r["inconclusive"] = r["handshakes"] == 0
    return r


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc(port, cookie, method, params=None, timeout=10):
    body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": params or []}).encode()
    auth = base64.b64encode(cookie.read_text().strip().encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=body,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["result"]


def run_network(satd, network, port, workdir, out):
    """Thread body: every way out leaves a result, so no network goes missing."""
    try:
        _run_network(satd, network, port, workdir, out)
    except Exception as e:
        out[network] = {"network": network, "error": f"harness error: {e!r}"}


def _run_network(satd, network, port, workdir, out):
    datadir = workdir / network
    datadir.mkdir(parents=True, exist_ok=True)
    log = workdir / f"{network}.log"
    args = [str(satd)]
    if NETWORK_FLAG[network]:
        args.append(NETWORK_FLAG[network])
    args += [
        f"--datadir={datadir}",
        "--listen=0",
        "--debug=net",
        "--esplora=0",
        "--electrum=0",
        "--stratum=0",
        "--mcp=0",
        "--rpcbind=127.0.0.1",
        f"--rpcport={port}",
    ]
    args += shlex.split(os.environ.get("LIVE_PEERS_EXTRA_ARGS", ""))
    cookie = datadir / NETWORK_SUBDIR[network] / ".cookie"
    snapshot = {}
    with open(log, "w") as lf:
        proc = subprocess.Popen(args, stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + SECONDS
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(1)
        if proc.poll() is not None:
            # satd itself gave up on the live network: a finding, unless it
            # could not bind its RPC port (taken between free_port() and the
            # bind), which is this harness's race.
            lf.flush()
            bind_race = "Address already in use" in Path(log).read_text(errors="replace")
            out[network] = {
                "network": network,
                "log": str(log),
                "error": f"satd exited early ({proc.returncode})" + (": RPC port taken" if bind_race else ""),
                "crashed": not bind_race,
            }
            return
        try:
            peers = rpc(port, cookie, "getpeerinfo")
            snapshot["peers_at_end"] = len(peers)
            snapshot["outbound_at_end"] = sum(1 for p in peers if not p.get("inbound"))
            mix = {}
            for p in peers:
                k = p.get("transport_protocol_type", "?")
                mix[k] = mix.get(k, 0) + 1
            snapshot["transport_at_end"] = mix
            snapshot["addrman_size"] = len(rpc(port, cookie, "getnodeaddresses", [0]))
            snapshot["blocks"] = rpc(port, cookie, "getblockcount")
        except Exception as e:  # trend data only
            snapshot["rpc_error"] = str(e)
        try:
            rpc(port, cookie, "stop")
        except Exception:
            proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    r = analyze(log, network)
    r.update(snapshot)
    out[network] = judge(r)


def report(results):
    lines = ["## Live-peer smoke", ""]
    lines.append(
        "| network | handshakes | distinct peers | short-lived | mean peers | decode errors (peers)"
        " | skipped msgs | v2/v1 | addrs received | addrman | blocks |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in results.values():
        if "error" in r:
            lines.append(f"| {r['network']} | {r['error']} |||||||||| |")
            continue
        t = r["transport"]
        lines.append(
            f"| {r['network']} | {r['handshakes']} | {r['distinct_peers']} | {r['short_lived']} "
            f"({r['short_ratio']:.0%}) | {r['mean_peers']} | {r['decode_errors']} ({r['decode_peers']}) "
            f"| {r['skipped_unparseable']} | {t['v2']}/{t['v1']} | {r['addr_received']} "
            f"| {r.get('addrman_size', '?')} | {r.get('blocks', '?')} |"
        )
    lines.append("")
    lines.append(
        f"Thresholds: decode failures from >= {DECODE_MIN_PEERS} peers on any network; churn "
        f"(> {MAX_SHORT_RATIO:.0%} of >= {MIN_HANDSHAKES} handshaken peers gone within "
        f"{SHORT_SECONDS:g}s, or mean < {MIN_MEAN_PEERS:g} peers after {WARMUP}s) on every network."
    )
    return "\n".join(lines)


def details(results):
    out = []
    for r in results.values():
        if "error" in r:
            continue
        for who, errs in list(r["decode_detail"].items())[:10]:
            out.append(f"[{r['network']}] decode failure from {who} ({len(errs)}x); first:")
            line, ctx = errs[0]
            if ctx:
                out.append(f"    preceded by: {ctx}")
            out.append(f"    {line}")
        for i, addr, ua, life in r["short_detail"]:
            out.append(f"[{r['network']}] short-lived peer={i} {addr} {ua}: {life:.2f}s")
        for line in r["skipped_detail"]:
            out.append(f"[{r['network']}] skipped: {line}")
    return "\n".join(out)


def verdict(results):
    rs = list(results.values())
    if not rs:
        return 2, "INCONCLUSIVE: no network produced a result"
    # Findings on one network stand whatever happened on the others.
    crashed = [r["network"] for r in rs if r.get("crashed")]
    if crashed:
        return 1, "FAIL (exit): satd exited before its run time on " + ", ".join(crashed)
    decode = [r["network"] for r in rs if r.get("decode_fail")]
    if decode:
        return 1, "FAIL (decode): peers' messages could not be decoded on " + ", ".join(decode)
    # Churn is judged across every network, so all of them must have run.
    unjudged = [r["network"] for r in rs if "error" in r or r["inconclusive"]]
    if unjudged:
        return 2, "INCONCLUSIVE: satd did not run, or no peer finished a handshake, on " + ", ".join(unjudged)
    if all(r["churn"] for r in rs):
        why = "; ".join(f"{r['network']}: {', '.join(r['churn_reasons'])}" for r in rs)
        return 1, "FAIL (churn on every network): " + why
    return 0, "PASS"


def main():
    argv = sys.argv[1:]
    results = {}
    if argv[:1] == ["--analyze"]:
        for p in argv[1:]:
            net = Path(p).stem
            results[net] = judge(analyze(Path(p), net))
    elif argv:
        print(__doc__)
        return 2
    else:
        satd = Path(os.environ.get("SATD_BIN", REPO / "target" / "release" / "satd"))
        if not os.access(satd, os.X_OK):
            print(f"error: no satd binary at {satd} (set SATD_BIN)", file=sys.stderr)
            return 2
        networks = os.environ.get("LIVE_PEERS_NETWORKS", "testnet4 signet").split()
        for n in networks:
            if n not in NETWORK_FLAG:
                print(f"error: unknown network {n}", file=sys.stderr)
                return 2
        base = os.environ.get("LIVE_PEERS_WORKDIR")
        if base:
            workdir = Path(base)
            workdir.mkdir(parents=True, exist_ok=True)
        else:
            parent = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
            workdir = Path(tempfile.mkdtemp(prefix="satd-live-peers-", dir=parent))
        print(f"satd {satd}; networks {' '.join(networks)}; {SECONDS}s each; logs in {workdir}", flush=True)
        # Read here, not in the threads, so a bad setting stops the run.
        ports = {n: env_int(f"LIVE_PEERS_RPCPORT_{n.upper()}", 0) or free_port() for n in networks}
        threads = [
            threading.Thread(target=run_network, args=(satd, n, ports[n], workdir, results)) for n in networks
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        results = {
            n: results.get(n, {"network": n, "error": "no result (harness thread died)"}) for n in networks
        }
        slim = {
            n: {k: v for k, v in r.items() if not k.endswith("_detail")} for n, r in results.items()
        }
        (workdir / "report.json").write_text(json.dumps(slim, indent=2) + "\n")

    code, text = verdict(results)
    summary = report(results) + "\n\n**" + text + "**\n"
    print(summary)
    d = details(results)
    if d:
        print(d)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(summary)
            if code and d:
                f.write("\n<details><summary>Offending lines</summary>\n\n```\n" + d[:20000] + "\n```\n</details>\n")
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Exit 1 is reserved for findings about satd; a harness bug is not one.
        import traceback

        traceback.print_exc()
        sys.exit(3)
