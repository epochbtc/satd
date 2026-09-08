#!/bin/bash
# boot-test.sh — boot a built appliance image and check that it works.
#
#   contrib/appliance/tests/boot-test.sh --image out/satd-appliance-...qcow2
#   contrib/appliance/tests/boot-test.sh --image ... --in-docker   # no host qemu
#
# This is the "the image is not broken" gate. It boots the actual artifact —
# no test-only build, no injected hooks — and asserts what a person who
# downloaded it would find.
#
# Two channels, deliberately:
#
#   * The QEMU guest agent, for looking inside: did first boot run, is satd
#     up, did the certificates get generated, is anything that should not
#     have shipped now present.
#   * Forwarded ports from the host, for the TLS surfaces. Checking a
#     certificate from inside the guest proves much less than connecting to
#     it the way a client on the network will. The CA comes out over the
#     guest agent and every external probe then verifies against it, so
#     these are real verifications rather than handshake-completed checks.
#
# KVM is used when available and TCG when it is not, so this runs on a
# hosted CI runner and on a laptop with no virtualisation.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

IMAGE=""
IN_DOCKER=0
MEMORY=2560
CPUS=2
BOOT_TIMEOUT=900
KEEP=0
PORT_BASE="${SATD_BOOT_TEST_PORT_BASE:-22400}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --in-docker) IN_DOCKER=1; shift ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --port-base) PORT_BASE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "boot-test.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$IMAGE" ]] || { echo "boot-test.sh: --image is required" >&2; exit 2; }
[[ -s "$IMAGE" ]] || { echo "boot-test.sh: no such image: $IMAGE" >&2; exit 2; }
IMAGE="$(readlink -f "$IMAGE")"

if [[ "$IN_DOCKER" == 1 ]]; then
    # qemu, python3 and openssl in a container, so the host needs none of
    # them. Not privileged: /dev/kvm is passed through when it exists, and
    # TCG needs no special access at all.
    kvm_args=()
    [[ -e /dev/kvm ]] && kvm_args=(--device /dev/kvm)
    exec docker run --rm "${kvm_args[@]}" \
        -v "$REPO:/repo" -v "$(dirname "$IMAGE"):/image" \
        -w /repo \
        -e DEBIAN_FRONTEND=noninteractive \
        debian:trixie bash -c '
set -euo pipefail
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    qemu-system-x86 qemu-utils python3 openssl curl ca-certificates > /dev/null
exec "$@"
' -- /repo/contrib/appliance/tests/boot-test.sh --image "/image/$(basename "$IMAGE")" \
        --memory "$MEMORY" --timeout "$BOOT_TIMEOUT" --port-base "$PORT_BASE" \
        $([[ "$KEEP" == 1 ]] && echo --keep)
fi

for tool in qemu-system-x86_64 qemu-img openssl python3; do
    command -v "$tool" > /dev/null || { echo "boot-test.sh: missing $tool (try --in-docker)" >&2; exit 1; }
done

WORK="$(mktemp -d)"
QGA_SOCK="$WORK/qga.sock"
CONSOLE="$WORK/console.log"
QEMU_PID=""

RPC_TLS=$((PORT_BASE + 0))
ELECTRUM_TLS=$((PORT_BASE + 1))
ESPLORA_TLS=$((PORT_BASE + 2))
MCP_TLS=$((PORT_BASE + 3))

cleanup() {
    if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done
        kill -KILL "$QEMU_PID" 2>/dev/null || true
    fi
    if [[ "$KEEP" == 1 ]]; then
        echo "boot-test.sh: --keep; console log at $CONSOLE"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

FAILURES=0
pass() { echo "ok   — $1"; }
fail() { echo "FAIL — $1"; [[ $# -lt 2 ]] || sed 's/^/       /' <<< "$2"; FAILURES=$((FAILURES + 1)); }

# --- the guest-agent client -------------------------------------------------
cat > "$WORK/qga.py" <<'PY'
"""Minimal QEMU guest-agent client.

Speaks newline-delimited JSON over the agent's unix socket. `exec` runs a
command in the guest and blocks until it exits, returning (rc, stdout,
stderr) — which is all this test needs and much less than a full QMP client.
"""
import base64
import json
import socket
import sys
import time


class Agent:
    def __init__(self, path, timeout=10):
        self.path = path
        self.timeout = timeout

    def _rpc(self, cmd, args=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        payload = {"execute": cmd}
        if args:
            payload["arguments"] = args
        s.sendall((json.dumps(payload) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise RuntimeError("guest agent closed the connection")
            buf += chunk
        s.close()
        reply = json.loads(buf.split(b"\n")[0])
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply.get("return")

    def ping(self):
        self._rpc("guest-ping")

    def exec(self, argv, timeout=300):
        r = self._rpc("guest-exec", {"path": argv[0], "arg": argv[1:],
                                     "capture-output": True})
        pid = r["pid"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = self._rpc("guest-exec-status", {"pid": pid})
            if st.get("exited"):
                out = base64.b64decode(st.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(st.get("err-data", "")).decode(errors="replace")
                return st.get("exitcode", -1), out, err
            time.sleep(0.5)
        raise TimeoutError(f"guest command timed out: {argv}")


if __name__ == "__main__":
    mode = sys.argv[1]
    agent = Agent(sys.argv[2])
    if mode == "ping":
        agent.ping()
    elif mode == "exec":
        rc, out, err = agent.exec(["/bin/sh", "-c", sys.argv[3]])
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(rc)
    else:
        raise SystemExit(f"unknown mode {mode}")
PY

guest() { python3 "$WORK/qga.py" exec "$QGA_SOCK" "$1"; }

# --- boot -------------------------------------------------------------------
# An overlay so the test never mutates the artifact it is checking; a rerun
# starts from the same bytes a downloader would get.
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$WORK/overlay.qcow2"

echo "boot-test.sh: booting $(basename "$IMAGE")"
# `accel=kvm:tcg` is a fallback list and belongs on -machine; `-accel` takes
# one accelerator and rejects the list outright. The comment lives here
# rather than inside the invocation below: a `#` on a backslash-continued
# line comments out every argument after it, and qemu then starts with none
# — no serial file, no agent socket, and a boot that hangs until the test's
# own timeout rather than failing.
qemu-system-x86_64 \
    -machine q35,accel=kvm:tcg \
    -cpu max \
    -m "$MEMORY" -smp "$CPUS" \
    -drive "file=$WORK/overlay.qcow2,if=virtio,format=qcow2" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$RPC_TLS-:8336,hostfwd=tcp:127.0.0.1:$ELECTRUM_TLS-:50002,hostfwd=tcp:127.0.0.1:$ESPLORA_TLS-:3001,hostfwd=tcp:127.0.0.1:$MCP_TLS-:8339" \
    -device virtio-net-pci,netdev=n0 \
    -chardev "socket,path=$QGA_SOCK,server=on,wait=off,id=qga0" \
    -device virtio-serial \
    -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
    -serial "file:$CONSOLE" \
    -display none \
    -no-reboot &
QEMU_PID=$!

echo "boot-test.sh: waiting for the guest agent (up to ${BOOT_TIMEOUT}s)..."
deadline=$(($(date +%s) + BOOT_TIMEOUT))
agent_up=0
while [[ $(date +%s) -lt $deadline ]]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        fail "the VM stayed running" "$(tail -40 "$CONSOLE" 2>/dev/null)"
        exit 1
    fi
    if python3 "$WORK/qga.py" ping "$QGA_SOCK" 2>/dev/null; then agent_up=1; break; fi
    sleep 5
done
if [[ "$agent_up" != 1 ]]; then
    fail "the guest booted and its agent answered" "$(tail -60 "$CONSOLE" 2>/dev/null)"
    exit 1
fi
pass "the image boots"

# --- first boot -------------------------------------------------------------
echo "boot-test.sh: waiting for first-boot setup..."
deadline=$(($(date +%s) + 600))
done_marker=0
while [[ $(date +%s) -lt $deadline ]]; do
    if guest 'test -f /var/lib/satd-appliance/firstboot-done' > /dev/null 2>&1; then
        done_marker=1; break
    fi
    sleep 5
done
if [[ "$done_marker" == 1 ]]; then
    pass "first boot completed"
else
    fail "first boot completed" "$(guest 'journalctl -u satd-appliance-firstboot --no-pager | tail -40' 2>&1)"
fi

# Everything unique to the install must now exist — and must have been
# created here rather than shipped, which 90-cleanup.sh asserted separately.
for path in /var/lib/satd/tls/ca.key /var/lib/satd/tls/ca.crt /var/lib/satd/tls/leaf.key \
            /var/lib/satd/tls/fullchain.crt /var/lib/satd/bitcoin.conf \
            /var/lib/satd/authfile.toml /var/lib/satd/secrets/mcp-token; do
    if guest "test -s $path" > /dev/null 2>&1; then
        pass "first boot created $path"
    else
        fail "first boot created $path"
    fi
done

# --- the node ---------------------------------------------------------------
if guest 'systemctl is-active --quiet satd' > /dev/null 2>&1; then
    pass "satd is running under systemd"
else
    fail "satd is running under systemd" "$(guest 'systemctl status satd --no-pager -l | tail -30' 2>&1)"
fi

# Switch to regtest through the operator command. This tests set-network as
# well as giving the rest of the checks a chain that is at a usable tip
# immediately, rather than however far into signet IBD the VM has got.
echo "boot-test.sh: switching to regtest via satd-appliance..."
if out="$(guest 'satd-appliance set-network regtest 2>&1')"; then
    pass "satd-appliance set-network regtest"
else
    fail "satd-appliance set-network regtest" "$out"
fi

deadline=$(($(date +%s) + 180))
rpc_up=0
while [[ $(date +%s) -lt $deadline ]]; do
    if guest 'sat-cli --datadir=/var/lib/satd --rpcport=8332 --rpccookiefile=/var/lib/satd/rpc-cookie getblockcount' > /dev/null 2>&1; then
        rpc_up=1; break
    fi
    sleep 5
done
if [[ "$rpc_up" == 1 ]]; then
    pass "sat-cli reaches the node over the loopback listener"
else
    fail "sat-cli reaches the node over the loopback listener" \
        "$(guest 'journalctl -u satd --no-pager | tail -40' 2>&1)"
fi

guest 'sat-cli --datadir=/var/lib/satd --rpcport=8332 --rpccookiefile=/var/lib/satd/rpc-cookie generatetoaddress 5 bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw' > /dev/null 2>&1 || true
HEIGHT="$(guest 'sat-cli --datadir=/var/lib/satd --rpcport=8332 --rpccookiefile=/var/lib/satd/rpc-cookie getblockcount' 2>/dev/null | tr -d '\r\n' || true)"
if [[ "$HEIGHT" == "5" ]]; then
    pass "the node mines and reports height 5"
else
    fail "the node mines and reports height 5" "height is '$HEIGHT'"
fi

# --- TLS, from outside the guest -------------------------------------------
CA="$WORK/ca.crt"
guest 'cat /var/lib/satd/tls/ca.crt' > "$CA" 2>/dev/null || true
if [[ -s "$CA" ]]; then
    pass "the appliance CA can be exported"
else
    fail "the appliance CA can be exported"
fi

probe_tls() {
    local name="$1" port="$2"
    local out
    out="$(timeout 25 openssl s_client -connect "127.0.0.1:$port" -servername satd \
            -CAfile "$CA" -verify_return_error -brief < /dev/null 2>&1 || true)"
    if grep -q "Verification: OK" <<< "$out"; then
        pass "$name is reachable over TLS and verifies against the appliance CA"
    else
        fail "$name is reachable over TLS and verifies against the appliance CA" "$out"
    fi
}
probe_tls "JSON-RPC" "$RPC_TLS"
probe_tls "Electrum" "$ELECTRUM_TLS"
probe_tls "Esplora" "$ESPLORA_TLS"
probe_tls "MCP" "$MCP_TLS"

# Negative control: without the CA the same handshake must fail. Otherwise
# the four checks above prove only that something is listening on the port.
out="$(timeout 25 openssl s_client -connect "127.0.0.1:$RPC_TLS" -servername satd \
        -verify_return_error -brief < /dev/null 2>&1 || true)"
if grep -q "Verification: OK" <<< "$out"; then
    fail "an untrusted client is rejected" "the handshake verified without the CA"
else
    pass "an untrusted client is rejected"
fi

# The certificate has to name the appliance the way clients will reach it.
sans="$(timeout 25 openssl s_client -connect "127.0.0.1:$RPC_TLS" -servername satd \
        -CAfile "$CA" -showcerts < /dev/null 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' \n' || true)"
for want in "DNS:satd" "DNS:satd.local" "DNS:localhost" "IPAddress:127.0.0.1"; do
    if [[ "$sans" == *"$want"* ]]; then
        pass "the certificate covers $want"
    else
        fail "the certificate covers $want" "SANs: $sans"
    fi
done

# --- Esplora and MCP answer, not just handshake -----------------------------
esplora_tip="$(curl -sS --cacert "$CA" --resolve "satd:$ESPLORA_TLS:127.0.0.1" \
    "https://satd:$ESPLORA_TLS/api/blocks/tip/height" 2>&1 || true)"
if [[ "$esplora_tip" == "$HEIGHT" ]]; then
    pass "Esplora over TLS reports the node's tip"
else
    fail "Esplora over TLS reports the node's tip" "got '$esplora_tip', expected '$HEIGHT'"
fi

TOKEN="$(guest 'cat /var/lib/satd/secrets/mcp-token' 2>/dev/null | tr -d '\r\n' || true)"
if [[ -n "$TOKEN" ]]; then
    # Unauthenticated first: a listener that answers without the token would
    # mean the bearer gate is not installed, which no amount of TLS fixes.
    anon_code="$(curl -sS --cacert "$CA" --resolve "satd:$MCP_TLS:127.0.0.1" \
        -o /dev/null -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        "https://satd:$MCP_TLS/" 2>&1 || true)"
    if [[ "$anon_code" == "401" || "$anon_code" == "403" ]]; then
        pass "MCP refuses an unauthenticated request ($anon_code)"
    else
        fail "MCP refuses an unauthenticated request" "http $anon_code"
    fi
else
    fail "the MCP token was generated"
fi

# --- the firewall -----------------------------------------------------------
if guest 'nft list ruleset | grep -q "policy drop"' > /dev/null 2>&1; then
    pass "inbound traffic is default-deny"
else
    fail "inbound traffic is default-deny" "$(guest 'nft list ruleset 2>&1 | head -30')"
fi

# The plain RPC listener must not be reachable from the network. It is not
# forwarded, so this reads the ruleset's intent directly — and the intent is
# specifically "only the container subnet", not "closed": the overlays reach
# a natively-run satd through the docker gateway, which arrives on this same
# input chain. So an accept for 8332 is expected; an accept for 8332 that
# does not name a source address is the bug.
plain_rpc_rules="$(guest 'nft list ruleset | grep -E "dport[^\n]*8332"' 2>/dev/null || true)"
if [[ -z "$plain_rpc_rules" ]]; then
    pass "the plain RPC port is not opened in the firewall"
elif grep -qv "ip saddr" <<< "$plain_rpc_rules"; then
    fail "the plain RPC port is only opened to the container subnet" "$plain_rpc_rules"
else
    pass "the plain RPC port is only opened to the container subnet"
fi

# --- the container stack is staged but idle ---------------------------------
if guest 'test -f /opt/satd/stack/compose.appliance.yml && test -f /opt/satd/stack/compose.lightning.yml' > /dev/null 2>&1; then
    pass "the compose overlays are staged on disk"
else
    fail "the compose overlays are staged on disk"
fi
if guest 'systemctl is-active --quiet docker' > /dev/null 2>&1; then
    fail "docker is idle until an overlay is enabled"
else
    pass "docker is idle until an overlay is enabled"
fi

# --- status, the command the README tells people to run ---------------------
if status_out="$(guest 'satd-appliance status 2>&1')" && grep -q "network:" <<< "$status_out"; then
    pass "satd-appliance status reports the node's state"
else
    fail "satd-appliance status reports the node's state" "$status_out"
fi

echo
if [[ $FAILURES -ne 0 ]]; then
    echo "$FAILURES boot check(s) failed" >&2
    exit 1
fi
echo "all appliance boot checks passed"
