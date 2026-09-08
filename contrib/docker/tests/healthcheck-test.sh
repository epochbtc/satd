#!/bin/bash
# Unit test for contrib/docker/satd-healthcheck.
#
# The probe speaks raw HTTP over /dev/tcp, which is exactly the kind of
# code that breaks silently: a malformed request makes the server wait for
# more input, the probe's read times out, and a perfectly healthy node is
# reported as down. So each case here asserts the exit status against a
# real listener rather than mocking the transport.
#
# No dependencies beyond bash and python3 (already required by the repo's
# other test tooling).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEALTHCHECK="$HERE/../satd-healthcheck"
[[ -x "$HEALTHCHECK" ]] || { echo "not executable: $HEALTHCHECK" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

cat > "$WORKDIR/server.py" <<'PY'
"""Minimal HTTP responder that answers a fixed status code.

`silent` mode accepts the connection and never writes, which is how a
wedged listener behaves: the probe must time out rather than hang.
"""
import socket
import sys
import threading

mode = sys.argv[1]
port = int(sys.argv[2])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
print("ready", flush=True)


def serve(conn):
    try:
        conn.settimeout(10)
        # Read the request head. A correctly-formed request ends with a
        # blank line; if the probe forgets the terminator this loop spins
        # until the timeout, which is the failure this test exists to catch.
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        if mode == "silent":
            return
        code = int(mode)
        body = b"{}"
        conn.sendall(
            b"HTTP/1.1 %d X\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (code, len(body), body)
        )
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# Ports are picked from a fixed high base plus an index. The suite is
# single-process and cleans up after itself, so a fixed base is fine; the
# base is uncommon enough not to collide with the canaries' ranges.
PORT_BASE=${SATD_HEALTHCHECK_TEST_PORT_BASE:-19540}

start_server() {
    local mode="$1" port="$2"
    python3 "$WORKDIR/server.py" "$mode" "$port" > "$WORKDIR/ready.$port" 2>&1 &
    PIDS+=($!)
    local deadline=$(($(date +%s) + 15))
    while [[ $(date +%s) -lt $deadline ]]; do
        grep -q ready "$WORKDIR/ready.$port" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "server on $port never became ready" >&2
    cat "$WORKDIR/ready.$port" >&2 || true
    return 1
}

FAILURES=0
check() {
    local name="$1" expected="$2"
    shift 2
    local actual=0
    "$@" > "$WORKDIR/out" 2>&1 || actual=$?
    if [[ "$actual" == "$expected" ]]; then
        echo "ok   — $name"
    else
        echo "FAIL — $name: expected exit $expected, got $actual"
        sed 's/^/       /' "$WORKDIR/out"
        FAILURES=$((FAILURES + 1))
    fi
}

P_OK=$((PORT_BASE + 0))
P_503=$((PORT_BASE + 1))
P_401=$((PORT_BASE + 2))
P_SILENT=$((PORT_BASE + 3))
P_DEAD=$((PORT_BASE + 4))

start_server 200 "$P_OK"
start_server 503 "$P_503"
start_server 401 "$P_401"
start_server silent "$P_SILENT"
# P_DEAD is deliberately never bound.

# --- readiness mode (SATD_HEALTH_URL) ---
check "readyz 200 is healthy" 0 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_OK/readyz" "$HEALTHCHECK"
check "readyz 503 is unhealthy (node still starting)" 1 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_503/readyz" "$HEALTHCHECK"
check "readyz on a refused port is unhealthy" 1 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_DEAD/readyz" "$HEALTHCHECK"
check "readyz against a silent listener times out unhealthy" 1 \
    env SATD_HEALTH_TIMEOUT=2 SATD_HEALTH_URL="http://127.0.0.1:$P_SILENT/readyz" "$HEALTHCHECK"
check "URL with no path still terminates the request" 0 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_OK" "$HEALTHCHECK"
check "nested path is preserved" 0 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_OK/a/b/c" "$HEALTHCHECK"

# --- RPC liveness mode ---
check "RPC 200 is healthy" 0 \
    env SATD_RPCPORT="$P_OK" "$HEALTHCHECK"
# The load-bearing case: a bound listener that rejects the probe's
# credentials is still a live listener, and must not read as down.
check "RPC 401 is healthy (listener is bound and serving)" 0 \
    env SATD_RPCPORT="$P_401" "$HEALTHCHECK"
check "RPC 503 is healthy in liveness mode" 0 \
    env SATD_RPCPORT="$P_503" "$HEALTHCHECK"
check "RPC on a refused port is unhealthy" 1 \
    env SATD_RPCPORT="$P_DEAD" "$HEALTHCHECK"
check "RPC against a silent listener times out unhealthy" 1 \
    env SATD_HEALTH_TIMEOUT=2 SATD_RPCPORT="$P_SILENT" "$HEALTHCHECK"

# SATD_HEALTH_URL wins when both are set, even if the RPC port is fine.
check "SATD_HEALTH_URL takes precedence over SATD_RPCPORT" 1 \
    env SATD_HEALTH_URL="http://127.0.0.1:$P_503/readyz" SATD_RPCPORT="$P_OK" "$HEALTHCHECK"

if [[ $FAILURES -ne 0 ]]; then
    echo "$FAILURES healthcheck test(s) failed" >&2
    exit 1
fi
echo "all healthcheck tests passed"
