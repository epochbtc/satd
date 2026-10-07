#!/bin/bash
# interop.sh — check satd's in-tree ZMTP PUB server against other ZMQ
# implementations.
#
#   contrib/zmq/interop.sh
#
# Runs events/examples/zmtp_pub.rs, which publishes a fixed sequence of 46
# messages (bodies from 0 bytes to 4 MiB), and checks that each client
# receives every message it subscribed to, intact and in order:
#
#   pyzmq   libzmq through Python; the library Core's own ZMQ tests, ckpool
#           and Node's `zeromq` package use. pyzmq is installed into a
#           virtualenv, with uv if it is installed, else python3 -m venv.
#   gozmq   github.com/lightninglabs/gozmq, the client LND uses for
#           bitcoind's rawblock and rawtx. Needs Go; the module is pinned in
#           contrib/zmq/gozmq_sub/go.mod.
#   chumak  the Erlang client Bitfeed uses. Not automated here: it is
#           reported as not run.
#
# A client whose toolchain is missing is reported as "not run" and does not
# fail the script. Exit status is 1 if any client that ran failed.
#
# Environment:
#   ZMQ_INTEROP_DIR   work directory (default: a new temporary directory)
#   ZMQ_INTEROP_VENV  virtualenv for pyzmq (default: $ZMQ_INTEROP_DIR/venv)
#   ZMQ_INTEROP_IPC_DIR  directory for the ipc:// sockets (default: a new
#                     directory under /tmp, short enough for a socket path)
#   ZMTP_PUB_BIN      a prebuilt zmtp_pub example (default: build it)
#   GO                the go binary (default: go)
#   PYTHON            the python binary for the virtualenv (default: python3)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="${ZMQ_INTEROP_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/zmtp-interop.XXXXXX")}"
VENV="${ZMQ_INTEROP_VENV:-$WORK/venv}"
GO="${GO:-go}"
PYTHON="${PYTHON:-python3}"
mkdir -p "$WORK"

# Unix socket paths are limited to about 107 bytes, so the ipc cases bind
# in a short directory of their own rather than under $WORK.
IPC_DIR="${ZMQ_INTEROP_IPC_DIR:-$(mktemp -d /tmp/zmtp-ipc.XXXXXX)}"

RESULTS=()
FAILED=0
record() { RESULTS+=("$1"); echo "$1"; }

# ---- the publisher ---------------------------------------------------------
PUB_BIN="${ZMTP_PUB_BIN:-}"
if [[ -z "$PUB_BIN" ]]; then
    echo "building the zmtp_pub example..."
    (cd "$REPO" && cargo build -q -p satd-events --features zmq --example zmtp_pub)
    target_dir="$(cd "$REPO" && cargo metadata --format-version 1 --no-deps \
        | "$PYTHON" -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
    PUB_BIN="$target_dir/debug/examples/zmtp_pub"
fi

# ---- the clients -----------------------------------------------------------
# pyzmq in a virtualenv: uv when it is installed, else python3 -m venv
# (which needs the python3-venv package on Debian and Ubuntu).
setup_pyzmq() {
    "$VENV/bin/python" -c 'import zmq' 2>/dev/null && return 0
    if command -v uv >/dev/null 2>&1; then
        uv venv -q --python "$PYTHON" "$VENV" && uv pip install -q --python "$VENV/bin/python" pyzmq
    else
        "$PYTHON" -m venv "$VENV" && "$VENV/bin/pip" install -q pyzmq
    fi
}
PYZMQ=""
if setup_pyzmq >"$WORK/venv.log" 2>&1; then
    PYZMQ="$WORK/pyzmq_sub"
    printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$VENV/bin/python" "$HERE/pyzmq_sub.py" >"$PYZMQ"
    chmod +x "$PYZMQ"
else
    record "pyzmq   NOT RUN (could not set up a virtualenv with pyzmq; see $WORK/venv.log)"
fi

GOZMQ=""
if command -v "$GO" >/dev/null 2>&1; then
    if (cd "$HERE/gozmq_sub" && "$GO" build -o "$WORK/gozmq_sub" .) >"$WORK/go-build.log" 2>&1; then
        GOZMQ="$WORK/gozmq_sub"
    else
        record "gozmq   NOT RUN (go build failed; see $WORK/go-build.log)"
    fi
else
    record "gozmq   NOT RUN (no Go toolchain; set GO=/path/to/go)"
fi

# ---- one case --------------------------------------------------------------
# run_case NAME ENDPOINT CLIENT GROUP...
#
# Starts the publisher on ENDPOINT, then one CLIENT per GROUP, concurrently.
# A GROUP is a comma-separated list of subscription prefixes for that client,
# with "-" for the empty prefix (everything).
run_case() {
    local name="$1" endpoint="$2" client="$3"
    shift 3
    local groups=("$@")
    local pub_prefixes=() g p
    for g in "${groups[@]}"; do
        IFS=, read -ra ps <<<"$g"
        for p in "${ps[@]}"; do
            [[ "$p" == "-" ]] && p=""
            pub_prefixes+=("$p")
        done
    done

    local out="$WORK/$name.pub.out" err="$WORK/$name.pub.err"
    : >"$out"
    timeout 180 "$PUB_BIN" "$endpoint" "${#groups[@]}" "${pub_prefixes[@]}" >"$out" 2>"$err" &
    local pub_pid=$!
    local bound="" i
    for i in $(seq 1 200); do
        bound="$(sed -n 's/^ENDPOINT //p' "$out")"
        [[ -n "$bound" ]] && break
        sleep 0.05
    done
    if [[ -z "$bound" ]]; then
        kill "$pub_pid" 2>/dev/null || true
        record "$name FAIL (publisher did not bind; see $err)"
        FAILED=1
        return
    fi
    # A wildcard bind is reached through loopback.
    bound="${bound/tcp:\/\/0.0.0.0:/tcp://127.0.0.1:}"

    local pids=() k=0 args
    for g in "${groups[@]}"; do
        IFS=, read -ra ps <<<"$g"
        args=()
        for p in "${ps[@]}"; do
            [[ "$p" == "-" ]] && p=""
            args+=("$p")
        done
        timeout 120 "$client" "$bound" "${args[@]}" >"$WORK/$name.client$k.log" 2>&1 &
        pids+=($!)
        k=$((k + 1))
    done
    local ok=1 pid
    for pid in "${pids[@]}"; do
        wait "$pid" || ok=0
    done
    wait "$pub_pid" || ok=0
    if ((ok)); then
        record "$name PASS ($(cat "$WORK/$name".client*.log | tr '\n' ' '))"
    else
        record "$name FAIL (logs in $WORK/$name.*)"
        FAILED=1
    fi
}

if [[ -n "$PYZMQ" ]]; then
    run_case pyzmq-tcp-all "tcp://127.0.0.1:0" "$PYZMQ" -
    run_case pyzmq-tcp-star "tcp://*:0" "$PYZMQ" -
    # Umbrel's layout: one connection per topic.
    run_case pyzmq-tcp-per-topic "tcp://127.0.0.1:0" "$PYZMQ" rawblock rawtx hashblock sequence
    run_case pyzmq-ipc "ipc://$IPC_DIR/pyzmq.sock" "$PYZMQ" hash,raw
fi
if [[ -n "$GOZMQ" ]]; then
    # LND's layout: rawblock and rawtx on separate connections.
    run_case gozmq-tcp-lnd "tcp://127.0.0.1:0" "$GOZMQ" rawblock rawtx
    run_case gozmq-tcp-all "tcp://127.0.0.1:0" "$GOZMQ" -
    run_case gozmq-ipc "ipc://$IPC_DIR/gozmq.sock" "$GOZMQ" -
fi
record "chumak  NOT RUN (no automated chumak client)"

# The publisher removes its socket files; the directory is left empty.
[[ -z "${ZMQ_INTEROP_IPC_DIR:-}" ]] && rmdir "$IPC_DIR" 2>/dev/null || true

echo
echo "== summary (work dir $WORK)"
printf '%s\n' "${RESULTS[@]}"
exit "$FAILED"
