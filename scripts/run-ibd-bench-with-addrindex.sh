#!/usr/bin/env bash
# Address-index IBD benchmark: wraps `run-ibd-bench.sh` with the
# `--addressindex={0,1}` flag so operators can quantify the cost of
# enabling the index. Usage:
#
#   IBD_BENCH_DATADIR=/satd/bench-run-addr-off \
#     ADDRINDEX=0 ./scripts/run-ibd-bench-with-addrindex.sh
#
#   IBD_BENCH_DATADIR=/satd/bench-run-addr-on \
#     ADDRINDEX=1 ./scripts/run-ibd-bench-with-addrindex.sh
#
# Two consecutive runs (off vs on) using distinct datadirs let you
# diff IBD wall-clock and the post-run RocksDB stats. The numbers
# from those runs feed `docs/benches/address-index-ibd.md`.
#
# All other env knobs (TARGET_HEIGHT, IBD_BENCH_RPCPORT, …) are
# forwarded unchanged to run-ibd-bench.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDRINDEX="${ADDRINDEX:-1}"

case "$ADDRINDEX" in
    0|1) ;;
    *)
        echo "ADDRINDEX must be 0 or 1; got '$ADDRINDEX'" >&2
        exit 1
        ;;
esac

# Forward via IBD_BENCH_EXTRA_ARGS — the underlying script appends
# whatever's set there to the satd invocation.
export IBD_BENCH_EXTRA_ARGS="${IBD_BENCH_EXTRA_ARGS:-} --addressindex=${ADDRINDEX}"

echo "[bench] Launching IBD bench with --addressindex=${ADDRINDEX}"
echo "[bench] Datadir: ${IBD_BENCH_DATADIR:-/satd/bench-run}"
exec "$SCRIPT_DIR/run-ibd-bench.sh" "$@"
