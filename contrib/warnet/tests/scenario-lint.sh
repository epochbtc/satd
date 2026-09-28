#!/usr/bin/env bash
# Byte-compile the Warnet scenarios, and lint them with ruff when it is
# installed. The scenarios import Warnet's commander and test_framework,
# which only exist inside a Warnet project, so this checks syntax and style,
# not imports. The scenarios run for real in a Warnet cluster.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCEN="$HERE/../scenarios"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
for f in "$SCEN"/*.py; do
    python3 -c 'import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' \
        "$f" "$tmp/$(basename "$f")c"
    echo "  ok    $(basename "$f") compiles"
done
if command -v ruff > /dev/null 2>&1; then
    ruff check --select E,F,W,I --line-length 120 "$SCEN"
    echo "  ok    ruff"
fi
