#!/usr/bin/env bash
# Regenerate tank0.conf and tank1.conf from Warnet's bitcoincore chart, so the
# compose test runs on exactly what the chart would mount. Run it after
# bumping the Warnet pin; a diff in the output is a change to the chart's
# bitcoin.conf that the lab image has to cope with.
#
#   contrib/warnet/tests/render-confs.sh                 # chart from the installed warnet package
#   WARNET_CHART=/path/to/charts/bitcoincore contrib/warnet/tests/render-confs.sh
#
# Requires helm and python3 with PyYAML; without WARNET_CHART, also warnet.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="${WARNET_CHART:-$(python3 -c 'from warnet.constants import BITCOIN_CHART_LOCATION as c; print(c)')}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

render() { # <release> [addnode]
    printf 'image: {repository: satd-warnet, tag: "0.6.0-warnet0"}\n' > "$tmp/values.yaml"
    [ -z "${2:-}" ] || printf 'addnode: [%s]\n' "$2" >> "$tmp/values.yaml"
    helm template "$1" "$CHART" -f "$tmp/values.yaml" | python3 -c '
import sys, yaml
for doc in yaml.safe_load_all(sys.stdin):
    if doc and doc.get("kind") == "ConfigMap":
        sys.stdout.write(doc["data"]["bitcoin.conf"])'
}
render tank0 > "$HERE/tank0.conf"
render tank1 tank0 > "$HERE/tank1.conf"
echo "rendered $HERE/tank0.conf and $HERE/tank1.conf from $CHART"
