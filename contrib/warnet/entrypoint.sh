#!/bin/sh
# Zero-argument start for Warnet's chart, which cannot pass a command line.
# Supplies -datadir unless the caller already did, then runs satd under tini
# through the `bitcoind` symlink so the chart's `pidof bitcoind` probe matches.
set -eu
DATADIR="${BITCOIN_DATA:-/root/.bitcoin}"
mkdir -p "$DATADIR"
has_datadir=0
for a in "$@"; do
    case "$a" in
        -datadir=*|--datadir=*) has_datadir=1 ;;
    esac
done
[ "$has_datadir" = 1 ] || set -- "-datadir=$DATADIR" "$@"
exec /usr/bin/tini -- /usr/local/bin/bitcoind "$@"
