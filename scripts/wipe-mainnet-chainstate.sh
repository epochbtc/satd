#!/usr/bin/env bash
# Wipe /satd chainstate + blocks for a clean mainnet IBD.
#
# Use this only when you want to reset the entire mainnet datadir — e.g.
# after the reindex OOM corrupted local state and a full re-sync is
# easier than debugging the half-rebuilt chainstate.
#
# Preserves the filesystem root at /satd (just empties it) so the
# satd-mainnet.service mount/path doesn't need re-creating.

set -euo pipefail

DATADIR=/satd

if ! systemctl --user is-active --quiet satd-mainnet.service; then
    echo "satd-mainnet.service: inactive (ok to wipe)"
else
    echo "ERROR: satd-mainnet.service is active — stop it first:"
    echo "  systemctl --user stop satd-mainnet.service"
    exit 1
fi

if pgrep -f "[s]atd.*datadir=${DATADIR}" >/dev/null; then
    echo "ERROR: a satd process is using ${DATADIR} — kill it first:"
    pgrep -af "[s]atd.*datadir=${DATADIR}"
    exit 1
fi

echo
echo "About to wipe ${DATADIR} contents."
echo "  Current usage:"
du -sh "${DATADIR}/blocks" "${DATADIR}/chainstate" 2>/dev/null | sed 's/^/    /'
echo
read -r -p "Type 'wipe' to confirm: " CONFIRM
if [[ "${CONFIRM}" != "wipe" ]]; then
    echo "aborted."
    exit 1
fi

# Keep bench-run/ and any other non-chain subdirs around — the operator
# may have other state there.
for sub in blocks chainstate mempool_history.log reorg.log .clean_shutdown .cookie; do
    target="${DATADIR}/${sub}"
    if [[ -e "${target}" ]]; then
        echo "rm -rf ${target}"
        rm -rf "${target}"
    fi
done

echo
echo "Wiped. ${DATADIR} now:"
ls -la "${DATADIR}" | sed 's/^/    /'

echo
echo "Next steps:"
echo "  systemctl --user start satd-mainnet.service"
echo "  journalctl --user -u satd-mainnet.service -f"
