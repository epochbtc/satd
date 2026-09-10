# Exported to other Umbrel apps that want to use this node.
#
# The names mirror the official `bitcoin` app's, so an app that already
# knows how to find Bitcoin Core can find satd — satd speaks Core's JSON-RPC
# and reads Core's cookie format, so nothing else has to change.
#
# The RPC endpoint here is the plain one on the app network. That is the
# same posture the official app has, and the reason satd's TLS listener
# exists separately: TLS is for what leaves the device, and a private CA is
# not something other store apps can be taught to trust.
# The container's DNS name on the app network, not an address: Umbrel
# resolves `<app-id>_<service>_1`, and an address would be whatever the bridge
# happened to hand out. (`10.21.0.0` here would be a network address, not a
# host at all.)
#
# The app id carries the store's `epochbtc-` prefix, so the container name
# does too. umbreld only surfaces apps from a community store whose id starts
# with the store id, so this prefix is not cosmetic — without it the app is
# filtered out of the registry and never appears at all.
export APP_SATD_HOST="epochbtc-satd_server_1"
export APP_SATD_IP="epochbtc-satd_server_1"
export APP_SATD_RPC_PORT="8332"
export APP_SATD_P2P_PORT="${APP_SATD_P2P_PORT:-8333}"
export APP_SATD_ELECTRUM_PORT="50001"
export APP_SATD_ELECTRUM_TLS_PORT="50002"
export APP_SATD_ESPLORA_PORT="3000"
export APP_SATD_NETWORK="${APP_SATD_NETWORK:-mainnet}"

# Cookie authentication. satd writes the cookie under the network's
# subdirectory, and `rpc-cookie` is a stable symlink satd-init maintains to
# whichever path that is — so a dependent app needs one path rather than a
# per-network rule.
# `EXPORTS_APP_DIR`, not `APP_DATA_DIR`. Umbrel sources this file from
# `app-script`, which runs under `set -euo pipefail` and defines
# `EXPORTS_APP_DIR` (and `EXPORTS_APP_DATA_DIR`) for the app being sourced.
# `APP_DATA_DIR` is exported later, for the compose environment only, so
# naming it here is an unbound variable that aborts the whole install —
# not an empty string, and not a warning.
#
# Both resolve to `${UMBREL_ROOT}/app-data/<app-id>`, and the compose file
# mounts `${APP_DATA_DIR}/data`, so this is the same path the container sees
# at /var/lib/satd.
export APP_SATD_RPC_COOKIE_FILE="${EXPORTS_APP_DIR}/data/rpc-cookie"
