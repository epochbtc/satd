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
# resolves `<app>_<service>_1`, and an address would be whatever the bridge
# happened to hand out. (`10.21.0.0` here would be a network address, not a
# host at all.)
export APP_SATD_HOST="satd_server_1"
export APP_SATD_IP="satd_server_1"
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
export APP_SATD_RPC_COOKIE_FILE="${APP_DATA_DIR}/data/rpc-cookie"
