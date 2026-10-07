#!/bin/bash
# LND bitcoind-mode canary — runs a real LND node with satd as its
# `bitcoind` backend: JSON-RPC for chain queries, and Bitcoin Core's ZMQ
# topics (`-zmqpubrawblock` / `-zmqpubrawtx`) for new blocks and mempool
# transactions.
#
# The LND Neutrino canary covers LND as a light client over P2P. This one
# covers the full-node backend, which needs Core's raw ZMQ topics. satd
# binds them on separate ports, one per topic, the way Umbrel's `bitcoin`
# app exports them and LND's documentation configures them.
#
# Coverage:
#   - LND starts against satd's RPC and ZMQ and reports
#     `synced_to_chain: true` at satd's tip.
#   - A payment to an LND address, made outside LND, shows as an
#     unconfirmed balance before any block is mined. LND learns of mempool
#     transactions from `rawtx`, so this proves `rawtx` delivery.
#   - Mining exactly one block confirms it. LND learns of blocks from
#     `rawblock`; a publisher that held back the tail of a large message
#     until its next send would deliver this block only when a second one
#     arrived, and the deadline would pass first.
#
# The payment is funded from coinbases paid to P2SH(OP_TRUE), spendable
# with a one-byte script and no key: satd is keyless, and this keeps the
# canary free of a wallet.
#
# Pin: LND_IMAGE in scripts/canary/PINS, shared with the Neutrino canary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"
# shellcheck source=PINS
source "$SCRIPT_DIR/PINS"

LND_CONTAINER="satd-canary-lnd-bitcoind-$$"
LND_RPC_PORT=18710
LND_P2P_PORT=18712
# port_base 18700 → RPC 18700, P2P 18701, Esplora 18702, Electrum 18703.
PORT_BASE=18700
ZMQ_RAWBLOCK_PORT=18704
ZMQ_RAWTX_PORT=18705

RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"
export SATD_RPCUSER="$RPCUSER"
export SATD_RPCPASSWORD="$RPCPASSWORD"

# P2SH(OP_TRUE): hash160(0x51). Spent with scriptSig `01 51`.
ANYONE_DESC="raw(a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87)"
SATD_MINE_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then return 0; fi
        if [[ $attempt -eq 3 ]]; then echo "docker pull $image failed 3 times" >&2; return 1; fi
        echo "docker pull $image attempt $attempt failed; retrying in $((attempt * 2))s..."
        sleep $((attempt * 2))
    done
}

lncli() {
    docker exec "$LND_CONTAINER" lncli \
        --network=regtest --no-macaroons --rpcserver="127.0.0.1:$LND_RPC_PORT" "$@"
}

dump_lnd() {
    docker logs "$LND_CONTAINER" 2>&1 | tail -60 >&2 || true
}

cleanup() {
    docker rm -f "$LND_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

pull_with_retries "$LND_IMAGE"

# ── Boot satd: basic-auth RPC and one ZMQ port per topic ──
LND_DATADIR="$(mktemp -d -t satd-canary-lnd-bitcoind.XXXXXX)"
boot_satd "$LND_DATADIR" "$PORT_BASE" \
    --rpcuser="$RPCUSER" \
    --rpcpassword="$RPCPASSWORD" \
    --txindex \
    --zmqpubrawblock="tcp://127.0.0.1:$ZMQ_RAWBLOCK_PORT" \
    --zmqpubrawtx="tcp://127.0.0.1:$ZMQ_RAWTX_PORT" \
    --server

notifications="$(sat_cli getzmqnotifications)"
echo "satd ZMQ notifiers: $(jq -c . <<<"$notifications")"
[[ "$(jq length <<<"$notifications")" == "2" ]] || { echo "satd: ZMQ notifiers not bound" >&2; exit 1; }

# Spendable coinbases for the payment below (block 1 matures at 101), then a
# few more blocks to an unrelated address.
sat_cli generatetodescriptor 101 "$ANYONE_DESC" >/dev/null
sat_cli generatetoaddress 5 "$SATD_MINE_ADDR" >/dev/null
echo "satd mined to height $(sat_cli getblockcount)"

# ── Boot LND in bitcoind mode, pointed at satd ──
docker run -d --name "$LND_CONTAINER" --network=host "$LND_IMAGE" \
    --bitcoin.active --bitcoin.regtest --bitcoin.node=bitcoind \
    --bitcoind.rpchost="127.0.0.1:$RPC_PORT" \
    --bitcoind.rpcuser="$RPCUSER" --bitcoind.rpcpass="$RPCPASSWORD" \
    --bitcoind.zmqpubrawblock="tcp://127.0.0.1:$ZMQ_RAWBLOCK_PORT" \
    --bitcoind.zmqpubrawtx="tcp://127.0.0.1:$ZMQ_RAWTX_PORT" \
    --nobootstrap --noseedbackup --no-macaroons \
    --norest \
    --rpclisten="127.0.0.1:$LND_RPC_PORT" \
    --listen="127.0.0.1:$LND_P2P_PORT" \
    --debuglevel=info >/dev/null

echo "waiting for LND to come up..."
lnd_deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $lnd_deadline ]]; do
    if lncli getinfo >/dev/null 2>&1; then echo "LND RPC ready."; break; fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$LND_CONTAINER\$"; then
        echo "lnd: container exited unexpectedly" >&2
        dump_lnd
        exit 1
    fi
    sleep 2
done
lncli getinfo >/dev/null 2>&1 || { echo "lnd: RPC never came up" >&2; dump_lnd; exit 1; }

# ── 1. LND syncs to satd's tip ──
TIP="$(sat_cli getblockcount)"
echo "waiting for LND to sync to satd tip ($TIP)..."
sync_deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $sync_deadline ]]; do
    info="$(lncli getinfo 2>/dev/null || echo '{}')"
    if [[ "$(jq -r '.synced_to_chain // false' <<<"$info")" == "true" &&
          "$(jq -r '.block_height // 0' <<<"$info")" == "$TIP" ]]; then
        echo "ok: LND synced_to_chain=true at height $TIP"
        break
    fi
    sleep 2
done
info="$(lncli getinfo)"
if [[ "$(jq -r '.synced_to_chain' <<<"$info")" != "true" || "$(jq -r '.block_height' <<<"$info")" != "$TIP" ]]; then
    echo "lnd: did not sync to satd tip $TIP" >&2
    jq '{synced_to_chain, block_height}' <<<"$info" >&2
    dump_lnd
    exit 1
fi

# ── 2. A payment from outside LND shows unconfirmed: rawtx ──
LND_ADDR="$(lncli newaddress p2wkh | jq -r '.address')"
LND_SPK="$(sat_cli validateaddress "$LND_ADDR" | jq -r '.scriptPubKey')"
FUND_TXID="$(sat_cli getblock "$(sat_cli getblockhash 1)" | jq -r '.tx[0]')"
# The whole 50 BTC coinbase less a 0.001 BTC fee: a payment with no change.
PAY_SATS=4999900000
# createrawtransaction leaves the scriptSig empty; P2SH(OP_TRUE) needs its
# redeem script pushed (`01 51`). The empty script's length byte sits right
# after version (4 bytes), input count (1), txid (32) and vout (4).
unsigned="$(sat_cli createrawtransaction \
    "[{\"txid\":\"$FUND_TXID\",\"vout\":0,\"sequence\":4294967293}]" \
    "[{\"$LND_ADDR\":49.999}]")"
script_len_at=$(( (4 + 1 + 32 + 4) * 2 ))
[[ "${unsigned:$script_len_at:2}" == "00" ]] || { echo "unexpected unsigned tx layout: $unsigned" >&2; exit 1; }
signed="${unsigned:0:$script_len_at}020151${unsigned:$((script_len_at + 2))}"
PAY_TXID="$(sat_cli sendrawtransaction "$signed")"
echo "paid $PAY_SATS sat to LND address $LND_ADDR in $PAY_TXID (spk $LND_SPK)"

unconf_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $unconf_deadline ]]; do
    bal="$(lncli walletbalance 2>/dev/null || echo '{}')"
    if [[ "$(jq -r '.unconfirmed_balance // 0' <<<"$bal")" == "$PAY_SATS" ]]; then
        echo "ok: LND sees the payment unconfirmed, before any block (rawtx)"
        break
    fi
    sleep 1
done
bal="$(lncli walletbalance)"
if [[ "$(jq -r '.unconfirmed_balance' <<<"$bal")" != "$PAY_SATS" ]]; then
    echo "lnd: payment $PAY_TXID never showed unconfirmed; rawtx not delivered?" >&2
    jq . <<<"$bal" >&2
    dump_lnd
    exit 1
fi
[[ "$(sat_cli getblockcount)" == "$TIP" ]] || { echo "a block was mined during the rawtx check" >&2; exit 1; }

# ── 3. One block confirms it: rawblock, promptly ──
sat_cli generatetoaddress 1 "$SATD_MINE_ADDR" >/dev/null
NEW_TIP="$(sat_cli getblockcount)"
conf_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $conf_deadline ]]; do
    info="$(lncli getinfo 2>/dev/null || echo '{}')"
    bal="$(lncli walletbalance 2>/dev/null || echo '{}')"
    if [[ "$(jq -r '.block_height // 0' <<<"$info")" == "$NEW_TIP" &&
          "$(jq -r '.confirmed_balance // 0' <<<"$bal")" == "$PAY_SATS" ]]; then
        echo "ok: one block took LND to height $NEW_TIP and confirmed the payment (rawblock)"
        echo "lnd bitcoind canary: PASS"
        exit 0
    fi
    sleep 1
done

echo "lnd: block $NEW_TIP did not confirm $PAY_TXID in LND's wallet within the deadline" >&2
lncli getinfo | jq '{synced_to_chain, block_height}' >&2 || true
lncli walletbalance >&2 || true
dump_lnd
exit 1
