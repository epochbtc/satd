#!/bin/bash
# Esplora canary — exercises documented endpoints with raw curl + jq.
# Verifies wire-shape parity at the bytes/JSON level, independent of
# any Rust client library. If our Esplora server diverges from what
# blockstream.info / mempool.space publish, this catches it.
#
# Coverage:
#   GET /blocks/tip/height
#   GET /blocks/tip/hash
#   GET /block/:hash
#   GET /block/:hash/txid/:index
#   GET /address/:addr
#   GET /address/:addr/utxo
#   GET /address/:addr/txs
#   GET /tx/:txid
#   GET /tx/:txid/hex
#   GET /tx/:txid/outspends
#   POST /tx
#   GET /mempool
#   GET /fee-estimates
#
# Intentionally does NOT test SSE — long-poll behaviour in CI is
# noisy. The HTTP shape suite is the load-bearing protocol gate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

ESPLORA_DATADIR="$(mktemp -d -t satd-canary-esplora.XXXXXX)"
boot_satd "$ESPLORA_DATADIR" 18100 --esplora=1 --addressindex=1

ESPLORA="http://127.0.0.1:$ESPLORA_PORT"

# Deterministic P2WPKH regtest address derived from secret [0x11; 32].
# Matches the DeterministicWallet helper in satd/tests/e2e.rs so the
# two suites mine to the same address (eases manual log correlation).
# satd has no built-in wallet; we don't try to spend from this address
# in the canary — we just mine to it.
ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

# Helper: GET an endpoint, assert HTTP 200, return body.
expect_200() {
    local path="$1"
    local body
    if ! body=$(curl -sf --max-time 10 "$ESPLORA$path"); then
        echo "esplora: GET $path failed (non-200)" >&2
        return 1
    fi
    printf '%s' "$body"
}

# Helper: assert a JSON path matches an expected value (or the
# expected pattern matches). Use jq -e so a missing path errors.
expect_jq() {
    local body="$1"
    local jq_expr="$2"
    local label="$3"
    if ! jq -e "$jq_expr" <<< "$body" > /dev/null; then
        echo "esplora: jq check failed: $label" >&2
        echo "  body: $body" >&2
        echo "  expr: $jq_expr" >&2
        return 1
    fi
}

# Mine 110 blocks to the deterministic P2WPKH (COINBASE_MATURITY is
# 100 on regtest — by block 101+ the genesis coinbase is spendable,
# +9 headroom puts us solidly past).
echo "miner addr: $ADDR"
sat_cli generatetoaddress 110 "$ADDR" > /dev/null

# --- /blocks/tip/height : integer ---
HEIGHT=$(expect_200 "/blocks/tip/height")
if [[ "$HEIGHT" != "110" ]]; then
    echo "esplora: expected tip height 110, got '$HEIGHT'" >&2
    exit 1
fi
echo "ok: /blocks/tip/height == 110"

# --- /blocks/tip/hash : 64-char hex ---
TIP_HASH=$(expect_200 "/blocks/tip/hash")
if ! [[ "$TIP_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "esplora: tip hash is not 64-hex: '$TIP_HASH'" >&2
    exit 1
fi
echo "ok: /blocks/tip/hash"

# --- /block/:hash : JSON with id, height, version, timestamp, tx_count ---
BLOCK_JSON=$(expect_200 "/block/$TIP_HASH")
expect_jq "$BLOCK_JSON" '.id == "'"$TIP_HASH"'"' "block.id"
expect_jq "$BLOCK_JSON" '.height == 110' "block.height"
expect_jq "$BLOCK_JSON" '.version | type == "number"' "block.version is number"
expect_jq "$BLOCK_JSON" '.timestamp | type == "number"' "block.timestamp is number"
expect_jq "$BLOCK_JSON" '.tx_count >= 1' "block.tx_count >= 1"
echo "ok: /block/:hash shape"

# --- /block/:hash/txid/:index : coinbase txid ---
COINBASE_TXID=$(expect_200 "/block/$TIP_HASH/txid/0")
if ! [[ "$COINBASE_TXID" =~ ^[0-9a-f]{64}$ ]]; then
    echo "esplora: coinbase txid is not 64-hex: '$COINBASE_TXID'" >&2
    exit 1
fi
echo "ok: /block/:hash/txid/0 = $COINBASE_TXID"

# --- /address/:addr : JSON with chain_stats + mempool_stats ---
ADDR_JSON=$(expect_200 "/address/$ADDR")
expect_jq "$ADDR_JSON" '.address == "'"$ADDR"'"' "address.address"
expect_jq "$ADDR_JSON" '.chain_stats.funded_txo_count >= 1' "chain_stats.funded_txo_count"
expect_jq "$ADDR_JSON" '.chain_stats.funded_txo_sum > 0' "chain_stats.funded_txo_sum"
echo "ok: /address/:addr shape"

# --- /address/:addr/utxo : array of {txid, vout, value, status} ---
UTXOS=$(expect_200 "/address/$ADDR/utxo")
expect_jq "$UTXOS" 'length >= 1' "utxos non-empty"
expect_jq "$UTXOS" '.[0].txid | test("^[0-9a-f]{64}$")' "utxo.txid hex"
expect_jq "$UTXOS" '.[0].vout | type == "number"' "utxo.vout number"
expect_jq "$UTXOS" '.[0].value > 0' "utxo.value positive"
expect_jq "$UTXOS" '.[0].status.confirmed == true' "utxo.status.confirmed"
echo "ok: /address/:addr/utxo shape"

# --- /address/:addr/txs : array of {txid, status, ...} ---
ADDR_TXS=$(expect_200 "/address/$ADDR/txs")
expect_jq "$ADDR_TXS" 'length >= 1' "addr.txs non-empty"
echo "ok: /address/:addr/txs shape"

# --- /tx/:txid : JSON with vin, vout, status ---
TX_JSON=$(expect_200 "/tx/$COINBASE_TXID")
expect_jq "$TX_JSON" '.txid == "'"$COINBASE_TXID"'"' "tx.txid"
expect_jq "$TX_JSON" '.vin | length >= 1' "tx.vin"
expect_jq "$TX_JSON" '.vout | length >= 1' "tx.vout"
expect_jq "$TX_JSON" '.status.confirmed == true' "tx.status.confirmed"
echo "ok: /tx/:txid shape"

# --- /tx/:txid/hex : raw hex (no JSON wrapping) ---
TX_HEX=$(expect_200 "/tx/$COINBASE_TXID/hex")
if ! [[ "$TX_HEX" =~ ^[0-9a-f]+$ ]]; then
    echo "esplora: tx hex is not bare hex: '${TX_HEX:0:80}…'" >&2
    exit 1
fi
echo "ok: /tx/:txid/hex shape"

# --- /tx/:txid/outspends : array of {spent: bool} ---
OUTSPENDS=$(expect_200 "/tx/$COINBASE_TXID/outspends")
expect_jq "$OUTSPENDS" 'type == "array"' "outspends is array"
expect_jq "$OUTSPENDS" '.[0].spent == false' "coinbase tip outspend.spent == false"
echo "ok: /tx/:txid/outspends shape"

# Spend-and-broadcast of the matured coinbase needs key material —
# satd has no built-in wallet by design (`feedback_wallet_scope` rule:
# legacy Core wallet is excluded). The broadcast shape is exercised
# by tests/e2e.rs:test_e2e_esplora_post_tx_round_trip already
# (PR-gated via ci.yml) using a DeterministicWallet helper. What's
# unique-to-this-canary is the raw-HTTP-from-shell verification of
# the read endpoints above.

# --- /mempool : JSON with count, vsize, total_fee ---
MEMPOOL_JSON=$(expect_200 "/mempool")
expect_jq "$MEMPOOL_JSON" '.count | type == "number"' "mempool.count number"
echo "ok: /mempool shape"

# --- /fee-estimates : JSON map of conf-target → feerate ---
FEE_JSON=$(expect_200 "/fee-estimates")
expect_jq "$FEE_JSON" 'type == "object"' "fee-estimates is object"
echo "ok: /fee-estimates shape"

echo "esplora canary: PASS"
