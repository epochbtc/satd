#!/usr/bin/env bash
# Regenerate core_v32_1_decodepsbt.json: Bitcoin Core v32.1's own decodepsbt
# output for PSBTs its wallet builds, at each stage of signing.
#
# Start a throwaway, empty regtest bitcoind v32.1 first, then run
#
#     BITCOIN_CLI="bitcoin-cli -regtest -datadir=<dir>" \
#         ./gen_core_v32_1_decodepsbt.sh > core_v32_1_decodepsbt.json
#
# Keys are the wallet's own, so every run gives different PSBTs; what the
# test checks is that satd decodes each one as Core does. Needs jq.
set -euo pipefail
read -r -a C <<< "${BITCOIN_CLI:-bitcoin-cli -regtest}"
W() { local w=$1; shift; "${C[@]}" -rpcwallet="$w" "$@"; }

"${C[@]}" createwallet w >/dev/null
"${C[@]}" createwallet a >/dev/null
"${C[@]}" createwallet b >/dev/null
MINER=$(W w getnewaddress)
W w generatetoaddress 110 "$MINER" >/dev/null

A_PKH=$(W a getnewaddress "" legacy)
A_SH=$(W a getnewaddress "" p2sh-segwit)
A_WPKH=$(W a getnewaddress "" bech32)
A_TR=$(W a getnewaddress "" bech32m)
A_PKH2=$(W a getnewaddress "" legacy)
A_WPKH2=$(W a getnewaddress "" bech32)
PKA=$(W a getaddressinfo "$(W a getnewaddress "" bech32)" | jq -r .pubkey)
PKB=$(W b getaddressinfo "$(W b getnewaddress "" bech32)" | jq -r .pubkey)
MS=$("${C[@]}" createmultisig 2 "[\"$PKA\",\"$PKB\"]" bech32)
MS_ADDR=$(jq -r .address <<< "$MS")
MS_DESC=$(jq -r .descriptor <<< "$MS")
for a in "$A_PKH" "$A_SH" "$A_WPKH" "$A_TR" "$MS_ADDR" "$A_PKH2" "$A_WPKH2"; do
    W w sendtoaddress "$a" 1.0 >/dev/null
done
W w generatetoaddress 1 "$MINER" >/dev/null
DEST=$(W w getnewaddress "" bech32)

utxo() { "${C[@]}" scantxoutset start "[\"addr($1)\"]" | jq -c '.unspents[0] | {txid, vout}'; }

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
save() {
    jq -c -n --arg name "$1" --arg psbt "$2" --argjson core "$("${C[@]}" decodepsbt "$2")" \
        '{($name): {psbt: $psbt, core: $core}}' >> "$OUT"
}

# One input of each type, signed by its own wallet. createpsbt's fifth and
# sixth arguments are the transaction and PSBT versions.
for psbt_version in 0 2; do
    for t in PKH SH WPKH TR; do
        eval addr=\$A_$t
        p=$("${C[@]}" createpsbt "[$(utxo "$addr")]" "[{\"$DEST\":0.9999}]" 0 true 2 $psbt_version)
        save "v${psbt_version}_${t}_0_created" "$p"
        p=$(W a walletprocesspsbt "$p" false ALL true false | jq -r .psbt)
        save "v${psbt_version}_${t}_1_updated" "$p"
        p=$(W a walletprocesspsbt "$p" true ALL true false | jq -r .psbt)
        save "v${psbt_version}_${t}_2_signed" "$p"
        p=$(W a walletprocesspsbt "$p" true ALL true true | jq -r .psbt)
        save "v${psbt_version}_${t}_3_final" "$p"
    done

    # P2WSH 2-of-2: updated from the descriptor, then each key signs.
    p=$("${C[@]}" createpsbt "[$(utxo "$MS_ADDR")]" "[{\"$DEST\":0.9999}]" 0 true 2 $psbt_version)
    save "v${psbt_version}_MS_0_created" "$p"
    p=$("${C[@]}" utxoupdatepsbt "$p" "[\"$MS_DESC\"]")
    save "v${psbt_version}_MS_1_updated" "$p"
    p=$(W a walletprocesspsbt "$p" true ALL true false | jq -r .psbt)
    save "v${psbt_version}_MS_2_signed_a" "$p"
    p=$(W b walletprocesspsbt "$p" true ALL true false | jq -r .psbt)
    save "v${psbt_version}_MS_3_signed_ab" "$p"
    p=$("${C[@]}" finalizepsbt "$p" false | jq -r .psbt)
    save "v${psbt_version}_MS_4_final" "$p"

    # Funded by the wallet: several input types, a bech32m change output with
    # its taproot derivation.
    p=$(W a walletcreatefundedpsbt "[]" "[{\"$DEST\":2.5}]" 0 \
        '{"change_type":"bech32m"}' true 2 $psbt_version | jq -r .psbt)
    save "v${psbt_version}_MIX_0_funded" "$p"
    p=$(W a walletprocesspsbt "$p" true ALL true false | jq -r .psbt)
    save "v${psbt_version}_MIX_1_signed" "$p"
    p=$(W a walletprocesspsbt "$p" true ALL true true | jq -r .psbt)
    save "v${psbt_version}_MIX_2_final" "$p"

    # SINGLE|ANYONECANPAY on a legacy and a segwit input: the final scriptSig's
    # asm names the sighash.
    p=$("${C[@]}" createpsbt "[$(utxo "$A_PKH2"),$(utxo "$A_WPKH2")]" \
        "[{\"$DEST\":0.5},{\"$MINER\":1.4}]" 0 true 2 $psbt_version)
    p=$(W a walletprocesspsbt "$p" true "SINGLE|ANYONECANPAY" true false | jq -r .psbt)
    save "v${psbt_version}_SIGHASH_1_signed" "$p"
    p=$("${C[@]}" finalizepsbt "$p" false | jq -r .psbt)
    save "v${psbt_version}_SIGHASH_2_final" "$p"
done

jq --indent 1 -s 'add | {"bitcoin_core": "v32.1", "network": "regtest", "decodepsbt": .}' "$OUT"
