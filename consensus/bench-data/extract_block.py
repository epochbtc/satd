#!/usr/bin/env python3
"""Extract a mainnet block + all its input prevouts into a JSON fixture
for real-block benchmarks.

Usage: python3 extract_block.py <height> <output-path>
Requires satd running with txindex enabled (fetches prevouts via
getrawtransaction).
"""
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from base64 import b64encode


def rpc(method, params, cookie):
    req = Request(
        "http://127.0.0.1:18880/",
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(cookie.encode()).decode(),
        },
    )
    with urlopen(req, timeout=60) as r:
        body = json.loads(r.read().decode())
    if body.get("error"):
        raise RuntimeError(f"{method} error: {body['error']}")
    return body["result"]


def main():
    if len(sys.argv) != 3:
        print("usage: extract_block.py <height> <output-path>", file=sys.stderr)
        sys.exit(1)
    height = int(sys.argv[1])
    out_path = Path(sys.argv[2])
    cookie = Path("/satd/.cookie").read_text().strip()

    block_hash = rpc("getblockhash", [height], cookie)
    block_hex = rpc("getblock", [block_hash, 0], cookie)
    block_meta = rpc("getblock", [block_hash, 1], cookie)
    print(
        f"block height={height} hash={block_hash[:16]}... "
        f"txs={len(block_meta['tx'])} size={block_meta['size']}",
        file=sys.stderr,
    )

    # Walk each non-coinbase input, fetch its prevout via txindex.
    # Cache prev-tx lookups since many inputs in a block may reference the same prev tx.
    prev_tx_cache = {}
    prevouts = {}
    for i, txid in enumerate(block_meta["tx"]):
        if i == 0:
            continue  # coinbase — no prevouts to resolve
        tx_info = rpc("getrawtransaction", [txid, True], cookie)
        for vin in tx_info["vin"]:
            prev_txid = vin["txid"]
            prev_vout = vin["vout"]
            key = f"{prev_txid}:{prev_vout}"
            if key in prevouts:
                continue
            if prev_txid not in prev_tx_cache:
                prev_tx_cache[prev_txid] = rpc(
                    "getrawtransaction", [prev_txid, True], cookie
                )
            prev_tx = prev_tx_cache[prev_txid]
            out = prev_tx["vout"][prev_vout]
            prevouts[key] = {
                "spk": out["scriptPubKey"]["hex"],
                "value": int(round(out["value"] * 1e8)),
            }
        if i % 50 == 0:
            print(f"  ...resolved {len(prevouts)} prevouts through tx {i}", file=sys.stderr)

    fixture = {
        "height": height,
        "hash": block_hash,
        "block_hex": block_hex,
        "prevouts": prevouts,
    }
    out_path.write_text(json.dumps(fixture, separators=(",", ":")))
    print(
        f"wrote {out_path} ({out_path.stat().st_size} bytes, "
        f"{len(prevouts)} unique prevouts)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
