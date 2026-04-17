#!/usr/bin/env python3
"""Extract a mainnet block + all its input prevouts into a JSON fixture
for real-block benchmarks.

Usage:
    extract_block.py <height> <output-path>
              [--rpc URL]           default http://127.0.0.1:18880/
              [--cookie PATH]       default /satd/.cookie
              [--rpcuser USER]      optional (if set, --rpcpassword required)
              [--rpcpassword PW]    optional

Requires satd (or any Bitcoin-Core-compatible node) running with txindex
enabled so it can resolve every input's prevout via getrawtransaction.

JSON is parsed with `parse_float=Decimal` so satoshi conversions don't
lose precision through a float round-trip.
"""
import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path
from urllib.request import Request, urlopen
from base64 import b64encode


def rpc(method, params, rpc_url, auth):
    req = Request(
        rpc_url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(auth.encode()).decode(),
        },
    )
    with urlopen(req, timeout=60) as r:
        body = json.loads(r.read().decode(), parse_float=Decimal)
    if body.get("error"):
        raise RuntimeError(f"{method} error: {body['error']}")
    return body["result"]


def btc_to_sats(value) -> int:
    """Convert a JSON numeric BTC value (parsed as Decimal) into satoshis
    without floating-point drift."""
    if not isinstance(value, Decimal):
        value = Decimal(str(value))
    return int((value * Decimal(10**8)).to_integral_value())


def resolve_auth(args) -> str:
    """Return the `user:password` string for Basic auth.

    Prefers explicit --rpcuser / --rpcpassword when both are provided;
    otherwise falls back to the cookie file at --cookie (which satd
    writes in the form `__cookie__:<hex>`)."""
    if args.rpcuser and args.rpcpassword:
        return f"{args.rpcuser}:{args.rpcpassword}"
    if args.rpcuser or args.rpcpassword:
        sys.exit("Error: --rpcuser and --rpcpassword must be used together")
    cookie_path = Path(args.cookie)
    if not cookie_path.exists():
        sys.exit(
            f"Error: cookie file {cookie_path} does not exist. "
            "Is satd running? Pass --cookie or use --rpcuser/--rpcpassword."
        )
    return cookie_path.read_text().strip()


def main():
    parser = argparse.ArgumentParser(
        description="Extract a block + its prevouts into a bench fixture JSON."
    )
    parser.add_argument("height", type=int, help="block height to extract")
    parser.add_argument("output_path", type=Path, help="destination JSON file")
    parser.add_argument(
        "--rpc",
        default="http://127.0.0.1:18880/",
        help="RPC URL (default: http://127.0.0.1:18880/)",
    )
    parser.add_argument(
        "--cookie",
        default="/satd/.cookie",
        help="cookie file path (default: /satd/.cookie)",
    )
    parser.add_argument("--rpcuser", help="explicit RPC username (overrides cookie)")
    parser.add_argument("--rpcpassword", help="explicit RPC password")
    args = parser.parse_args()

    auth = resolve_auth(args)

    block_hash = rpc("getblockhash", [args.height], args.rpc, auth)
    block_hex = rpc("getblock", [block_hash, 0], args.rpc, auth)
    block_meta = rpc("getblock", [block_hash, 1], args.rpc, auth)
    print(
        f"block height={args.height} hash={block_hash[:16]}... "
        f"txs={len(block_meta['tx'])} size={block_meta['size']}",
        file=sys.stderr,
    )

    # Walk each non-coinbase input, fetch its prevout via txindex.
    # Cache prev-tx lookups since many inputs may reference the same prev tx.
    prev_tx_cache = {}
    prevouts = {}
    for i, txid in enumerate(block_meta["tx"]):
        if i == 0:
            continue  # coinbase — no prevouts to resolve
        tx_info = rpc("getrawtransaction", [txid, True], args.rpc, auth)
        for vin in tx_info["vin"]:
            prev_txid = vin["txid"]
            prev_vout = vin["vout"]
            key = f"{prev_txid}:{prev_vout}"
            if key in prevouts:
                continue
            if prev_txid not in prev_tx_cache:
                prev_tx_cache[prev_txid] = rpc(
                    "getrawtransaction", [prev_txid, True], args.rpc, auth
                )
            prev_tx = prev_tx_cache[prev_txid]
            out = prev_tx["vout"][prev_vout]
            prevouts[key] = {
                "spk": out["scriptPubKey"]["hex"],
                "value": btc_to_sats(out["value"]),
            }
        if i % 50 == 0:
            print(
                f"  ...resolved {len(prevouts)} prevouts through tx {i}",
                file=sys.stderr,
            )

    fixture = {
        "height": args.height,
        "hash": block_hash,
        "block_hex": block_hex,
        "prevouts": prevouts,
    }
    args.output_path.write_text(json.dumps(fixture, separators=(",", ":")))
    print(
        f"wrote {args.output_path} ({args.output_path.stat().st_size} bytes, "
        f"{len(prevouts)} unique prevouts)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
