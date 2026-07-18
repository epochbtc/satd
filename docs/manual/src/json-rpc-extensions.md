# JSON-RPC Extensions

satd preserves Bitcoin Core's JSON-RPC contract by default — the same method
names, response field names, and types — so existing clients work unchanged.
On top of that, satd adds a handful of **opt-in** extensions for developers and
integrators. Each is either enabled by a server flag (and is therefore
live-reloadable over `SIGHUP`) or exposed as an additional method or parameter;
none of them alters the default Core-compatible wire shape. All are governed by
the
[stability policy](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md),
and the authoritative, exhaustive catalogue of where satd differs from Core is
[`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md).

For the push-based event firehose and cursor-resumable watch subscriptions
(gRPC / WebSocket / SSE / ZMQ), see the
[Streaming Consumption API](streaming.md) chapter — a distinct surface from the
JSON-RPC extensions here.

> **Authentication.** JSON-RPC keeps Bitcoin Core's cookie / `rpcuser` / `rpcauth`
> credentials by default; capability-scoped bearer tokens (`-rpcauthbearer`,
> `rpc:read` / `rpc:write`) are an opt-in addition. See
> [Authentication & Authorization](authentication.md).

## Satoshis-as-integers

Bitcoin Core emits every amount as an IEEE-754 double in whole BTC
(`0.00001000`), which loses precision near dust and at the supply boundary —
Core's long-standing [#3249](https://github.com/bitcoin/bitcoin/issues/3249),
open since 2013. satd can instead emit exact integer satoshis.

This is a **server-wide default**, `--rpc-default-units=sats|btc`
(`rpcdefaultunits` in the config file), not a per-request flag. It defaults to
`btc`, where output is **byte-identical** to Core (a fixed 8-decimal number,
formatted from the integer satoshi value so it is exact). Set it to `sats` and
amounts serialize as JSON integers everywhere; in that mode responses also carry
a `_units: "sats"` tag so a client can confirm the shape it received (the tag is
absent in the default `btc` mode to stay byte-for-byte compatible). The setting
is live-reloadable. A per-request HTTP-header override is a planned follow-up.

## Structured RPC errors

By default, error responses are byte-identical to Core's `{code, message}`. With
`--rpc-extended-errors` (`rpcextendederrors`; default off, live-reloadable)
enabled server-wide, satd additionally populates the JSON-RPC `data` object with
machine-actionable fields:

- `category` — a stable, dashboard-friendly taxonomy string
  (e.g. `mempool.policy.feerate`, `validation.consensus`, `storage.not_found`).
- `suggestion` — a concrete remediation hint, when one applies.
- `debug` — arbitrary structured detail (field positions, computed values),
  when present.

Category names are stable once shipped in a release — only new names are added,
existing ones never change meaning. As with the units default, this is a
server-wide switch (the common deployment pattern is satd driven only by
satd-aware tooling); a per-request `X-Satd-Extended-Errors` header is a planned
follow-up.

## Fee estimation

Core's `estimatesmartfee conf_target [estimate_mode]` is kept with its exact
response shape (`{feerate, blocks, errors}`) and is Core-compatible by default.
Beyond Core's `economical` / `conservative` / `unset` vocabulary (all treated as
the historical estimator), the optional mode argument additionally accepts
satd's own `historical` / `mempool` / `blend` values.

Alongside it, satd adds an `estimatefees [targets] [mode]` RPC (default mode
`blend`, default targets `[1, 3, 6, 12, 24]`). It simulates the next-N block
templates from the *current* mempool with ancestor-feerate (CPFP-aware) package
sorting, and **never hard-errors** — it always returns a result. The response
maps each target to a `{feerate, confidence}` pair (`confidence` is
`high | medium | low`) and includes a feerate histogram. This is the basis for
Core's [#11500](https://github.com/bitcoin/bitcoin/issues/11500).

## Mempool subscription stream

`subscribemempool` is a JSON-RPC WebSocket subscription (paired with
`unsubscribemempool`) emitting structured lifecycle events, each tagged by a
`kind` field:

*   `enter` — a transaction was admitted to the mempool.
*   `leave_confirmed` — it was confirmed in a block.
*   `leave_evicted` — it was dropped, with an explicit `reason`
    (`full_pool` | `expiry`).
*   `leave_replaced` — it was RBF-replaced, carrying the `replacing_txid`.

Where Bitcoin Core requires polling `getrawmempool` or rebuilding state from
per-tx ZMQ frames, this stream carries explicit eviction reasons and RBF
replacement linkage directly. For the richer firehose with cursor replay, see
the [Streaming Consumption API](streaming.md); `subscribemempool` is the
lightweight JSON-RPC option.

## Silent-payment block data

`getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` returns the
public BIP 352 tweak data for one block, from the tweak index
(`-silentpaymentindex=1`, default off). It is the JSON-RPC fallback for the
streaming `tweaks` category — the same bytes, for scripts, the
reference-implementation differential, and integrators not yet on an SDK.

*   `verbosity 0` (default) → `{ "block_hash", "height", "tweaks": ["<33-byte
    hex>", …] }`.
*   `verbosity 1` → each entry becomes `{ "txid", "tweak", "max_value" }`.
*   `dust_limit` (sats, default `0`) drops entries whose largest taproot output
    value is below the floor.

Errors: `-5` for an unknown or non-active block, `-8` when the index is
disabled, and `-1` when the block is not yet indexed at that height (the row is
absent — a height-by-height scanner cannot proceed past a gap, but unlike BIP
157 it cannot silently miss its own outputs either). The method is read-only. A
light client runs one ECDH per returned tweak locally, so the scan key never
reaches the node; for the streaming firehose with cursor replay, see the
[Streaming Consumption API](streaming.md).

## Client-side PSBT signing (no signing RPC)

By design there is **no signing RPC** — the `satd` daemon never handles private
keys. Signing is instead a client-side `sat-cli` command:
`sat-cli signpsbtwithkey` reads a WIF private key or a BIP-32 xpriv from
**stdin** (prompting without echo when stdin is a terminal) and signs the PSBT
entirely locally, using only the prevout data already carried in the PSBT. It
covers the common single-sig script types — Legacy, SegWit v0, nested SegWit,
and Taproot key-path — and writes `partial_sigs` / `tap_key_sig` for the node's
`finalizepsbt` to assemble, rather than finalizing itself. An xpriv is expanded
over the standard BIP 44/49/84/86 paths so it can sign PSBTs that carry no
derivation metadata (including satd's own `createpsbt` output). Because the key
never crosses the JSON-RPC boundary, the daemon stays strictly keyless.
