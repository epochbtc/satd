# JSON-RPC Extensions

satd preserves Bitcoin Core's JSON-RPC contract by default: the same method
names, response field names, and types, so existing clients work unchanged.
On top of that, satd adds opt-in extensions for developers and integrators.
Each extension is either enabled by a server flag (and is therefore
live-reloadable over `SIGHUP`) or exposed as an additional method or
parameter. None of them alters the default Core-compatible wire shape. All
are governed by the
[stability policy](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md).
The authoritative catalogue of where satd differs from Core is
[`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md).

For the push-based event firehose and cursor-resumable watch subscriptions
(gRPC, WebSocket, SSE, ZMQ), see the
[Streaming Consumption API](streaming.md) chapter. That is a distinct
surface from the extensions described here.

> **Note.** JSON-RPC keeps Bitcoin Core's cookie / `rpcuser` / `rpcauth`
> credentials by default. Capability-scoped bearer tokens (`-rpcauthbearer`,
> `rpc:read` / `rpc:write`) are an opt-in addition. See
> [Authentication & Authorization](authentication.md).

## Satoshis-as-integers

Bitcoin Core emits every amount as an IEEE-754 double in whole BTC
(`0.00001000`), which loses precision near dust and at the supply boundary.
This is Core's long-standing
[#3249](https://github.com/bitcoin/bitcoin/issues/3249), open since 2013.
satd can instead emit exact integer satoshis.

This is a server-wide default, `--rpc-default-units=sats|btc`
(`rpcdefaultunits` as a config key), not a per-request flag. The default is
`btc`, where output is byte-identical to Core: a fixed 8-decimal number,
formatted from the integer satoshi value so it is exact. Set it to `sats`
and amounts serialize as JSON integers everywhere. In that mode responses
also carry a `_units: "sats"` tag so a client can confirm the shape it
received. The tag is absent in the default `btc` mode, which stays
byte-for-byte compatible. The option is live-reloadable. A per-request
HTTP-header override is a planned follow-up.

## Structured RPC errors

By default, error responses are byte-identical to Core's `{code, message}`.
`--rpc-extended-errors` (`rpcextendederrors`; default off, live-reloadable)
is a server-wide option. With it enabled, satd additionally populates the
JSON-RPC `data` object with machine-actionable fields:

- `category`: a stable taxonomy string, for example
  `mempool.policy.feerate`, `validation.consensus`, `storage.not_found`.
- `suggestion`: a concrete remediation hint, when one applies.
- `debug`: arbitrary structured detail (field positions, computed values),
  when present.

Category names are stable once shipped in a release: new names can be
added, and existing ones never change meaning. As with the units default,
this is a server-wide option, since the common deployment pattern is satd
driven only by satd-aware tooling. A per-request `X-Satd-Extended-Errors`
header is a planned follow-up.

## Fee estimation

Core's `estimatesmartfee conf_target [estimate_mode]` is kept with its
exact response shape (`{feerate, blocks, errors}`) and is Core-compatible
by default. The optional mode argument accepts Core's `economical` /
`conservative` / `unset` vocabulary, all treated as the historical
estimator. It also accepts satd's own `historical` / `mempool` / `blend`
values.

satd also adds an `estimatefees [targets] [mode]` method (default mode
`blend`, default targets `[1, 3, 6, 12, 24]`). It simulates the next N
block templates from the current mempool, with ancestor-feerate
(CPFP-aware) package sorting. It never hard-errors; it always returns a
result. The response maps each target to a `{feerate, confidence}` pair,
where `confidence` is `high | medium | low`, and includes a feerate
histogram. This is the basis for Core's
[#11500](https://github.com/bitcoin/bitcoin/issues/11500).

## Mempool subscription stream

`subscribemempool` is a JSON-RPC WebSocket subscription, paired with
`unsubscribemempool`, that emits structured lifecycle events. Each event is
tagged by a `kind` field:

*   `enter`: a transaction was admitted to the mempool.
*   `leave_confirmed`: it was confirmed in a block.
*   `leave_evicted`: it was dropped, with an explicit `reason`
    (`full_pool` | `expiry`).
*   `leave_replaced`: it was RBF-replaced, carrying the `replacing_txid`.

Bitcoin Core requires polling `getrawmempool` or rebuilding this state from
per-tx ZMQ frames. This stream carries explicit eviction reasons and RBF
replacement linkage directly. For the richer firehose with cursor replay,
see the [Streaming Consumption API](streaming.md); `subscribemempool` is
the lightweight JSON-RPC option.

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

There is no signing method: satd never handles private keys. Signing is a
client-side `sat-cli` command.

`sat-cli signpsbtwithkey` reads a WIF private key or a BIP-32 xpriv from
stdin, prompting without echo when stdin is a terminal. It signs the PSBT
entirely locally, using only the prevout data already carried in the PSBT.
It covers the common single-sig script types (Legacy, SegWit v0, nested
SegWit, and Taproot key-path) and writes `partial_sigs` / `tap_key_sig` for
the node's `finalizepsbt` to assemble, rather than finalizing itself. An
xpriv is expanded over the standard BIP 44/49/84/86 paths, so it can sign
PSBTs that carry no derivation metadata, including satd's own `createpsbt`
output. The key never crosses the JSON-RPC boundary, so satd stays strictly
keyless.
