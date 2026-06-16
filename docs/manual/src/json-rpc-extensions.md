# JSON-RPC Extensions

satd preserves Bitcoin Core's JSON-RPC contract by default — the same method
names, response field names, and types — so existing clients work unchanged.
On top of that, satd adds a handful of **opt-in** extensions for developers and
integrators. Every extension below is either requested per-call or enabled by a
flag; none of them alter the default Core-compatible response shape, and all are
governed by the
[stability policy](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md).
The authoritative, exhaustive catalogue of where satd differs from Core is
[`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md);
this chapter is the operator-facing tour.

For the push-based event firehose and cursor-resumable watch subscriptions
(gRPC / WebSocket / SSE / ZMQ), see the
[Streaming Consumption API](streaming.md) chapter — a distinct surface from the
JSON-RPC extensions here.

> **Authentication.** JSON-RPC keeps Bitcoin Core's cookie / `rpcuser` / `rpcauth`
> credentials by default; capability-scoped bearer tokens (`-rpcauthbearer`,
> `rpc:read` / `rpc:write`) are an opt-in addition. See
> [Authentication & Authorization](authentication.md).

## Satoshis-as-integers

The default wire format keeps Core's BTC-as-doubles so existing clients are
unaffected. To avoid IEEE-754 rounding, a caller can pass `"amounts": "sats"`
on any request and receive exact integer satoshi values instead of BTC
decimals; the response echoes `"units": "sats"` so the caller can confirm the
mode it got. This closes Core's long-standing
[#3249](https://github.com/bitcoin/bitcoin/issues/3249).

## Structured RPC errors

Opt-in `category` / `suggestion` / `debug` fields on JSON-RPC error payloads,
for clients that want machine-actionable error handling. The default error
shape stays Core-compatible; the extra fields appear only when requested. The
category schema is a Tier-2 stability surface (see `STABILITY_POLICY.md`).

## Mempool-aware fee estimation

Core's `estimatesmartfee` is preserved **unchanged** (same inputs, same
response shape). Alongside it, satd adds an `estimatefees` RPC that simulates
the next-N block templates from the *current* mempool with CPFP-aware sorting.
It **never hard-errors** — it always returns a result with a
`confidence: low | medium | high` field rather than failing and breaking
downstream applications. This closes Core's
[#11500](https://github.com/bitcoin/bitcoin/issues/11500).

## Mempool subscription stream

`subscribemempool` is a JSON-RPC WebSocket subscription emitting structured
lifecycle events:

*   `enter` — a transaction was admitted to the mempool.
*   `leave_confirmed` — it was confirmed in a block.
*   `leave_evicted` — it was dropped, with an explicit `reason`
    (`full_pool` | `expiry`).
*   `leave_replaced` — it was RBF-replaced, with the `replacing_txid`.

Where Bitcoin Core requires polling `getrawmempool` or rebuilding state from
per-tx ZMQ frames, this stream carries explicit eviction reasons and RBF
replacement linkage directly. The richer firehose / cursor-replay surface is
the [Streaming Consumption API](streaming.md); `subscribemempool` is the
lightweight JSON-RPC option.

## Client-side PSBT signing (no signing RPC)

By design there is **no signing RPC** — the `satd` daemon never handles private
keys. Signing is instead a client-side `sat-cli` command:
`sat-cli signpsbtwithkey` reads a WIF or xpriv from **stdin** and signs Taproot
key-path, SegWit, or Legacy inputs locally. Because the key never crosses the
JSON-RPC boundary, the daemon stays strictly keyless while operators can still
sign PSBTs from their terminal.
