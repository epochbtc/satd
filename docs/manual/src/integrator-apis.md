# Integrator APIs

Developer- and integrator-facing surfaces that go beyond Bitcoin Core's
JSON-RPC contract. These are satd extensions; the Core-compatible RPC methods
they build on remain governed by the
[stability policy](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md).

The push-based [streaming consumption
API](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md)
(gRPC / WebSocket / ZMQ, cursor-resumable watch subscriptions) is specified
separately as a forward-looking protocol spec.

> **Authentication.** JSON-RPC keeps Bitcoin Core's cookie / `rpcuser` / `rpcauth`
> credentials by default; capability-scoped bearer tokens (`-rpcauthbearer`,
> `rpc:read` / `rpc:write`) are an opt-in addition. See
> [Authentication & Authorization](authentication.md).

## Mempool-Based Fee Estimation

*   `estimatesmartfee` supports an optional `mode` param (`historical`, `mempool`, `blend`).
*   `satd` never hard-errors on fee estimation; it falls back to the min-relay floor with `confidence: low` rather than breaking downstream applications.

## Mempool Subscription Stream

*   `subscribemempool` JSON-RPC WS stream emitting structured events: `enter`, `leave_confirmed`, `leave_evicted`, and `leave_replaced`.
*   Includes explicit eviction reasons and RBF replacement linkage.

## Satoshis-as-Integers

*   To prevent IEEE 754 float precision errors, operators can pass `amounts=sats` to any RPC request to receive exact integer satoshi values instead of BTC decimals.

## Persistent Reorg Log & Webhook

*   A persistent, append-only JSONL log at `$datadir/<network>/reorg.log` (the network-specific datadir subdirectory; directly under `$datadir` only on mainnet) survives restarts.
*   Optional HTTP POST on reorgs via `--reorg-webhook=<url>`.

## Client-Side PSBT Signing

*   `sat-cli signpsbtwithkey` is a client-side command that reads a WIF or xpriv from **stdin** and signs Taproot key-path, SegWit, or Legacy inputs locally. Because the private key is never passed over JSON-RPC, the `satd` daemon stays strictly keyless while allowing operators to securely sign PSBTs via their CLI terminal.
