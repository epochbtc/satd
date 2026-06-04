# MCP Server

satd ships a native **Model Context Protocol** server (the `mcp` crate, built on
`rmcp`) that exposes the node's query, ops, and transaction-construction surfaces
as MCP **tools** for AI agents and other MCP clients. It lets an LLM-driven client
inspect chain/mempool/peer state, estimate fees, decode and build transactions,
and run operator actions through a structured, typed tool interface instead of
raw JSON-RPC.

It is **off by default** — enable it with `--mcp`.

## Transports

| Transport | Enable | Bind / default | Notes |
|---|---|---|---|
| **stdio** | `--mcpstdio` (on by default when `--mcp` is set) | stdin/stdout | Local process only; no network auth. |
| **Streamable HTTP** (+ legacy SSE) | set `--mcpport` | `--mcpbind`, default `127.0.0.1` | Network transport; gated by auth for remote use. |

Both transports run on satd's **core (consensus) tokio runtime**, not the
isolated API runtime — deliberately, because MCP exposes block-connecting and
broadcast tools (see *Posture* below).

## Authentication

MCP uses the [unified auth system](authentication.md):

- **Loopback default** — with `--mcpauth` off, the HTTP server performs no
  per-request auth check (loopback-trust). stdio is always local/unauthenticated.
- **Bearer** — `--mcpauth` (which requires `--authfile`) requires
  `Authorization: Bearer <token>` resolving to a principal that holds the
  **`mcp:*`** capability; otherwise the server returns `401` with
  `WWW-Authenticate: Bearer`, and applies the token's rate limit (`429` +
  `Retry-After` on throttle).
- **Remote exposure is gated** — a non-loopback `--mcpbind` requires
  `--mcpallowremote`, which requires `--mcpauth`, which requires `--authfile`.
  satd refuses to start a routable MCP listener that isn't authenticated.

MCP is gated by the **single** `mcp:*` capability — there is no read-only-vs-
mutating split inside MCP, so any token with `mcp:*` can call **every** tool.

## Posture: MCP is not read-only

Unlike a pure query API, MCP exposes **state-changing** tools — `send_transaction`
(broadcasts to the network), `generate_blocks` (mines/connects blocks; regtest),
and `manage_peer` (disconnect/ban/unban/add), plus transaction
construction/signing. Treat an `mcp:*` token as a privileged credential, keep the
HTTP transport loopback-bound unless you've deliberately authenticated it, and
prefer stdio for a co-located agent.

## Tools

The server registers the following tools (each returns a text result).

### Node status / ops
- `get_node_status` — chain height, sync progress, mempool summary, peers, difficulty, uptime.
- `get_system_info` — process RSS, UTXO-cache stats, DB info.
- `get_config` — effective post-merge config (secrets redacted).
- `get_metrics_snapshot` — current Prometheus metrics as text.
- `get_health` / `get_readiness` — liveness / readiness (mirror `/healthz` & `/readyz`).
- `get_reorg_history` — persisted reorg events. Param: `since_secs` (default 86400).

### Blockchain / block
- `get_block` — block by hash or height. Params: `identifier`, `verbosity` (`summary`/`full`/`raw`).
- `get_block_header` — header by hash or height. Params: `identifier`, `raw`.
- `get_block_stats` — fees, sizes, tx counts, UTXO/SegWit stats. Param: `identifier`.
- `get_chain_info` — tips, tx rate over a window, difficulty. Param: `window` (default 30).
- `search_block_range` — headers for a range (max 100). Params: `start_height`, `end_height`.

### Transaction (query / decode)
- `get_transaction` — lookup by `txid` (chain + mempool); optional `blockhash` hint.
- `decode_raw_transaction` — decode hex tx to JSON. Param: `hex_tx`.
- `decode_script` — decode a hex script (opcodes/type/addresses). Param: `hex_script`.

### Mempool
- `get_mempool_overview` — size, byte usage, fee histogram, policy.
- `list_mempool_transactions` — list with `sort_by` (`fee_rate`/`time`/`size`), `limit` (≤100), `min_fee_rate`.
- `get_mempool_entry` — one tx; optional `include_relatives` (ancestors/descendants).
- `get_mempool_entries_bulk` — detail for many `txids` (missing → null).
- `get_mempool_history` — windowed snapshots. Param: `since_secs` (default 3600).
- `subscribe_mempool_snapshot` — most recent mempool events. Param: `limit` (≤50).

### Fees
- `estimate_fee` — rates for multiple `targets` (default `[1,3,6,12,25]`), in BTC/kvB and sat/vB.

### Network / peers
- `get_peer_info` — connected peers. Param: `summary` (default true).
- `manage_peer` — **mutating:** `add` / `disconnect` / `ban` / `unban`. Params: `action`, `address`.
- `get_ban_list` — banned peers with timestamps/reasons.

### Transaction construction (mutating)
- `create_transaction` — build an unsigned raw tx. Params: `inputs`, `outputs`, `locktime`.
- `sign_transaction` — sign with WIF keys client-side. Params: `hex_tx`, `private_keys`, `prevtxs`, `sighash`.
- `send_transaction` — **broadcast** a signed raw tx. Param: `hex_tx`.
- `psbt_workflow` — PSBT `create`/`decode`/`analyze`/`combine`/`finalize`/`update`/`convert`/`join`.

### Mining
- `get_mining_info` — difficulty, network hashrate, height.
- `generate_blocks` — **mine blocks (regtest only).** Params: `count`, `address`.
- `get_block_template` — mining template.

### UTXO / address
- `get_utxo` — single UTXO by `txid`/`vout` (null if spent).
- `get_utxo_set_stats` — total UTXOs, total value, best block.
- `validate_address` — validate + classify (P2PKH/P2SH/P2WPKH/P2WSH/P2TR), script hex, witness info.
