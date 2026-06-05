# MCP Server

satd ships a native **Model Context Protocol** server (the `mcp` crate, built on
`rmcp`) that exposes the node's query, ops, and transaction-construction surfaces
as MCP **tools** for AI agents and other MCP clients. It lets an LLM-driven client
inspect chain/mempool/peer state, estimate fees, decode and build transactions,
and run operator actions through a structured, typed tool interface instead of
raw JSON-RPC.

It is **off by default** — enable it with `--mcp` plus `--mcpport`.

## Transport

MCP is served over a single **Streamable HTTP** listener (which also serves
legacy SSE clients). There is no stdio transport: the MCP server is part of the
running `satd` process, so clients attach to an already-running daemon over the
network rather than launching their own node.

| Setting | Default | Notes |
|---|---|---|
| `--mcpport` | *(off)* | Port to serve MCP on; enables the listener. |
| `--mcpbind` | `127.0.0.1` | Bind address. Non-loopback requires auth **and** TLS. |
| `--mcpcert` / `--mcpkey` | *(none)* | PEM cert/key — enables **HTTPS**. Required for any non-loopback bind. |
| `--mcpmtls` | `false` | Require client certs (mTLS). Needs `--mcpcert`/`--mcpkey` + `--mcpmtlsclientca`. |
| `--mcpmtlsclientca` | *(none)* | PEM CA bundle that client certs must chain to. |
| `--mcpmtlsclientallow` | *(any)* | Optional allowlist of client-cert CN / DNS-SAN values. |

The listener runs on satd's **core (consensus) tokio runtime**, not the isolated
API runtime — deliberately, because MCP exposes block-connecting and broadcast
tools (see *Posture* below).

## Transport security (TLS)

The MCP listener is plaintext HTTP only when bound to loopback. Set `--mcpcert`
and `--mcpkey` to serve **HTTPS** instead — this is **mandatory for any
non-loopback bind**, so a bearer token is never sent in cleartext over the
network. satd refuses to start a routable MCP listener without TLS.

TLS uses the same `tls_config` layer as the RPC / Esplora / Electrum surfaces
(hot-reloadable on `SIGUSR1`). For mutual TLS, add `--mcpmtls --mcpmtlsclientca
<ca.pem>`; clients without a cert that chains to the CA are rejected at the
handshake. Narrow further with `--mcpmtlsclientallow <CN>` (repeatable /
comma-separated). mTLS is **additive** — the `--mcpauth` bearer layer still runs
on top.

## Authentication

MCP uses the [unified auth system](authentication.md):

- **Loopback default** — with `--mcpauth` off, the server performs no per-request
  auth check (loopback-trust). Only valid for a loopback bind.
- **Bearer** — `--mcpauth` (which requires `--authfile`) requires
  `Authorization: Bearer <token>` resolving to a principal that holds the
  **`mcp:*`** capability; otherwise the server returns `401` with
  `WWW-Authenticate: Bearer`, and applies the token's rate limit (`429` +
  `Retry-After` on throttle).
- **Remote exposure is gated** — a non-loopback `--mcpbind` requires
  `--mcpallowremote` (→ `--mcpauth` → `--authfile`) **and** TLS
  (`--mcpcert`/`--mcpkey`). satd refuses to start a routable MCP listener that
  isn't both authenticated and encrypted.

MCP is gated by the **single** `mcp:*` capability — there is no read-only-vs-
mutating split inside MCP, so any token with `mcp:*` can call **every** tool.

## Posture: MCP is not read-only

Unlike a pure query API, MCP exposes **state-changing** tools — `send_transaction`
(broadcasts to the network), `generate_blocks` (mines/connects blocks; regtest),
and `manage_peer` (disconnect/ban/unban/add), plus transaction
construction/signing. Treat an `mcp:*` token as a privileged credential, and keep
the listener loopback-bound unless you've deliberately put auth **and** TLS in
front of it.

## Connecting a client

Enable the listener on the node, then point the client at the URL.

### Enable the listener

In `bitcoin.conf`:

```ini
mcp=1
mcpport=18888
# mcpbind=127.0.0.1   # default: loopback only
```

or on the command line:

```sh
satd --datadir=/path/to/node --mcp --mcpport=18888
```

The server is then reachable at `http://127.0.0.1:18888/`. For remote use, add
TLS and auth — issue a token that holds the `mcp:*` capability:

```sh
satd --datadir=/path/to/node --mcp --mcpport=18888 \
  --mcpbind=0.0.0.0 --mcpallowremote \
  --mcpauth --authfile=/etc/satd/auth.toml \
  --mcpcert=/etc/satd/mcp.crt --mcpkey=/etc/satd/mcp.key
```

The server is then reachable at `https://NODE_HOST:18888/`. Clients
authenticate with an `Authorization: Bearer <token>` header. See
[Authentication](#authentication) and [Transport security](#transport-security-tls).

### Claude Code

```sh
# Loopback daemon, no auth:
claude mcp add --transport http satd http://127.0.0.1:18888/

# Authenticated, TLS daemon — pass the bearer token as a header:
claude mcp add --transport http satd https://NODE_HOST:18888/ \
  --header "Authorization: Bearer YOUR_TOKEN"
```

Append `--scope project` to write a shared, committable `.mcp.json` instead of
your personal config; inspect with `claude mcp list` and the in-session `/mcp`.
The equivalent `.mcp.json` entry:

```json
{
  "mcpServers": {
    "satd": {
      "type": "http",
      "url": "https://NODE_HOST:18888/",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}
```

### Codex CLI

Add to `~/.codex/config.toml` (or `.codex/config.toml` in a trusted project):

```toml
[mcp_servers.satd]
url = "https://NODE_HOST:18888/"
# Authenticated daemon — supply the bearer token:
http_headers = { Authorization = "Bearer YOUR_TOKEN" }
```

> If you terminate TLS with a self-signed cert, configure the client to trust it
> (or front satd with a reverse proxy holding a CA-issued cert). mTLS clients
> additionally present their own cert/key per their MCP-client documentation.

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
