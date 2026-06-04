# Authentication & Authorization

satd has **one** authentication model shared by every API surface — JSON-RPC,
Esplora, the streaming APIs (events gRPC + `streamws`), and the MCP server — plus
full backward compatibility with Bitcoin Core's cookie / `rpcuser` / `rpcauth`
credentials.

There are two layers, and understanding the split is the key to operating satd
safely:

1. **Core-compatible operator auth** — cookie file, `-rpcuser`/`-rpcpassword`,
   and `-rpcauth`. This is the **default** and behaves exactly like Bitcoin
   Core. It is **all-or-nothing**: a valid operator credential is the *operator*
   — full access to everything.
2. **The unified bearer-token layer** (`satd-auth`) — **opt-in**, capability-
   scoped, per-token rate-limited and quota-bounded bearer tokens loaded from an
   `-authfile`. This is what makes satd safe to expose to multiple,
   partially-trusted consumers (a BTCPay instance, a watchtower, an AI agent)
   without handing each one operator keys.

> **The default is pure Bitcoin Core.** With no `-authfile` configured, the
> bearer layer is entirely inert: the only credentials that work are the
> Core-compatible ones, and every authenticated request is the full-capability
> operator. You opt into scoped tokens deliberately, per surface. The capability
> gate is not even installed on a surface that has no bearer tokens enabled — it
> is a zero-cost no-op for the default path.

## How the bearer layer differs from Core-style auth

| | Core-style operator auth | Unified bearer tokens |
|---|---|---|
| **Credentials** | `.cookie` file, `-rpcuser`/`-rpcpassword`, `-rpcauth` (HMAC) | Opaque high-entropy tokens, presented as `Authorization: Bearer <token>` |
| **Granularity** | All-or-nothing — the *operator*, full access | Per-token **capabilities** (e.g. read-only, Esplora-only, stream-only) |
| **Multi-tenant** | No — one shared identity | Yes — many tokens, each with its own id, scope, quota, rate limit, expiry |
| **Rate / quota limits** | None (operator is unlimited) | Per-token request rate (`429`/`RESOURCE_EXHAUSTED`) and watch-set quota |
| **Where defined** | CLI flags / `bitcoin.conf` / generated cookie | A TOML `-authfile` (reloadable on `SIGHUP`) |
| **Default** | **On** (cookie auto-generated) | **Off** until `-authfile` is set *and* the surface opts in |
| **Compatibility** | Bitcoin Core wire-identical | satd extension |

Both coexist. On a bearer-enabled surface the **operator (Basic) credential is
tried first**, so existing Core tooling is never affected; a `Bearer` token is
consulted only when the request isn't a valid operator Basic credential. A
matching cookie / userpass / `rpcauth` always resolves to the full-capability
operator.

## Capabilities

A bearer token carries a set of capabilities; a surface enforces the one it
requires (fail-closed — an unknown method or a missing principal requires the
*write* capability, which a read-only token does not hold).

| Capability | String | Grants |
|---|---|---|
| RPC read | `rpc:read` | Read-only JSON-RPC methods (classified by the same table the read-only listener uses). |
| RPC write | `rpc:write` | Mutating / control / mining JSON-RPC, **and** any unclassified method (fail-closed). |
| Esplora read | `esplora:read` | The Esplora REST + SSE surface. |
| Stream subscribe | `stream:subscribe` | Open a streaming subscription (events gRPC, `streamws`). |
| Stream watch | `stream:watch` | Register outpoint/script/descriptor/txid watches (also bounded by the token's watch quota). |
| MCP | `mcp:*` | The MCP server (single capability — no per-tool split). |

The operator and loopback-trust principals implicitly hold **all** capabilities.

## The authfile

`-authfile=<path>` points at a TOML file of bearer tokens. The plaintext token is
**never stored** — only its SHA-256 digest.

```toml
version = 1

# Read-only integration: REST + Esplora reads, rate-capped.
[[token]]
id = "btcpay"                              # logging/accounting id — never the secret
hash = "sha256:<64-hex SHA-256 of the token>"
capabilities = ["rpc:read", "esplora:read"]
watch_quota = 50000                        # optional; omit for unlimited
rate_limit = "200/s"                       # optional; omit for unlimited

# Watchtower: streaming subscribe + watch registration, expires end-2026.
[[token]]
id = "watchtower"
hash = "sha256:<64-hex>"
capabilities = ["stream:subscribe", "stream:watch"]
watch_quota = 10000
expires = 2026-12-31T00:00:00Z             # unquoted RFC 3339 datetime, or unix seconds

# AI agent: full MCP tool access.
[[token]]
id = "agent"
hash = "sha256:<64-hex>"
capabilities = ["mcp:*"]
```

Rules:

- **`version = 1` is required.** Each `[[token]]` needs a unique `id` and a
  `hash` of the form `sha256:<64 hex>`. `capabilities` defaults to empty (a token
  that can authenticate but is denied everything). `watch_quota`, `rate_limit`
  (`"<n>/s"`), and `expires` are optional; omitting a limit means unlimited.
- **An unknown capability string, a duplicate `id`/`hash`, or a wrong `version`
  aborts the load** with a clear error (recognize-reject, never silent).
- **File permissions** (Unix) must expose no group/world or execute bits —
  `0600` or `0400`, like a cookie or an SSH private key. A `0644`/`0640` file is
  rejected.
- **Generate a token's hash** with, e.g.:
  ```sh
  TOKEN=$(openssl rand -hex 32)        # the secret you give the client
  printf 'sha256:%s\n' "$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)"
  ```
- **Reload on `SIGHUP`** — editing the file and reloading swaps the token table
  atomically; removing a `[[token]]` revokes it immediately. A parse/permission
  error keeps the last-good table (a bad reload never drops auth).

## Presenting a token

Clients send the raw token in a standard header (scheme is case-insensitive):

```
Authorization: Bearer <token>
```

Verification computes `SHA-256(token)` and looks the digest up in the loaded
table (with a constant-time guard), then checks expiry. A blank token can never
authenticate.

## Quotas & rate limits

- **Rate limit** — a per-token token bucket (`"<n>/s"`, burst = rate). Over-budget
  requests are shed, never queued (a slow/abusive consumer must never backpressure
  the node): HTTP **429** with `Retry-After` on JSON-RPC / Esplora / MCP, gRPC
  **`RESOURCE_EXHAUSTED`** on events gRPC, and a connection-time throttle on
  `streamws`.
- **Watch quota** — the streaming watch-set is metered in units (one scripthash =
  one unit; prefix watches are priced by coarseness). A token holds units via an
  RAII lease, so a disconnect releases its quota automatically. Over-quota watch
  adds are rejected cleanly without tearing down the subscription.

Operator and loopback principals are unlimited.

## Per-surface enablement

Bearer support is **opt-in per surface**: the surface flag turns it on, and it
requires `-authfile`. satd refuses to start if a surface flag is set without an
authfile.

| Surface | Enable flag | Capability gate | Default without the flag |
|---|---|---|---|
| JSON-RPC (read/write listeners) | `-rpcauthbearer` | `rpc:read` / `rpc:write` | Core Basic auth (cookie/userpass/rpcauth) |
| Esplora REST / SSE | `-esploraauthbearer` | `esplora:read` | `-esploraauth` Basic, loopback-unauth default |
| events gRPC | `-eventsgrpcauth` | `stream:subscribe` / `stream:watch` | loopback-trust |
| streaming WS/SSE (`streamws`) | `-streamwsauth` | `stream:subscribe` / `stream:watch` | loopback-trust |
| MCP (HTTP) | `-mcpauth` | `mcp:*` | loopback-trust |

The **read-only JSON-RPC listener** (`-rpcreadonlybind`) does not honor bearer
tokens. The **Electrum** surface's client-cert (mTLS) principal is a documented
future seam, not yet live.

## Exposing a surface remotely

Binding the streaming / MCP surfaces to a routable address requires auth — the
node refuses an unauthenticated remote bind. The chain is:

```
-eventsgrpcallowremote  →  requires -eventsgrpcauth  →  requires -authfile
-streamwsallowremote    →  requires -streamwsauth    →  requires -authfile
-mcpallowremote         →  requires -mcpauth         →  requires -authfile
```

For a proxy- or mTLS-terminated deployment, bind loopback and omit the
`*-allow-remote` flag. JSON-RPC remote exposure is governed by Core's existing
`-rpcbind`/`-rpcallowip` (there is no separate allow-remote flag for it).

## Transport TLS / mTLS

Native TLS and mutual TLS (see the [Configuration](configuration.md) chapter's
`*tls*`/`*mtls*` keys) compose **underneath** this layer: mTLS gates the
connection, and a bearer token presented over it further refines the principal's
capabilities. satd terminates TLS natively on the RPC, Esplora, and Electrum
surfaces, so no sidecar is required.
