# Authentication & Authorization

satd has one authentication model shared by every API surface: JSON-RPC,
Esplora, the streaming APIs (events gRPC and `streamws`), and the MCP server.
It also keeps full backward compatibility with Bitcoin Core's cookie,
`rpcuser`, and `rpcauth` credentials.

There are two layers:

1. **Core-compatible operator auth**: the cookie file,
   `-rpcuser`/`-rpcpassword`, and `-rpcauth`. This is the default and behaves
   exactly like Bitcoin Core. It is all-or-nothing: a valid operator
   credential has full access to everything.
2. **The unified bearer-token layer** (`satd-auth`): opt-in,
   capability-scoped bearer tokens loaded from an `-authfile`, each
   rate-limited and quota-bounded. Scoped tokens let you expose the node to
   partially trusted consumers, such as a BTCPay instance or a watchtower,
   without giving any of them operator credentials.

> **Note.** The default is pure Bitcoin Core behavior. With no `-authfile`
> configured, the bearer layer is inert: the only credentials that work are
> the Core-compatible ones, and every authenticated request acts as the
> full-capability operator. Scoped tokens are opt-in, per surface. A surface
> with no bearer tokens enabled does not install the capability gate at all.

## How the bearer layer differs from Core-style auth

| | Core-style operator auth | Unified bearer tokens |
|---|---|---|
| **Credentials** | `.cookie` file, `-rpcuser`/`-rpcpassword`, `-rpcauth` (HMAC) | Opaque high-entropy tokens, sent as `Authorization: Bearer <token>` |
| **Granularity** | All-or-nothing: full operator access | Per-token capabilities (for example read-only, Esplora-only, stream-only) |
| **Multi-tenant** | No; one shared identity | Yes; each token has its own id, scope, quota, rate limit, and expiry |
| **Rate / quota limits** | None; the operator is unlimited | Per-token request rate (`429`/`RESOURCE_EXHAUSTED`) and watch-set quota |
| **Where defined** | Flags, `bitcoin.conf`, or the generated cookie | A TOML `-authfile`, reloadable on `SIGHUP` |
| **Default** | On (cookie auto-generated) | Off until `-authfile` is set and the surface opts in |
| **Compatibility** | Bitcoin Core wire-identical | satd extension |

Both layers coexist. On a bearer-enabled surface the operator (Basic)
credential is tried first, so existing Core tooling is not affected. A
`Bearer` token is consulted only when the request does not carry a valid
operator Basic credential. A matching cookie, userpass, or `rpcauth`
credential always resolves to the full-capability operator.

## Capabilities

A bearer token carries a set of capabilities, and each surface enforces the
capability it requires. Enforcement fails closed: an unknown method, or a
request with no principal, requires the write capability, which a read-only
token does not hold.

| Capability | String | Grants |
|---|---|---|
| RPC read | `rpc:read` | Read-only JSON-RPC methods (classified by the same table the read-only listener uses). |
| RPC write | `rpc:write` | Mutating, control, and mining JSON-RPC methods, plus any unclassified method (fail-closed). |
| Esplora read | `esplora:read` | The Esplora REST + SSE surface. |
| Stream subscribe | `stream:subscribe` | Open a streaming subscription (events gRPC, `streamws`). |
| Stream watch | `stream:watch` | Register outpoint/script/descriptor/txid watches, bounded by the token's watch quota. |
| MCP | `mcp:*` | The MCP server. One capability; there is no per-tool split. |

The operator and loopback-trust principals hold all capabilities.

## The authfile

`-authfile=<path>` points at a TOML file of bearer tokens. The file stores
only the SHA-256 digest of each token, never the plaintext.

```toml
version = 1

# Read-only integration: REST + Esplora reads, rate-capped.
[[token]]
id = "btcpay"                              # logging/accounting id, not the secret
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

- `version = 1` is required. Each `[[token]]` needs a unique `id` and a
  `hash` of the form `sha256:<64 hex>`. `capabilities` defaults to empty;
  such a token can authenticate but is denied everything. `watch_quota`,
  `rate_limit` (`"<n>/s"`), and `expires` are optional. An omitted limit
  means unlimited.
- An unknown capability string, a duplicate `id` or `hash`, or a wrong
  `version` aborts the load with an error. Nothing is ignored silently.
- On Unix the file must have no group, world, or execute permission bits:
  `0600` or `0400`, like a cookie file or an SSH private key. A `0644` or
  `0640` file is rejected.
- Generate a token and its hash with, for example:
  ```sh
  TOKEN=$(openssl rand -hex 32)        # the secret you give the client
  printf 'sha256:%s\n' "$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)"
  ```
- Edit the file and send `SIGHUP` to reload it. The reload swaps the token
  table atomically, and removing a `[[token]]` revokes it immediately. A
  parse or permission error keeps the last-good table, so a bad reload never
  drops auth.

## Presenting a token

Clients send the raw token in a standard header. The scheme is
case-insensitive.

```
Authorization: Bearer <token>
```

The server computes `SHA-256(token)`, looks the digest up in the loaded
table with a constant-time guard, then checks expiry. A blank token can
never authenticate.

## Quotas & rate limits

- **Rate limit.** A per-token token bucket (`"<n>/s"`, burst equal to the
  rate). Requests over budget are shed, never queued, so a slow or abusive
  consumer cannot backpressure the node. JSON-RPC, Esplora, and MCP return
  HTTP **429** with `Retry-After`; events gRPC returns
  `RESOURCE_EXHAUSTED`; `streamws` throttles at connection time.
- **Watch quota.** The streaming watch-set is metered in units. One
  scripthash costs one unit, and prefix watches are priced by coarseness. A
  token holds units through an RAII lease, so a disconnect releases its
  quota automatically. A watch add over quota is rejected without tearing
  down the subscription.

Operator and loopback principals are unlimited.

## Per-surface enablement

Bearer support is opt-in per surface: the surface flag turns it on, and it
requires `-authfile`. satd refuses to start if a surface flag is set without
an authfile.

| Surface | Enable flag | Capability gate | Default without the flag |
|---|---|---|---|
| JSON-RPC (read/write listeners) | `-rpcauthbearer` | `rpc:read` / `rpc:write` | Core Basic auth (cookie/userpass/rpcauth) |
| Esplora REST / SSE | `-esploraauthbearer` | `esplora:read` | `-esploraauth` Basic, loopback-unauth default |
| events gRPC | `-eventsgrpcauth` | `stream:subscribe` / `stream:watch` | loopback-trust |
| streaming WS/SSE (`streamws`) | `-streamwsauth` | `stream:subscribe` / `stream:watch` | loopback-trust |
| MCP (HTTP) | `-mcpauth` | `mcp:*` | loopback-trust |

The read-only JSON-RPC listener (`-rpcreadonlybind`) does not honor bearer
tokens. Client-certificate (mTLS) principals for the Electrum surface are
planned but not yet implemented.

## Exposing a surface remotely

Binding the streaming or MCP surfaces to a routable address requires auth;
the node refuses an unauthenticated remote bind. The chain is:

```
-eventsgrpcallowremote  →  requires -eventsgrpcauth  →  requires -authfile
-streamwsallowremote    →  requires -streamwsauth    →  requires -authfile
-mcpallowremote         →  requires -mcpauth         →  requires -authfile
```

For a proxy-terminated or mTLS-terminated deployment, bind to loopback and
omit the `*-allow-remote` flag. JSON-RPC remote exposure is governed by
Core's existing `-rpcbind`/`-rpcallowip`; there is no separate allow-remote
flag for it.

## Transport TLS / mTLS

Native TLS and mutual TLS compose underneath this layer: mTLS gates the
connection, and a bearer token presented over it further refines the
principal's capabilities. satd terminates TLS natively on the RPC, Esplora,
and Electrum surfaces, so no sidecar is required. The `*tls*`/`*mtls*`
config keys are listed in the [Configuration](configuration.md) chapter.
