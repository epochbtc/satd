# satd

satd is a Bitcoin Core-compatible full node written in Rust. It speaks Core's
JSON-RPC, config file and CLI, and serves an Electrum server and an Esplora
REST API from the same process.

## What this service gives you

| Interface | What it is for |
|---|---|
| **RPC** | Bitcoin Core-compatible JSON-RPC, with cookie authentication. Other services on this server reach it over the container bridge; you reach it from your LAN over TLS. |
| **Electrum** | For Sparrow, Electrum, BlueWallet and Zeus. Point the wallet at the Electrum address on the Interfaces tab. |
| **Esplora** | Blockstream-compatible REST API under `/api`. |
| **MCP** | Lets an AI assistant query your own node instead of a public explorer. Needs the bearer token from the **MCP Token** action, and the address you use listed under **MCP Hostnames**. |
| **Peer** | Inbound connections from other Bitcoin nodes. |

TLS is handled by StartOS, with a certificate chaining to this server's root
CA — the one your browser already trusts here. There is no second certificate
authority to import.

## Before an AI assistant can reach MCP

Two settings, both one-time.

**MCP Token** prints the bearer token. Clients send it as
`Authorization: Bearer <token>`.

**MCP Hostnames** needs the name you type in the address bar to reach this
server — usually something like `my-server.local`. Enter it once and MCP
starts answering; until then every request that arrives by name is refused
with `403 Forbidden`, token or no token.

That check is worth the one step. It is what stops a web page you happen to
be visiting from pointing a name it controls at this server and driving your
node through MCP from inside your own browser. Listing your server's real
name tells satd which requests are yours. If you reach this server by more
than one name, list them all, separated by commas.

## Disk

This node runs fully indexed. Electrum and Esplora both require the
transaction and address indices, and pruning is not compatible with them, so
there is no prune option. Budget for the full chain plus roughly the same
again in indices.

## First start

The node syncs from scratch. **Blockchain Sync** on the service's page tracks
it: block headers first, then blocks. Electrum and Esplora answer for the part
of the chain that has been indexed so far, so wallet balances are not
trustworthy until the sync completes.

## Changing network

The **Network** action switches chains. Each network keeps its own directory,
so switching away and back does not discard what was already synced — but the
new network syncs from scratch the first time, and the peer port changes with
it.

## Backups

Backups deliberately exclude the chain, the chainstate and the indices: they
are hundreds of gigabytes that the node re-downloads on its own. What is kept
is the part that cannot be re-derived — this install's certificate authority,
the MCP token and your network selection.
