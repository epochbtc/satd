# API Scaling & Runtimes

satd is a single process: one RocksDB instance, one chainstate, and every API
surface (JSON-RPC, Esplora, Electrum, the streaming APIs, MCP, metrics) in the
same process as consensus. This chapter explains how that process is split into
two runtimes so that API load cannot endanger consensus. It also covers the
options that tune each runtime, and how to scale out when one node is not
enough.

The design goal is to bound the remotely-consumed API surfaces so they can
never starve or stall the consensus core. Default behavior is unchanged and
Bitcoin Core-compatible; everything in this chapter is opt-in or a bounded
default.

## The two runtimes

satd runs two separate tokio runtimes. The split is structural, not a priority
hint.

### Core (consensus) runtime

This runtime carries everything that must never be starved: P2P, block
connection, and mempool acceptance. It also carries:

- The main JSON-RPC listener (`-rpcport`, read and write). It serves the
  block-connecting control methods (`generate*`, `submitblock`,
  `submitheader`, `preciousblock`, `loadtxoutset`), which must originate on
  the core runtime to preserve address-index and SSE event ordering. Keeping
  JSON-RPC here also means public API load cannot starve the admin interface.
- The MCP server. It exposes block-connecting tools (`generate_blocks`) and
  broadcast, so it stays on the core runtime for the same reason.

### Isolated API runtime (`--api-threads`)

A separate, bounded runtime carries the read and streaming surfaces, so a flood
on any of them cannot contend with the threads that connect blocks:

- Esplora REST and SSE
- the Electrum protocol server
- the events gRPC and ZMQ sinks, and the streaming WS/SSE (`streamws`)
- the Prometheus `/metrics`, `/healthz`, and `/readyz` endpoints
- the opt-in read-only JSON-RPC listener (`-rpcreadonlybind`)

Use `--api-threads` to size this pool. The default is `max(2, cores/4)` worker
threads, clamped to 1024. Because the isolation is structural, a flood on a
consumption surface cannot starve block connection or mempool acceptance.
`SIGHUP` and `SIGUSR1` reload reach the relocated surfaces unchanged.

## Admission control and tuning options

Every remotely-consumed surface bounds its concurrency and backlog, and sheds
work that is over budget. Nothing queues without bound; an unbounded queue
would let a consumer backpressure the node. Shedding runs ahead of
authentication and request-body buffering, so a flood is bounded before it does
work, authenticated or not. Each option is clamped to a ceiling, so a mistyped
value cannot panic satd at boot.

| Surface | Options | Default | Over-budget response |
|---|---|---|---|
| Isolated API runtime size | `--api-threads` | `max(2, cores/4)` | none (sizing only) |
| JSON-RPC (main) | `-rpcthreads` (in-flight), `-rpcworkqueue` (backlog) | 16 / 64 | HTTP 429 + `Retry-After` |
| Read-only JSON-RPC | `-rpcreadonlythreads`, `-rpcreadonlyworkqueue` | inherit main | HTTP 429 + `Retry-After` |
| events gRPC | `-eventsgrpcmaxconns`, `-eventsgrpcmaxsubscriptions` | 64 / 256 | gRPC `RESOURCE_EXHAUSTED` |
| streaming WS/SSE | `-streamwsmaxconns`, `-streamwsmaxsubscriptions`, `-streamwsmaxmessagebytes` | 256 / 256 / 262144 | connection refused / 429 |
| Esplora | `-esploramaxconns`, `-esplorasseconns` | 256 / = maxconns | HTTP 429 |
| Electrum | `-electrummaxconns`, `-electrummaxsubsperconn` | 64 / 1000 | connection refused |

`-rpcthreads` and `-rpcworkqueue` are recognized from Bitcoin Core, so a
Core-shaped config that carries them loads. In-flight calls are capped at
`-rpcthreads`, and the waiting backlog at `-rpcthreads + -rpcworkqueue`.
Per-token rate limits and watch quotas layer on top of these per-surface caps;
see [Authentication & Authorization](authentication.md).

## Scaling read RPC on one node: the read-only listener

`-rpcreadonlybind` adds a second JSON-RPC listener on the isolated API runtime.
It dispatches only read methods and mempool submission (`sendrawtransaction`),
and rejects block-connecting and node-control methods with JSON-RPC error
`-32001`. The method filter fails closed: an unclassified method is rejected,
never served. A release-safe invariant guard asserts that block connection
never originates on the API runtime.

The read-only listener has its own bind address, source-IP allowlist
(`-rpcreadonlyallowip`), admission budget (`-rpcreadonlythreads` /
`-rpcreadonlyworkqueue`), and TLS/mTLS options (`-rpcreadonlytlsbind` /
`…tlscert` / `…tlskey` / `…mtls` / `…mtlsclientca` / `…mtlsclientallow`). It
reuses the main listener's authentication.

To scale read traffic, put this listener behind a load balancer and keep the
core-runtime listener private. The write and admin methods never leave the
private listener.

## Scaling beyond one node

The vertical levers above (`--api-threads`, the per-surface admission caps,
the read-only listener behind a load balancer) scale the API surfaces up to
the capacity of a single node. satd is one process over one chainstate, so
there is no in-process read-replica mode. You cannot add API capacity beyond
what one node's API runtime can serve.

When you need more than that, run multiple independent satd nodes behind a
load balancer. Each node is a full node with its own chainstate and mempool.
Together they serve more aggregate read and stream traffic than any single
node can.

### Clients must tolerate transient divergence between nodes

Independent nodes are eventually consistent with each other. At any instant,
two nodes can differ, and a load balancer can route consecutive requests to
different backends. Design clients to expect:

- **Tip skew.** One node may be a block (briefly more) ahead of another.
  `getblockcount` and the chain-tip height can go backwards across two
  requests routed to different nodes.
- **Mempool divergence.** A newly broadcast transaction may be visible on the
  node that received it but not yet on others. Fee estimates and mempool
  contents differ between nodes.
- **Reorg timing skew.** Nodes can adopt a reorg at slightly different
  moments, so a transaction's confirmed status and its `confirmations` count
  can differ transiently.
- **Per-node streaming cursors.** A streaming cursor (`seq`, `instance_id`)
  is only meaningful against the node that issued it. Do not resume a cursor
  against a different backend.

Practical guidance:

- Do not assume monotonic or read-your-writes consistency across requests that
  may hit different backends. Where read-your-writes matters, pin a client or
  session to one backend with sticky sessions: for example, submit a
  transaction and poll for it on the same node.
- Choose where to broadcast. Send a transaction to one chosen node, or fan it
  out to all, then rely on P2P propagation. Do not assume every node already
  has a transaction another node accepted a moment ago.
- Use confirmation thresholds rather than single-node point reads for
  irreversibility decisions. Confirm across nodes if you need cross-node
  agreement.
- Health-gate the pool. Route only to nodes that pass `/readyz` and are near
  the network tip. Drop a node that has fallen behind so it does not serve
  stale reads.

This is the same operational model as running multiple Bitcoin Core nodes
behind a balancer. The difference is that a single satd node already isolates
its API surfaces from consensus, so multiple nodes are for horizontal
throughput, not for protecting a node from its own API load.
