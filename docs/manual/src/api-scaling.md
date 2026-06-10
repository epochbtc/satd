# API Scaling & Runtimes

satd is a **single, unified process**: one RocksDB instance, one chainstate, and
all the API surfaces (JSON-RPC, Esplora, Electrum, the streaming APIs, MCP,
metrics) served from the same daemon. This chapter explains how that process is
internally partitioned into two runtimes so heavy API load can't endanger
consensus, which knobs tune each, and how to scale **out** when one node isn't
enough.

The guiding principle: **bound the blast radius of the remotely-consumed API
surfaces so they can never starve or stall the consensus core.** Default behavior
is unchanged and Bitcoin Core-compatible; everything here is opt-in or a
safe-by-default backstop.

## The two runtimes

satd runs on **two separate tokio runtimes**, and the split is structural — not a
policy or a priority hint:

### Core (consensus) runtime

Carries everything that must never be starved: P2P, **block connection**,
**mempool acceptance**, plus:

- **The main JSON-RPC listener** (`-rpcport`, read *and* write). It carries the
  block-connecting control methods (`generate*`, `submitblock`, `submitheader`,
  `preciousblock`, `loadtxoutset`), which must originate on the core runtime to
  preserve address-index / SSE event ordering. Keeping JSON-RPC here also makes
  it a **"break-glass" admin endpoint** that public API load cannot starve.
- **The MCP server** — it exposes block-connecting tools (`generate_blocks`) and
  broadcast, so it stays on the core runtime for the same reason.

### Isolated API runtime (`--api-threads`)

A **separate, bounded** runtime for the read- and streaming-oriented surfaces, so
a flood on any of them cannot contend with the threads that connect blocks:

- Esplora REST + SSE
- Electrum protocol server
- events gRPC + ZMQ sinks, and the streaming WS/SSE (`streamws`)
- the Prometheus `/metrics` + `/healthz` + `/readyz` endpoint
- the opt-in **read-only JSON-RPC listener** (`-rpcreadonlybind`)

`--api-threads` sizes this pool. Default **`max(2, cores/4)`** worker threads
(clamped to 1024). A flood on any consumption surface therefore *cannot* starve
block connection or mempool acceptance — the isolation is structural. `SIGHUP` /
`SIGUSR1` reload reach the relocated surfaces unchanged.

## Admission control & tuning knobs

Every remotely-consumed surface bounds concurrency and backlog and **sheds**
over-budget work (it never queues unboundedly — that would let a consumer
backpressure the node). Shedding runs *ahead* of authentication and request-body
buffering, so a flood — authenticated or not — is bounded before it does work.
All knobs are clamped to a sane ceiling so a fat-fingered value can't panic the
daemon at boot.

| Surface | Knobs | Default | Over-budget response |
|---|---|---|---|
| Isolated API runtime size | `--api-threads` | `max(2, cores/4)` | — (sizing) |
| JSON-RPC (main) | `-rpcthreads` (in-flight), `-rpcworkqueue` (backlog) | 16 / 64 | HTTP **429** + `Retry-After` |
| Read-only JSON-RPC | `-rpcreadonlythreads`, `-rpcreadonlyworkqueue` | inherit main | HTTP **429** + `Retry-After` |
| events gRPC | `-eventsgrpcmaxconns`, `-eventsgrpcmaxsubscriptions` | 64 / 256 | gRPC **`RESOURCE_EXHAUSTED`** |
| streaming WS/SSE | `-streamwsmaxconns`, `-streamwsmaxsubscriptions`, `-streamwsmaxmessagebytes` | 256 / 256 / 262144 | connection refused / **429** |
| Esplora | `-esploramaxconns`, `-esplorasseconns` | 256 / = maxconns | HTTP **429** |
| Electrum | `-electrummaxconns`, `-electrummaxsubsperconn` | 64 / 1000 | connection refused |

`-rpcthreads` / `-rpcworkqueue` are recognized from Bitcoin Core (a Core-shaped
config carrying them loads): in-flight calls are capped at `-rpcthreads`, and the
waiting backlog at `-rpcthreads + -rpcworkqueue`. Per-token rate limits and watch
quotas (see [Authentication & Authorization](authentication.md)) layer on top of
these per-surface caps.

## Scaling read RPC on one node: the read-only listener

`-rpcreadonlybind` adds a **second JSON-RPC listener on the isolated API runtime**
that dispatches only read and mempool-submit methods (`sendrawtransaction`) and
rejects block-connecting / node-control methods with JSON-RPC error `-32001`. The
method filter is **fail-closed** (an unclassified method is rejected, never
served), and a release-safe invariant guard asserts block connection never
originates on the API runtime.

It has its own bind, source-IP allowlist (`-rpcreadonlyallowip`), admission
budget (`-rpcreadonlythreads` / `-rpcreadonlyworkqueue`), and TLS/mTLS
(`-rpcreadonlytlsbind` / `…tlscert` / `…tlskey` / `…mtls` / `…mtlsclientca` /
`…mtlsclientallow`); it reuses the main listener's authentication. This lets you
put read RPC traffic behind a load balancer **without exposing the control
plane** — the write/admin methods stay on the core-runtime listener you keep
private.

## Scaling beyond one node — run multiple nodes

The vertical levers above (`--api-threads`, the per-surface admission caps, the
read-only listener behind a load balancer) scale the API surfaces **up to the
capacity of a single node**. Because satd is a **unified process over one
chainstate**, there is no in-process read-replica mode: you cannot add API
capacity beyond what one node's API runtime can serve.

**When you need more than that, run multiple independent satd nodes behind a load
balancer.** Each node is a full node maintaining its own chainstate and mempool;
together they serve more aggregate read/stream traffic than any single node can.

### Clients must tolerate transient divergence between nodes

Independent nodes are only *eventually* consistent with each other. At any instant
two nodes can legitimately differ, and a load balancer can route consecutive
requests to different backends. Design clients to expect:

- **Tip skew** — one node may be a block (or briefly more) ahead of another;
  `getblockcount` / chain-tip height can go *backwards* across two requests routed
  to different nodes.
- **Mempool divergence** — a just-broadcast transaction may be visible on the node
  that received it but not yet on others; fee estimates and mempool contents
  differ between nodes.
- **Reorg timing skew** — nodes can adopt a reorg at slightly different moments,
  so a tx's confirmed/unconfirmed status (and `confirmations`) can differ
  transiently.
- **Streaming cursors are per-node** — a streaming cursor / `seq` / `instance_id`
  is only meaningful against the node that issued it; do not resume a cursor
  against a different backend.

Practical guidance:

- **Don't assume monotonic or read-your-writes consistency** across requests that
  may hit different backends. Use **sticky sessions** (pin a client/session to one
  backend) where read-your-writes matters — e.g. submit a tx and then poll for it
  on the *same* node.
- **Broadcast deliberately.** Send a transaction to one chosen node (or fan it out
  to all), then rely on P2P propagation; don't assume every node already has a tx
  another node just accepted.
- **Use confirmation thresholds**, not single-node point reads, for
  irreversibility decisions; confirm across nodes if you need cross-node
  agreement.
- **Health-gate the pool.** Route only to nodes that are `/readyz` and near the
  network tip; drop a node that has fallen behind so it doesn't serve stale reads.

This is the same operational model as running multiple Bitcoin Core nodes behind a
balancer — satd's contribution is that a *single* node already isolates its API
surfaces from consensus, so you reach for multiple nodes only for genuine
horizontal throughput, not to protect the node from its own API load.
