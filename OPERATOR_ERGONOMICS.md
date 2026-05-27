# satd: Operator Ergonomics & Tuning

`satd` is built from the ground up to make running a full node easier, safer, and more transparent for infrastructure maintainers.

This document catalogs the operator-facing surfaces, configuration flags, tuning profiles, and observability tools available in `satd`.

---

## 1. Observability & Metrics

### Native TUI (`sat-tui`)
`satd` ships with a native Ratatui-based terminal interface. Rather than running blind or relying on chatty log files, operators can visualize node progress in real-time.
*   **IBD Bitmap:** Visualizes block download and verification progress.
*   **Peer Stats:** Shows connected peers, their latency, and block delivery rates.
*   **Mempool Status:** Live view of mempool depth and fee percentiles.

### Prometheus Metrics Endpoint
*   **Flag:** `--metricsbind=<addr:port>`
*   Exposes a native Prometheus HTTP server at `GET /metrics` providing deep insights into P2P traffic, block validation times, mempool depth, and RocksDB performance.
*   Includes `GET /healthz` and `GET /readyz` endpoints for load balancer and orchestrator integration.

### Structured JSON Logging
*   **Flag:** `--log-format=json|text`
*   Replaces the traditional `debug.log` text firehose with structured, machine-parseable JSON logs. Perfect for Datadog, ELK, or custom log-alerting pipelines. Trace IDs allow operators to follow a single block through prefetch, connect, and flush.

## 2. Configuration & Tuning

`satd` fully supports Bitcoin Core's `bitcoin.conf` syntax and standard CLI flags. However, to simplify deployment on different hardware profiles, `satd` introduces configuration presets.

### `--profile` Presets
Instead of manually tuning `-dbcache`, `-maxmempool`, and connection limits, operators can use `--profile=<preset>`:
*   `archival`: Maximizes indexing and P2P serving. Disables pruning.
*   `pruned-home`: Optimizes for Raspberry Pi or home servers. Enables pruning, bounds memory.
*   `mining`: Optimizes block template generation latency.
*   `regtest-dev`: Fast, isolated environment for local development.

### Indexing & Protocol Flags
| Flag | Default | Notes |
|---|---|---|
| `--addressindex=<0\|1>` | `1` | Builds the scripthash history index over RocksDB. Required for Esplora/Electrum. |
| `--esplora=<0\|1>` | `1` | Enables the native Esplora REST API (loopback unauthenticated by default). |
| `--electrum=<0\|1>` | `0` | Enables the native Electrum protocol server. |
| `--blockfilterindex=<0\|1\|basic>` | `0` | Builds the BIP 158 compact block filter index. |
| `--peerblockfilters=<0\|1>` | `0` | Advertises `NODE_COMPACT_FILTERS` (bit 6) and serves BIP 157 P2P queries. |
| `--rpctlsbind=<addr:port>` | None | Enables native TLS for JSON-RPC, eliminating the need for a TLS-terminating sidecar. Requires `--rpctlscert` and `--rpctlskey`. |
| `--electrumtlsbind=<addr:port>`| None | Enables native TLS for the Electrum server. Requires `--electrumtlscert` and `--electrumtlskey`. |
| `--esploratlsbind=<addr:port>` | None | Enables native TLS for the Esplora REST API. Requires `--esploratlscert` and `--esploratlskey`. |
| `--v2transport=<0\|1>` | `1` | Enables BIP 324 v2 encrypted P2P transport. Offers/accepts the ElligatorSwift + ChaCha20-Poly1305 v2 handshake, transparently falling back to v1. |
| `--v2only=<0\|1>` | `0` | satd-specific privacy/anti-surveillance flag. If `1`, strictly refuses or immediately disconnects any peer not using the v2 encrypted P2P transport. |
| `--dbcache=auto` | None | Spawns the adaptive dbcache resizing task to automatically scale RocksDB block cache and CoinCache clean-LRU in response to system memory pressure. |

### Mempool Policy Sovereignty
`satd` believes that operators should have strict, ultimate control over what their hardware validates and relays. Instead of requiring a patched C++ fork (like Bitcoin Knots) to filter spam or unwanted data, `satd` exposes these policies as first-class configuration knobs:

| Flag | Default | Notes |
|---|---|---|
| `--datacarrier=<0\|1>` | `1` | If set to `0`, strictly rejects **all** transactions containing `OP_RETURN` outputs from entering the mempool or being relayed. |
| `--datacarriersize=<bytes>` | `83` | The maximum permitted size of an `OP_RETURN` script. Anything larger is rejected as non-standard. |
| `--dustrelayfee=<sat/kvB>` | `3000` | The threshold used to calculate dust. Raising this forces spam transactions creating tiny, unspendable UTXOs to pay significantly higher fees. |
| `--permitbaremultisig=<0\|1>` | `1` | If `0`, rejects complex, non-standard bare multisig setups often used for data-storage hacks. |
| `--limitancestorcount=<N>` | `25` | Maximum unconfirmed ancestor count. |

## 3. Developer & Integrator APIs

### Mempool-Based Fee Estimation
*   `estimatesmartfee` supports an optional `mode` param (`historical`, `mempool`, `blend`).
*   `satd` never hard-errors on fee estimation; it falls back to the min-relay floor with `confidence: low` rather than breaking downstream applications.

### Mempool Subscription Stream
*   `subscribemempool` JSON-RPC WS stream emitting structured events: `enter`, `leave_confirmed`, `leave_evicted`, and `leave_replaced`.
*   Includes explicit eviction reasons and RBF replacement linkage.

### Satoshis-as-Integers
*   To prevent IEEE 754 float precision errors, operators can pass `amounts=sats` to any RPC request to receive exact integer satoshi values instead of BTC decimals.

### Persistent Reorg Log & Webhook
*   A persistent, append-only JSONL log at `$datadir/reorg.log` survives restarts.
*   Optional HTTP POST on reorgs via `--reorg-webhook=<url>`.

### Client-Side PSBT Signing
*   `sat-cli signpsbtwithkey` is a client-side command that reads a WIF or xpriv from **stdin** and signs Taproot key-path, SegWit, or Legacy inputs locally. Because the private key is never passed over JSON-RPC, the `satd` daemon stays strictly keyless while allowing operators to securely sign PSBTs via their CLI terminal.
