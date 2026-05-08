# satd

**A Bitcoin Core-compatible full node in Rust.**

`satd` provides the core node, plus the wallet-server protocols operators usually wire up alongside it (Esplora REST, Electrum, BIP 157/158). 

*One process. One RocksDB. One systemd unit.*

---

## Why satd?

*   **Node Sovereignty:** Built to give economic node operators a robust, memory-safe alternative to the monoculture, strengthening the network's resilience. Read the [Manifesto](MANIFESTO.md).
*   **Zero Consensus Divergence (Dual Engine):** Features a full Rust implementation of the consensus rules that passes Bitcoin Core's test suite (and beyond). Operators can choose to run the pure Rust engine, the C++ `libbitcoinconsensus` engine, or both simultaneously with bidirectional shadow-validation to mathematically guarantee zero divergence.
*   **Built for the Operator:** Eliminates the `bitcoind` + `electrs` + `esplora` multi-process headache. Everything shares a single chainstate and a single RocksDB instance.

## Features

### Consensus & Network
*   **Dual Consensus Engine:** A complete, independently written Rust consensus engine that passes the Bitcoin Core test suite, with a C++ `libbitcoinconsensus` conservative fallback.
*   **Swarm-Style IBD:** BitTorrent-like parallel block downloading and speculative verification pipeline for heavily optimized Initial Block Download.
*   **Full P2P:** BIP 152 compact blocks, ban scoring, addrv2, BIP 324 v2 transport (in progress), Tor v3 (hardcoded `.onion` seeds).
*   **Modern Mempool:** Full RBF / opt-in BIP 125, CPFP ancestor tracking, configurable policy (`-dustrelayfee`, `-limitancestorcount`, etc.).

### Native Integrations (No side-cars required)
*   **AI-Native MCP Server:** An optional Model Context Protocol (`mcp`) binary that exposes node data and operational surfaces directly to AI agents.
*   **Electrum Protocol:** Native TCP server (v1.4.5) for wallets like BlueWallet, Sparrow, and Nunchuk.
*   **Esplora REST:** Wire-shape parity with blockstream.info / mempool.space for the implemented endpoint set.
*   **Compact Block Filters:** Native BIP 157/158 index and P2P service for embedded-Neutrino mobile wallets (Zeus, Blixt, Mutiny).
*   **Shared Indexing:** Address-history index atomic with `connect_block`. One database powers everything.

### Operator Ergonomics

<details>
<summary><b>View the satd Terminal UI</b></summary>

![satd Terminal UI showing IBD progress](docs/assets/tui-hero.png)
*The `sat-tui` interface provides real-time observability, including an IBD bitmap, peer stats, and a JSON-RPC explorer.*
</details>

*   **Native TUI (`sat-tui`):** A beautiful Ratatui-based terminal interface for real-time IBD bitmap visualization, peer stats, and node observability.
*   **Metrics & Observability:** Native Prometheus `/metrics`, `/healthz`, and JSON-structured logs.
*   **Core-Compatible:** Accepts standard `bitcoin.conf` and CLI flags (`-prune`, `-txindex`, `-assumeutxo`). Uses standard `.cookie` auth.
*   **Mempool Stream:** `subscribemempool` JSON-RPC WS subscription with explicit eviction/replacement reasons.
*   **Events Bus:** gRPC + ZMQ publishers for chain and mempool events (`satd-events`).
*   **Reorg Logging:** Persistent reorg log with an optional webhook.

*(See [CORE_DIFFERENCES.md](CORE_DIFFERENCES.md) for a full catalog of intentional deviations and features explicitly out of scope, such as the legacy wallet).*

---

## Getting Started

### Building

Requires Rust (stable, edition 2024), a C/C++ compiler, and clang/LLVM libraries (for `rocksdb-sys` bindgen).

```sh
./configure          # detect dependencies, generate .cargo/config.toml
cargo build
```

**Consensus-only build** (no BIP 158 codec, no Esplora handlers, no Electrum protocol code):
```sh
cargo build -p satd --no-default-features
```

**Reproducible build via Nix** (deterministic across hosts; toolchain pinned in `rust-toolchain.toml`):
```sh
nix build .#satd     # produces ./result/bin/{satd, sat-cli}
```
*See `docs/PACKAGING.md` §"Reproducible build via Nix" for the full story.*

### Running

```sh
# Regtest — quick local node
cargo run --bin satd -- --regtest

# Mainnet — Esplora and address index on by default
cargo run --bin satd -- --datadir=/path/to/datadir

# Add the Electrum server (loopback; expose via Tor)
cargo run --bin satd -- --electrum=1

# Add BIP 157/158 P2P service for embedded-Neutrino wallets
cargo run --bin satd -- --blockfilterindex=basic --peerblockfilters=1
```

### Querying & Stopping
```sh
cargo run --bin sat-cli -- --regtest getblockchaininfo
cargo run --bin sat-cli -- --regtest getindexinfo
cargo run --bin sat-cli -- --regtest getserverstatus
cargo run --bin sat-cli -- --regtest stop
```

## Configuration

Bitcoin Core-compatible flags (`-regtest`, `-datadir`, `-rpcport`, `-prune`, `-txindex`, `-assumeutxo`, …) and the `bitcoin.conf` file format are accepted as the default surface. 

Bundled `--profile=<preset>` selects from `archival`, `pruned-home`, `mining`, `regtest-dev`, and `signet-watchtower`. CLI flags override profile values; `getconfig` / `sat-cli node config` shows the effective post-merge configuration.

Authentication uses a cookie file (default) or `--rpcuser` / `--rpcpassword`. The Esplora listener defaults to **unauthenticated loopback**; for non-loopback exposure, set `--esploraauth=cookie` or `--esploraauth=userpass`.

*See `OPERATOR_ERGONOMICS.md` for the full flag matrix and tuning notes.*

---

## Repository Layout

```text
satd/                         Daemon binary — config, lifecycle, wiring
sat-cli/                      CLI client — Bitcoin-Core-compatible RPC client
sat-tui/                      Ratatui-based ops TUI
node/                         Core library (chain, storage, mempool, P2P, RPC, validation)
node-index/                   Address-history index over the shared RocksDB
node-filter-index/            BIP 158 compact-block-filter index
esplora-handlers/             Native Esplora-compatible REST
electrum-proto/               Native Electrum protocol server (vendored from electrs)
events/                       Event-bus sinks (gRPC + ZMQ)
mcp/                          MCP tools over the ops-surface RPCs
consensus/                    Rust script-verifier shadow
block-analyzer/               Standalone tool for offline block analysis
docs/                         API + integration docs
```

## Documentation

| File | Purpose |
|---|---|
| [`MANIFESTO.md`](MANIFESTO.md) | Node Sovereignty, the monoculture risk, and the conservative BIP policy. |
| `CORE_DIFFERENCES.md` | Catalog of intentional deviations from Bitcoin Core: native surfaces, exclusions, and behavioral defaults. |
| `OPERATOR_ERGONOMICS.md` | Operator-facing flag matrix, tuning, every shipped surface. |
| `STABILITY_POLICY.md` | Tiered stability contract; deprecation policy; canary CI. |
| `ECOSYSTEM.md` | Mobile / packaging strategy; why native + shared chainstate. |
| `docs/PACKAGING.md` | Authoritative reference for downstream packagers. |
| `docs/api/esplora.md` | Esplora REST endpoint reference + wire-shape gotchas. |

## License

MIT — see [`LICENSE`](LICENSE) for the full text.

*Vendored code from `romanz/electrs` (MIT) is attributed in `electrum-proto/vendor/electrs.MIT` with original LICENSE text preserved.*
