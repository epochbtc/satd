# satd

A Bitcoin Core-compatible full node in Rust, plus the wallet-server protocols
operators usually wire up alongside it (Esplora REST, Electrum, BIP 157/158).
One process. One RocksDB. One systemd unit.

## Status

Pre-1.0; tracks mainnet from genesis. Consensus parity with Bitcoin Core
v28+, validated against the C++ verifier as a shadow on every block sync
through ~945k. See `CORE_DIFFERENCES.md` for the catalog of intentional deviations
(extra surfaces, exclusions, default differences) and
`STABILITY_POLICY.md` for the integrator-facing stability contract.

What's implemented today (non-exhaustive):

- **Bitcoin-Core-compatible JSON-RPC** — 80 methods across chain, mempool,
  PSBT, mining, indexes, ops. Cookie auth or `--rpcuser`/`--rpcpassword`.
- **Native Esplora REST** (`esplora-handlers`) — wire-shape parity with
  blockstream.info / mempool.space for the implemented endpoint set.
  See `docs/api/esplora.md`.
- **Native Electrum protocol server** (`electrum-proto`) — TCP + optional TLS,
  v1.4.5 protocol. Plain TCP loopback default; expose via Tor.
- **Address-history index** (`node-index`) — single RocksDB instance shared
  with chainstate, atomic with `connect_block` / `disconnect_block`. Powers
  Esplora and Electrum. See `CORE_DIFFERENCES.md` §"Address-history index".
- **BIP 157/158 compact block filters** (`node-filter-index`) — index +
  P2P service (`getcfilters` / `getcfheaders` / `getcfcheckpt`) for
  embedded-Neutrino mobile wallets (Zeus, Blixt, Mutiny). See
  `OPERATOR_ERGONOMICS.md` §"Compact block filter index".
- **Pruning, AssumeUTXO, txindex, reindex, reindex-chainstate.**
- **Full P2P** including BIP 152 compact blocks, ban scoring, BIP 155 addrv2,
  BIP 324 v2 transport (in progress), Tor v3 (`ADD_ONION` / `DEL_ONION`,
  hardcoded `.onion` seeds).
- **Mempool** with full RBF / opt-in BIP 125, CPFP ancestor tracking,
  configurable policy (`-dustrelayfee`, `-datacarrier`, `-limitancestorcount`,
  `-mempoolexpiry`, `-permitbaremultisig`).
- **Mempool subscription stream** (`subscribemempool` JSON-RPC WS) emitting
  `enter` / `leave_confirmed` / `leave_evicted` / `leave_replaced`.
- **Persistent reorg log + webhook** at `$datadir/reorg.log`,
  `--reorg-webhook=<url>` with optional HMAC-SHA256.
- **Operator surfaces** — Prometheus `/metrics`, `/healthz`, `/readyz`,
  structured-JSON logs (`--log-format=json`), `--profile=<preset>`,
  `getserverstatus`, `getreorghistory`, `getconfig`.
- **Events bus** (`satd-events`) — gRPC + ZMQ event publishers for chain
  + mempool events.
- **MCP server** (`satd-mcp`) — Model Context Protocol tools over the
  ops-surface RPCs (stdio + HTTP transports).
- **Ratatui TUI** (`sat-tui`) — IBD bitmap, peer stats, service status,
  RPC explorer.
- **Rust shadow verifier** at parity with `libbitcoinconsensus` (cached
  secp256k1 context). Async shadow queue keeps connect-block on the hot path.

What's intentionally out of scope:

- Bitcoin Core's legacy (BDB) wallet, WIF-keyed wallet RPCs, descriptor
  wallet GUI. PSBT construction / signing / analysis is implemented;
  external signers are how operators sign.
- BIP 37 bloom filters (deprecated, off-by-default in Core since v0.19).
- SOCKS5 proxy, ZMQ topic-pub (event bus is gRPC + ZMQ frames over the
  events crate).

## Repository layout

```
satd/                         Daemon binary — config, lifecycle, wiring
sat-cli/                      CLI client — Bitcoin-Core-compatible RPC client
sat-tui/                      Ratatui-based ops TUI
node/                         Core library (chain, storage, mempool, P2P, RPC, validation)
node-index/                   Address-history index over the shared RocksDB
node-filter-index/            BIP 158 compact-block-filter index
esplora-handlers/             Native Esplora-compatible REST
electrum-proto/               Native Electrum protocol server (vendored from romanz/electrs MIT)
events/                       Event-bus sinks (gRPC + ZMQ)
mcp/                          MCP tools over the ops-surface RPCs
consensus/                    Rust script-verifier shadow
block-analyzer/               Standalone tool for offline block analysis
docs/                         API + integration docs
```

## Building

Requires Rust (stable, edition 2024), a C/C++ compiler, and clang/LLVM
libraries (for `rocksdb-sys` bindgen).

```sh
./configure          # detect dependencies, generate .cargo/config.toml
cargo build
```

Consensus-only build (no BIP 158 codec, no Esplora handlers, no Electrum
protocol code):

```sh
cargo build -p satd --no-default-features
```

## Running

```sh
# Regtest — quick local node
cargo run --bin satd -- --regtest

# Mainnet — Esplora and address index on by default
cargo run --bin satd -- --datadir=/path/to/datadir

# Add the Electrum server (loopback; expose via Tor)
cargo run --bin satd -- --electrum=1

# Add BIP 157/158 P2P service for embedded-Neutrino wallets
cargo run --bin satd -- --blockfilterindex=basic --peerblockfilters=1

# Query via CLI
cargo run --bin sat-cli -- --regtest getblockchaininfo
cargo run --bin sat-cli -- --regtest getindexinfo
cargo run --bin sat-cli -- --regtest getserverstatus

# Stop the node
cargo run --bin sat-cli -- --regtest stop
```

## Configuration

Bitcoin Core-compatible flags (`-regtest`, `-datadir`, `-rpcport`, `-prune`,
`-txindex`, `-assumeutxo`, …) and `bitcoin.conf` file format are accepted as
the default surface. Bundled `--profile=<preset>` selects from `archival`,
`pruned-home`, `mining`, `regtest-dev`, `signet-watchtower`. CLI flags
override profile values; `getconfig` / `sat-cli node config` shows the
effective post-merge configuration.

Authentication via cookie file (default) or `--rpcuser` / `--rpcpassword`.
The Esplora listener defaults to **unauthenticated loopback**; for
non-loopback exposure set `--esploraauth=cookie` or `--esploraauth=userpass`.

See `OPERATOR_ERGONOMICS.md` for the full flag matrix and tuning notes.

## Testing

```sh
cargo test --workspace                 # full workspace
cargo test -p satd --test regtest      # regtest integration suite
cargo clippy --all-features --all-targets -- -D warnings
```

## Documentation

| File | Purpose |
|---|---|
| `README.md` | This file — overview + quick start. |
| `CORE_DIFFERENCES.md` | Catalog of intentional deviations from Bitcoin Core: native protocol surfaces, exclusions, behavioral defaults, and the migration path for Core operators. |
| `OPERATOR_ERGONOMICS.md` | Operator-facing flag matrix, tuning, every shipped surface. |
| `STABILITY_POLICY.md` | Tiered stability contract; deprecation policy; canary CI. |
| `ECOSYSTEM.md` | Mobile / packaging strategy; why native + shared chainstate. |
| `docs/api/esplora.md` | Esplora REST endpoint reference + wire-shape gotchas. |

## License

TBD — pending public release. Vendored code from `romanz/electrs` (MIT) is
attributed in `electrum-proto/vendor/electrs.MIT` with original LICENSE
text preserved.
