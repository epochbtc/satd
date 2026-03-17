# btcd

A Bitcoin Core-compatible full node implementation in Rust.

## Status

**Phase 1 — Bitcoin-compatible node**

- **M1** (complete): Daemon skeleton, config system, RPC server with auth, CLI client
- **M2** (complete): Block storage (RocksDB + flat files), UTXO set, PoW validation, chain state management, `submitblock` and block query RPCs

## Architecture

```
btcd/           Daemon binary — config, lifecycle, entry point
btc-cli/        CLI client — Bitcoin Core-compatible RPC client
node/           Core library
├── chain/      Chain state management, block connection
├── storage/    RocksDB store, flat file block storage, UTXO set
├── validation/ PoW, difficulty, timestamp, merkle root checks
└── rpc/        JSON-RPC server, auth middleware, method handlers
```

## Building

Requires Rust (stable), a C/C++ compiler, and clang/LLVM libraries.

```sh
./configure     # detect dependencies, generate .cargo/config.toml
cargo build
```

## Running

```sh
# Start in regtest mode
cargo run --bin btcd -- --regtest

# Query via CLI
cargo run --bin btc-cli -- --regtest getblockchaininfo
cargo run --bin btc-cli -- --regtest getblockcount
cargo run --bin btc-cli -- --regtest getbestblockhash

# Submit a block
cargo run --bin btc-cli -- --regtest submitblock <hex>

# Stop the node
cargo run --bin btc-cli -- --regtest stop
```

## Configuration

Supports Bitcoin Core-compatible flags (`-regtest`, `-datadir`, `-rpcport`, etc.) and `bitcoin.conf` file format.

Authentication via cookie file (default) or `--rpcuser`/`--rpcpassword`.

## Testing

```sh
cargo test
```

## RPC Methods

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Chain state summary |
| `getnetworkinfo` | Network/version info |
| `getbestblockhash` | Tip block hash |
| `getblockcount` | Tip height |
| `getblockhash <height>` | Hash at height |
| `getblock <hash> [verbosity]` | Block data (0=hex, 1=JSON) |
| `getblockheader <hash> [verbose]` | Header data |
| `submitblock <hex>` | Submit a new block |
| `stop` | Shut down the node |

## License

TBD
