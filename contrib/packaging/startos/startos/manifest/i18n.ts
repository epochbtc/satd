export const short = {
  en_US: 'A Bitcoin full node in Rust, with Electrum and Esplora built in',
}

export const long = {
  en_US:
    "satd is a Bitcoin Core-compatible full node written in Rust. It speaks Core's JSON-RPC, config file and CLI, and serves an Electrum server and an Esplora REST API from the same process — no second indexer to run and no second copy of the chain to store. This package contains satd and its own tools only; Lightning, BTCPay and wallets come from the marketplace as separate services. It runs fully indexed, because Electrum and Esplora both require the transaction and address indices, so pruning is not offered and the disk budget is the full chain plus roughly the same again.",
}
