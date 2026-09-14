# satd for Umbrel

An Umbrel community app store with one app: [satd](https://github.com/epochbtc/satd),
a Bitcoin Core-compatible full node written in Rust, with an Electrum server
and an Esplora REST API built in.

## Install

1. In umbrelOS, open the **App Store**, then **⋯ → Community App Stores**.
2. Paste `https://github.com/epochbtc/umbrel-apps` and choose **Add**.
3. Open the **satd** store and install **satd**.

satd installs alongside Bitcoin Node, Fulcrum and Ride The Lightning. It uses
its own host ports:

| Port | Surface |
|---|---|
| 8430 | The status page, through Umbrel's proxy |
| 8431 | Esplora, TLS |
| 8433 | Bitcoin P2P |
| 50012 | Electrum, TLS |
| 8436 | JSON-RPC, TLS |
| 8439 | MCP, TLS and a bearer token |

The [Operator Manual](https://epochbtc.github.io/satd/) covers connecting
wallets, importing the install's certificate authority, and the MCP token.

## This repository

Generated. The package is developed in
[`contrib/packaging/umbrel/`](https://github.com/epochbtc/satd/tree/master/contrib/packaging/umbrel)
in the satd repository and copied here by `contrib/packaging/sync-store.sh`.
Report problems and send changes there, not here.
