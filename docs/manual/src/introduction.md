# satd Operator Manual

`satd` is a Bitcoin Core-compatible full node written in Rust. It is designed
for the people who run node infrastructure: self-custodians on home servers and
Raspberry Pis, downstream packagers (Umbrel, Start9, RaspiBlitz, MyNode), and
integrators who build wallets, Lightning nodes, and explorers on a node they
control.

This manual is the reference for operators, integrators, and packagers. It
catalogs every shipped surface: observability and metrics, configuration and
tuning, live reload, integrator APIs, the terminal UI, the native protocol
surfaces (Esplora, Electrum, BIP 157-158), and the packaging contract.

## One process, one store

Every API service in satd is a query layer over the same RocksDB store and
chainstate the node itself uses. That covers JSON-RPC, Esplora, Electrum,
BIP 157/158 filters, the streaming APIs, and MCP. The store is updated
atomically inside block connection, so there is no second process and no second
copy of the data. A satd deployment replaces the usual assembly of `bitcoind`,
`electrs`, an Esplora indexer, and exporters with a single process that shares
the node's storage across all surfaces.

This removes two failure modes of external indexers: the parallel block
re-scan, and the reorg-window race where the indexer's view lags the node.
Every surface reads one tip-consistent store.

The trade-off is disk. Serving Electrum, Esplora, `getrawtransaction`, and
BIP 158 from one node makes satd's aggregate on-disk index larger than a
standalone external index. See [Disk Footprint & Indices](disk-footprint.md)
for the byte-level accounting, and [API Scaling & Runtimes](api-scaling.md) for
the scale-out trade-off.

## How this manual is organized

- **Operating**: the day-to-day surfaces. [Observability and
  metrics](observability.md); [configuration, tuning, and live
  reload](configuration.md); [initial block download and AssumeUTXO fast
  sync](ibd.md); [API scaling and the two-runtime model](api-scaling.md);
  [authentication and authorization](authentication.md), covering
  Core-compatible credentials and the unified bearer-token layer; the
  [JSON-RPC extensions](json-rpc-extensions.md); and the [`sat-tui`](tui.md)
  terminal dashboard.
- **Protocol Surfaces**: the [Esplora REST API](esplora.md) and [Electrum
  protocol](electrum.md) references, the [streaming consumption
  API](streaming.md), and the [MCP server](mcp.md). Each runs as a native,
  shared-chainstate subsystem of `satd` itself rather than as a companion
  process. The [Disk Footprint & Indices](disk-footprint.md) chapter covers
  what the single shared store costs and provides.
- **Packaging & Deployment**: the authoritative [packaging
  contract](packaging.md) for downstream distributions. File layout, signals,
  ports, the release and signing pipeline, and reproducible builds.
- **Reference**: the [Configuration Flag Reference](config-reference.md). Every
  recognized config key, its default, its reload disposition, and whether it is
  Bitcoin Core-compatible or a satd extension.

## Related documents (in the repository)

These live at the repository root rather than in this manual:

- [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md):
  the catalog of intentional deviations from Bitcoin Core.
- [`STABILITY_POLICY.md`](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md):
  the tiered stability contract and deprecation policy.
- [`SECURITY.md`](https://github.com/epochbtc/satd/blob/master/SECURITY.md):
  signing keys, verification commands, and vulnerability reporting.
- [`MANIFESTO.md`](https://github.com/epochbtc/satd/blob/master/MANIFESTO.md):
  node sovereignty, the monoculture risk, and the conservative BIP policy.
- [`ROADMAP.md`](https://github.com/epochbtc/satd/blob/master/ROADMAP.md):
  upcoming operator features and research areas not yet shipped.
- [`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md):
  the wire-level specification of the streaming-consumption API. It is a
  protocol spec; this manual documents the shipped surface.
