# satd Operator Manual

`satd` is a Bitcoin Core-compatible full node written in Rust, built from the
ground up to make running a node easier, safer, and more transparent for the
people who actually operate infrastructure — home-server and Raspberry Pi
self-custodians, downstream packagers (Umbrel, Start9, RaspiBlitz, MyNode), and
integrators building wallets, Lightning nodes, and explorers on top of a node
they control.

This manual is the operator-, integrator-, and packager-facing reference. It
catalogs every shipped operator surface: observability and metrics,
configuration and tuning, live reload, integrator APIs, the terminal UI, the
native protocol surfaces (Esplora / Electrum / BIP 157-158), and the packaging
contract.

## How this manual is organized

- **Operating** — the day-to-day surfaces: [observability and
  metrics](observability.md), [configuration, tuning, and live
  reload](configuration.md), [authentication and authorization](authentication.md)
  (Core-compatible credentials plus the unified bearer-token layer), the
  [integrator APIs](integrator-apis.md), and the [`sat-tui`](tui.md) terminal
  dashboard.
- **Protocol Surfaces** — the [Esplora REST API](esplora.md) reference, the
  [streaming consumption API](streaming.md), the [MCP server](mcp.md), and the
  [architecture](native-protocol-surfaces.md) behind satd's native, shared-chainstate
  protocol servers (the headline differentiator over the `bitcoind` + `electrs`
  status quo).
- **Packaging & Deployment** — the authoritative [packaging
  contract](packaging.md) for downstream distributions: file layout, signals,
  ports, the release/signing pipeline, and reproducible builds.
- **Reference** — the [Configuration Flag Reference](config-reference.md): every
  recognized config key, its default, reload disposition, and whether it is
  Bitcoin Core-compatible or a satd extension.

## Related documents (in the repository)

These live at the repository root rather than in this manual:

- [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md)
  — the catalog of intentional deviations from Bitcoin Core.
- [`STABILITY_POLICY.md`](https://github.com/epochbtc/satd/blob/master/STABILITY_POLICY.md)
  — the tiered stability contract and deprecation policy.
- [`SECURITY.md`](https://github.com/epochbtc/satd/blob/master/SECURITY.md)
  — signing keys, verification commands, and vulnerability reporting.
- [`MANIFESTO.md`](https://github.com/epochbtc/satd/blob/master/MANIFESTO.md)
  — node sovereignty, the monoculture risk, and the conservative BIP policy.
- [`ROADMAP.md`](https://github.com/epochbtc/satd/blob/master/ROADMAP.md)
  — upcoming operator features and research areas not yet shipped.
- The streaming-consumption API is specified in
  [`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md)
  (a forward-looking protocol spec, distinct from this shipped-surface manual).
