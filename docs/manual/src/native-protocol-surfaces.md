# Native Protocol Architecture

satd serves the Electrum protocol, the Esplora REST API, and the BIP 157/158
compact-filter service as **native subsystems inside the `satd` binary**, gated
by runtime flags (`--electrum=1`, `--esplora=1`, `--blockfilterindex=basic
--peerblockfilters=1`). The `block-filter-index` Cargo feature additionally
allows compiling out the BIP 158 codec entirely for a consensus-only build.

This chapter documents the architecture and the design rationale behind that
choice. For operator flags and tuning see [Configuration, Tuning &
Reload](configuration.md); for the wire surfaces see the [Esplora REST
API](esplora.md) and [Electrum Protocol Server](electrum.md) chapters; for how
these surfaces authenticate (and the unified bearer-token layer) see
[Authentication & Authorization](authentication.md); for
the catalog of shipped surfaces see
[`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md)
§"Native protocol surfaces".

The architectural story — and the headline differentiator over the `bitcoind` +
`electrs` status quo — is that **Electrum and Esplora are query layers over
satd's chainstate, not a separate process maintaining a parallel index**.

## Why native + shared chainstate, not bundled electrs

A bundled-electrs companion solves install-friction but inherits the
architectural costs of the two-process world: a *second copy* of the
address-history data living in its own database, parallel block re-scanning to
build it, and a reorg-window race where the Electrum view lags the chainstate.
None of those go away by vendoring `electrs` alongside `satd`.

Native + shared chainstate gives:

- **One RocksDB instance.** Same WAL, same crash recovery, same backup target.
- **No duplicate scriptPubKey scanning.** The address-history index is updated inside the existing `connect_block` / `disconnect_block` loop — no second pass over the blocks to build a parallel database.
- **Atomic reorg consistency.** The index update lives in the same `WriteBatch` as the chainstate update, so protocol handlers can never observe an index out of sync with the tip.
- **Sub-millisecond, O(1) index lookups.** Address history, outpoint-spend, and txid lookups are direct keyed reads on fixed-width keys — function calls, not RPC, and not range scans over a derived view.
- **Native TLS.** No need to configure or bundle reverse proxy sidecars like nginx just to terminate TLS for these protocol servers.

That's the architectural claim worth making in the announcement. A
bundled-electrs approach can't earn it.

Because one node serves Electrum *and* Esplora *and* `getrawtransaction` *and*
BIP 158 from a single store, satd's *aggregate* index is **larger** on disk than
any one external indexer — and larger than `bitcoind + txindex + electrs` summed.
That disk buys a tip-consistent, single-process, single-backup deployment. The
full byte-level accounting — what each column family stores, why, and what query
it powers — is in [Disk Footprint & Indices](disk-footprint.md).

## Why a single binary, not separate companion binaries (for v1)

Originally this design proposed separate `sat-electrum` and `sat-esplora`
companion binaries. Revisited: a single `satd` binary with feature flags is
simpler to ship, package, document, and operate, and the failure-isolation
arguments for separation are weaker than they look in modern Rust + tokio code
with bounded subscription queues, request timeouts, and per-connection limits.

Concretely:

- **One systemd unit, one Docker image, one log stream, one PID.**
- **One dbcache budget**, one memory allocator, no double-counting RAM.
- **No RocksDB-secondary-mode coordination problem** — RocksDB doesn't allow concurrent writers; secondary-mode read-only access works but adds lag and schema-coordination headaches.
- **Runtime flags address the "don't pay for what you don't use" concern.** Esplora and Electrum are always compiled into the `satd` binary and are gated at runtime by `--esplora` / `--electrum` (Esplora on by default, Electrum off). The only build-time switch is `--no-default-features`, which compiles out the BIP 158 block-filter-index codec — it does not remove the protocol servers.

The case for separation gets stronger if Electrum subscriptions turn out to be
the dominant memory pressure point in production (mobile wallets subscribing to
thousands of scripthashes). Mitigation in v1: bounded subscription cap,
per-connection memory accounting, easily-flippable feature flag. If pressure
becomes real, a v1.x companion-binary split is cheap because the workspace is
already structured as library crates (see "Workspace structure" below).

## Future split into companion binaries (v2)

If operational data demands process isolation in v2 — e.g. Electrum
subscription RAM pressure competing with UTXO cache, or a desire for tighter
security boundaries on Tor-exposed protocol surfaces — the workspace structure
supports adding `sat-electrum` and `sat-esplora` companion binaries that open
the RocksDB datadir in **secondary mode** (read-only with WAL replay). Same
library code, different deployment shape. v1.x release, not a rewrite.

This is explicitly deferred. Single-binary v1 is the simpler thing.

## Implementation strategy for Electrum + Esplora

### Vendor electrs's protocol code, write the index ourselves

Neither romanz/electrs nor Blockstream/electrs is published as a usable library:
romanz's internal modules are private (`mod`, not `pub mod`), Blockstream's is
`pub mod` but git-only and never API-stable. In both, RocksDB access is
hardcoded — there is no `Store` trait we could implement against satd's
chainstate. The literal "import as crates" approach doesn't exist.

The realistic path is to **vendor specific source files** from romanz/electrs
(MIT licensed, with attribution and license headers preserved) for the
well-tested wire protocol layer, and write the index ourselves against satd's
RocksDB. Vendor-worthy files (~1500 LOC total):

- `electrum.rs` — Electrum wire-protocol parsing + JSON-RPC method dispatch.
- `status.rs` — subscription state machine (`ScriptHashStatus`).
- `merkle.rs` — Electrum merkle-proof construction.
- `types.rs` — wire types.

Refactor their `Index` dependency from a concrete type to a small trait we own
(~4-5 methods: `funding_for(scripthash)`, `spending_for(scripthash)`,
`txids_at(height)`, `header_at(height)`, plus mempool variants).

Esplora REST handlers are a smaller protocol — no upstream borrow needed. Direct
handler implementation against the same `Index` trait.

### Workspace structure

The code is built as library crates so binary count is a packaging decision, not
an architectural one:

- `node-index` — address-history index over RocksDB. The load-bearing crate; both protocols depend on it.
- `electrum-proto` — vendored Electrum protocol layer, depends on the `Index` trait from `node-index`.
- `esplora-handlers` — Esplora REST handlers, depends on the same `Index` trait.
- `satd` (binary) — links all three library crates; the Esplora and Electrum servers are started/stopped by the runtime flags `--esplora` / `--electrum`.

Future companion binaries (`sat-electrum`, `sat-esplora` per "Future split"
above) reuse the same library crates with thin `main.rs` shells.

### Index column-family layout

The address-history index is two RocksDB column families — `addr_funding_v2` and
`addr_spending_v2` — keyed by
`(scripthash_prefix[16], height_be[4], txid[32], vout/vin_be[4])`. See
`node-index/src/keys.rs`. The index is on by default (`--addressindex=1`); opt
out with `--addressindex=0`. Esplora and Electrum auto-require it. After an
AssumeUTXO fast-start, history is backfilled lazily and opt-in via
`backfillindex address` (and `backfillindex blockfilter` for the BIP 158 index);
the node remains usable with partial history.

### Effort estimate (historical, for reference)

The pre-implementation estimate, recorded for posterity:

- **Address-history index** (`node-index` crate): ~3-5 weeks. Column-family layout, IBD-time backfill, online maintenance on connect / disconnect, reorg correctness, mempool tracking.
- **Esplora REST** (native, `esplora-handlers` crate): ~4-8 weeks on top of the index.
- **Electrum** (vendored protocol code, `electrum-proto` crate): ~3-5 weeks of vendoring + adaptation, parallelizable with Esplora.

Both protocols and the index landed in the timeframe estimated.

### Alternatives considered and rejected

- **Bundle electrs as a `sat-electrum` companion binary.** Marginal user-visible UX delta over separately-installed electrs (one install vs. two; auto-wired defaults). Does *not* fix the duplicate-index, parallel-block-rescan, or reorg-race problems — those are architectural, not packaging. Doesn't earn the headline.
- **Fork Blockstream/electrs and swap the storage layer.** ~4-6 weeks Electrum-only, ~8-10 with Esplora REST kept working. Inherits Blockstream's three-DB layout, bincode rows, and Liquid feature flags. Larger surface to maintain forever; less clean conceptually than vendoring just the protocol layer.
- **Full reimplementation of Electrum protocol.** ~12-16 weeks. Defensible but pays the cost of re-deriving well-tested wire-protocol parsing for no gain over vendoring.
