# Guided Code Tour

The [guided code tour](tour.html) is a slide deck that walks the satd source
module by module. Each subsystem gets an introduction, verbatim source
snippets with `file:line` references, the design trade-offs, and a comparison
to the equivalent Bitcoin Core implementation.

[**Open the code tour**](tour.html)

The tour opens as a full-page deck outside the manual layout. Navigate with
the arrow keys. Press `t` for the table of contents. Use the `manual` link in
the footer to return here.

## What it covers

Nine parts, 42 slides:

1. **Orientation**: the compatibility thesis, the workspace crate map, and the
   architecture at a glance.
2. **Storage**: the `Store` trait, the RocksDB column-family schema, the coin
   cache, flat block files, and undo data.
3. **Chain and validation**: `ChainState`, the connect pipeline, reorg
   atomicity, the dual script engines, parallel IBD, and AssumeUTXO.
4. **P2P networking**: the peer-manager actor model, BIP 324 transport, the
   swarm IBD scheduler, addrman, compact blocks, and Tor.
5. **Mempool and mining**: the two-class mempool, fee estimation, block
   templates, the policy language, and the Lightning danger gate.
6. **RPC and surfaces**: the middleware stack, Core compatibility machinery,
   authentication, Esplora, and Electrum.
7. **Indexes**: the shared write batch, the address index schema, BIP 158
   filters, the BIP 352 tweak index, and deferred backfill.
8. **Streaming and ops**: the event envelope, watch streams, the Rust and Go
   SDKs, alerts, and the operator tooling.
9. **satd vs Core**: default differences, intentional exclusions, how parity
   is proven, and migration.

## Snapshot provenance

The deck is a snapshot. Every snippet and `file:line` reference was taken
from master at commit `4874b537` (2026-08-19). The code moves; the commit
pins where each snippet came from. To read a referenced file at that exact
state, run:

```sh
git show 4874b537:node/src/chain/state.rs
```
