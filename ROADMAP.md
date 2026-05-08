# satd Roadmap

This document outlines upcoming operator-focused features and research areas for `satd`.

These items are organized into tiers based on their impact and feasibility for operators. This is a living document and priorities may shift.

## Upcoming Operator Features

### PSBT signing (stdin-keyed, no stored keys)
`satd` today has all the non-signing PSBT ops (create, decode, analyze, combine, finalize, join, utxoupdate). Signing is missing because `satd` is keyless by design.
**Proposal:**
- `signpsbtwithkey`: WIF or xpriv provided on stdin, never stored, zeroed after use.
- External-signer dispatch protocol: stdin/stdout JSON frames so hardware wallets / SSS / airgap signers can plug in.
- Miniscript-aware signing (BIP 388 wallet policies) — descriptor language + output modeled on Sparrow's UX.

### AssumeUTXO `--fast-start`
**Proposal:** `satd` automatically fetches the latest published AssumeUTXO snapshot over P2P, loads it into a background RocksDB instance, and swaps it in when ready.
**Why it matters:** Fast node sync without manual `loadtxoutset` commands.

### Resource budget caps (`--max-cpu`, `--max-memory`, `--max-disk-growth-per-day`)
**Proposal:** Hard caps enforced at the scheduler layer:
- `--max-cpu=50%` — cgroup-style throttle.
- `--max-memory=3GB` — strict memory ceiling covering coin cache + mempool + RocksDB block cache. Shrink caches proactively before OOM.
- `--max-disk-growth-per-day=5GB` — if about to exceed, prune aggressively or pause non-critical indexes.
**Why it matters:** On shared hardware (e.g., Pi running Umbrel), the node can starve its neighbors during IBD.

### Bandwidth caps + "data cap" awareness
**Proposal:**
- `--max-upload-per-month=500GB` — cumulative counter persisted across restarts.
- `--max-upload-rate=5Mbps` and `--max-download-rate=50Mbps` — token bucket at the socket layer.
- Configurable "upload-only at night" window.

### Adaptive dbcache sizing
**Proposal:** Instead of a static `-dbcache=N`, an adaptive mechanism that monitors system RAM and scales RocksDB block cache dynamically, releasing memory under OS pressure.

### Config hot reload on SIGHUP
**Proposal:** Reload `satd.conf` on `SIGHUP` and apply changes (e.g. log levels, P2P limits, metrics binds) without dropping the P2P swarm or flushing the chainstate.

### Built-in alerting hooks
**Proposal:** Webhook dispatches for node health events (e.g., IBD complete, new connection, low disk space, mempool congestion).

### CPFP helper RPC
**Proposal:** `bumpfeerate <txid> <target_feerate>` RPC that automatically crafts a Child-Pays-For-Parent transaction if the user controls one of the outputs.

### Block storage compression (zstd)
**Proposal:** Optional per-file zstd compression (`--blocks-compression=zstd`) for the raw block data. Expected ~25–30% disk savings at the cost of some CPU overhead.

### SD-card-friendly write discipline
**Proposal:** `--sdcard-safe` mode: rate-limit RocksDB compactions, batch log writes, and warn if OS appears to be on removable media.
