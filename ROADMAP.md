# satd Roadmap

This document outlines upcoming operator-focused features and research areas for `satd`.

These items are organized into tiers based on their impact and feasibility for operators. This is a living document and priorities may shift.

## Advanced Mempool Sovereignty

While `satd` currently matches Core's mempool policy defaults and exposes basic flags (`-datacarrier`, `-dustrelayfee`), our ultimate goal is to give operators programmatic, frictionless control over what their hardware validates.

### Transaction Validation DSL (Domain Specific Language)
**Proposal:** A lightweight, strictly bounded rule engine (e.g., via YAML/JSON or a highly constrained scripting environment) that evaluates every transaction before it enters the mempool.
**Why it matters:** It completely removes `satd` developers from the policy debate. If a new class of spam or controversial transaction format emerges, operators do not have to wait for a software update or run a patched C++ fork (like Bitcoin Knots) to filter it. They simply update their local policy ruleset.
**Security constraint:** Because this runs on every incoming transaction, the DSL must be strictly bounded in execution time and memory to prevent DoS attacks. No loops, no external network calls, just flat boolean evaluation of transaction metadata (e.g., `tx.witness.size > 400000`, `tx.has_op_return == true`).

### Granular Script Type Filtering
**Proposal:** Explicit CLI toggles for *every* standard script type, rather than just bare multisig or OP_RETURN.
**Why it matters:** Operators can strictly define the shape of their mempool. Knobs would include `--permit-p2pk=0`, `--permit-p2tr=1`, or `--permit-unknown-witness-versions=0` (preventing future upgrade vectors without explicit operator opt-in).

### Economic Content Discrimination (Fee Multipliers)
**Proposal:** Instead of flat-out rejecting certain transaction types, allow operators to demand a premium fee rate for them.
**Why it matters:** An operator might allow large `OP_RETURN` data blobs, but require them to pay 2x the standard minimum relay fee to compensate for the bandwidth/storage bloat.

### Dynamic Dust Thresholds
**Proposal:** `--dynamic-dust=1` — Automatically scales the dust threshold as a percentage of the trailing 24-hour median block fee.
**Why it matters:** A static `3000 sat/kvB` dust limit is insufficient to prevent UTXO set exhaustion during extreme high-fee environments. Dynamic thresholds protect the node when network congestion spikes.

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
