# satd Roadmap

This document outlines upcoming operator-focused features and research areas for `satd`.

These items are organized into tiers based on their impact and feasibility for operators. This is a living document and priorities may shift.

## Advanced Mempool Sovereignty

While `satd` currently matches Core's mempool policy defaults and exposes basic flags (`-datacarrier`, `-dustrelayfee`), our ultimate goal is to give operators programmatic, frictionless control over what their hardware validates.

### Transaction Validation DSL (Domain Specific Language)
**Proposal:** A lightweight, highly constrained rule engine that evaluates every transaction before it enters the mempool. By folding all filtering strategies into a single DSL, we eliminate the need to hardcode new CLI flags every time a controversial transaction format emerges.

Operators could define local rulesets using simple boolean logic on transaction metadata. For example:
- **Granular Script Filtering:** `tx.outputs.any(out => out.script_type == 'p2tr') -> reject`
- **Economic Discrimination:** `tx.has_op_return && tx.fee_rate < (network.min_relay * 2) -> reject`
- **Witness Size Caps:** `tx.witness.size > 400000 -> reject`

**Why it matters:** It completely removes `satd` developers from the policy debate. Operators do not have to wait for a software update or run a patched C++ fork (like Bitcoin Knots) to enforce their preferences. They simply update their local policy.

**Crucial Security Constraint (DoS Protection):** Because this runs on every incoming transaction, the DSL **must not be Turing complete**. It must be strictly bounded in execution time and memory. The engine will support *no loops*, *no recursion*, and *no external network calls*—only flat, O(1) or O(N) boolean evaluations of static transaction metadata. This ensures the DSL cannot be used as an attack vector to exhaust node CPU or memory.

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
