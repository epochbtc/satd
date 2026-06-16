# satd Roadmap

This document outlines upcoming operator-focused features and research areas for `satd`.

These items are organized into tiers based on their impact and feasibility for operators. This is a living document and priorities may shift.

## Advanced Mempool Sovereignty

While `satd` currently matches Core's mempool policy defaults and exposes basic flags (`-datacarrier`, `-dustrelayfee`), our ultimate goal is to give operators programmatic, frictionless control over what their hardware validates.

### Transaction-Filtering Policy DSL
**Status:** ✅ Shipped (0.4.0, opt-in via `policyfile=`). A lightweight, highly
constrained rule engine that evaluates every transaction at mempool admission.
By folding all filtering strategies into a single DSL, we eliminate the need to
hardcode new CLI flags every time a controversial transaction format emerges.

**Quarantine, not reject.** The crucial design choice: a rule never makes the
node *reject* a consensus-valid transaction (which would risk forking the node's
mempool off the network and, worse, give a false sense that filtering removes a
transaction — it does not). Instead it **quarantines**: the transaction is held
but withheld from relay and/or block templates. Consensus is untouched, the
node stays in sync, and — because a held transaction is visible and a verdict is
reversible on one `SIGHUP` — a too-broad rule is survivable rather than silent
and permanent. The guiding honesty: *filtering cannot prevent confirmation; it
can only decline to assist it.*

Operators define local rulesets with simple boolean logic on transaction
metadata. For example:
- **Self-identifying markers:** `any input (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))`
- **Economic discrimination:** `any output (out.script_type == op_return and out.op_return_size > 83) and tx.fee_rate < node.min_relay_fee * 3`
- **Mine-neutral witness caps:** `quarantine ... on template when tx.total_witness_size > 100kb`

**Why it matters:** It removes `satd` developers from the policy debate.
Operators do not have to wait for a software update or run a patched C++ fork
(like Bitcoin Knots) to enforce their preferences — they update a local file and
`SIGHUP`. The quarantine view (`getquarantineinfo`, `listquarantine`,
`policytest`, Prometheus) lets them measure a rule's effect, including watching
filtered transactions confirm anyway.

**DoS protection:** the DSL is **not Turing complete** — no loops, no recursion,
no external calls — and is statically cost-bounded with a runtime fuel backstop,
so it cannot exhaust node CPU or memory. See the
[Transaction-Filtering Policy](https://epochbtc.github.io/satd/policy.html)
Operator Manual chapter.

**Fast-follow (Tier 2):** general byte transforms (`rc4`/`sha256`/`reverse` +
`tx.first_input_txid`/`out.op_return_data`, a `version 2` file) for protocols
that obfuscate a self-carried marker — sequenced after the version-1 cost model
is proven on the dogfood fleet.

### Dynamic Dust Thresholds
**Proposal:** `--dynamic-dust=1` — Automatically scales the dust threshold as a percentage of the trailing 24-hour median block fee.
**Why it matters:** A static `3000 sat/kvB` dust limit is insufficient to prevent UTXO set exhaustion during extreme high-fee environments. Dynamic thresholds protect the node when network congestion spikes.

## Upcoming Operator Features

### PSBT signing (stdin-keyed, no stored keys)
`satd` has all the non-signing PSBT ops (create, decode, analyze, combine, finalize, join, utxoupdate). The node stays keyless by design, so signing happens **client-side in `sat-cli`** — the key never travels over RPC.
- ✅ **Shipped:** `sat-cli signpsbtwithkey` — WIF or xpriv read from stdin (no-echo prompt on a TTY), key material best-effort erased after use, never sent to the daemon. Signs p2pkh / p2wpkh / p2sh-p2wpkh / p2tr key-path inputs, emitting a signed PSBT to feed into `finalizepsbt`. An xpriv is expanded client-side over the standard BIP 44/49/84/86 paths (`--gap`-bounded), so it signs derivation-free PSBTs — including satd's own `createpsbt` output — as well as PSBTs that carry `bip32_derivation`. Workflow: `createpsbt` → `utxoupdatepsbt` → `signpsbtwithkey` → `finalizepsbt` → `sendrawtransaction`.
- ✅ **Shipped:** `sat-cli signpsbtwithsigner` — external-signer dispatch over the HWI / Bitcoin-Core arg-based contract (`<signer> enumerate` + `--fingerprint=<fp> --chain <net> signtx <psbt>`), so the real `hwi` tool and any conforming script (hardware wallet / airgap / SSS) can sign. The key stays in the signer process; the daemon is untouched. Scope: `enumerate` + `signtx` (`displayaddress`/`getdescriptors` deferred). A device only signs inputs carrying its own `bip32_derivation` — properly-formed PSBTs, not satd's bare `createpsbt` output.
- **Next:** Miniscript-aware signing (BIP 388 wallet policies) — descriptor language + output modeled on Sparrow's UX, for signing arbitrary script paths beyond the standard single-key types.

### AssumeUTXO `--fast-start`
**Status:** ✅ Shipped. `--fast-start=<url>` (or a local file path) downloads a
UTXO snapshot at startup, waits for header sync to reach the snapshot's anchor,
and loads it automatically — no manual `loadtxoutset`. Remote sources must be
`https://` (plain `http://` is refused; certificates are validated); the file
itself is verified against satd's hardcoded anchor hash, so a tampered or wrong
snapshot is rejected regardless of where it came from. Download progress renders
in the pre-RPC startup TUI gauge (like a reindex); the genesis→snapshot
background re-validation is visible in `getchainstates`. satd deliberately does
**not** host or distribute snapshots, and there is no P2P snapshot fetch — the
operator names a trusted source.
**Next:** mirror lists / multiple fallback URLs are a possible ergonomic
follow-up; the trust root stays the hardcoded anchor either way.

### Resource governance on shared & constrained hardware
On shared hardware (e.g., a Pi running Umbrel) the node can starve its neighbors, fill the disk, or get OOM-killed mid-write. But not every resource belongs under daemon control.

**Guiding principle:** satd owns a resource control only when enforcement needs *internal knowledge* (which bytes are prunable vs. load-bearing, which cache to shrink) or must *survive restarts* (a persistent counter). Otherwise the kernel, cgroups, systemd, or the container does the job better, and satd's job is to document the knob — not reinvent it. Our deployment targets (Umbrel, Start9, Pi-in-a-container) already run everything under cgroups, so a daemon-side reimplementation would duplicate infrastructure that's already present and more capable. The subsections below apply this principle to CPU, memory, disk, and bandwidth.

#### CPU — delegate to cgroups / systemd
No daemon-side flag. The kernel CFS scheduler — `CPUQuota=` under systemd, `--cpus` under Docker, `cpu.max` under a raw cgroup — throttles more precisely than satd could from userspace, where the only lever is inserting sleeps into its own verification loops (strictly worse). `docs/manual/src/packaging.md` should document the recommended `CPUQuota=` for a Pi profile rather than satd growing a `--max-cpu` flag.

#### Memory — daemon governs, cgroup backstops
An external memory limit (cgroup `memory.max`, Docker `-m`) enforces via the **OOM killer**: when satd crosses the limit it is SIGKILL'd mid-write — exactly the unclean-shutdown / corrupted-chainstate scenario the Pi-ergonomics work guards against. The daemon's value-add is *staying below* the cap, not capping: it knows its footprint is split across the CoinCache clean-LRU, the RocksDB block cache, and the mempool, and can shrink them proactively under pressure.

**Proposal:** `--max-memory=3GB` — a soft **governor target**, not a hard ceiling. It extends the existing `--dbcache=auto` controller (see "Adaptive dbcache sizing" below, already monitoring `/proc/meminfo` and resizing both caches) from "react to system memory pressure" to "hold caches under an operator-set budget." Set it ~15% below the cgroup `memory.max` so the daemon back-pressures before the kernel kills. Best practice is both layers — cgroup as the hard backstop, daemon as the soft governor — not one or the other.

#### Disk — total footprint cap (`-maxdiskusage`)
**Proposal:** `-maxdiskusage=<size>` — a holistic cap on satd's datadir footprint. This replaces the earlier `--max-disk-growth-per-day` idea: a *rate* cap is the wrong unit. It bites hardest during IBD / index backfill (when growth is fast and you want sync to finish) and almost never triggers at steady-state tip. Operators don't fear "grew 5 GB today"; they fear "my SSD fills up" — a total cap maps directly to that, and to the mental model they already have from `-prune`.

It is a **superset of `-prune`, not a parallel knob.** Core's `-prune=<MiB>` caps *block files* only; it ignores chainstate and indexes (the address index alone is 120–180 GB at mainnet tip). `-maxdiskusage` accounts for blocks + chainstate + indexes + undo together, and as it approaches the limit grades its response: tighten the effective prune target → pause non-critical index backfill (address, filters) → refuse new backfills → alert. Only satd can do this, because only satd knows which bytes are prunable vs. load-bearing — a filesystem quota just returns `ENOSPC`, which is catastrophic for a database mid-write.

**Hard floor, fail loud.** Chainstate is not prunable and grows on its own, so if `-maxdiskusage` is set below `chainstate + minimum block window + WAL`, satd cannot honor it and must refuse at startup with a clear message — never silently thrash or corrupt.

**Optional refinement (not first):** `-mindiskfree=<size>` — stop growing when free space on the *volume* drops below N, protecting other tenants on a shared host (the Umbrel "don't starve neighbors" concern). Complementary to the footprint cap; the footprint cap ships first.

#### Bandwidth — mostly delegated / already shipped
The cumulative upload cap is application state with block-serving semantics — the daemon is the only thing that knows the rolling counter and can stop serving historical blocks while still relaying — which is why Core has `-maxuploadtarget`, and satd shipped it in 0.2.0. What remains is marginal: a socket-layer token bucket (`--max-upload-rate` / `--max-download-rate`) that overlaps with `tc` traffic shaping, and a configurable "upload-only at night" window. Low priority; the persistent-counter need is already met. The disk-*rate* signal, likewise, belongs in the alerting-hooks feature as an early-warning webhook ("disk growing faster than expected"), not as an enforcement knob.

### Adaptive dbcache sizing
**Status:** ✅ Shipped. Exposes `--dbcache=auto` which spawns a background controller task monitoring `/proc/meminfo` on Linux hosts. It resizes both the RocksDB block cache and CoinCache clean-LRU on a 30s tick in response to system memory pressure, automatically backing off during IBD vs. steady tip operation and contracting on sharp memory drops.

### Config hot reload on SIGHUP
**Status:** ✅ Shipped. `SIGHUP` (or `systemctl reload satd`) re-reads `bitcoin.conf` and applies the hot-reloadable subset live without dropping the P2P swarm or flushing the chainstate — CLI flags stay authoritative (only the file is re-read). Bitcoin Core uses `SIGHUP` to reopen `debug.log`; satd logs to stdout (no `debug.log`) and repurposes the signal for config reload. Applied live: log verbosity (`-debug`/`-debugexclude`), connection knobs (`-timeout`/`-blocksonly`/`-maxuploadtarget`/`-v2transport`/`-v2only`/`-externalip`/`-whitelist`), RPC-behavior switches (`-rpcextendederrors`/`-rpcdefaultunits`), mempool/relay policy (`-minrelaytxfee`/`-maxmempool`/`-dustrelayfee`/`-datacarrier(size)`/`-mempoolfullrbf`/`-limitancestorcount`/`-limitdescendantcount`/`-mempoolexpiry`/`-permitbaremultisig`), and the peer-limit knobs (`-maxconnections`/`-maxinboundperip`/`-bantime`). Settings wired into long-lived state at startup (network, datadir, ports/binds, `-dbcache`, indexes, TLS, seeds, Tor) are reported as "restart required" and never silently ignored; a reload that fails to parse keeps the running config and never crashes the daemon. Per-key reference in the operator manual (`docs/manual/src/configuration.md`); behavior contract in `CORE_DIFFERENCES.md`.

### Built-in alerting hooks
**Proposal:** Webhook dispatches for node health events (e.g., IBD complete, new connection, low disk space, mempool congestion).

### CPFP helper RPC
**Proposal:** `bumpfeerate <txid> <target_feerate>` RPC that automatically crafts a Child-Pays-For-Parent transaction if the user controls one of the outputs.

### Block storage compression (zstd)
**Proposal:** Optional per-file zstd compression (`--blocks-compression=zstd`) for the raw block data. Expected ~25–30% disk savings at the cost of some CPU overhead.

### SD-card-friendly write discipline
**Proposal:** `--sdcard-safe` mode: rate-limit RocksDB compactions, batch log writes, and warn if OS appears to be on removable media.

## Network Privacy & Anti-Surveillance

### BIP 324 v2 encrypted transport + v2-only peer policy
**Status:** ✅ Shipped. The ElligatorSwift + ChaCha20-Poly1305 v2 handshake runs on both inbound (responder) and outbound (initiator) connections via the rust-bitcoin `bip324` crate, with v1↔v2 detection and outbound downgrade-reconnect. `-v2transport` is on by default (Core parity); the satd-specific `-v2only` (off by default) refuses non-v2 peers. Composes with `-proxy`/Tor; `getpeerinfo.transport_protocol_type` and the `satd_peer_connections_v2` metric expose per-peer status.

**Why `-v2only` matters:** Greg Maxwell (gmaxwell) has observed that, as of 2025, virtually none of the spy / DoS / surveillance nodes on the network support v2 transport. Disconnecting anything not using v2 sheds essentially all of that traffic without banlists or mass-connector heuristics. It also drops legitimate not-yet-upgraded honest peers, so `-v2only` stays **opt-in** until v2 adoption is high enough that the connectivity tradeoff is safe.

**Future work:** consider surfacing v2 vs v1 peer ratios in the TUI, and revisiting the `-v2only` default as adoption rises.

## Streaming Consumption API

**Status: ✅ Shipped.** A push-based, streaming-first node-consumption API: a
real-time event firehose plus live, cursor-resumable watch subscriptions keyed
on outpoints, scripts, descriptors, and transaction ids — served over gRPC,
JSON/WebSocket, SSE, and a Core-compatible ZMQ sink. The generalizing primitive
is **outpoint subscription**: channel-close detection, watchtower triggers,
deposit confirmation, and theft monitoring all reduce to it, and address-watching
is outpoint-watching with a derivation rule on top. Durable confirmed-side
cursors `(height, tx_index)` replay straight from the block index. The matcher
runs off the consensus hot path on the isolated API runtime (`--api-threads`), so
a slow or flooding consumer can never backpressure block connection or mempool
acceptance; auth and per-token watch quotas reuse the unified `satd-auth` layer.

Integrator guide: the **Streaming Consumption API** chapter of the operator
manual ([`docs/manual/src/streaming.md`](docs/manual/src/streaming.md)).
Authoritative wire spec: [`docs/api/streaming.md`](docs/api/streaming.md).

**Possible follow-up (uncertain):** standardizing the wire protocol as an open,
transport-agnostic spec with a second (bitcoind-sidecar) implementation — a
governance lift deferred until a real downstream consumer's feedback justifies
it. Mining ops (`getblocktemplate` / `submitblock` — Stratum is the venue),
wallet key management, and any consensus / block-production knobs remain
explicitly out of scope.

## Ecosystem & Mobile Integration

satd's mobile and self-custody strategy is to be **the server half**, not to
ship a mobile wallet: the phone holds keys and scans filters, while satd runs on
the user's home server or Pi and serves filters, mempool, blocks, history, and
broadcast — one trusted party (the user) and no custodial intermediary. The
wallet-facing surfaces that realize this — Electrum, Esplora REST, BIP 157/158
compact filters, and Core-compatible JSON-RPC — are **shipped** (see the operator
manual's [Native Protocol Architecture](docs/manual/src/native-protocol-surfaces.md)
chapter). What remains below is unshipped; likelihood is tagged.

**Likelihood legend:** **(likely)** — intend to ship · **(plausible)** — wanted,
not committed · **(uncertain)** — only if a clear need emerges · **(non-code)** —
an outreach / ops effort, not a feature.

### Silent Payments (BIP 352) index — (plausible)
Server-side scanning of every output's ECDH tweak, pushing only the relevant
outputs to the client; without server-side indexing, SP is impractical on mobile.
Rides on the same scan-every-output infrastructure as the shipped address-history
index — likely that index extended rather than a parallel one.

### Mobile push notifications (APNs / FCM) — (plausible)
Push to a mobile wallet on relevant block / tx events so the app needn't stay
awake polling. Pairs naturally with the shipped streaming watch-matcher as the
event source.

### LND-compatible gRPC / REST — (uncertain)
Would let Zeus and other LND-aware wallets treat satd as "my remote LND." Large
surface; only worth it if satd makes a deliberate Lightning-first move. Deferred.

### Grafana dashboard JSON — (likely)
A bundled `contrib/grafana/` dashboard over the shipped Prometheus `/metrics`
endpoint. Small, self-contained, high operator value.

### Raspberry Pi validation pass — (likely)
Benchmark and tune `dbcache` / `maxmempool` / parallel-verify defaults on 4 GB /
8 GB Pi 5 hardware, and validate the pruning + AssumeUTXO recommended profile
end-to-end on-device. The code paths are shipped; this is the empirical tuning +
sign-off the packager-ready gate calls for.

### Ecosystem outreach — (non-code)
Open the first Umbrel and Start9 app PRs ourselves rather than waiting for
volunteers; recruit one maintainer from each into early packaging review; stand
up a publicly-reachable reference deployment (satd on a real Pi 5 with the Umbrel
app) linked from the README; maintain presence in the relevant packaging channels
(`#umbrel-dev`, the Start9 community, BTCPay ops).

### Open questions
- Sponsor / upstream satd-specific presets into an existing mobile wallet
  (Nunchuk, BlueWallet), or stay a pure server?
- Support a non-Tor cloud-accessible deployment path (HTTPS reverse proxy,
  Tailscale, mutual-TLS), or intentionally de-emphasize it in favor of Tor-first?
- Build the Silent Payments index on top of the address-history index, or as a
  parallel index? (Likely the former, given the shared scan-every-output shape.)
