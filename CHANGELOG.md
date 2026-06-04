# Changelog

All notable changes to satd are documented here. Format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); satd follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) for its Tier 1
public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per `STABILITY_POLICY.md`.

## [Unreleased]

### Consensus

- **Enforce four previously-missing block-level consensus rules**, all
  surfaced by the differential matrix (see Testing) and now matching Bitcoin
  Core. Each is exercised by the matrix (regtest) and by unit tests; the
  height-gating and exemptions are written to reproduce Core on historical
  mainnet blocks.
  - **Block sigop-cost limit** (`bad-blk-sigops`): `connect_block` now
    accumulates the witness-scaled signature-operation cost across the block
    and rejects when it exceeds `MAX_BLOCK_SIGOPS_COST` (80 000). Height-gated
    to match Core's `GetTransactionSigOpCost` (legacy-only below P2SH
    activation; full BIP141 cost at/after).
  - **BIP30** (`bad-txns-BIP30`): reject a block that re-creates an outpoint
    already holding an unspent coin. Gated to where Core enforces it and
    exempting the two grandfathered mainnet blocks (91 842 / 91 880,
    CVE-2012-1909) so historical replay is unaffected.
  - **Future timestamp** (`time-too-new`): reject a block whose timestamp is
    more than 2 hours ahead of the node's clock. No-op for historical replay.
  - **Block version gate** (`bad-version`): enforce the mandatory minimum
    block version per height (BIP34 ⇒ v≥2, BIP66 ⇒ v≥3, BIP65 ⇒ v≥4).
  - Mainnet IBD-replay verification is recommended before relying on the
    sigop/BIP30 height-gating on mainnet (regtest cannot exercise it).
- **Reject merkle-tree mutation (CVE-2012-2459)** (`bad-txns-duplicate`):
  `check_block` now mirrors Core's `ComputeMerkleRoot` `mutated` out-flag — a
  block whose transaction list duplicates a trailing subtree (e.g.
  `[cb, t1, t2, t2]`) has the **same** merkle root as the honest list, so the
  root comparison alone passes; satd now detects the duplicated adjacent
  subtree and rejects at the correct stage, instead of only catching it later
  in `connect_block` as a double-spend. Surfaced by the block-handling
  equivalence audit (finding A).
- **Per-transaction weight cap in `check_transaction`** (`bad-txns-oversize`):
  reject a transaction whose no-witness serialized size × 4 exceeds
  `MAX_BLOCK_WEIGHT`. The block path was already covered by the block-weight
  check, but a standalone transaction (e.g. `sendrawtransaction`) previously
  slipped through. Surfaced by the block-handling equivalence audit (finding F).
- **Align four block-rejection reason strings to Bitcoin Core** (finding H).
  satd already rejected these blocks/transactions; only the reject-*reason*
  label differed, which matters for operators and tools that key on Core's
  strings. Now matched exactly: empty block `bad-txns-empty` → `bad-blk-length`;
  missing/mismatched witness commitment `bad-witness-commitment` →
  `bad-witness-merkle-match`; output over `MAX_MONEY` `bad-txns-vout-negative` →
  `bad-txns-vout-toolarge` (and the running-total case now distinctly reports
  `bad-txns-txouttotal-toolarge`, matching Core); bad proof-of-work `bad-pow` →
  `high-hash`. The differential matrix is now **32/32 exact** against Core on
  both verdict and reject reason.
- **Reject mutated blocks on receipt (Core's `IsBlockMutated` gate)** (finding
  D). At every P2P block-ingress point — direct `Block` messages and both
  compact-block reconstruction paths (`cmpctblock` reconstructed from mempool
  and the `blocktxn` completion) — satd now rejects a block whose merkle tree is
  malleable (CVE-2012-2459) or that contains a transaction whose non-witness
  serialized size is exactly 64 bytes — a tx that can be reinterpreted as an
  inner merkle node, enabling forged merkle proofs against SPV clients. The
  check is centralized in one `reject_if_mutated` helper applied at all three
  ingress sites so no route into the block-processing channel can bypass it. The
  sending peer is penalized, but the block is **not** marked permanently
  invalid, so an honest block sharing the same hash remains acceptable from
  another peer (avoiding the CVE-2012-2459 index-poisoning DoS). This is a
  networking-layer anti-malleation check, not a new consensus rule: a 64-byte
  transaction remains consensus-valid, matching Core, which performs this check
  outside `CheckBlock`/`ConnectBlock`.

### RPC

- **`invalidateblock` / `reconsiderblock` are now implemented** (previously
  absent), matching Bitcoin Core. `invalidateblock <hash>` marks a block — and
  every descendant — invalid, rolls the active chain back past it, and
  re-activates the best remaining valid chain (a pure truncation to the
  invalid block's parent, or a reorg onto a competing side chain that now
  carries the most work). `reconsiderblock <hash>` clears the invalid mark on
  the block and its descendants and re-activates the best chain (reorging back
  if that chain regains the most work). The `Invalid` mark is persisted in the
  block index **before** the active chain is rolled back, so a crash mid-call
  can never durably truncate the tip while leaving the disconnected block
  `Valid` (which would silently un-do the invalidation); and startup
  reconciliation re-activates the best valid chain if a node is ever loaded
  with its tip on a durably-`Invalid` block (the inverse crash window), so it
  can never boot stuck rejecting extensions as `bad-prevblk`. `accept_block`/
  `store_block` refuse to build on an invalidated parent (`bad-prevblk`), so the
  subtree stays excluded until reconsidered. On an AssumeUTXO node, invalidating
  a block at or below the loaded snapshot height is refused (no undo data
  exists there), matching the reorg-depth guard `accept_block` already enforces. Both are classified `BlockConnecting` (rejected on the
  read-only RPC listener). This lets a single regtest node be driven into a
  reorg without a second node — the standard tool for reorg testing, and it now
  drives the single-node reorg E2E coverage for the Streaming Consumption API
  (`Reorg` / `BlockDisconnected` / `TxidUnconfirmed` over a real socket).
- **`getblock` now serves an invalidated block** (Core parity): an
  `invalidateblock`'d block keeps its data on disk and remains retrievable, and
  the reorg/watch machinery re-reads a just-disconnected block to emit
  `TxidUnconfirmed`. (Header-only and pruned blocks remain unreadable.)

### Testing

- **Block-level consensus differential matrix.** A new golden fixture suite
  (`node/tests/feature_block_consensus.rs`), ported from Bitcoin Core's
  `test/functional/feature_block.py`, pins satd's block- and chain-level
  validation verdicts against Core's reference behavior across 32 cases
  (coinbase structure, merkle, weight, UTXO/amount rules, locktime/sequence,
  difficulty, MTP). Core is the oracle: each case carries Core's exact reject
  reason, and the runner fails CI if satd's verdict drifts in either direction
  — a covered rule that stops matching is a regression, and a known gap that
  starts matching forces the case to be promoted. Phase B of the consensus
  differential-fuzzing roadmap. The matrix surfaced four consensus rules satd
  did not enforce on its accept path — block-wide sigop limit
  (`bad-blk-sigops`), BIP30 duplicate-unspent-txid (`bad-txns-BIP30`),
  2-hour-ahead future timestamp (`time-too-new`), and the mandatory block
  version gate (`bad-version`) — and the deeper code-path equivalence audit
  added two more — merkle-tree mutation (`bad-txns-duplicate`, CVE-2012-2459)
  and a per-transaction weight cap (`bad-txns-oversize`). All six are now
  enforced (see Consensus above), so every case in the matrix matches Core
  exactly on accept/reject (28 also match the reject *reason*; the remaining 4
  reject for the same cause under a different label).
- **Live block-acceptance differential against Bitcoin Core (Phase C).** A new
  integration test (`satd/tests/phase_c_differential.rs`, gated behind the
  `phase-c` cargo feature) spawns BOTH a satd regtest node and a real
  `bitcoind` (`lncm/bitcoind:v27.0`, in Docker) and submits identical
  adversarial blocks/transactions to each via `submitblock` /
  `testmempoolaccept`, asserting they reach the identical accept/reject
  verdict. Where Phase B bakes in Core's verdicts from `feature_block.py`,
  Phase C observes them from a *live* Core (the oracle) and, crucially,
  exercises satd's real composite acceptance path (`accept_block`) rather than
  the validation functions in isolation. Every candidate is built on a tip
  both nodes provably share (a base mined by dual-submitting identical valid
  blocks, coinbases paying bare `OP_TRUE` so spends need no signing), and any
  connectivity/duplicate verdict is treated as a harness bug so it can never
  mask a real divergence. 25 cases run live (24 exact verdict+reason matches,
  plus the documented BIP68 reject-label difference where both nodes reject);
  the run also re-validates the Phase B reject strings against the live node.
  Wired as the PR-gating `canary / Bitcoin Core block-acceptance differential`
  job. Layer 1 of the live differential harness.
- **In-process consensus fuzzer with a live Core oracle (Phase C, Layer 2).** A
  cargo-fuzz/libFuzzer target (`fuzz/fuzz_targets/block_differential.rs`,
  standalone workspace excluded from the normal build) mutates raw bytes into a
  `Block`, fixes the header connectivity fields so it builds on the shared
  genesis tip with valid PoW/time, then runs satd's **real** validation
  IN-PROCESS (`check_block` + `check_block_version` + `connect_block` with the
  bitcoinconsensus script verifier) — so libFuzzer's coverage feedback is
  driven by satd's actual consensus code and a satd panic is caught directly —
  and submits the identical bytes to a resident `bitcoind` as the accept/reject
  oracle. It asserts **verdict (accept/reject) parity**, not reason parity: a
  randomly-mutated block usually violates several rules at once and the two
  implementations legitimately report different first-fault reasons by check
  order, so reason parity stays the curated Layer-1 cases' job. A divergence
  dumps the block hex and aborts (libFuzzer records the input). Runs as the
  nightly/on-demand `Bitcoin Core block-acceptance fuzz` workflow (not
  PR-gating), seeded by `gen_corpus`; a 12.7k-run smoke against Core v27 found
  zero divergences.

### Operator

- **`SIGUSR1` now hot-reloads TLS certificates in place.** `kill -USR1 <pid>`
  re-reads each native-TLS surface's leaf cert/key (`rpctls*`, `esploratls*`,
  `electrumtls*`) from its **already-configured** path and swaps it into the
  live listener without a restart — new handshakes use the new cert, in-flight
  connections keep theirs, and the bound socket never changes. Purpose-built
  for short-TTL auto-rotated certs (cert-manager / ACME / Vault): point a
  renewal hook or a systemd `path` unit at `kill -USR1`. It reloads the leaf
  cert/key only; the cert/key **paths** and the mTLS **client CA** stay
  restart-only. A failed reload (unreadable / malformed / mismatched key) is
  logged per-surface and the previous, still-valid certificate is kept — the
  listener is never left without a usable cert. Deliberately separate from
  `SIGHUP` config reload so frequent automated cert rotation doesn't re-read
  `bitcoin.conf`. Bitcoin Core has no equivalent (no `SIGUSR1` handler, no
  native TLS). See `OPERATOR_ERGONOMICS.md` / `CORE_DIFFERENCES.md`.

- **`SIGHUP` now reloads `bitcoin.conf` live.** Edit the config file and
  `kill -HUP <pid>` (or `systemctl reload satd`) to re-read it and apply the
  hot-reloadable subset of settings without a restart — the P2P swarm and
  chainstate are untouched. CLI flags stay authoritative across reloads (only
  the file is re-read). This is an intentional difference from Bitcoin Core,
  which uses `SIGHUP` to reopen `debug.log`: satd logs to stdout (no
  `debug.log`; rotation is delegated to systemd-journald or the container
  runtime), so `SIGHUP` is free for config reload. Applied live: log verbosity
  (`-debug`/`-debugexclude`), connection knobs
  (`-timeout`/`-blocksonly`/`-maxuploadtarget`/`-v2transport`/`-v2only`/`-externalip`/`-whitelist`),
  the RPC-behavior switches (`-rpcextendederrors`/`-rpcdefaultunits`), mempool
  and relay policy
  (`-minrelaytxfee`/`-maxmempool`/`-dustrelayfee`/`-datacarrier(size)`/`-mempoolfullrbf`/`-limitancestorcount`/`-limitdescendantcount`/`-mempoolexpiry`/`-permitbaremultisig`),
  the peer-limit knobs (`-maxconnections`/`-maxinboundperip`/`-bantime`),
  outbound peers (`-connect`/`-addnode`/`-seednode` — newly-added entries are
  dialed immediately, existing connections untouched), compact-filter serving
  (`-peerblockfilters`), the address-index subscription cap
  (`-addrindexsubscriptions`), the reorg webhook
  (`-reorgwebhook`/`-reorgwebhooksecret`), the shutdown knobs
  (`-persistmempool`/`-maxshutdownsecs`, which take effect at the next
  shutdown), and RPC credentials (`-rpcuser`/`-rpcpassword`/`-rpcauth` rotate
  live on every listener surface; the auto-generated cookie is preserved, and
  the credential values stay redacted in the reload log). Mempool-policy
  changes govern subsequent transaction admissions; connection/ban-limit
  changes apply to new connections and future bans.
  Settings wired into long-lived state at startup that cannot change without
  restarting the relevant socket/engine/process — network, `datadir`,
  ports/binds, `-dbcache`, index enable/disable, TLS material, DNS-seed
  bootstrap, and Tor — are logged as "restart required" and never silently
  ignored. A reload that fails to parse — e.g. a
  typo'd or unknown key, which hard-errors at load — is logged and the running
  config is kept; the daemon never crashes on a bad reload. A test asserts
  every known `bitcoin.conf` key has an explicit reload disposition, so no key
  can silently fall through. See `OPERATOR_ERGONOMICS.md` for the per-key
  reference and `CORE_DIFFERENCES.md` for the behavior contract.

### Authentication & authorization

An opt-in unified auth layer that adds capability-scoped bearer tokens on top of
the Core-compatible operator credentials, without changing any default behavior.
With no `authfile` configured, satd authenticates exactly as before (cookie /
`-rpcuser`/`-rpcpassword` / `-rpcauth`), and those credentials map to a
full-capability "operator" principal so `bitcoin-cli`, BTCPay, and NBXplorer keep
working when the layer is enabled.

- **`-authfile=<path>` — opt-in bearer-token table.** A separate TOML file (kept
  out of `bitcoin.conf` so it stays Core-shaped) listing tokens as
  `sha256:<hash>` (never plaintext), each with a capability set, optional
  watch-set quota / rate limit, and optional expiry. Token `id`s must be unique
  (they key per-tenant accounting and the revocation audit log) and unknown
  capability strings are rejected — both fail the parse loudly rather than
  silently. The file must be a regular file readable only by its owner with no
  execute bit (`0600`, or `0400` for a read-only secret) or satd refuses to start
  (like the cookie). It is re-read on `SIGHUP`
  independently of the rest of the config, so **removing a token and reloading
  revokes it live**; a malformed reload keeps the last-good table. An
  `authfile`-only misconfiguration can never lock out the operator: satd refuses
  to start if no operator credential remains.
- **`-rpcauthbearer` — bearer tokens on the JSON-RPC listeners.** When set
  (requires `-authfile`), the read/write JSON-RPC listeners additionally accept
  `Authorization: Bearer <token>` and enforce **per-method capabilities**:
  `rpc:read` tokens may call read methods, `rpc:write` is required for
  mempool-submit / control / block-connecting / unknown methods (fail-closed). A
  forbidden call returns JSON-RPC error `-32004`. The operator credential keeps
  full access, so the capability filter is a no-op for legacy clients.
- **`-esploraauthbearer` — bearer tokens on the Esplora server.** When set
  (requires `-authfile`), the Esplora HTTP/SSE surface additionally accepts
  `Authorization: Bearer <token>` for tokens holding the `esplora:read`
  capability, alongside the existing `-esploraauth` cookie/userpass credential.
- **`-events-grpc-auth` — bearer tokens on the events gRPC stream.** When set
  (requires `-authfile`), every `Subscribe` must present an
  `authorization: Bearer <token>` metadata entry for a token holding the
  `stream:subscribe` capability; otherwise the stream is rejected with gRPC
  `UNAUTHENTICATED` / `PERMISSION_DENIED`. The loopback / `-events-grpc-allow-remote`
  gate stays as a transport pre-check beneath this app-layer auth. **A remote
  bind now requires auth:** `-events-grpc-allow-remote` is refused at startup
  unless `-events-grpc-auth` is also set (the sink has no transport TLS, so a
  routable bind without bearer auth would be an unauthenticated firehose). A
  proxy/mTLS-terminated deployment keeps the loopback bind and omits
  `-events-grpc-allow-remote`. This mirrors the `-mcpallowremote` → `-mcpauth` rule.
- **`-mcpauth` / `-mcpallowremote` — bearer tokens + safe remote exposure for
  the MCP HTTP server.** With `-mcpauth` (requires `-authfile`), every MCP
  request must present an `Authorization: Bearer <token>` for a token holding
  the `mcp:*` capability; otherwise it is answered with 401. A **non-loopback
  `-mcpbind` is now refused at startup** unless `-mcpallowremote` (which requires
  `-mcpauth`) is set — closing the prior gap where `mcpbind=0.0.0.0` would serve
  the block-connecting MCP tools unauthenticated. Loopback MCP is unchanged.
- **Per-token rate limiting.** A `[[token]]`'s optional `rate_limit = "<n>/s"` is
  now enforced across every bearer-enabled surface with an in-process token
  bucket: an over-budget request is **shed** — HTTP **429 + `Retry-After`**
  (JSON-RPC / Esplora / MCP) or gRPC **`RESOURCE_EXHAUSTED`** — and never
  blocks, so a throttled consumption client can't backpressure block connection
  or mempool acceptance. The operator credential is unlimited. Per-principal
  state is keyed by token id, so a tenant's budget is shared across its
  connections (per-replica; a future Redis backend can make it global).

- **Per-token watch-set quota on live subscriptions.** A `[[token]]`'s optional
  `watch_quota = <N>` now caps how many concurrent Esplora SSE
  address/scripthash watches the token may hold (one subscription = one unit),
  gated by the `stream:watch` capability. A request lacking the capability is
  refused **403**; one over its quota is **429**. The quota composes *above* the
  node-wide `addrindexsubscriptions` cap and is reconciled automatically on
  disconnect (an RAII lease released when the stream drops), so abandoned
  sockets cannot permanently consume a tenant's budget. The operator credential
  and loopback (auth-disabled) requests are unlimited. Like the rate limiter,
  the per-tenant counter is keyed by token id and shared across the tenant's
  connections (per-replica). The gRPC event firehose is gated by
  `stream:subscribe` and its own concurrent-subscription cap instead, as it
  carries no per-scripthash watch set.

### API surface scaling

The unifying goal of these three changes is to bound the blast radius of the
remotely-consumed API surfaces so they can never starve or stall the consensus
core. Default behavior is unchanged and Bitcoin Core-compatible; everything
new is opt-in or a safe-by-default backstop.

- **Consistent per-surface admission control, and recognition of Core's
  `-rpcthreads` / `-rpcworkqueue`.** The JSON-RPC listener now bounds
  concurrent in-flight method calls to `-rpcthreads` (default 16, Core's
  default) and the backlog of waiting requests to `-rpcthreads + -rpcworkqueue`
  (default 64), shedding over-budget requests with **HTTP 429 + `Retry-After`**
  rather than queueing unboundedly. satd previously hard-errored on these two
  Core config keys; they are now honored (a Core-shaped config carrying them
  loads). The events gRPC stream gained matching connection and concurrent-
  subscription caps (`-eventsgrpcmaxconns` / `-eventsgrpcmaxsubscriptions`,
  defaults 64 / 256), returning `RESOURCE_EXHAUSTED` past the cap. Shedding runs
  ahead of authentication and request-body buffering, so a flood — authenticated
  or not — is bounded before it does work. The admission knobs are clamped to a
  sane ceiling so a fat-fingered value can't panic the daemon at boot.
- **Isolated, bounded runtime for the read/streaming surfaces (`--api-threads`).**
  Esplora, Electrum, the events gRPC + ZMQ sinks, and the metrics endpoint now
  run on a **separate, bounded tokio runtime** (default `max(2, cores/4)`
  workers, clamped to 1024) rather than sharing the consensus/P2P core runtime.
  A flood on any consumption surface therefore **cannot** starve block
  connection or mempool acceptance — the isolation is structural, not policy.
  JSON-RPC and MCP stay on the core runtime: they carry the block-connecting
  control methods (`generate*` / `submitblock` / `submitheader` /
  `preciousblock` / `loadtxoutset`), which must originate on the core runtime
  to preserve address-index/SSE event ordering, and keeping JSON-RPC there also
  makes it a "break-glass" admin endpoint that public API load cannot starve.
  `SIGHUP`/`SIGUSR1` reload continues to reach the relocated surfaces unchanged.
- **Opt-in read-only JSON-RPC listener (`-rpcreadonlybind`).** A second
  JSON-RPC listener, served on the bounded API runtime, that dispatches only
  read and mempool-submit methods (`sendrawtransaction`) and rejects block-
  connecting and node-control methods with JSON-RPC error `-32001`. The method
  filter is **fail-closed** — an unclassified method is rejected, never served —
  and a release-safe invariant guard asserts block connection never originates
  on the API runtime. It has its own bind, source-IP allowlist
  (`-rpcreadonlyallowip`), and admission budget (`-rpcreadonlythreads` /
  `-rpcreadonlyworkqueue`), reuses the main listener's authentication, and
  supports **TLS and optional mTLS** like every other surface
  (`-rpcreadonlytlsbind` / `-rpcreadonlytlscert` / `-rpcreadonlytlskey` /
  `-rpcreadonlymtls` / `-rpcreadonlymtlsclientca` / `-rpcreadonlymtlsclientallow`).
  The default remains a single full read/write listener on `-rpcport`; the
  read-only listener is off unless a bind is configured. Lets operators scale
  read RPC traffic horizontally (behind a load balancer) without exposing the
  control plane. See `SATD_API_SCALING.md`.

### Streaming Consumption API

A push-based consumption surface for downstream indexers, wallets, and
watchtowers: a real-time event firehose plus live subscriptions, delivered over
three transports. It is strictly **publish/read-only and decoupled from
consensus** — every sink, the watch matcher, and the WS server run on the
isolated API runtime and consume the node's existing chain/mempool broadcasts
with non-blocking, lossy delivery, so no consumer (slow, lagging, or malicious)
can ever backpressure, stall, or crash block connection or mempool acceptance.
All additions are opt-in; the wire schema is `v1`. See `docs/api/streaming.md`.

- **Event firehose over three transports.** A schema-versioned `NodeEvent`
  stream of mempool, chain (connect/disconnect/reorg), and heartbeat events:
  a **gRPC** server-streaming `Subscribe` and bidirectional `Watch`
  (`-events-grpc-bind`), a **WebSocket + SSE** transport (`--streamws`,
  curl-friendly query params), and Bitcoin Core-compatible **ZMQ** PUB sockets.
  A live category bitfield lets a subscriber select mempool / chain / heartbeat.
- **Durable, reorg-safe cursor replay.** Every confirmed-side event carries a
  `Cursor`; a client persists it and resumes with `from_cursor` on gRPC
  `Subscribe`, WS, and SSE, getting confirmed history replayed from the block
  index then a seamless join to the live stream with boundary de-duplication.
  Replay walks the active chain back from the tip (never the pollutable
  best-known-at-height index), so a reorg at the replay→live seam forwards the
  replacement rather than dropping or duplicating it, and the span is capped.
  The cursor carries a per-process `instance_id` epoch token so a client detects
  a daemon restart (mempool sequence reset) and resets its mempool watermark
  while confirmed replay stays durable.
- **In-band lag signal.** When a consumer falls behind the broadcast buffer it
  receives an in-band `Lagged { dropped_count, resume_cursor }` on every carrier
  (the notice bypasses category filtering) instead of silently missing events —
  it can immediately re-subscribe `from_cursor` and recover the gap.
- **Live watch registry.** A subscription can register, and rotate at runtime,
  a watch-set of **outpoints** (spend detection, mempool + confirmed),
  **scripts** (funding, and spending both in confirmed blocks via undo data and
  in the mempool via prevout scripthashes retained at admission, so a watched
  script's unconfirmed spend is seen without also watching the outpoint),
  **descriptors** (server-side rust-miniscript expansion over a bounded window), and
  **transaction ids** — matched with O(1) inverted indexes that cost a node with
  no watchers nothing. Each watch item charges one unit of an optional per-token
  quota with cross-message de-duplication and per-remove release.
- **Transaction lifecycle watches and confirmation-depth alarms.** A txid watch
  narrates a transaction's full lifecycle — seen (mempool) → confirmed →
  replaced (RBF, with the replacing txid) → evicted (policy) → unconfirmed
  (reorg rollback) — and an optional `auto_close_depth` emits a terminal
  `TxidFinalized` and self-evicts the watch once the tx is buried that deep.
  Separately, single-shot **depth alarms** (`min_depths`) fire `TxidDepthReached`
  the moment a tx reaches N confirmations and then self-evict; a client can arm
  several depths per tx. Depth tracking is reorg-safe (a confirming block reorged
  off the active chain reverts the entry, which re-arms if the tx reappears) and
  resolves already-buried txs best-effort via the txindex.
- **Privacy-preserving prefix watches.** A subscription can watch a *k-bit
  prefix* of `sha256(scriptPubKey)` (`AddScriptPrefixes`) instead of an exact
  script: the server delivers every transaction whose output *or* spent-prevout
  script falls in the 2⁻ᵏ bucket — the full transaction inline, so the client
  filters locally — and learns only the bucket, never the exact script. It is the
  push dual of BIP 158 (output + spent-prevout membership) but with no fetch step
  and full mempool coverage. Granularity is operator-bounded
  (`-streamprefixminbits` / `-streamprefixmaxbits`, defaults 8 / 32; the maximum
  caps precision so a bucket always spans many scripts), and the quota is priced
  by coarseness — a coarser bucket costs proportionally more units. Spent-prevout
  matching covers both confirmed spends (the matched prevout's full script, from
  block undo data) and *unconfirmed* mempool spends; for the mempool side the
  match carries the spent outpoint but not the prevout script (the node retains
  only its hash), so a client resolves the prevout from its own UTXO set.
- **Operator-configurable consumption caps.** Connection, per-connection
  subscription, and inbound-message-size caps for the WS transport
  (`-streamwsmaxconns` / `-streamwsmaxsubscriptions` / `-streamwsmaxmessagebytes`,
  defaults 256 / 256 / 262144; `0` = unlimited), alongside the existing events-
  gRPC connection / subscription caps. Control messages are bounded before they
  allocate, so a malformed or oversized request is rejected, not amplified.

### Monitoring

- **Startup/reindex progress timing is now computed daemon-side.** The node
  tracks elapsed time, throughput rate, and ETA for the pre-RPC startup
  phases (reindex scan/connect, chainstate replay, and the AssumeUTXO
  fast-start download) and reports them on `getstartupinfo` as `elapsed_secs`,
  `total_elapsed_secs`, `rate`, and `eta_secs`. Previously `sat-tui` derived
  these client-side from a cold sample window, so elapsed reset to zero on
  every TUI launch, rate took tens of seconds to appear, and ETA stayed
  blank. Reindex ETAs reuse the weight-aware IBD estimator — which models the
  ~50x per-block processing-cost variation across Bitcoin's history — for a
  stable, converging estimate; the fast-start download gets a simple
  remaining-bytes/rate ETA. `getstartupinfo` is a satd-native pre-init RPC
  with no Bitcoin Core equivalent, so the added fields don't affect Core
  compatibility.
- **`sat-tui` now identifies an unreadable RPC cookie specifically, instead
  of reporting a generic authentication failure.** When the cookie file
  couldn't be read (permission denied, missing, malformed) the TUI fell back
  to an empty auth header, so the request 401'd and surfaced the generic
  "RPC authentication failed" modal — leaving the operator to guess between a
  wrong password and an unreadable cookie. This is easy to hit against a node
  mid-`--reindex-chainstate`: satd holds the cookie at `0600 satd:satd` until
  it reaches READY, so a non-`satd` user can't read it yet. The client now
  keeps the actual read error (e.g. "Permission denied") and shows a dedicated
  "RPC cookie unreadable" modal with that message and cookie-side remediation,
  distinct from the credentials-rejected case. It only applies when satd
  actually returned a 401 (a connection failure still reads as "is satd
  running?"), and auto-recovers: the cookie is re-read on each auth failure,
  so once satd relaxes it to `0640` at READY the next good poll dismisses the
  modal.

### RPC / P2P compatibility (Bitcoin Core clients)

- **JSON-RPC 1.0 / 1.1 requests are now accepted.** satd's RPC server
  previously required strict `"jsonrpc":"2.0"` and rejected any other
  form (including a missing `jsonrpc` member) with `-32600 Invalid
  request`. Bitcoin Core accepts the 1.0/1.1 shapes, and the canonical
  Core client libraries emit them — NBitcoin (→ NBXplorer → BTCPayServer)
  sends `"jsonrpc":"1.0"`, and `python-bitcoinrpc` and many scripts omit
  the member. satd now normalizes request bodies (a `"method"`-bearing
  object, single or batched, gets `"jsonrpc":"2.0"`) before dispatch, so
  these clients work unmodified. Malformed bodies still yield the correct
  `-32700` parse error; responses keep their JSON-RPC 2.0 shape (the Core
  client libraries read `result`/`error`/`id` and don't validate it).
- **`getpeerinfo` now includes `timeoffset` and `inflight`.** Bitcoin
  Core always emits both, and Core client libraries read them without a
  null guard (NBitcoin's `GetPeersInfoAsync` threw on their absence,
  aborting its node connection). `timeoffset` reports `0` (satd does not
  track a per-peer clock offset); `inflight` is an array of in-flight
  block heights, empty in this per-peer record.
- **The per-IP inbound connection cap (`-maxinboundperip`, default 3) no
  longer applies to loopback.** It is an anti-eclipse guard against a
  single remote source; localhost integrations (NBXplorer/BTCPayServer,
  the Electrum/Esplora-personality wallets, multiple local clients) open
  several connections from `127.0.0.1` and were tripping a cap meant for
  hostile peers. Bitcoin Core does not throttle localhost this way. The
  total inbound cap still bounds loopback.
- **New-tip blocks are now announced to peers (BIP 130 `headers` /
  legacy `inv`).** satd connected blocks — whether self-mined via
  `generatetoaddress`/`submitblock` or relayed — without advertising the
  new tip to its peers, so an announcement-driven consumer (another node,
  or a Core-client backend indexing blocks over P2P) learned the height
  by polling yet never fetched the block and stayed unsynced. satd now
  announces each connected tip (suppressed during bulk IBD); peers pull
  the block with their existing `getdata` path.

### P2P

- **A synced node now adopts a competing longer chain announced by an inbound
  peer.** Previously a node that was a passive listener (not in IBD) would not
  reorg onto a better chain announced by a peer that dialed *it*: it requested
  missing blocks by walking forward from its own tip height
  (`tip+1, tip+2, …`), so it never requested the competing chain's **fork
  block** — which sits at a height at or below the listener's tip — and without
  that block's data the reorg could never reconnect. The listener stayed on its
  shorter chain indefinitely. Two fixes: (1) block requests are now **fork-aware**
  — `request_missing_blocks` walks back from the best-work header chain tip to
  the fork point, requesting the blocks it lacks in connect order (including
  fork blocks at heights ≤ the active tip); (2) **headers-first discovery** on
  announcements — an `inv`/`headers` announcement that builds on an unknown
  (competing) chain now triggers a `getheaders` to that peer to learn the
  connecting chain, instead of being dropped (and, for headers, instead of
  ban-scoring an honest peer announcing a better chain). Verified by a
  two-node regtest test where a height-1 listener adopts an inbound peer's
  height-4 competing chain.
  handler answered `MSG_BLOCK` / `MSG_WITNESS_BLOCK` and tx requests but
  silently ignored `MSG_CMPCT_BLOCK` (BIP 152). A Bitcoin Core peer with a
  high-bandwidth compact-block relationship requests the block right after
  its tip as a compact block, so satd never served it — a Core peer would
  receive satd's block *headers* but never the body of the next block,
  stalling with headers-only orphans and never advancing. satd now serves
  these requests with a full `block` message (BIP 152 explicitly permits
  answering `MSG_CMPCT_BLOCK` with a full block, and it is what Core itself
  sends for any block more than a few back from the tip). Block propagation
  satd→Core now works. Surfaced by the new Bitcoin Core interop canary.
- **`sendrawtransaction`-submitted transactions are now relayed to peers.**
  A tx accepted via the `sendrawtransaction` RPC entered the local mempool
  but was never announced to peers — only txs *received from another peer*
  were relayed. An RPC broadcast therefore never propagated to the network.
  satd now `inv`s a locally-accepted tx to every fee-permitting peer,
  synchronously from the RPC handler. Surfaced by the Bitcoin Core interop
  canary; locked by a new two-node regression test
  (`test_rpc_submitted_tx_relays_to_peer`).

### RPC amount formatting (Bitcoin Core parity)

- **BTC-denominated amounts are now emitted with a fixed 8 decimal places**
  (`0.00001000`), byte-for-byte matching Bitcoin Core's `%d.%08d` output,
  instead of the shortest form (`0.00001`). satd previously rendered
  amounts via `serde_json`'s default f64 formatting, which strips trailing
  zeros — and strict Core-amount parsers reject that. In particular **Core
  Lightning's `bcli` plugin** (`json_to_bitcoin_amount`, which reads exactly
  8 fractional digits) failed on `getmempoolinfo`/`estimatefees`, so CLN
  could not start against satd at all. Formatting is now done from the
  integer satoshi value (exact for every amount, no f64 drift) and emitted
  as a JSON **number** literal via `serde_json`'s `arbitrary_precision`
  feature. Affects every BTC-mode amount field (`getmempoolinfo`,
  `gettxout`, `getbalance`, `getrawmempool` fees, `estimatesmartfee`, …);
  the satoshi-unit mode (`-rpc-default-units=sats`) is unchanged. Surfaced
  by the new Core Lightning canary.

### Esplora

- **Coinbase transaction inputs now carry `txid`, `vout`, and `prevout`.**
  satd's Esplora `vin` serialization previously omitted these three fields
  on coinbase inputs. Reference Esplora (blockstream.info) always emits
  them — `txid` as the all-zeros hash, `vout` as `4294967295`, and
  `prevout` as `null` — and strict typed clients (notably BDK's
  `esplora_client`, which types `vin[].txid` as a required field) fail to
  deserialize *any* transaction with a coinbase input when they are
  absent. That broke descriptor-wallet `full_scan` over every
  coinbase-funded address. The fields are now always present and
  byte-identical to upstream. Surfaced by the new BDK descriptor-wallet
  canary; locked by a new in-tree regression test
  (`test_e2e_esplora_coinbase_vin_shape`).

### Testing / CI

- **The third-party canary fleet is now enforced as required status checks**
  on `master` (BDK, Bitcoin Core interop, LND Neutrino, Electrum reference
  wallet, Core Lightning, NBXplorer, BTCPayServer), with a job-level skip
  gate that exempts docs-only PRs so they stay mergeable without running the
  fleet. See `STABILITY_POLICY.md`.
  (`scripts/canary/nbxplorer-smoke.sh`, `scripts/canary/btcpay-smoke.sh`;
  `.github/workflows/canary.yml`). They boot the real downstream Docker
  images against a satd regtest backend and assert full sync / healthy
  operation end-to-end — the first canaries exercising real third-party
  downstreams over RPC **and** P2P. See `STABILITY_POLICY.md`.
- **BDK descriptor-wallet canary is now PR-gating**
  (`scripts/canary/bdk-smoke.sh` + the standalone `scripts/canary/bdk-canary`
  crate). Drives a real third-party wallet (`bdk_wallet` + `bdk_electrum` +
  `bdk_esplora`) through a full descriptor-wallet workflow against a live
  satd — gap-limit `full_scan` over **both** the Electrum and Esplora
  surfaces, coinbase-maturity accounting, a signed spend broadcast via
  Esplora and observed over Electrum, and a confirm step — asserting the two
  surfaces agree byte-for-byte throughout. The real-consumer gate for the
  native Electrum + Esplora surfaces. See `STABILITY_POLICY.md`.
- **Bitcoin Core interop canary is now PR-gating**
  (`scripts/canary/core-interop-smoke.sh`). Peers satd with a real
  `bitcoind` (`lncm/bitcoind:v27.0`) regtest node and asserts bidirectional
  P2P interop: handshake + peer identity, BIP 324 v2 encrypted transport,
  block sync both ways (satd↔Core), and tx relay both ways. The only canary
  that tests satd against the reference implementation directly; it surfaced
  the two P2P fixes above. See `STABILITY_POLICY.md`.
- **Core Lightning (CLN) canary is now PR-gating**
  (`scripts/canary/cln-smoke.sh`). Runs a real CLN node
  (`elementsproject/lightningd:v24.11`) with satd as its Bitcoin backend
  over JSON-RPC (`bcli`, no ZMQ). Asserts CLN syncs against satd and that a
  funded+matured wallet address shows in `listfunds`. Surfaced the
  Core-amount formatting fix above. See `STABILITY_POLICY.md`.
- **Electrum reference-wallet canary is now PR-gating**
  (`scripts/canary/electrum-wallet-smoke.sh`). Runs the actual Electrum
  wallet (`spesmilo/electrum` 4.5.8) headless against satd's Electrum
  server and exercises **SPV** — header-chain verification and merkle
  proofs — which the library-level Electrum checks don't fully cover.
  Asserts Electrum connects + SPV-syncs to satd's tip and reports an
  SPV-verified confirmed balance for a funded+matured wallet address.
  See `STABILITY_POLICY.md`.
- **LND Neutrino canary is now PR-gating**
  (`scripts/canary/lnd-neutrino-smoke.sh`). Runs a real LND node
  (`lightninglabs/lnd:v0.18.5-beta`) as a BIP 157/158 light client backed by
  satd over P2P — the only canary exercising satd's compact-block-filter
  serving (`--peerblockfilters=1`). Asserts LND reaches `synced_to_chain` at
  satd's tip and that a single filter-matched funding block is selectively
  downloaded and credited to LND's wallet. See `STABILITY_POLICY.md`.

## [0.2.1] — 2026-05-29

### Packaging

- **`sat-tui` is now included in the release tarballs.** The terminal
  dashboard (`sat-tui`) ships in `bin/` of every `satd-<version>-<target>.tar.zst`
  alongside `satd` and `sat-cli`, with a CycloneDX SBOM
  (`sat-tui-v<version>.cdx.json`) and a minisign signature like the other
  artifacts. It was a workspace member but was never built or staged into the
  tarball through 0.2.0, so operators who installed from a release archive had
  no TUI. No code changed from 0.2.0 — this release exists solely to package
  the binary.

## [0.2.0] — 2026-05-27

### Network

- **BIP 324 v2 encrypted transport** (`-v2transport`, on by default, matching Bitcoin Core). satd offers/accepts the ElligatorSwift + ChaCha20-Poly1305 v2 handshake on inbound and outbound connections, transparently falling back to plaintext v1 for legacy peers. The satd-specific **`-v2only`** flag (off by default) refuses non-v2 peers as an anti-surveillance lever. `getpeerinfo` reports `transport_protocol_type`; a `satd_peer_connections_v2` Prometheus gauge counts v2 peers. Built on the rust-bitcoin `bip324` crate.

### Wallet / signing

- **`sat-cli signpsbtwithkey` — client-side PSBT signing.** Signs a base64 PSBT locally using a private key (WIF or xpriv) read from **stdin**; the key is never sent over JSON-RPC, keeping the daemon keyless. On an interactive terminal the key is read with a no-echo prompt; when piped, newline-separated keys are accepted. Key material is best-effort erased after use. Signs p2pkh, p2wpkh, p2sh-wrapped-p2wpkh, and p2tr key-path inputs (populating `partial_sigs` / `tap_key_sig`); the signed PSBT is emitted on stdout to feed into the existing `finalizepsbt` RPC. Exits `0` when fully signed, `2` when partial (PSBT still emitted, unsigned inputs reported on stderr). Intended workflow: `createpsbt` → `utxoupdatepsbt` → `signpsbtwithkey` → `finalizepsbt` → `sendrawtransaction`. For an xpriv, standard BIP 44/49/84/86 child keys are derived client-side (account 0, receive + change, over a `--gap`-bounded scan, default 100) and matched against the input scripts, so an xpriv signs PSBTs that carry no derivation metadata — including satd's own `createpsbt` output; PSBTs that *do* carry `bip32_derivation` also sign on their declared paths.

- **`sat-cli signpsbtwithsigner` — external-signer dispatch (HWI / Bitcoin-Core compatible).** Signs a base64 PSBT by spawning an external signer command (`--signer "<cmd>"`, e.g. the `hwi` tool or any conforming script) locally; the key lives in that process and is never sent over RPC, keeping the daemon keyless. Speaks Core's `doc/external-signer.md` arg-based contract: runs `<signer> enumerate` to discover the device fingerprint (auto-selected when exactly one is present, or chosen with `--fingerprint`), then `<signer> --fingerprint=<fp> --chain <net> signtx <psbt>` (chain derived from `--regtest`/`--testnet`), parsing `{"psbt"}` / `{"error"}`. The signed PSBT is emitted on stdout for `finalizepsbt`; same `0`/`2`/`1` exit scheme as `signpsbtwithkey`. Note: a hardware device only signs inputs carrying its own `bip32_derivation`, so it acts on properly-formed PSBTs (from a wallet that knows the device xpub), not satd's bare `createpsbt` output. Scope: `enumerate` + `signtx` (`displayaddress`/`getdescriptors` not yet wired).

### Native protocol surfaces

- **Native TLS Support:** Direct TLS termination for JSON-RPC, Electrum, and Esplora servers via `--rpctlsbind`, `--electrumtlsbind`, and `--esploratlsbind`. Eliminates the need for a TLS-terminating sidecar.

### Configuration and CLI compatibility

- **Bitcoin Core CLI/config-compatibility gap closed.** Every recognized
  `bitcoin.conf` key is now either honored or recognize-rejected with a
  clear message — no silent accept-and-ignore. Newly implemented:
  `-includeconf` chained config files (main file read first, included
  files appended; single-valued keys resolve first-wins, matching Core's
  `reverse_precedence`); comprehensive `-no<option>` boolean negation
  across all boolean flags; `-signetchallenge` custom signet with
  opt-in BIP 325 block-solution validation; `-testnet4` chain params
  including BIP 94 (timewarp guard + first-block-seeded retarget);
  `-blocksonly`; `-externalip`; `-whitelist` / `-whitebind` peer
  permissions (NoBan + Relay/ForceRelay acted on); `-maxuploadtarget`
  (meters block-serving bytes); persistent address manager
  (`peers.dat`, satd-native format — see `CORE_DIFFERENCES.md`); `-asmap`
  ASN-based bucketing (Core `util/asmap.cpp` port); `-forcednsseed` and
  `-fixedseeds`. `-includeconf` on the command line is now a hard error,
  matching Core.
- **JSON-RPC server CLI flags.** `-rpcbind=<addr>[:port]` (repeatable),
  `-rpcallowip=<subnet>` allow-list, `-rpcauth=<user>:<salt>$<hash>`
  HMAC credentials, and the `-rpccookiefile` / `-rpccookieperms` cookie
  controls, all matching Bitcoin Core.
- **`-chain=<name>` unified network selector** (Core's single-flag form),
  mutually exclusive with `-regtest` / `-testnet` / `-testnet4` / `-signet`;
  a `[signet]` config section; `-blocksdir` for a separate blocks directory;
  `-signetseednode`; and `-timeout=<ms>` peer-connection timeout. `sat-cli`
  gains `-rpcwait` to block until the daemon's RPC is reachable.
- **`-persistmempool`** — the mempool is saved to `mempool.dat` on clean
  shutdown and reloaded (each tx re-validated against the chainstate) at
  startup. The flag, filename, and behavior match Bitcoin Core, but the
  on-disk format is satd-native and **not** byte-compatible with Core's
  `mempool.dat` (like `peers.dat` — see `CORE_DIFFERENCES.md`).
- **`-listenonion`** Tor hidden-service wiring is honored end-to-end.

### RPC compatibility

- **`getchaintxstats` now reports Core-faithful cumulative statistics.**
  `txcount` is the cumulative chain-wide transaction total through the
  window's final block (previously it duplicated the window count), and
  the optional second `blockhash` argument — which selects the block that
  *ends* the window (default = chain tip) — is now honored (previously
  silently ignored). The cumulative count is maintained in a new
  additive `chain_tx` column family, seeded at the AssumeUTXO anchor and
  backfilled at startup on upgraded datadirs with no reindex. Field
  optionality matches Core exactly: `txcount` is omitted when the final
  block's count is unknown (e.g. a pre-snapshot block on an AssumeUTXO
  node still validating in the background), `window_tx_count` is the
  difference of the two endpoint counts and is omitted unless both are
  known, and `txrate` is omitted unless `window_tx_count` exists and the
  interval is positive. The window interval is measured between the
  endpoints' median-time-past values (BIP 113), as in Core. Active-chain
  membership for an explicit `blockhash` is resolved authoritatively
  (rejecting side-chain blocks with "Block is not in main chain").

### AssumeUTXO

- **`loadtxoutset` / `getchainstates` RPCs** plus two-chainstate
  (background) sync. satd loads Bitcoin Core's published UTXO snapshot
  files directly; the anchor table is copied verbatim from Core's
  `m_assumeutxo_data`. Refuses to load under pruning. Note: While AssumeUTXO is fully compatible with commonly-distributed snapshots, satd does not create or distribute these snapshots. Users must find their own source for trusted snapshots.
- **`dumptxoutset` RPC** — exports a byte-compatible UTXO snapshot at the
  current tip, loadable into either Core or satd via `loadtxoutset`. The
  returned `txoutset_hash` is Core's `hash_serialized_3` UTXO-set hash
  (not the file digest), so it can be checked against a height's
  `hash_serialized` in Core's `m_assumeutxo_data`. Finalize is atomic and
  refuses to clobber an existing file.
- **UTXO-set hash parity with Core.** Provably-unspendable outputs are
  now excluded from the UTXO set, so `gettxoutsetinfo` and `dumptxoutset`
  produce the same `hash_serialized_3` as Bitcoin Core at a given height —
  required for AssumeUTXO snapshots to cross-validate against Core anchors.
- **`--fast-start=<url>` one-flag startup UX.** Downloads a UTXO snapshot
  at startup (from an `https://` URL or a local file path), waits for
  header sync to reach the snapshot's anchor, and loads it automatically
  — no manual `loadtxoutset`. Remote sources **must** be `https://`
  (plain `http://` is refused at config time; TLS certificates are
  validated), and the snapshot is verified against satd's hardcoded
  anchor hash at load, so a tampered or wrong file is rejected regardless
  of its source. The download is resumable and its progress renders in
  the pre-RPC startup TUI gauge (like a reindex); the genesis→snapshot
  background re-validation shows in `getchainstates`. Incompatible with
  `-prune`. On a node that already has chainstate the flag is a no-op, so
  it is safe to leave in a systemd unit. satd never fetches snapshots
  over P2P and hosts none — the operator names a trusted source. The
  download is length-checked against the server's `Content-Length`, and an
  optional `--fast-start-sha256=<hex>` fails fast if the file doesn't match
  an operator-supplied digest (opt-in; the anchor-hash check at load is the
  authoritative gate regardless).

### Performance

- **Pipelined `-reindex-chainstate`.** Rebuilding the UTXO set from
  on-disk blocks now uses the same parallel block-processing pipeline as
  initial block download instead of a serial pass, substantially reducing
  reindex-chainstate wall-clock time on multi-core hosts.

### Packaging

- **musl-linux static tarballs** (`x86_64`/`aarch64-unknown-linux-musl`,
  built via `cargo-zigbuild`) and **macOS Apple Silicon tarballs**
  (`aarch64-apple-darwin`) now ship in the release matrix.
- **systemd `WatchdogSec=` liveness** wired into both `satd.service` and
  the new **`satd@.service`** template unit for per-network instances.

### Storage

- **Breaking — storage format cleanup.** Undo entries are now v1-only
  on disk (8-byte magic + 1-byte version + compact-coin stream);
  address-history rows live exclusively in the `addr_funding_v2` /
  `addr_spending_v2` column families (16-byte scripthash-prefix keys).
  The dual-read fallbacks, the legacy v1 address CFs, and the offline
  migrators (`--migrate-undo`, `--migrate-addr-index`) introduced
  post-0.1.0 are all removed. Any chainstate written by an earlier
  post-0.1.0 build that did not run both migrators must be rebuilt
  with `--reindex-chainstate`. The `_v2` naming is preserved as a
  fossilized marker — these are now the only address-history CFs.

## [0.1.0] — 2026-05-08

First public release. Pre-1.0 in semver terms; the Tier 1 surfaces listed
below are governed by `STABILITY_POLICY.md` from this tag forward.

### Consensus and chain

- Bitcoin Core-compatible JSON-RPC across chain, mempool, mining, indexes,
  PSBT, and ops surfaces.
- `bitcoinconsensus` FFI as primary script verifier with a parity-validated
  native Rust verifier as a shadow on every block sync.
- Full mainnet sync from genesis through tip with no consensus divergence.
- Pruning, AssumeUTXO, txindex, reindex, and reindex-chainstate.
- Full P2P including BIP 152 compact blocks, BIP 155 addrv2, ban scoring,
  Tor v3 (`ADD_ONION` / `DEL_ONION`).
- Mempool with full RBF / opt-in BIP 125, CPFP ancestor tracking, and
  configurable policy (`-dustrelayfee`, `-datacarrier`, `-limitancestorcount`,
  `-mempoolexpiry`, `-permitbaremultisig`).

### Native protocol surfaces

- **Esplora REST** (`esplora-handlers`) — wire-shape parity with
  blockstream.info / mempool.space for the implemented endpoint set. On by
  default on loopback. See `docs/api/esplora.md`.
- **Electrum protocol server** (`electrum-proto`) — TCP + optional TLS,
  protocol version 1.4.5. Vendored protocol code from `romanz/electrs` (MIT,
  attribution preserved) layered over the address-history index.
- **Address-history index** (`node-index`) — single RocksDB instance shared
  with chainstate, atomic with `connect_block` / `disconnect_block`. Powers
  Esplora and Electrum.
- **BIP 157/158 compact block filters** (`node-filter-index`) — index plus
  P2P service (`getcfilters` / `getcfheaders` / `getcfcheckpt`) for
  embedded-Neutrino mobile wallets.

### Operator ergonomics

- `/healthz`, `/readyz`, `/metrics` (Prometheus) on `--metricsport`.
- Mempool subscription stream via `subscribemempool` JSON-RPC WS.
- Persistent reorg log at `$datadir/reorg.log` plus optional webhook.
- Structured JSON logging via `tracing-subscriber`.
- `sat-tui` startup progress panel with per-phase ETA and rate.
- MCP server for AI-assisted operations.

### Packaging

- Multi-arch Docker images (`linux/amd64`, `linux/arm64`) on GHCR.
- Signed release tarballs for `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu`.
- Three-surface release signing: minisign for tarballs, cosign keyless for
  containers, SSH signatures on git tags. No GPG.
- Nix flake reproducible build with two-runner byte-identical CI verification.
- CycloneDX 1.5 SBOMs per binary plus `cargo-deny` supply-chain gate at PR
  time and tag time.
- `Type=notify` systemd unit with reindex-resilient `EXTEND_TIMEOUT_USEC`
  heartbeat, OpenRC and runit equivalents.
- `docs/PACKAGING.md` as the authoritative downstream-packager reference.

### Documentation

- `CORE_DIFFERENCES.md` — catalog of intentional deviations from Bitcoin Core.
- `OPERATOR_ERGONOMICS.md` — full flag matrix and tuning guide.
- `STABILITY_POLICY.md` — tiered stability contract with the deprecation
  policy and canary-CI commitments.
- `SECURITY.md` — disclosure address, signing key matrix, threat-model notes.
- `ECOSYSTEM.md` — packaging and protocol-surface strategy.

### Known deferred items

Tracked in `ECOSYSTEM.md` and `docs/PACKAGING.md` for the v0.1.x line.
(macOS Apple Silicon tarballs, musl-linux tarballs, systemd
`WatchdogSec=`, the `satd@.service` template, and the AssumeUTXO
`--fast-start` UX all shipped post-0.1.0 — see the `[Unreleased]`
section above.)

- `cargo-auditable` to embed the dependency manifest in the binary.

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/epochbtc/satd/releases/tag/v0.1.0
