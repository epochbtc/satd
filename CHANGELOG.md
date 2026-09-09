# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.5.2**, a patch release on the 0.5.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.5.2-pre.md`](docs/release-notes/0.5.2-pre.md).

### Changed

- **Breaking:** `getdeploymentinfo` reports the buried deployments under
  Bitcoin Core's names — `dersig` is now `bip66` and `cltv` is now `bip65`
  (#666). It also honours the `blockhash` argument instead of ignoring it.
- **Breaking:** `validateaddress` describes a destination as Bitcoin Core
  does. `witness_version` and `witness_program` are omitted for a non-witness
  address instead of reporting `witness_version: -1`; `isscript` is now true
  for Taproot and anchor outputs and absent for an unknown witness version.
- **Breaking:** `converttopsbt` refuses a transaction carrying signature data
  unless `permitsigdata` is true, as Core does, instead of silently
  discarding it (#687).
- 24 RPCs accept the optional arguments Bitcoin Core declares for them, and
  an argument error is no longer a Rust `Debug` dump. `submitpackage`,
  `converttopsbt` and `utxoupdatepsbt` rejected their optional arguments
  outright (#687).
- A wrong-length hash and a right-length non-hex string report different
  errors, as Core's `ParseHashV` does; `getblockfrompeer` names the argument
  `blockhash`, as Core does (#692).
- **Breaking:** an RPC call that passes more arguments than the method
  declares is rejected with `-1`, as Core does, instead of being answered with
  the surplus ignored (#688).
- **Breaking:** `-connect` soft-sets `-listen=0`, as Core's
  `InitParameterInteraction` does; so does `-maxconnections` ≤ 0. A node pinned
  to specific peers no longer accepts inbound connections unless `-bind`,
  `-whitebind` or an explicit `-listen` says so (#690).
- **Breaking:** `-listen=0` soft-sets `-listenonion=0`, as Core's
  `InitParameterInteraction` does. A node pinned with `-connect` and
  `-torcontrol` used to lower `listen` and still publish a hidden service,
  accepting inbound peers over it. An explicit `-listenonion=1` still wins
  (#690).
- **Breaking:** a literal `-connect=0` mixed with a peer address is refused
  rather than silently discarding the peer. `-connect=0` on its own, and
  `-noconnect`, are unchanged (#690).
- `generatetoaddress` and `generatetodescriptor` honour Core's `maxtries`
  argument, which also puts the first bound on satd's nonce grind (#688).
- `help <command>` answers for every registered RPC, including the ones the
  listing deliberately omits, and the listing itself now names every method
  satd registers — thirty were missing, among them the PSBT builders and
  satd's own index, quarantine and address-index RPCs (#692).

### Added

- `addconnection`, Bitcoin Core's hidden regtest-only RPC for opening an
  outbound connection of a chosen type (`outbound-full-relay`,
  `block-relay-only`, `addr-fetch`, `feeler`). `getpeerinfo` now reports the
  real `connection_type`, and each type behaves as Core's does.
- `validateaddress` reports *why* an address is invalid: Core's `error`
  string plus `error_locations` for a Bech32 checksum failure.
- `dumptxoutset` accepts Core's `type` argument (every Core-shaped call was
  previously a parse error), and resolves a relative `path` against the
  network data directory as Core does rather than the working directory.

### Fixed

- CI: every `apt-get update` drops the runner image's third-party apt sources
  first. A hash-sum mismatch on Google's Chrome repository — which none of the
  installed packages come from — was failing the whole step, and with it every
  canary job.

- **Breaking:** dust thresholds are Bitcoin Core's. satd charged 68 vbytes to
  spend a witness output where Core charges 67, 107 for P2SH where Core charges
  148, and truncated a fee Core rounds up — so P2WPKH was 297 against Core's
  294, P2TR 333 against 330, and P2SH 417 against 540 (#661).
- **Breaking:** one dust output is standard, as Core's
  `MAX_DUST_OUTPUTS_PER_TX` allows, and a dusty transaction that pays any fee
  — base or `prioritisetransaction` delta — is refused
  `dust, tx with dust output must be 0-fee` on the single-transaction path as
  well as in `submitpackage` (#661).
- **Breaking:** bare P2PK outputs and witness programs at versions satd has no
  name for — pay-to-anchor among them — are standard, as Core's `Solver` and
  `IsStandard` have them. A bare P2PK payment was refused outright, and bare
  multisig is now bounded at x-of-3 as Core bounds it (#661).
- `-dustrelayfee` reaches every dust decision. `prioritisetransaction`, the
  package path and the stranded-parent unwind read the built-in rate instead of
  the configured one, so `-dustrelayfee=0` did not switch dust policy off
  (#661).
- The block template refuses a spend of an immature coinbase. A reorg can
  leave one in the mempool, and `connect_block` rejects the whole block for it
  (#670).
- `-blockmintxfee` is applied. It was parsed and then read nowhere, so the
  template floor did not exist; it is judged on the package feerate, as Core's
  `addPackageTxs` does, so a zero-fee parent still rides in on its child. Its
  default is now Core's 1 sat/kvB rather than 1000 — the old value matched the
  default `-minrelaytxfee`, which would have stranded every transaction on a
  node with a lower relay floor (#661).
- `reorg` is documented as a mempool eviction reason. The node has emitted it
  on every carrier since the reorg sweep landed, but the wire spec and the
  Operator Manual listed only some of the reasons (#670).
- The ephemeral dust rule is enforced on the single-transaction path, as Core
  does: a transaction that spends a resident dust parent without sweeping its
  dust is refused `missing-ephemeral-spends` instead of accepted (#703).
- An ephemeral dust parent reached the mempool without a mempool `Enter`
  event, so a consumer reconstructing membership from the event stream
  disagreed with `getrawmempool` (#704).
- `submitpackage` could leave a zero-fee ephemeral-dust parent in the mempool
  after the child that was to sweep its dust was refused, stranding the dust —
  the one outcome the policy exists to prevent. The parent is now removed with
  the child (#673).
- `submitpackage` reported `bad-txns-inputs-missingorspent` for a child that
  left its parent's ephemeral dust unspent, burying the real reason. It now
  reports `missing-ephemeral-spends`, and the package result is `unspent-dust`
  rather than `transaction failed`, as Core does (#673).
- `getpeerinfo.permissions` was hardcoded `[]` while each peer's permissions
  were populated all along, so a `-whitelist`ed peer reported no grants at all.
  It now reports Core's `ToStrings` of the real flags (#667). `noban` also
  carries `download`, as Core's `NetPermissionFlags::NoBan` does — a reporting
  change, since the upload-budget check already honoured either flag.
- The `logging` RPC honours Core's wildcard set exactly: `""`, `1` and `all`
  all mean every category. `none` and `0` are rejected as unknown categories,
  as Core rejects them — they are `-debug` config spellings, and accepting them
  meant `logging '["none"]'` silently turned off all logging where Core refuses
  the call (#667).
- **Breaking:** two `-whitelist` grants were wider than Core's, and are
  narrowed to match: a bare `-whitelist=<subnet>` no longer grants `addr`, and
  `-whitelist=@<subnet>` — Core's "match this range, grant nothing" idiom —
  grants nothing instead of the implicit set, which had been silently handing
  out `noban` (#667).
- **Breaking (security):** `-whitelist` is inbound-only unless the entry
  carries an `out` token, as in Core, and an `out` entry applies only to
  *manual* outbound connections. satd swallowed the `in`/`out` tokens as no-ops
  and applied every entry in both directions, so `-whitelist=noban@<subnet>`
  made outbound peers in that range un-bannable and exempt from the upload
  budget (#701).
- **Breaking:** a `-whitelist` entry that sets only a direction and no
  permission (`-whitelist=out@10.0.0.0/8`) is refused at startup, as Core
  refuses it — it granted nothing while looking like a grant. `-whitebind`
  refuses an `out` token outright, also as Core does: a bind address describes
  where connections arrive (#701).
- **Security:** a peer arriving over the Tor hidden service is no longer
  matched against `-whitelist`. Tor forwards the service to a local socket, so
  every inbound onion peer looked like a loopback connection and inherited a
  `-whitelist=127.0.0.1` entry — the ordinary way to whitelist a local wallet
  integration — making anonymous remote peers un-bannable and exempt from the
  inbound connection caps. `-listenonion` now gets its own listener on
  `127.0.0.1:<port+1>` (Core's `onion_binds`), and peers accepted there are
  exempt from whitelist matching (#701).
- `getmemoryinfo` reported the process RSS as the secure-allocator pool's
  `used`, with `free`, `total` and both `chunks_*` invented around it. satd has
  no secure allocator, so the pool is empty and the numbers are zero (#667).
- Nine RPC fields reported constants chosen to look plausible rather than
  values read from the node, in two cases contradicting another RPC on the same
  node (#702). `getnetworkinfo` now reports the configured `relayfee` /
  `incrementalfee` (the fixed `0.00001000` was ten times satd's own default,
  while `getmempoolinfo` had the real value all along), the service flags it
  actually advertises (the fixed value claimed `NODE_NETWORK_LIMITED`, which
  satd never sets, and never showed `NODE_COMPACT_FILTERS`, which it does),
  `localrelay` as the inverse of `-blocksonly`, and the node's real warnings.
  `getblockchaininfo.pruned` follows `-prune` instead of being false on a
  pruned node, with Core's `prune_target_size` / `automatic_pruning` alongside.
  `getmininginfo.warnings` is populated. `decodescript.p2sh` returns the P2SH
  address. `getpeerinfo.session_id` carries the BIP 324 session ID for a v2
  peer — the field exists for out-of-band MITM detection and was empty for
  every peer. `decodepsbt.fee` and `analyzepsbt.fee` are computed once every
  input's UTXO is known, as Core does — through Core's `GetInputUTXO` rules,
  which prefer the `non_witness_utxo` and check its txid against the input's
  own `previous_output`, so a PSBT's author cannot choose the fee that is
  reported. `analyzepsbt.estimated_feerate` stays absent: Core derives it from
  a dummy-signed transaction, which satd cannot produce, and the unsigned size
  would overstate the rate by the whole witness.
- **`savemempool` wrote nothing** while returning Core's success value. It now
  writes `mempool.dat` and returns Core's `{"filename": …}` (#702).
- **Breaking:** `-prune` is measured in MiB, as Core's is
  (`nPruneArg * 1024 * 1024`), so `getblockchaininfo.prune_target_size` for
  `-prune=550` reports 576,716,800 rather than 550,000,000 and the pruner keeps
  the matching number of blocks. `-prune=1` — Core's spelling for manual
  pruning, which satd does not implement — is refused at startup instead of
  being read as a 1 MiB budget that silently deletes block data (#702).
- `decodescript` emits `p2sh` under Core's `can_wrap` rules rather than a
  size check: no address for a script that can never be spent (an `OP_RETURN`,
  a Taproot or anchor output script, an unknown witness program, a truncated
  push), and an address for a redeemScript between 521 and 10,000 bytes, which
  Core returns and satd silently dropped (#702).
- `logging` reported from a static map initialised to "everything on" that
  nothing else in the process read: a node running with no `-debug` claimed 30
  categories enabled, and toggling one flipped a bit that never reached the log
  filter. It now reads and writes the node's live `EnvFilter`, lists the
  categories satd can actually act on, and answers Core's
  `-8 unknown logging category <cat>` (#667).
- `estimaterawfee` returned the same feerate for every horizon with `decay: 0`
  — not a value Core's estimator can produce — and zeroed buckets, and
  discarded `threshold` entirely. It now omits a horizon that does not track
  the target, omits the bucket fields satd has no data for, answers Core's
  "insufficient data" error when the estimator has none, and range-checks
  `threshold` (#667).

- `banlist.json` is Bitcoin Core's format — an object keyed by `banned_nets`
  with a per-entry `version` — instead of a bare JSON array. More importantly,
  a ban list satd cannot read is now recreated, as Core does, instead of
  silently disabling persistence: pointing satd at a datadir Core had used made
  every subsequent `setban` accepted by the RPC, applied in memory, and gone on
  restart, with no error at any point. satd's own historical array format is
  still read and rewritten in Core's shape at startup, so an upgrade keeps its
  bans and Bitcoin Core can read the datadir straight away (#669).
- The ban list is written through a temporary file and a rename, and the write
  no longer happens while holding the ban-list lock on the peer event loop
  (#669).

- `-connect=0` was parsed as the peer address `0`, so the node dialled
  `0.0.0.0:8333` at every startup. Core reads it as "open no outbound
  connections"; satd now does too, and any `-connect` stops the node dialling
  addresses it learned from gossip.
- `-connect` and `-addnode` entries without a port took 8333 on every network;
  they now take the network's default P2P port, as `-seednode` already did
  (#690).
- `-noconnect` is honoured rather than refused. Core treats it exactly like a
  `-connect`, which satd can now express (#690).

- `validateaddress` reported an address from another network as valid — it
  never checked the network at all.
- **Breaking:** `createrawtransaction` and `createpsbt` built an output from an
  address belonging to another network. On mainnet that pays a scriptPubKey the
  sender does not control, with no prefix left in the transaction to catch it.
  Both now decode with the network, as Core does, and answer
  `-5 Invalid Bitcoin address: <addr>` (#689). `createpsbt` picks up the array
  form of `outputs` (which it had been ignoring, returning a PSBT with no
  outputs), string amounts, and Core's duplicate-address and amount-range
  checks in the process — it had its own copy of the parser.
- **Breaking:** output amounts are parsed as exact decimals, Core's
  `ParseFixedPoint`, instead of round-tripping through `f64`. `createpsbt`
  truncated where it should have rounded, so 5.6% of five-decimal amounts were
  built one satoshi short of what the caller wrote; and `f64::from_str` accepted
  `NaN`, which passed both range guards and saturated to a zero-value output
  with no error. `.5`, `1.`, `01.0`, `+1.0` and `1.000000009` are now refused,
  as Core refuses them (#689).
- The JSON-RPC compatibility layer round-tripped every request body through
  `serde_json::Value` to rewrite the `jsonrpc` member, which silently collapsed
  duplicate keys in `params` and renormalised number spellings. Core keeps
  duplicates, and `createrawtransaction`'s duplicate-key check sat downstream of
  this — so it could never fire. Members are now re-emitted byte-for-byte
  (#689).
- `createrawtransaction`/`createpsbt`: `outputs` that is neither an object nor
  an array is refused rather than treated as an empty output set —
  `createpsbt '"hello"'` returned a valid PSBT with no outputs. A `data` value
  follows Core's `ParseHexV`: a JSON number is accepted as its own spelling, and
  an empty string is refused rather than building `OP_RETURN OP_0` (#689).
- `createrawtransaction`/`createpsbt`: an explicit `null` for `outputs` is
  refused by name — `-8 Invalid parameter, output argument must be non-null`,
  as Core's `NormalizeOutputs` does — instead of being reported as a missing
  argument (#689).
- `createrawtransaction`/`createpsbt`: a repeated output key is read with its
  *first* value, as Core's `outputs[name_]` is, so a duplicate is reported as a
  duplicate rather than as whatever the later value happened to be (#689).
- The JSON-RPC compatibility layer no longer strands the rest of a batch when
  one element is not an object, and a repeated `jsonrpc` member is judged on
  its last value — the one the server will act on (#689).
- `getdeploymentinfo`: a 64-character `blockhash` that is not hexadecimal
  reported a length error; it now reports a hex error, as Core does.

- JSON-RPC: a mistyped argument no longer discards every argument after it.
  `generateblock` with a bad `transactions` silently ignored `submit=false`
  and mined a block. Wrong-typed arguments now return Core's `-3`
  `Wrong type passed:` error naming each one (#672).
- `sat-cli -named`: an argument with no `=` was silently dropped; it is now
  sent as a positional argument in Core's reserved `args` slot (#672).
- JSON-RPC: an error raised while reading a *later* argument no longer buries
  an earlier argument's type mismatch, which in a debug build closed the
  connection with no response at all (#672).
- `getnetworkhashps`: `nblocks` and `height` are signed again, so Core's
  documented `-1` works for both; out-of-range values now return Core's
  errors. The estimate counts the whole window's work rather than one block's,
  correcting a figure that was low by a factor of the window size — also
  reported by `getmininginfo.networkhashps` and the TUI.
- `getblockstats`: accepts a numeric height (Core's own help example) and the
  `stats` filter, both of which were rejected outright.
- P2P: a `block-relay-only` connection now actually withholds transaction and
  address relay instead of only being labelled as such — satd answered
  `getaddr`, ingested the peer's addresses, and announced its own transactions
  over links opened to prevent exactly that. `getpeerinfo.relaytxes` reports
  `false` for block-relay-only and feeler peers, as Core does.
- P2P: an `addr-fetch` connection now ends when the peer answers with
  `addrv2`, not only with the legacy `addr` — every BIP155-capable peer uses
  the former, so the connection previously held an outbound slot for the full
  five-minute expiry.
- `-connect`: gossiped and `peers.dat` addresses are no longer dialled. The
  previous gate ran where addresses were recorded, which `peers.dat` bypasses
  by being loaded before the setting is applied.
- `-connect=0` no longer raises the `peer_floor` alert threshold from 1 to 3,
  and is reported as `automatic_outbound` by `getconfig`, which could not
  otherwise tell a deliberately isolated node from a default one.
- SIGHUP: a `connect` change now applies the gossip-dialling disposition, and
  adding `connect=0` is no longer reported as "no changes detected".
- P2P: the per-type outbound connection limits are enforced against dials in
  flight, so concurrent `addconnection` calls can no longer exceed them.
- P2P: answering `getaddr` no longer re-enters the peer-table read lock, which
  `parking_lot` does not allow re-entrantly — a writer arriving between the two
  acquisitions deadlocked the manager's event loop.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.5.1](docs/release-notes/0.5.1.md) | 2026-09-04 | A Bitcoin Core compatibility release. satd now runs **Core's own functional test suite**, unmodified and pinned to a Core release, with all 264 test files inventoried as run-or-skip-with-a-reason; the set gates every pull request and found twelve defects in shipped behaviour — an RPC `Content-Type` Core-derived clients reject outright, a startup listener answering "no such method" where Core answers "warming up", a `bitcoin.conf` fee-rate value silently discarded, a panic on any unparseable `-bind` (and no IPv6 bind at all), mempool chain limits enforcing a limit Core v31 no longer has, and an oversized locator banning the peer where Core only disconnects. The mempool event broadcast now holds a whole block's confirmations — its 1024-slot ring was smaller than a single mainnet block, so every subscriber silently lost roughly 37% of each block's burst (#682). Silent payments reach wallets that exist today via `blockchain.tweaks.subscribe` on the Electrum server, plus `tweak_unspent_only` cut-through and spendable silent-payment outputs (#609). **Breaking:** `getindexinfo` is now Core's method — satd's richer view moved to `getsatdindexinfo`; `uacomment` is now validated and an unparseable `minrelaytxfee`/`dustrelayfee` now stops the node. Drop-in binary upgrade, no reindex. |
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.5.1...HEAD
