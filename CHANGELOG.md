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
- The container image is stripped: **670 MB → 136 MB**. `[profile.release]`
  has carried `debug = "line-tables-only"` since 0.4.0, and every `docker
  pull` since has been half a gigabyte of DWARF. Tarballs were never
  affected — `release.yml` already stripped them and split out a signed
  `.debug` sidecar. Rebuild with `--build-arg STRIP_BINARIES=0` to get an
  unstripped image back.
- `contrib/stack/tests/smoke.sh` runs on macOS. `timeout` and `sha256sum`
  are GNU and macOS has neither, so the script resolves `gtimeout` and
  `shasum -a 256`; it now preflights every tool it needs by name, and
  refuses LibreSSL rather than emitting TLS passes that verified nothing.
- The container's `HEALTHCHECK` is a liveness probe, and the reference stack
  no longer overrides it with `SATD_HEALTH_URL=…/readyz`. `/readyz` is 503
  until the tip is within six blocks of the headers tip, so pointing a
  container health gate at it reports every initial sync as a fault — days
  of it on mainnet.

### Added

- A **reference stack** (`contrib/stack/`): docker-compose running satd with
  RPC, Electrum, Esplora, metrics and optional MCP, each TLS-terminated by a
  certificate the install issues for itself, plus best-effort overlays for
  LND (Neutrino), Core Lightning, Ride The Lightning, a Cashu mint and
  BTCPay Server.
- A **downloadable appliance image** (`contrib/appliance/`): a bootable VM
  with satd, its tooling and — in the desktop flavour — Sparrow, Electrum
  and Liana already pointed at the node. Signet by default;
  `satd-appliance set-network mainnet` switches. Built with `mmdebstrap`,
  and gated in CI by booting the artifact under QEMU.
- **App-store packages for Umbrel and StartOS** (`contrib/packaging/`): satd,
  `sat-cli`, `sat-tui` and MCP, sharing the reference stack's `satd-init` and
  certificate scheme rather than re-implementing them. Each has been
  installed on a real server of its own kind and driven through every
  interface it exports; `x86_64` on both, `aarch64` not yet.
- `sat-cli` and `sat-tui` can reach a TLS-terminated RPC listener:
  `-rpctls`, `-rpccacert`, and `-rpcclientcert` / `-rpcclientkey` for mTLS.
  Previously an operator who enabled `-rpctlsbind` had to keep the plain
  listener up for the project's own clients.
- The container image ships `sat-tui` and a `HEALTHCHECK`, so `docker exec
  -it satd sat-tui` works and `depends_on: service_healthy` means something.
- `addconnection`, Bitcoin Core's hidden regtest-only RPC for opening an
  outbound connection of a chosen type (`outbound-full-relay`,
  `block-relay-only`, `addr-fetch`, `feeler`). `getpeerinfo` now reports the
  real `connection_type`, and each type behaves as Core's does.
- `validateaddress` reports *why* an address is invalid: Core's `error`
  string plus `error_locations` for a Bech32 checksum failure.
- `-vbparams=deployment:start:end[:min_activation_height]`, Core's
  regtest-only BIP 9 window override. Only `testdummy` is accepted; `taproot`
  is refused by name, because satd activates it at a fixed height and would
  report an override it does not honour (#692).
- `dumptxoutset` accepts Core's `type` argument (every Core-shaped call was
  previously a parse error), and resolves a relative `path` against the
  network data directory as Core does rather than the working directory.

### Fixed

- CI: every `apt-get update` drops the runner image's third-party apt sources
  first. A hash-sum mismatch on Google's Chrome repository — which none of the
  installed packages come from — was failing the whole step, and with it every
  canary job.

- **Breaking:** a JSON-RPC 2.0 request with no `id` is a notification: the
  method runs and the node answers `204 No Content`, and in a batch it
  produces no entry. satd injected `"id": null` into every request that lacked
  one, so it always answered (#664).
- **Breaking:** the `id` a request carried is echoed, `null` included, and
  omitted entirely when the request carried none — as Core's optional `id`
  does. satd omitted every null id, losing the difference (#664).
- **Breaking:** the HTTP status of a *legacy* (non-2.0) request carries the
  JSON-RPC error class as Core's does: an invalid request is 400, an unknown
  method 404, and any other error — a parse error, `-8`, `-5` — 500. A
  JSON-RPC 2.0 request keeps 200 and carries the error in the body, as Core
  does (#664).
- `-rpcservertimeout` bounds idle keep-alive connections and HTTP/2 as well
  as the header read, and reaches the TLS listener, which had no timeout at
  all (#664).
- A JSON-RPC response too large to normalise is forwarded rather than
  DOM-parsed, which cost several times its size in peak memory (#664).
- **Breaking:** a replacement is now compared against the *feerate diagram*
  it displaces, as Bitcoin Core's `ImprovesFeerateDiagram` does, rather than
  against each conflicting transaction's own feerate. A cheap transaction
  carrying an expensive child is one chunk to a miner, so beating the parent
  alone no longer replaces it — even when the replacement pays more in total.
  A conflict's surviving parent that the replacement also spends counts once
  in the diagram (#660).
- `testmempoolaccept` and `sendrawtransaction` run one shared RBF check over
  the same transitive ancestor set, and `testmempoolaccept` reports
  `too-long-mempool-chain` as `sendrawtransaction` does, so
  they cannot disagree about a replacement (#660).
- Five RPC fields that were constants stop pretending to be measurements
  (#702): `getblockchaininfo.size_on_disk` is a maintained total of block-file
  bytes instead of `0`; `getblockchaininfo.pruneheight` is reported on a
  pruning node with Core's meaning — the lowest height from which every block
  up to the tip is still stored, `0` until something has been deleted — and
  persisted across restarts;
  `getchainstates[].coins_tip_cache_bytes` reports the configured coin-cache
  budget, as Core's does; `getrpcinfo.active_commands` lists the requests
  actually executing instead of an empty array; and `getpeerinfo.inflight`
  carries the block heights outstanding to that peer during IBD.
- **Breaking:** `getdeploymentinfo` reports Bitcoin Core v31.1's full
  deployment set. `taproot` moves from `type: "buried"` to `type: "bip9"`
  (Core models it as a version-bits deployment), `testdummy` is added, and the
  result object carries the `script_flags` array it was missing (#692).
- `dumptxoutset` reports `nchaintx`, one of the three numbers an AssumeUTXO
  anchor is made of; without it a dumped snapshot could not be turned into one
  (#692).
- **Breaking:** `addconnection` returns as soon as the capacity grant is
  taken, as Core's does, instead of awaiting the dial and the transport
  handshake — which deadlocked against a caller that binds a listener, calls
  the RPC, and only then accepts. It also accepts a hostname, not just a
  literal `address:port` (#692).
- `addconnection` requires the new `test:net` capability rather than
  `rpc:write`, so a delegated write token cannot reshape the node's peer set.
  The cookie/`rpcauth` operator is unaffected (#692).
- **Breaking:** an operator-supplied peer name (`-addnode`, `-connect`,
  `addnode`) is no longer resolved with the local resolver under `-proxy` —
  that leaked to the resolver exactly the peers a proxied node exists to hide
  — nor at all under `-dns=0`, which was parsed and then ignored outside DNS
  seeding. Literal IPs and `.onion` targets are unaffected (#668).
- `getpeerinfo` reports the peer's real `network` (an RFC1918, link-local or
  loopback peer is `not_publicly_routable`, not `ipv4`/`ipv6`; an IPv4-mapped
  IPv6 address is judged as the IPv4 address it carries, as Core's is),
  `addr_relay_enabled` as Core's `SetupAddressRelay` latches it rather than as
  a function of the direction, and `servicesnames` in bit order (#668).
- `last_block` / `last_transaction` move only when the node *accepts* the
  block or transaction, as Core's do. Stamped on receipt, a peer could keep
  its eviction protection alive with blocks the node already had (#668).
- `getconnectioncount` counts the peers `getpeerinfo` lists, instead of a
  narrower set (#668).
- `getblocks` no longer announces the `hashStop` block the requester said it
  already had; `getblocks` and `getheaders` start at height 1 rather than
  re-announcing genesis when nothing in the locator matches, ignore locator
  entries that sit on a stale fork (Core's `FindForkInGlobalIndex`), and
  `getheaders` honours `hashStop` instead of always sending up to 2000
  headers (#668).
- `addnode <peer> remove` clears the peer's manual status, so it stops being
  dialled as a manual connection and stops bypassing `-connect` gating (#668).
- The total number of automatic outbound connections is bounded, as Core's
  `semOutbound` bounds it. `addconnection` could open unlimited `addr-fetch`
  and `feeler` connections, the two types Core caps only through that
  semaphore (#691).
- **Breaking:** `verifytxoutproof` requires the block to be on the active
  chain and the proof to cover the whole block, as Core does, and answers
  `-5 Block not found in chain` otherwise. A proof built on a stale branch read
  as valid (#671).
- **Breaking:** `decoderawtransaction`'s and `converttopsbt`'s `iswitness`
  selects the serialization it names. There was no legacy reader:
  `iswitness=false` used the witness decoder with the full-consumption check
  removed, so it returned the witness reading and accepted trailing bytes.
  `converttopsbt` refused the argument outright (#671).
- **Breaking:** `createrawtransaction`'s and `createpsbt`'s `replaceable=true`
  check was inverted. Core refuses only when **no** input signals; satd
  refused when any input did not, so a mixed transaction was rejected (#671).
- `estimatesmartfee` validates `conf_target` against 1..1008, as
  `estimaterawfee` already did (#671).
- `generatetodescriptor` takes the descriptors Core takes. It went through
  `scantxoutset`'s `raw()`/`addr()`-only parser, whose refusal named
  `scantxoutset` and carried the wrong code (#671).
- `getrawmempool verbose` and `getmempoolentry` report amounts through the
  same formatter as every other RPC, so `-amountunit=sat` reaches them (#671).
- `gettxoutproof` without a `blockhash` scans every output index a block can
  hold instead of the first 100, so a transaction whose only unspent output is
  further along is found (#671).
- `-noincludeconf` works. It was rewritten to a valueless `--includeconf`
  that the argument parser refused before satd's own handling saw it (#671).
- **Breaking:** `testmempoolaccept` reports `txn-already-known` only while one
  of the transaction's outputs is still an unspent coin, as Core does; it also
  consulted the txindex, which finds a confirmed transaction forever, so a
  fully-spent one was reported as already known instead of `missing-inputs`.
  A missing input is `missing-inputs`, Core's own name for it, rather than the
  mempool's internal reject reason (#665).
- **Breaking:** an output value with the high bit set is `bad-txns-vout-negative`,
  as Core reads it (`int64_t`), not `bad-txns-vout-toolarge` (#665).
- **Breaking:** `submitpackage` applies `maxfeerate` and `maxburnamount`
  instead of refusing them by name, bounds its array to Core's 1..25, checks
  Core's child-with-parents topology, and always emits
  `replaced-transactions` (#665).
- `submitpackage` answers with an entry for every submitted wtxid, carrying
  `package-not-validated` when the package aborted, `other-wtxid` for a
  same-txid-different-witness member, and `fees.effective-feerate` /
  `fees.effective-includes` for an accepted one — per result as Core's are:
  a member accepted on its own is judged by itself, members accepted together
  share one feerate, an already-resident member reports neither.
  `replaced-transactions` includes the evicted descendants, and a member over
  `maxfeerate` is refused with Core's `max feerate exceeded`. An unwound
  ephemeral-dust parent is no longer reported as accepted (#665).
- **Breaking:** `testmempoolaccept` reports `wtxid` on every result, adds
  `fees.effective-feerate` and `fees.effective-includes`, bounds its array to
  1..25, and applies package well-formedness from the same implementation the
  mempool uses. `maxfeerate` is parsed as Core's `ParseFeeRate`: a negative
  value is `-3 Amount out of range` and one at or above 1 BTC/kvB is `-8`,
  where both used to be silently replaced by the default (#665).
- **Breaking:** mempool reject reasons match Bitcoin Core's. A script failure
  is `mempool-script-verify-flag-failed` on the relay path and
  `block-script-verify-flag-failed` in `connect_block`, not
  `mandatory-script-verify-flag-failed` for both; a failed feerate-diagram
  check is `replacement-failed`; and `min relay fee not met` carries Core's
  `"<fee> < <required>"` detail in satoshis (#671, #660).
- RBF Rule 5 counts distinct mempool *clusters*, as Core does, instead of
  counting the conflicts — a replacement conflicting with a hundred children
  of one parent affects one cluster and is no longer refused (#660).
- The relay floor reads the modified fee on both `sendrawtransaction` and
  `testmempoolaccept`, so the two agree about a prioritised transaction, and
  mempool eviction sorts on the modified feerate — a `prioritisetransaction`
  delta could not save a transaction from eviction (#660).
- `getprioritisedtransactions` reported `in_mempool: false` for every
  prioritised transaction that was in the mempool (#660).
- The RBF descendant walk is bounded by the cluster limit, and
  `-minrelaytxfee` / `-dustrelayfee` / `-incrementalrelayfee` refuse a value
  outside Core's money range instead of overflowing the incremental-fee
  multiplication (#660).
- `getchaintips` no longer walks the whole block index on every call. The leaf
  set is maintained incrementally, the status of a stored-but-unvalidated
  branch is `valid-headers` rather than `valid-fork`, and the order is
  deterministic across calls (#662).
- **Breaking:** `getblocktemplate` proposal mode validates the proposed block
  the way `submitblock` does. It ran a separate loop that skipped script
  verification by its own admission, and with it BIP 68 sequence locks, the
  block sigop cost and BIP 30, so a miner was told a block would be accepted
  when it would not (#663).
- `getblocktemplate` answers `duplicate` / `duplicate-invalid` /
  `duplicate-inconclusive` for a block the node already knows, as Core does,
  instead of `inconclusive-not-best-prevblk` (#663).
- **Breaking:** `getblocktemplate` rejects a `mode` it does not understand with
  `-8 Invalid mode` rather than silently returning a template, and proposal
  mode without a string `data` is `-3`, as Core's is (#663).
- **Breaking:** a block that is both oversized and merkle-broken reports
  `bad-txnmrklroot`, as Core's `CheckBlock` does — it checks the merkle root
  before the size limits — and `check_block` applies Core's legacy-sigop
  ceiling, which fired before any prevout was resolved (#663).
- `-blockversion` overrides the template's block version on regtest, as Core's
  `CreateNewBlock` does. It was accepted and ignored (#663).
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
  node with a lower relay floor. It takes Core's BTC/kvB spelling in
  `bitcoin.conf` like the other fee-rate options (#661).
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
