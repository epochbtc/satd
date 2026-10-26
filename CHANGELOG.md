# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.7.0**, a minor release on the 0.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.7.0-pre.md`](docs/release-notes/0.7.0-pre.md).

### Added

- `verifymessage` and `signmessagewithprivkey`, Bitcoin Core's message-signing
  RPCs, byte-compatible with Core.

- `verifybip322`: BIP 322 message verification for every address type
  (`smp`, `ful`, or unprefixed), on satd's own script interpreter.

- Node Attestation Protocol publisher (`-nap=1`, off by default):
  `createnapattestation`, `submitnapattestation`, `listnapattestations` and
  `removenapattestation` store holders' signed, coin-weighted statements and
  judge them at every block. `-napstorerecover=1` starts with an empty store
  when the saved one does not read back; `-napmaxattestations` caps the store.
  Hardware and multisig signers sign the BIP 322 `to_sign` PSBT that
  `createnapattestation` returns (with key origins and scripts filled in from
  an optional descriptor), and `submitnapattestation` finalizes it, or takes
  the signed transaction in hex as a wallet that finalizes it exports. A coin
  attests 4,032 blocks after it confirms on mainnet, 6 on the test networks,
  and only if it holds at least 10,000 sats.
  The publisher advertises the experimental `NODE_NAP` service bit (bit 30)
  and serves its valid attestations to peers that ask with `getnapatt`,
  within per-connection and per-network-group limits.

- NAP aggregator (`-napaggregator=1`, off by default): collects attestations
  from `NODE_NAP` peers, and over short `nap-pull` connections (a new
  `getpeerinfo` connection type) from publishers the address book knows;
  verifies them cheapest check first within budgets; keeps for each coin and
  key the one that counts, and its predecessors while a reorg could bring
  them back, in `<datadir>/nap/aggregate/aggregate.dat`, up to
  `-napaggregatormax` (default 1,000,000); and lists them with
  `listnapaggregate`.
- NAP reports: `getnapreport` gives each key's weight per value (in
  satoshis, shares in parts per million), with breakdowns by coin value,
  anchor age, coin age and script type, and the digest of the set it came
  from, computed once per tip and set and allowed on the read-only
  listener; `exportnapsnapshot` writes that set to a file, and
  `replaynapsnapshot` replays it on any node, byte for byte at the same
  tip.

- `sat-tui` NAP view (`5`, only while the node has `-nap` or `-napaggregator`
  on): what the node publishes and its `getnapreport` report, in BTC and
  percentages, with each value's breakdowns.
- Bitcoin Core's `-zmqpub*` notifications (`hashblock`, `hashtx`, `rawblock`,
  `rawtx`, `sequence`) and `getzmqnotifications`: Core's messages byte-for-byte,
  so LND, Umbrel's Bitcoin apps and other ZMQ consumers work unchanged. Ordering
  between block and mempool messages differs from Core; the streaming API
  remains the recommended interface.

- The unknown-rules warning: a version-bits soft fork this node does not know
  that locks in is logged, and one that activates raises Core's "Unknown new
  rules activated (versionbit N)" in the RPC warnings and `-alertnotify`
  (#976).

- Package CPFP in `submitpackage`: a parent below the relay floor or the
  rolling minimum fee is accepted with a child that pays for both, by the
  package's combined feerate, as in Core (#984). The pool trims once per
  package and evicts by descendant score.

- TRUC (BIP 431) policy for version 3 transactions: one unconfirmed parent or
  child, a 1,000 vB child cap, a 10,000 vB cap, sibling eviction, and Core's
  `TRUC-violation` reasons, in `sendrawtransaction`, `testmempoolaccept`,
  `submitpackage` and relay (#1020).

- Cluster limits on admission, as in Core v31: a transaction joins at most
  `-limitclustercount` (64) connected unconfirmed transactions, itself
  included, and at most `-limitclustersize` (101 kvB, now accepted) of them.
  satd counted ancestors only, so a parent took any number of children and
  a chain of 65 passed at 64. A reorg's returned transactions are held to
  the limits too, and a cluster they grow past them by joining their
  mempool spenders is trimmed, as in Core.

- `gettxspendingprevout`, as in Core v31: the mempool spender of each
  output, and under `-txospenderindex` the confirmed spender and its block,
  read from the address index's spend rows. `-txospenderindex` is now
  refused with pruning, as in Core, and without `-addressindex`.

- Core's opportunistic 1-parent-1-child package relay: a parent a peer
  sends, refused on its fee alone, enters with a child of it the same peer
  sent, as a package (CPFP, ephemeral dust or package RBF).

- Transaction announcements trickle as Core's do: queued per peer and
  announced on a Poisson timer (2 s outbound, 5 s inbound), parents first,
  and a transaction is served only to a peer it has been announced to.
  `getpeerinfo` reports `inv_to_send` and `last_inv_sequence`.
  `txannouncedelay=0` (opt-in) announces to every peer at once.

- `getorphantxs`, Core's hidden RPC listing the orphanage. The orphanage
  records every peer that sent or announced an orphan, as Core's does: each
  is asked for the missing parents and may pair the orphan with a parent it
  sends, and an orphan stays until the last of them disconnects.

- The orphanage has Core v30's limits: a latency score of 3,000 and
  404,000 WU of orphans per peer with one, evicting from the peer furthest
  over its share. Orphans are keyed by wtxid, so a malleated copy no longer
  displaces the real one, and they no longer expire after 20 minutes.

- Package RBF in `submitpackage`, as in Core v31: a child may pay for its
  parent's replacement, which the parent could not afford alone. Core's
  `PackageRBFChecks` apply (one parent and one child, no unconfirmed
  ancestors, the package's fees and feerate, the feerate diagram), and
  both transactions' scripts are checked before anything is evicted.

- `sat-tui` shows the quarantine class while a transaction-filtering policy
  is loaded: a Quarantine panel in the mempool view (held count and bytes
  against the budget, confirmed-anyway count, foregone fees, a per-rule
  table), and the held count beside the Txs line of the steady view.

### Fixed

- The address index built by a backfill (`-addressindex` turned on for an
  already-synced chain) leaves out unspendable outputs, as the index built
  while blocks connect always has. It used to record each OP_RETURN output,
  and each output script over 10,000 bytes, as an unspent coin under that
  script's scripthash.

- The address book's service bits follow an outbound peer's `version` and
  add up over later announcements, as Core's do; they used to stay as first
  heard.

- BIP 324 (v2 transport) handshakes send 0 to 4095 random garbage bytes after
  the key, as Core's do. satd sent none, so its v2 connections were a fixed
  size that a network observer could recognise.

- `sat-cli` and `sat-tui` with `-rpccacert` trust only the certificates in
  that file. The public CA roots used to apply as well, so any public CA that
  issued a certificate for the node's hostname, such as one signing with the
  leaked emSign intermediate keys, could intercept the RPC credential.

- `rustls-webpki` 0.103.16 and `webpki-roots` / `webpki-root-certs` 1.0.10
  (RUSTSEC-2026-0381, -0382, -0383: distrusted emSign intermediates).

- `getrawmempool` lists transactions in Core's mining order: best chunk
  feerate first, a cluster's transactions in its order. It listed them in
  hash-map order, which changed when a reorg returned the same
  transactions.
- A `submitpackage` ephemeral dust parent is judged by the transaction
  policy (`policyfile=`); it skipped the policy, so a rule matching it did
  not hold or refuse it.
- The Rust script engine computes a tapscript signature hash as Core does,
  from the annex hashed once per input instead of once per signature check.
  A spend with many checks and a large annex verified many times slower than
  in libbitcoinconsensus.
- A multi-transaction `testmempoolaccept` evaluates its transactions
  together, as Core does: a transaction may spend an earlier one, the TRUC
  package checks and cluster limits apply to the set as `package-error`,
  replacement is refused as `bip125-replacement-disallowed`, and the first
  refusal ends the evaluation.
- A replacement in a cluster the two-transaction diagrams cannot describe,
  such as one of several children of a cheap parent, is judged over the
  clusters it touches, as in Core v31. The per-conflict rule satd used there
  refused bumps Core accepts and accepted replacements that drop a rich
  descendant, so some replacements satd accepted are now refused. The
  cluster order approximates Core's optimal one. A replacement past the
  cluster limits is refused as `too-large-cluster` before its diagram is
  compared, as in Core.
- An announced transaction is requested from one peer at a time, as by Core's
  `TxRequestTracker`: a transaction announced by several peers was downloaded
  from every one of them. The next announcer is asked when the request times
  out (60 s), the peer answers `notfound`, or it disconnects; inbound and
  txid-only announcements wait Core's 2 s delays.
- Electrum and Esplora scripthash queries read the whole history before
  applying any cap, so one request for a busy scripthash could use GBs of
  memory. `get_history`, `get_balance`, `listunspent`, `subscribe` and the
  Esplora address stats, `/utxo` and `/sse` now stop counting at 200,000
  transactions and refuse a longer history (Electrum `history too large`,
  Esplora 400 `Too many history entries`); `get_first_use` reads only the
  first block. The new `-addrindexmaxhistory` sets the cap (`0` for none).
- `-maxmempool` below 5 MB is refused at startup with Core's message, as Core
  does; `0` is still allowed.
- A reorg of more than about 30 blocks could overflow the chain-event channel,
  and streaming subscribers silently missed blocks from it; the channel now
  holds 1024 events.
- A `submitpackage` parent with an ephemeral dust output was announced on the
  mempool stream after the child that spends it; it is now announced first,
  as Core does.
- Header timestamps (median time past, two hours ahead) and minimum block
  versions are checked on every header and block-store path, and transaction
  finality, coinbase height and `CheckTransaction` before a block is written,
  as in Core's `AcceptBlockHeader` and `AcceptBlock`; they were checked only
  for blocks arriving outside initial block download, or only at connect.
- `-assumevalid` skipped script verification for every block at or below the
  assumevalid height; it now skips only buried ancestors of the assumevalid
  block on the best-header chain, under Core's minimum-chain-work and
  two-week conditions, and logs Core's decision lines. `-minimumchainwork`,
  accepted and ignored before, now takes effect.
- A peer that sends an invalid block is now charged for it like any other
  misbehaviour (disconnected and banned; `noban` and manual peers kept, local
  ones only disconnected), including for a block judged only when the
  initial-block-download connector reaches it (#544).
- A node that caught up through its parallel block download never announced
  the tip it reached, so a peer that does not poll for headers, as Core does
  not, stayed behind until the next block; the tip is now announced.
- A coin or undo record with a ten-byte varint that does not fit in 64 bits is
  now refused as corrupt instead of decoding to a truncated value (#975).
- BIP 30's buried-BIP 34 skip now needs Core's BIP 34 block at that height
  and ends at height 1,983,702, as in Core; testnet3, past that height, checks
  BIP 30 on every block again.
- `getblocktemplate` transactions carry Core's `hash` (wtxid) and `depends`
  fields; gateways that require them (such as OCEAN's DATUM gateway) refused
  every non-empty template (#982).
- `-onlynet` restricts automatic outbound connections and kept addresses, with
  Core's startup refusals; `-proxy` soft-sets `-listen=0`; `-proxy=0` and
  `-onion=0` are read as Core reads them. **A node with `-proxy` and no explicit
  `-listen` stops listening.**
- `/readyz` is 503 while the `tip_stall` or `peer_floor` health detector is
  raised: a node that lost its peers showed no lag and stayed ready (#979).
- `getaddr` is answered only for inbound peers, once per connection, from a
  cached sample of the address book per listening socket, as in Core; satd
  sent every peer its live connection list and its own addresses.
- The mempool applies Core's script policy: the standard script verification
  flags, `ValidateInputsStandardness` (with BIP 54's legacy sigop limit),
  `IsWitnessStandard`, and the 16000 sigop-cost cap. It checked scripts under
  the block's flags alone, and relayed and mined spends of soft-fork upgrade
  hooks.
- A transaction the mempool refused is not downloaded and validated again
  until the tip moves, as with Core's recent-rejects filters; satd fetched it
  from every peer that announced it.
- `-bytespersigop` (default 20) takes effect: the mempool and block template
  price a transaction at Core's sigop-adjusted size, the larger of its vsize
  and its sigop cost times 20 bytes; it was accepted and ignored.
- A pruned node advertises `NODE_NETWORK_LIMITED` and not `NODE_NETWORK`, and
  every node sets `NODE_NETWORK_LIMITED`, as Core does. Blocks are served as
  in Core's `ProcessGetBlockData`: a block off the active chain only if it was
  validated, and from a pruned node nothing more than 290 below the tip.
- Shutdown waits for running JSON-RPC calls to finish before it flushes the
  chainstate and dumps the mempool, as Core does; a call still running could
  admit a transaction after the dump or, with `generatetoaddress`, connect
  blocks past the tip the clean-shutdown marker recorded (#983).
  `generatetoaddress`, `waitfor*` and long-polling `getblocktemplate` stop at
  shutdown.
- `invalidateblock` disconnects to the invalidated block's parent before it
  activates a competing branch, as Core does; a competing branch that failed
  to connect left the node on the tip it had just marked invalid, refusing
  every new block until a restart (#977).
- A peer stalling initial block download is disconnected, with Core's
  adaptive stall timeout (15s here, doubling to 64s); it stayed connected and
  could be handed the same blocks again. A block handed to another peer is
  timed from that peer's request (#972). A peer is judged stalling only
  while another peer is delivering, so a brief outage of the node's own link
  no longer drops every peer; one silent for ten minutes is dropped anyway,
  as by Core's block download timeout.
- `mempool.dat` keeps `prioritisetransaction` deltas for transactions not in
  the pool, as Core does, and a zero-fee package parent's entry time follows
  `setmocktime` (#981).
- A list option given on the command line and in `bitcoin.conf` takes both,
  command line first, as Core's `GetSettingsList` merges them; the command
  line's replaced the file's (#995). The `getaddr` cache follows
  `setmocktime`.
- DNS and fixed seeds are tried after startup too, as Core does: the DNS
  seeds when the node has fewer than two full-relay outbound peers 11 seconds
  in (5 minutes with a large address book), the fixed seeds a minute in if
  the book has nothing reachable. A stale `peers.dat` stopped all seeding
  (#974).
- The Tor hidden service keeps its address across restarts: its key is saved
  to `onion_v3_private_key` (mode 0600) and reused, as in Core; satd asked
  Tor to discard it (#973).
- satd sets Core's `umask(077)` at startup: new files are 0600 and new
  directories 0700. `mempool.dat`, `peers.dat` and the ban list were
  world-readable.
- `-externalip` accepts a v3 `.onion` address and advertises it, Core's
  manual hidden-service setup; satd refused it at startup (#973).
- The Tor hidden service comes back after Tor restarts: satd reconnects to
  the control port with Core's backoff (1 s, growing by half, at most 10
  minutes) and adds the service again, and stops advertising the address
  while it is down. It connected once, at startup (#973).
- `getblock` and `getrawtransaction` answer with Core v31's fields (#978):
  `getblock` adds `strippedsize` and `coinbase_tx`, and at verbosity 2 and
  3 each transaction's `fee` and each input's `prevout` from the block's
  undo data, with or without `-txindex`. A coinbase shows its witness.
  satd's own extra fields are gone: `blockheight`, a mempool
  transaction's `confirmations: 0`, the per-transaction block fields in
  `getblock`, and `decoderawtransaction`'s `hex`.
- `getblocktemplate`'s `mintime`, and its `curtime` on every network, take
  Core's BIP 94 floor at a retarget height: no more than 600 seconds before
  the parent. A testnet4 block stamped at the advertised `mintime` could fail
  as a timewarp.
- A custom signet (`-signetchallenge`) no longer uses the default signet's
  checkpoints or assumevalid block. Its block at height 50,000 failed as a
  checkpoint mismatch, and the node stopped following the chain.
- A dial through `-proxy` waits up to 20 seconds for the proxy's SOCKS5
  replies, as Core does; only the connect to the proxy is bounded by
  `-timeout`. A Tor circuit often took longer than the 5-second default, so
  clearnet peers through Tor failed to connect.
- `getblocktemplate` on mainnet refuses with -9 when the node has no peers
  and -10 during initial block download, as Core does. It handed out
  templates on a stale tip.
- `gettxout`'s `scriptPubKey` has Core's `desc`, `address` and `type`.
- The scriptPubKey `type` that `getrawtransaction`, `decoderawtransaction`,
  `decodescript` and `gettxout` report names bare P2PK (`pubkey`), bare
  multisig (`multisig`), P2A (`anchor`) and witness v2+ (`witness_unknown`)
  outputs as Core does, and calls an `OP_RETURN` script `nulldata` only when
  the rest of it is pushes. They were `nonstandard`.
- An unroutable `-externalip` address (private, loopback, documentation
  space) is no longer advertised to peers or listed in `localaddresses`, as
  Core's `AddLocal` refuses it.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.6.3](docs/release-notes/0.6.3.md) | 2026-10-21 | Security release. With `-rpctls`, `sat-cli` and `sat-tui` trust only the CA named by `-rpccacert` instead of adding it to the public roots, so no public CA can stand in for the node and receive the RPC credentials. A `-rpccacert` that does not name the node certificate's issuer is now refused. The node is unchanged from 0.6.2. No reindex. |
| [0.6.2](docs/release-notes/0.6.2.md) | 2026-10-20 | Security release. Certificates that chain through the eMudhra (emSign) intermediate CAs, whose private keys were disclosed, are refused wherever satd, `sat-cli` and `sat-tui` check a server against the public roots: alert webhooks, TLS JSON-RPC clients, `satd-events-client` without a pinned CA, and the `--fast-start` download. `rustls-webpki` 0.103.16, `webpki-roots` 1.0.10 (RUSTSEC-2026-0381 to 0383). The 0.6.0 appliance images are superseded. No reindex. |
| [0.6.1](docs/release-notes/0.6.1.md) | 2026-10-15 | Fixes for 0.6.0. An interrupted `-reindex` continues where it stopped on any start, a stop signal ends a rebuild cleanly (also as PID 1), and the reindex scan reads block headers only. Initial sync no longer waits on one slow peer or stalls with a full download window. Sigop counting, the tapscript `OP_SUCCESS` set, header sync, signet commitments and invalid-block handling match Bitcoin Core. Core's P2P message limits, address rate limits, one outbound peer per network group, and no bans for `noban`, manual, local or onion-inbound peers. Mempool eviction checks scripts first, a restart keeps the whole mempool, and mempool and other RPC answers match Core. Electrum status hashes follow history order, Esplora pages with `after_txid`, a refused streaming watch add is reported to the client, and the filter index repairs a header chain a 0.6.0 backfill broke. `rustls` 0.23.46 (RUSTSEC-2026-0346 to 0349, none affecting satd's configuration). No reindex; an `rpcpassword` containing `#` is now refused. |
| [0.6.0](docs/release-notes/0.6.0.md) | 2026-10-05 | Solo mining, silent-payment sending, and half-size indexes. A **Stratum V1 and V2 solo-mining server** in the node (TLS for V1, Noise for V2, Job Declaration, per-miner statistics) lets a miner mine to its own address with no pool and no proxy, from block templates that now match Core's: the right difficulty at a retarget, the sigop limit, CPFP package selection, `-blockmaxweight`, and a validity check before a miner sees one. **Silent-payment sending (BIP 375)** over PSBT version 2, with `analyzepsbt` and `finalizepsbt` verifying every silent-payment output before it can be broadcast; the node stays keyless. Every index is keyed on transaction ordinals instead of txids, which **halves a fully indexed chainstate** (805 GB to 388 GB on mainnet). Faster block relay with BIP 152 high-bandwidth compact blocks and BIP 339 wtxid relay, sync, reorg and reindex robustness fixes, and another round of Core parity from Core's functional tests. Installable from Umbrel's community store or a signed appliance image for amd64 and arm64. **One `-reindex-chainstate` is required** (chainstate schema 3 to 7; app-store installs run it by themselves, pruned nodes must resync, and there is no downgrade). A configured `-rpcallowip` now also gates the TLS JSON-RPC listener, the HTTP listeners speak HTTP/1.1 only, and Esplora tokens that broadcast need `rpc:submit`. |
| [0.5.2](docs/release-notes/0.5.2.md) | 2026-09-11 | Deployment and Bitcoin Core parity. Three new ways to run satd — a docker-compose **reference stack** with TLS everywhere and LND/CLN/RTL/Cashu/BTCPay overlays, a bootable **appliance image**, and **Umbrel and StartOS packages** — each installed and driven on a real server; `sat-cli`/`sat-tui` reach a TLS RPC listener; the container image ships `sat-tui` and a `HEALTHCHECK` and is **136 MB instead of 670 MB**. MCP is reachable by hostname (`-mcpallowedhost`, #734). The defects filed from the 0.5.1 functional-test review (#660–#673) and the ones Core's suite went on to find, closed in Core's direction: a mistyped RPC argument no longer discards the ones after it (#672), surplus arguments are refused (#688), `createrawtransaction`/`createpsbt` check the address network and parse amounts exactly (#689), mempool policy at Core parity — dust thresholds, feerate-diagram RBF, ephemeral dust, `submitpackage`/`testmempoolaccept` shapes (#660, #661, #665, #673), `getblocktemplate` proposal mode validates like `submitblock` (#663), more than a dozen RPC fields that were constants now come from the node (#667, #702), `-connect=0` no longer dials the address zero and a pinned node stops listening (#690), and two **security** fixes — `-whitelist` no longer reaches Tor or outbound peers (#701) and a proxied node no longer resolves peer hostnames locally (#668). An **IBD wedge** on fork-heavy networks, where a competing header could permanently replace the next block to fetch, is fixed and a damaged datadir heals on the first restart (#738). Drop-in binary upgrade, no reindex; `banlist.json` moves to Core's format, so delete it before any downgrade. |
| [0.5.1](docs/release-notes/0.5.1.md) | 2026-09-04 | A Bitcoin Core compatibility release. satd now runs **Core's own functional test suite**, unmodified and pinned to a Core release, with all 264 test files inventoried as run-or-skip-with-a-reason; the set gates every pull request and found twelve defects in shipped behaviour — an RPC `Content-Type` Core-derived clients reject outright, a startup listener answering "no such method" where Core answers "warming up", a `bitcoin.conf` fee-rate value silently discarded, a panic on any unparseable `-bind` (and no IPv6 bind at all), mempool chain limits enforcing a limit Core v31 no longer has, and an oversized locator banning the peer where Core only disconnects. The mempool event broadcast now holds a whole block's confirmations — its 1024-slot ring was smaller than a single mainnet block, so every subscriber silently lost roughly 37% of each block's burst (#682). Silent payments reach wallets that exist today via `blockchain.tweaks.subscribe` on the Electrum server, plus `tweak_unspent_only` cut-through and spendable silent-payment outputs (#609). **Breaking:** `getindexinfo` is now Core's method — satd's richer view moved to `getsatdindexinfo`; `uacomment` is now validated and an unparseable `minrelaytxfee`/`dustrelayfee` now stops the node. Drop-in binary upgrade, no reindex. |
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.6.0...HEAD
