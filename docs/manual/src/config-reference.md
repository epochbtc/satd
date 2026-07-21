# Configuration Flag Reference

This chapter is the complete reference for every config key satd recognizes:
what it does, its default, whether it reloads live on `SIGHUP`, and whether it
is Bitcoin Core-compatible or a satd extension.

For how configuration is sourced and how live reload works, see
[Configuration, Tuning & Reload](configuration.md). This chapter is the flat
per-key index. The auth keys (`authfile`, `*authbearer`/`*auth`,
`*allowremote`, cookie/`rpcuser`/`rpcauth`) are explained in context in
[Authentication & Authorization](authentication.md). The sync, consensus, and
storage-tuning keys (`assumevalid`, `consensus`, `shadow*`, `dbcache`,
`prefetchworkers`, `maxahead`, `storageprofile`, the `rocksdb*` / `compaction*`
family, reindex) are covered in [Initial Block Download & Fast Sync](ibd.md).

## How satd reads configuration

The goal is that an existing Bitcoin Core `bitcoin.conf` drops in and works.
satd reads Core's configuration surface directly: the same
`bitcoin.conf` / `satd.conf` `key=value` and `[network]` section syntax, and
the same flag names (`-datadir`, `-rpcport`, …). Supported names and semantics
track Bitcoin Core v30.

- **Resolution order.** `-conf=<path>` if given, else `<datadir>/bitcoin.conf`,
  else `<datadir>/satd.conf`. Flags override file values.
- **Key disposition.** Each config-file key gets one of four treatments:
  1. **Honored.** satd implements it. This is the common case.
  2. **Skipped with a warning.** A recognized Core v30 option satd does not
     implement but that is safe to skip. The node still starts, and a `WARN`
     line names the ignored key and the satd equivalent, if any. This is what
     lets a real `bitcoin.conf` boot unedited.
  3. **Rejected at load.** A small set where skipping would mislead you about
     the node's security, exposure, or privacy posture (see
     [Unsupported Core keys](#unsupported-core-keys-skipped-vs-rejected)).
     satd fails closed with guidance.
  4. **Rejected as a typo.** A key that is neither a satd option nor a known
     Core v30 option. Rejection stops a mistyped security option such as
     `rpcusser=` from silently disabling auth.
- No key is silently ignored. Skipped keys always warn; nothing a config asks
  for is dropped without a log line.
- `-profile=<preset>` seeds a hardware/role profile (`archival`,
  `pruned-home`, `mining`, `regtest-dev`, `signet-watchtower`). Explicit flags
  override the profile's values.

> **Note.** Compatibility is pinned to Bitcoin Core v30, a frozen and
> verifiable surface. Keys Core adds in v31 or later (for example
> `limitclustercount`, `limitclustersize`, `privatebroadcast`,
> `txospenderindex`) are not recognized and are rejected as typos until the
> pin is bumped. Keys Core removed at or before v30 (for example `upnp`,
> `maxorphantx`) are likewise not honored. A `bitcoin.conf` migrated from a
> newer Core that contains a v31+ key stops satd at startup with an "unknown
> key" error. This is intentional.

> **Note.** This reference is for operating the node. To write software that
> consumes node state (blocks, mempool, address activity, reorgs), use the
> [Streaming Consumption API](streaming.md) (gRPC, WebSocket, or ZMQ). It is
> reorg-safe, supports durable cursor replay, and is decoupled from consensus.
> The Core `*notify` shell hooks and RPC polling exist for compatibility and
> quick scripts only. They have no delivery guarantee, no replay, and no reorg
> awareness.

## Legend

- **Reload.** `hot`: applied live on `SIGHUP` (`systemctl reload satd`).
  `restart`: wired into long-lived state at startup; reported as "restart
  required" on reload, never silently ignored. TLS certificate contents reload
  via `SIGUSR1` even where the key is `restart`; see
  [Live TLS Certificate Reload](configuration.md#live-tls-certificate-reload-sigusr1).
- **Compat.** `core`: same key name and substantially the same semantics as
  Bitcoin Core. `satd`: a satd-specific extension (no Core equivalent, or
  satd-only semantics). The classification is best-effort; a key modeled on
  Core behavior but without a Core flag of the same name is `satd`.

> **Note.** Every key in the per-category tables below is honored: satd
> implements it. Recognized Core v30 keys satd does not honor are not in these
> tables. They are listed, with their warn-and-skip or fail-closed disposition,
> under [Unsupported Core keys: skipped vs
> rejected](#unsupported-core-keys-skipped-vs-rejected). A key in neither
> place is rejected as a typo.

---

## Network selection

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `regtest` | off | restart | core | Use the regtest network. |
| `testnet` | off | restart | core | Use the testnet network. |
| `testnet4` | off | restart | core | Use the testnet4 network. |
| `signet` | off | restart | core | Use the signet network. |
| `chain` | main | restart | core | Unified network selector: `main`\|`test`\|`signet`\|`regtest`\|`testnet4`. Alternative to the per-net flags. |

The bare selectors (`signet=1`, `testnet4=1`, …) and `chain=` are honored both
on the command line and in `bitcoin.conf`, as in Bitcoin Core. Command-line
selectors take precedence over the config file. Selecting more than one network
(two bare selectors, or a `chain=` that disagrees with a bare selector) is a
startup error.

## Filesystem

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `datadir` | platform default | restart | core | Data directory. |
| `blocksdir` | `<datadir>/blocks` | restart | core | Alternative location for `blocks/` and flat-file undo data. |
| `blocksxor` | unset | restart | core | Blocks-dir `*.dat` XOR obfuscation (Core v28+ `blocks/xor.dat`). Unset: honor an existing key (an obfuscated Core v28+ `blocks/` dir reads with no config) and initialize fresh dirs plaintext. `1`: also generate a random key on a brand-new blocks dir (Core's default). `0`: demand plaintext; refuses a dir with a nonzero stored key. |
| `conf` | `bitcoin.conf` in datadir | restart | core | Config file path. |
| `includeconf` | none | restart | core | Additional config file to splice in; honored only inside a config file. |
| `pid` | none | restart | core | Write PID to file. |
| `profile` | none | restart | satd | Named preset: `archival`\|`pruned-home`\|`mining`\|`regtest-dev`\|`signet-watchtower`; CLI flags override it. |

## Daemon control

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `daemon` | off | restart | core | Run in background; accepted for compatibility (no-op; use systemd). |
| `server` | on | restart | core | Accept RPC commands; accepted for compatibility (always on). |
| `logformat` | text | restart | satd | Log output format: `text` or `json`. Only verbosity hot-reloads, not the format. |
| `logtimestamps` | on | restart | core | Prepend a timestamp to each log line. Disable (`-nologtimestamps`) when journald / the container runtime already stamps lines. |
| `logthreadnames` | off | restart | core | Prepend the originating thread name to each log line. |
| `logsourcelocations` | off | restart | core | Prepend source `file:line` to each log line. |
| `debug` | none | hot | core | Enable debug logging for a category (repeatable; bare/`all`/`1` = everything). |
| `debugexclude` | none | hot | core | Disable debug logging for a category `debug` would otherwise enable. |
| `loglevel` | info | hot | core | Global verbosity (`trace`/`debug`/`info`/`warn`/`error`) or a per-category override (`net:debug`). Maps onto satd's `tracing` filter: a bare level sets the default for targets without an override, and does not lower a more specific `-debug`/`RUST_LOG` directive (`-debug=net -loglevel=error` still logs `net` at debug). A `category:level` pair overrides that subsystem. |
| `allowignoredconf` | off | restart | core | Suppress startup warnings about `includeconf` files satd had to ignore. |
| `maxshutdownsecs` | 30 | hot | satd | Max graceful-shutdown flush duration (seconds) before force exit. |

## RPC server

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `rpcport` | 8332 (network-dependent) | restart | core | RPC server port. Defaults: main 8332, test 18332, testnet4 48332, signet 38332, regtest 18443. |
| `rpcbind` | `127.0.0.1:<rpcport>` | restart | core | Bind plain-HTTP JSON-RPC to address (repeatable). Non-loopback requires `rpcallowip`. |
| `rpcallowip` | loopback only | restart | core | Per-request source-IP allowlist for JSON-RPC (repeatable). |
| `rpcuser` | none | hot | core | RPC username. |
| `rpcpassword` | none | hot | core | RPC password. |
| `rpcthreads` | 16 | restart | core | Max concurrent in-flight RPC method calls. |
| `rpcworkqueue` | 64 | restart | core | Max queued RPC requests beyond `rpcthreads` before HTTP 429 (Core returns 503; documented divergence). |
| `apithreads` | `max(2, cores/4)` | restart | satd | Worker threads for the isolated API runtime (Esplora/Electrum/events gRPC/metrics). |
| `rpcreadonlybind` | none | restart | satd | Bind an opt-in read-only JSON-RPC listener (reads + mempool submit) on the API runtime. |
| `rpcreadonlyport` | 8330 | restart | satd | Default port for `rpcreadonlybind` entries without an explicit port. |
| `rpcreadonlyallowip` | loopback only | restart | satd | Source-IP allowlist for the read-only listener. |
| `rpcreadonlythreads` | = `rpcthreads` | restart | satd | Max in-flight calls on the read-only listener. |
| `rpcreadonlyworkqueue` | = `rpcworkqueue` | restart | satd | Read-only listener work-queue depth before HTTP 429. |
| `rpcreadonlytlsbind` | none | restart | satd | TLS bind for the read-only listener (requires cert+key). |
| `rpcreadonlytlscert` | none | restart | satd | PEM certificate (chain) for the read-only TLS listener. |
| `rpcreadonlytlskey` | none | restart | satd | PEM private key for the read-only TLS listener. |
| `rpcreadonlymtls` | false | restart | satd | Require a client cert (mTLS) on the read-only TLS surface. |
| `rpcreadonlymtlsclientca` | none | restart | satd | CA bundle client certs must chain to on the read-only TLS surface. |
| `rpcreadonlymtlsclientallow` | any CA-signed | restart | satd | Allowlist of client-cert subjects on the read-only TLS surface. |
| `rpcauth` | none | hot | core | HMAC-SHA256 RPC credential `user:salt$hash` (Core `rpcauth` format; repeatable). |
| `authfile` | none | restart | satd | Path to unified-auth bearer-token file (TOML); enables the opt-in bearer-auth layer. Token contents reload live. |
| `rpcauthbearer` | false | restart | satd | Honor `Authorization: Bearer` tokens on the JSON-RPC listeners (requires `authfile`). |
| `rpccookiefile` | `$DATADIR/.cookie` | restart | core | Override the auto-generated cookie file path. |
| `rpccookieperms` | owner (0600) | restart | core | Cookie file permissions: `owner`(0600)\|`group`(0640)\|`all`(0644). |
| `rpcdefaultunits` | btc | hot | satd | Default units for RPC amount fields: `btc` (Core-compatible) or `sats`. |
| `rpcdisableauth` | false | restart | satd | Disable HTTP Basic auth on the JSON-RPC TLS surface; only valid with `rpcmtls=1`. |
| `rpcextendederrors` | off | hot | satd | Emit structured error payloads (category/suggestion/debug) on RPC errors. |

## RPC TLS

(satd-specific; Core's RPC is HTTP-only behind a TLS-terminating sidecar.)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `rpctlsbind` | none | restart | satd | Bind the JSON-RPC TLS listener (requires cert+key). |
| `rpctlscert` | none | restart | satd | PEM TLS certificate for the JSON-RPC server. |
| `rpctlskey` | none | restart | satd | PEM TLS private key for the JSON-RPC server. |
| `rpctlshandshaketimeout` | 10 | restart | satd | Per-handshake timeout (seconds) for the JSON-RPC TLS surface. |
| `rpcmtls` | false | restart | satd | Require mutual TLS on the JSON-RPC TLS listener. |
| `rpcmtlsclientca` | none | restart | satd | PEM CA bundle to verify client certs when `rpcmtls=1`. |
| `rpcmtlsclientallow` | any CA-signed | restart | satd | Allowlist of accepted client-cert CN/DNS-SAN values. |

## P2P

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `listen` | on | restart | core | Accept P2P connections. |
| `networkactive` | on | hot | core | Start with P2P networking enabled. `=0` boots with networking paused (no inbound accepts, no outbound dials); change it at runtime with the `setnetworkactive` RPC. |
| `blocksonly` | false | hot | core | Suppress P2P transaction relay; locally-submitted txs still relayed. |
| `v2transport` | true | hot | core | Offer/accept BIP 324 v2 encrypted transport (Core default since v26). |
| `v2only` | false | hot | satd | Refuse peers that do not speak BIP 324 v2 (privacy hardening). |
| `externalip` | none | hot | core | External address to advertise to peers (repeatable). |
| `whitelist` | none | hot | core | Grant net permissions to peers by source subnet (repeatable). |
| `whitelistrelay` | on | hot | core | Grant `relay` to whitelisted peers with default permissions (relay their txes even under `-blocksonly`). Entries with an explicit `perms@` prefix are unaffected. |
| `whitelistforcerelay` | off | hot | core | Grant `forcerelay` to whitelisted peers with default permissions. Entries with an explicit `perms@` prefix are unaffected. |
| `whitebind` | none | restart | core | Bind an extra permissioned P2P listener (repeatable). |
| `asmap` | none | restart | core | asmap file for ASN-based addrman bucketing (eclipse resistance). |
| `port` | network default | restart | core | P2P listen port. |
| `bind` | `0.0.0.0` | restart | core | Bind P2P to this address. |
| `connect` | none | hot | core | Connect only to specific peer(s) (repeatable). Connect-only *exclusivity* is a startup decision (restart to change). |
| `addnode` | none | hot | core | Add a node to connect to (does not disable DNS seeding). |
| `seednode` | none | hot | core | One-shot seed peer connected at startup to bootstrap discovery. |
| `maxconnections` | 125 | hot | core | Maximum total connections. |
| `maxinboundperip` | 3 | hot | satd | Max simultaneous inbound peers from one source IP (Core-style flood guard; no Core flag). |
| `maxuploadtarget` | 0 (unlimited) | hot | core | Soft cap (bytes/24h) on historical block upload. |
| `dns` | true | restart | core | Allow DNS lookups for `-addnode`/`-seednode`/`-connect`. |
| `dnsseed` | true | restart | core | Query DNS seeds for peer addresses (requires `dns`). |
| `forcednsseed` | false | restart | core | Always query DNS seeds even with a populated address book. |
| `fixedseeds` | true | restart | core | Allow the compiled-in fixed-seed fallback. |
| `bantime` | 86400 | hot | core | Ban duration in seconds. |
| `timeout` | 5000 ms | hot | core | P2P connection timeout in milliseconds (accepts `5s`/`5000ms`). |
| `onlynet` | all | restart | core | Restrict to network types: `ipv4`, `ipv6`, `onion`. |
| `signetseednode` | built-in seeds | restart | core | Additional signet seed node (repeatable; signet only). |
| `signetchallenge` | default signet | restart | core | Custom signet challenge script, hex (BIP 325; signet only). |

> **Note.** satd answers a peer's BIP35 `mempool` message (a request to
> announce our entire mempool) only for peers granted the `mempool` net
> permission: `-whitelist=mempool@<subnet>`, `all@<subnet>`, or a bare
> `-whitelist=<subnet>` entry, whose implicit permission set includes
> `mempool`, as in Core. The permission is not implied by `noban@`. The
> response honors the requesting peer's fee filter, and dumps to one peer
> are rate-limited to at most one per 30 s. satd does not advertise
> `NODE_BLOOM` (BIP37 bloom filters are unsupported). `mempool` requests
> from peers without the permission are ignored, which is softer than
> Bitcoin Core with bloom disabled: Core disconnects such peers unless
> they have `noban`.

## Proxy / Tor

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `proxy` | none | restart | core | SOCKS5 proxy for all outbound connections. |
| `proxyrandomize` | on | restart | core | Use fresh random SOCKS5 credentials per connection so Tor isolates each peer on its own circuit (`IsolateSOCKSAuth`). Relies on Tor's default SocksPort isolation; a no-op on a non-Tor SOCKS proxy (or one with `IsolateSOCKSAuth` disabled), where credentials are not negotiated. Set `=0` to opt out. |
| `onion` | = `-proxy` | restart | core | SOCKS5 proxy for `.onion` connections. |
| `torcontrol` | `127.0.0.1:9051` | restart | core | Tor control port for the hidden service. Auth is negotiated via `PROTOCOLINFO`: SAFECOOKIE (stock-Tor default) when no password is set, else password, else null. |
| `torpassword` | none | restart | core | Tor control port password (for a `HashedControlPassword` setup). Leave unset to use SAFECOOKIE cookie auth. |
| `listenonion` | off (on if `torcontrol` set) | restart | core | Create a Tor v3 hidden service via the control port. |

## Consensus

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `assumevalid` | per-network hash | restart | core | Skip script verification up to HASH (`0`=verify all, `all`=skip old blocks). |
| `assumevalidage` | 86400 | restart | satd | With `assumevalid=all`, still verify scripts for blocks newer than SECS. |
| `checkpoints` | on | restart | core | Enforce the built-in block checkpoints. `-checkpoints=0` disables checkpoint validation. |
| `stopatheight` | none | restart | core | Stop once the active-chain tip reaches HEIGHT. |
| `consensus` | rust-shadow | restart | satd | Consensus engine: `cpp`\|`rust`\|`rust-shadow`\|`cpp-shadow`. |

## Indexing

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `txindex` | off | restart | core | Maintain a full transaction index. |
| `addressindex` | on | restart | satd | Maintain an address-history index (backs native Electrum/Esplora). |
| `addrindexsubscriptions` | 10000 | hot | satd | Max concurrent per-scripthash status subscriptions. |
| `blockfilterindex` | off | restart | core | BIP 158 compact-block-filter index (`basic`/`0`/`1`). |
| `peerblockfilters` | off | hot | core | Advertise `NODE_COMPACT_FILTERS` and serve BIP 157 filters; implies `blockfilterindex=basic`. |

## Mempool / relay policy

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `mempoolfullrbf` | on | hot | satd | Enable full replace-by-fee. Core removed this flag in v28 (full-RBF is now unconditional there); satd retains the flag. |
| `maxmempool` | 300 MB | hot | core | Maximum mempool size in MB. |
| `minrelaytxfee` | 1000 sat/kvB | hot | core | Minimum relay fee rate. |
| `dustrelayfee` | 3000 sat/kvB | hot | core | Dust relay fee rate. |
| `datacarrier` | on | hot | core | Accept `OP_RETURN` outputs. |
| `datacarriersize` | 83 bytes | hot | core | Maximum `OP_RETURN` size in bytes (`0` = reject all). |
| `limitancestorcount` | 25 | hot | core | Maximum unconfirmed ancestor count. |
| `limitdescendantcount` | 25 | hot | core | Maximum unconfirmed descendant count. |
| `mempoolexpiry` | 336 h | hot | core | Mempool entry expiry in hours. |
| `persistmempool` | on | hot | core | Persist the mempool to `mempool.dat` across restarts. |
| `rebroadcastinterval` | 0 (auto) | hot | satd | Seconds between rebroadcasts of unconfirmed *local* transactions (those submitted here via `sendrawtransaction`, the MCP tool, Esplora `POST /tx`, or Electrum `transaction.broadcast`). `0` = auto: a randomized 10–15 min interval per pass, matching Bitcoin Core. A locally-submitted tx is re-announced until enough peers take it (see `broadcastconfirmpeers`) or it leaves the mempool, so it still propagates if no peer was connected at submit time; the pending set is persisted in `mempool.dat` so it also survives restarts. A SIGHUP interval change applies after the in-flight sleep completes. |
| `broadcastconfirmpeers` | 1 | hot | satd | Distinct peer IPs that must take a locally-broadcast tx before it counts as propagated and rebroadcast stops. A peer takes a tx by fetching it via `getdata` (the primary signal) or announcing it back via `inv`. Counted per IP, not per connection, so a reconnecting host is one witness. Raising it demands wider observed propagation before retries stop. |
| `permitbaremultisig` | on | hot | core | Allow bare multisig outputs. |
| `acceptnonstdtxn` | off | hot | core | Relay and accept non-standard transactions (bypass the standardness relay checks: oversize, dust, OP_RETURN/datacarrier, non-standard scripts). Consensus rules are never relaxed. Intended for test/dev networks. |

## Esplora

(satd-specific; native Esplora REST server. See [Esplora REST API](esplora.md).)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `esplora` | on | restart | satd | Run the native Esplora REST server (requires `addressindex=1`). |
| `esplorabind` | `127.0.0.1:3000` | restart | satd | Bind the Esplora REST listener. |
| `esploratlsbind` | none | restart | satd | Bind the Esplora TLS listener (requires cert+key). |
| `esploratlscert` | none | restart | satd | PEM TLS certificate for the Esplora server. |
| `esploratlskey` | none | restart | satd | PEM TLS private key for the Esplora server. |
| `esploramtls` | false | restart | satd | Require mutual TLS on the Esplora TLS listener. |
| `esploramtlsclientca` | none | restart | satd | PEM CA bundle to verify client certs when `esploramtls=1`. |
| `esploramtlsclientallow` | any CA-signed | restart | satd | Allowlist of accepted client-cert CN/DNS-SAN values. |
| `esploraprefix` | `/` | restart | satd | URL prefix to mount the API under (`/api` for blockstream-style). |
| `esploracors` | none | restart | satd | Allowed CORS origin (repeatable). |
| `esplorarequesttimeout` | 30 | restart | satd | Per-request handler timeout (seconds). |
| `esploramaxconns` | 256 | restart | satd | Hard cap on concurrent in-flight Esplora requests. |
| `esplorasseconns` | = `esploramaxconns` | restart | satd | Hard cap on simultaneously-open SSE streams (`0` disables SSE). |
| `esploraauth` | none | restart | satd | Esplora auth mode: `none`\|`cookie`\|`userpass`. |
| `esploraauthbearer` | false | restart | satd | Honor bearer tokens (`esplora:read`) on the Esplora server (requires `authfile`). |
| `esploracookiefile` | shared `.cookie` | restart | satd | Cookie file when `esploraauth=cookie`. |
| `esplorauserpass` | none | restart | satd | Static `user:pass` when `esploraauth=userpass`. |

## Electrum

(satd-specific; native Electrum protocol server.)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `electrum` | off | restart | satd | Run the native Electrum protocol server (requires `addressindex=1` and `txindex=1`). |
| `electrumbind` | `127.0.0.1:50001` | restart | satd | Bind the Electrum plain-TCP listener. |
| `electrumtlsbind` | none (std port 50002) | restart | satd | Bind the Electrum TLS listener (requires cert+key). |
| `electrumtlscert` | none | restart | satd | PEM TLS certificate for the Electrum server. |
| `electrumtlskey` | none | restart | satd | PEM TLS private key for the Electrum server. |
| `electrummtls` | false | restart | satd | Require mutual TLS on the Electrum TLS listener. |
| `electrummtlsclientca` | none | restart | satd | PEM CA bundle to verify client certs when `electrummtls=1`. |
| `electrummtlsclientallow` | any CA-signed | restart | satd | Allowlist of accepted client-cert CN/DNS-SAN values. |
| `electrummaxconns` | 64 | restart | satd | Hard cap on simultaneously-open Electrum connections. |
| `electrummaxsubsperconn` | 1000 | restart | satd | Per-connection scripthash subscription cap. |
| `electrumrequesttimeout` | 30 | restart | satd | Per-request handler timeout (seconds). |
| `electrummaxbatchrequests` | 100 | restart | satd | Max requests per JSON-RPC batch line. Wallets (Sparrow) batch their whole gap-limit window of subscribes at scan time. |
| `electrummaxbroadcastpackagetxs` | 25 | restart | satd | Max txs per `blockchain.transaction.broadcast_package`. |
| `electrumfeehistogramttl` | 10 | restart | satd | TTL (seconds) for the `mempool.get_fee_histogram` cache. |
| `electrumbanner` | `powered by satd <ver>` | restart | satd | Override for `server.banner`. |

## Storage / pruning / reindex

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `prune` | 0 (no pruning) | restart | core | Prune block data to target size in MB. |
| `reindex` | off | restart | core | Rebuild block index and chain state from block files on disk. |
| `reindexchainstate` | off | restart | core | Rebuild the UTXO set from existing block files (Core `-reindex-chainstate`). |
| `checkblockindex` | off (on for regtest) | restart | core | Audit block-index / active-chain consistency at startup (Core `-checkblockindex`). |
| `dbcache` | 450 MB (or `auto`) | restart | core | Total write-cache size in MB, or `auto` for adaptive sizing. |
| `storageprofile` | ssd | restart | satd | Storage class for chainstate tuning: `ssd` or `hdd`. |
| `prefetchworkers` | CPU cores | restart | satd | Number of IBD prefetch worker threads. |
| `maxahead` | 50000 | restart | satd | Max blocks ahead during IBD: number, `N%`, or `all`. |
| `maxopenfiles` | 2048 | restart | satd | RocksDB `max_open_files` cap; `-1` = unlimited. |
| `rocksdbbackgroundjobs` | from `storageprofile` | restart | satd | Override RocksDB `max_background_jobs` (advanced). |
| `rocksdbsubcompactions` | from `storageprofile` | restart | satd | Override RocksDB `max_subcompactions` (advanced). |
| `rocksdbwalmb` | from `storageprofile` | restart | satd | Override RocksDB `max_total_wal_size` in MB (advanced). |
| `compactiondiagintervalsecs` | 60 (`0` disables) | restart | satd | Per-CF pending-compaction diagnostic log interval. |
| `compactionintervalsecs` | 1800 (`0` disables) | restart | satd | Periodic forced-compaction interval in seconds. |
| `compactionl0at` | 16 | restart | satd | Force chainstate compaction when L0 SST count ≥ N. |
| `ibdl0pauseat` | 64 (`0` disables) | restart | satd | Pause the IBD connector when chainstate L0 SST count ≥ N. |
| `stallwatchdogsecs` | 300 (`0` disables) | restart | satd | Stall-watchdog forensic-dump threshold (seconds without tip advance). |
| `stallabortsecs` | 300 | restart | satd | Additional grace after the forensics dump before `abort()`. |
| `shadowqueuesize` | 4194304 | restart | satd | Shadow-verification queue capacity. |
| `shadowworkers` | 4 | restart | satd | Shadow-verification worker threads. |

## Mining

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `blockmaxweight` | 4000000 | restart | core | Maximum block weight for templates. |
| `blockmintxfee` | 1000 sat/kvB | restart | core | Minimum tx fee for the block template. |
| `par` | unset | restart | core | Script-verification threads (Core name). When `shadowworkers` is unset, a positive value sets the shadow-verification worker count. It does not size the connect path. |

## Events

(satd-specific event bus. The `eventszmq*` spelling is satd's; Core uses
per-topic `-zmqpub*=<addr>` flags. The `hashtx`/`hashblock` payloads are
Core ZMQ wire-format compatible.)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `eventsnodeid` | auto (persisted to `<datadir>/node_id`) | restart | satd | Stable per-node identifier (32-char hex) stamped on events envelopes. |
| `eventsregion` | none | restart | satd | Optional region tag (≤8 ASCII bytes) on events envelopes. |
| `eventsgrpcbind` | off | restart | satd | host:port to bind the events gRPC streaming server. |
| `eventsgrpcallowremote` | false | restart | satd | Permit `eventsgrpcbind` on a non-loopback address (requires `eventsgrpcauth` or `eventsgrpcmtls`). |
| `eventsgrpcauth` | false | restart | satd | Require bearer tokens (`stream:subscribe`) on events gRPC (requires `authfile`). |
| `eventsgrpcmaxconns` | 64 (`0` disables) | restart | satd | Hard cap on simultaneously-open events gRPC connections. |
| `eventsgrpcmaxsubscriptions` | 256 (`0` disables) | restart | satd | Hard cap on concurrent events gRPC `Subscribe` streams. |
| `eventsgrpctlscert` | off | restart | satd | PEM TLS certificate. Set with `eventsgrpctlskey` to terminate TLS in-process on the `eventsgrpcbind` listener (no separate TLS bind). |
| `eventsgrpctlskey` | off | restart | satd | PEM TLS private key (required with `eventsgrpctlscert`). |
| `eventsgrpcmtls` | false | restart | satd | Require mutual TLS (client certificates). Requires `eventsgrpctlscert`/`key` and `eventsgrpcmtlsclientca`. |
| `eventsgrpcmtlsclientca` | off | restart | satd | PEM CA bundle verifying client certs when `eventsgrpcmtls=1`. |
| `eventsgrpcmtlsclientallow` | empty (any CA-signed cert) | restart | satd | Allowlist of accepted client-cert CN / DNS-SAN values (repeatable, comma-separated). Requires `eventsgrpcmtls=1`. |
| `eventsgrpctlshandshaketimeout` | 30 | restart | satd | Per-handshake timeout (seconds) for the events gRPC TLS surface. |
| `streamws` | off | restart | satd | host:port for the streaming JSON-over-WebSocket + SSE transport (`/ws` + `/sse`). |
| `streamwsallowremote` | false | restart | satd | Permit `streamws` on a non-loopback address (requires `streamwsauth`). |
| `streamwsauth` | false | restart | satd | Require bearer tokens (`stream:subscribe`) on `streamws` (requires `authfile`). |
| `streamwsmaxconns` | 256 | restart | satd | Hard cap on simultaneously-open `streamws` connections. |
| `streamwsmaxsubscriptions` | 256 | restart | satd | Hard cap on watch-set entries per `streamws` connection. |
| `streamwsmaxmessagebytes` | 262144 | restart | satd | Cap on a single inbound WebSocket message/frame in bytes. |
| `streammaxresyncblocks` | 10000 (`0` disables) | restart | satd | Max blocks the watch matcher re-scans in one catch-up after lagging. |
| `streamprefixminbits` | 8 | restart | satd | Minimum bit-length for a privacy-preserving script-prefix watch. |
| `streamprefixmaxbits` | 32 | restart | satd | Maximum bit-length for a script-prefix watch (range `[min, 32]`). |
| `eventszmqbind` | off | restart | satd | ZMQ endpoint for the events PUB sink. |
| `eventszmqhashtx` | on when bound | restart | satd | Enable the Core wire-format `hashtx` topic. |
| `eventszmqhashblock` | on when bound | restart | satd | Enable the Core wire-format `hashblock` topic. |
| `eventszmqmpevict` | on when bound | restart | satd | Enable `mpevict` topic (mempool eviction w/ reason; JSON). |
| `eventszmqmpreplace` | on when bound | restart | satd | Enable `mpreplace` topic (RBF replacement; JSON). |
| `eventszmqmpconfirm` | on when bound | restart | satd | Enable `mpconfirm` topic (mempool tx confirmed; JSON). |
| `eventszmqnodeevent` | on when bound | restart | satd | Enable `nodeevent` topic (full envelope JSON). |

## Webhooks / notifications

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `blocknotify` | none | restart | core | Shell command run on each new best block; `%s` is replaced by the block hash. Commands run serially on a dedicated subscriber task; a slow hook never stalls block connection, because notifications coalesce instead. The command body is not logged (it may embed credentials). |
| `alertnotify` | none | restart | core | Shell command run on each *new* node warning; `%s` is replaced by the warning text. Deduped by warning id (a repeated condition fires once, not per repeat). Runs serially like `blocknotify`. |
| `startupnotify` | none | restart | core | Shell command run once after the node finishes starting up (no `%s`). Detached, so a slow hook does not delay startup. Prefer a systemd `ExecStartPost=`. |
| `shutdownnotify` | none | restart | core | Shell command run once at the start of a graceful shutdown, before the final flush (no `%s`). Bounded by `maxshutdownsecs` so a hung hook can't wedge teardown. Prefer a systemd `ExecStopPost=`. |
| `reorgwebhook` | none | hot | satd | HTTP(S) endpoint receiving a POST on reorg detection. |
| `reorgwebhooksecret` | none | hot | satd | HMAC-SHA256 secret signing webhook bodies via `X-Satd-Signature`. |

> **Note.** The `*notify` shell hooks (`blocknotify`, `alertnotify`,
> `startupnotify`, `shutdownnotify`) exist for drop-in Bitcoin Core
> compatibility and quick scripts. They are best-effort shell execs with no
> delivery guarantee, no replay, and no reorg awareness. To build on satd, use
> the [Streaming Consumption API](streaming.md) (gRPC, WebSocket, or ZMQ): it
> is reorg-safe, offers durable cursor replay, and is decoupled from
> consensus. For lifecycle actions, prefer your service manager (systemd
> `ExecStartPost=` / `ExecStopPost=`). satd honors these four hooks. Only
> `walletnotify` is unsupported: satd is keyless, so watch scripts via the
> streaming or Esplora API. A node started with any of these hooks logs this
> guidance at startup.

## MCP

(satd-specific; Model Context Protocol server.)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `mcp` | off | restart | satd | Enable the MCP server. |
| `mcpport` | none | restart | satd | Enable the MCP HTTP transport on this port. |
| `mcpbind` | `127.0.0.1` | restart | satd | MCP HTTP bind address (non-loopback requires auth + TLS). |
| `mcpcert` | none | restart | satd | PEM TLS certificate for the MCP server (enables HTTPS; requires `mcpkey`). Required for any non-loopback bind. |
| `mcpkey` | none | restart | satd | PEM TLS private key for the MCP server (requires `mcpcert`). |
| `mcpmtls` | false | restart | satd | Require mutual TLS on the MCP listener (requires `mcpcert`/`mcpkey` + `mcpmtlsclientca`). |
| `mcpmtlsclientca` | none | restart | satd | PEM CA bundle that client certs must chain to when `mcpmtls`. |
| `mcpmtlsclientallow` | any | restart | satd | Allowlist of accepted client-cert CN / DNS-SAN values. |
| `mcpauth` | false | restart | satd | Require bearer tokens (`mcp:*`) on the MCP HTTP server (requires `authfile`). |
| `mcpallowremote` | false | restart | satd | Permit a non-loopback MCP HTTP bind (requires `mcpauth` + TLS). |

## Metrics / health

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `metricsport` | none | restart | satd | Enable Prometheus `/metrics` + `/healthz` + `/readyz` on this port (unauthenticated). |
| `metricsbind` | `127.0.0.1` | restart | satd | Metrics/health HTTP bind address. |

---

## Unsupported Core keys: skipped vs rejected

A Core v30 option satd doesn't [honor](#how-satd-reads-configuration) is handled
one of two ways so that an existing `bitcoin.conf` still drops in.

### Skipped with a warning (the node still starts)

Recognized Core v30 options satd doesn't implement, but that are safe to skip,
are ignored with a startup `WARN` line; the node boots without them. The
warning names the satd equivalent where one exists. This covers the long tail:

| Key(s) | Warning guidance |
|---|---|
| `rest` | satd ships native Esplora REST instead of Core's `/rest/`; enable with `-esplora` (on by default). |
| `zmqpub*` (`hashtx`/`hashblock`/`rawtx`/`rawblock`/`sequence` + `*hwm`) | Core's per-topic ZMQ is replaced by the events bus (`-eventszmqbind` + `-eventszmqhashtx`/`-eventszmqhashblock`, Core wire-format). |
| `peerbloomfilters` | BIP37 unsupported (privacy/DoS); use BIP157/158 (`-blockfilterindex`/`-peerblockfilters`). |
| `natpmp` | satd doesn't implement PCP/NAT-PMP port mapping; configure port forwarding externally. (`upnp` was removed in Core v29 and is rejected as unknown, as in Core v30.) |
| `debuglogfile`, `shrinkdebugfile`, `printtoconsole`, `logratelimit` | satd logs to stdout/journald; no `debug.log`. |
| `logtimemicros` | satd's logger always emits sub-second timestamps; there is no seconds-only mode, so the option has no effect. Use `-logtimestamps=0` to drop timestamps entirely. |
| `maxorphantx` | Removed in Core v30 too. |
| `wallet`, `walletdir`, `walletnotify`, … | satd is keyless (no wallet); use external wallets + PSBT, and watch scripts via the streaming/Esplora API. |
| `coinstatsindex`, `loadblock`, `checkblocks`/`checklevel`, `bytespersigop`, `maxsigcachesize`, `blockversion`, `printpriority`, `txreconciliation`, `discover`, `persistmempoolv1`, `acceptstalefeeestimates`, `settings`, `daemonwait`, `deprecatedrpc`, `rpcdoccheck`, … | Recognized Core v30 options satd does not implement; skipped (generic warning). |

### Rejected at load (fail-closed)

A small set stays fatal, because silently skipping them would mislead you
about the node's security, exposure, or privacy posture. Each rejects with an
actionable message:

| Key(s) | Reason |
|---|---|
| `i2psam`, `i2pacceptincoming` | I2P is out of scope; skipping would route traffic over clearnet instead of the privacy network you configured. Tor is satd's anonymity network (`-proxy`/`-onion`/`-torcontrol`). |
| `rpcwhitelist`, `rpcwhitelistdefault` | satd uses capability-scoped bearer tokens (`-authfile`); skipping would leave RPC less restricted than your Core config intends. See [Authentication & Authorization](authentication.md). |

### Typos

A key that is neither a satd option nor a known Core v30 option is rejected at
load as a likely typo. This is what stops a mistyped `rpcusser=` from silently
disabling authentication. The same rule catches Core v31+ keys: the
compatibility surface is frozen at v30, so a key Core only added later is
treated as unknown until the pin is bumped.

> **Note.** "Supported" means the commonly used Core v30 operator surface,
> with semantics pinned to Core v30 (not later releases). The long tail is
> skipped with a warning rather than honored. To consume node events from your
> own software, use the [Streaming Consumption API](streaming.md) instead of
> the `*notify` hooks or RPC polling.
