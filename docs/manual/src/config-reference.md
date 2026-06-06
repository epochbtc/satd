# Configuration Flag Reference

This chapter is the complete reference for every configuration key satd
recognizes — what it does, its default, whether it reloads live on `SIGHUP`, and
whether it is **Bitcoin Core-compatible** or a **satd extension**.

For *how* configuration is sourced and the live-reload mechanics, see
[Configuration, Tuning & Reload](configuration.md). This chapter is the flat
per-key index. The auth-related keys (`authfile`, `*authbearer`/`*auth`,
`*allowremote`, cookie/`rpcuser`/`rpcauth`) are explained in context in
[Authentication & Authorization](authentication.md); the sync / consensus /
storage-tuning keys (`assumevalid`, `consensus`, `shadow*`, `dbcache`,
`prefetchworkers`, `maxahead`, `storageprofile`, the `rocksdb*` / `compaction*`
family, reindex) in [Initial Block Download & Fast Sync](ibd.md).

## How satd reads configuration

**Goal: drop in your existing Bitcoin Core `bitcoin.conf` and have it just
work.** satd reads Core's configuration surface directly — same
`bitcoin.conf` / `satd.conf` `key=value` + `[network]` section syntax and the
same CLI flag names (`-datadir`, `-rpcport`, …). Supported-flag names and
semantics track **Bitcoin Core v30**.

- **Resolution order:** `-conf=<path>` if given, else `<datadir>/bitcoin.conf`,
  else `<datadir>/satd.conf`. **CLI flags always win** over file values.
- **What happens to each config-file key** (the four-way disposition that makes
  drop-in safe):
  1. **Honored** — satd implements it. The common operator surface.
  2. **Skipped with a warning** — a recognized Core v30 option satd doesn't
     implement but is *safe to skip*. The node **still starts**; a `WARN` line
     names the ignored key (and the satd equivalent, if any). This is what lets
     a real `bitcoin.conf` boot unedited.
  3. **Rejected at load** — a small set where silently skipping would mislead
     you about the node's **security / exposure / privacy** posture (see
     [Unsupported Core keys](#unsupported-core-keys-skipped-vs-rejected)).
     Fail-closed with guidance.
  4. **Rejected as a typo** — a key that is neither a satd option nor a known
     Core v30 option. Rejected so a fat-fingered security option (e.g.
     `rpcusser=`) can't silently disable auth.
- **Never *silently* ignored.** Skipped keys always warn; nothing a config asks
  for is dropped without the operator being told.
- **`-profile=<preset>`** seeds a hardware/role profile (`archival`,
  `pruned-home`, `mining`, `regtest-dev`, `signet-watchtower`); explicit flags
  override the profile's values.

## Legend

- **Reload** — `hot`: applied live on `SIGHUP` (`systemctl reload satd`).
  `restart`: wired into long-lived state at startup; reported as "restart
  required" on reload, never silently ignored. (TLS *certificate contents*
  reload via `SIGUSR1` even where the key is `restart` — see
  [Live TLS Certificate Reload](configuration.md#live-tls-certificate-reload-sigusr1).)
- **Compat** — `core`: same key name **and** substantially the same semantics as
  Bitcoin Core. `satd`: a satd-specific extension (no Core equivalent, or
  satd-only semantics). Best-effort classification; a key "modeled on" Core
  behavior but without a Core flag of the same name is `satd`.

---

## Network selection

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `regtest` | off | restart | core | Use the regtest network. |
| `testnet` | off | restart | core | Use the testnet network. |
| `testnet4` | off | restart | core | Use the testnet4 network. |
| `signet` | off | restart | core | Use the signet network. |
| `chain` | main | restart | core | Unified network selector: `main`\|`test`\|`signet`\|`regtest`. Alternative to the per-net flags. |

## Filesystem

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `datadir` | platform default | restart | core | Data directory. |
| `blocksdir` | `<datadir>/blocks` | restart | core | Alternative location for `blocks/` and flat-file undo data. |
| `conf` | `bitcoin.conf` in datadir | restart | core | Config file path. |
| `includeconf` | none | restart | core | Additional config file to splice in; honored only inside a config file. |
| `pid` | none | restart | core | Write PID to file. |
| `profile` | none | restart | satd | Named preset: `archival`\|`pruned-home`\|`mining`\|`regtest-dev`\|`signet-watchtower`; CLI flags override it. |

## Daemon control

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `daemon` | off | restart | core | Run in background; accepted for compatibility (no-op — use systemd). |
| `server` | on | restart | core | Accept RPC commands; accepted for compatibility (always on). |
| `logformat` | text | restart | satd | Log output format: `text` or `json`. Only verbosity hot-reloads, not the format. |
| `debug` | none | hot | core | Enable debug logging for a category (repeatable; bare/`all`/`1` = everything). |
| `debugexclude` | none | hot | core | Disable debug logging for a category `debug` would otherwise enable. |
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
| `rpcworkqueue` | 64 | restart | core | Max queued RPC requests beyond `rpcthreads` before HTTP 429 (Core returns 503 — documented divergence). |
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

(satd-specific — Core's RPC is HTTP-only behind a TLS-terminating sidecar.)

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
| `blocksonly` | false | hot | core | Suppress P2P transaction relay; locally-submitted txs still relayed. |
| `v2transport` | true | hot | core | Offer/accept BIP 324 v2 encrypted transport (Core default since v26). |
| `v2only` | false | hot | satd | Refuse peers that do not speak BIP 324 v2 (privacy / anti-surveillance lever). |
| `externalip` | none | hot | core | External address to advertise to peers (repeatable). |
| `whitelist` | none | hot | core | Grant net permissions to peers by source subnet (repeatable). |
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

## Proxy / Tor

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `proxy` | none | restart | core | SOCKS5 proxy for all outbound connections. |
| `proxyrandomize` | on | restart | core | Use fresh random SOCKS5 credentials per connection so Tor isolates each peer on its own circuit (`IsolateSOCKSAuth`). Relies on Tor's default SocksPort isolation; a no-op on a non-Tor SOCKS proxy (or one with `IsolateSOCKSAuth` disabled), where credentials are simply not negotiated. Set `=0` to opt out. |
| `onion` | = `-proxy` | restart | core | SOCKS5 proxy for `.onion` connections. |
| `torcontrol` | `127.0.0.1:9051` | restart | core | Tor control port for the hidden service. Auth is negotiated via `PROTOCOLINFO`: SAFECOOKIE (stock-Tor default) when no password is set, else password, else null. |
| `torpassword` | none | restart | core | Tor control port password (for a `HashedControlPassword` setup). Leave unset to use SAFECOOKIE cookie auth. |
| `listenonion` | off (on if `torcontrol` set) | restart | core | Create a Tor v3 hidden service via the control port. |

## Consensus

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `assumevalid` | per-network hash | restart | core | Skip script verification up to HASH (`0`=verify all, `all`=skip old blocks). |
| `assumevalidage` | 86400 | restart | satd | With `assumevalid=all`, still verify scripts for blocks newer than SECS. |
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
| `mempoolfullrbf` | on | hot | satd | Enable full replace-by-fee. Core removed this flag in v28 (full-RBF is now unconditional there); satd retains it as a toggle. |
| `maxmempool` | 300 MB | hot | core | Maximum mempool size in MB. |
| `minrelaytxfee` | 1000 sat/kvB | hot | core | Minimum relay fee rate. |
| `dustrelayfee` | 3000 sat/kvB | hot | core | Dust relay fee rate. |
| `datacarrier` | on | hot | core | Accept `OP_RETURN` outputs. |
| `datacarriersize` | 83 bytes | hot | core | Maximum `OP_RETURN` size in bytes (`0` = reject all). |
| `limitancestorcount` | 25 | hot | core | Maximum unconfirmed ancestor count. |
| `limitdescendantcount` | 25 | hot | core | Maximum unconfirmed descendant count. |
| `mempoolexpiry` | 336 h | hot | core | Mempool entry expiry in hours. |
| `persistmempool` | on | hot | core | Persist the mempool to `mempool.dat` across restarts. |
| `permitbaremultisig` | on | hot | core | Allow bare multisig outputs. |

## Esplora

(satd-specific — native Esplora REST server. See [Esplora REST API](esplora.md).)

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

(satd-specific — native Electrum protocol server.)

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
| `electrummaxsubsperconn` | 100 | restart | satd | Per-connection scripthash subscription cap. |
| `electrumrequesttimeout` | 30 | restart | satd | Per-request handler timeout (seconds). |
| `electrummaxbatchrequests` | 16 | restart | satd | Max requests per JSON-RPC batch line. |
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
| `par` | — | restart | core | Script-verification threads; accepted for compatibility (no-op). |

## Events

(satd-specific event bus. The `eventszmq*` spelling is satd's — Core uses
per-topic `-zmqpub*=<addr>` flags — but the `hashtx`/`hashblock` payloads are
Core ZMQ wire-format compatible.)

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `eventsnodeid` | auto (persisted to `<datadir>/node_id`) | restart | satd | Stable per-node identifier (32-char hex) stamped on events envelopes. |
| `eventsregion` | none | restart | satd | Optional region tag (≤8 ASCII bytes) on events envelopes. |
| `eventsgrpcbind` | off | restart | satd | host:port to bind the events gRPC streaming server. |
| `eventsgrpcallowremote` | false | restart | satd | Permit `eventsgrpcbind` on a non-loopback address (requires `eventsgrpcauth`). |
| `eventsgrpcauth` | false | restart | satd | Require bearer tokens (`stream:subscribe`) on events gRPC (requires `authfile`). |
| `eventsgrpcmaxconns` | 64 (`0` disables) | restart | satd | Hard cap on simultaneously-open events gRPC connections. |
| `eventsgrpcmaxsubscriptions` | 256 (`0` disables) | restart | satd | Hard cap on concurrent events gRPC `Subscribe` streams. |
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

## Webhooks

| Key | Default | Reload | Compat | Description |
|---|---|---|---|---|
| `reorgwebhook` | none | hot | satd | HTTP(S) endpoint receiving a POST on reorg detection. |
| `reorgwebhooksecret` | none | hot | satd | HMAC-SHA256 secret signing webhook bodies via `X-Satd-Signature`. |

## MCP

(satd-specific — Model Context Protocol server.)

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

Recognized Core v30 options satd doesn't implement but that are **safe to skip**
are ignored with a startup `WARN` line — the node boots without them. The warning
names the satd equivalent where one exists. This covers the low-value long tail,
e.g.:

| Key(s) | Warning guidance |
|---|---|
| `rest` | satd ships native Esplora REST instead of Core's `/rest/`; enable with `-esplora` (on by default). |
| `zmqpub*` (`hashtx`/`hashblock`/`rawtx`/`rawblock`/`sequence` + `*hwm`) | Core's per-topic ZMQ is replaced by the events bus (`-eventszmqbind` + `-eventszmqhashtx`/`-eventszmqhashblock`, Core wire-format). |
| `peerbloomfilters` | BIP37 unsupported (privacy/DoS); use BIP157/158 (`-blockfilterindex`/`-peerblockfilters`). |
| `upnp`, `natpmp` | Deprecated in Core; configure port forwarding externally. |
| `debuglogfile`, `shrinkdebugfile`, `printtoconsole`, `logratelimit` | satd logs to stdout/journald; no `debug.log`. |
| `maxorphantx` | Removed in Core v30 too. |
| `wallet`, `walletdir`, … | satd is keyless (no wallet); use external wallets + PSBT. |
| `coinstatsindex`, `loadblock`, `checkblocks`/`checklevel`, `bytespersigop`, `maxsigcachesize`, `blockversion`, `printpriority`, `txreconciliation`, `discover`, `persistmempoolv1`, `acceptstalefeeestimates`, `blocksxor`, `settings`, `daemonwait`, `deprecatedrpc`, `rpcdoccheck`, … | Recognized Core v30 options satd does not implement; skipped (generic warning). |

### Rejected at load (fail-closed)

A small set stays **fatal**, because silently skipping them would mislead you
about the node's **security / exposure / privacy** posture. Each rejects with an
actionable message:

| Key(s) | Reason |
|---|---|
| `i2psam`, `i2pacceptincoming` | I2P out of scope — skipping would route traffic over clearnet instead of the privacy network you configured. Tor is satd's anonymity network (`-proxy`/`-onion`/`-torcontrol`). |
| `rpcwhitelist`, `rpcwhitelistdefault` | satd uses capability-scoped bearer tokens (`-authfile`); skipping would leave RPC less restricted than your Core config intends. See [Authentication & Authorization](authentication.md). |

### Typos

A key that is **neither a satd option nor a known Core v30 option** is rejected
at load as a likely typo — this is what stops a fat-fingered `rpcusser=` from
silently disabling authentication.

> **Compatibility scope.** "Supported" is the commonly-used Core operator
> surface, with semantics pinned to Core v30. The long tail is skipped-with-warning
> rather than honored.
