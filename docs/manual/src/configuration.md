# Configuration, Tuning & Reload

`satd` reads Bitcoin Core's `bitcoin.conf` syntax and CLI flag names directly,
so an existing Core config drops in and starts the node. Commonly used options
are honored, with semantics pinned to Core v30. A recognized option that satd
does not implement is skipped with a startup warning rather than aborting. See
the [Configuration Flag
Reference](config-reference.md#how-satd-reads-configuration) for the exact
disposition of every key.

On top of that compatibility, satd adds hardware-profile presets, a set of
mempool policy options under direct operator control, and live reload of both
configuration (`SIGHUP`) and TLS certificates (`SIGUSR1`).

Related chapters: [Observability & Metrics](observability.md) for the TUI,
Prometheus, and structured logs; [JSON-RPC
Extensions](json-rpc-extensions.md) for the satd-specific developer APIs;
[API Scaling & Runtimes](api-scaling.md) for the two-runtime model and the
`--api-threads` and admission-control options. The [Configuration Flag
Reference](config-reference.md) indexes every flag with its default, its reload
disposition, and whether it is Core-compatible or a satd extension.

## Configuration & Tuning

### `--profile` Presets

The `--profile=<preset>` flag replaces manual tuning of `-dbcache`,
`-maxmempool`, and connection limits with a single choice of hardware profile:

*   `archival`: maximizes indexing and P2P serving. Disables pruning.
*   `pruned-home`: fits Raspberry Pi and home servers. Enables pruning and
    bounds memory.
*   `mining`: optimizes block template generation latency.
*   `regtest-dev`: fast, isolated environment for local development.

### Indexing & Protocol Flags

| Flag | Default | Notes |
|---|---|---|
| `--addressindex=<0\|1>` | `1` | Builds the scripthash history index over RocksDB. Required for Esplora/Electrum. |
| `--esplora=<0\|1>` | `1` | Enables the native Esplora REST API (loopback unauthenticated by default). |
| `--electrum=<0\|1>` | `0` | Enables the native Electrum protocol server. |
| `--blockfilterindex=<0\|1\|basic>` | `0` | Builds the BIP 158 compact block filter index. |
| `--peerblockfilters=<0\|1>` | `0` | Advertises `NODE_COMPACT_FILTERS` (bit 6) and serves BIP 157 P2P queries. |
| `--rpctlsbind=<addr:port>` | None | Enables native TLS for JSON-RPC; no TLS-terminating sidecar is needed. Requires `--rpctlscert` and `--rpctlskey`. |
| `--electrumtlsbind=<addr:port>`| None | Enables native TLS for the Electrum server. Requires `--electrumtlscert` and `--electrumtlskey`. |
| `--esploratlsbind=<addr:port>` | None | Enables native TLS for the Esplora REST API. Requires `--esploratlscert` and `--esploratlskey`. |
| `--v2transport=<0\|1>` | `1` | Enables BIP 324 v2 encrypted P2P transport. Offers and accepts the ElligatorSwift + ChaCha20-Poly1305 v2 handshake, and falls back to v1. |
| `--v2only=<0\|1>` | `0` | satd-specific privacy flag. If `1`, refuses or immediately disconnects any peer not using the v2 encrypted P2P transport. |
| `--dbcache=auto` | None | Spawns the adaptive dbcache resizing task, which scales the RocksDB block cache and the CoinCache clean-LRU in response to system memory pressure. |

### Mempool Policy Sovereignty

The operator decides what the node's hardware validates and relays. satd
exposes these policies as ordinary options, where filtering spam or unwanted
data with Bitcoin Core requires a patched fork such as Bitcoin Knots:

| Flag | Default | Notes |
|---|---|---|
| `--datacarrier=<0\|1>` | `1` | If set to `0`, rejects all transactions containing `OP_RETURN` outputs from entering the mempool or being relayed. |
| `--datacarriersize=<bytes>` | `83` | The maximum permitted size of an `OP_RETURN` script. Anything larger is rejected as non-standard. |
| `--dustrelayfee=<sat/kvB>` | `3000` | The threshold used to calculate dust. Raising it forces transactions that create tiny, unspendable UTXOs to pay higher fees. |
| `--permitbaremultisig=<0\|1>` | `1` | If `0`, rejects non-standard bare multisig setups, a construction often used for data storage. |
| `--limitancestorcount=<N>` | `25` | Maximum unconfirmed ancestor count. |

## Live Config Reload (`SIGHUP`)

Edit `bitcoin.conf`, then send `SIGHUP` with `kill -HUP <pid>` or `systemctl
reload satd`. satd re-reads the file and applies the hot-reloadable options
without restarting. The P2P swarm and chainstate are untouched.

CLI flags remain authoritative across reloads. Only the config file is re-read,
so a flag passed on the command line always wins over the same key in the file.

> **Difference from Bitcoin Core.** Core uses `SIGHUP` to reopen `debug.log`
> for logrotate. satd has no `debug.log`: it logs to stdout and leaves rotation
> and retention to systemd-journald or the container runtime, so `SIGHUP` is
> repurposed for config reload. See
> [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md).

A reload that fails to parse, such as a typo or an invalid value, is logged and
the running config is kept; satd never exits on a bad reload. A
recognized-but-unsupported Core option is skipped with a warning, not an error.
Every change is either applied live or logged as `restart required`; nothing is
silently ignored. Secret-bearing keys (`rpcuser`, `rpcpassword`, `rpcauth`,
`torpassword`, `esplorauserpass`, `reorgwebhooksecret`) report only that they
changed. Their values are redacted in the log, never printed.

### Hot-reloadable keys (applied live)

| Key(s) | Effect on reload |
|---|---|
| `debug`, `debugexclude` | Log verbosity and categories change immediately; the env-filter is swapped live. |
| `timeout` | New peer-handshake timeout for subsequent connections. |
| `blocksonly` | Turns transaction-relay suppression on or off. |
| `maxuploadtarget` | New rolling 24h upload cap. |
| `v2transport`, `v2only` | Adjusts BIP 324 v2 transport and v2-only peering for new connections. |
| `externalip`, `whitelist` | Replaces advertised external addresses and the `-whitelist` permission set. |
| `rpcextendederrors`, `rpcdefaultunits` | Switches the RPC error-payload shape and the default amount unit. |
| `maxconnections`, `maxinboundperip` | New limits govern subsequent connections. Existing peers above a lowered cap are not dropped. |
| `bantime` | New ban duration applies to bans created after the change. |
| `minrelaytxfee`, `maxmempool`, `dustrelayfee`, `datacarrier`, `datacarriersize`, `mempoolfullrbf`, `limitancestorcount`, `limitdescendantcount`, `mempoolexpiry`, `permitbaremultisig` | Mempool and relay policy is swapped atomically and governs subsequent transaction admissions. Already-admitted entries are not re-evaluated. |
| `connect`, `addnode`, `seednode` | Newly added peers are registered and dialed immediately; existing connections are untouched. Removing an entry does not disconnect that peer (use `disconnectnode`), matching Core's `-addnode`. The exclusivity of `-connect` (connect only to these peers, with automatic outbound and DNS seeding suppressed) is a startup-time decision and is not re-evaluated on reload. Adding `-connect` live dials the new peer but does not put a running node into connect-only mode; restart for that. |
| `peerblockfilters` | Turns `NODE_COMPACT_FILTERS` advertisement on or off for new handshakes, still gated on a complete `blockfilterindex`. |
| `addrindexsubscriptions` | New address-index subscription cap, applied to subsequent subscriptions. Lowering it does not evict existing subscribers. |
| `reorgwebhook`, `reorgwebhooksecret` | Adds, changes, or removes the reorg webhook URL and signing secret. The next reorg uses the new target. |
| `persistmempool`, `maxshutdownsecs` | No restart needed. The value is read from the reloaded config at shutdown time and governs the next shutdown, not an in-flight one. |
| `rpcuser`, `rpcpassword`, `rpcauth` | RPC credentials rotate live on every listener surface; subsequent requests are checked against the new set. The auto-generated cookie is preserved. Values are redacted in the reload log. |

> **Note.** `logformat` (json vs text) is not hot-reloadable; only verbosity
> is. Changing the format requires a restart.

> **Warning.** Removing `rpcuser`/`rpcpassword` from a node started with a
> static user/pass (that is, without a cookie) leaves no credentials at all.
> The RPC interface then rejects everything until you restore a credential or
> restart; a restart regenerates the cookie. satd logs a warning when a reload
> lands in this state. The cookie file (`rpccookiefile`/`rpccookieperms`) and
> the `rpcdisableauth` mTLS option remain restart-only.

### Restart required (reported, not applied)

The following are wired into long-lived state at startup, such as a bound
socket, an opened database, or the chain identity. They cannot be swapped
without restarting the relevant socket, engine, or process:

*   network selection
*   `datadir` and `blocksdir`
*   all RPC, P2P, Esplora, and Electrum ports and binds
*   the RPC cookie file (`rpccookiefile`/`rpccookieperms`) and `rpcdisableauth`
*   TLS/mTLS paths and the mTLS CA (the cert and key contents reload via
    `SIGUSR1`; see below)
*   `dbcache`, `prune`, `storageprofile`, and reindex
*   index enable/disable (`txindex`/`addressindex`/`blockfilterindex`)
*   DNS-seed bootstrap (`dns`/`dnsseed`/`forcednsseed`/`fixedseeds`/`asmap`)
*   Tor (`proxy`/`onion`/`torcontrol`/`listenonion`)
*   `consensus`
*   `assumevalid` and `stopatheight`

## Live TLS Certificate Reload (`SIGUSR1`)

Send `SIGUSR1` with `kill -USR1 <pid>` to reload the TLS server certificates
from their already-configured paths (`rpctlscert`/`rpctlskey`,
`esploratlscert`/`esploratlskey`, `electrumtlscert`/`electrumtlskey`) without
restarting. Every TLS surface re-reads its leaf cert and key from disk and
swaps them in atomically.

This exists for infrastructure that auto-rotates certificates on short TTLs:
cert-manager, Vault, ACME sidecars. Point a renewal hook, or a systemd `path`
unit watching the cert file, at `kill -USR1`.

- New handshakes use the new cert. In-flight connections keep theirs, so no
  connections drop and no socket rebinds.
- Only the leaf cert and key reload. Changing the cert or key paths, or
  rotating the mTLS client CA (`rpcmtlsclientca` and friends), still requires a
  restart. CAs are long-lived and do not rotate on the short TTLs this signal
  targets.
- A reload that fails, whether unreadable, malformed, or a cert/key pair that
  does not match, is logged per surface and the previous, still-valid
  certificate is kept. The listener is never left without a usable cert. Each
  surface reloads independently; one failure does not affect the others.
- Cert rotation is frequent and automation-driven, so it gets a dedicated
  signal distinct from `SIGHUP`. `SIGUSR1` does not re-read `bitcoin.conf` and
  does not run the config diff/apply machinery.

> **Difference from Bitcoin Core.** Core has no `SIGUSR1` handler and no
> native TLS; its RPC is HTTP-only behind a sidecar. satd's native TLS makes
> in-place cert reload meaningful. See
> [`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md).
