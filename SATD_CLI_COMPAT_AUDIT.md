# satd ↔ Bitcoin Core CLI / config compatibility audit

The parity roadmap for satd's command-line flags and `bitcoin.conf` /
`satd.conf` config keys. satd's config parser is **strict**: like Bitcoin
Core (since the v0.17 args overhaul), an unrecognized option is a fatal
error rather than a silent no-op. That makes this document load-bearing —
a Core key that satd doesn't recognize will stop a migrated config from
booting, so the parser distinguishes three dispositions, enforced in
`satd/src/config.rs`:

1. **Implemented** — in `KNOWN_CONFIG_KEYS`; parsed and honoured.
2. **Recognised, not yet implemented** — in `NOT_YET_IMPLEMENTED_KEYS`;
   hard-errors with a message telling the operator to remove the line
   *for now* (support is tracked here). Silently accepting these is the
   exact hazard the strict parser exists to prevent: e.g. ignoring
   `includeconf` would make a config look valid while every setting in
   the included file vanished.
3. **Recognised, intentionally excluded** — in
   `INTENTIONALLY_EXCLUDED_KEYS`; hard-errors with a message telling the
   operator to remove the line *permanently*. See `CORE_DIFFERENCES.md`
   "Intentional exclusions".

When a not-yet-implemented key gains real support it moves into
`KNOWN_CONFIG_KEYS`; update this document in the same change.

---

## Implemented

The authoritative list is `KNOWN_CONFIG_KEYS` in `satd/src/config.rs`;
single-dash Core spellings are aliased by `normalize_args`. Grouped:

- **Network / chain:** `regtest`, `testnet`, `testnet4`, `signet`,
  `chain`, `signetseednode`, `signetchallenge`
- **Filesystem:** `datadir`, `blocksdir`, `conf`, `includeconf`, `pid`,
  `profile`
- **Daemon / logging:** `daemon`, `server`, `logformat`, `debug`,
  `debugexclude`, `maxshutdownsecs`
- **RPC + TLS / mTLS:** `rpcport`, `rpcbind`, `rpcallowip`, `rpcuser`,
  `rpcpassword`, `rpcauth`, `rpccookiefile`, `rpccookieperms`,
  `rpcdefaultunits`, `rpcdisableauth`, `rpcextendederrors`,
  `rpctlsbind`, `rpctlscert`, `rpctlskey`, `rpctlshandshaketimeout`,
  `rpcmtls`, `rpcmtlsclientca`, `rpcmtlsclientallow`
- **P2P:** `listen`, `blocksonly`, `externalip`, `port`, `bind`,
  `connect`, `addnode`, `seednode`, `maxconnections`, `maxinboundperip`,
  `dns`, `dnsseed`, `bantime`, `timeout`, `onlynet`
- **Proxy / Tor:** `proxy`, `onion`, `torcontrol`, `torpassword`,
  `listenonion`
- **Consensus:** `assumevalid`, `assumevalidage`, `stopatheight`,
  `consensus`
- **Indexing:** `txindex`, `addressindex`, `addrindexsubscriptions`,
  `blockfilterindex`, `peerblockfilters`
- **Mempool / relay:** `mempoolfullrbf`, `maxmempool`, `minrelaytxfee`,
  `dustrelayfee`, `datacarrier`, `datacarriersize`, `limitancestorcount`,
  `limitdescendantcount`, `mempoolexpiry`, `persistmempool`,
  `permitbaremultisig`
- **Native protocol surfaces:** the `esplora*` and `electrum*` families
  (see `OPERATOR_ERGONOMICS.md`)
- **Storage / pruning / reindex / mining / events / webhooks / MCP /
  metrics:** see `KNOWN_CONFIG_KEYS` for the full enumeration.

### CLI form compatibility

- **Bare boolean flags.** Core-style bare invocations (`-listenonion`,
  `-dnsseed`, `-persistmempool`) are accepted as "true" (clap
  `default_missing_value`), as are valued forms (`-listenonion=0`).
  Bare `-debug` means "all categories".
- **`-no` negation.** Bitcoin Core negates a boolean with a `-no`
  prefix (`-nolistenonion` == `-listenonion=0`, `-noserver` ==
  `-server=0`). satd implements this comprehensively: **every** boolean
  CLI flag is value-accepting (`--flag`, `--flag=0/1`,
  `--flag=true/false`) and negatable with `-no` / `--no`. This includes
  the former network selectors and `SetTrue`-style flags (`-noregtest`,
  `-noserver`, `-nodaemon`, `-noreindex`, `-notxindex`, …) and the
  `Option<bool>` flags (`-nolisten`, `-nodns`, …). The single exception
  is `blockfilterindex`, which is not a plain bool (it accepts `basic`);
  its `-no` form is handled via the `-noindex=blockfilter` alias instead.

### Notable semantics

- **`listenonion`** — Bitcoin Core defaults this on (but it is a silent
  no-op without a reachable Tor control port). satd defaults it **off**
  to avoid dialing the control port on every boot, with one backward-
  compat carve-out: an explicitly-set `-torcontrol` implies
  `-listenonion=1` (satd's original trigger), and `-listenonion=0`
  forces it off. The control-port address is `-torcontrol`, defaulting
  to Core's `127.0.0.1:9051`. See `CORE_DIFFERENCES.md`.
- **`dnsseed`** — satd gates DNS seeding on *both* `-dns` and `-dnsseed`,
  so either set to `0` disables it.
- **`seednode`** — connected at startup to bootstrap peer discovery on
  all networks. Accepts `host[:port]` (default P2P port when omitted),
  literal IPv4/`[IPv6]`, and `.onion` — resolved through the shared
  operator-seed resolver (clearnet hostnames are skipped under proxy
  mode to avoid a DNS leak). Core disconnects after pulling addresses;
  satd currently keeps the connection (a harmless superset for
  bootstrap).
- **`debug` / `debugexclude`** — Core categories are mapped onto satd's
  `tracing` subsystems (`net`, `mempool`, `rpc`, `validation`, `tor`,
  storage); `1` / `all` enable debug everywhere. Categories with no satd
  equivalent (e.g. `qt`, `zmq`, `walletdb`) are accepted but produce no
  output. An explicit `RUST_LOG` takes precedence as the base filter.
- **`persistmempool`** — default on (Core-compatible). satd uses its own
  `mempool.dat` format (Core's datadir is not byte-compatible; see
  `CORE_DIFFERENCES.md`); the file is re-validated against the current
  chainstate on load, never trusted blindly.
- **`externalip`** — Bitcoin Core's `-externalip=<ip[:port]>`,
  repeatable. Declares external addresses the node advertises to peers
  (prepended to `getaddr` responses, and used as the version message's
  `addr_from`). satd accepts literal `IP` / `IP:port` only (a bare IP
  inherits the network's default P2P port); hostnames/.onion are not
  resolved here.
- **`blocksonly`** — Bitcoin Core's `-blocksonly`. When set, the node
  advertises `relay=false` in its version message, ignores inbound `tx`
  messages from peers, and does not request advertised transactions.
  Transactions submitted locally via RPC still enter the mempool and are
  relayed. (Per-peer relay-permission exceptions arrive with
  `whitelist`/`whitebind`.)
- **`testnet4`** — full network wiring for Bitcoin's testnet4. Selectable
  via `-testnet4` or `--chain=testnet4`; magic `0x1c163f28`, P2P/RPC ports
  48333/48332, datadir subdir + `[testnet4]` config section, and DNS
  seeds. Difficulty follows testnet3's algorithm (20-minute
  min-difficulty + standard retarget) plus the **BIP 94** timewarp guard:
  the first block of each retarget period may not be timestamped more
  than 600 s before its parent.
- **`signetchallenge`** — selects a custom/private signet (BIP 325).
  Hex-encoded challenge script; signet only (hard-errors on other
  networks). When set, satd derives the P2P network magic from the
  challenge (`SHA256d` of the length-prefixed bytes, first 4 — verified
  against the default-signet magic in tests) and validates each block's
  signet solution against the challenge. **Opt-in:** the default signet
  (no `-signetchallenge`) is not solution-checked today, so this flag
  only adds validation for the custom signet it configures — bounding
  consensus risk to nodes explicitly running a custom signet. Wiring
  default-signet solution validation is a follow-up. The signet genesis
  is identical across signets, so it is not overridden.
- **`includeconf`** — pulls in an additional config file (resolved
  relative to `--datadir`, absolute paths used as-is). Matching Core,
  the **entire main file is read first**, then included files are
  appended (Core does *not* splice at the directive's position).
  Single-valued keys resolve **first-wins** — Core's `reverse_precedence`
  for config-file settings — so a key set in both the main file and an
  included file takes the **main file's** value, regardless of where the
  `includeconf=` line sits; repeatable keys add in main-then-included
  order. The common case (an included file holding keys the main file
  never sets, e.g. `rpcpassword`) takes effect unopposed. Processed for
  the global scope plus the active network's section. Like Core: an
  `includeconf` *inside* an included file is ignored with a warning
  (recursion guard), and a command-line `-includeconf` is **rejected with
  an error** (config-file-only feature — matches Core's "cannot be used
  from commandline"). A `chain=` inside an included file does not change
  the active network — the network is resolved from the main file + CLI
  before includes run (and `chain=` itself stays last-wins, Core's
  documented chain-type exception to first-wins).

---

## Recognised but not yet implemented

These hard-error today. Listed with what real support would require.

| Key | Notes |
|---|---|
| `maxuploadtarget` | Upload bandwidth cap + serving limits. Needs per-peer/global byte accounting + disconnect logic. |
| `whitelist` / `whitebind` | Peer permission flags (`NetPermissionFlags`). Needs a peer-permission model in the peer manager. |
| `asmap` | ASN-based addrman bucketing (eclipse resistance). Needs an ASN map loader + addrman bucketing. |
| `forcednsseed` | Force DNS seeding even when addrman is full. satd has no persistent addrman and seeds at every start, so this has no distinct effect yet. |
| `fixedseeds` | Fall back to the compiled-in fixed-IP seed list. satd has no fixed-IP seed list (only DNS + `.onion` seeds), so nothing to gate yet. |

---

## Recognised but intentionally excluded

These hard-error with a "remove permanently" message. See
`CORE_DIFFERENCES.md` "Intentional exclusions" for the rationale.

| Key | Reason |
|---|---|
| `upnp` | UPnP port mapping — deprecated in Bitcoin Core. |
| `natpmp` | NAT-PMP port mapping — deprecated in Bitcoin Core. |
| `i2psam` | I2P SAM proxy — Tor is satd's supported anonymity network. |
| `i2pacceptincoming` | I2P inbound — out of scope (see `i2psam`). |

Wallet keys (`wallet`, `walletdir`, `dumpprivkey`, the `import*` family,
…) are not recognized at all: satd has no wallet by charter, so they
fall through to the generic "unrecognized key" error rather than either
unsupported list.
