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

- **Network / chain:** `regtest`, `testnet`, `signet`, `chain`,
  `signetseednode`
- **Filesystem:** `datadir`, `blocksdir`, `conf`, `pid`, `profile`
- **Daemon / logging:** `daemon`, `server`, `logformat`, `debug`,
  `debugexclude`, `maxshutdownsecs`
- **RPC + TLS / mTLS:** `rpcport`, `rpcbind`, `rpcallowip`, `rpcuser`,
  `rpcpassword`, `rpcauth`, `rpccookiefile`, `rpccookieperms`,
  `rpcdefaultunits`, `rpcdisableauth`, `rpcextendederrors`,
  `rpctlsbind`, `rpctlscert`, `rpctlskey`, `rpctlshandshaketimeout`,
  `rpcmtls`, `rpcmtlsclientca`, `rpcmtlsclientallow`
- **P2P:** `listen`, `port`, `bind`, `connect`, `addnode`, `seednode`,
  `maxconnections`, `maxinboundperip`, `dns`, `dnsseed`, `bantime`,
  `timeout`, `onlynet`
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
  prefix (`-nolistenonion` == `-listenonion=0`). satd supports this for
  the value-accepting boolean flags this family added (`listenonion`,
  `dnsseed`, `persistmempool`). **Not yet implemented:** comprehensive
  `-no` coverage across *every* boolean option — notably the clap
  `SetTrue` flags (`-server`, `-daemon`, `-regtest`, `-reindex`, …)
  which reject a value entirely, and the older `Option<bool>` flags
  (`-listen`, `-dns`, `-txindex`, …). Extending `-no` to all booleans
  is a follow-up.

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

---

## Recognised but not yet implemented

These hard-error today. Listed with what real support would require.

| Key | Notes |
|---|---|
| `includeconf` | Recursive config inclusion. High-value; the marquee strict-parser hazard. Tracked as PR-2b. |
| `signetchallenge` | Custom signet challenge script. Tracked as PR-2b. |
| `maxuploadtarget` | Upload bandwidth cap + serving limits. Needs per-peer/global byte accounting + disconnect logic. |
| `whitelist` / `whitebind` | Peer permission flags (`NetPermissionFlags`). Needs a peer-permission model in the peer manager. |
| `blocksonly` | Suppress transaction relay. Needs a relay-suppression path in P2P. |
| `externalip` | Advertise an external address to peers. Needs local-address tracking + version-message wiring. |
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
