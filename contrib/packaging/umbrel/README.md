# App-store packages

Sources for the Umbrel and StartOS packages. They live here so they are
reviewed and versioned with satd; each is published from its own repository,
because that is how both stores consume packages.

**These packages contain satd and nothing else** — the daemon, `sat-cli`,
`sat-tui` and the MCP server. No Lightning, no BTCPay, no wallets. Users of
those platforms compose the rest from their own app stores, and a package
that bundled a second copy of software the store already offers would be
worse than useless. The best-effort support notice that applies to the
appliance image therefore does not apply here: there is no third-party
software to disclaim.

Both derive their satd service from `contrib/stack/compose.yml`, and both
run the same `satd-init` and `mkca.sh` that the reference stack does — they
are baked into the container image for exactly this reason. A package that
re-implemented first-run behaviour would drift from the stack within a
release.

## Status

Both packages have now been installed and run on a real server: the Umbrel
package on umbrelOS 1.7.4, the StartOS package on StartOS 0.4.0.1. Neither
had been, and installing them is what found almost everything below.

Six of the nine defects in the Umbrel package were invisible to every static
check — `umbrel lint` passes clean both before and after each of them:

- The app id must be prefixed with the store id, or the store adds
  successfully, reports no error, and lists zero apps.
- `exports.sh` is sourced under `set -euo pipefail` with `EXPORTS_APP_DIR`
  defined and `APP_DATA_DIR` not yet defined; naming the wrong one aborts the
  install.
- No published image contained `satd-init`, because this branch adds it.
- Umbrel bind-mounts the data directory, and Docker creates the host side of a
  bind mount root-owned, so an unprivileged init service cannot write to it.
- `app_proxy` dials its upstream as `http://` with no TLS option, so pointing
  it at a TLS listener 502s every request.
- The health check probed `/readyz`, which is 503 until the node is within six
  blocks of its headers tip. The container reported `Up 2 hours (unhealthy)`
  with a failing streak of 254 while serving RPC, Electrum, Esplora and MCP
  normally, and would have done so for the whole multi-day initial sync. It
  read healthy on the first check only because the node was minutes old and
  its header chain had not yet outrun its blocks — a window narrow enough to
  pass a spot check and nothing else.

What is checked statically:

- `umbrel/` — two linters, and neither replaces the other.
  `umbrel lint` (from `npm i -g umbrel-cli`) validates the store manifest,
  each app manifest, the compose file and `exports.sh`; it is what caught the
  missing image digest pin. The store's own linter, in a clone of
  `getumbrel/umbrel-apps`, is the one that knows every other app: copy
  `epochbtc-satd/` into the clone and run
  `npm run lint:apps -- epochbtc-satd --check-images`. It is what checks host
  ports against the whole store. `umbrel lint` passed while this package took
  three ports other apps own.
- `startos/` — typechecks against the SDK, tests its network table against
  `satd-init`, guards the two defects the install found, and packs to a
  `.s9pk`. See `startos/README.md` for what running it on a server showed.

Neither validator understands satd's own flags, so the checks that cover
those live in `contrib/stack/tests/compose-test.sh`.

## Host ports

Umbrel has one host port space for every app on the device: an app's manifest
`port` and every port any app publishes share it. This package used to take
3001, 8333 and 50002, which belong to Ride The Lightning, Bitcoin Node and
Fulcrum, so it could not be installed beside the three apps a satd user is
most likely to run. It now has its own block, clear of every app in the store:

| Port | Surface | Was |
|---|---|---|
| 8430 | the status page, via `app_proxy` | 3001 |
| 8431 | Esplora, TLS | — |
| 8433 | Bitcoin P2P | 8333 |
| 8436 | JSON-RPC, TLS | 8336 |
| 50012 | Electrum, TLS | 50002 |
| 8439 | MCP, TLS | 8339 |

The app opens onto satd's status page, which `app_proxy` fronts behind
Umbrel's login. Esplora is published on its own port instead, since
`app_proxy` fronts one upstream. The page's connection strings come from
`SATD_STATUS_ADVERTISE`, built from the device's name and these ports.

Each is mapped 1:1, and satd listens on the same number. P2P cannot be
remapped any other way: satd advertises the port it listens on, so
`8433:8333` would send every peer that learned this node's address to Bitcoin
Node instead. The listener flags on the server's command line override the
ports satd-init renders, which keeps satd-init shared with the stack.
`contrib/stack/tests/compose-test.sh` checks the mappings, the flags and the
known collisions.

## Backups

`backupIgnore` leaves out the chain, the chainstate (with the indices inside
it), the AssumeUTXO background chainstate, `mempool.dat` and the cookie, at the
datadir root for mainnet and in each network's subdirectory. The certificate
authority, the MCP token, `authfile.toml` and `bitcoin.conf` stay in. The set
matches the StartOS package's exclusions, and `compose-test.sh` checks that it
still does.

## Publishing the Umbrel app

Umbrel installs community stores from a git repository whose root holds
`umbrel-app-store.yml` and one directory per app, named for the app id:

```
epochbtc/umbrel-apps/
  README.md               # from STORE_README.md
  umbrel-app-store.yml
  epochbtc-satd/
    umbrel-app.yml
    docker-compose.yml
    exports.sh
    data/.gitkeep
```

The app id carries the store id as a prefix, and both are permanent once
anyone installs: Umbrel names the app's data directory and containers after
them. The store's display name is `satd`.

For each release:

1. Bump the image tag and digest in `docker-compose.yml`, `version` and
   `releaseNotes` in `umbrel-app.yml`, and the `icon` URL's tag.
2. Run both linters, above.
3. Copy it into a clean clone of `epochbtc/umbrel-apps`:

   ```sh
   contrib/packaging/sync-store.sh umbrel ../umbrel-apps
   ```

   It refuses an image that is not a release, or whose tag does not match
   `version`, and it never commits or pushes. Review the diff there, then
   commit and push.

## `implements: bitcoin`

Both questions this section used to leave open have been checked against the
current store.

**`manifestVersion` is `1.1`.** Every app in `getumbrel/umbrel-apps` uses it,
including `bitcoin` and `bitcoin-knots`. This package was on `1`.

**satd must not declare `implements: bitcoin`.** The mechanism does exist —
it is a top-level `implements:` array in the manifest, `bitcoin-knots`
declares `implements: [bitcoin]`, and a dependent like `electrs` declares
`dependencies: [bitcoin]` and is satisfied by either. The contract is
`exports.sh`: Knots ends with a loop aliasing every `APP_BITCOIN_KNOTS_<VAR>`
to `APP_BITCOIN_<VAR>`, and that variable set is what a substitute owes its
dependents.

satd cannot honour it. Two of those exports it can — it accepts Core-format
`rpcauth`, so `RPC_USER`/`RPC_PASS` are reachable — but
`ZMQ_RAWBLOCK_PORT` and `ZMQ_RAWTX_PORT` name topics satd does not publish.
It serves Core-compatible `hashblock`/`hashtx` and its own JSON topics, which
is exactly why the reference stack runs LND in Neutrino mode rather than
bitcoind mode. There is no way to declare "implements `bitcoin`, except the
raw topics": a dependent that needs them would install cleanly against satd
and then fail at runtime, and the ones that do not need them would work.
Shipping that is worse than not offering the substitution at all.

Revisit this if satd grows raw block and transaction ZMQ topics. Until then
satd runs standalone and dependent apps keep using Core.
