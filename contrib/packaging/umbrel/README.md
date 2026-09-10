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

- `umbrel/` — `umbrel lint` (from `npm i -g umbrel-cli`) validates the store
  manifest, each app manifest, the compose file and `exports.sh`. It is what
  caught the missing image digest pin, which the Umbrel app store requires.
- `startos/` — typechecks against the SDK, tests its network table against
  `satd-init`, guards the two defects the install found, and packs to a
  `.s9pk`. See `startos/README.md` for what running it on a server showed.

Neither validator understands satd's own flags, so the checks that cover
those live in `contrib/stack/tests/compose-test.sh`.

## Publishing the Umbrel app

Umbrel installs community stores from a git repository whose root holds
`umbrel-app-store.yml` and one directory per app:

```
epochbtc/umbrel-apps/
  umbrel-app-store.yml
  satd/
    umbrel-app.yml
    docker-compose.yml
    exports.sh
```

Copy `umbrel/` to that repository's root.

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
