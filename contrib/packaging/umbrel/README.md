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

Both packages are written. **Neither has been installed on a real Umbrel or
StartOS instance**, which is the gap that matters: everything below is
statically checked, and static checks did not stop this Umbrel package from
shipping a `--mainnet` flag satd does not have or an image tag the registry
has never held.

What is checked:

- `umbrel/` — `umbrel lint` (from `npm i -g umbrel-cli`) validates the store
  manifest, each app manifest, the compose file and `exports.sh`. It is what
  caught the missing image digest pin, which the Umbrel app store requires.
- `startos/` — typechecks against the SDK, tests its network table against
  `satd-init`, and packs to a `.s9pk`. See `startos/README.md`.

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
