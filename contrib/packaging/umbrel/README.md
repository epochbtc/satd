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

`umbrel/` is complete and ready to publish to a community app store.

`startos/` is **not written yet.** A StartOS package is a TypeScript project
built with Start9's SDK, and the SDK's shape has changed across StartOS
versions; writing one against a guessed API would produce something that
looks right and does not build. What it needs is: pick the StartOS version
to target, install that SDK, and copy the structure of
`start9labs/bitcoind-startos` at the matching tag. The interfaces to declare
are RPC (plain, app-internal), RPC-TLS, Electrum-TLS, Esplora-TLS and MCP;
the health check maps to `/readyz` and sync progress to
`getblockchaininfo`. Network is a config option; `txindex` is not — it stays
forced on, because Electrum and Esplora require it.

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

Copy `umbrel/` to that repository's root. Before submitting upstream to
`getumbrel/umbrel-apps`, re-check two things against the current store:

- the `manifestVersion` and the field set in `umbrel-app.yml`, which have
  changed between store generations;
- whether apps can now declare satd as an alternative to the `bitcoin`
  dependency — the mechanism added so Bitcoin Knots could satisfy it. If
  they can, `exports.sh` should export the same variable names the official
  `bitcoin` app does, so a dependent app is satisfied by either. If they
  cannot, satd runs standalone and dependent apps keep using Core.
