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

Copy `umbrel/` to that repository's root. Before submitting upstream to
`getumbrel/umbrel-apps`, re-check two things against the current store:

- the `manifestVersion` and the field set in `umbrel-app.yml`, which have
  changed between store generations;
- whether apps can now declare satd as an alternative to the `bitcoin`
  dependency — the mechanism added so Bitcoin Knots could satisfy it. If
  they can, `exports.sh` should export the same variable names the official
  `bitcoin` app does, so a dependent app is satisfied by either. If they
  cannot, satd runs standalone and dependent apps keep using Core.
