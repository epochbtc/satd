# StartOS package

A StartOS package for satd, built with Start9's TypeScript SDK. It is
published from its own repository (`epochbtc/satd-startos`) — Start9's
registry expects one repository per package — and lives here so it is
reviewed and versioned with satd.

**Contents: satd only** — the daemon, `sat-cli`, `sat-tui` and the MCP server.
No Lightning, no BTCPay, no wallets: StartOS users compose those from their
own marketplace, and a package that bundled a second copy of software the
store already offers would be worse than useless.

**Image:** `ghcr.io/epochbtc/satd`, unmodified. It already carries `satd-init`
and `mkca.sh`, so this package's first run is the same one the reference stack
and the appliance perform and cannot drift from them.

## Who terminates TLS

satd serves TLS itself on 8336 / 50002 / 3001, from a CA it generates per
install. That is the right answer for the reference stack and the appliance,
where nothing else can issue a certificate. It is the wrong answer here.

StartOS already terminates TLS at its reverse proxy, with a certificate
chaining to the server's root CA — the one the user's browser trusts on that
box. Exporting satd's own listeners would ask every user to import a second
certificate authority for a single service.

So this package binds satd's **plain** listeners and lets the OS wrap them.
satd's TLS listeners still run, unexported, which leaves them on `lo` and
`lxcbr0` and off the LAN. satd-init is used unmodified.

MCP is the exception: satd refuses to start with MCP bound off-loopback unless
TLS and auth are both configured, so that listener speaks TLS from satd's own
certificate. The OS re-wraps it — terminating the client's connection with the
server's certificate and opening a fresh one inward — with
`upstreamCertValidation: 'disable'`, because the inward leg presents a
certificate from satd's per-install CA that the OS has no way to be taught.

This is a deliberate departure from the interface table this file used to
carry, which specified satd's own TLS ports. That table was written without
reference to how StartOS handles TLS.

## Building

Requires Node 22+, Docker, `jq`, and:

- **`start-cli` 2.0+** — from
  [`Start9Labs/start-technologies` releases](https://github.com/Start9Labs/start-technologies/releases)
  (`start-cli_x86_64-linux`). Note that `Start9Labs/shared-workflows` is the
  *legacy* build line and pins start-cli `v0.4.0-beta.9`; the SDK 2.0 line
  this package targets uses `start-technologies` instead.
- **`squashfs-tools-ng`** — `pack` shells out to `tar2sqfs` to turn each image
  layer set into the squashfs the `.s9pk` carries.
- **A packaging workspace in the parent directory.** `start-cli` looks for a
  `.startos/` marker in the directory *containing* the package repo, so
  `contrib/packaging/.startos/` has to exist. Create it with
  `cd contrib/packaging && start-cli s9pk init-workspace` — note that also
  clones the whole `start-technologies` monorepo beside it, which is not
  wanted here; only `.startos/` is required, and it is gitignored because it
  holds a per-machine signing key.

Then:

```sh
make            # typecheck, test, lint, bundle, and pack every arch
make x86        # just x86_64
make install    # sideload to the server in ~/.startos/config.yaml
```

`make` runs `tsc --noEmit`, the tests, the SDK's lint pass and `ncc` before it
packs, so a type error or a failing test stops the build.

The SDK ships the entire build as `s9pk.mk`; the `Makefile` here is one
`include` line.

`make` itself cannot run in CI — packing wants `start-cli`, `tar2sqfs` and a
signing workspace, and `make install` wants a server. The parts that can are
gated by the **app-store packages** job in `.github/workflows/appliance.yml`:
`npm ci`, `tsc --noEmit`, the tests, and the `ncc` bundle, on any PR touching
this directory.

### The lockfile advisories

`npm audit` reports high-severity DoS advisories against `brace-expansion`
and `js-yaml`, and they cannot be fixed here. `@start9labs/start-sdk`
declares `bundleDependencies: [@start9labs/start-core, eslint,
typescript-eslint]`, which makes 127 of the 158 entries in
`package-lock.json` `inBundle: true` — files inside the SDK's tarball rather
than edges npm resolves. `overrides` regenerates the lockfile and leaves
those versions exactly as they were, and 2.0.9 is the newest SDK published.

They are also not reachable. eslint and typescript-eslint are the SDK's own
linting toolchain; nothing in `package.json`'s scripts invokes either, and
the bundle the `.s9pk` actually ships (`javascript/index.js`) contains no
`js-yaml` or `brace-expansion` code at all — its only matches for `eslint`
are `// eslint-disable-next-line` comments in vendored source.

`.github/dependabot.yml` records this and scopes an `ignore` to those two
package names, so an advisory against something this package really does
resolve still surfaces.

## Status

Installed and run on **StartOS 0.4.0.1** (x86_64), sideloaded with
`start-cli package install -s`. What that proved:

- satd-init runs unmodified from the image and produces this install's CA,
  certificate, MCP token, `authfile.toml` and `bitcoin.conf`, all owned by
  `satd` with the right modes.
- The node syncs, and both health checks report as documented — **Node**
  "satd is ready", **Blockchain Sync** "Syncing blocks: …%".
- Every exported interface answers through StartOS's reverse proxy with a
  certificate chaining to the server's root CA: Esplora
  `GET /api/blocks/tip/height` → 200, Electrum `server.version` →
  `satd-electrs-compatible`, both verifying against that CA with
  `Verify return code: 0 (ok)`. MCP is 401 without a token and returns a
  full `initialize` result with the token the **MCP Token** action prints.
- The **Network** action moves a running node between chains, re-rendering
  the config and rebinding the P2P port each time.

Three defects came out of it, none of them visible to a typecheck: the ready
gate probed `/readyz` and so never went green during a sync; the **Network**
action wrote the store without restarting the node; and the manifest pinned
an image tag that predates `satd-init`, so the package as first written could
not have started at all.

`bridgeSubnet` is now checked rather than assumed — the `rpcallowip` range it
feeds is what admits the OS proxy on the real bridge, and the RPC interface
answers.

Also checked, now on every PR that touches this directory: the package
typechecks against `@start9labs/start-sdk` 2.0.9, `test/networks.test.ts`
verifies the network list and every P2P port against
`contrib/stack/satd/satd-init` itself so the two cannot drift, and
`test/reactivity.test.ts` guards the two defects above that a typecheck
cannot see.

Still unverified: `aarch64` — only the x86_64 `.s9pk` has been installed —
and backup/restore.

## Before publishing

1. Bump the image tag in `startos/manifest/index.ts` and the version in
   `startos/versions/current.ts` to the release being published.
2. Install it on a StartOS box and confirm every interface answers.
3. Push to `epochbtc/satd-startos` and call
   `Start9Labs/start-technologies/.github/workflows/build.yml@master` from its
   CI, which builds the `.s9pk` with no secrets (it generates a temporary
   signing key when `DEV_KEY` is absent).
