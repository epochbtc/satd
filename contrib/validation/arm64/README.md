# arm64 validation

Everything the repository claims about the container image, the reference
stack and the two app-store packages was checked on `x86_64`. The `arm64`
halves are built by CI and pass the same automated checks, but nothing has
ever been stood up on an `arm64` machine. That is the gap this directory
closes, and it is why the Operator Manual says the store packages are
supported on `x86_64` rather than supported outright.

Run these on an `arm64` machine — Apple Silicon or an arm64 Linux box. Not
under emulation: an emulated run proves the emulator works.

```sh
contrib/validation/arm64/preflight.sh     # is this machine able to?
contrib/validation/arm64/run-stack.sh     # leg 1
contrib/validation/arm64/pack-s9pk.sh     # leg 2
```

Evidence lands in `evidence/`, which is gitignored. Report `summary.txt` and
anything that failed.

## What each leg has to prove

**Leg 1 — the reference stack (scripted, `run-stack.sh`).** Build the image
for `linux/arm64`, prove the binaries in it are genuinely aarch64, and run
the existing `contrib/stack/tests/smoke.sh` against it twice: core, and with
the Lightning and proxy overlays. smoke.sh is the test; `run-stack.sh` only
arranges for it to run on the right image and captures the output. A pass is
all of smoke.sh's checks green in both runs — 17 core, 22 with overlays as
of this writing.

The arch check is deliberately three claims, not one. `docker image inspect`
reporting `arm64` is the weakest of them: metadata can say arm64 for an image
whose binaries are x86-64 under emulation. So the script also reads the ELF
`e_machine` field at offset 18 of `/usr/local/bin/satd`, which is `b7 00`
(`EM_AARCH64`) on a real aarch64 binary and `3e 00` (`EM_X86_64`) otherwise,
and then executes all three binaries.

**Leg 2 — the StartOS package (scripted, `pack-s9pk.sh`).** Pack
`satd_aarch64.s9pk`. `start-cli s9pk pack --arch=aarch64` resolves the image
pinned in `startos/manifest/index.ts` and embeds its layers, so the artifact
is self-contained: the server that installs it never contacts a registry. A
pass is a packed file whose manifest reports `aarch64` and a clean `gitHash`
(no `-modified` suffix).

**Leg 3 — installing that package on an aarch64 StartOS server (manual).**
The one that actually matters, and the one no script here can do for you
because it needs a StartOS VM. What has to be shown is what the `x86_64`
install showed, which is recorded in `contrib/packaging/startos/README.md`:
`satd-init` producing the CA, certificate, MCP token and config all owned by
`satd`; both health checks reporting as documented; Esplora and Electrum
answering through the OS reverse proxy with a certificate that verifies
against the server's root CA (`Verify return code: 0 (ok)`); MCP refusing an
unauthenticated call and completing an `initialize` with the token the
package's action prints; the **Network** action moving a running node between
chains; and satd coming back by itself after a reboot.

**Leg 4 — Umbrel on arm64 (manual, least certain).** umbrelOS's arm64 target
is Raspberry Pi hardware, so a VM is not the same thing as the supported
configuration. Treat a failure here as information about the environment
until you have ruled that out.

## Setting the machine up

`preflight.sh` names anything missing and how to get it. On macOS the whole
list is:

```sh
brew install coreutils openssl@3 node@22 jq
# put OpenSSL first on PATH — /usr/bin/openssl is LibreSSL, which smoke.sh
# refuses because its TLS probes need real OpenSSL
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

Docker Desktop supplies `docker` and `docker compose`. Turn **off** Rosetta
for x86_64/amd64 emulation while doing this, so a wrong-arch image fails
loudly instead of quietly working.

`preflight.sh` reports `tar2sqfs` as a warning rather than an error because
its availability on macOS is genuinely unknown from here. It is
**squashfs-tools-ng**, not the more common squashfs-tools/mksquashfs, and
`start-cli s9pk pack` shells out to it for every image layer. If Homebrew
has no formula for it, pack inside a Linux container instead — the artifact
is identical, since packing is deterministic over the image layers it pulls.

## Facts already established, so you do not have to re-derive them

Measured on 2026-09-11; re-check if something does not match.

- **Every image the stack pins resolves on `linux/arm64`.** All of them are
  pinned by digest, and a digest that named a single-platform manifest would
  simply not resolve — so this was worth checking rather than assuming:

  | image | architectures in the pinned index |
  |---|---|
  | `lightninglabs/lnd` | amd64, **arm64** |
  | `shahanafarooqui/rtl` | amd64, **arm64**, arm/v7 |
  | `caddy` | amd64, **arm64/v8**, arm/v6, arm/v7, ppc64le, riscv64, s390x |
  | `btcpayserver/btcpayserver` | amd64, arm, **arm64** |
  | `cashubtc/nutshell` | amd64, **arm64** |
  | `elementsproject/lightningd` | amd64, arm, **arm64** |
  | `ghcr.io/arkade-os/arkd`, `arkd-wallet` | amd64, **arm64** |
  | `nicolasdorier/nbxplorer` | amd64, arm, **arm64** |
  | `postgres` | 386, amd64, arm, **arm64**, ppc64le |

- **The satd image is anonymously pullable from ghcr**, and the digest the
  packages pin is a two-arch index covering `linux/arm64`. So leg 2 needs no
  registry credentials — and leg 4 can finally exercise the registry hop that
  the Umbrel package's own comment records as untested.
- **`start-cli` has an `aarch64-macos` build**, in the `start-cli/v2.0.0`
  release of `Start9Labs/start-technologies`. `pack-s9pk.sh` fetches it if it
  is not already on PATH.
- **`smoke.sh` runs on macOS.** `timeout` and `sha256sum` are GNU and macOS
  has neither; the script now resolves `gtimeout` and `shasum -a 256`, and
  refuses LibreSSL rather than emitting TLS passes that mean less than they
  read.

## Notes for leg 3, from the x86_64 install

The StartOS installer is a kiosk browser driving an Angular app, and every
step of it is a `POST /rpc/v1` with `{"method": ..., "params": ...}`. It can
be driven headlessly against that endpoint: `setup.status`,
`setup.get-pubkey`, `setup.set-language`, `setup.disk.list`,
`setup.install-os`, `setup.execute`, `setup.complete`, and
`setup.logs.follow`, which returns a guid for `ws://<host>/ws/rpc/<guid>`.

Two things cost time on `x86_64` and will cost it again:

- **The language code is a full locale.** `setup.set-language` accepts
  `{"language": "en"}` without complaint and then `setup.execute` fails
  minutes later, deep in `start_core::setup::execute_inner`, with
  `/usr/lib/locale/locale-archive: No such file or directory`. Send `en_US`.
- **The password is JWE, not plaintext.** Fetch the EC P-256 JWK with
  `setup.get-pubkey` and send `{"encrypted": <compact JWE>}`; node-jose's
  defaults (ECDH-ES, A128CBC-HS256, general JSON serialization) are what the
  wizard uses.

`start-cli auth login` reads the password from a terminal, so a pipe or a
heredoc fails with `No such device or address (os error 6)`. Drive it from a
pty.

Also: the SDK's own `s9pk.mk` uses `stat -c %Y` in its `publish` target,
which is GNU-only and will fail on macOS. Nothing here calls `publish`.

## Reporting back

Keep it to what was observed. This repository is public, so describe the
machine only as "an arm64 machine" — no hostnames, addresses, or hardware.
Evidence is the point; provenance is not.

For each leg: whether it passed, the failing output verbatim if it did not,
and — if it failed — whether the cause looks like the architecture or like
the environment. Those are very different findings, and only the first one
changes what the manual is allowed to say.
