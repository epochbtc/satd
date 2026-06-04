# Security Policy

## Reporting a vulnerability

Email `ben@keroack.com` with a description of the issue, ideally with
a proof of concept and your suggested remediation. We acknowledge
receipt within three business days. **Do not** open public GitHub
issues for security reports.

If the report concerns a *consensus-affecting* bug — anything that
could cause a node to accept an invalid block or reject a valid one —
treat it as P0 and expect a same-day acknowledgement.

## Supported versions

satd is pre-1.0; only the latest release line receives security
fixes. Operators tracking master should expect to upgrade promptly
when a fix lands.

## Verifying a release

satd releases are signed across three independent surfaces:

| Surface | Mechanism | Custody |
|---|---|---|
| Tarballs (`.tar.zst`) | minisign Ed25519 | Offline maintainer keys; passphrases in 1Password gated by YubiKey |
| Container image | cosign keyless OIDC (Sigstore) | None — short-lived cert from GitHub Actions OIDC, attested to Rekor |
| Git tags | SSH-key signatures | Maintainer's GitHub-published SSH keys |

Independent surfaces matter: a compromise of one mechanism (Sigstore
outage, leaked minisign passphrase, GitHub account takeover) does
not silently weaken verification on the others.

### Maintainers

| Name | GitHub | Email |
|---|---|---|
| Ben Keroack | [@bkeroack](https://github.com/bkeroack) | `ben@keroack.com` |

## 1. Tarballs — minisign

Each tarball published to a GitHub Release is accompanied by a
detached `.minisig` signature. Two minisign pubkeys are trusted;
either may sign a release. Both are reproduced here verbatim and
should match what 1Password / hardware-backed channels deliver to
maintainers — flag any mismatch.

**Primary pubkey:**

```
untrusted comment: minisign public key 870F28CC1CA33F1E
RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3
```

**Cold-spare pubkey** (used only if the primary key is rotated or
a release is cut from the spare-only environment):

```
untrusted comment: minisign public key 833443BBE004F979
RWR5+QTgu0M0g9bY5n6cKW9yFWM0Ac49p7Zk+bHVJgA39anA6q4q0mn/
```

### Verify

```sh
# Download tarball + signature
gh release download v0.1.0 --pattern 'satd-*-x86_64-unknown-linux-gnu.tar.zst*'

# Verify against the primary pubkey
minisign -Vm satd-0.1.0-x86_64-unknown-linux-gnu.tar.zst \
  -P 'RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3'
```

If the primary check fails, retry with the cold-spare pubkey before
treating the artifact as compromised:

```sh
minisign -Vm satd-0.1.0-x86_64-unknown-linux-gnu.tar.zst \
  -P 'RWR5+QTgu0M0g9bY5n6cKW9yFWM0Ac49p7Zk+bHVJgA39anA6q4q0mn/'
```

The `SHA256SUMS` file in the release lists the canonical hash of
every tarball; `sha256sum -c SHA256SUMS` is the right "did the file
arrive intact" check before going to minisign.

## 2. Container image — cosign

The multi-arch image at `ghcr.io/epochbtc/satd` is signed in CI by
keyless cosign via GitHub Actions OIDC. There is no long-lived
signing key — every signature is bound to a specific workflow run
and identity, and the attestation is logged to the Rekor
transparency log.

### Verify

```sh
cosign verify ghcr.io/epochbtc/satd:0.1.0 \
  --certificate-identity-regexp \
    'https://github.com/epochbtc/satd/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`cosign verify` returns a JSON-formatted certificate set on success
and exits non-zero on failure. The identity regex pins verification
to:

- The exact workflow file (`.github/workflows/release.yml`)
- A `refs/tags/v…` ref (manual `workflow_dispatch` runs on master
  do not produce signed images by design)

## 3. Git tags — SSH signatures

Annotated tags are signed with the maintainer's SSH key. The
authoritative pubkey set is whatever GitHub publishes for the
maintainer at the time of verification:

```
https://github.com/bkeroack.keys
```

Pinning a static keys file in this repo would go stale across
machine rotation; delegating to GitHub's `.keys` endpoint keeps
verification working as keys come and go without repo edits.

### Verify

The repo ships a wrapper that fetches the live key set and runs
`git verify-tag` against it:

```sh
contrib/release/verify-tag.sh v0.1.0
```

For operators who prefer to do it by hand:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/bkeroack.keys \
  | awk '{ print "ben@keroack.com namespaces=\"git\" " $0 }' \
  > /tmp/satd-allowed-signers

git -c gpg.ssh.allowedSignersFile=/tmp/satd-allowed-signers \
    verify-tag v0.1.0
```

Verification succeeds if the tag's signature matches *any* of the
SSH keys currently on `bkeroack.keys`. To pin a snapshot for offline
verification, save the output of the `awk` command and reference it
via `gpg.ssh.allowedSignersFile`.

## Key rotation

### Minisign

- The cold-spare pubkey (`833443BBE004F979`) is the recovery path.
  If the primary key file is lost or its passphrase is unrecoverable,
  releases continue under the spare key and a new primary is
  generated and published in this file.
- Pubkey rotation requires a signed commit modifying this file by
  whichever maintainer key is still valid at rotation time.

### SSH (git tags)

- Per-machine. Generate a new key on the new machine, add it to your
  GitHub account, remove the old key. Verifiers fetching
  `bkeroack.keys` automatically pick up the change. No repo edit is
  required for operator key rotation.
- Old tags signed with retired keys remain verifiable as long as the
  retired pubkey stays on the GitHub account. To preserve historical
  verifiability across hard key removal, snapshot the keys file and
  attach it to the corresponding GitHub Release.

### Cosign

- No keys to rotate. The identity binding is intrinsically per-run.

## Software Bill of Materials

Each release ships CycloneDX 1.5 JSON SBOMs for every shipped binary
(`satd-v<version>.cdx.json`, `sat-cli-v<version>.cdx.json`). The SBOMs
are signed with the same minisign primary key as the tarballs and
verify with the same recipe — see
[`docs/manual/src/packaging.md`](docs/manual/src/packaging.md) §"Software Bill of Materials".

Supply-chain enforcement runs as a `cargo-deny` gate against the
RustSec advisory database. The policy is in `deny.toml` at the repo
root; it runs on every dep-graph-touching PR and as a hard
precondition for every release artifact (tag-time enforcement) — see
`docs/manual/src/packaging.md` §"Supply-chain policy".

## Threat model — what these signatures do and don't prove

**They prove:**
- The artifact came out of a workflow run authored by the configured
  maintainer (cosign).
- The maintainer's offline key signed this exact tarball (minisign).
- The tag was created by someone holding a current SSH key on the
  maintainer's GitHub account (SSH).

**They do not prove:**
- That the published tarball binary matches a third-party rebuild
  of the same source. The `Nix` workflow gives independent
  verification on the `nix build` path (two-runner byte-identical
  check, see `docs/manual/src/packaging.md` §"Reproducible build via Nix" and
  `contrib/repro/diff-build.sh` for offline reproduction). Aligning
  the rustup-stable tarball binary against the Nix output bit-for-bit
  is a v1.x follow-up.
- That the source tree at the tag has been independently reviewed.
- That the maintainer's machine wasn't compromised at signing time.
  Hardware-token-backed signing (FIDO2-resident SSH for tags;
  passphrase + YubiKey 2FA on 1Password for the minisign passphrase)
  raises that bar but does not eliminate it.

For high-assurance deployments, combine the signature checks above
with the reproducible-build verification described in
[`docs/manual/src/packaging.md`](docs/manual/src/packaging.md) §"Reproducible build via Nix".
