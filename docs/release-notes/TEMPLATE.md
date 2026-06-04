# satd <VERSION>

> Released YYYY-MM-DD · git tag [`v<VERSION>`](https://github.com/epochbtc/satd/releases/tag/v<VERSION>) · [Changelog](../../CHANGELOG.md)
>
> _(While in development, name the file `<VERSION>-pre.md` and replace the date
> with "Pre-release — in progress"; drop the `-pre` suffix and fill in the date
> + tag link when the release is cut.)_

<One- or two-paragraph overview: what this release is about, who should care,
and whether it carries any breaking changes or required operator action.>

## Highlights

- <The 3–6 things a reader most needs to know, one line each, linking down to
  the detailed section.>

## <Category>

<Verbose, explanatory entries. Use the same category headings the changelog
uses where they apply: Consensus, RPC, P2P, Operator, Monitoring, Packaging,
Storage, Testing / CI, and the compatibility/surface families
(RPC / P2P compatibility, Esplora, Authentication & authorization, API surface
scaling, Streaming Consumption API, …). State the default and Bitcoin Core
compatibility posture for anything new or changed.>

## Upgrade notes

<Anything operator-visible that requires action or is breaking: storage-format
changes and the reindex/migration needed, removed flags, changed defaults,
new mandatory configuration. Omit the section only if there is genuinely
nothing — most releases have at least "no action required, drop-in upgrade".>

---

## About this release

satd is free software under the [MIT License](../../LICENSE).

- **Stability & compatibility** — Tier 1 surfaces (Bitcoin Core-compatible
  JSON-RPC wire shape, CLI flag names/defaults, `bitcoin.conf` keys, on-disk
  layout, Electrum/Esplora surfaces) are governed by
  [`STABILITY_POLICY.md`](../../STABILITY_POLICY.md). satd follows
  [semantic versioning](https://semver.org/spec/v2.0.0.html); while in the
  `0.x` pre-1.0 line, deprecations may be accelerated (see the policy).
- **Security & disclosure** — report vulnerabilities per
  [`SECURITY.md`](../../SECURITY.md). Consensus-affecting bugs are treated as
  P0 with same-day acknowledgement.
- **Verifying this release** — tarballs are signed with minisign, container
  images with cosign (keyless OIDC), and git tags with SSH signatures (no GPG).
  The key matrix and verification steps are in
  [`SECURITY.md`](../../SECURITY.md).
- **Intentional differences from Bitcoin Core** — catalogued in
  [`CORE_DIFFERENCES.md`](../../CORE_DIFFERENCES.md).
- **Operating satd** — the full flag matrix and tuning guide is in
  [`OPERATOR_ERGONOMICS.md`](../../OPERATOR_ERGONOMICS.md); downstream
  packaging in [`docs/PACKAGING.md`](../PACKAGING.md).
