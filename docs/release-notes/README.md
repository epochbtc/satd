# satd release notes

This directory holds the **user-facing release notes** for each satd release —
verbose, explanatory write-ups intended for operators and integrators.

The split is deliberate:

- [`CHANGELOG.md`](../../CHANGELOG.md) (repo root) is the **terse index**: one
  entry per release pointing here, plus a short bullet list of unreleased
  changes. It is the at-a-glance "what shipped, when".
- This directory holds the **detail**: one file per release
  (`<major>.<minor>.<patch>.md`), with the full rationale, behavior contracts,
  upgrade steps, and links to the governing policies.

## Files

| File | Release | Status |
|---|---|---|
| [`0.3.0.md`](0.3.0.md) | 0.3.0 | Released 2026-06-10 |
| [`0.2.1.md`](0.2.1.md) | 0.2.1 | Released 2026-05-29 |
| [`0.2.0.md`](0.2.0.md) | 0.2.0 | Released 2026-05-27 |
| [`0.1.0.md`](0.1.0.md) | 0.1.0 | Released 2026-05-08 (first public release) |

[`TEMPLATE.md`](TEMPLATE.md) is the canonical format. **Copy it for every new
release** so the structure stays consistent.

## Conventions

- One file per release, named for the version. While a version is in
  development its file carries a `-pre` suffix (`0.3.0-pre.md`) to make explicit
  it is not yet released; the suffix is dropped (`0.3.0.md`) when the release is
  tagged.
- Every file opens with a one-paragraph overview and a **Highlights** list,
  then category sections (Consensus, RPC, P2P, Operator, Packaging, …),
  an **Upgrade notes** section for anything breaking or requiring operator
  action, and the standard **About this release** footer that links to the
  license and the governing policies.
- Notes are written for a reader who was *not* following development: explain
  the "why", the default/compat posture, and the operator-visible behavior.
- When a release tags, rename its file to drop the `-pre` suffix
  (`0.3.0-pre.md` → `0.3.0.md`), flip its line in the table above from
  pre-release to "Released YYYY-MM-DD", update the date in the file header, and
  add the dated entry + compare link to `CHANGELOG.md`.
