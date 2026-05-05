# Release helpers

Scripts run by maintainers and operators around tagged releases.

| Script | Audience | Purpose |
|---|---|---|
| `sign-tarballs.sh <tag>` | Maintainer | Download a release's tarballs, sign each with minisign, upload `.minisig` files back to the release. |
| `verify-tag.sh <tag>` | Operator | Fetch the maintainer's live SSH pubkey set from `github.com/<user>.keys` and run `git verify-tag` against it. |

Verification commands for tarballs (minisign), images (cosign), and
the full key-rotation procedure live in the repo-root
[`SECURITY.md`](../../SECURITY.md). The packaging contract for
release artifacts lives in [`docs/PACKAGING.md`](../../docs/PACKAGING.md).
