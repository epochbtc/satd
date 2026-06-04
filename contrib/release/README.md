# Release helpers

Scripts run by maintainers and operators around tagged releases.

| Script | Audience | Purpose |
|---|---|---|
| `build-release-notes.sh --repo <owner/repo> --tag <tag>` | Maintainer / CI | Resolve `docs/release-notes/<version>.md` for a tag, validate it, and emit a GitHub-Release-ready body (relative links rewritten to absolute blob URLs at the tag). The release workflow uses it to drive the Release body; run it locally to preview a tag's body before pushing. |
| `sign-tarballs.sh <tag>` | Maintainer | Download a release's tarballs, sign each with minisign, upload `.minisig` files back to the release. |
| `verify-tag.sh <tag>` | Operator | Fetch the maintainer's live SSH pubkey set from `github.com/<user>.keys` and run `git verify-tag` against it. |

Release-notes authoring convention (one file per release, `-pre` suffix while
in development) lives in [`docs/release-notes/README.md`](../../docs/release-notes/README.md).

Verification commands for tarballs (minisign), images (cosign), and
the full key-rotation procedure live in the repo-root
[`SECURITY.md`](../../SECURITY.md). The packaging contract for
release artifacts lives in [`docs/manual/src/packaging.md`](../../docs/manual/src/packaging.md).
