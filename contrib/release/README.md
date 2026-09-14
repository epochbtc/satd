# Release helpers

Scripts run by maintainers and operators around tagged releases.

| Script | Audience | Purpose |
|---|---|---|
| `build-release-notes.sh --repo <owner/repo> --tag <tag>` | Maintainer / CI | Resolve `docs/release-notes/<version>.md` for a tag, validate it, and emit a GitHub-Release-ready body (relative links rewritten to absolute blob URLs at the tag). The release workflow uses it to drive the Release body; run it locally to preview a tag's body before pushing. |
| `sign-tarballs.sh <tag>` | Maintainer | Download a release's tarballs, sign each with minisign, upload `.minisig` files back to the release. |
| `sign-tarballs.sh --images <dir> <tag>` | Maintainer | Same, for the appliance images in `<dir>`: sign each and upload it and its `.minisig` to the release. An image already attached with a matching size is not re-uploaded. |
| `publish-sdk-crates.sh [--dry-run]` | Maintainer | Publish `satd-events-proto` then `satd-events-client` to crates.io, in that order (the client depends on the proto crate's published version). Run once per release, after the version bump lands and CI is green. |
| `git tag -s clients/go/v$VERSION <release-commit> -m "satd Go SDK $VERSION" && git push origin clients/go/v$VERSION` | Maintainer | Tag the Go SDK (`clients/go`). Done once per release at the same commit as `v$VERSION`, after CI is green; the Go module version always equals the node version. The cut PR bumps `clients/go/version.go` along with `Cargo.toml` (`TestVersionMatchesWorkspace` fails otherwise), and so does the dev-cycle bump that follows. |
| `verify-tag.sh <tag>` | Operator | Fetch the maintainer's live SSH pubkey set from `github.com/<user>.keys` and run `git verify-tag` against it. |

Release-notes authoring convention (one file per release, `-pre` suffix while
in development) lives in [`docs/release-notes/README.md`](../../docs/release-notes/README.md).

Verification commands for tarballs (minisign), images (cosign), and
the full key-rotation procedure live in the repo-root
[`SECURITY.md`](../../SECURITY.md). The packaging contract for
release artifacts lives in [`docs/manual/src/packaging.md`](../../docs/manual/src/packaging.md).
