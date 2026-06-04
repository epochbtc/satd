#!/usr/bin/env bash
# build-release-notes.sh — resolve the docs/release-notes/ file for a tag,
# validate it, and emit a GitHub-Release-ready body to stdout (or --output).
#
# The release workflow (.github/workflows/release.yml) calls this to drive the
# GitHub Release body from the curated, versioned release notes instead of an
# auto-generated PR-title list. Maintainers can also run it locally to preview
# exactly what a tag's release body will look like before pushing the tag:
#
#   contrib/release/build-release-notes.sh --repo epochbtc/satd --tag v0.3.0
#
# What it does:
#   - Maps tag vX.Y.Z[-pre] -> version X.Y.Z[-pre], finds
#     docs/release-notes/<version>.md (falling back to <version>-pre.md with a
#     warning, in case the rename-on-tag step was missed).
#   - Validates the file exists, is non-empty, and its H1 matches the version.
#   - Prepends a banner linking to the canonical rendered file at the tag, then
#     emits the notes with their repo-relative links rewritten to absolute
#     blob URLs at the tag, so every link resolves from the release page.
#
# Exit codes:
#   0   body written
#   3   no release-notes file for this version (caller may fall back to
#       auto-generated notes — e.g. an -rcN pre-release tag)
#   1   found but malformed (empty), or other hard error
#   64  usage error
#
# Usage:
#   build-release-notes.sh --repo <owner/repo> --tag <vX.Y.Z>
#                          [--notes-dir docs/release-notes] [--output FILE]

set -euo pipefail

REPO=""
TAG=""
NOTES_DIR="docs/release-notes"
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) REPO="${2:-}"; shift 2 ;;
        --tag) TAG="${2:-}"; shift 2 ;;
        --notes-dir) NOTES_DIR="${2:-}"; shift 2 ;;
        --output) OUTPUT="${2:-}"; shift 2 ;;
        --help|-h)
            sed -n '2,/^set -e/p' "$0" | sed -n '/^# /p' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

if [[ -z "$REPO" || -z "$TAG" ]]; then
    echo "usage: $0 --repo <owner/repo> --tag <vX.Y.Z> [--notes-dir DIR] [--output FILE]" >&2
    exit 64
fi

# vX.Y.Z[-suffix] -> X.Y.Z[-suffix]
version="${TAG#v}"

notes="${NOTES_DIR}/${version}.md"
if [[ ! -f "$notes" ]]; then
    pre="${NOTES_DIR}/${version}-pre.md"
    if [[ -f "$pre" ]]; then
        echo "::warning::using pre-release notes file ${pre} for release ${TAG} — rename it to ${version}.md when cutting the release" >&2
        notes="$pre"
    else
        echo "no release-notes file found: ${notes} (or ${pre})" >&2
        exit 3
    fi
fi

if [[ ! -s "$notes" ]]; then
    echo "release-notes file is empty: ${notes}" >&2
    exit 1
fi

# Format check: the H1 should name this version, so a stale copy/paste from
# another release is caught. Warn rather than hard-fail — the body is still
# shippable, and we'd rather not block a release on a heading typo.
first_heading=$(grep -m1 '^# ' "$notes" || true)
if [[ "$first_heading" != "# satd ${version}"* ]]; then
    echo "::warning::${notes} H1 is '${first_heading}', expected '# satd ${version}'" >&2
fi

blob="https://github.com/${REPO}/blob/${TAG}"
notes_url="${blob}/${notes}"

# Emit: banner linking the canonical source, then the notes with repo-relative
# markdown links rewritten to absolute blob URLs at this tag. Order matters in
# the link rewrite — '../../' before '../', and the bare-filename rule
# (sibling release-notes files) last so it can't clobber the '../' matches.
emit() {
    printf '> 📄 **Canonical release notes:** [`%s`](%s)\n\n' "$notes" "$notes_url"
    sed \
        -e "s#](\.\./\.\./#](${blob}/#g" \
        -e "s#](\.\./#](${blob}/docs/#g" \
        -e "s#](\([0-9A-Za-z._-]\+\.md\))#](${blob}/${NOTES_DIR}/\1)#g" \
        "$notes"
}

if [[ -n "$OUTPUT" ]]; then
    emit > "$OUTPUT"
    echo "wrote release body to ${OUTPUT} (from ${notes})" >&2
else
    emit
fi
