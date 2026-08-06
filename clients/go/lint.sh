#!/usr/bin/env bash
# Run the Go SDK's lint gate: gofmt, go vet, staticcheck, errcheck.
#
# staticcheck and errcheck are pinned in the sibling `tools` module. They have
# to run from THIS module's directory (their package patterns resolve against
# the main module), so build them to a scratch bin dir first rather than
# invoking `go tool` from tools/.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

bin_dir="$(mktemp -d)"
trap 'rm -rf "$bin_dir"' EXIT
(cd tools && GOBIN="$bin_dir" go install \
	honnef.co/go/tools/cmd/staticcheck \
	github.com/kisielk/errcheck)

# Generated bindings are excluded from gofmt: protoc-gen-go's output is
# canonical and not ours to restyle. staticcheck skips them via
# staticcheck.conf; errcheck via its -ignoregenerated-like exclusion below.
unformatted="$(gofmt -l . | grep -v '^eventspb/' || true)"
if [[ -n "$unformatted" ]]; then
	echo "gofmt needed for:" >&2
	echo "$unformatted" >&2
	exit 1
fi

go vet ./...
"$bin_dir/staticcheck" ./...
# Generated code checks nothing; -ignoregenerated skips files carrying the
# standard "Code generated ... DO NOT EDIT." header.
"$bin_dir/errcheck" -ignoregenerated ./...

echo "lint ok"
