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

# gofmt walks directories, but the three analyzers resolve `./...` against the
# main module and stop at a nested go.mod — so `examples` and `e2e` would be
# silently unlinted if this only ran once, here. Run the gate in each module.
#
# `e2e` needs its build tag, or its files are excluded from the build and every
# analyzer reports a clean run over nothing at all.
lint_module() {
	local dir="$1"
	shift
	echo "--- linting ${dir}"
	(
		cd "$dir"
		go vet "$@" ./...
		"$bin_dir/staticcheck" "$@" ./...
		# Generated code checks nothing; -ignoregenerated skips files carrying
		# the standard "Code generated ... DO NOT EDIT." header.
		"$bin_dir/errcheck" -ignoregenerated "$@" ./...
	)
}

lint_module .
lint_module examples
lint_module e2e -tags e2e

echo "lint ok"
