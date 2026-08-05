#!/usr/bin/env bash
# Regenerate clients/go/eventspb from the shared satd.events.v1 proto.
#
# The generators and the buf compiler are pinned in the sibling `tools` module
# (kept out of the SDK's own dependency graph). buf brings its own protobuf
# compiler, so nothing here needs a system protoc.
#
# CI runs this and then `git diff --exit-code clients/go/eventspb`, so a proto
# change that lands without regenerated bindings fails that PR.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
proto_dir="$repo_root/satd-events-proto/proto"

if [[ ! -d "$proto_dir" ]]; then
	echo "proto directory not found: $proto_dir" >&2
	exit 1
fi

# Build the pinned generators into a scratch bin dir and put it first on PATH:
# buf invokes `protoc-gen-go` / `protoc-gen-go-grpc` by name.
bin_dir="$(mktemp -d)"
trap 'rm -rf "$bin_dir"' EXIT
(cd "$here/tools" && GOBIN="$bin_dir" go install \
	google.golang.org/protobuf/cmd/protoc-gen-go \
	google.golang.org/grpc/cmd/protoc-gen-go-grpc)
export PATH="$bin_dir:$PATH"

# Output paths in buf.gen.yaml are relative to the working directory, and the
# `module=` plugin option strips the module prefix — so running from clients/go
# lands the files in clients/go/eventspb.
rm -f "$here/eventspb"/*.pb.go
cd "$here"
(cd tools && go tool buf generate --template "$here/buf.gen.yaml" --output "$here" "$proto_dir")

gofmt -l -w "$here/eventspb"
echo "regenerated $here/eventspb"
