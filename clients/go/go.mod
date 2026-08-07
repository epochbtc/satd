// The satd streaming-events Go SDK. An independently versioned module inside
// the satd repo (released as `clients/go/vX.Y.Z` tags), so proto changes and
// both SDKs land atomically and the Go E2E suite gates every satd PR.
//
// The `go` directive tracks (latest stable - 1) to cover Go's two-release
// support window; `toolchain` names the version CI builds with. Bump both
// deliberately, in their own PR.
//
// Dependencies are gRPC + protobuf only. Silent-payment scan-key validation is
// an in-tree on-curve check rather than a btcec dependency, so consuming this
// SDK never forces a secp256k1 implementation - or an MVS version bump - on a
// btcd/lnd-ecosystem application. Code generators and linters live in the
// sibling `tools` module so they stay out of this graph entirely.
module github.com/epochbtc/satd/clients/go

go 1.25.0

toolchain go1.26.5

require (
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)
