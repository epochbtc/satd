// Runnable examples for the satd Go SDK, one program per usage shape.
//
// A SEPARATE module, for the same reason `tools` and `e2e` are: a dependency
// declared here must never reach an application that only imports the SDK. Two
// of these examples (sp_wallet, sp_light_scan) do BIP 352 receiver derivation,
// which needs real secp256k1 scalar and point arithmetic — so they import
// btcec. Keeping that import in this module means it stays out of every
// consumer's module graph, which is exactly the constraint the SDK's own go.mod
// exists to hold: the published SDK graph is gRPC + protobuf and nothing else.
//
// (The SDK's in-tree on-curve check covers *validating* a scan key, which is
// all the SDK itself needs. Deriving spending keys is wallet work, and an
// example that hand-rolled secp256k1 with math/big would be teaching the wrong
// lesson — a real Go wallet has a curve library already.)
//
// The `replace` points at the checkout so the examples always compile against
// the SDK in this tree rather than a published version — which is what makes
// them a build-time check that the API still reads the way the docs claim.
module github.com/epochbtc/satd/clients/go/examples

go 1.25.0

toolchain go1.26.5

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/epochbtc/satd/clients/go v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	google.golang.org/grpc v1.76.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/epochbtc/satd/clients/go => ../
