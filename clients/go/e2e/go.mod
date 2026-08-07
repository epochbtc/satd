// End-to-end tests for the Go SDK, driving a real satd regtest node.
//
// A separate module so nothing this suite needs can reach the published SDK's
// dependency graph, and a `replace` so it always tests the SDK in this
// checkout rather than a released version.
module github.com/epochbtc/satd/clients/go/e2e

go 1.25.0

toolchain go1.26.5

require (
	github.com/epochbtc/satd/clients/go v0.0.0
	// Pinned to the same release the SDK module requires: the E2E suite dials
	// with explicit HTTP/2 window options to force a Lagged, and a skewed grpc
	// here would be testing a different transport than consumers get.
	google.golang.org/grpc v1.82.1
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/epochbtc/satd/clients/go => ../
