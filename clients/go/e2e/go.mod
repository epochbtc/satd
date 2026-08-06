// End-to-end tests for the Go SDK, driving a real satd regtest node.
//
// A separate module so nothing this suite needs can reach the published SDK's
// dependency graph, and a `replace` so it always tests the SDK in this
// checkout rather than a released version.
module github.com/epochbtc/satd/clients/go/e2e

go 1.25.0

toolchain go1.26.5

require github.com/epochbtc/satd/clients/go v0.0.0

require (
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	google.golang.org/grpc v1.76.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/epochbtc/satd/clients/go => ../
