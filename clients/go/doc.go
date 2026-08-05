// Package satdevents is the Go client SDK for the satd Streaming Consumption
// API (the satd.events.v1 gRPC service).
//
// It wraps the generated protobuf client with a typed event model, auth and TLS
// setup, cursor capture, and reconnect/replay resilience, so a consumer writes
// against [Client] instead of hand-rolling streams, metadata, and protobuf
// unwrapping.
//
// # Byte order
//
// Every hash and txid on this API is carried in internal (consensus) byte
// order - the order the wire and key derivation use, not the reversed order
// block explorers and Bitcoin Core JSON-RPC display. Convert only at the edge,
// with [DisplayHex] (or [ParseTxid] for the reversed 32-byte array). Do not
// apply either to a public key or tweak: those are raw bytes and are not
// reversed for display.
//
// # Stability
//
// The SDK tracks the additive satd.events.v1 wire schema, not the node's
// release cadence: new optional fields and event kinds are added without
// breaking existing consumers, and this module is versioned independently of
// the satd node - a node and SDK do not need matching versions. The generated
// wire types are exported from the eventspb subpackage for the cases a typed
// helper does not yet cover.
package satdevents
