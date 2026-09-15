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
// The module is versioned with the node: clients/go/vX.Y.Z is cut at the node's
// vX.Y.Z, and [Version] names it. An SDK works with any node on the same event
// schema whose version is at or above its own; newer nodes only add fields and
// event kinds, which an older build decodes as [UnknownEvent].
//
// When a stream opens, the SDK compares the version the node advertises with
// its own. A node one minor version behind gets a warning, logged once per node
// version through [WithLogger] (default slog.Default()). A node two or more
// minor versions, or a major version, behind is refused with [ErrNodeTooOld];
// [WithAllowOldNode] turns that into the warning. A different event schema is
// always refused with [ErrSchemaMismatch]. A node older than 0.6.0 advertises
// nothing and counts as 0.5. [Client.NodeVersion] reports what the node
// advertised. The rule is in STABILITY_POLICY.md, "Streaming API & SDK
// compatibility".
//
// The generated wire types are exported from the eventspb subpackage for the
// cases a typed helper does not yet cover.
package satdevents
