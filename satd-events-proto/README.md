# satd-events-proto

Generated protobuf/tonic types for satd's `satd.events.v1` streaming
consumption API (the gRPC firehose + bidirectional `Watch`).

This is the low-level wire-types crate: generated message structs, the tonic
client/server stubs, and nothing else. Most consumers want
[`satd-events-client`](https://docs.rs/satd-events-client) instead, which
wraps these types in an ergonomic, reconnect-aware async client. Use this
crate directly only if you are hand-rolling a client in a way the SDK doesn't
cover, or implementing a server against the same schema.

The wire schema is documented in
[`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md)
in the main [`satd`](https://github.com/epochbtc/satd) repository.

Licensed under the [MIT License](https://github.com/epochbtc/satd/blob/master/LICENSE).
