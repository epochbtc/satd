//! Generated protobuf and tonic types for the satd Streaming Consumption API
//! (`satd.events.v1`).
//!
//! This crate contains only generated code — no logic. It is the single codegen
//! site for the wire schema; both the server (`satd-events`) and the client SDK
//! (`satd-events-client`) depend on it so the `.proto` has one source of truth.
//!
//! The module path mirrors the proto package: types are exposed at
//! [`satd::events::v1`], and re-exported at the crate root as [`v1`] for the
//! common short alias `use satd_events_proto::v1 as pb;`.
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(missing_docs)]

pub mod satd {
    pub mod events {
        pub mod v1 {
            tonic::include_proto!("satd.events.v1");
        }
    }
}

pub use self::satd::events::v1 as v1;
