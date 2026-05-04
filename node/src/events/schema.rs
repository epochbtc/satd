//! Schema version policy for [`super::NodeEvent`].
//!
//! Every envelope carries `schema_version` so adapters can advertise
//! capabilities and consumers can detect incompatible upgrades. The rules:
//!
//! - **Adding** a new [`super::NodeEventBody`] variant: no bump. Consumers
//!   ignore unknown `kind` tags (JSON), and protobuf `oneof` is forward-
//!   compatible.
//! - **Adding** a field to an existing variant: no bump. Same reasoning.
//! - **Renaming** or **removing** a field, or changing the semantics of an
//!   existing field: bump the major version. gRPC sinks must close active
//!   streams with `Status::failed_precondition`; ZMQ consumers see the
//!   bumped version on the next `nodeevent` frame.
//! - The [`super::EdgeStamp`] fields are append-only. The `seq` semantics
//!   ("monotonic per `EventPublisher` instance") are frozen.
//!
//! Bump only when forced. The envelope is the user-visible API surface.

/// Current schema version. See module docs for the evolution policy.
pub const SCHEMA_VERSION: u32 = 1;
