//! Operator alerting: the `alertfile` webhook configuration, the delivery
//! contract, and the retry policy.
//!
//! This crate is the pure half of the alerting subsystem. It parses and
//! validates an alertfile, decides whether a given event matches a hook,
//! renders the delivery headers, signs a body, and classifies a response as
//! delivered / retryable / dead. It does **not** open sockets: the dispatcher
//! task and its `reqwest` client live in the `satd` binary, so every rule here
//! is testable without a network, and the signature contract can be pinned by
//! golden vectors that a third-party receiver implementation can check itself
//! against.
//!
//! The split mirrors `satd-auth`, and for the same reason: policy that decides
//! *whether* and *how* something is delivered belongs somewhere a test can
//! reach without standing up a daemon.
//!
//! Module layout:
//! - [`config`] — the alertfile format, its validation rules, and permission
//!   checks.
//! - [`contract`] — the wire contract: header names, delivery ids, HMAC
//!   signing, and the version constant.
//! - [`retry`] — response classification and the backoff curve.

pub mod config;
pub mod contract;
pub mod retry;

pub use config::{AlertFile, AlertFileError, Hook, HookFilter, HOOK_QUEUE_CAPACITY};
pub use contract::{
    delivery_id, replay_delivery_id, sign_body, sign_v2, v2_signing_string, ATTEMPT_HEADER,
    DELIVERY_HEADER, HOOK_HEADER, LEGACY_WEBHOOK_VERSION, MAX_TIMESTAMP_SKEW_SECS,
    SIGNATURE_HEADER, TIMESTAMP_HEADER, WEBHOOK_VERSION, WEBHOOK_VERSION_HEADER,
};
pub use retry::{classify_response, retry_delay, Disposition, MAX_BACKOFF};
