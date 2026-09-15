//! Stratum V2 (the Mining Protocol over a Noise-encrypted transport).
//!
//! [`noise`] is the transport, [`wire`] the message payloads, [`session`] the
//! per-connection state machine, and [`authority`] the persisted key miners
//! authenticate the server by. Work, shares and vardiff are the same
//! protocol-agnostic core the Stratum V1 server uses.

pub mod authority;
pub mod jd;
pub mod noise;
pub mod session;
pub mod wire;
