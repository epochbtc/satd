//! BIP 324 v2 encrypted P2P transport.
//!
//! This module holds the v2 side of the transport seam introduced in
//! `connection.rs`. The types below are the encrypted counterparts of
//! `V1Connection` / `V1Reader` / `V1Writer`: once the v2 handshake
//! (ElligatorSwift ECDH + key derivation) has run on the raw socket, the
//! resulting cipher session is wrapped here so the rest of the peer
//! pipeline continues to speak `NetworkMessage` without knowing the link
//! is encrypted.
//!
//! Scaffolding only at this stage: the handshake, the `bip324` cipher
//! wiring, and the `NetworkMessage` ⇄ BIP 324 packet (de)serialization are
//! filled in by later PRs in the v2 transport stack. The methods here
//! preserve the same async signatures as their v1 counterparts so the
//! `Connection` / `ConnectionReader` / `ConnectionWriter` enums dispatch
//! uniformly.

use bitcoin::p2p::message::NetworkMessage;
use std::io;

/// Encrypted v2 P2P connection (pre-split).
pub struct V2Connection;

/// Read half of a split [`V2Connection`].
pub struct V2Reader;

/// Write half of a split [`V2Connection`].
pub struct V2Writer;

impl V2Connection {
    /// Split into separate read and write halves.
    pub fn split(self) -> (V2Reader, V2Writer) {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Send a network message over the encrypted channel.
    pub async fn send(&mut self, _msg: NetworkMessage) -> io::Result<()> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Receive the next network message from the encrypted channel.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}

impl V2Writer {
    /// Send a network message over the encrypted channel.
    pub async fn send(&mut self, _msg: NetworkMessage) -> io::Result<()> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}

impl V2Reader {
    /// Receive the next network message from the encrypted channel.
    ///
    /// As with [`V1Reader`](crate::net::connection), this must NOT be used
    /// inside `tokio::select!` — it is not cancel-safe.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}
