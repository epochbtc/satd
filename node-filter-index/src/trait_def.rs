//! The `FilterIndex` trait — read-side surface used by the
//! `getblockfilter` RPC and the BIP 157 P2P service handlers.
//!
//! Trait surface is intentionally minimal: callers can ask for one
//! filter, one header, a contiguous range of headers (capped by the
//! BIP 157 1000-block limit), and the 1000-block-interval checkpoints.
//! `is_complete()` is the gate the P2P handlers and RPC consult
//! before serving — when `false`, both refuse, since serving partial
//! filter data would let a downstream client miss outputs and treat
//! addresses as silent on-chain.

use crate::types::IndexError;

pub trait FilterIndex: Send + Sync {
    /// Get the filter blob for a block at `height`. `filter_type` must
    /// be `FILTER_TYPE_BASIC` (0x00) for v1.
    fn filter_at(&self, filter_type: u8, height: u32) -> Result<Vec<u8>, IndexError>;

    /// Get the filter header for a block at `height`.
    fn header_at(&self, filter_type: u8, height: u32) -> Result<[u8; 32], IndexError>;

    /// Get a contiguous range of filter headers, `[start_height,
    /// stop_height]` inclusive. Returns `Err(InvalidRange)` when
    /// `stop < start` or `stop - start >= 1000` (the BIP 157 cap).
    fn headers_range(
        &self,
        filter_type: u8,
        start_height: u32,
        stop_height: u32,
    ) -> Result<Vec<[u8; 32]>, IndexError>;

    /// Filter headers at every 1000-block boundary up to (but not
    /// including) `stop_height + 1`. `getcfcheckpt` semantics per BIP
    /// 157 ("intervals of 1,000").
    fn checkpoints_to(
        &self,
        filter_type: u8,
        stop_height: u32,
    ) -> Result<Vec<[u8; 32]>, IndexError>;

    /// Completeness gate. Both the RPC and the P2P handler arms check
    /// this before serving. Reads `block_filter_index.complete` from
    /// the metadata CF.
    fn is_complete(&self) -> bool;
}
