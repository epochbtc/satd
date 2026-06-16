//! Mempool event stream — broadcast to subscribemempool clients and
//! tapped into a bounded ring for MCP snapshot consumption.
//!
//! Emitted on every state transition the mempool performs:
//! tx enters, is confirmed in a block, is evicted (mempool full /
//! expired), or is replaced by a higher-fee RBF candidate. Consumers
//! are best-effort — a slow subscriber that can't keep up with the
//! broadcast will see `RecvError::Lagged` and miss events, but the
//! mempool's consensus path never blocks on broadcast send.

use bitcoin::{BlockHash, Txid};
use serde::Serialize;

/// Reason a mempool tx was evicted by policy (distinct from confirmed
/// / replaced removals, which have their own event variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictReason {
    /// Evicted by `evict_lowest_fee_entries` to free space for a new tx.
    FullPool,
    /// Evicted by `remove_expired` because it aged past `expiry_secs`.
    Expiry,
    /// A block connected that spends inputs this tx also spends — the
    /// chain, not policy, retired the tx. Distinct from `FullPool` so
    /// operators aren't misled into thinking the mempool is under
    /// pressure.
    BlockConflict,
    /// Evicted from the **quarantine class** because that class's own byte
    /// budget (`quarantinemempool`) overflowed — fee-rate eviction within the
    /// held set. Distinct from `FullPool` (the acting class) so per-class
    /// pressure is legible. Inert until a policy is loaded (PR 4c).
    Policy,
}

impl EvictReason {
    /// Stable snake_case wire string (matches the serde representation).
    pub fn as_str(&self) -> &'static str {
        match self {
            EvictReason::FullPool => "full_pool",
            EvictReason::Expiry => "expiry",
            EvictReason::BlockConflict => "block_conflict",
            EvictReason::Policy => "policy",
        }
    }
}

/// Event emitted on a mempool state transition. Serialized to the WS
/// subscription payload verbatim (the `kind` tag discriminates).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MempoolEvent {
    /// Transaction accepted into the mempool.
    Enter {
        txid: Txid,
        fee: u64,
        vsize: u64,
        fee_rate_sat_per_kvb: u64,
        time: u64,
    },
    /// Transaction confirmed in a block and removed from the mempool.
    LeaveConfirmed {
        txid: Txid,
        block_hash: BlockHash,
        height: u32,
    },
    /// Transaction removed by policy (not confirmation, not replacement).
    LeaveEvicted { txid: Txid, reason: EvictReason },
    /// Transaction replaced by a conflicting RBF candidate. `replacing_txid`
    /// is the txid of the incoming tx that caused the eviction.
    LeaveReplaced {
        txid: Txid,
        replacing_txid: Txid,
    },
}

impl MempoolEvent {
    pub fn txid(&self) -> &Txid {
        match self {
            Self::Enter { txid, .. }
            | Self::LeaveConfirmed { txid, .. }
            | Self::LeaveEvicted { txid, .. }
            | Self::LeaveReplaced { txid, .. } => txid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn tx(byte: u8) -> Txid {
        let mut b = [0u8; 32];
        b[0] = byte;
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(b))
    }

    fn bh(byte: u8) -> BlockHash {
        let mut b = [0u8; 32];
        b[0] = byte;
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(b))
    }

    #[test]
    fn enter_serializes_with_snake_case_kind() {
        let ev = MempoolEvent::Enter {
            txid: tx(1),
            fee: 100,
            vsize: 250,
            fee_rate_sat_per_kvb: 400,
            time: 1_700_000_000,
        };
        let j = serde_json::to_value(&ev).unwrap();
        assert_eq!(j["kind"], "enter");
        assert_eq!(j["fee"], 100);
        assert_eq!(j["vsize"], 250);
    }

    #[test]
    fn leave_confirmed_serializes() {
        let ev = MempoolEvent::LeaveConfirmed {
            txid: tx(2),
            block_hash: bh(9),
            height: 42,
        };
        let j = serde_json::to_value(&ev).unwrap();
        assert_eq!(j["kind"], "leave_confirmed");
        assert_eq!(j["height"], 42);
    }

    #[test]
    fn leave_evicted_reason_snake_case() {
        for (reason, expected) in [
            (EvictReason::FullPool, "full_pool"),
            (EvictReason::Expiry, "expiry"),
            (EvictReason::BlockConflict, "block_conflict"),
        ] {
            let ev = MempoolEvent::LeaveEvicted { txid: tx(3), reason };
            let j = serde_json::to_value(&ev).unwrap();
            assert_eq!(j["kind"], "leave_evicted");
            assert_eq!(j["reason"], expected);
        }
    }

    #[test]
    fn leave_replaced_carries_replacing_txid() {
        let ev = MempoolEvent::LeaveReplaced {
            txid: tx(4),
            replacing_txid: tx(5),
        };
        let j = serde_json::to_value(&ev).unwrap();
        assert_eq!(j["kind"], "leave_replaced");
        assert!(j["replacing_txid"].is_string());
    }
}
