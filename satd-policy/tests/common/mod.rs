//! Shared test scaffolding: owned transaction data + borrowed-view builders.
#![allow(dead_code)]

use satd_policy::{Ctx, InputView, Network, OutputView, ScriptType, Source, TxView};

pub struct InB {
    pub prevout_txid: Vec<u8>,
    pub prevout_vout: i128,
    pub sequence: i128,
    pub script_sig: Vec<u8>,
    pub witness_items: i128,
    pub witness_size: i128,
    pub max_witness_item: i128,
    pub has_annex: bool,
    pub prevout_value: i128,
    pub prevout_script_type: ScriptType,
    pub prevout_script: Vec<u8>,
    pub spends_coinbase: bool,
    pub leaf_script: Vec<u8>,
}

impl Default for InB {
    fn default() -> Self {
        InB {
            prevout_txid: vec![0u8; 32],
            prevout_vout: 0,
            sequence: 0xffff_ffff,
            script_sig: vec![],
            witness_items: 0,
            witness_size: 0,
            max_witness_item: 0,
            has_annex: false,
            prevout_value: 100_000,
            prevout_script_type: ScriptType::P2wpkh,
            prevout_script: vec![],
            spends_coinbase: false,
            leaf_script: vec![],
        }
    }
}

pub struct OutB {
    pub value: i128,
    pub script_type: ScriptType,
    pub script: Vec<u8>,
    pub op_return_size: i128,
    pub is_dust: bool,
}

impl Default for OutB {
    fn default() -> Self {
        OutB {
            value: 50_000,
            script_type: ScriptType::P2wpkh,
            script: vec![],
            op_return_size: 0,
            is_dust: false,
        }
    }
}

pub struct TxB {
    pub version: i128,
    pub locktime: i128,
    pub vsize: i128,
    pub weight: i128,
    pub total_witness_size: i128,
    pub signals_rbf: bool,
    pub txid: Vec<u8>,
    pub fee: i128,
    pub fee_rate: i128,
    pub sigops_cost: i128,
    pub source: Source,
    pub from_whitelisted_peer: bool,
    pub inputs: Vec<InB>,
    pub outputs: Vec<OutB>,
}

impl Default for TxB {
    fn default() -> Self {
        TxB {
            version: 2,
            locktime: 0,
            vsize: 200,
            weight: 800,
            total_witness_size: 0,
            signals_rbf: false,
            txid: vec![0u8; 32],
            fee: 2_000,
            fee_rate: 10_000,
            sigops_cost: 4,
            source: Source::P2p,
            from_whitelisted_peer: false,
            inputs: vec![InB::default()],
            outputs: vec![OutB::default()],
        }
    }
}

impl TxB {
    pub fn input_views(&self) -> Vec<InputView<'_>> {
        self.inputs
            .iter()
            .map(|i| InputView {
                prevout_txid: &i.prevout_txid,
                prevout_vout: i.prevout_vout,
                sequence: i.sequence,
                script_sig: &i.script_sig,
                witness_items: i.witness_items,
                witness_size: i.witness_size,
                max_witness_item: i.max_witness_item,
                has_annex: i.has_annex,
                prevout_value: i.prevout_value,
                prevout_script_type: i.prevout_script_type,
                prevout_script: &i.prevout_script,
                spends_coinbase: i.spends_coinbase,
                leaf_script: &i.leaf_script,
            })
            .collect()
    }

    pub fn output_views(&self) -> Vec<OutputView<'_>> {
        self.outputs
            .iter()
            .map(|o| OutputView {
                value: o.value,
                script_type: o.script_type,
                script: &o.script,
                op_return_size: o.op_return_size,
                is_dust: o.is_dust,
            })
            .collect()
    }

    pub fn tx_view<'a>(
        &'a self,
        ins: &'a [InputView<'a>],
        outs: &'a [OutputView<'a>],
    ) -> TxView<'a> {
        TxView {
            version: self.version,
            locktime: self.locktime,
            vsize: self.vsize,
            weight: self.weight,
            total_witness_size: self.total_witness_size,
            signals_rbf: self.signals_rbf,
            txid: &self.txid,
            fee: self.fee,
            fee_rate: self.fee_rate,
            sigops_cost: self.sigops_cost,
            source: self.source,
            from_whitelisted_peer: self.from_whitelisted_peer,
            inputs: ins,
            outputs: outs,
        }
    }
}

pub fn ctx() -> Ctx {
    Ctx {
        network: Network::Mainnet,
        height: 900_000,
        min_relay_fee: 1_000,
        dust_relay_fee: 3_000,
        mempool_bytes: 10_000_000,
        mempool_min_fee: 1_000,
    }
}

/// Build an ordinals-envelope tapleaf: `<pubkey> OP_CHECKSIG OP_FALSE OP_IF
/// <push "ord"> <push body> OP_ENDIF`.
pub fn ord_leaf() -> Vec<u8> {
    let mut s = Vec::new();
    s.push(0x20);
    s.extend_from_slice(&[0xaa; 32]);
    s.push(0xac); // OP_CHECKSIG
    s.push(0x00); // OP_FALSE
    s.push(0x63); // OP_IF
    s.push(0x03);
    s.extend_from_slice(b"ord");
    s.push(0x0a);
    s.extend_from_slice(b"text/plain");
    s.push(0x68); // OP_ENDIF
    s
}
