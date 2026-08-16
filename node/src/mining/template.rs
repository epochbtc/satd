use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Transaction};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;

/// Maximum block weight (4 million weight units).
const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// Reserve weight for coinbase transaction. Matches Bitcoin Core v30's
/// `DEFAULT_BLOCK_RESERVED_WEIGHT` (8000 WU).
const COINBASE_WEIGHT_RESERVE: usize = 8_000;

/// A selected transaction for the block template.
pub struct TemplateTx {
    pub tx: Transaction,
    pub fee: u64,
    pub weight: usize,
}

/// Block template ready for mining.
pub struct BlockTemplate {
    pub version: i32,
    pub prev_hash: BlockHash,
    pub height: u32,
    pub bits: CompactTarget,
    pub cur_time: u32,
    pub transactions: Vec<TemplateTx>,
    pub coinbase_value: u64,
}

/// Create a block template from the current chain state and mempool.
pub fn create_template(chain_state: &ChainState, mempool: &Mempool) -> BlockTemplate {
    let tip_hash = chain_state.tip_hash();
    let tip_entry = chain_state.get_block_index(&tip_hash).unwrap();
    let height = tip_entry.height + 1;
    let subsidy = crate::chain::connect::block_subsidy(height);

    // Determine bits (difficulty)
    let bits = match chain_state.network {
        bitcoin::Network::Regtest => CompactTarget::from_consensus(0x207fffff),
        _ => tip_entry.header.bits, // Simplified; full retarget in pow.rs
    };

    // Select transactions from mempool by effective fee rate (includes
    // fee_delta). Template assembly is scope-filtered: transactions
    // quarantined `on template` are held but never mined by this node
    // (design §2.4/§3), so they are excluded here.
    let mut entries = mempool.get_template_entries();
    entries.sort_by(|a, b| {
        // Saturating add: a corrupt persisted mempool could carry an
        // extreme fee_delta; it must not overflow the effective-fee sum
        // (which would mis-order block-template selection).
        let eff_a = (a.1.fee as i64).saturating_add(a.1.fee_delta).max(0) as u64 * 1000
            / a.1.weight.max(1) as u64;
        let eff_b = (b.1.fee as i64).saturating_add(b.1.fee_delta).max(0) as u64 * 1000
            / b.1.weight.max(1) as u64;
        eff_b.cmp(&eff_a)
    });

    // The (height, MTP) this block will be validated under — the MTP
    // context of `height` is the 11 blocks strictly below it, i.e. the
    // tip's MTP.
    let template_mtp = chain_state.get_median_time_past(height);

    // Dependency- and finality-aware selection (#588/#589). A transaction
    // is includable only when it is final for this block (Core's miner
    // re-checks `IsFinalTx` exactly like this — admission normally
    // guarantees it, but a reorg can lower the tip after admission, and a
    // persisted mempool may predate the admission check), its sequence
    // locks are satisfiable at this (height, MTP), and every input
    // resolves to a confirmed coin or an output of a transaction already
    // included. Greedy by effective fee rate over the ready set; a child
    // deferred behind its parent lands in a later pass, which is what
    // yields parent-before-child order in the emitted list. A child whose
    // parent never makes it in — weight cap, template quarantine — is
    // dropped with it: without this, CPFP's fee-rate inversion put
    // children *before* their parents and the mined block was invalid.
    let in_mempool = mempool.all_txids();
    let mut included: std::collections::HashSet<bitcoin::Txid> = std::collections::HashSet::new();
    let mut transactions = Vec::new();
    let mut total_weight = COINBASE_WEIGHT_RESERVE;
    let mut total_fees = 0u64;

    let mut remaining = entries;
    loop {
        let mut deferred = Vec::with_capacity(remaining.len());
        let mut progressed = false;
        for (txid, entry) in remaining {
            if !tx_is_final_at(&entry.tx, height, template_mtp) {
                continue; // never includable in this block
            }
            // Resolve every input against the UTXO set, not mempool
            // membership: a parent evicted after this child was admitted
            // (expiry, RBF, block-connect conflict) is in neither the
            // mempool nor the UTXO set, and treating "not in mempool" as
            // "confirmed" would mine the orphaned child →
            // bad-txns-inputs-missingorspent. An input creates one of
            // four cases: already included in this template (the coin is
            // born at `height`), a confirmed coin, a mempool parent that
            // may still be included (defer to a later pass), or nothing
            // anywhere (drop — unminable). Resolved coin heights feed the
            // BIP 68 re-check, which mirrors the absolute one above: a
            // reorg or persisted mempool can hold sequence-locked
            // transactions admission never re-judged.
            let bip68_enforced = (entry.tx.version.0 as u32) >= 2;
            let mut awaits_parent = false;
            let mut minable = true;
            for input in &entry.tx.input {
                let parent = input.previous_output.txid;
                let prev_height = if included.contains(&parent) {
                    height
                } else if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                    coin.height
                } else if in_mempool.contains(&parent) {
                    awaits_parent = true;
                    continue;
                } else {
                    minable = false;
                    break;
                };
                if bip68_enforced
                    && !Mempool::bip68_satisfied(
                        chain_state,
                        input.sequence.0,
                        prev_height,
                        height,
                        template_mtp,
                    )
                {
                    minable = false;
                    break;
                }
            }
            if !minable {
                continue; // never includable in this block
            }
            if awaits_parent {
                deferred.push((txid, entry));
                continue;
            }
            if total_weight + entry.weight > MAX_BLOCK_WEIGHT {
                continue; // weight only grows; this can never fit later
            }
            total_weight += entry.weight;
            total_fees += entry.fee;
            included.insert(txid);
            transactions.push(TemplateTx {
                tx: entry.tx,
                fee: entry.fee,
                weight: entry.weight,
            });
            progressed = true;
        }
        if !progressed || deferred.is_empty() {
            break;
        }
        remaining = deferred;
    }

    // Timestamp: max of current time and parent time + 1
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let cur_time = std::cmp::max(now, tip_entry.header.time + 1);

    BlockTemplate {
        version: 0x20000000, // BIP 9 version bits
        prev_hash: tip_hash,
        height,
        bits,
        cur_time,
        transactions,
        coinbase_value: subsidy + total_fees,
    }
}

/// Absolute finality for a block at `height` whose MTP context is `mtp` —
/// the rule `connect_block` enforces (Core's `IsFinalTx`): final iff the
/// locktime is zero, *strictly* below the cutoff (height for height
/// locktimes, MTP for time locktimes), or every input's sequence is
/// SEQUENCE_FINAL.
fn tx_is_final_at(tx: &Transaction, height: u32, mtp: u32) -> bool {
    let locktime = tx.lock_time.to_consensus_u32();
    if locktime == 0 {
        return true;
    }
    let cutoff = if locktime < 500_000_000 { height } else { mtp };
    if locktime < cutoff {
        return true;
    }
    tx.input
        .iter()
        .all(|i| i.sequence == bitcoin::Sequence::MAX)
}

/// Compute merkle root from a list of 32-byte hashes.
fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current = hashes.to_vec();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::new();
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(hash.to_byte_array());
        }
        current = next;
    }
    current[0]
}

/// Compute the default witness commitment hex for a block template.
/// Returns the full OP_RETURN script hex (6a24aa21a9ed + 32-byte commitment).
/// Returns empty string if no transactions have witness data.
pub fn compute_witness_commitment_hex(txs: &[TemplateTx]) -> String {
    let has_witness = txs
        .iter()
        .any(|ttx| ttx.tx.input.iter().any(|i| !i.witness.is_empty()));
    if !has_witness {
        return String::new();
    }

    // Coinbase wtxid = 0x00...00, then wtxids of included transactions
    let mut hashes: Vec<[u8; 32]> = vec![[0u8; 32]];
    for ttx in txs {
        hashes.push(ttx.tx.compute_wtxid().to_raw_hash().to_byte_array());
    }
    let witness_root = merkle_root(&hashes);

    // commitment = SHA256d(witness_root || witness_nonce)
    let witness_nonce = [0u8; 32];
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&witness_root);
    preimage[32..].copy_from_slice(&witness_nonce);
    let commitment = bitcoin::hashes::sha256d::Hash::hash(&preimage);

    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    hex::encode(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_create_empty_template() {
        let dir = std::env::temp_dir().join(format!("satd-template-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), AssumeValid::Disabled, 450, 4, Default::default(), Default::default(), Default::default()).unwrap();
        let mp = Mempool::new(1_000_000, 0);

        let template = create_template(&cs, &mp);

        assert_eq!(template.height, 1);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);
        assert!(template.transactions.is_empty());
        assert_eq!(template.coinbase_value, 50 * 100_000_000); // 50 BTC subsidy

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_template_env() -> (ChainState, Mempool, std::path::PathBuf) {
        make_funded_template_env(&[])
    }

    fn make_funded_template_env(
        coins: &[(bitcoin::OutPoint, crate::storage::coinview::Coin)],
    ) -> (ChainState, Mempool, std::path::PathBuf) {
        use crate::storage::Store as _;
        let dir = std::env::temp_dir().join(format!(
            "satd-template-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        if !coins.is_empty() {
            let mut batch = crate::storage::StoreBatch::default();
            for (op, c) in coins {
                batch.coin_puts.push((*op, c.clone()));
            }
            store.write_batch(batch).unwrap();
        }
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
        .unwrap();
        let mp = Mempool::new(1_000_000, 0);
        (cs, mp, dir)
    }

    #[test]
    fn test_template_height_increments() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        // At genesis (height 0), the next block should be height 1
        assert_eq!(template.height, cs.tip_height() + 1);
        assert_eq!(template.height, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_coinbase_subsidy_only() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        let expected_subsidy = crate::chain::connect::block_subsidy(template.height);
        // With empty mempool, coinbase_value should equal the subsidy alone
        assert_eq!(template.coinbase_value, expected_subsidy);
        assert_eq!(template.coinbase_value, 50 * 100_000_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_bits_regtest() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_prev_hash() {
        let (cs, mp, dir) = make_template_env();

        let tip_hash = cs.tip_hash();
        let template = create_template(&cs, &mp);
        // Template's prev_hash must be the current tip hash
        assert_eq!(template.prev_hash, tip_hash);
        // At genesis, that should be the regtest genesis hash
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(template.prev_hash, genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Dependency- and finality-aware selection (#588/#589) ──────────

    fn tx_spending(
        prev: bitcoin::OutPoint,
        out_value: u64,
        out_tag: u8,
        sequence: u32,
        locktime: u32,
    ) -> Transaction {
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[out_tag; 20]);
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        }
    }

    fn confirmed_prev(tag: u8) -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [tag; 32],
            )),
            vout: 0,
        }
    }

    fn coin_at(height: u32) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount: 100_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height,
            coinbase: false,
        }
    }

    #[test]
    fn a_cpfp_child_is_emitted_after_its_parent() {
        // The child pays a far higher fee rate — that is what CPFP means —
        // so pure fee-rate order put it *before* its parent and the mined
        // block was invalid (#589).
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA1), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA1), 50_000, 0x31, 0xffff_ffff, 0);
        let parent_txid =
            mp.insert_tx_weighted_for_test(parent, 100, 400, QuarantineScope::acting());
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x32,
            0xffff_ffff,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let order: Vec<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        let p = order.iter().position(|t| *t == parent_txid).expect("parent mined");
        let c = order.iter().position(|t| *t == child_txid).expect("child mined");
        assert!(
            p < c,
            "parent must precede the child it funds (order: {order:?})"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_child_whose_parent_is_not_includable_is_dropped() {
        // Parent quarantined `on template`; the child spends it. Including
        // the child alone spends an output that exists nowhere in the
        // block or the chain (#589).
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA2), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA2), 50_000, 0x33, 0xffff_ffff, 0);
        let parent_txid = mp.insert_tx_weighted_for_test(
            parent,
            100,
            400,
            QuarantineScope { relay: false, template: true },
        );
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x34,
            0xffff_ffff,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(!mined.contains(&parent_txid), "quarantined parent is not mined");
        assert!(
            !mined.contains(&child_txid),
            "child of an unmined mempool parent must be dropped with it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_nonfinal_transaction_is_never_templated() {
        // Admission refuses these since #588, but a reorg can lower the
        // tip after admission and a persisted mempool can predate the
        // check — the template must filter regardless.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xA3), coin_at(0)),
            (confirmed_prev(0xA4), coin_at(0)),
        ]);

        let nonfinal = tx_spending(confirmed_prev(0xA3), 50_000, 0x35, 0, 1_000_000);
        let nonfinal_txid =
            mp.insert_tx_weighted_for_test(nonfinal, 50_000, 400, QuarantineScope::acting());
        let fine = tx_spending(confirmed_prev(0xA4), 50_000, 0x36, 0xffff_ffff, 0);
        let fine_txid =
            mp.insert_tx_weighted_for_test(fine, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&nonfinal_txid),
            "a non-final transaction would make the mined block invalid"
        );
        assert!(mined.contains(&fine_txid), "the final one is unaffected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_child_of_an_evicted_parent_is_dropped() {
        // The parent was evicted after the child was admitted (expiry,
        // RBF, block-connect conflict): its txid is in neither the
        // mempool nor the UTXO set. "Not in mempool" must not be read as
        // "confirmed" — mining the orphan makes the block invalid with
        // bad-txns-inputs-missingorspent.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA6), coin_at(0))]);

        let orphan = tx_spending(confirmed_prev(0xA5), 50_000, 0x37, 0xffff_ffff, 0);
        let orphan_txid =
            mp.insert_tx_weighted_for_test(orphan, 50_000, 400, QuarantineScope::acting());
        let fine = tx_spending(confirmed_prev(0xA6), 50_000, 0x38, 0xffff_ffff, 0);
        let fine_txid = mp.insert_tx_weighted_for_test(fine, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&orphan_txid),
            "a spend of a nonexistent coin must never be templated"
        );
        assert!(mined.contains(&fine_txid), "the resolvable one is unaffected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsatisfied_sequence_lock_is_never_templated() {
        // Both spend a coin confirmed at height 0; the template is for
        // height 1, so one block has elapsed. A 10-block sequence lock is
        // unsatisfied — mining it yields a SequenceLockNotMet block. Like
        // the absolute-finality re-check, admission (#588) normally
        // prevents this, but a reorg-lowered tip or a persisted mempool
        // does not re-run admission.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xA7), coin_at(0)),
            (confirmed_prev(0xA8), coin_at(0)),
        ]);

        let locked = tx_spending(confirmed_prev(0xA7), 50_000, 0x39, 10, 0);
        let locked_txid =
            mp.insert_tx_weighted_for_test(locked, 50_000, 400, QuarantineScope::acting());
        let elapsed = tx_spending(confirmed_prev(0xA8), 50_000, 0x3A, 1, 0);
        let elapsed_txid =
            mp.insert_tx_weighted_for_test(elapsed, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&locked_txid),
            "an unsatisfied BIP 68 lock would make the mined block invalid"
        );
        assert!(
            mined.contains(&elapsed_txid),
            "a one-block lock on a height-0 coin is satisfied at height 1"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sequence_lock_counted_from_an_in_template_parent_is_unsatisfiable() {
        // The child's coin would be born in this very block, so zero
        // blocks have elapsed — any nonzero height lock fails. The parent
        // itself is unaffected.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA9), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA9), 50_000, 0x3B, 0xffff_ffff, 0);
        let parent_txid =
            mp.insert_tx_weighted_for_test(parent, 100, 400, QuarantineScope::acting());
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x3C,
            1,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(mined.contains(&parent_txid), "the parent is mineable");
        assert!(
            !mined.contains(&child_txid),
            "a nonzero lock on a same-block parent can never be satisfied"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // PR 5: a transaction quarantined `on template` is held but never selected
    // into a block this node builds (design §2.4/§3).
    #[test]
    fn test_template_excludes_template_quarantined() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_template_env();

        let acting = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let relay_only =
            mp.insert_scoped_for_test(2, 100, QuarantineScope { relay: true, template: false });
        // High fee rate — if scope were ignored it would sort to the top.
        let template_only =
            mp.insert_scoped_for_test(3, 100_000, QuarantineScope { relay: false, template: true });

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> =
            template.transactions.iter().map(|t| t.tx.compute_txid()).collect();

        assert!(mined.contains(&acting), "acting tx is mined");
        assert!(mined.contains(&relay_only), "on-relay tx is still mineable by us");
        assert!(
            !mined.contains(&template_only),
            "on-template tx is excluded even at a far higher fee rate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
