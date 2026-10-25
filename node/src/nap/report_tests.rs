use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{Amount, BlockHash};
use serde_json::Value;

use super::report::*;
use super::tests::*;
use super::validity::{Coin, Timelocks, verify_signature};
use super::*;

/// A coin of `sat` for `signer`, confirmed at `height`.
fn coin_of(signer: &Signer, sat: u64, height: u32) -> Coin {
    Coin { value: Amount::from_sat(sat), script_pubkey: signer.spk.clone(), height, coinbase: false }
}

/// `atts` with the timelocks their signatures leave, as the aggregator
/// holds them.
fn verified(chain: &Chain, atts: &[Attestation]) -> Vec<(Attestation, Timelocks)> {
    atts.iter()
        .map(|a| {
            let script = &chain.coins[&a.outpoint()].script_pubkey;
            (a.clone(), verify_signature(a, script).unwrap())
        })
        .collect()
}

/// The report on `atts` at `chain`'s tip.
fn report_on(chain: &Chain, atts: &[Attestation]) -> Value {
    let held = verified(chain, atts);
    let set = canonical(atts.iter().cloned());
    let (tip, counting) = counting_at(&held, chain);
    report(tip, digest(&set), set.len(), 0, &counting)
}

/// The report's entry for `key`.
fn key<'a>(r: &'a Value, key: &str) -> &'a Value {
    r["keys"].as_array().unwrap().iter().find(|k| k["key"] == key).unwrap()
}

/// The entry for `value` of `key`.
fn value<'a>(r: &'a Value, k: &str, v: &str) -> &'a Value {
    key(r, k)["values"].as_array().unwrap().iter().find(|e| e["value"] == v).unwrap()
}

/// The bucket labelled `label` in `buckets`, as (weight, outpoints).
fn bucket(buckets: &Value, field: &str, label: &str) -> (u64, u64) {
    let b = buckets.as_array().unwrap().iter().find(|b| b[field] == label).unwrap();
    (b["weight_sat"].as_u64().unwrap(), b["outpoints"].as_u64().unwrap())
}

#[test]
fn one_coin_and_a_hundred_coins_of_the_same_value_weigh_the_same() {
    let s = p2wpkh();
    let mut one = Chain::new();
    one.coins.insert(outpoint(1), coin_of(&s, 100_000_000, COIN_HEIGHT));
    let mut split = Chain::new();
    for n in 1..=100 {
        split.coins.insert(outpoint(n), coin_of(&s, 1_000_000, COIN_HEIGHT));
    }
    let whole = report_on(&one, &[attest(&one, &s, outpoint(1), "k", "yes", ANCHOR)]);
    let parts: Vec<Attestation> = (1..=100).map(|n| attest(&split, &s, outpoint(n), "k", "yes", ANCHOR)).collect();
    let parts = report_on(&split, &parts);
    assert_eq!(value(&whole, "k", "yes")["weight_sat"], 100_000_000);
    assert_eq!(value(&parts, "k", "yes")["weight_sat"], value(&whole, "k", "yes")["weight_sat"]);
    assert_eq!(key(&parts, "k")["weight_sat"], key(&whole, "k")["weight_sat"]);
    assert_eq!(
        (value(&whole, "k", "yes")["outpoints"].as_u64(), value(&parts, "k", "yes")["outpoints"].as_u64()),
        (Some(1), Some(100)),
        "outpoints are counted, but they carry no weight of their own"
    );
}

#[test]
fn the_same_set_gives_the_same_bytes_in_any_order() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    for n in 1..=6 {
        chain.coins.insert(outpoint(n), coin_of(&s, 20_000 * u64::from(n), COIN_HEIGHT));
    }
    let mut atts: Vec<Attestation> = (1..=6)
        .map(|n| attest(&chain, &s, outpoint(n), "k", if n % 2 == 0 { "yes" } else { "no" }, ANCHOR))
        .collect();
    atts.push(attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 50));
    atts.push(attest(&chain, &s, outpoint(2), "other", "x", ANCHOR));
    let forward = serde_json::to_string(&report_on(&chain, &atts)).unwrap();
    atts.reverse();
    // A repeat is one attestation, as in the set.
    atts.push(atts[0].clone());
    let backward = serde_json::to_string(&report_on(&chain, &atts)).unwrap();
    assert_eq!(forward, backward);
}

#[test]
fn a_snapshot_round_trips_and_replays_the_same_report() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    for n in 1..=3 {
        chain.coins.insert(outpoint(n), coin_of(&s, 50_000, COIN_HEIGHT));
    }
    let atts: Vec<Attestation> = vec![
        attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR),
        attest(&chain, &s, outpoint(1), "k", "no", ANCHOR - 10),
        attest(&chain, &s, outpoint(2), "k", "no", ANCHOR),
        attest(&chain, &s, outpoint(3), "k", "", ANCHOR),
    ];
    let set = canonical(atts.iter().cloned());
    let tip_hash = chain.block_hash(TIP).unwrap();
    let file = encode_snapshot(TIP, tip_hash, &set);
    let snap = decode_snapshot(&file, 0).unwrap();
    assert_eq!(snap, Snapshot { height: TIP, hash: tip_hash, attestations: set.clone() });
    assert_eq!(report_on(&chain, &snap.attestations), report_on(&chain, &atts));
    // The digest names the set, not the tip it was exported at.
    let elsewhere = decode_snapshot(&encode_snapshot(7, BlockHash::all_zeros(), &set), 0).unwrap();
    assert_eq!(digest(&elsewhere.attestations), digest(&set));
    assert_eq!(report_on(&chain, &atts)["digest"], digest(&set).to_string());
}

#[test]
fn the_digest_is_over_length_prefixed_wire_forms_in_id_order() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let a = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let b = attest(&chain, &s, outpoint(1), "k", "no", ANCHOR);
    let set = canonical([a.clone(), b.clone()]);
    assert!(set[0].id() < set[1].id());
    let mut bytes = Vec::new();
    for att in &set {
        let wire = att.to_bytes();
        assert!(wire.len() < 0xfd, "a one-byte compact size");
        bytes.push(wire.len() as u8);
        bytes.extend_from_slice(&wire);
    }
    assert_eq!(digest(&set), bitcoin::hashes::sha256::Hash::hash(&bytes));
}

#[test]
fn a_snapshot_has_one_form() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let set = canonical([
        attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR),
        attest(&chain, &s, outpoint(1), "k", "no", ANCHOR),
    ]);
    let hash = BlockHash::all_zeros();
    let good = encode_snapshot(TIP, hash, &set);
    assert!(decode_snapshot(&good, 0).is_ok());
    assert!(decode_snapshot(&good, 2).is_ok());
    assert!(decode_snapshot(&good, 1).unwrap_err().contains("more than the 1"));

    let unordered = encode_snapshot(TIP, hash, &[set[1].clone(), set[0].clone()]);
    assert!(decode_snapshot(&unordered, 0).unwrap_err().contains("ascending id order"));
    let repeated = encode_snapshot(TIP, hash, &[set[0].clone(), set[0].clone()]);
    assert!(decode_snapshot(&repeated, 0).unwrap_err().contains("ascending id order"));

    let mut corrupt = good.clone();
    corrupt[60] ^= 1;
    assert!(decode_snapshot(&corrupt, 0).unwrap_err().contains("checksum"));
    assert!(decode_snapshot(&good[..good.len() - 1], 0).is_err());
    assert!(decode_snapshot(b"SNAG", 0).unwrap_err().contains("truncated"));

    // A byte more inside the checksummed body.
    let mut long = good[..good.len() - 32].to_vec();
    long.push(0);
    let checksum = bitcoin::hashes::sha256::Hash::hash(&long);
    long.extend_from_slice(checksum.as_byte_array());
    assert!(decode_snapshot(&long, 0).unwrap_err().contains("follow the last entry"));
}

#[test]
fn the_newest_valid_attestation_counts_and_a_lost_anchor_brings_back_the_older() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let old = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 100);
    let new = attest(&chain, &s, outpoint(1), "k", "no", ANCHOR);
    let atts = [old, new];
    let r = report_on(&chain, &atts);
    assert_eq!(r["counting"], 1);
    assert_eq!(value(&r, "k", "no")["weight_sat"], 50_000);
    assert!(key(&r, "k")["values"].as_array().unwrap().iter().all(|v| v["value"] != "yes"));

    // Reorganised from below the newer anchor: the older one counts.
    let held = verified(&chain, &atts);
    chain.fork_at = ANCHOR - 50;
    let set = canonical(atts.iter().cloned());
    let (tip, counting) = counting_at(&held, &chain);
    let r = report(tip, digest(&set), set.len(), 0, &counting);
    assert_eq!(value(&r, "k", "yes")["weight_sat"], 50_000);
    assert_eq!(r["hash"], chain.block_hash(TIP).unwrap().to_string());
}

#[test]
fn spent_coins_and_unmet_timelocks_do_not_count() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    chain.coins.insert(outpoint(2), coin_of(&s, 60_000, COIN_HEIGHT));
    let atts = [
        attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR),
        attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR),
    ];
    let held = verified(&chain, &atts);
    chain.coins.remove(&outpoint(2));
    let (_, counting) = counting_at(&held, &chain);
    assert_eq!(counting.len(), 1);
    assert_eq!(counting[0].attestation.outpoint(), outpoint(1));

    // A full proof whose locktime is past the next block.
    let locked = p2wsh_full(Builder::new(), 2, TIP + 10, 0xFFFF_FFFE);
    chain.coins.insert(outpoint(3), coin_of(&locked, 70_000, COIN_HEIGHT));
    let att = attest(&chain, &locked, outpoint(3), "k", "yes", ANCHOR);
    let (_, counting) = counting_at(&verified(&chain, &[att]), &chain);
    assert!(counting.is_empty(), "not yet valid counts nothing");
}

#[test]
fn withdrawals_are_reported_apart_and_take_no_share() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 300_000, COIN_HEIGHT));
    chain.coins.insert(outpoint(2), coin_of(&s, 100_000, COIN_HEIGHT));
    chain.coins.insert(outpoint(3), coin_of(&s, 600_000, COIN_HEIGHT));
    let r = report_on(
        &chain,
        &[
            attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR),
            attest(&chain, &s, outpoint(2), "k", "no", ANCHOR),
            attest(&chain, &s, outpoint(3), "k", "", ANCHOR),
        ],
    );
    let k = key(&r, "k");
    assert_eq!(k["withdrawn"], serde_json::json!({ "weight_sat": 600_000, "outpoints": 1 }));
    assert_eq!(k["weight_sat"], 400_000);
    assert_eq!(k["outpoints"], 2);
    assert_eq!(value(&r, "k", "yes")["share_ppm"], 750_000);
    assert_eq!(value(&r, "k", "no")["share_ppm"], 250_000);
    assert!(k["values"].as_array().unwrap().iter().all(|v| v["value"] != ""));
    // The mock's UTXO set is twice the coins: 2,000,000 sats.
    assert_eq!(r["utxo_total_sat"], 2_000_000);
    assert_eq!(k["coverage_ppm"], 200_000);
    assert_eq!(value(&r, "k", "yes")["coverage_ppm"], 150_000);
    // Heaviest value first.
    assert_eq!(k["values"][0]["value"], "yes");
}

#[test]
fn shares_round_down_in_parts_per_million() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    for n in 1..=3 {
        chain.coins.insert(outpoint(n), coin_of(&s, 100_000, COIN_HEIGHT));
    }
    let r = report_on(
        &chain,
        &[
            attest(&chain, &s, outpoint(1), "k", "a", ANCHOR),
            attest(&chain, &s, outpoint(2), "k", "b", ANCHOR),
            attest(&chain, &s, outpoint(3), "k", "c", ANCHOR),
        ],
    );
    for v in ["a", "b", "c"] {
        assert_eq!(value(&r, "k", v)["share_ppm"], 333_333, "1/3 rounds down");
    }
    // Equal weights are ordered by value.
    let order: Vec<&str> = key(&r, "k")["values"].as_array().unwrap().iter().map(|v| v["value"].as_str().unwrap()).collect();
    assert_eq!(order, ["a", "b", "c"]);
}

#[test]
fn breakdowns_file_each_coin_by_value_ages_and_script() {
    let w = p2wpkh();
    let l = p2pkh();
    let mut chain = Chain::new();
    // Long enough for the oldest coin age bucket.
    chain.tip = 300_000;
    let tip = chain.tip;
    // (coin, signer, value: each tier at its lower bound or just under the
    // next, coin age at the tip, anchor age).
    let coins = [
        (1, &w, 999_999, 13_103, ANCHOR_DEPTH),
        (2, &w, 1_000_000, 13_104, 2_016),
        (3, &l, 100_000_000, 262_079, 13_104),
        (4, &w, 10_000_000_000, 262_080, ANCHOR_DEPTH),
    ];
    let mut atts = Vec::new();
    for (n, signer, sat, coin_age, anchor_age) in coins {
        chain.coins.insert(outpoint(n), coin_of(signer, sat, tip - coin_age));
        atts.push(attest(&chain, signer, outpoint(n), "k", "yes", tip - anchor_age));
    }
    let r = report_on(&chain, &atts);
    let v = value(&r, "k", "yes");
    let tiers = &v["value_tiers"];
    assert_eq!(bucket(tiers, "tier", "<0.01"), (999_999, 1));
    assert_eq!(bucket(tiers, "tier", "0.01-1"), (1_000_000, 1));
    assert_eq!(bucket(tiers, "tier", "1-100"), (100_000_000, 1));
    assert_eq!(bucket(tiers, "tier", ">=100"), (10_000_000_000, 1));

    let ages = &v["anchor_age"];
    assert_eq!(bucket(ages, "blocks", "<2016"), (999_999 + 10_000_000_000, 2));
    assert_eq!(bucket(ages, "blocks", "<13104"), (1_000_000, 1));
    assert_eq!(bucket(ages, "blocks", "<26208"), (100_000_000, 1));

    let ages = &v["coin_age"];
    assert_eq!(bucket(ages, "blocks", "<13104"), (999_999, 1));
    assert_eq!(bucket(ages, "blocks", "<52416"), (1_000_000, 1));
    assert_eq!(bucket(ages, "blocks", "<104832"), (0, 0), "an empty bucket is listed");
    assert_eq!(bucket(ages, "blocks", "<262080"), (100_000_000, 1));
    assert_eq!(bucket(ages, "blocks", ">=262080"), (10_000_000_000, 1));

    let scripts = &v["script_types"];
    assert_eq!(bucket(scripts, "type", "p2pkh"), (100_000_000, 1));
    assert_eq!(bucket(scripts, "type", "p2wpkh"), (999_999 + 1_000_000 + 10_000_000_000, 3));
    assert_eq!(bucket(scripts, "type", "p2tr"), (0, 0));
    assert_eq!(scripts.as_array().unwrap().len(), 6);
}

#[test]
fn concentration_is_the_largest_outpoints_share_of_a_value() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    // Coin n holds n × 10,000 sats: 110 coins, 61,050,000 sats in all.
    for n in 1..=110u8 {
        chain.coins.insert(outpoint(n), coin_of(&s, 10_000 * u64::from(n), COIN_HEIGHT));
    }
    let atts: Vec<Attestation> = (1..=110).map(|n| attest(&chain, &s, outpoint(n), "k", "yes", ANCHOR)).collect();
    let r = report_on(&chain, &atts);
    let c = &value(&r, "k", "yes")["concentration"];
    let total: u64 = (1..=110).map(|n| 10_000 * n).sum();
    let top10: u64 = (101..=110).map(|n| 10_000 * n).sum();
    let top100: u64 = (11..=110).map(|n| 10_000 * n).sum();
    assert_eq!(c["top10_ppm"], top10 * 1_000_000 / total);
    assert_eq!(c["top100_ppm"], top100 * 1_000_000 / total);
}

// --- Round 1 fixes --------------------------------------------------------------

/// A chain that shows `chains[i]` at its `i`th read, and the last one after.
struct Moving<'a> {
    chains: Vec<&'a Chain>,
    reads: std::cell::Cell<usize>,
}

impl super::publisher::ChainSource for Moving<'_> {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        let i = self.reads.get();
        self.reads.set(i + 1);
        Some(read(self.chains[i.min(self.chains.len() - 1)]))
    }
}

#[test]
fn a_replay_reads_again_when_a_block_lands_between_its_reads() {
    let s = p2wpkh();
    let mut before = Chain::new();
    before.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let mut after = Chain::new();
    after.tip = TIP + 1;
    after.coins = before.coins.clone();
    // A coin the block brings back, as a reorg can.
    after.coins.insert(outpoint(2), coin_of(&s, 70_000, COIN_HEIGHT));
    let atts = canonical([
        attest(&after, &s, outpoint(1), "k", "yes", ANCHOR),
        attest(&after, &s, outpoint(2), "k", "yes", ANCHOR),
    ]);
    // The coins read before the block, the set judged after it.
    let moving = Moving { chains: vec![&before, &after], reads: Default::default() };
    let replay = replay(&moving, &atts).unwrap();
    assert_eq!(replay.tip.height, TIP + 1);
    assert_eq!(replay.counting.len(), 2, "the coin read before the block is judged with the rest");
    let held = verified(&after, &atts);
    let (tip, counting) = counting_at(&held, &after);
    assert_eq!(
        serde_json::to_string(&report(replay.tip, digest(&atts), atts.len(), replay.invalid, &replay.counting))
            .unwrap(),
        serde_json::to_string(&report(tip, digest(&atts), atts.len(), 0, &counting)).unwrap(),
        "the same bytes as the live set at that tip"
    );
}

#[test]
fn a_replay_gives_up_on_a_chain_that_never_holds_still() {
    let s = p2wpkh();
    let mut chains: Vec<Chain> = Vec::new();
    for n in 0..10 {
        let mut c = Chain::new();
        c.tip = TIP + n;
        c.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
        chains.push(c);
    }
    let atts = [attest(&chains[0], &s, outpoint(1), "k", "yes", ANCHOR)];
    let moving = Moving { chains: chains.iter().collect(), reads: Default::default() };
    assert!(replay(&moving, &atts).is_none());
}

#[test]
fn a_replay_counts_failed_signatures_only_for_coins_it_holds() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let good = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let other = attest(&chain, &s, outpoint(1), "k", "no", ANCHOR);
    let forge = |op| {
        Attestation::new(op, "k".into(), "no".into(), ANCHOR, chain.block_hash(ANCHOR).unwrap(), good.signature().clone())
            .unwrap()
    };
    // Coin 1's "no" with the "yes" signature, and the same for a coin that
    // is not in the UTXO set.
    let atts = canonical([good.clone(), forge(outpoint(1)), forge(outpoint(9))]);
    assert_ne!(forge(outpoint(1)).id(), other.id());
    let moving = Moving { chains: vec![&chain], reads: Default::default() };
    let replay = replay(&moving, &atts).unwrap();
    assert_eq!(replay.invalid, 1);
    assert_eq!(replay.counting.len(), 1);
    assert_eq!(replay.counting[0].attestation, good);
}

#[test]
fn a_snapshot_file_too_long_for_its_limit_is_refused_before_it_is_read() {
    let s = p2wpkh();
    let mut chain = Chain::new();
    chain.coins.insert(outpoint(1), coin_of(&s, 50_000, COIN_HEIGHT));
    let set = canonical([attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR)]);
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.dat");
    std::fs::write(&good, encode_snapshot(TIP, BlockHash::all_zeros(), &set)).unwrap();
    assert_eq!(read_snapshot(&good, 1).unwrap().attestations, set);
    assert_eq!(read_snapshot(&good, 0).unwrap().attestations, set);

    // One byte longer than any snapshot of one attestation.
    let long = dir.path().join("long.dat");
    std::fs::write(&long, vec![0u8; 4 + 4 + 4 + 32 + 4 + 32 + 3 + MAX_ATTESTATION_SIZE + 1]).unwrap();
    assert!(read_snapshot(&long, 1).unwrap_err().contains("longer than a snapshot of 1"));
    assert!(read_snapshot(&dir.path().join("missing.dat"), 1).unwrap_err().contains("reading"));
    // A limit too large to multiply out is no limit, not a panic.
    assert_eq!(read_snapshot(&good, usize::MAX).unwrap().attestations, set);
}

#[test]
fn an_export_never_replaces_a_file_and_leaves_no_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("snap.dat");
    write_new(&path, b"first").unwrap();
    let err = write_new(&path, b"second").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, ["snap.dat"]);
}

#[test]
fn without_hard_links_an_export_writes_in_place_and_still_never_replaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.dat");
    let no_links = |_: &std::path::Path, _: &std::path::Path| {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    };
    write_new_linking(&path, b"first", no_links).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    let err = write_new_linking(&path, b"second", no_links).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, ["snap.dat"], "no temporary is left");
    // Any other link failure is the export's.
    let other = |_: &std::path::Path, _: &std::path::Path| Err(std::io::Error::other("disk on fire"));
    assert!(write_new_linking(&dir.path().join("b.dat"), b"x", other).is_err());
    assert!(!dir.path().join("b.dat").exists());
}

// --- Read-only reports and the snapshot buffer ----------------------------------

#[test]
fn a_cached_report_is_served_again_until_the_tip_or_the_set_changes() {
    let cache = Cache::default();
    let computed = std::cell::Cell::new(0);
    let t0 = std::time::Instant::now();
    let later = t0 + REPORT_REUSE;
    let tip = BlockHash::from_byte_array([1; 32]);
    let other = BlockHash::from_byte_array([2; 32]);
    let ask = |tip: BlockHash, changes: u64, now| {
        cache
            .get_or::<()>(tip, changes, now, || {
                computed.set(computed.get() + 1);
                Ok((tip, serde_json::json!({ "n": computed.get() })))
            })
            .unwrap()
    };
    assert_eq!(ask(tip, 7, t0)["n"], 1);
    assert_eq!(ask(tip, 7, later)["n"], 1, "served again, however late, while nothing changed");
    assert_eq!(ask(tip, 8, later)["n"], 2, "the set changed and the report is old");
    assert_eq!(ask(other, 8, later)["n"], 3, "the tip moved");
    assert_eq!(ask(other, 8, later)["n"], 3);
    assert_eq!(computed.get(), 3);
    // A failed computation is not cached.
    assert!(cache.get_or(tip, 9, later, || Err::<(BlockHash, Value), _>("busy")).is_err());
    assert_eq!(ask(tip, 9, later)["n"], 4);
}

#[test]
fn a_changing_set_is_reported_on_at_most_once_per_reuse_interval() {
    let cache = Cache::default();
    let computed = std::cell::Cell::new(0);
    let t0 = std::time::Instant::now();
    let tip = BlockHash::from_byte_array([1; 32]);
    let ask = |changes: u64, now| {
        cache
            .get_or::<()>(tip, changes, now, || {
                computed.set(computed.get() + 1);
                Ok((tip, serde_json::json!(computed.get())))
            })
            .unwrap()
    };
    // Collection changes the set before every call.
    for (n, secs) in (0..30).enumerate() {
        ask(n as u64, t0 + std::time::Duration::from_secs(secs));
    }
    assert_eq!(computed.get(), 1, "one report in the first interval");
    ask(30, t0 + REPORT_REUSE);
    assert_eq!(computed.get(), 2);
    // A new tip is reported on at once.
    cache.get_or::<()>(BlockHash::from_byte_array([2; 32]), 31, t0 + REPORT_REUSE, || {
        computed.set(computed.get() + 1);
        Ok((BlockHash::from_byte_array([2; 32]), serde_json::json!(0)))
    })
    .unwrap();
    assert_eq!(computed.get(), 3);
}

#[test]
fn a_cached_report_is_filed_under_the_tip_it_judged_at() {
    let cache = Cache::default();
    let now = std::time::Instant::now();
    let asked = BlockHash::from_byte_array([1; 32]);
    let judged = BlockHash::from_byte_array([2; 32]);
    // The tip moved between the caller's read and the judging.
    cache.get_or::<()>(asked, 1, now, || Ok((judged, serde_json::json!(1)))).unwrap();
    let again = cache.get_or::<()>(asked, 1, now, || Ok((asked, serde_json::json!(2)))).unwrap();
    assert_eq!(again, 2, "not served for a tip it was not judged at");
    let at_judged = cache.get_or::<()>(asked, 1, now, || Ok((asked, serde_json::json!(3)))).unwrap();
    assert_eq!(at_judged, 2);
}

#[test]
fn the_smallest_entry_is_at_least_min_entry_len() {
    let att = Attestation::new(
        outpoint(1),
        "k".into(),
        String::new(),
        ANCHOR,
        BlockHash::all_zeros(),
        NapSignature::Simple(bitcoin::Witness::new()),
    )
    .unwrap();
    // Its length prefix is one byte.
    assert!(1 + att.to_bytes().len() >= report::MIN_ENTRY_LEN, "{}", att.to_bytes().len());
}

#[test]
fn a_snapshot_reserves_room_only_for_the_entries_its_bytes_can_hold() {
    // A file that claims u32::MAX entries in a megabyte.
    assert_eq!(report::room_for(u32::MAX as usize, 1_000_000), 1_000_000 / report::MIN_ENTRY_LEN);
    assert_eq!(report::room_for(3, 1_000_000), 3);
    assert_eq!(report::room_for(5, 10), 0);
}
