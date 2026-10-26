use std::path::PathBuf;

use bitcoin::hashes::{Hash as _, sha256};

use super::publisher::{COLDCARD_MESSAGE_LIMIT, Report, encode_signature, transition};
use super::tests::*;
use super::validity::{ChainView, Coin};
use super::*;

impl ChainSource for Chain {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        Some(read(self))
    }
}

/// A store path in a fresh directory, which the test keeps alive.
fn store_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nap").join("attestations.dat");
    (dir, path)
}

/// A chain holding coin `n` for `signer`, and an attestation for it.
fn coin(chain: &mut Chain, signer: &Signer, n: u8) -> OutPoint {
    let op = outpoint(n);
    chain.coins.insert(
        op,
        Coin { value: VALUE, script_pubkey: signer.spk.clone(), height: COIN_HEIGHT, coinbase: false },
    );
    op
}

/// What the store on disk holds: the file with its journal applied, as the
/// publisher opens it before judging anything.
fn on_disk(path: &std::path::Path) -> Vec<Attestation> {
    let opened = store::read(path).unwrap();
    let mut held = std::collections::BTreeMap::new();
    for att in opened.base {
        held.insert((att.outpoint(), att.key().to_owned()), att);
    }
    for record in opened.records {
        match record {
            store::Record::Put(att) => {
                held.insert((att.outpoint(), att.key().to_owned()), att);
            }
            store::Record::Remove(outpoint, key) => {
                held.remove(&(outpoint, key));
            }
        }
    }
    held.into_values().collect()
}

fn submit(p: &Publisher, chain: &Chain, att: &Attestation) -> Result<Option<sha256::Hash>, PublishError> {
    p.submit(chain, &att.message(), &encode_signature(att.signature())).map(|(_, replaced)| replaced)
}

fn rule(r: Result<impl std::fmt::Debug, PublishError>) -> &'static str {
    r.unwrap_err().rule()
}

#[test]
fn a_submitted_attestation_is_stored_and_survives_a_reload() {
    let (_dir, path) = store_path();
    let (mut chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    let legacy = p2pkh();
    let op = coin(&mut chain, &legacy, 9);
    let legacy_att = attest(&chain, &legacy, op, "k", "v", ANCHOR);

    let p = Publisher::open(path.clone(), &chain).unwrap();
    assert_eq!(submit(&p, &chain, &att), Ok(None));
    assert_eq!(submit(&p, &chain, &legacy_att), Ok(None));
    assert!(store::journal_path(&path).exists());
    assert!(!path.with_extension("dat.tmp").exists(), "no temporary file left behind");
    assert!(!path.with_extension("journal.tmp").exists(), "no temporary file left behind");

    let p = Publisher::open(path, &chain).unwrap();
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].attestation, att);
    assert_eq!(listed[0].status, Some(Ok(VALUE)));
    assert_eq!(listed[1].attestation, legacy_att);
    assert_eq!(p.serving().len(), 2);
}

/// D14: `smp`, `ful`, unprefixed (simple for segwit, legacy for P2PKH), the
/// full proof as a raw transaction in hex; not `pof`.
#[test]
fn signature_strings_by_prefix() {
    let (_dir, path) = store_path();
    let (mut chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();
    let smp = encode_signature(att.signature());
    assert!(smp.starts_with("smp"));
    assert!(p.submit(&chain, &att.message(), &smp[3..]).is_ok(), "unprefixed is simple for P2WPKH");

    let full = p2wsh_full(bitcoin::script::Builder::new(), 0, 0, 0);
    let op = coin(&mut chain, &full, 8);
    let full_att = attest(&chain, &full, op, "k", "v", ANCHOR);
    assert!(encode_signature(full_att.signature()).starts_with("ful"));
    assert_eq!(submit(&p, &chain, &full_att), Ok(None));

    // The signed `to_sign` in hex, as Sparrow exports it, is the full proof.
    let hex_att = attest(&chain, &full, op, "k2", "v", ANCHOR);
    let NapSignature::Full(tx) = hex_att.signature() else { panic!("a full proof") };
    let hex = bitcoin::consensus::encode::serialize_hex(tx);
    let (stored, _) = p.submit(&chain, &hex_att.message(), &hex.to_uppercase()).unwrap();
    assert_eq!(stored.attestation, hex_att, "the same full proof");
    let bad = p.submit(&chain, &hex_att.message(), &hex[..hex.len() - 2]).unwrap_err();
    assert_eq!(bad.rule(), "format");
    assert!(bad.to_string().contains("neither a transaction in hex"), "{bad}");

    let legacy = p2pkh();
    let op = coin(&mut chain, &legacy, 9);
    let legacy_att = attest(&chain, &legacy, op, "k", "v", ANCHOR);
    let legacy_sig = encode_signature(legacy_att.signature());
    assert!(!legacy_sig.starts_with("smp") && !legacy_sig.starts_with("ful"));
    assert_eq!(submit(&p, &chain, &legacy_att), Ok(None));
    // Unprefixed is simple for a segwit coin, so a legacy signature fails.
    assert!(p.submit(&chain, &att.message().replace("value: yes", "value: no"), &legacy_sig).is_err());

    let pof = p.submit(&chain, &att.message(), "pofAAAA").unwrap_err();
    assert_eq!(pof.rule(), "format");
    assert!(pof.to_string().contains("sign without extra inputs"), "{pof}");
}

#[test]
fn rejections_name_the_rule() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();
    let sig = encode_signature(att.signature());

    assert_eq!(rule(p.submit(&chain, "not a message", &sig)), "format");
    assert_eq!(rule(p.submit(&chain, &att.message(), "smp!!")), "format");
    let wrong_value = att.message().replace("value: yes", "value: no");
    assert_eq!(rule(p.submit(&chain, &wrong_value, &sig)), "signature-invalid");

    let op = coin(&mut chain, &signer, 8);
    chain.coins.get_mut(&op).unwrap().height = ANCHOR - MIN_COIN_AGE + 1;
    let young = attest(&chain, &signer, op, "young", "yes", ANCHOR);
    assert_eq!(rule(submit(&p, &chain, &young)), "coin-too-young");
    chain.fork_at = ANCHOR;
    assert_eq!(rule(submit(&p, &chain, &att)), "anchor-not-on-chain");
    chain.fork_at = u32::MAX;
    chain.tip = ANCHOR + FRESHNESS_WINDOW;
    assert_eq!(rule(submit(&p, &chain, &att)), "stale");
    chain.tip = TIP;
    chain.coins.clear();
    assert_eq!(rule(submit(&p, &chain, &att)), "coin-not-found");
    assert!(p.list(&chain).is_empty(), "nothing rejected was stored");
}

#[test]
fn one_attestation_per_key_and_the_newer_one_wins() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, old) = setup(&signer, COIN_HEIGHT, ANCHOR - 100);
    let new = attest(&chain, &signer, old.outpoint(), old.key(), "no", ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();

    assert_eq!(submit(&p, &chain, &old), Ok(None));
    assert_eq!(submit(&p, &chain, &old), Ok(None), "the same attestation again changes nothing");
    assert_eq!(submit(&p, &chain, &new), Ok(Some(old.id())));
    assert_eq!(
        submit(&p, &chain, &old),
        Err(PublishError::Superseded { anchor_height: ANCHOR }),
    );
    assert_eq!(p.list(&chain)[0].attestation, new);

    // Once the newer one has lost its anchor, the older one may come back.
    chain.fork_at = ANCHOR - 10;
    assert_eq!(submit(&p, &chain, &old), Ok(Some(new.id())));
    assert_eq!(p.list(&chain).len(), 1);
}

/// D3: at most 32 keys per outpoint.
#[test]
fn an_outpoint_holds_at_most_32_keys() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, _) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let op = outpoint(7);
    let other = coin(&mut chain, &signer, 8);
    let p = Publisher::open(path, &chain).unwrap();
    for i in 0..MAX_KEYS_PER_OUTPOINT {
        let att = attest(&chain, &signer, op, &format!("key{i}"), "yes", ANCHOR - 1);
        assert_eq!(submit(&p, &chain, &att), Ok(None), "key {i}");
    }
    let extra = attest(&chain, &signer, op, "one too many", "yes", ANCHOR);
    assert_eq!(submit(&p, &chain, &extra), Err(PublishError::KeyLimit));
    let draft = p.create(&chain, op, "one too many", "yes").unwrap();
    assert!(draft.warnings.iter().any(|w| w.contains("refuse")), "{:?}", draft.warnings);

    // Replacing one of the 32, or a key on another outpoint, is fine.
    let replace = attest(&chain, &signer, op, "key0", "no", ANCHOR);
    assert!(matches!(submit(&p, &chain, &replace), Ok(Some(_))));
    let elsewhere = attest(&chain, &signer, other, "one too many", "yes", ANCHOR);
    assert_eq!(submit(&p, &chain, &elsewhere), Ok(None));
    assert!(p.create(&chain, op, "key1", "x").unwrap().warnings.is_empty());
}

#[test]
fn create_anchors_below_the_tip_and_checks_the_coin() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, _) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let op = outpoint(7);
    let p = Publisher::open(path, &chain).unwrap();

    let draft = p.create(&chain, op, "bip_xyz.support", "yes").unwrap();
    assert_eq!(draft.anchor_height, TIP - ANCHOR_DEPTH);
    assert_eq!(Some(draft.anchor_hash), chain.block_hash(TIP - ANCHOR_DEPTH));
    assert_eq!(draft.message, message::render(&op, "bip_xyz.support", "yes", draft.anchor_height, &draft.anchor_hash));
    assert!(draft.warnings.is_empty());
    // A message signed as drafted is accepted.
    let text = (signer.sign)(&draft.message);
    let p_ok = p.submit(&chain, &draft.message, &encode_signature(&text));
    assert!(p_ok.is_ok(), "{p_ok:?}");

    // D16: over 330 characters, a Coldcard cannot sign it.
    let long = "v".repeat(MAX_VALUE_LEN);
    let draft = p.create(&chain, op, "a.much.longer.key", &long).unwrap();
    assert!(draft.message.len() > COLDCARD_MESSAGE_LIMIT);
    assert!(draft.warnings.iter().any(|w| w.contains("Coldcard")), "{:?}", draft.warnings);

    // The coin must hold enough to attest.
    let value = chain.coins[&op].value;
    chain.coins.get_mut(&op).unwrap().value = MIN_COIN_VALUE - bitcoin::Amount::ONE_SAT;
    assert_eq!(rule(p.create(&chain, op, "k", "v")), "coin-too-small");
    chain.coins.get_mut(&op).unwrap().value = MIN_COIN_VALUE;
    assert!(p.create(&chain, op, "k", "v").is_ok());
    chain.coins.get_mut(&op).unwrap().value = value;

    // The coin must be old enough at the anchor, not at the tip.
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - MIN_COIN_AGE + 1;
    assert_eq!(rule(p.create(&chain, op, "k", "v")), "coin-too-young");
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - MIN_COIN_AGE;
    assert!(p.create(&chain, op, "k", "v").is_ok());
    // A test network takes the short age, at the anchor too.
    chain.network = bitcoin::Network::Signet;
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - TEST_MIN_COIN_AGE + 1;
    assert_eq!(rule(p.create(&chain, op, "k", "v")), "coin-too-young");
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - TEST_MIN_COIN_AGE;
    assert!(p.create(&chain, op, "k", "v").is_ok());
    chain.network = bitcoin::Network::Bitcoin;

    assert_eq!(rule(p.create(&chain, outpoint(99), "k", "v")), "coin-not-found");
    assert_eq!(rule(p.create(&chain, op, "", "v")), "format");
    assert_eq!(rule(p.create(&chain, op, "k", "line\nbreak")), "format");
    chain.tip = ANCHOR_DEPTH - 1;
    assert_eq!(p.create(&chain, op, "k", "v").unwrap_err(), PublishError::ChainTooShort);
}

#[test]
fn a_new_tip_drops_spent_coins_and_keeps_the_rest() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let op2 = coin(&mut chain, &signer, 8);
    let kept = attest(&chain, &signer, op2, "k", "v", ANCHOR);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &att).unwrap();
    submit(&p, &chain, &kept).unwrap();

    // Behind the anchor (a reindex, say), a missing coin proves nothing.
    let mut behind = Chain::new();
    behind.tip = ANCHOR - 1;
    p.on_tip(&behind);
    assert_eq!(p.list(&chain).len(), 2);
    let reopened = Publisher::open(path.clone(), &behind).unwrap();
    assert_eq!(reopened.list(&chain).len(), 2, "a reload behind the anchor keeps everything");

    // On a fork without the anchor, a missing coin may be back on the
    // anchor's branch: kept, not served.
    let spent_coin = chain.coins.remove(&att.outpoint()).unwrap();
    chain.fork_at = ANCHOR;
    p.on_tip(&chain);
    assert_eq!(p.list(&chain).len(), 2);
    assert!(p.serving().is_empty(), "both anchors are off this fork");
    chain.fork_at = u32::MAX;
    chain.coins.insert(att.outpoint(), spent_coin);
    p.on_tip(&chain);
    assert_eq!(p.serving().len(), 2, "back on the anchor's branch, both are valid again");

    // On a chain holding the anchor, the coin was spent.
    chain.coins.remove(&att.outpoint());
    p.on_tip(&chain);
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attestation, kept);
    assert_eq!(on_disk(&path), vec![kept], "the drop was written");
}

#[test]
fn a_lost_anchor_or_a_stale_one_is_kept_but_not_served() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();
    submit(&p, &chain, &att).unwrap();
    assert_eq!(p.serving(), vec![att.clone()]);

    chain.fork_at = ANCHOR;
    // Listing between tips does not hide the change from the next tip.
    assert_eq!(p.list(&chain)[0].status, Some(Err(Rejection::AnchorNotOnChain)));
    assert_eq!(p.serving(), vec![att.clone()]);
    p.on_tip(&chain);
    assert!(p.serving().is_empty());
    assert_eq!(p.list(&chain)[0].status, Some(Err(Rejection::AnchorNotOnChain)));

    chain.fork_at = u32::MAX;
    p.on_tip(&chain);
    assert_eq!(p.serving(), vec![att.clone()], "back on the chain, served again");

    chain.tip = ANCHOR + FRESHNESS_WINDOW;
    p.on_tip(&chain);
    assert!(p.serving().is_empty());
    assert!(matches!(p.list(&chain)[0].status, Some(Err(Rejection::Stale { .. }))));
}

/// A coin's scriptPubKey never changes, so a signature is verified once.
#[test]
fn a_signature_is_verified_once() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();
    submit(&p, &chain, &att).unwrap();
    // A script no real coin could switch to: if the signature were checked
    // again, it would fail.
    chain.coins.get_mut(&att.outpoint()).unwrap().script_pubkey = p2pkh().spk;
    p.on_tip(&chain);
    assert_eq!(p.list(&chain)[0].status, Some(Ok(VALUE)));
}

/// An entry loaded from the store has no cached result; listing it verifies
/// the signature and keeps the result.
#[test]
fn listing_keeps_what_it_learned_about_a_signature() {
    let (_dir, path) = store_path();
    let (mut chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    store::save(&path, &store::encode([&att].into_iter())).unwrap();
    // Opened behind the anchor, so nothing is verified at open.
    let mut behind = Chain::new();
    behind.tip = ANCHOR - 1;
    let p = Publisher::open(path, &behind).unwrap();
    assert_eq!(p.list(&chain)[0].status, Some(Ok(VALUE)));
    chain.coins.get_mut(&att.outpoint()).unwrap().script_pubkey = p2pkh().spk;
    assert_eq!(p.list(&chain)[0].status, Some(Ok(VALUE)));
}

#[test]
fn removal_stops_publishing() {
    let (_dir, path) = store_path();
    let (chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &att).unwrap();
    assert_eq!(p.remove(att.outpoint(), "another key"), Err(PublishError::NotFound));
    assert_eq!(p.remove(att.outpoint(), att.key()), Ok(att.clone()));
    assert!(p.list(&chain).is_empty());
    assert!(Publisher::open(path, &chain).unwrap().list(&chain).is_empty());
}

#[test]
fn a_failed_write_changes_nothing() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let op = coin(&mut chain, &signer, 8);
    let other = attest(&chain, &signer, op, "k", "v", ANCHOR);
    store::save(&path, &store::encode([&att].into_iter())).unwrap();
    let p = Publisher::open(path.clone(), &chain).unwrap();
    // The journal's path is a directory, so every write fails putting the
    // journal in place.
    std::fs::create_dir(store::journal_path(&path)).unwrap();
    assert_eq!(rule(submit(&p, &chain, &other)), "io");
    assert_eq!(rule(p.remove(att.outpoint(), att.key())), "io");
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attestation, att);
    assert!(!path.with_extension("journal.tmp").exists(), "no temporary file left behind");
    assert_eq!(store::load(&path).unwrap(), vec![att], "the file is as it was");
}

#[test]
fn the_store_file_refuses_anything_it_did_not_write() {
    let (chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    let legacy = attest(&chain, &p2pkh(), outpoint(9), "k", "v", ANCHOR);
    let good = store::encode([&att, &legacy].into_iter());
    assert_eq!(store::decode(&good), Ok(vec![att.clone(), legacy]));
    assert_eq!(store::decode(&store::encode(std::iter::empty())), Ok(vec![]));

    let mut flipped = good.clone();
    flipped[20] ^= 1;
    assert!(store::decode(&flipped).unwrap_err().contains("checksum"));
    assert!(store::decode(&good[..good.len() - 1]).is_err());
    assert!(store::decode(&good[..10]).unwrap_err().contains("truncated"));

    // With a valid checksum, the header and the entries are still checked.
    let reseal = |body: &[u8]| {
        let mut b = body.to_vec();
        b.extend_from_slice(sha256::Hash::hash(body).as_byte_array());
        b
    };
    let body = &good[..good.len() - 32];
    let mut magic = body.to_vec();
    magic[0] = b'X';
    assert!(store::decode(&reseal(&magic)).unwrap_err().contains("not a NAP"));
    let mut version = body.to_vec();
    version[4] = 2;
    assert!(store::decode(&reseal(&version)).unwrap_err().contains("version 2"));
    let mut count = body.to_vec();
    count[8] = 3;
    assert!(store::decode(&reseal(&count)).unwrap_err().contains("entry 2"));
    count[8] = 1;
    assert!(store::decode(&reseal(&count)).unwrap_err().contains("follow the last entry"));

    // Two for one key (not something the publisher writes): the newer wins.
    let (_dir, path) = store_path();
    let newer = attest(&chain, &p2wpkh(), att.outpoint(), att.key(), "no", ANCHOR + 1);
    for order in [[&att, &newer], [&newer, &att]] {
        store::save(&path, &store::encode(order.into_iter())).unwrap();
        let listed = Publisher::open(path.clone(), &chain).unwrap().list(&chain);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].attestation, newer);
    }

    // Opening a damaged store fails rather than starting empty.
    let (_dir, path) = store_path();
    store::save(&path, &flipped).unwrap();
    assert!(Publisher::open(path, &chain).is_err());
}

/// `-napstorerecover`: a damaged store is moved aside, intact, and the
/// publisher starts empty and keeps working. A good store opens as usual.
#[test]
fn recovery_sets_a_damaged_store_aside_and_starts_empty() {
    let (_dir, path) = store_path();
    let (chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);

    let (p, aside) = Publisher::open_recovering(path.clone(), &chain).unwrap();
    assert!(aside.is_none(), "a missing store is an empty one, not a damaged one");
    submit(&p, &chain, &att).unwrap();
    let (p, aside) = Publisher::open_recovering(path.clone(), &chain).unwrap();
    assert!(aside.is_none());
    assert_eq!(p.list(&chain).len(), 1, "a good store is kept");

    let damaged = b"not a store".to_vec();
    std::fs::write(&path, &damaged).unwrap();
    assert!(Publisher::open(path.clone(), &chain).is_err(), "without recovery, still an error");
    let (p, aside) = Publisher::open_recovering(path.clone(), &chain).unwrap();
    let (aside, why) = aside.expect("the damaged file was set aside");
    assert!(why.contains("truncated"), "{why}");
    // The file and the journal that followed it.
    assert_eq!(aside.len(), 2, "{aside:?}");
    let aside = &aside[0];
    assert!(aside.file_name().unwrap().to_str().unwrap().starts_with("attestations.dat.bad-"), "{aside:?}");
    assert_eq!(std::fs::read(aside).unwrap(), damaged, "the damaged file is kept as it was");
    assert!(!path.exists());
    assert!(p.list(&chain).is_empty());
    submit(&p, &chain, &att).unwrap();
    assert_eq!(on_disk(&path), vec![att]);
}

// --- The journal --------------------------------------------------------------

/// `count` coins for one signer, each with an attestation.
fn attested(chain: &mut Chain, count: u8) -> Vec<Attestation> {
    let signer = p2wpkh();
    (1..=count)
        .map(|n| {
            let op = coin(chain, &signer, n);
            attest(chain, &signer, op, "k", "v", ANCHOR)
        })
        .collect()
}

#[test]
fn a_change_appends_one_record_and_leaves_the_file_alone() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 30);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    let mut lens = vec![p.journal_len()];
    for att in &atts {
        submit(&p, &chain, att).unwrap();
        lens.push(p.journal_len());
    }
    // Each submission grew the journal by one record (the first also by
    // the journal's 40-byte header), as much for the thirtieth as for the
    // first: no change rewrites what is stored. A DER signature's length
    // varies by a byte.
    let grew: Vec<u64> = lens.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(grew[1..].iter().all(|g| g.abs_diff(grew[1]) <= 1), "{grew:?}");
    assert!(grew[0].abs_diff(grew[1] + 40) <= 1, "{grew:?}");
    assert!(!path.exists(), "the file is written only when the journal is folded in");
    assert_eq!(on_disk(&path), atts);
    p.remove(atts[3].outpoint(), "k").unwrap();
    let mut left = atts.clone();
    left.remove(3);
    assert_eq!(on_disk(&path), left);
    let reopened = Publisher::open(path, &chain).unwrap().list(&chain);
    assert_eq!(reopened.iter().map(|p| p.attestation.clone()).collect::<Vec<_>>(), left);
}

#[test]
fn a_torn_last_record_is_dropped_and_the_journal_goes_on() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 3);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[0]).unwrap();
    submit(&p, &chain, &atts[1]).unwrap();
    let whole = std::fs::read(store::journal_path(&path)).unwrap();
    // A crash during the second append: its record cut short, or written
    // whole but not its checksum.
    // The first record ends after its kind, length, payload and checksum;
    // its length is the four bytes after the 40-byte header and its kind.
    let first_len = u32::from_le_bytes(whole[41..45].try_into().unwrap()) as usize;
    let first_end = 40 + 5 + first_len + 32;
    for torn in [&whole[..whole.len() - 5], &whole[..first_end + 3]] {
        std::fs::write(store::journal_path(&path), torn).unwrap();
        let p = Publisher::open(path.clone(), &chain).unwrap();
        assert_eq!(on_disk(&path), vec![atts[0].clone()]);
        assert_eq!(std::fs::read(store::journal_path(&path)).unwrap(), whole[..first_end], "the torn end is cut off");
        // The next change follows the last whole record.
        submit(&p, &chain, &atts[2]).unwrap();
        assert_eq!(on_disk(&path), vec![atts[0].clone(), atts[2].clone()]);
    }
}

#[test]
fn a_damaged_record_before_the_end_is_an_error_and_recovery_sets_both_files_aside() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 2);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[0]).unwrap();
    submit(&p, &chain, &atts[1]).unwrap();
    drop(p);
    let jpath = store::journal_path(&path);
    let mut damaged = std::fs::read(&jpath).unwrap();
    damaged[50] ^= 1;
    std::fs::write(&jpath, &damaged).unwrap();
    let err = Publisher::open(path.clone(), &chain).err().unwrap();
    assert!(err.contains("checksum"), "{err}");
    let (p, aside) = Publisher::open_recovering(path.clone(), &chain).unwrap();
    let (aside, _) = aside.unwrap();
    // No file was written yet, so the journal is all there is to set aside.
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert!(aside[0].file_name().unwrap().to_str().unwrap().starts_with("attestations.journal.bad-"), "{aside:?}");
    assert_eq!(std::fs::read(&aside[0]).unwrap(), damaged, "kept as it was");
    assert!(!jpath.exists());
    assert!(p.list(&chain).is_empty());
}

#[test]
fn a_journal_that_names_another_file_is_ignored() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 2);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[0]).unwrap();
    drop(p);
    // A compaction that wrote the new file and crashed before starting the
    // new journal: the file holds everything, and the old journal, which
    // names no file, must not be applied over it.
    store::save(&path, &store::encode([&atts[1]].into_iter())).unwrap();
    assert_eq!(on_disk(&path), vec![atts[1].clone()]);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    assert_eq!(p.list(&chain).len(), 1);
    // The first change after it starts a journal naming the file.
    submit(&p, &chain, &atts[0]).unwrap();
    assert_eq!(on_disk(&path), atts);
}

#[test]
fn a_journal_that_outgrows_the_file_is_folded_into_it() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 20);
    let p = Publisher::open(path.clone(), &chain).unwrap().with_compaction_at(1);
    for att in &atts {
        submit(&p, &chain, att).unwrap();
    }
    p.remove(atts[0].outpoint(), "k").unwrap();
    // Folded in as it went: the journal never grows past the file.
    let file = std::fs::metadata(&path).unwrap().len();
    assert!(p.journal_len() <= file, "{} > {file}", p.journal_len());
    assert_eq!(on_disk(&path), atts[1..]);
    let reopened = Publisher::open(path.clone(), &chain).unwrap().list(&chain);
    assert_eq!(reopened.iter().map(|p| p.attestation.clone()).collect::<Vec<_>>(), atts[1..]);
    // Under the real threshold a store this small is never rewritten.
    let (_dir, path) = store_path();
    let p = Publisher::open(path.clone(), &chain).unwrap();
    for att in &atts {
        submit(&p, &chain, att).unwrap();
    }
    assert!(!path.exists());
}

/// A chain source that runs `hook` before its first read and gives up after
/// `reads` reads: a submission landing mid-pass, or a chain that will not
/// hold still.
struct Hooked<'a> {
    chain: &'a Chain,
    hook: std::cell::Cell<Option<Box<dyn FnOnce() + 'a>>>,
    reads: std::cell::Cell<usize>,
}

impl<'a> Hooked<'a> {
    fn new(chain: &'a Chain, reads: usize, hook: Option<Box<dyn FnOnce() + 'a>>) -> Self {
        Hooked { chain, hook: std::cell::Cell::new(hook), reads: std::cell::Cell::new(reads) }
    }
}

impl ChainSource for Hooked<'_> {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        if let Some(hook) = self.hook.take() {
            hook();
        }
        let left = self.reads.get();
        if left == 0 {
            return None;
        }
        self.reads.set(left - 1);
        Some(read(self.chain))
    }
}

/// A re-check of the stored attestation that cannot read the chain is
/// "try again", not a verdict.
#[test]
fn a_recheck_that_cannot_read_the_chain_is_busy() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (chain, old) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let older = attest(&chain, &signer, old.outpoint(), old.key(), "no", ANCHOR - 100);
    let p = Publisher::open(path, &chain).unwrap();
    submit(&p, &chain, &old).unwrap();
    // Two reads for the submission itself; the re-check gets none.
    let stuck = Hooked::new(&chain, 2, None);
    let r = p.submit(&stuck, &older.message(), &encode_signature(older.signature()));
    assert_eq!(r.unwrap_err(), PublishError::Busy);
}

/// A tip pass judges without the writer lock, so a submission can replace an
/// entry mid-pass; the pass's verdict on the old entry must not land on the
/// new one.
#[test]
fn a_tip_pass_does_not_judge_an_entry_replaced_during_it() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, old) = setup(&signer, COIN_HEIGHT, ANCHOR - 100);
    let new = attest(&chain, &signer, old.outpoint(), old.key(), "no", ANCHOR);
    let p = Publisher::open(path, &chain).unwrap();
    submit(&p, &chain, &new).unwrap();
    // The newer one loses its anchor; the older one, submitted mid-pass,
    // replaces it and is valid.
    chain.fork_at = ANCHOR - 10;
    let replace = || {
        assert_eq!(submit(&p, &chain, &old), Ok(Some(new.id())));
    };
    p.on_tip(&Hooked::new(&chain, usize::MAX, Some(Box::new(replace))));
    assert_eq!(p.serving(), vec![old]);
}

/// What a tip pass reports: a lost anchor once the tip has reached its
/// height (at startup too), never while the node is behind it, and nothing
/// for an entry that was already not served.
#[test]
fn a_lost_anchor_is_reported_only_when_the_chain_has_reached_it() {
    let lost = || Err(Rejection::AnchorNotOnChain);
    let stale = || Err(Rejection::Stale { age: FRESHNESS_WINDOW });
    let valid = Ok(VALUE);
    let said = |before: Option<&Result<bitcoin::Amount, Rejection>>, now, tip| transition(before, now, tip, ANCHOR).1;
    assert_eq!(said(Some(&valid), lost(), ANCHOR), Some(Report::LostAnchor));
    assert_eq!(said(None, lost(), ANCHOR + 1), Some(Report::LostAnchor), "found at startup");
    assert_eq!(said(None, lost(), ANCHOR - 1), None, "behind the anchor: IBD, not a reorg");
    assert_eq!(said(Some(&valid), lost(), ANCHOR - 1), None);
    assert_eq!(said(Some(&lost()), lost(), ANCHOR), None, "reported once");
    assert_eq!(said(Some(&valid), stale(), TIP), Some(Report::NoLongerValid(stale().unwrap_err())));
    assert_eq!(said(Some(&stale()), stale(), TIP), None);
    assert_eq!(said(Some(&valid), Ok(VALUE), TIP), None);

    // A reorg in two passes: the tip drops below the anchor (not served, not
    // yet reported), then the new branch passes its height without it.
    let (mid, said_mid) = transition(Some(&valid), lost(), ANCHOR - 1, ANCHOR);
    assert_eq!((mid.clone(), said_mid), (None, None));
    assert_eq!(transition(mid.as_ref(), lost(), ANCHOR + 5, ANCHOR).1, Some(Report::LostAnchor));
    // The same blocks coming back: valid again, nothing to report.
    assert_eq!(transition(mid.as_ref(), Ok(VALUE), ANCHOR + 5, ANCHOR), (Some(Ok(VALUE)), None));
    // Already reported, then behind: stays reported.
    assert_eq!(transition(Some(&lost()), lost(), ANCHOR - 1, ANCHOR), (Some(lost()), None));
}

/// An entry the chain has never held still for is "not judged yet", not a
/// spent coin.
#[test]
fn an_entry_never_judged_lists_as_unknown() {
    let (_dir, path) = store_path();
    let (chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    store::save(&path, &store::encode([&att].into_iter())).unwrap();
    let p = Publisher::open(path, &Hooked::new(&chain, 0, None)).unwrap();
    assert_eq!(p.list(&Hooked::new(&chain, 0, None))[0].status, None);
    assert!(p.serving().is_empty());
    assert_eq!(p.list(&chain)[0].status, Some(Ok(VALUE)));
}

/// `-napmaxattestations`: new attestations stop at the limit, replacements
/// do not, and a store already over a lowered limit is kept whole.
#[test]
fn the_store_holds_at_most_the_operators_limit() {
    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, a) = setup(&signer, COIN_HEIGHT, ANCHOR - 1);
    let op2 = coin(&mut chain, &signer, 8);
    let b = attest(&chain, &signer, op2, "k", "v", ANCHOR);
    let c = attest(&chain, &signer, a.outpoint(), "another key", "v", ANCHOR);
    let p = Publisher::open(path.clone(), &chain).unwrap().with_max_attestations(2);
    submit(&p, &chain, &a).unwrap();
    submit(&p, &chain, &b).unwrap();
    assert_eq!(submit(&p, &chain, &c), Err(PublishError::StoreFull { max: 2 }));
    assert_eq!(rule(submit(&p, &chain, &c)), "store-full");
    let draft = p.create(&chain, a.outpoint(), "another key", "v").unwrap();
    assert!(draft.warnings.iter().any(|w| w.contains("-napmaxattestations")), "{:?}", draft.warnings);
    assert!(p.create(&chain, a.outpoint(), a.key(), "no").unwrap().warnings.is_empty(), "a replacement fits");
    let newer = attest(&chain, &signer, a.outpoint(), a.key(), "no", ANCHOR);
    assert_eq!(submit(&p, &chain, &newer), Ok(Some(a.id())), "replacing one is allowed at the limit");

    // Lowered below what is stored: everything is kept, nothing new taken.
    let p = Publisher::open(path.clone(), &chain).unwrap().with_max_attestations(1);
    assert_eq!(p.list(&chain).len(), 2);
    assert_eq!(rule(submit(&p, &chain, &c)), "store-full");
    // 0 is no limit.
    let p = Publisher::open(path, &chain).unwrap().with_max_attestations(0);
    assert_eq!(submit(&p, &chain, &c), Ok(None));
}

/// Resubmitting a stored attestation that has just been judged valid serves
/// it now, not at the next tip pass (which IBD can hold off).
#[test]
fn resubmitting_a_stored_attestation_updates_its_status() {
    let (_dir, path) = store_path();
    let (mut chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    store::save(&path, &store::encode([&att].into_iter())).unwrap();
    chain.fork_at = ANCHOR;
    let p = Publisher::open(path, &chain).unwrap();
    assert!(p.serving().is_empty(), "judged without its anchor at open");
    chain.fork_at = u32::MAX;
    assert_eq!(submit(&p, &chain, &att), Ok(None));
    assert_eq!(p.serving(), vec![att]);
}

/// D15: the draft carries BIP 322's `to_sign` PSBT, and a signed copy of it
/// is finalized into the same simple proof a message signer makes.
#[test]
fn a_signed_draft_psbt_is_finalized_and_stored() {
    use base64::Engine as _;
    use bitcoin::secp256k1::{Message as SecpMessage, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let (_dir, path) = store_path();
    let signer = p2wpkh();
    let (mut chain, _) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let op = coin(&mut chain, &signer, 7);
    let p = Publisher::open(path, &chain).unwrap();
    let b64 = |psbt: &bitcoin::psbt::Psbt| base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    let sign = |mut psbt: bitcoin::psbt::Psbt| {
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(0, &signer.spk, bitcoin::Amount::ZERO, EcdsaSighashType::All)
            .unwrap();
        let sk = super::tests::secret(1);
        let signature = Secp256k1::new().sign_ecdsa(&SecpMessage::from_digest(sighash.to_byte_array()), &sk);
        let pk = bitcoin::PublicKey::new(sk.public_key(&Secp256k1::new()));
        psbt.inputs[0]
            .partial_sigs
            .insert(pk, bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All });
        psbt
    };

    let draft = p.create(&chain, op, "bip_xyz.support", "yes").unwrap();
    let other = p.create(&chain, op, "bip_xyz.support", "no").unwrap();

    let unsigned = p.submit(&chain, &draft.message, &b64(&draft.psbt)).unwrap_err();
    assert_eq!(unsigned.rule(), "format");
    assert!(unsigned.to_string().contains("not fully signed"), "{unsigned}");

    let mismatch = p.submit(&chain, &draft.message, &b64(&sign(other.psbt.clone()))).unwrap_err();
    assert!(mismatch.to_string().contains("different message"), "{mismatch}");

    let foreign = crate::bip322::psbt::create(&p2pkh().spk, draft.message.as_bytes());
    let foreign = p.submit(&chain, &draft.message, &b64(&foreign)).unwrap_err();
    assert!(foreign.to_string().contains("different scriptPubKey"), "{foreign}");

    let (stored, _) = p.submit(&chain, &draft.message, &b64(&sign(draft.psbt.clone()))).unwrap();
    assert_eq!(stored.status, Some(Ok(VALUE)));
    assert_eq!(*stored.attestation.signature(), (signer.sign)(&draft.message), "the same simple proof");
}

/// The chain a real-wallet vector was signed against: the anchor block and
/// the coin its message names, as they were on signet.
struct Signed {
    anchor_height: u32,
    anchor_hash: bitcoin::BlockHash,
    outpoint: OutPoint,
    coin: Coin,
}

impl ChainView for Signed {
    fn network(&self) -> bitcoin::Network {
        bitcoin::Network::Signet
    }
    fn tip_height(&self) -> u32 {
        self.anchor_height + ANCHOR_DEPTH
    }
    fn block_hash(&self, height: u32) -> Option<bitcoin::BlockHash> {
        (height <= self.tip_height())
            .then(|| if height == self.anchor_height { self.anchor_hash } else { hash_at(height, false) })
    }
    fn median_time_past(&self, height: u32) -> u32 {
        mtp(height)
    }
    fn coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        (*outpoint == self.outpoint).then(|| self.coin.clone())
    }
    fn utxo_total(&self) -> bitcoin::Amount {
        self.coin.value
    }
}

impl ChainSource for Signed {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        Some(read(self))
    }
}

/// G1: signatures real wallets made on signet, submitted exactly as each
/// wallet emitted them (a PSBT, a raw transaction, prefixed or not), so
/// later changes are tested against what wallets actually produce. Each
/// vector's `wallet` field says what made it.
#[test]
fn real_wallet_signatures_are_accepted() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("testdata/wallet-signatures.json")).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for v in vectors {
        let field = |k: &str| v[k].as_str().unwrap();
        let (wallet, text, signature) = (field("wallet"), field("message"), field("signature"));
        let msg = message::parse(text).unwrap();
        let chain = Signed {
            anchor_height: msg.anchor_height,
            anchor_hash: msg.anchor_hash,
            outpoint: msg.outpoint,
            coin: Coin {
                value: VALUE,
                script_pubkey: bitcoin::ScriptBuf::from_hex(field("script_pubkey")).unwrap(),
                height: msg.anchor_height - TEST_MIN_COIN_AGE,
                coinbase: false,
            },
        };
        let (_dir, path) = store_path();
        let p = Publisher::open(path, &chain).unwrap();
        let (stored, _) = p.submit(&chain, text, signature).unwrap_or_else(|e| panic!("{wallet}: {e}"));
        assert_eq!(stored.status, Some(Ok(VALUE)), "{wallet}");
        let format = match stored.attestation.signature() {
            NapSignature::Simple(_) => "simple",
            NapSignature::Full(_) => "full",
            NapSignature::Legacy(_) => "legacy",
        };
        assert_eq!(format, field("format"), "{wallet}");
        // The signature commits to the text: another value fails.
        let other = text.replace("\nvalue: yes\n", "\nvalue: no\n");
        assert_ne!(other, text);
        assert!(p.submit(&chain, &other, signature).is_err(), "{wallet}: signs any value");
    }
}

#[test]
fn a_damaged_length_is_an_error_not_a_torn_end() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 2);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[0]).unwrap();
    submit(&p, &chain, &atts[1]).unwrap();
    drop(p);
    let jpath = store::journal_path(&path);
    let whole = std::fs::read(&jpath).unwrap();
    // The first record's length, made to reach past the end: were it
    // trusted, the second record, reported done, would be cut off with it.
    let mut damaged = whole.clone();
    damaged[41..45].copy_from_slice(&1_000_000u32.to_le_bytes());
    std::fs::write(&jpath, &damaged).unwrap();
    let err = Publisher::open(path.clone(), &chain).err().unwrap();
    assert!(err.contains("longer than any record"), "{err}");
    assert_eq!(std::fs::read(&jpath).unwrap(), damaged, "nothing is cut off");
    // A record kind the journal does not write is damage too.
    let mut damaged = whole.clone();
    damaged[40] = 9;
    std::fs::write(&jpath, &damaged).unwrap();
    assert!(Publisher::open(path.clone(), &chain).err().unwrap().contains("unknown record kind"));
    // Zeros after the last record, as a filesystem may leave after a power
    // loss, are a torn end.
    let mut zeros = whole.clone();
    zeros.extend_from_slice(&[0; 300]);
    std::fs::write(&jpath, &zeros).unwrap();
    Publisher::open(path.clone(), &chain).unwrap();
    assert_eq!(on_disk(&path), atts);
    assert_eq!(std::fs::read(&jpath).unwrap(), whole);
    // So is a last record whose checksum fails, with zeros after it.
    let mut torn = whole.clone();
    let last = torn.len() - 10;
    torn[last..].fill(0);
    torn.extend_from_slice(&[0; 300]);
    std::fs::write(&jpath, &torn).unwrap();
    Publisher::open(path.clone(), &chain).unwrap();
    assert_eq!(on_disk(&path), atts[..1]);
}

#[test]
fn a_damaged_journal_naming_another_file_does_not_stop_startup() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 2);
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[0]).unwrap();
    submit(&p, &chain, &atts[1]).unwrap();
    drop(p);
    store::save(&path, &store::encode([&atts[1]].into_iter())).unwrap();
    let jpath = store::journal_path(&path);
    let mut damaged = std::fs::read(&jpath).unwrap();
    damaged[50] ^= 1;
    std::fs::write(&jpath, &damaged).unwrap();
    // Its records are never read, so their damage does not matter.
    let p = Publisher::open(path.clone(), &chain).unwrap();
    assert_eq!(p.list(&chain).len(), 1);
}

#[test]
fn a_file_that_cannot_be_written_is_not_rewritten_on_every_change() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 40);
    let p = Publisher::open(path.clone(), &chain).unwrap().with_compaction_at(1);
    // The file's path is a directory: every compaction fails at the rename,
    // while the journal takes each change.
    std::fs::create_dir_all(&path).unwrap();
    for att in &atts {
        submit(&p, &chain, att).unwrap();
    }
    assert_eq!(on_disk_journal_only(&path), atts);
    // Tried again only once the journal has doubled since the last try:
    // a handful of times for forty changes, not forty.
    assert!(p.compactions() <= 7, "{} compactions for {} changes", p.compactions(), atts.len());
    assert!(p.compactions() >= 2, "still tried again as the journal grows");
}

/// The journal's records alone, for a store whose file cannot be read.
fn on_disk_journal_only(path: &std::path::Path) -> Vec<Attestation> {
    let bytes = std::fs::read(store::journal_path(path)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("attestations.dat");
    std::fs::write(store::journal_path(&copy), bytes).unwrap();
    on_disk(&copy)
}

#[test]
fn recoveries_in_the_same_second_keep_every_damaged_file() {
    let (_dir, path) = store_path();
    let (chain, _) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut kept = Vec::new();
    for damage in [b"first".as_slice(), b"second"] {
        std::fs::write(&path, damage).unwrap();
        let (_, aside) = Publisher::open_recovering(path.clone(), &chain).unwrap();
        kept.extend(aside.unwrap().0);
    }
    assert_eq!(kept.len(), 2);
    assert_ne!(kept[0], kept[1]);
    assert_eq!(std::fs::read(&kept[0]).unwrap(), b"first");
    assert_eq!(std::fs::read(&kept[1]).unwrap(), b"second");
}

#[test]
fn a_fold_leaves_the_file_holding_everything_as_an_older_build_reads_it() {
    let (_dir, path) = store_path();
    let mut chain = Chain::new();
    let atts = attested(&mut chain, 5);
    assert_eq!(Publisher::open(path.clone(), &chain).unwrap().fold_journal(), Ok(false), "nothing to fold");
    let p = Publisher::open(path.clone(), &chain).unwrap();
    for att in &atts {
        submit(&p, &chain, att).unwrap();
    }
    p.remove(atts[2].outpoint(), "k").unwrap();
    let mut left = atts.clone();
    left.remove(2);
    // Too small to be folded in as it went: the file does not exist yet.
    assert!(!path.exists());
    assert_eq!(p.fold_journal(), Ok(true));
    // The file alone, as a build that ignores the journal reads it.
    assert_eq!(store::load(&path).unwrap(), left);
    assert_eq!(on_disk(&path), left);
    assert_eq!(p.fold_journal(), Ok(false), "folded already");
    // Nothing is recorded after it: a submission still running at shutdown
    // is refused, and the file stays whole.
    let journal = std::fs::read(store::journal_path(&path)).unwrap();
    assert_eq!(rule(submit(&p, &chain, &atts[2])), "io");
    assert_eq!(rule(p.remove(atts[0].outpoint(), "k")), "io");
    assert_eq!(std::fs::read(store::journal_path(&path)).unwrap(), journal);
    assert_eq!(store::load(&path).unwrap(), left);
    // The next start takes changes again.
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &atts[2]).unwrap();
    assert_eq!(on_disk(&path), atts);
}
