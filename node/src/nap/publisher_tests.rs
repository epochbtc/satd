use std::path::PathBuf;

use bitcoin::hashes::{Hash as _, sha256};

use super::publisher::{COLDCARD_MESSAGE_LIMIT, encode_signature};
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
    chain.coins.insert(op, Coin { value: VALUE, script_pubkey: signer.spk.clone(), height: COIN_HEIGHT });
    op
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
    assert!(path.exists());
    assert!(!path.with_extension("dat.tmp").exists(), "no temporary file left behind");

    let p = Publisher::open(path, &chain).unwrap();
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].attestation, att);
    assert_eq!(listed[0].status, Ok(VALUE));
    assert_eq!(listed[1].attestation, legacy_att);
    assert_eq!(p.serving().len(), 2);
}

/// D14: `smp`, `ful`, unprefixed (simple for segwit, legacy for P2PKH); not
/// `pof`.
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
    let draft = p.create(&chain, op, "a.long.key", &long).unwrap();
    assert!(draft.message.len() > COLDCARD_MESSAGE_LIMIT);
    assert!(draft.warnings.iter().any(|w| w.contains("Coldcard")), "{:?}", draft.warnings);

    // The coin must be old enough at the anchor, not at the tip.
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - MIN_COIN_AGE + 1;
    assert_eq!(rule(p.create(&chain, op, "k", "v")), "coin-too-young");
    chain.coins.get_mut(&op).unwrap().height = TIP - ANCHOR_DEPTH - MIN_COIN_AGE;
    assert!(p.create(&chain, op, "k", "v").is_ok());

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

    // At or above it, the coin was spent.
    chain.coins.remove(&att.outpoint());
    p.on_tip(&chain);
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attestation, kept);
    assert_eq!(store::load(&path).unwrap(), vec![kept], "the drop was written");
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
    assert_eq!(p.list(&chain)[0].status, Err(Rejection::AnchorNotOnChain));
    assert_eq!(p.serving(), vec![att.clone()]);
    p.on_tip(&chain);
    assert!(p.serving().is_empty());
    assert_eq!(p.list(&chain)[0].status, Err(Rejection::AnchorNotOnChain));

    chain.fork_at = u32::MAX;
    p.on_tip(&chain);
    assert_eq!(p.serving(), vec![att.clone()], "back on the chain, served again");

    chain.tip = ANCHOR + FRESHNESS_WINDOW;
    p.on_tip(&chain);
    assert!(p.serving().is_empty());
    assert!(matches!(p.list(&chain)[0].status, Err(Rejection::Stale { .. })));
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
    assert_eq!(p.list(&chain)[0].status, Ok(VALUE));
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
    let p = Publisher::open(path.clone(), &chain).unwrap();
    submit(&p, &chain, &att).unwrap();
    // The store's path is a directory, so every write fails at the rename.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(rule(submit(&p, &chain, &other)), "io");
    assert_eq!(rule(p.remove(att.outpoint(), att.key())), "io");
    let listed = p.list(&chain);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attestation, att);
    assert!(!path.with_extension("dat.tmp").exists(), "no temporary file left behind");
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
