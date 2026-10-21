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
    assert_eq!(listed[0].status, Some(Ok(VALUE)));
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
    assert!(aside.file_name().unwrap().to_str().unwrap().starts_with("attestations.dat.bad-"), "{aside:?}");
    assert_eq!(std::fs::read(&aside).unwrap(), damaged, "the damaged file is kept as it was");
    assert!(!path.exists());
    assert!(p.list(&chain).is_empty());
    submit(&p, &chain, &att).unwrap();
    assert_eq!(store::load(&path).unwrap(), vec![att]);
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
