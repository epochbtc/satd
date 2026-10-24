use std::collections::HashMap;

use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message as SecpMessage, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, CompressedPublicKey, Network, OutPoint, PrivateKey, ScriptBuf, Sequence,
    Txid, Witness, absolute::LockTime, opcodes::all::*,
};

use super::validity::{ChainView, Coin, Rejection};
use super::*;
use crate::bip322;
use crate::rpc::signmessage;

// --- A chain to evaluate against ------------------------------------------

pub(super) const TIP: u32 = 40_000;
pub(super) const ANCHOR: u32 = TIP - ANCHOR_DEPTH;
pub(super) const COIN_HEIGHT: u32 = 1_000;
pub(super) const VALUE: Amount = Amount::from_sat(150_000);

/// Blocks `0..=tip`, each with a hash derived from its height and, from
/// `fork_at` up, a fork byte: the same chain reorganised from `fork_at`.
pub(super) struct Chain {
    pub(super) network: Network,
    pub(super) tip: u32,
    pub(super) fork_at: u32,
    pub(super) coins: HashMap<OutPoint, Coin>,
}

impl Chain {
    pub(super) fn new() -> Self {
        Chain { network: Network::Bitcoin, tip: TIP, fork_at: u32::MAX, coins: HashMap::new() }
    }
}

pub(super) fn hash_at(height: u32, fork: bool) -> BlockHash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&height.to_le_bytes());
    b[4] = u8::from(fork);
    b[31] = 0xab;
    BlockHash::from_byte_array(b)
}

/// MTP grows 600 s a block.
pub(super) fn mtp(height: u32) -> u32 {
    1_600_000_000 + height * 600
}

impl ChainView for Chain {
    fn network(&self) -> Network {
        self.network
    }
    fn tip_height(&self) -> u32 {
        self.tip
    }
    fn block_hash(&self, height: u32) -> Option<BlockHash> {
        (height <= self.tip).then(|| hash_at(height, height >= self.fork_at))
    }
    fn median_time_past(&self, height: u32) -> u32 {
        assert!(height <= self.tip + 1);
        mtp(height)
    }
    fn coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.get(outpoint).cloned()
    }
}

pub(super) fn outpoint(n: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([n; 32]), vout: u32::from(n) }
}

// --- Signers ----------------------------------------------------------------

pub(super) fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

pub(super) fn compressed(sk: &SecretKey) -> CompressedPublicKey {
    CompressedPublicKey(sk.public_key(&Secp256k1::new()))
}

/// How a test attestation is signed: the scriptPubKey it signs for, and a
/// signer from the message text.
pub(super) struct Signer {
    pub(super) spk: ScriptBuf,
    pub(super) sign: Box<dyn Fn(&str) -> NapSignature>,
}

/// BIP 322 simple, P2WPKH.
pub(super) fn p2wpkh() -> Signer {
    let sk = secret(1);
    let pk = compressed(&sk);
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let challenge = spk.clone();
    Signer {
        spk,
        sign: Box::new(move |message| {
            let spend = bip322::to_spend(&challenge, message.as_bytes());
            let tx = bip322::to_sign(spend.compute_txid(), Witness::new());
            let sighash = SighashCache::new(&tx)
                .p2wpkh_signature_hash(0, &challenge, Amount::ZERO, EcdsaSighashType::All)
                .unwrap();
            let sig = Secp256k1::new().sign_ecdsa(&SecpMessage::from_digest(sighash.to_byte_array()), &sk);
            let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
            NapSignature::Simple(Witness::p2wpkh(&sig, &pk.0))
        }),
    }
}

/// Legacy, P2PKH.
pub(super) fn p2pkh() -> Signer {
    let key = PrivateKey::new(secret(3), Network::Regtest);
    let spk = ScriptBuf::new_p2pkh(&key.public_key(&Secp256k1::new()).pubkey_hash());
    Signer {
        spk,
        sign: Box::new(move |message| {
            let sig = signmessage::decode_base64(&signmessage::message_sign(&key, message)).unwrap();
            NapSignature::Legacy(sig.try_into().unwrap())
        }),
    }
}

/// BIP 322 full, P2WSH over `<prefix> <key> OP_CHECKSIG`, with `to_sign`'s
/// version, locktime and sequence set.
pub(super) fn p2wsh_full(prefix: Builder, version: i32, lock_time: u32, sequence: u32) -> Signer {
    let sk = secret(4);
    let pk = compressed(&sk);
    let ws = prefix.push_key(&pk.into()).push_opcode(OP_CHECKSIG).into_script();
    let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let challenge = spk.clone();
    Signer {
        spk,
        sign: Box::new(move |message| {
            let spend = bip322::to_spend(&challenge, message.as_bytes());
            let mut tx = bip322::to_sign(spend.compute_txid(), Witness::new());
            tx.version = Version(version);
            tx.lock_time = LockTime::from_consensus(lock_time);
            tx.input[0].sequence = Sequence(sequence);
            let sighash = SighashCache::new(&tx)
                .p2wsh_signature_hash(0, &ws, Amount::ZERO, EcdsaSighashType::All)
                .unwrap();
            let sig = Secp256k1::new().sign_ecdsa(&SecpMessage::from_digest(sighash.to_byte_array()), &sk);
            let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
            let mut w = Witness::new();
            w.push(sig.to_vec());
            w.push(ws.as_bytes());
            tx.input[0].witness = w;
            NapSignature::Full(tx)
        }),
    }
}

/// An attestation by `signer` for `op`, anchored at `anchor` on `chain`.
pub(super) fn attest(chain: &Chain, signer: &Signer, op: OutPoint, key: &str, value: &str, anchor: u32) -> Attestation {
    let hash = chain.block_hash(anchor).unwrap();
    let text = message::render(&op, key, value, anchor, &hash);
    Attestation::new(op, key.into(), value.into(), anchor, hash, (signer.sign)(&text)).unwrap()
}

/// A chain holding one coin for `signer` at `coin_height`, and an attestation
/// for it anchored at `anchor`.
pub(super) fn setup(signer: &Signer, coin_height: u32, anchor: u32) -> (Chain, Attestation) {
    let mut chain = Chain::new();
    let op = outpoint(7);
    chain.coins.insert(
        op,
        Coin { value: VALUE, script_pubkey: signer.spk.clone(), height: coin_height, coinbase: false },
    );
    let att = attest(&chain, signer, op, "bip_xyz.support", "yes", anchor);
    (chain, att)
}

// --- Message text -------------------------------------------------------------

#[test]
fn message_renders_the_designs_text() {
    let op = OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 3 };
    let hash = hash_at(39_994, false);
    let text = message::render(&op, "bip_xyz.support", "yes", 39_994, &hash);
    assert_eq!(
        text,
        format!(
            "NAP attestation v1\noutpoint: {}:3\nkey: bip_xyz.support\nvalue: yes\nanchor: 39994 {}",
            "11".repeat(32),
            hash
        )
    );
    let m = message::parse(&text).unwrap();
    assert_eq!((m.outpoint, m.key.as_str(), m.value.as_str()), (op, "bip_xyz.support", "yes"));
    assert_eq!((m.anchor_height, m.anchor_hash), (39_994, hash));

    // An empty value renders as "value: " and parses back.
    let withdrawal = message::render(&op, "k", "", 1, &hash);
    assert!(withdrawal.contains("\nvalue: \n"));
    assert_eq!(message::parse(&withdrawal).unwrap().value, "");
}

#[test]
fn message_parse_accepts_only_the_canonical_text() {
    let op = OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 3 };
    let hash = hash_at(5, false);
    let good = message::render(&op, "key", "value", 5, &hash);
    let bad = [
        good.replace('\n', "\r\n"),
        format!("{good}\n"),
        good.to_uppercase(),
        good.replace(":3\n", ":03\n"),
        good.replace(":3\n", ":+3\n"),
        good.replace("anchor: 5 ", "anchor: 05 "),
        good.replace("anchor: 5 ", "anchor: 5  "),
        good.replace(&hash.to_string(), &hash.to_string().to_uppercase()),
        good.replace("v1\n", "v2\n"),
        good.replace("v1\n", "v1 \n"),
        good.replace("key: key", "key: "),
        good.replace("key: key", "key: k\u{7f}"),
        good.replace("value: value", "value: v\talue"),
        good.replace("value: value", &format!("value: {}", "v".repeat(MAX_VALUE_LEN + 1))),
        good.replace("key: key", &format!("key: {}", "k".repeat(MAX_KEY_LEN + 1))),
        good.replace("value: value\n", ""),
        format!("{good}\nextra: line"),
    ];
    for text in bad {
        assert!(message::parse(&text).is_err(), "accepted {text:?}");
    }
    let longest = good
        .replace("key: key", &format!("key: {}", "k".repeat(MAX_KEY_LEN)))
        .replace("value: value", &format!("value: {}", "v".repeat(MAX_VALUE_LEN)));
    assert!(message::parse(&longest).is_ok());
}

// --- Wire form ----------------------------------------------------------------

#[test]
fn every_format_round_trips() {
    for signer in [p2wpkh(), p2pkh(), p2wsh_full(Builder::new(), 0, 0, 0)] {
        let (_, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
        let bytes = att.to_bytes();
        assert_eq!(bytes.len(), wire::serialized_size(&att));
        assert_eq!(bytes[0], VERSION);
        assert_eq!(Attestation::from_bytes(&bytes).unwrap(), att);
    }
}

#[test]
fn a_list_decodes_one_attestation_at_a_time() {
    let (_, a) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    let (_, b) = setup(&p2pkh(), COIN_HEIGHT, ANCHOR);
    let bytes = [a.to_bytes(), b.to_bytes()].concat();
    let mut r = bytes.as_slice();
    assert_eq!(Attestation::decode_from(&mut r).unwrap(), a);
    assert_eq!(Attestation::decode_from(&mut r).unwrap(), b);
    assert!(r.is_empty());
    assert!(matches!(Attestation::from_bytes(&bytes), Err(FormatError::Decode(_))));
}

/// The byte offset of the format byte: after the signature's compact size
/// and bytes are the last of the encoding.
fn format_offset(att: &Attestation) -> usize {
    let sig = att.signature().to_bytes();
    att.to_bytes().len() - sig.len() - bitcoin::consensus::encode::VarInt(sig.len() as u64).size() - 1
}

#[test]
fn decoding_refuses_malformed_bytes() {
    let (_, att) = setup(&p2pkh(), COIN_HEIGHT, ANCHOR);
    let good = att.to_bytes();
    let at = format_offset(&att);
    assert_eq!(good[at], 2);

    let mut b = good.clone();
    b[0] = 2;
    assert_eq!(Attestation::from_bytes(&b), Err(FormatError::Version(2)));

    let mut b = good.clone();
    b[at] = 3;
    assert_eq!(Attestation::from_bytes(&b), Err(FormatError::SignatureFormat(3)));

    // Format 0 or 1 over a legacy signature's bytes.
    for f in [0, 1] {
        let mut b = good.clone();
        b[at] = f;
        assert!(matches!(Attestation::from_bytes(&b), Err(FormatError::Signature(_))), "{f}");
    }

    // A 64-byte legacy signature.
    let mut b = good[..at + 1].to_vec();
    b.push(64);
    b.extend_from_slice(&[1; 64]);
    assert!(matches!(Attestation::from_bytes(&b), Err(FormatError::Signature(_))));

    // Truncated anywhere.
    for n in 0..good.len() {
        assert!(Attestation::from_bytes(&good[..n]).is_err(), "{n}");
    }

    // A non-minimal compact size for the key (0xfd, then a u16 length).
    let key_at = 1 + 36;
    let key_len = usize::from(good[key_at]);
    let mut b = good[..key_at].to_vec();
    b.push(0xfd);
    b.extend_from_slice(&(key_len as u16).to_le_bytes());
    b.extend_from_slice(&good[key_at + 1..]);
    assert!(matches!(Attestation::from_bytes(&b), Err(FormatError::Decode(_))));

    // A key with a newline in it.
    let mut b = good.clone();
    b[key_at + 1] = b'\n';
    assert_eq!(Attestation::from_bytes(&b), Err(FormatError::KeyCharacters));
}

#[test]
fn size_limit_holds_on_construction_and_decoding() {
    let chain = Chain::new();
    let op = outpoint(1);
    let hash = chain.block_hash(ANCHOR).unwrap();
    let witness_of = |n: usize| {
        let mut w = Witness::new();
        w.push(vec![0u8; n]);
        NapSignature::Simple(w)
    };
    let make = |n| Attestation::new(op, "k".into(), "v".into(), ANCHOR, hash, witness_of(n));
    // 1 version + 36 outpoint + 2 key + 2 value + 4 height + 32 hash + 1
    // format + 3 signature length + 1 item count + 3 item length = 85 bytes
    // around the item.
    let fits = MAX_ATTESTATION_SIZE - 85;
    let att = make(fits).unwrap();
    assert_eq!(att.to_bytes().len(), MAX_ATTESTATION_SIZE);
    assert_eq!(Attestation::from_bytes(&att.to_bytes()).unwrap(), att);
    assert_eq!(make(fits + 1), Err(FormatError::TooLarge(MAX_ATTESTATION_SIZE + 1)));

    // The same oversized bytes, as a peer might send them.
    let big = Attestation { signature: witness_of(fits + 1), ..att };
    assert_eq!(
        Attestation::from_bytes(&big.to_bytes()),
        Err(FormatError::TooLarge(MAX_ATTESTATION_SIZE + 1))
    );

    // A key length that claims more than an attestation can hold (65,536
    // bytes, which the compact-size decoder allows) is refused before the
    // bytes are read.
    let mut b = vec![VERSION];
    b.extend_from_slice(&bitcoin::consensus::serialize(&op));
    b.extend_from_slice(&[0xfe, 0x00, 0x00, 0x01, 0x00]);
    let r = Attestation::from_bytes(&b);
    assert!(matches!(r, Err(FormatError::TooLarge(_))), "{r:?}");
}

#[test]
fn construction_checks_key_and_value() {
    let op = outpoint(1);
    let hash = hash_at(1, false);
    let sig = || NapSignature::Legacy([0; LEGACY_SIGNATURE_LEN]);
    let make = |k: &str, v: &str| Attestation::new(op, k.into(), v.into(), 1, hash, sig());
    assert_eq!(make("", "v"), Err(FormatError::KeyLength(0)));
    assert_eq!(make(&"k".repeat(129), "v"), Err(FormatError::KeyLength(129)));
    assert_eq!(make("k\n", "v"), Err(FormatError::KeyCharacters));
    assert_eq!(make("k", &"v".repeat(129)), Err(FormatError::ValueLength(129)));
    assert_eq!(make("k", "v\u{e9}"), Err(FormatError::ValueCharacters));
    assert!(make(&"k".repeat(128), &"v".repeat(128)).is_ok());
    assert!(make("k", "").unwrap().is_withdrawal());
}

#[test]
fn a_segwit_encoding_with_no_witness_is_not_canonical() {
    // A version-0 to_sign serialized with the segwit marker and an empty
    // witness: the same transaction as its legacy serialization.
    let tx = bip322::to_sign(Txid::from_byte_array([9; 32]), Witness::new());
    let legacy = bitcoin::consensus::serialize(&tx);
    let mut marked = legacy[..4].to_vec();
    marked.extend_from_slice(&[0x00, 0x01]);
    marked.extend_from_slice(&legacy[4..legacy.len() - 4]);
    marked.push(0x00);
    marked.extend_from_slice(&legacy[legacy.len() - 4..]);
    assert!(NapSignature::from_bytes(1, &legacy).is_ok());
    assert!(NapSignature::from_bytes(1, &marked).is_err());
}

// --- Validity -------------------------------------------------------------------

#[test]
fn each_signer_is_valid_and_weighs_its_coin() {
    for signer in [p2wpkh(), p2pkh(), p2wsh_full(Builder::new(), 0, 0, 0)] {
        let (chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
        assert_eq!(evaluate(&att, &chain).unwrap().value, VALUE);
    }
}

#[test]
fn freshness_boundary() {
    let signer = p2wpkh();
    let (chain, att) = setup(&signer, COIN_HEIGHT, TIP - (FRESHNESS_WINDOW - 1));
    assert!(evaluate(&att, &chain).is_ok());
    let (chain, att) = setup(&signer, COIN_HEIGHT, TIP - FRESHNESS_WINDOW);
    assert_eq!(evaluate(&att, &chain), Err(Rejection::Stale { age: FRESHNESS_WINDOW }));
    // An anchor at the tip is fresh.
    let (chain, att) = setup(&signer, COIN_HEIGHT, TIP);
    assert!(evaluate(&att, &chain).is_ok());
}

#[test]
fn a_coin_attests_from_ten_thousand_sats() {
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    chain.coins.get_mut(&att.outpoint()).unwrap().value = MIN_COIN_VALUE;
    assert!(evaluate(&att, &chain).is_ok());
    chain.coins.get_mut(&att.outpoint()).unwrap().value = MIN_COIN_VALUE - Amount::ONE_SAT;
    assert_eq!(evaluate(&att, &chain), Err(Rejection::CoinTooSmall { value: 9_999, min: 10_000 }));
    assert_eq!(Rejection::CoinTooSmall { value: 9_999, min: 10_000 }.rule(), "coin-too-small");
}

#[test]
fn coin_age_boundary_at_the_anchor() {
    let signer = p2wpkh();
    let (chain, att) = setup(&signer, ANCHOR - MIN_COIN_AGE, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
    let (chain, att) = setup(&signer, ANCHOR - MIN_COIN_AGE + 1, ANCHOR);
    assert_eq!(
        evaluate(&att, &chain),
        Err(Rejection::CoinTooYoung {
            coin_height: ANCHOR - MIN_COIN_AGE + 1,
            anchor_height: ANCHOR,
            min_age: MIN_COIN_AGE
        })
    );
    // An anchor too low for any coin to be old enough.
    let (chain, att) = setup(&signer, 0, MIN_COIN_AGE - 1);
    let mut chain = chain;
    chain.tip = MIN_COIN_AGE + 10;
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::CoinTooYoung { .. })));
}

/// A coinbase output can be attested once MIN_COIN_AGE has passed, which is
/// after it matures: the age rule covers coinbase maturity.
#[test]
fn coin_age_covers_coinbase_maturity() {
    const { assert!(MIN_COIN_AGE >= COINBASE_MATURITY) };
    let (mut chain, att) = setup(&p2wpkh(), ANCHOR - MIN_COIN_AGE, ANCHOR);
    chain.coins.get_mut(&att.outpoint()).unwrap().coinbase = true;
    assert!(evaluate(&att, &chain).is_ok());
}

/// Every network but mainnet takes TEST_MIN_COIN_AGE, at its exact boundary.
#[test]
fn test_networks_take_the_short_coin_age() {
    let signer = p2wpkh();
    for network in [Network::Testnet, Network::Testnet4, Network::Signet, Network::Regtest] {
        let (mut chain, att) = setup(&signer, ANCHOR - TEST_MIN_COIN_AGE, ANCHOR);
        chain.network = network;
        assert!(evaluate(&att, &chain).is_ok(), "{network}");
        let (mut chain, att) = setup(&signer, ANCHOR - TEST_MIN_COIN_AGE + 1, ANCHOR);
        chain.network = network;
        assert_eq!(
            evaluate(&att, &chain),
            Err(Rejection::CoinTooYoung {
                coin_height: ANCHOR - TEST_MIN_COIN_AGE + 1,
                anchor_height: ANCHOR,
                min_age: TEST_MIN_COIN_AGE
            }),
            "{network}"
        );
    }
    // Mainnet keeps the long age.
    let (chain, att) = setup(&signer, ANCHOR - TEST_MIN_COIN_AGE, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::CoinTooYoung { min_age: MIN_COIN_AGE, .. })));
}

/// On a test network a coinbase coin still waits for coinbase maturity: it
/// cannot attest before it can be spent.
#[test]
fn a_test_network_coinbase_waits_for_maturity() {
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, ANCHOR - COINBASE_MATURITY + 1, ANCHOR);
    chain.network = Network::Signet;
    chain.coins.get_mut(&att.outpoint()).unwrap().coinbase = true;
    assert_eq!(
        evaluate(&att, &chain),
        Err(Rejection::CoinTooYoung {
            coin_height: ANCHOR - COINBASE_MATURITY + 1,
            anchor_height: ANCHOR,
            min_age: COINBASE_MATURITY
        })
    );
    // The same coin, not a coinbase, is old enough.
    chain.coins.get_mut(&att.outpoint()).unwrap().coinbase = false;
    assert!(evaluate(&att, &chain).is_ok());
    // A coinbase at maturity attests.
    let (mut chain, att) = setup(&signer, ANCHOR - COINBASE_MATURITY, ANCHOR);
    chain.network = Network::Signet;
    chain.coins.get_mut(&att.outpoint()).unwrap().coinbase = true;
    assert!(evaluate(&att, &chain).is_ok());
}

#[test]
fn a_spent_coin_does_not_count() {
    let (mut chain, att) = setup(&p2wpkh(), COIN_HEIGHT, ANCHOR);
    chain.coins.clear();
    assert_eq!(evaluate(&att, &chain), Err(Rejection::CoinNotFound));
}

#[test]
fn anchor_must_be_the_active_chains_block() {
    let signer = p2wpkh();
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    chain.fork_at = ANCHOR;
    assert_eq!(evaluate(&att, &chain), Err(Rejection::AnchorNotOnChain));
    chain.fork_at = ANCHOR + 1;
    assert!(evaluate(&att, &chain).is_ok());

    // An anchor above the tip: the publisher's chain is ahead.
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, TIP);
    chain.tip = TIP - 1;
    assert_eq!(evaluate(&att, &chain), Err(Rejection::AnchorNotOnChain));
}

#[test]
fn signature_rules() {
    // The signature covers every field of the message.
    let signer = p2wpkh();
    let (chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let other_value = Attestation::new(
        att.outpoint(),
        att.key().into(),
        "no".into(),
        att.anchor_height(),
        att.anchor_hash(),
        att.signature().clone(),
    )
    .unwrap();
    assert!(matches!(evaluate(&other_value, &chain), Err(Rejection::SignatureInvalid(_))));

    // Legacy is for P2PKH only, and the recovered key must be the coin's.
    let legacy = p2pkh();
    let (mut chain, att) = setup(&legacy, COIN_HEIGHT, ANCHOR);
    chain.coins.get_mut(&att.outpoint()).unwrap().script_pubkey = signer.spk.clone();
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::WrongFormat(_))));
    let other_key = PrivateKey::new(secret(9), Network::Regtest).public_key(&Secp256k1::new());
    chain.coins.get_mut(&att.outpoint()).unwrap().script_pubkey = ScriptBuf::new_p2pkh(&other_key.pubkey_hash());
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::SignatureInvalid(_))));
    let mut zeroed = att.clone();
    zeroed.signature = NapSignature::Legacy([0; LEGACY_SIGNATURE_LEN]);
    assert!(matches!(evaluate(&zeroed, &chain), Err(Rejection::SignatureInvalid(_))));

    // Simple is for native segwit only (D13).
    let (mut chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    chain.coins.get_mut(&att.outpoint()).unwrap().script_pubkey = legacy.spk.clone();
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::WrongFormat(_))));

    // An unknown witness version is inconclusive, and that is not valid.
    let future = Signer {
        spk: Builder::new().push_opcode(OP_PUSHNUM_2).push_slice([7u8; 32]).into_script(),
        sign: Box::new(|_| NapSignature::Simple(Witness::new())),
    };
    let (chain, att) = setup(&future, COIN_HEIGHT, ANCHOR);
    let rejection = evaluate(&att, &chain).unwrap_err();
    assert!(matches!(rejection, Rejection::SignatureInconclusive(_)), "{rejection:?}");
}

#[test]
fn chain_state_rejections_are_distinguished_from_bad_signatures() {
    let chain_state = [
        Rejection::AnchorNotOnChain,
        Rejection::Stale { age: FRESHNESS_WINDOW },
        Rejection::CoinNotFound,
        Rejection::CoinTooYoung { coin_height: 2, anchor_height: 1, min_age: 6 },
        Rejection::NotYetValid("x"),
    ];
    assert!(chain_state.iter().all(Rejection::is_chain_state));
    let never = [
        Rejection::CoinTooSmall { value: 1, min: 10_000 },
        Rejection::WrongFormat("x"),
        Rejection::SignatureInvalid("x".into()),
        Rejection::SignatureInconclusive("x".into()),
    ];
    assert!(!never.iter().any(Rejection::is_chain_state));
}

// --- D11 timelocks ------------------------------------------------------------

pub(super) fn cltv(lock: u32) -> Signer {
    let prefix = Builder::new().push_int(i64::from(lock)).push_opcode(OP_CLTV).push_opcode(OP_DROP);
    p2wsh_full(prefix, 0, lock, Sequence::ENABLE_LOCKTIME_NO_RBF.0)
}

pub(super) fn csv(sequence: u32) -> Signer {
    let prefix = Builder::new().push_int(i64::from(sequence)).push_opcode(OP_CSV).push_opcode(OP_DROP);
    p2wsh_full(prefix, 2, 0, sequence)
}

#[test]
fn locktime_height_is_judged_at_the_next_block() {
    let (chain, att) = setup(&cltv(TIP), COIN_HEIGHT, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
    let (mut chain, att) = setup(&cltv(TIP + 1), COIN_HEIGHT, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::NotYetValid(_))));
    // Valid once the chain grows a block.
    chain.tip += 1;
    assert!(evaluate(&att, &chain).is_ok());
}

#[test]
fn locktime_time_is_judged_against_the_tips_mtp() {
    let tip_mtp = mtp(TIP + 1);
    let (chain, att) = setup(&cltv(tip_mtp - 1), COIN_HEIGHT, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
    let (chain, att) = setup(&cltv(tip_mtp), COIN_HEIGHT, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::NotYetValid(_))));
}

#[test]
fn relative_height_lock_counts_from_the_coin() {
    let n = 5_000;
    let (chain, att) = setup(&csv(n), TIP + 1 - n, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
    let (chain, att) = setup(&csv(n), TIP + 2 - n, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::NotYetValid(_))));
}

#[test]
fn relative_time_lock_counts_from_the_coins_mtp() {
    // 5,000 units of 512 s is 4,266.7 blocks of 600 s.
    let seq = Sequence::from_512_second_intervals(5_000).0;
    let (chain, att) = setup(&csv(seq), TIP + 1 - 4_267, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
    let (chain, att) = setup(&csv(seq), TIP + 1 - 4_266, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::NotYetValid(_))));
}

#[test]
fn relative_locks_need_version_2_and_no_disable_flag() {
    // Version 0 and the disable flag both switch BIP 68 off; a script
    // without CSV then needs nothing of the coin's age.
    for (version, sequence) in [(0, 60_000), (2, (1 << 31) | 60_000)] {
        let (chain, att) = setup(&p2wsh_full(Builder::new(), version, 0, sequence), COIN_HEIGHT, ANCHOR);
        assert!(evaluate(&att, &chain).is_ok(), "{version} {sequence:#x}");
    }
    let (chain, att) = setup(&p2wsh_full(Builder::new(), 2, 0, 60_000), COIN_HEIGHT, ANCHOR);
    assert!(matches!(evaluate(&att, &chain), Err(Rejection::NotYetValid(_))));
}

#[test]
fn a_final_sequence_ignores_the_locktime() {
    let signer = p2wsh_full(Builder::new(), 0, TIP + 100, Sequence::MAX.0);
    let (chain, att) = setup(&signer, COIN_HEIGHT, ANCHOR);
    assert!(evaluate(&att, &chain).is_ok());
}

// --- Supersession ---------------------------------------------------------------

#[test]
fn the_higher_anchor_counts() {
    let signer = p2wpkh();
    let (chain, old) = setup(&signer, COIN_HEIGHT, ANCHOR - 100);
    let new = attest(&chain, &signer, old.outpoint(), old.key(), "no", ANCHOR);
    assert!(supersedes(&new, &old) && !supersedes(&old, &new));
    for order in [[&old, &new], [&new, &old]] {
        let sel = select(order);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[&(old.outpoint(), old.key())].value(), "no");
    }
}

#[test]
fn a_tie_goes_to_the_lower_id() {
    let signer = p2wpkh();
    let (chain, a) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let b = attest(&chain, &signer, a.outpoint(), a.key(), "no", ANCHOR);
    let (lo, hi) = if a.id().to_byte_array() < b.id().to_byte_array() { (&a, &b) } else { (&b, &a) };
    assert!(supersedes(lo, hi) && !supersedes(hi, lo));
    assert!(!supersedes(lo, lo));
    for order in [[lo, hi], [hi, lo]] {
        assert_eq!(select(order)[&(a.outpoint(), a.key())], lo);
    }
}

#[test]
fn an_empty_value_withdraws() {
    let signer = p2wpkh();
    let (chain, vote) = setup(&signer, COIN_HEIGHT, ANCHOR - 1);
    let withdrawal = attest(&chain, &signer, vote.outpoint(), vote.key(), "", ANCHOR);
    assert!(evaluate(&withdrawal, &chain).is_ok());
    let sel = select([&vote, &withdrawal]);
    assert!(sel[&(vote.outpoint(), vote.key())].is_withdrawal());
}

#[test]
fn keys_and_outpoints_are_counted_apart() {
    let signer = p2wpkh();
    let (mut chain, a) = setup(&signer, COIN_HEIGHT, ANCHOR);
    let other_key = attest(&chain, &signer, a.outpoint(), "mempool.rbf_policy", "full", ANCHOR);
    chain.coins.insert(outpoint(8), chain.coins[&a.outpoint()].clone());
    let other_coin = attest(&chain, &signer, outpoint(8), a.key(), "no", ANCHOR);
    assert_eq!(select([&a, &other_key, &other_coin]).len(), 3);
}

/// A reorg that takes out the newer attestation's anchor makes it invalid,
/// and the holder's earlier attestation counts again.
#[test]
fn a_reorganised_anchor_restores_the_earlier_attestation() {
    let signer = p2wpkh();
    let (mut chain, old) = setup(&signer, COIN_HEIGHT, ANCHOR - 100);
    let new = attest(&chain, &signer, old.outpoint(), old.key(), "no", ANCHOR);
    chain.fork_at = ANCHOR - 10;
    assert_eq!(evaluate(&new, &chain), Err(Rejection::AnchorNotOnChain));
    let valid: Vec<&Attestation> = [&old, &new].into_iter().filter(|a| evaluate(a, &chain).is_ok()).collect();
    assert_eq!(select(valid)[&(old.outpoint(), old.key())], &old);
}

#[test]
fn id_is_the_sha256_of_the_wire_form() {
    let (_, att) = setup(&p2pkh(), COIN_HEIGHT, ANCHOR);
    assert_eq!(att.id(), bitcoin::hashes::sha256::Hash::hash(&att.to_bytes()));
}
