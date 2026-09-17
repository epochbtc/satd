//! The `sp1…` address codec, refereed against BIP 352's vectors.

use bitcoin::Network;
use bitcoin::secp256k1::PublicKey;
use satd_psbt::{AddressError, SpAddress};
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../node-sp-index/tests/vectors/send_and_receive_test_vectors.json");

/// Every address the BIP publishes, decoded and re-encoded. Round-tripping
/// both ways is what catches a codec that is self-consistently wrong.
#[test]
fn bip352_addresses_round_trip() {
    let doc: Value = serde_json::from_str(VECTORS).expect("the vector file parses");
    let mut checked = 0usize;

    for case in doc.as_array().expect("an array") {
        for send in case["sending"].as_array().expect("a sending array") {
            for r in send["given"]["recipients"].as_array().expect("recipients") {
                let text = r["address"].as_str().expect("an address");
                let (address, hrp) = SpAddress::decode_any(text)
                    .unwrap_or_else(|e| panic!("{text}: should decode: {e}"));

                assert_eq!(
                    address.scan_key,
                    public_key(r["scan_pub_key"].as_str().expect("a scan key")),
                    "{text}"
                );
                assert_eq!(
                    address.spend_key,
                    public_key(r["spend_pub_key"].as_str().expect("a spend key")),
                    "{text}"
                );

                let network = match hrp.as_str() {
                    "sp" => Network::Bitcoin,
                    _ => Network::Signet,
                };
                assert_eq!(
                    address.encode(network),
                    text.to_ascii_lowercase(),
                    "re-encoding {text} changed it"
                );
                // And the network check refuses the other side.
                let other = match network {
                    Network::Bitcoin => Network::Regtest,
                    _ => Network::Bitcoin,
                };
                assert!(matches!(
                    SpAddress::decode(text, other),
                    Err(AddressError::WrongNetwork { .. })
                ));
                checked += 1;
            }
        }
    }
    assert!(checked > 20, "only {checked} addresses checked");
}

/// A silent payment address is about 117 characters — well past BIP 173's
/// 90-character cap for segwit addresses. A codec that reuses a segwit
/// decoder rejects every one of them, which is the single easiest way to get
/// this wrong.
#[test]
fn addresses_are_longer_than_a_segwit_address_may_be() {
    let address = sample();
    let text = address.encode(Network::Bitcoin);
    assert!(text.len() > 90, "expected a long address, got {}", text.len());
    assert!(text.starts_with("sp1q"), "{text}");
    assert_eq!(SpAddress::decode(&text, Network::Bitcoin).unwrap(), address);
}

#[test]
fn every_test_network_shares_one_human_readable_part() {
    let address = sample();
    for network in [Network::Testnet, Network::Testnet4, Network::Signet, Network::Regtest] {
        let text = address.encode(network);
        assert!(text.starts_with("tsp1"), "{network}: {text}");
        // And an address written for one test network decodes on the others,
        // because BIP 352 gives them all the same prefix.
        for other in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert_eq!(SpAddress::decode(&text, other).unwrap(), address);
        }
        assert!(matches!(
            SpAddress::decode(&text, Network::Bitcoin),
            Err(AddressError::WrongNetwork { .. })
        ));
    }
}

#[test]
fn a_corrupt_address_is_refused() {
    let text = sample().encode(Network::Bitcoin);

    // One character changed: the checksum catches it.
    let mut broken = text.clone();
    let last = broken.pop().expect("non-empty");
    broken.push(if last == 'q' { 'p' } else { 'q' });
    assert!(matches!(
        SpAddress::decode(&broken, Network::Bitcoin),
        Err(AddressError::Malformed(_))
    ));

    // Not bech32 at all.
    assert!(SpAddress::decode("not an address", Network::Bitcoin).is_err());
    assert!(SpAddress::decode("", Network::Bitcoin).is_err());

    // A bech32m string with the wrong prefix.
    assert!(SpAddress::decode_any("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").is_err());
}

/// Version 31 is reserved so a future format cannot be misread as one a wallet
/// can already pay. Versions 1 to 30 are forward-compatible: read the two keys
/// and ignore what follows.
#[test]
fn version_handling_follows_bip352() {
    let address = sample();

    for version in [1u8, 15, 30] {
        let longer = SpAddress {
            version,
            ..address
        };
        let text = longer.encode(Network::Bitcoin);
        let decoded = SpAddress::decode(&text, Network::Bitcoin).expect("decodes");
        assert_eq!(decoded.version, version);
        assert_eq!(decoded.scan_key, address.scan_key);
        // But this node will not create an output for it.
        assert!(matches!(
            decoded.require_v0(),
            Err(AddressError::UnsupportedForCreation(v)) if v == version
        ));
    }

    let reserved = SpAddress {
        version: 31,
        ..address
    };
    let text = reserved.encode(Network::Bitcoin);
    assert!(matches!(
        SpAddress::decode(&text, Network::Bitcoin),
        Err(AddressError::UnknownVersion(31))
    ));

    assert!(address.require_v0().is_ok());
}

/// A version 0 address is exactly two keys. Anything longer means a field the
/// reader does not understand, and paying it would be a guess.
#[test]
fn a_version_0_payload_must_be_exactly_two_keys() {
    let address = sample();
    let text = address.encode(Network::Bitcoin);

    // Splice extra data into a version 1 address (allowed) and the same into
    // a version 0 one (refused), so the difference is the version alone.
    let mut padded = address.to_info();
    padded.extend_from_slice(&[0xab; 8]);

    for (version, should_decode) in [(0u8, false), (1u8, true)] {
        let encoded = encode_raw(version, &padded);
        let decoded = SpAddress::decode(&encoded, Network::Bitcoin);
        assert_eq!(
            decoded.is_ok(),
            should_decode,
            "version {version} with a long payload: {decoded:?}"
        );
    }

    // And a payload too short for two keys is refused at any version.
    for version in [0u8, 1] {
        let short = encode_raw(version, &address.to_info()[..40]);
        assert!(matches!(
            SpAddress::decode(&short, Network::Bitcoin),
            Err(AddressError::BadPayloadLength { .. })
        ));
    }

    assert!(SpAddress::decode(&text, Network::Bitcoin).is_ok());
}

#[test]
fn looks_like_matches_what_decode_accepts() {
    let address = sample();
    assert!(SpAddress::looks_like(
        &address.encode(Network::Bitcoin),
        Network::Bitcoin
    ));
    assert!(SpAddress::looks_like(
        &address.encode(Network::Regtest),
        Network::Regtest
    ));
    assert!(!SpAddress::looks_like(
        &address.encode(Network::Bitcoin),
        Network::Regtest
    ));
    assert!(!SpAddress::looks_like(
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202",
        Network::Regtest
    ));
    // Upper case is a valid bech32 spelling and must not fool the sniff.
    assert!(SpAddress::looks_like(
        &address.encode(Network::Bitcoin).to_uppercase(),
        Network::Bitcoin
    ));
}

// ---------------------------------------------------------------------------

fn sample() -> SpAddress {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let scan = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
    let spend = bitcoin::secp256k1::SecretKey::from_slice(&[0x22u8; 32]).unwrap();
    SpAddress::new(scan.public_key(&secp), spend.public_key(&secp))
}

/// Encode an arbitrary payload under a version, to build the shapes the codec
/// has to refuse.
fn encode_raw(version: u8, payload: &[u8]) -> String {
    use bitcoin::bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
    use bitcoin::bech32::{Bech32m, Fe32, Hrp};
    let hrp = Hrp::parse_unchecked("sp");
    payload
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::try_from(version).expect("a field element"))
        .chars()
        .collect()
}

fn public_key(hex: &str) -> PublicKey {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    PublicKey::from_slice(&bytes).expect("a public key")
}
