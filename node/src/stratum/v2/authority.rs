//! The Stratum V2 server's authority key, kept on disk.
//!
//! A Stratum V2 miner authenticates the server by its authority public key:
//! either configured in advance, or trusted on first use and remembered. A key
//! that changed on every restart would make every attached miner refuse the
//! node until someone reconfigured it, so the key is generated once and kept
//! in the datadir, like the RPC cookie.

use std::fs;
use std::io;
use std::path::Path;

/// File name for the authority key inside the network datadir.
pub const AUTHORITY_KEY_FILE: &str = "stratum_v2.key";

/// Where the key the server is about to use came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyOrigin {
    /// Read from a file that was already there.
    Loaded,
    /// Generated and written, because there was no file.
    Created,
}

/// Read the authority key at `path`, generating and storing one if absent.
///
/// A file that is present but unreadable or malformed is an error, never a
/// reason to make a new key: regenerating would hand every miner a public key
/// it does not trust, which is the failure this file exists to prevent.
pub fn load_or_create(path: &Path) -> io::Result<([u8; 32], KeyOrigin)> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok((parse_key(&contents)?, KeyOrigin::Loaded)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => match create(path) {
            Ok(key) => Ok((key, KeyOrigin::Created)),
            // Another process wrote the file between the read and the create.
            // Its key is the one on disk, so use it rather than failing.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                let contents = fs::read_to_string(path)?;
                Ok((parse_key(&contents)?, KeyOrigin::Loaded))
            }
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    }
}

/// The x-only public key a miner is configured with.
pub fn authority_pubkey(key: &[u8; 32]) -> Result<[u8; 32], bitcoin::secp256k1::Error> {
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(key)?;
    let (xonly, _parity) = secret.x_only_public_key(&secp);
    Ok(xonly.serialize())
}

/// The public key in the base58check form Stratum V2 tooling and miner
/// firmware accept: a little-endian `u16` key version of 1, then the 32-byte
/// x-only key.
pub fn authority_pubkey_base58(pubkey: &[u8; 32]) -> String {
    let mut payload = [0u8; 34];
    payload[..2].copy_from_slice(&1u16.to_le_bytes());
    payload[2..].copy_from_slice(pubkey);
    bitcoin::base58::encode_check(&payload)
}

fn parse_key(contents: &str) -> io::Result<[u8; 32]> {
    let bytes = hex::decode(contents.trim()).map_err(|e| invalid(format!("not hex ({e})")))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("expected 32 bytes, found {}", bytes.len())))?;
    // A value outside the curve order would otherwise surface as a handshake
    // failure against the first miner to connect. Say so at startup.
    bitcoin::secp256k1::SecretKey::from_slice(&key)
        .map_err(|e| invalid(format!("not a valid secp256k1 key ({e})")))?;
    Ok(key)
}

/// The caller adds the path, which a bare `io::Error` does not carry.
fn invalid(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

fn create(path: &Path) -> io::Result<[u8; 32]> {
    use std::io::Write;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (secret, _) = secp.generate_keypair(&mut rand::thread_rng());
    let key = secret.secret_bytes();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // The mode is set on the open, not afterwards: in between, the secret
    // would be readable by anyone for as long as the gap lasted.
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(format!("{}\n", hex::encode(key)).as_bytes())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_missing_key_is_generated_and_kept() {
        let dir = tmpdir();
        let path = dir.path().join(AUTHORITY_KEY_FILE);

        let (first, origin) = load_or_create(&path).unwrap();
        assert_eq!(origin, KeyOrigin::Created);
        assert!(path.exists(), "the generated key is written out");

        let (second, origin) = load_or_create(&path).unwrap();
        assert_eq!(origin, KeyOrigin::Loaded);
        assert_eq!(first, second, "a restart gets the same key, not a new one");
    }

    #[cfg(unix)]
    #[test]
    fn a_generated_key_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let path = dir.path().join(AUTHORITY_KEY_FILE);
        load_or_create(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_key_file_that_cannot_be_read_is_an_error_not_a_new_key() {
        let dir = tmpdir();
        let path = dir.path().join(AUTHORITY_KEY_FILE);
        let zero = "00".repeat(32);
        for bad in ["not hex at all", "abcd", zero.as_str()] {
            fs::write(&path, bad).unwrap();
            let err = load_or_create(&path).expect_err("a bad key file fails the start");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{bad}");
            assert_eq!(fs::read_to_string(&path).unwrap(), bad, "the file is left alone");
        }
    }

    #[test]
    fn surrounding_whitespace_does_not_change_the_key() {
        let dir = tmpdir();
        let path = dir.path().join(AUTHORITY_KEY_FILE);
        let (generated, _) = load_or_create(&path).unwrap();
        fs::write(&path, format!("  {}\n\n", hex::encode(generated))).unwrap();
        let (loaded, origin) = load_or_create(&path).unwrap();
        assert_eq!(origin, KeyOrigin::Loaded);
        assert_eq!(loaded, generated);
    }

    #[test]
    fn the_pubkey_is_the_one_the_noise_responder_accepts() {
        let dir = tmpdir();
        let (key, _) = load_or_create(&dir.path().join(AUTHORITY_KEY_FILE)).unwrap();
        let public = authority_pubkey(&key).unwrap();
        // The responder refuses a public key that does not match the private.
        assert!(
            stratum_core::noise_sv2::Responder::from_authority_kp(
                &public,
                &key,
                std::time::Duration::from_secs(3600),
            )
            .is_ok()
        );
        let encoded = authority_pubkey_base58(&public);
        let decoded = bitcoin::base58::decode_check(&encoded).unwrap();
        assert_eq!(&decoded[..2], &[1, 0]);
        assert_eq!(&decoded[2..], &public);
    }
}
