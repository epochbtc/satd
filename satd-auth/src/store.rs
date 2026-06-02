//! The TOML bearer-token table: `auth.toml`, referenced by `authfile=` in
//! `bitcoin.conf`.
//!
//! The file stores `SHA-256(token)`, never the plaintext (SATD_AUTH_PLAN.md §5).
//! A client presents the plaintext token; the verifier hashes it and looks the
//! digest up here. The file must be `0600` or the load is refused (mirroring the
//! cookie / SSH-key convention). Removing a `[[token]]` and reloading revokes it.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use toml_edit::{DocumentMut, Item};

use crate::capability::CapabilitySet;
use crate::error::StoreError;
use crate::principal::Principal;
use crate::quota::{Accounting, RatePolicy, unlimited};

/// The expected on-disk schema version. Unknown versions are rejected
/// (recognize-reject) so a future format can't be silently mis-read.
const SCHEMA_VERSION: i64 = 1;

/// One parsed `[[token]]` entry.
#[derive(Debug, Clone)]
pub struct TokenEntry {
    /// Operator-chosen identifier (for logging/accounting; never the secret).
    pub id: Arc<str>,
    /// `SHA-256(token)` — the lookup key.
    pub hash: [u8; 32],
    /// Capabilities this token grants.
    pub caps: CapabilitySet,
    /// Per-principal watch-set ceiling (units). `None` = unlimited.
    pub watch_quota: Option<u64>,
    /// Per-principal request rate ceiling. `None` = unlimited.
    pub rate_limit: Option<RatePolicy>,
    /// Expiry as a unix timestamp (seconds). `None` = never expires.
    pub expires: Option<i64>,
}

/// An immutable snapshot of the token table, swapped atomically on reload.
#[derive(Debug, Default)]
pub struct TokenTable {
    /// Schema version (always [`SCHEMA_VERSION`] today).
    pub version: i64,
    by_hash: HashMap<[u8; 32], TokenEntry>,
}

impl TokenTable {
    /// Look up an entry by `SHA-256(token)`. The caller still verifies expiry
    /// and runs a constant-time tag check.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&TokenEntry> {
        self.by_hash.get(hash)
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Are there no tokens?
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    fn ids(&self) -> HashSet<Arc<str>> {
        self.by_hash.values().map(|e| e.id.clone()).collect()
    }
}

/// What changed between two table revisions (for logging revocations).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadDelta {
    /// Token ids present after the reload but not before.
    pub added: Vec<String>,
    /// Token ids present before the reload but not after (revoked).
    pub removed: Vec<String>,
}

/// A live, reloadable token store. Reads are lock-light (read-lock + `Arc`
/// clone of the current table); reload takes a brief write-lock to swap.
pub struct TokenStore {
    inner: RwLock<Arc<TokenTable>>,
    path: PathBuf,
    /// Accounting handle attached to every resolved token principal. Defaults to
    /// the no-op unlimited backend; the daemon swaps in a shared
    /// [`LocalAccounting`](crate::LocalAccounting) (or a future remote backend)
    /// via [`with_accounting`](Self::with_accounting) when enforcement is on.
    accounting: Arc<dyn Accounting>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `accounting` is a trait object (not Debug); omit it.
        f.debug_struct("TokenStore")
            .field("path", &self.path)
            .field("tokens", &self.inner.read().len())
            .finish()
    }
}

impl TokenStore {
    /// Load and validate the token file. Refuses group/world-accessible perms.
    /// Token principals get the no-op unlimited accounting until
    /// [`with_accounting`](Self::with_accounting) attaches a real backend.
    pub fn load(path: impl AsRef<Path>) -> Result<TokenStore, StoreError> {
        let path = path.as_ref().to_path_buf();
        let table = read_and_parse(&path)?;
        Ok(TokenStore {
            inner: RwLock::new(Arc::new(table)),
            path,
            accounting: unlimited(),
        })
    }

    /// Attach a shared accounting backend (rate limiter + watch-set quota store).
    /// Every token principal this store resolves will carry it, so per-principal
    /// caps survive across the principal's connections.
    pub fn with_accounting(mut self, accounting: Arc<dyn Accounting>) -> TokenStore {
        self.accounting = accounting;
        self
    }

    /// Re-read the file and swap the table atomically. On any error the current
    /// (last-good) table is **retained** and the error returned — a SIGHUP
    /// reload of a malformed file never leaves the node without auth.
    pub fn reload(&self) -> Result<ReloadDelta, StoreError> {
        let new_table = read_and_parse(&self.path)?;
        let new_ids = new_table.ids();

        let mut guard = self.inner.write();
        let old_ids = guard.ids();

        let added = new_ids
            .difference(&old_ids)
            .map(|s| s.to_string())
            .collect();
        let removed = old_ids
            .difference(&new_ids)
            .map(|s| s.to_string())
            .collect();

        *guard = Arc::new(new_table);
        Ok(ReloadDelta { added, removed })
    }

    /// A cheap `Arc` snapshot of the current table for the lookup hot path.
    pub fn snapshot(&self) -> Arc<TokenTable> {
        self.inner.read().clone()
    }

    /// Resolve a presented bearer token to a token [`Principal`], or `None` if
    /// it is unknown, expired, or revoked. `now` is unix seconds.
    ///
    /// The token is SHA-256'd and looked up by digest; the stored hash is then
    /// re-compared in constant time (`subtle`) so the accept decision never
    /// short-circuits on a near-collision. Token principals carry the no-op
    /// unlimited accounting handle for now; per-principal rate/quota accounting
    /// is wired in a later PR.
    pub fn resolve(&self, token: &str, now: i64) -> Option<Principal> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let table = self.snapshot();
        let entry = table.get(&digest)?;
        if !bool::from(entry.hash.ct_eq(&digest)) {
            return None;
        }
        if let Some(exp) = entry.expires
            && now >= exp
        {
            return None;
        }
        Some(Principal::token(
            entry.id.clone(),
            entry.caps,
            entry.watch_quota,
            entry.rate_limit,
            self.accounting.clone(),
        ))
    }

    /// The file path this store loads from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Open the file, enforce perms from the open handle (no TOCTOU), read, parse.
fn read_and_parse(path: &Path) -> Result<TokenTable, StoreError> {
    let mut file = std::fs::File::open(path).map_err(|source| StoreError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| StoreError::Io {
        path: path.display().to_string(),
        source,
    })?;
    check_perms(path, &meta)?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|source| StoreError::Io {
            path: path.display().to_string(),
            source,
        })?;
    parse_table(path, &content)
}

#[cfg(unix)]
fn check_perms(path: &Path, meta: &std::fs::Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(StoreError::Permissions {
            path: path.display().to_string(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_perms(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), StoreError> {
    Ok(())
}

fn parse_table(path: &Path, content: &str) -> Result<TokenTable, StoreError> {
    let malformed = |detail: String| StoreError::Malformed {
        path: path.display().to_string(),
        detail,
    };

    let doc = content
        .parse::<DocumentMut>()
        .map_err(|e| malformed(e.to_string()))?;

    let version = doc
        .get("version")
        .and_then(Item::as_integer)
        .ok_or_else(|| malformed("missing or non-integer `version`".into()))?;
    if version != SCHEMA_VERSION {
        return Err(malformed(format!(
            "unsupported schema version {version} (expected {SCHEMA_VERSION})"
        )));
    }

    let mut by_hash: HashMap<[u8; 32], TokenEntry> = HashMap::new();

    if let Some(tokens) = doc.get("token") {
        let arr = tokens.as_array_of_tables().ok_or_else(|| {
            malformed("`token` must be an array of tables (`[[token]]`)".into())
        })?;
        for (i, t) in arr.iter().enumerate() {
            let ctx = |d: String| malformed(format!("[[token]] #{}: {d}", i + 1));

            let id = t
                .get("id")
                .and_then(Item::as_str)
                .ok_or_else(|| ctx("missing or non-string `id`".into()))?;

            let hash_str = t
                .get("hash")
                .and_then(Item::as_str)
                .ok_or_else(|| ctx("missing or non-string `hash`".into()))?;
            let hash = parse_hash(hash_str).map_err(|d| ctx(format!("`hash` {d}")))?;

            let caps = match t.get("capabilities") {
                None => CapabilitySet::EMPTY,
                Some(item) => {
                    let arr = item
                        .as_array()
                        .ok_or_else(|| ctx("`capabilities` must be an array".into()))?;
                    let strs: Result<Vec<&str>, _> = arr
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .ok_or_else(|| ctx("`capabilities` entries must be strings".into()))
                        })
                        .collect();
                    CapabilitySet::from_strs(strs?)
                        .map_err(|bad| ctx(format!("unknown capability `{bad}`")))?
                }
            };

            let watch_quota = match t.get("watch_quota") {
                None => None,
                Some(item) => Some(
                    item.as_integer()
                        .and_then(|n| u64::try_from(n).ok())
                        .ok_or_else(|| ctx("`watch_quota` must be a non-negative integer".into()))?,
                ),
            };

            let rate_limit = match t.get("rate_limit") {
                None => None,
                Some(item) => {
                    let s = item
                        .as_str()
                        .ok_or_else(|| ctx("`rate_limit` must be a string like \"200/s\"".into()))?;
                    Some(RatePolicy::parse(s).map_err(|bad| ctx(format!("invalid `rate_limit` `{bad}`")))?)
                }
            };

            let expires = match t.get("expires") {
                None => None,
                Some(item) => Some(parse_expires(item).map_err(|d| ctx(format!("`expires` {d}")))?),
            };

            let entry = TokenEntry {
                id: Arc::from(id),
                hash,
                caps,
                watch_quota,
                rate_limit,
                expires,
            };
            if by_hash.insert(hash, entry).is_some() {
                return Err(ctx("duplicate token hash".into()));
            }
        }
    }

    Ok(TokenTable { version, by_hash })
}

/// Parse a `sha256:<64 hex>` digest.
fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s
        .strip_prefix("sha256:")
        .ok_or_else(|| "must be `sha256:<64 hex chars>`".to_string())?;
    let bytes = hex::decode(hex_str).map_err(|_| "is not valid hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "must be 32 bytes (64 hex chars)".to_string())?;
    Ok(arr)
}

/// Parse an `expires` value: a TOML datetime (unquoted RFC 3339, e.g.
/// `2026-12-31T00:00:00Z`) or an integer unix timestamp (seconds). A quoted
/// string is rejected — drop the quotes to make it a TOML datetime.
fn parse_expires(item: &Item) -> Result<i64, String> {
    if let Some(n) = item.as_integer() {
        return Ok(n);
    }
    if let Some(dt) = item.as_datetime() {
        return datetime_to_unix(dt);
    }
    Err("must be a TOML datetime (unquoted, e.g. 2026-12-31T00:00:00Z) \
         or an integer unix timestamp"
        .to_string())
}

fn datetime_to_unix(dt: &toml_edit::Datetime) -> Result<i64, String> {
    let date = dt
        .date
        .ok_or_else(|| "must include a date".to_string())?;
    let (hour, minute, second) = match dt.time {
        Some(t) => (
            t.hour as i64,
            t.minute as i64,
            t.second.unwrap_or(0) as i64,
        ),
        None => (0, 0, 0),
    };
    let days = days_from_civil(date.year as i64, date.month as i64, date.day as i64);
    let mut secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    // Normalize the stated offset back to UTC.
    if let Some(offset) = dt.offset {
        match offset {
            toml_edit::Offset::Z => {}
            toml_edit::Offset::Custom { minutes } => secs -= minutes as i64 * 60,
        }
    }
    Ok(secs)
}

/// Days from the unix epoch (1970-01-01) for a proleptic-Gregorian date.
/// Howard Hinnant's `days_from_civil` — exact, branch-light, dependency-free.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // Mar = 0 .. Feb = 11
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    fn sha256_hex(token: &str) -> String {
        let d = Sha256::digest(token.as_bytes());
        format!("sha256:{}", hex::encode(d))
    }

    fn write_file(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let _ = mode;
        p
    }

    #[test]
    fn loads_a_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let toml = format!(
            r#"
version = 1

[[token]]
id = "btcpay"
hash = "{}"
capabilities = ["rpc:read", "esplora:read"]
watch_quota = 50000
rate_limit = "200/s"

[[token]]
id = "watchtower"
hash = "{}"
capabilities = ["stream:subscribe", "stream:watch"]
"#,
            sha256_hex("token-one"),
            sha256_hex("token-two"),
        );
        let p = write_file(dir.path(), "auth.toml", &toml, 0o600);
        let store = TokenStore::load(&p).unwrap();
        let table = store.snapshot();
        assert_eq!(table.len(), 2);

        let h = Sha256::digest(b"token-one");
        let entry = table.get(&h.into()).unwrap();
        assert_eq!(&*entry.id, "btcpay");
        assert!(entry.caps.contains(crate::Capability::RpcRead));
        assert_eq!(entry.watch_quota, Some(50000));
        assert_eq!(entry.rate_limit, Some(RatePolicy { burst: 200, per_sec: 200 }));
        assert!(entry.expires.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_or_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let toml = format!("version = 1\n[[token]]\nid=\"x\"\nhash=\"{}\"\n", sha256_hex("t"));
        let p = write_file(dir.path(), "auth.toml", &toml, 0o644);
        let err = TokenStore::load(&p).unwrap_err();
        assert!(matches!(err, StoreError::Permissions { .. }), "{err}");
    }

    #[test]
    fn rejects_unknown_capability_and_bad_hash() {
        let dir = tempfile::tempdir().unwrap();

        let bad_cap = format!(
            "version=1\n[[token]]\nid=\"x\"\nhash=\"{}\"\ncapabilities=[\"rpc:admin\"]\n",
            sha256_hex("t")
        );
        let p = write_file(dir.path(), "a.toml", &bad_cap, 0o600);
        let e = TokenStore::load(&p).unwrap_err();
        assert!(matches!(e, StoreError::Malformed { .. }), "{e}");

        let bad_hash = "version=1\n[[token]]\nid=\"x\"\nhash=\"deadbeef\"\n";
        let p = write_file(dir.path(), "b.toml", bad_hash, 0o600);
        let e = TokenStore::load(&p).unwrap_err();
        assert!(matches!(e, StoreError::Malformed { .. }), "{e}");

        let bad_version = "version=2\n";
        let p = write_file(dir.path(), "c.toml", bad_version, 0o600);
        let e = TokenStore::load(&p).unwrap_err();
        assert!(matches!(e, StoreError::Malformed { .. }), "{e}");
    }

    #[test]
    fn reload_revokes_removed_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let two = format!(
            "version=1\n[[token]]\nid=\"a\"\nhash=\"{}\"\n[[token]]\nid=\"b\"\nhash=\"{}\"\n",
            sha256_hex("aaa"),
            sha256_hex("bbb"),
        );
        let p = write_file(dir.path(), "auth.toml", &two, 0o600);
        let store = TokenStore::load(&p).unwrap();
        assert_eq!(store.snapshot().len(), 2);

        // Rewrite with only token "a".
        let one = format!("version=1\n[[token]]\nid=\"a\"\nhash=\"{}\"\n", sha256_hex("aaa"));
        write_file(dir.path(), "auth.toml", &one, 0o600);
        let delta = store.reload().unwrap();
        assert_eq!(delta.removed, vec!["b".to_string()]);
        assert!(delta.added.is_empty());

        let table = store.snapshot();
        assert_eq!(table.len(), 1);
        // "bbb" is now revoked.
        let h: [u8; 32] = Sha256::digest(b"bbb").into();
        assert!(table.get(&h).is_none());
    }

    #[test]
    fn reload_error_retains_last_good_table() {
        let dir = tempfile::tempdir().unwrap();
        let good = format!("version=1\n[[token]]\nid=\"a\"\nhash=\"{}\"\n", sha256_hex("aaa"));
        let p = write_file(dir.path(), "auth.toml", &good, 0o600);
        let store = TokenStore::load(&p).unwrap();

        write_file(dir.path(), "auth.toml", "this is not valid toml {{{", 0o600);
        assert!(store.reload().is_err());
        // Last-good table preserved.
        let h: [u8; 32] = Sha256::digest(b"aaa").into();
        assert!(store.snapshot().get(&h).is_some());
    }

    #[test]
    fn expires_parsing() {
        // 2021-01-01T00:00:00Z == 1609459200
        let dir = tempfile::tempdir().unwrap();
        let toml = format!(
            "version=1\n[[token]]\nid=\"x\"\nhash=\"{}\"\nexpires=2021-01-01T00:00:00Z\n",
            sha256_hex("t")
        );
        let p = write_file(dir.path(), "auth.toml", &toml, 0o600);
        let store = TokenStore::load(&p).unwrap();
        let table = store.snapshot();
        let h: [u8; 32] = Sha256::digest(b"t").into();
        assert_eq!(table.get(&h).unwrap().expires, Some(1_609_459_200));
    }

    #[test]
    fn days_from_civil_known_points() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2021, 1, 1), 18628);
    }
}
