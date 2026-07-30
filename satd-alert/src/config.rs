//! The `alertfile=` format: parsing, validation, and permission checks.
//!
//! ```toml
//! version = 1
//!
//! [[webhook]]
//! id = "ops"                      # unique; appears in headers and metric labels
//! url = "https://alerts.example/satd"
//! secret = "a-long-random-string" # required — it signs the body
//! categories = ["status"]         # status | chain | mempool | heartbeat
//! kinds = ["tip_stall", "disk_low"]   # optional, status only
//! min_severity = "warning"            # optional, status only
//! heartbeat_interval_secs = 60        # optional dead-man ping; default off
//! ```
//!
//! Why a file rather than flat `bitcoin.conf` keys: a hook has a secret, a
//! filter, and (from the watch-set work) a watch-set. Core's config format is
//! flat and first-wins, so several hooks cannot be expressed in it without
//! inventing an index syntax. The precedent is `authfile=`, which is the same
//! shape for the same reason — down to the 0600 permission check, since both
//! files hold secrets.
//!
//! Validation is **recognize-and-reject**, matching satd's config posture: an
//! unknown key, an unknown category, a duplicate id, or a missing secret is a
//! hard error. An accepted-but-ignored alerting rule is worse than a refused
//! one — the operator believes they are covered when they are not.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use node::events::{StatusKind, StatusSeverity};

/// Per-hook outbound queue depth. Delivery is serial per hook, so this is how
/// far a hook may fall behind before events are dropped and the gap is reported
/// to the receiver as a `Lagged` notice. 1024 is the same order as the
/// publisher's own replay ring: enough to ride out a receiver restart, small
/// enough that a permanently dead endpoint cannot grow memory without bound.
pub const HOOK_QUEUE_CAPACITY: usize = 1024;

/// The only alertfile schema version this build understands.
pub const ALERTFILE_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum AlertFileError {
    #[error("alertfile {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "alertfile {path} is group/world accessible (mode {mode:04o}); it holds webhook signing \
         secrets — run: chmod 600 {path}"
    )]
    Permissions { path: PathBuf, mode: u32 },
    #[error("alertfile {path}: not valid TOML: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml_edit::TomlError,
    },
    #[error("alertfile {path}: {message}")]
    Invalid { path: PathBuf, message: String },
}

impl AlertFileError {
    fn invalid(path: &Path, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.to_path_buf(),
            message: message.into(),
        }
    }
}

/// Which event classes a hook receives, as a mask of the streaming API's
/// category bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CategoryMask(pub u32);

impl CategoryMask {
    pub fn contains(self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

/// A hook's event filter: categories, then (for status events) kinds and a
/// severity floor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookFilter {
    pub categories: CategoryMask,
    /// `None` = every kind in the subscribed categories. Only meaningful for
    /// status events; a hook that filters kinds still receives whatever other
    /// categories it asked for.
    pub kinds: Option<BTreeSet<StatusKind>>,
    /// `None` = no floor. Status events only.
    pub min_severity: Option<StatusSeverity>,
}

impl HookFilter {
    /// Whether a status event passes this filter. `category_bit` is checked by
    /// the caller for non-status bodies; this is the status-specific half.
    pub fn accepts_status(&self, kind: StatusKind, severity: StatusSeverity) -> bool {
        if !self.categories.contains(node::events::CATEGORY_STATUS) {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&kind)
        {
            return false;
        }
        if let Some(min) = self.min_severity
            && severity < min
        {
            return false;
        }
        true
    }
}

/// One configured webhook.
///
/// `Debug` is hand-written: a derived one renders `secret` in full, and a
/// single `tracing::debug!(?hook)` added later would put a signing key in the
/// log. The crate already takes this posture for watch-set scan keys.
#[derive(Clone, PartialEq, Eq)]
pub struct Hook {
    pub id: String,
    pub url: String,
    /// Required. An unsigned webhook invites anyone who learns the URL to
    /// forge node events into the operator's alerting pipeline, and a secret
    /// costs nothing.
    pub secret: String,
    pub filter: HookFilter,
    /// Forward at most one heartbeat per interval, as a dead-man's switch
    /// ("tell me when my node goes quiet"). `None` = off. The bus heartbeat is
    /// 1 Hz, which no HTTP receiver wants unthrottled.
    pub heartbeat_interval_secs: Option<u64>,
    /// Permit a plaintext `http://` URL to a non-loopback, non-private
    /// address. Off by default: webhook bodies carry chain data rather than
    /// secrets, but signed-then-cleartext is still a footgun.
    pub allow_insecure_http: bool,
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hook")
            .field("id", &self.id)
            .field("url", &self.url)
            .field("secret", &"<redacted>")
            .field("filter", &self.filter)
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}



/// A parsed, validated alertfile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertFile {
    pub hooks: Vec<Hook>,
}

impl AlertFile {
    /// Read, permission-check, parse, and validate an alertfile.
    pub fn load(path: &Path) -> Result<Self, AlertFileError> {
        let file = std::fs::File::open(path).map_err(|source| AlertFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        check_perms(path, &file)?;
        let text = std::io::read_to_string(&file).map_err(|source| AlertFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(path, &text)
    }

    /// Parse and validate alertfile contents. Split from [`load`](Self::load)
    /// so the rules are testable without a file on disk.
    pub fn parse(path: &Path, text: &str) -> Result<Self, AlertFileError> {
        let doc: toml_edit::DocumentMut =
            text.parse().map_err(|source| AlertFileError::Toml {
                path: path.to_path_buf(),
                source,
            })?;

        match doc.get("version").and_then(|v| v.as_integer()) {
            Some(v) if v as u64 == ALERTFILE_VERSION => {}
            Some(v) => {
                return Err(AlertFileError::invalid(
                    path,
                    format!("unsupported version {v} (this build understands {ALERTFILE_VERSION})"),
                ));
            }
            None => {
                return Err(AlertFileError::invalid(
                    path,
                    "missing required `version` key",
                ));
            }
        }

        for key in doc.as_table().iter().map(|(k, _)| k) {
            if !matches!(key, "version" | "webhook") {
                return Err(AlertFileError::invalid(
                    path,
                    format!("unknown top-level key `{key}`"),
                ));
            }
        }

        let mut hooks = Vec::new();
        if let Some(array) = doc.get("webhook") {
            let Some(entries) = array.as_array_of_tables() else {
                return Err(AlertFileError::invalid(
                    path,
                    "`webhook` must be an array of tables (`[[webhook]]`)",
                ));
            };
            for entry in entries {
                hooks.push(parse_hook(path, entry)?);
            }
        }

        // Ids name a hook in delivery headers, in metrics labels, and in the
        // metric label and header value, so a duplicate would conflate two hooks
        // share one resume position.
        let mut seen = BTreeSet::new();
        for h in &hooks {
            if !seen.insert(h.id.clone()) {
                return Err(AlertFileError::invalid(
                    path,
                    format!("duplicate webhook id `{}`", h.id),
                ));
            }
        }
        Ok(Self { hooks })
    }
}

fn parse_hook(path: &Path, t: &toml_edit::Table) -> Result<Hook, AlertFileError> {
    const KNOWN: &[&str] = &[
        "id",
        "url",
        "secret",
        "categories",
        "kinds",
        "min_severity",
        "heartbeat_interval_secs",
        "allow_insecure_http",
    ];
    for key in t.iter().map(|(k, _)| k) {
        if !KNOWN.contains(&key) {
            return Err(AlertFileError::invalid(
                path,
                format!("unknown key `{key}` in [[webhook]] (known: {})", KNOWN.join(", ")),
            ));
        }
    }

    let id = req_str(path, t, "id")?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(AlertFileError::invalid(
            path,
            format!("webhook id `{id}` must be non-empty [A-Za-z0-9_-] (it is used in headers and metric labels)"),
        ));
    }
    let url = req_str(path, t, "url")?;
    let secret = req_str(path, t, "secret")?;
    if secret.is_empty() {
        return Err(AlertFileError::invalid(
            path,
            format!("webhook `{id}`: `secret` must not be empty — it signs every delivery"),
        ));
    }

    let allow_insecure_http = t
        .get("allow_insecure_http")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    validate_url(path, &id, &url, allow_insecure_http)?;

    let categories = parse_categories(path, &id, t)?;
    let kinds = parse_kinds(path, &id, t)?;
    let min_severity = match t.get("min_severity") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                AlertFileError::invalid(path, format!("webhook `{id}`: `min_severity` must be a string"))
            })?;
            Some(StatusSeverity::from_str_exact(s).ok_or_else(|| {
                AlertFileError::invalid(
                    path,
                    format!("webhook `{id}`: unknown min_severity `{s}` (info, warning, critical)"),
                )
            })?)
        }
    };
    let heartbeat_interval_secs = match t.get("heartbeat_interval_secs") {
        None => None,
        Some(v) => {
            let n = v.as_integer().filter(|n| *n > 0).ok_or_else(|| {
                AlertFileError::invalid(
                    path,
                    format!("webhook `{id}`: `heartbeat_interval_secs` must be a positive integer"),
                )
            })?;
            Some(n as u64)
        }
    };
    if heartbeat_interval_secs.is_some()
        && !categories.contains(node::events::CATEGORY_HEARTBEAT)
    {
        return Err(AlertFileError::invalid(
            path,
            format!(
                "webhook `{id}`: `heartbeat_interval_secs` needs the `heartbeat` category — \
                 without it there is nothing to downsample"
            ),
        ));
    }

    Ok(Hook {
        id,
        url,
        secret,
        filter: HookFilter {
            categories,
            kinds,
            min_severity,
        },
        heartbeat_interval_secs,
        allow_insecure_http,
    })
}

fn parse_categories(
    path: &Path,
    id: &str,
    t: &toml_edit::Table,
) -> Result<CategoryMask, AlertFileError> {
    use node::events::{CATEGORY_CHAIN, CATEGORY_HEARTBEAT, CATEGORY_MEMPOOL, CATEGORY_STATUS};
    let Some(v) = t.get("categories") else {
        // A hook with no categories would receive nothing, which is never what
        // anyone meant to configure.
        return Err(AlertFileError::invalid(
            path,
            format!("webhook `{id}`: `categories` is required (status, chain, mempool, heartbeat)"),
        ));
    };
    let arr = v.as_array().ok_or_else(|| {
        AlertFileError::invalid(path, format!("webhook `{id}`: `categories` must be an array"))
    })?;
    let mut mask = 0u32;
    for item in arr {
        let name = item.as_str().ok_or_else(|| {
            AlertFileError::invalid(
                path,
                format!("webhook `{id}`: `categories` entries must be strings"),
            )
        })?;
        mask |= match name {
            "status" => CATEGORY_STATUS,
            "chain" => CATEGORY_CHAIN,
            "mempool" => CATEGORY_MEMPOOL,
            "heartbeat" => CATEGORY_HEARTBEAT,
            // Rejected rather than silently ignored: the tweak firehose is
            // per-block bulk data and an HTTP receiver is the wrong consumer
            // for it. Tweaks stay on the streaming API.
            "tweaks" => {
                return Err(AlertFileError::invalid(
                    path,
                    format!(
                        "webhook `{id}`: the `tweaks` category is not deliverable over webhooks \
                         (it is a per-block firehose); consume it on the streaming API"
                    ),
                ));
            }
            other => {
                return Err(AlertFileError::invalid(
                    path,
                    format!(
                        "webhook `{id}`: unknown category `{other}` \
                         (status, chain, mempool, heartbeat)"
                    ),
                ));
            }
        };
    }
    if mask == 0 {
        return Err(AlertFileError::invalid(
            path,
            format!("webhook `{id}`: `categories` must not be empty"),
        ));
    }
    Ok(CategoryMask(mask))
}

fn parse_kinds(
    path: &Path,
    id: &str,
    t: &toml_edit::Table,
) -> Result<Option<BTreeSet<StatusKind>>, AlertFileError> {
    let Some(v) = t.get("kinds") else {
        return Ok(None);
    };
    let arr = v.as_array().ok_or_else(|| {
        AlertFileError::invalid(path, format!("webhook `{id}`: `kinds` must be an array"))
    })?;
    let mut out = BTreeSet::new();
    for item in arr {
        let name = item.as_str().ok_or_else(|| {
            AlertFileError::invalid(path, format!("webhook `{id}`: `kinds` entries must be strings"))
        })?;
        // Validated against the live taxonomy, not a copy: a typo'd kind would
        // otherwise match nothing and silently disable the hook.
        let kind = StatusKind::from_str_exact(name).ok_or_else(|| {
            AlertFileError::invalid(
                path,
                format!(
                    "webhook `{id}`: unknown status kind `{name}` (known: {})",
                    StatusKind::ALL
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;
        out.insert(kind);
    }
    if out.is_empty() {
        return Err(AlertFileError::invalid(
            path,
            format!("webhook `{id}`: `kinds` must not be empty (omit it to accept every kind)"),
        ));
    }
    Ok(Some(out))
}

fn validate_url(
    path: &Path,
    id: &str,
    url: &str,
    allow_insecure_http: bool,
) -> Result<(), AlertFileError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(AlertFileError::invalid(
            path,
            format!("webhook `{id}`: url must start with https:// or http://"),
        ));
    };
    if allow_insecure_http || is_local_target(rest) {
        return Ok(());
    }
    Err(AlertFileError::invalid(
        path,
        format!(
            "webhook `{id}`: plaintext http:// to a non-local address; use https://, or set \
             allow_insecure_http = true to accept it"
        ),
    ))
}

/// Whether an `http://` authority is loopback or RFC1918 — the cases where
/// plaintext is normal (a relay on the same host, a receiver inside a private
/// network) and demanding TLS would just push operators to set the override.
fn is_local_target(rest: &str) -> bool {
    // Authority is everything before the path, query, or fragment.
    //
    // A backslash terminates the authority too. The WHATWG URL parser — which
    // is what `reqwest` resolves this string with — treats `\` as a path
    // separator for special schemes, so `http://evil.example\@127.0.0.1/hook`
    // has host `evil.example`, while splitting on `/` alone leaves an authority
    // of `evil.example\@127.0.0.1` whose last `@` yields `127.0.0.1`. That
    // reads as loopback, waives the `allow_insecure_http` gate, and posts the
    // signed body in cleartext to the attacker's host — the same bypass the
    // userinfo rule below closes, through a different separator.
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    // Strip userinfo — everything through the *last* `@`.
    //
    // Without this, `http://127.0.0.1:8332@evil.example/hook` reads as host
    // `127.0.0.1`, is judged loopback, and is accepted with no
    // `allow_insecure_http` acknowledgement — while the request actually goes
    // in cleartext to `evil.example` with `127.0.0.1:8332` as userinfo. The
    // operator is not the adversary here; the gate exists to make them
    // consciously accept cleartext to a public host, and this skipped it.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // An IPv6 literal is bracketed, and its address contains colons — so the
    // port must be split on the bracket, not on the last colon.
    let host = if let Some(after) = host_port.strip_prefix('[') {
        match after.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        host_port.split_once(':').map_or(host_port, |(h, _)| h)
    };
    if host == "localhost" || host == "::1" {
        return true;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn req_str(path: &Path, t: &toml_edit::Table, key: &str) -> Result<String, AlertFileError> {
    t.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            AlertFileError::invalid(path, format!("[[webhook]] is missing required string `{key}`"))
        })
}

/// Refuse a group/world-accessible alertfile. Checked from the **open handle**,
/// not the path, so the permissions that are validated are the ones of the file
/// actually read (no TOCTOU window against a swap).
#[cfg(unix)]
fn check_perms(path: &Path, file: &std::fs::File) -> Result<(), AlertFileError> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(|source| AlertFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AlertFileError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_perms(_path: &Path, _file: &std::fs::File) -> Result<(), AlertFileError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<AlertFile, AlertFileError> {
        AlertFile::parse(Path::new("/test/alertfile"), text)
    }

    const MINIMAL: &str = r#"
version = 1
[[webhook]]
id = "ops"
url = "https://alerts.example/satd"
secret = "s3cret"
categories = ["status"]
"#;

    #[test]
    fn parses_a_minimal_hook() {
        let f = parse(MINIMAL).unwrap();
        assert_eq!(f.hooks.len(), 1);
        let h = &f.hooks[0];
        assert_eq!(h.id, "ops");
        assert!(h.filter.categories.contains(node::events::CATEGORY_STATUS));
        assert!(h.filter.kinds.is_none());
        assert!(h.filter.min_severity.is_none());
        assert_eq!(h.heartbeat_interval_secs, None);
    }

    #[test]
    fn parses_filters() {
        let f = parse(
            r#"
version = 1
[[webhook]]
id = "pager"
url = "https://alerts.example/satd"
secret = "s"
categories = ["status", "chain"]
kinds = ["tip_stall", "disk_low"]
min_severity = "warning"
"#,
        )
        .unwrap();
        let h = &f.hooks[0];
        assert!(h.filter.categories.contains(node::events::CATEGORY_STATUS));
        assert!(h.filter.categories.contains(node::events::CATEGORY_CHAIN));
        let kinds = h.filter.kinds.as_ref().unwrap();
        assert!(kinds.contains(&StatusKind::TipStall));
        assert!(!kinds.contains(&StatusKind::PeerFloor));
        assert_eq!(h.filter.min_severity, Some(StatusSeverity::Warning));
    }

    #[test]
    fn status_filter_applies_kind_and_severity_floors() {
        let f = parse(
            r#"
version = 1
[[webhook]]
id = "pager"
url = "https://x.example/h"
secret = "s"
categories = ["status"]
kinds = ["tip_stall", "peer_floor"]
min_severity = "critical"
"#,
        )
        .unwrap();
        let filter = &f.hooks[0].filter;
        assert!(filter.accepts_status(StatusKind::TipStall, StatusSeverity::Critical));
        // Right kind, too quiet.
        assert!(!filter.accepts_status(StatusKind::PeerFloor, StatusSeverity::Warning));
        // Loud enough, wrong kind.
        assert!(!filter.accepts_status(StatusKind::DiskLow, StatusSeverity::Critical));
    }

    #[test]
    fn a_hook_without_the_status_category_never_takes_status_events() {
        let f = parse(
            r#"
version = 1
[[webhook]]
id = "chain-only"
url = "https://x.example/h"
secret = "s"
categories = ["chain"]
"#,
        )
        .unwrap();
        assert!(!f.hooks[0]
            .filter
            .accepts_status(StatusKind::TipStall, StatusSeverity::Critical));
    }

    #[test]
    fn missing_or_wrong_version_is_rejected() {
        assert!(matches!(
            parse("[[webhook]]\nid=\"a\"\nurl=\"https://x/h\"\nsecret=\"s\"\ncategories=[\"status\"]\n"),
            Err(AlertFileError::Invalid { .. })
        ));
        assert!(parse(&MINIMAL.replace("version = 1", "version = 2")).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected_not_ignored() {
        // An accepted-but-ignored alerting rule is worse than a refused one:
        // the operator believes they are covered when they are not.
        assert!(parse(&format!("{MINIMAL}\nnot_a_key = 1\n")).is_err());
        assert!(parse(&MINIMAL.replace("categories = [\"status\"]", "categories = [\"status\"]\nkindz = [\"tip_stall\"]")).is_err());
    }

    #[test]
    fn unknown_categories_and_kinds_are_rejected() {
        assert!(parse(&MINIMAL.replace("\"status\"", "\"blocks\"")).is_err());
        let with_kind = MINIMAL.replace(
            "categories = [\"status\"]",
            "categories = [\"status\"]\nkinds = [\"tip_stal\"]",
        );
        assert!(parse(&with_kind).is_err(), "a typo'd kind must not silently match nothing");
    }

    #[test]
    fn tweaks_category_is_rejected_with_a_pointer_to_the_streaming_api() {
        let err = parse(&MINIMAL.replace("\"status\"", "\"tweaks\"")).unwrap_err();
        assert!(
            err.to_string().contains("streaming API"),
            "the error should say where tweaks are consumed: {err}"
        );
    }

    #[test]
    fn secret_is_required_and_must_be_non_empty() {
        assert!(parse(&MINIMAL.replace("secret = \"s3cret\"", "")).is_err());
        assert!(parse(&MINIMAL.replace("s3cret", "")).is_err());
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        // Two hooks sharing an id would be indistinguishable to a receiver.
        let two = format!("{MINIMAL}\n[[webhook]]\nid = \"ops\"\nurl = \"https://b.example/h\"\nsecret = \"t\"\ncategories = [\"chain\"]\n");
        let err = parse(&two).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn ids_are_restricted_to_header_and_label_safe_characters() {
        for bad in ["has space", "quote\"", "new\nline", ""] {
            let text = MINIMAL.replace("id = \"ops\"", &format!("id = {bad:?}"));
            assert!(parse(&text).is_err(), "id {bad:?} should be rejected");
        }
    }

    #[test]
    fn plaintext_http_is_gated_unless_local_or_opted_in() {
        let remote = MINIMAL.replace("https://alerts.example/satd", "http://alerts.example/satd");
        assert!(parse(&remote).is_err(), "plaintext to a public host needs the opt-in");

        // Loopback and RFC1918 are fine unannotated — a relay on the same host
        // or inside a private network is the normal deployment.
        for local in [
            "http://127.0.0.1:9000/hook",
            "http://localhost:9000/hook",
            "http://10.1.2.3/hook",
            "http://192.168.0.9:8443/h",
            "http://[::1]:9000/hook",
        ] {
            let text = MINIMAL.replace("https://alerts.example/satd", local);
            assert!(parse(&text).is_ok(), "{local} should be accepted");
        }

        // And the escape hatch works.
        let opted = remote.replace(
            "categories = [\"status\"]",
            "categories = [\"status\"]\nallow_insecure_http = true",
        );
        assert!(parse(&opted).is_ok());
    }

    #[test]
    fn userinfo_cannot_impersonate_a_local_host() {
        // The authority's host is what comes after the last `@`. Reading the
        // userinfo as the host would let a config pasted from a third-party
        // setup guide send signed cleartext to a public endpoint while
        // *looking* like a loopback target, silently skipping the acknowledgement
        // the plaintext gate exists to force.
        for sneaky in [
            "http://127.0.0.1:8332@evil.example/hook",
            "http://localhost@evil.example/hook",
            "http://10.0.0.1@evil.example:8080/hook",
            "http://user:127.0.0.1@evil.example/hook",
        ] {
            let text = MINIMAL.replace("https://alerts.example/satd", sneaky);
            assert!(
                parse(&text).is_err(),
                "{sneaky} resolves to a public host and must need the opt-in"
            );
        }

        // A genuine loopback target with userinfo is still local.
        let text = MINIMAL.replace("https://alerts.example/satd", "http://user:pw@127.0.0.1:9000/h");
        assert!(parse(&text).is_ok(), "userinfo on a real loopback host is fine");
    }

    #[test]
    fn a_backslash_cannot_smuggle_a_public_host_past_the_local_check() {
        // The WHATWG URL parser (what `reqwest` resolves these with) treats `\`
        // as a path separator for special schemes, so the host here is
        // `evil.example` — but splitting the authority on `/` alone leaves
        // `evil.example\@127.0.0.1`, whose last `@` yields a loopback address.
        // Same bypass as the userinfo case, through a different separator.
        // Written as TOML *literal* strings (single-quoted). A backslash in a
        // basic string is an escape, so `"...\@..."` fails at the TOML layer
        // and would make this test pass without ever reaching the URL check.
        for sneaky in [
            r"http://evil.example\@127.0.0.1/hook",
            r"http://evil.example\@10.0.0.1/hook",
            r"http://evil.example\@localhost:8080/hook",
        ] {
            let text = format!(
                "version = 1\n\
                 [[webhook]]\n\
                 id = \"ops\"\n\
                 url = '{sneaky}'\n\
                 secret = \"s3cret\"\n\
                 categories = [\"status\"]\n"
            );
            assert!(
                parse(&text).is_err(),
                "{sneaky} resolves to a public host and must need the opt-in"
            );
        }

        // A backslash in the *path* of a genuinely local target is unaffected.
        let text = format!(
            "version = 1\n\
             [[webhook]]\n\
             id = \"ops\"\n\
             url = '{}'\n\
             secret = \"s3cret\"\n\
             categories = [\"status\"]\n",
            r"http://127.0.0.1:9000/a\b"
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in ["ftp://x/h", "file:///etc/passwd", "x.example/h", ""] {
            let text = MINIMAL.replace("https://alerts.example/satd", url);
            assert!(parse(&text).is_err(), "{url} should be rejected");
        }
    }

    #[test]
    fn heartbeat_interval_requires_the_heartbeat_category() {
        // Otherwise the knob silently does nothing.
        let text = MINIMAL.replace(
            "categories = [\"status\"]",
            "categories = [\"status\"]\nheartbeat_interval_secs = 60",
        );
        assert!(parse(&text).is_err());
        let ok = MINIMAL.replace(
            "categories = [\"status\"]",
            "categories = [\"status\", \"heartbeat\"]\nheartbeat_interval_secs = 60",
        );
        assert_eq!(
            parse(&ok).unwrap().hooks[0].heartbeat_interval_secs,
            Some(60)
        );
        // Zero would mean "every heartbeat", i.e. 1 Hz of HTTP.
        let zero = MINIMAL.replace(
            "categories = [\"status\"]",
            "categories = [\"status\", \"heartbeat\"]\nheartbeat_interval_secs = 0",
        );
        assert!(parse(&zero).is_err());
    }

    #[test]
    fn debug_never_renders_the_signing_secret() {
        // A derived `Debug` prints `secret` in full, so one
        // `tracing::debug!(?hook)` added later would write a signing key to the
        // log — and to anywhere the log is shipped. Assert on the secret's
        // *value*, not on the presence of "redacted", so the test cannot pass
        // by rendering both.
        let f = parse(
            "version = 1\n\
             [[webhook]]\n\
             id = \"pager\"\n\
             url = \"https://example.invalid/h\"\n\
             secret = \"correct-horse-battery-staple\"\n\
             categories = [\"status\"]\n",
        )
        .unwrap();
        let hook_dbg = format!("{:?}", f.hooks[0]);
        assert!(
            !hook_dbg.contains("correct-horse-battery-staple"),
            "Hook Debug leaked the secret: {hook_dbg}"
        );
        // The whole file renders through the same impl.
        let file_dbg = format!("{f:?}");
        assert!(
            !file_dbg.contains("correct-horse-battery-staple"),
            "AlertFile Debug leaked the secret: {file_dbg}"
        );
    }

    #[test]
    fn empty_file_with_only_a_version_is_valid() {
        // "configured but no hooks" is a legitimate intermediate state during
        // an edit; it must not fail the daemon.
        assert!(parse("version = 1\n").unwrap().hooks.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_file_is_refused() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alertfile");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(MINIMAL.as_bytes()).unwrap();
        drop(f);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(AlertFile::load(&path), Err(AlertFileError::Permissions { .. })),
            "a world-readable file holding signing secrets must be refused",
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AlertFile::load(&path).is_ok());
    }
}
