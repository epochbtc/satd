//! SDK ↔ node version compatibility (`STABILITY_POLICY.md` → "Streaming API &
//! SDK compatibility").
//!
//! A node advertises its version and event schema in two gRPC response headers
//! on every stream. This module parses them and applies the rule: a node at or
//! above this SDK's version is fine; one minor version behind warns; two or more
//! minor versions (or a major version) behind is refused. The SDK does not track
//! which node version added which feature.
//!
//! Everything here is pure so the table can be tested with injected versions;
//! the client applies it in `StreamClient::subscribe` / `watch`.

use tonic::metadata::MetadataMap;

/// Response header carrying the node version (`satd-version`).
pub(crate) const VERSION_HEADER: &str = "satd-version";
/// Response header carrying the node's event schema version (`satd-events-schema`).
pub(crate) const SCHEMA_HEADER: &str = "satd-events-schema";

/// This SDK's version. The crate inherits the workspace version, so it equals
/// the satd release it shipped with.
pub(crate) const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What a node that sends no (or an unparseable) `satd-version` header is taken
/// to be: the headers first shipped in 0.6.0, so such a node is 0.5.x or older.
pub(crate) const HEADERLESS_NODE: Version = Version { major: 0, minor: 5 };

/// A major/minor version. Patch numbers and `-pre` / `+build` suffixes never
/// affect compatibility, so they are not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Version {
    pub(crate) major: u32,
    pub(crate) minor: u32,
}

/// Parse `MAJOR.MINOR[.PATCH][-suffix][+build]`. `None` for anything else.
pub(crate) fn parse(s: &str) -> Option<Version> {
    let core = s.split(['-', '+']).next().unwrap_or("");
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    if let Some(patch) = parts.next() {
        patch.parse::<u32>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Version { major, minor })
}

/// The outcome of comparing a node's version to the SDK's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compat {
    /// The node is at or above the SDK's version.
    Ok,
    /// The node is exactly one minor version behind: warn.
    OneBehind,
    /// Two or more minor versions, or a major version, behind: refuse (unless
    /// the caller opted in with `allow_old_node`).
    TooOld,
}

/// Apply the compatibility rule.
pub(crate) fn classify(sdk: Version, node: Version) -> Compat {
    if node >= sdk {
        Compat::Ok
    } else if node.major != sdk.major {
        Compat::TooOld
    } else if sdk.minor - node.minor == 1 {
        Compat::OneBehind
    } else {
        Compat::TooOld
    }
}

/// The raw `satd-version` header (if present and ASCII) and the version to
/// compare: the parsed header, or [`HEADERLESS_NODE`] when it is missing or
/// unparseable.
pub(crate) fn node_version_from(md: &MetadataMap) -> (Option<String>, Version) {
    let raw = md.get(VERSION_HEADER).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let parsed = raw.as_deref().and_then(parse).unwrap_or(HEADERLESS_NODE);
    (raw, parsed)
}

/// The node's schema version from the `satd-events-schema` header. A node
/// without the header predates it and speaks schema 1. A header that is present
/// but not a number is reported as `0`, which never matches.
pub(crate) fn schema_from(md: &MetadataMap) -> u32 {
    match md.get(SCHEMA_HEADER) {
        None => 1,
        Some(v) => v.to_str().ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0),
    }
}

/// How a node version is shown in the warning and the `NodeTooOld` error.
pub(crate) fn display_node_version(raw: Option<&str>) -> String {
    match raw {
        Some(v) => v.to_owned(),
        None => "(no version header; older than 0.6.0)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        parse(s).expect(s)
    }

    fn md(version: Option<&str>, schema: Option<&str>) -> MetadataMap {
        let mut md = MetadataMap::new();
        if let Some(s) = version {
            md.insert(VERSION_HEADER, s.parse().unwrap());
        }
        if let Some(s) = schema {
            md.insert(SCHEMA_HEADER, s.parse().unwrap());
        }
        md
    }

    /// Compare as the client does: the header (possibly missing or garbage)
    /// against an injected SDK version.
    fn classify_header(sdk: &str, header: Option<&str>) -> Compat {
        classify(v(sdk), node_version_from(&md(header, None)).1)
    }

    #[test]
    fn parse_accepts_release_pre_and_build_forms() {
        assert_eq!(parse("0.6.0"), Some(Version { major: 0, minor: 6 }));
        assert_eq!(parse("0.6.0-pre"), Some(Version { major: 0, minor: 6 }));
        assert_eq!(parse("1.0"), Some(Version { major: 1, minor: 0 }));
        assert_eq!(parse("0.6"), Some(Version { major: 0, minor: 6 }));
        assert_eq!(parse("0.6.0+build"), Some(Version { major: 0, minor: 6 }));
        assert_eq!(parse("0.12.3-rc.1"), Some(Version { major: 0, minor: 12 }));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse("garbage"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("1"), None);
        assert_eq!(parse("0.x.0"), None);
        assert_eq!(parse("0.6.x"), None);
        assert_eq!(parse("0.6.0.1"), None);
    }

    /// The worked examples from the policy, row by row.
    #[test]
    fn classify_matches_the_policy_table() {
        assert_eq!(classify_header("0.6.0", Some("0.6.0")), Compat::Ok);
        assert_eq!(classify_header("0.6.0", Some("0.6.0-pre")), Compat::Ok);
        assert_eq!(classify_header("0.6.0-pre", Some("0.7.3")), Compat::Ok);
        assert_eq!(classify_header("0.6.0", Some("1.0.0")), Compat::Ok);
        assert_eq!(classify_header("0.6.0-pre", Some("0.5.2")), Compat::OneBehind);
        assert_eq!(classify_header("0.6.0", None), Compat::OneBehind);
        assert_eq!(classify_header("0.7.0", Some("0.5.2")), Compat::TooOld);
        assert_eq!(classify_header("0.7.0", None), Compat::TooOld);
        assert_eq!(classify_header("1.1.0", Some("0.9.0")), Compat::TooOld);
        assert_eq!(classify_header("0.6.0", Some("garbage")), Compat::OneBehind);
        // A major version behind is refused even when the minor looks close.
        assert_eq!(classify_header("1.0.0", Some("0.9.9")), Compat::TooOld);
    }

    #[test]
    fn schema_defaults_to_one_and_garbage_never_matches() {
        assert_eq!(schema_from(&md(None, None)), 1);
        assert_eq!(schema_from(&md(None, Some("1"))), 1);
        assert_eq!(schema_from(&md(None, Some("2"))), 2);
        assert_eq!(schema_from(&md(None, Some("one"))), 0);
    }

    #[test]
    fn node_version_keeps_the_raw_header() {
        assert_eq!(node_version_from(&md(None, None)), (None, HEADERLESS_NODE));
        assert_eq!(
            node_version_from(&md(Some("garbage"), None)),
            (Some("garbage".to_owned()), HEADERLESS_NODE)
        );
        assert_eq!(
            node_version_from(&md(Some("0.7.1"), None)),
            (Some("0.7.1".to_owned()), Version { major: 0, minor: 7 })
        );
    }

    #[test]
    fn the_sdk_version_parses() {
        assert!(parse(SDK_VERSION).is_some(), "{SDK_VERSION}");
    }
}
