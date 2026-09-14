//! `statusadvertise`: the connection strings the status page shows.
//!
//! The page never builds one from the request. The `Host` header can be
//! spoofed, names the proxy in front of the node rather than the surface a
//! wallet should dial, and would be one more attacker-chosen value to escape.
//! Platforms also disagree about ports: Umbrel publishes satd's ports
//! unchanged, StartOS remaps them and shows its own addresses. So the
//! operator, or the package, says what to show.

use serde::Serialize;

/// A surface a client connects to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Electrum,
    Esplora,
    Rpc,
    Mcp,
}

impl Surface {
    pub const ALL: [Surface; 4] = [Surface::Electrum, Surface::Esplora, Surface::Rpc, Surface::Mcp];

    pub fn name(self) -> &'static str {
        match self {
            Surface::Electrum => "electrum",
            Surface::Esplora => "esplora",
            Surface::Rpc => "rpc",
            Surface::Mcp => "mcp",
        }
    }

    /// How the page labels it.
    pub fn label(self) -> &'static str {
        match self {
            Surface::Electrum => "Electrum",
            Surface::Esplora => "Esplora",
            Surface::Rpc => "JSON-RPC",
            Surface::Mcp => "MCP",
        }
    }
}

/// One `statusadvertise=<surface>=<url>` value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Advertised {
    pub surface: Surface,
    pub url: String,
}

/// Long enough for any real URL, short enough that the page cannot be made
/// to carry a paragraph.
const MAX_URL_LEN: usize = 512;

impl Advertised {
    /// Parse `<surface>=<url>`.
    ///
    /// The URL must be `scheme://authority[/path]`: a lowercase scheme, a
    /// non-empty authority, and nothing but printable ASCII with no spaces,
    /// quotes or angle brackets. It is shown as text and never fetched, so
    /// this is not a URL parser; it refuses what is plainly not a connection
    /// string, which is almost always a value that lost its scheme or picked
    /// up shell quoting.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (surface, url) = value
            .split_once('=')
            .ok_or_else(|| "expected <surface>=<url>".to_string())?;
        let surface = Surface::ALL
            .into_iter()
            .find(|s| s.name() == surface.trim())
            .ok_or_else(|| {
                format!(
                    "unknown surface `{}`; expected one of electrum, esplora, rpc, mcp",
                    surface.trim()
                )
            })?;
        let url = url.trim();
        if url.len() > MAX_URL_LEN {
            return Err(format!("the URL is longer than {MAX_URL_LEN} characters"));
        }
        if let Some(bad) = url
            .chars()
            .find(|c| !c.is_ascii_graphic() || matches!(c, '"' | '\'' | '<' | '>' | '\\' | '`'))
        {
            return Err(format!("the URL contains {bad:?}"));
        }
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| "the URL has no scheme; write it as scheme://host:port".to_string())?;
        let scheme_ok = scheme.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && scheme
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'));
        if !scheme_ok {
            return Err(format!("`{scheme}` is not a URL scheme"));
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return Err("the URL has no host".to_string());
        }
        Ok(Self {
            surface,
            url: url.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_surface() {
        for (v, s) in [
            ("electrum=ssl://umbrel.local:50012", Surface::Electrum),
            ("esplora=https://umbrel.local:8430/api", Surface::Esplora),
            ("rpc=https://umbrel.local:8436", Surface::Rpc),
            ("mcp=https://umbrel.local:8439/mcp", Surface::Mcp),
        ] {
            let a = Advertised::parse(v).unwrap();
            assert_eq!(a.surface, s);
            assert_eq!(a.url, v.split_once('=').unwrap().1);
        }
    }

    #[test]
    fn statusadvertise_rejects_unknown_surface() {
        let e = Advertised::parse("lightning=ssl://node:9735").unwrap_err();
        assert!(e.contains("unknown surface `lightning`"), "{e}");
    }

    #[test]
    fn rejects_what_is_not_a_connection_string() {
        for v in [
            "electrum",
            "electrum=",
            "electrum=node.local:50002",
            "electrum=ssl://",
            "electrum=SSL://node:50002",
            "electrum=ssl://node:50002 extra",
            "electrum=\"ssl://node:50002\"",
            "esplora=https://node/<script>",
            "rpc=https://nodé.local",
        ] {
            assert!(Advertised::parse(v).is_err(), "accepted {v}");
        }
        let long = format!("esplora=https://node/{}", "a".repeat(600));
        assert!(Advertised::parse(&long).is_err());
    }
}
