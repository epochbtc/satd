pub mod adaptive_cache;
pub mod chain;
pub mod diskspace;
pub mod events;
pub mod health;
pub mod ibd_eta;
pub mod index;
pub mod memstat;
pub mod mempool;
pub mod metrics;
pub mod mining;
pub mod net;
pub mod perf;
pub mod rpc;
pub mod shutdown;
pub mod sp_serve;
pub mod stall_watchdog;
pub mod startup_progress;
pub mod time;
pub mod storage;
pub mod validation;
pub mod warnings;

/// BIP 14 user agent string with no `-uacomment` comments, derived from
/// Cargo.toml version at compile time. This is what a node reports unless
/// [`set_user_agent`] has installed a commented form.
pub const USER_AGENT: &str = concat!("/satd:", env!("CARGO_PKG_VERSION"), "/");

/// Bitcoin Core's `MAX_SUBVERSION_LENGTH`. A peer's advertised user agent
/// rides in every `version` message, so it is bounded.
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// Characters Bitcoin Core permits inside a `-uacomment` (`SAFE_CHARS_UA_COMMENT`
/// in `util/string.h`): alphanumerics plus ` .,;-_?@`.
///
/// Note what is excluded: `/`, `:`, `(` and `)` are the user agent's own
/// delimiters, so allowing them would let a comment forge extra fields in a
/// string other implementations parse.
fn is_safe_ua_comment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " .,;-_?@".contains(c)
}

static USER_AGENT_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The user agent this node advertises: [`USER_AGENT`] unless
/// [`set_user_agent`] installed a commented form at startup.
pub fn user_agent() -> &'static str {
    USER_AGENT_OVERRIDE
        .get()
        .map(String::as_str)
        .unwrap_or(USER_AGENT)
}

/// Install the process-wide user agent. Call once, at startup, before any
/// peer connection or `getnetworkinfo` can observe it.
///
/// Returns whether it was installed. A second call is refused rather than
/// silently ignored, so a caller cannot believe it changed a value that peers
/// have already been told, and so is a string that is not safe to put on the
/// wire.
///
/// The wire check is deliberately not the `-uacomment` character rule --
/// that one governs *comments*, and a formatted user agent legitimately
/// contains the `/`, `:`, `(` and `)` that rule excludes. What is checked is
/// the invariant that matters wherever this value ends up: printable ASCII
/// within Core's length bound. [`format_user_agent`] is the only producer
/// today and cannot violate it; this keeps that true for the next caller,
/// since a newline here would land in log lines and JSON alike.
pub fn set_user_agent(ua: String) -> bool {
    if ua.len() > MAX_SUBVERSION_LENGTH || !ua.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return false;
    }
    USER_AGENT_OVERRIDE.set(ua).is_ok()
}

/// Build the BIP 14 user agent from `-uacomment` values, as Bitcoin Core's
/// `FormatSubVersion` does: `/satd:<version>(comment1; comment2)/`.
///
/// Errors are worded exactly as Core words them, because they are operator
/// facing and Core's own functional tests match them literally.
pub fn format_user_agent(comments: &[String]) -> Result<String, String> {
    for comment in comments {
        // Core names the whole offending comment, not the character.
        if !comment.chars().all(is_safe_ua_comment_char) {
            return Err(format!(
                "User Agent comment ({comment}) contains unsafe characters."
            ));
        }
    }

    let ua = if comments.is_empty() {
        USER_AGENT.to_string()
    } else {
        format!(
            "/satd:{}({})/",
            env!("CARGO_PKG_VERSION"),
            comments.join("; ")
        )
    };

    if ua.len() > MAX_SUBVERSION_LENGTH {
        return Err(format!(
            "Total length of network version string ({}) exceeds maximum length ({}). \
             Reduce the number or size of uacomments.",
            ua.len(),
            MAX_SUBVERSION_LENGTH
        ));
    }
    Ok(ua)
}

#[cfg(test)]
mod user_agent_tests {
    use super::*;

    #[test]
    fn no_comments_yields_the_plain_user_agent() {
        assert_eq!(format_user_agent(&[]).unwrap(), USER_AGENT);
    }

    #[test]
    fn comments_are_joined_with_a_semicolon_inside_one_paren_group() {
        let ua = format_user_agent(&["testnode0".into(), "foo".into()]).unwrap();
        assert!(ua.ends_with("(testnode0; foo)/"), "{ua}");
        assert!(ua.starts_with("/satd:"), "{ua}");
    }

    #[test]
    fn the_user_agent_delimiters_are_refused_inside_a_comment() {
        // Allowing these would let a comment forge extra fields in a string
        // other implementations parse.
        for unsafe_char in ["/", ":", "(", ")", "\u{20bf}", "\u{1f3c3}"] {
            let err = format_user_agent(&[unsafe_char.to_string()]).unwrap_err();
            assert_eq!(
                err,
                format!("User Agent comment ({unsafe_char}) contains unsafe characters.")
            );
        }
    }

    #[test]
    fn an_oversized_comment_is_refused_by_total_length() {
        let err = format_user_agent(&["a".repeat(256)]).unwrap_err();
        assert!(
            err.starts_with("Total length of network version string (")
                && err.ends_with("exceeds maximum length (256). Reduce the number or size of uacomments."),
            "{err}"
        );
    }
}
