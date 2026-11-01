//! Core's `-deprecatedrpc`: deprecated RPC behaviours an operator can bring
//! back (`IsDeprecatedRPCEnabled`, src/rpc/server.cpp).

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

/// The names satd has a deprecated form for.
pub const KNOWN: &[&str] = &["warnings"];

/// `-deprecatedrpc=warnings`. Set once at startup by [`set`].
static WARNINGS: AtomicBool = AtomicBool::new(false);

/// Record the `-deprecatedrpc` names. Call once, before the RPC server
/// starts; names not in [`KNOWN`] are ignored here (config warns about them).
pub fn set(names: &[String]) {
    WARNINGS.store(names.iter().any(|n| n == "warnings"), Ordering::Relaxed);
}

/// The `warnings` field of `getblockchaininfo`, `getnetworkinfo` and
/// `getmininginfo`, as Core's `GetWarningsForRpc` (src/node/warnings.cpp)
/// builds it: an array of messages, `[]` when there are none. Under
/// `-deprecatedrpc=warnings`, Core's pre-v28 form instead: one string, the
/// latest message, or `""`.
///
/// satd returned `""` when there were no warnings and an array otherwise,
/// so the field's type changed with the node's state (#956).
pub fn warnings_value(warnings: Vec<String>) -> Value {
    warnings_value_with(warnings, WARNINGS.load(Ordering::Relaxed))
}

fn warnings_value_with(warnings: Vec<String>, deprecated: bool) -> Value {
    if deprecated {
        Value::String(warnings.into_iter().last().unwrap_or_default())
    } else {
        Value::Array(warnings.into_iter().map(Value::String).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn warnings_are_always_an_array_unless_deprecated() {
        let two = || vec!["first".to_string(), "second".to_string()];
        assert_eq!(warnings_value_with(Vec::new(), false), json!([]));
        assert_eq!(warnings_value_with(two(), false), json!(["first", "second"]));
        assert_eq!(warnings_value_with(Vec::new(), true), json!(""));
        assert_eq!(warnings_value_with(two(), true), json!("second"), "Core keeps the latest message");
    }
}
