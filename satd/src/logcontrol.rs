//! The live category state behind the `logging` RPC.
//!
//! satd's verbosity is a `tracing_subscriber` `EnvFilter`, rebuilt from the
//! config by [`config::build_env_filter`] and swapped in through the reload
//! handle. This type is the one place that owns *both* the category state the
//! RPC reports and the filter the node logs through, so the two cannot drift —
//! which is what went wrong before: `logging` answered from a private map that
//! nothing else read.
//!
//! Every change goes the same way a `-debug` change does: mutate the stored
//! config's `debug` / `debugexclude` lists, rebuild the filter from them, swap.
//! There is no second code path and no second source of truth.

use crate::config::{self, Config};
use crate::reload::LogReloadHandle;
use node::rpc::logging::{ALL_CATEGORIES, LogControl};
use parking_lot::Mutex;

/// The live `logging` surface.
pub struct LiveLogControl {
    handle: LogReloadHandle,
    /// The config the current filter was built from. Mutated in place by
    /// `update`, replaced wholesale by [`Self::reset_to`] on SIGHUP.
    config: Mutex<Config>,
}

impl LiveLogControl {
    pub fn new(handle: LogReloadHandle, config: Config) -> Self {
        Self {
            handle,
            config: Mutex::new(config),
        }
    }

    /// A SIGHUP re-derives verbosity from the config file, discarding runtime
    /// `logging` changes. That is deliberate and matches the rest of the
    /// reload contract: the file is the declared state, and a reload asserts
    /// it. Bitcoin Core has no config-reload path for `-debug` to disagree
    /// with, so there is no parity question here.
    pub fn reset_to(&self, config: &Config) {
        *self.config.lock() = config.clone();
        self.handle.reload(config);
    }

    /// Whether `name` is a category satd can act on, or Core's `all` wildcard
    /// (`""`, `"1"`, `"all"` -- see [`ALL_CATEGORIES`]).
    ///
    /// `none` and `0` are deliberately *not* known here. They are `-debug`
    /// config spellings; Core's `logging` RPC answers
    /// `-8 unknown logging category none` for both, and accepting them meant
    /// `logging '["none"]'` silently turned off all logging on a node where
    /// Core would have refused the call.
    fn is_known(name: &str) -> bool {
        let lower = name.trim().to_ascii_lowercase();
        ALL_CATEGORIES.contains(&lower.as_str())
            || config::debug_category_target(&lower).is_some()
    }
}

impl LogControl for LiveLogControl {
    fn categories(&self) -> Vec<(&'static str, bool)> {
        let config = self.config.lock();
        // Exactly the predicate `debug_directives` applies when it builds the
        // filter, so a category reads back as enabled precisely when its
        // subsystem is being logged at debug.
        let norm = |s: &str| s.trim().to_ascii_lowercase();
        let all = config
            .debug
            .iter()
            .any(|c| ALL_CATEGORIES.contains(&norm(c).as_str()));
        let excluded: Vec<String> = config.debugexclude.iter().map(|c| norm(c)).collect();
        let included: Vec<String> = config.debug.iter().map(|c| norm(c)).collect();

        config::DEBUG_CATEGORIES
            .iter()
            .map(|&cat| {
                let on = if excluded.iter().any(|e| e == cat) {
                    false
                } else if all {
                    true
                } else {
                    included.iter().any(|i| i == cat)
                };
                (cat, on)
            })
            .collect()
    }

    fn update(&self, include: &[String], exclude: &[String]) -> Result<(), String> {
        // Validate everything before applying anything: Core throws on the
        // first unknown name, and a half-applied change is not something a
        // caller can reason about.
        for name in include.iter().chain(exclude.iter()) {
            if !Self::is_known(name) {
                return Err(name.clone());
            }
        }

        let mut config = self.config.lock();
        let norm = |s: &str| s.trim().to_ascii_lowercase();
        let mut debug: Vec<String> = config.debug.iter().map(|c| norm(c)).collect();
        let mut debugexclude: Vec<String> = config.debugexclude.iter().map(|c| norm(c)).collect();

        // Core's order: include first, then exclude, "so a category named in
        // both ends up excluded".
        for name in include {
            let cat = norm(name);
            if ALL_CATEGORIES.contains(&cat.as_str()) {
                debug = vec!["all".to_string()];
                debugexclude.clear();
            } else {
                debugexclude.retain(|e| e != &cat);
                if !debug.iter().any(|d| d == &cat) {
                    debug.push(cat);
                }
            }
        }
        for name in exclude {
            let cat = norm(name);
            // Core's `DisableCategory(BCLog::ALL)` clears the whole mask.
            if ALL_CATEGORIES.contains(&cat.as_str()) {
                debug.clear();
                debugexclude.clear();
            } else {
                debug.retain(|d| d != &cat);
                // Only meaningful under `-debug=all`, which is also the only
                // case `debug_directives` reads it in.
                if !debugexclude.iter().any(|e| e == &cat) {
                    debugexclude.push(cat);
                }
            }
        }

        config.debug = debug;
        config.debugexclude = debugexclude;
        self.handle.reload(&config);
        Ok(())
    }
}
