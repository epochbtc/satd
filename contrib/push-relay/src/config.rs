//! Relay configuration.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level `relay.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. Bind loopback and let satd reach it locally, or
    /// bind a private interface — this endpoint accepts anything that can forge
    /// the HMAC, so it should not face the internet without a reverse proxy.
    pub listen: String,
    /// The `secret` from the matching `[[webhook]]` entry in satd's alertfile.
    /// Every request is verified against it before anything else happens.
    pub satd_secret: String,
    /// Severity floor for **status** notifications (`info` | `warning` |
    /// `critical`). Most operators want `warning`: a push notification for
    /// "IBD finished" is noise. Reorg and gap notifications are not status
    /// events and are not filtered by this — they are always pushed.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    #[serde(default)]
    pub apns: Option<ApnsConfig>,
    #[serde(default)]
    pub fcm: Option<FcmConfig>,
}

fn default_min_severity() -> String {
    "warning".to_string()
}

/// Apple Push Notification service, token-based (`.p8`) auth.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// Path to the `AuthKey_XXXXXXXXXX.p8` downloaded from Apple.
    pub key_file: PathBuf,
    /// The key's 10-character identifier.
    pub key_id: String,
    /// Your Apple Developer team id.
    pub team_id: String,
    /// The app's bundle id, sent as `apns-topic`.
    pub topic: String,
    /// `true` for production, `false` for the sandbox gateway.
    #[serde(default)]
    pub production: bool,
    /// Device tokens to notify. v1 ships a static list: a registration endpoint
    /// is wallet-vendor territory, and a reference relay that grew one would be
    /// pretending to be a product.
    pub device_tokens: Vec<String>,
}

impl ApnsConfig {
    pub fn host(&self) -> &'static str {
        if self.production {
            "api.push.apple.com"
        } else {
            "api.sandbox.push.apple.com"
        }
    }
}

/// Firebase Cloud Messaging, HTTP v1 API with a service account.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmConfig {
    /// Path to the service-account JSON downloaded from the Firebase console.
    pub service_account_file: PathBuf,
    /// Registration tokens to notify (the static-list caveat above applies).
    pub device_tokens: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        check_perms(path, &file)?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        if cfg.satd_secret.is_empty() {
            anyhow::bail!("satd_secret must not be empty — it is what authenticates satd");
        }
        if cfg.apns.is_none() && cfg.fcm.is_none() {
            anyhow::bail!("configure at least one of [apns] or [fcm]; the relay would do nothing");
        }
        if !matches!(cfg.min_severity.as_str(), "info" | "warning" | "critical") {
            anyhow::bail!(
                "min_severity must be info, warning, or critical (got {:?})",
                cfg.min_severity
            );
        }
        Ok(cfg)
    }
}

/// Refuse a group- or world-accessible config.
///
/// This file holds the same HMAC secret as satd's alertfile — which satd itself
/// refuses to read at looser than 0600 for exactly this reason — plus the paths
/// to the APNs `.p8` key and the FCM service-account JSON. Anyone who can read
/// it can forge correctly-signed alerts into the operator's push channel. The
/// README tells people to `cp relay.example.toml`, which under a default umask
/// produces 0644.
///
/// Checked against the open handle rather than the path, so it cannot be raced.
#[cfg(unix)]
fn check_perms(path: &Path, file: &std::fs::File) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} is group/world accessible (mode {mode:04o}); it holds the satd signing secret \
             and your push credentials — run: chmod 600 {}",
            path.display(),
            path.display(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_perms(_path: &Path, _file: &std::fs::File) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("relay.toml");
        std::fs::write(&p, text).unwrap();
        // The loader refuses a group/world-accessible file; a tempdir write
        // lands at 0644 under the usual umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (dir, p)
    }

    #[test]
    fn parses_a_minimal_fcm_config() {
        let (_d, p) = write(
            r#"
listen = "127.0.0.1:9099"
satd_secret = "s"
[fcm]
service_account_file = "/etc/relay/sa.json"
device_tokens = ["tok"]
"#,
        );
        let c = Config::load(&p).unwrap();
        assert_eq!(c.min_severity, "warning", "default");
        assert!(c.fcm.is_some());
        assert!(c.apns.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        // Same posture satd takes for its alertfile: this file holds the
        // shared HMAC secret and the paths to the push credentials, and the
        // README tells operators to `cp` the example — which lands at 0644.
        let (_d, p) = write(
            "listen = \"127.0.0.1:9099\"\nsatd_secret = \"s\"\n\
             [fcm]\nservice_account_file = \"/x\"\ndevice_tokens = [\"t\"]\n",
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Config::load(&p).expect_err("0644 must be refused");
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_refused() {
        // `producton = true` would otherwise leave `production` at its default
        // of false and silently talk to the APNs *sandbox*, so no notification
        // ever arrives on a real device — with nothing anywhere saying why.
        let (_d, p) = write(
            "listen = \"127.0.0.1:9099\"\nsatd_secret = \"s\"\nmin_severty = \"info\"\n\
             [fcm]\nservice_account_file = \"/x\"\ndevice_tokens = [\"t\"]\n",
        );
        let err = Config::load(&p).expect_err("a typo'd key must be refused");
        assert!(err.to_string().contains("min_severty"), "{err}");
    }

    #[test]
    fn a_relay_with_no_provider_is_refused() {
        // It would accept and verify deliveries, then drop them — the most
        // confusing possible behavior.
        let (_d, p) = write("listen = \"127.0.0.1:9099\"\nsatd_secret = \"s\"\n");
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn an_empty_secret_is_refused() {
        let (_d, p) = write(
            "listen = \"127.0.0.1:9099\"\nsatd_secret = \"\"\n[fcm]\nservice_account_file = \"x\"\ndevice_tokens = []\n",
        );
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn an_unknown_severity_is_refused() {
        let (_d, p) = write(
            "listen = \"127.0.0.1:9099\"\nsatd_secret = \"s\"\nmin_severity = \"loud\"\n[fcm]\nservice_account_file = \"x\"\ndevice_tokens = []\n",
        );
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn apns_host_follows_the_production_flag() {
        let sandbox = ApnsConfig {
            key_file: "k".into(),
            key_id: "K".into(),
            team_id: "T".into(),
            topic: "com.example.app".into(),
            production: false,
            device_tokens: vec![],
        };
        assert_eq!(sandbox.host(), "api.sandbox.push.apple.com");
        let prod = ApnsConfig { production: true, ..sandbox };
        assert_eq!(prod.host(), "api.push.apple.com");
    }
}
