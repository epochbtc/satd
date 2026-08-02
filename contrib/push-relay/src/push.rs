//! Provider adapters: APNs (token auth) and FCM (HTTP v1).
//!
//! Both providers authenticate with a short-lived JWT the relay mints from a
//! key the *operator* supplies. satd never holds a push credential — that is
//! the whole reason this service exists as a separate process (see the design's
//! D9): a Bitcoin node has no business carrying Apple and Google credentials.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{ApnsConfig, FcmConfig};
use crate::event::Notification;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A provider token and the moment it stops being usable.
///
/// Both providers rate-limit *minting*, so a relay that mints per delivery
/// fails in the one situation it exists for. Apple documents at most one token
/// per 20 minutes and answers `429 TooManyProviderTokenUpdates` beyond that; a
/// flapping condition (`tip_stall` raising and clearing, peers oscillating at
/// the threshold) produces raise/clear pairs minutes apart, so four alerts in
/// an hour is enough to trip it. Google's is worse per delivery: a full
/// RSA-signed assertion *and* a network round trip to `oauth2.googleapis.com`
/// in the alert path.
///
/// Reading the key file per delivery was also a blocking `std::fs` read inside
/// an `async fn`. Caching removes that too.
#[derive(Clone)]
struct CachedToken {
    token: String,
    /// Extra value APNs does not need and FCM does: the project id.
    project: String,
    expires_at: u64,
}

/// Refresh this long before a token actually expires, so a delivery never races
/// the boundary.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 300;

/// APNs accepts a provider token for an hour; refresh at 50 minutes.
const APNS_TOKEN_LIFETIME_SECS: u64 = 50 * 60;

/// Process-wide token caches. One entry each; the relay talks to at most one
/// APNs app and one FCM project.
static APNS_TOKEN: std::sync::LazyLock<tokio::sync::Mutex<Option<CachedToken>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));
static FCM_TOKEN: std::sync::LazyLock<tokio::sync::Mutex<Option<CachedToken>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));

fn fresh(entry: &Option<CachedToken>) -> Option<CachedToken> {
    entry
        .as_ref()
        .filter(|t| t.expires_at > now_secs().saturating_add(TOKEN_REFRESH_MARGIN_SECS))
        .cloned()
}

// ---------------------------------------------------------------- APNs -----

#[derive(Debug, Serialize)]
struct ApnsClaims {
    iss: String,
    iat: u64,
}

/// Mint an APNs provider token (ES256 over the `.p8` key).
///
/// Apple accepts a token for an hour and rate-limits minting, so a real
/// deployment caches it; this reference relay mints per batch, which is fine at
/// alert volumes (a handful a day) and keeps the code readable.
pub fn apns_token(cfg: &ApnsConfig) -> anyhow::Result<String> {
    let key = std::fs::read(&cfg.key_file)
        .map_err(|e| anyhow::anyhow!("reading APNs key {}: {e}", cfg.key_file.display()))?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(cfg.key_id.clone());
    let claims = ApnsClaims {
        iss: cfg.team_id.clone(),
        iat: now_secs(),
    };
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(&key)
        .map_err(|e| anyhow::anyhow!("APNs key is not a valid EC PEM (.p8): {e}"))?;
    Ok(jsonwebtoken::encode(&header, &claims, &enc)?)
}

/// The APNs payload for a notification.
pub fn apns_payload(n: &Notification) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "alert": { "title": n.title, "body": n.message },
            "sound": "default",
            // A node alert is a state change the user should see now, not a
            // background refresh.
            "interruption-level": "time-sensitive",
        }
    })
}

/// The cached APNs provider token, minting a new one only when needed.
async fn cached_apns_token(cfg: &ApnsConfig) -> anyhow::Result<String> {
    let mut slot = APNS_TOKEN.lock().await;
    if let Some(t) = fresh(&slot) {
        return Ok(t.token);
    }
    let token = apns_token(cfg)?;
    *slot = Some(CachedToken {
        token: token.clone(),
        project: String::new(),
        expires_at: now_secs().saturating_add(APNS_TOKEN_LIFETIME_SECS),
    });
    Ok(token)
}

pub async fn send_apns(
    client: &reqwest::Client,
    cfg: &ApnsConfig,
    n: &Notification,
) -> anyhow::Result<()> {
    let token = cached_apns_token(cfg).await?;
    let payload = apns_payload(n);
    for device in &cfg.device_tokens {
        let url = format!("https://{}/3/device/{device}", cfg.host());
        let resp = client
            .post(&url)
            .bearer_auth(&token)
            .header("apns-topic", &cfg.topic)
            .header("apns-push-type", "alert")
            // Collapsing means a raise and its later clear replace each other
            // on the lock screen instead of stacking up.
            .header("apns-collapse-id", collapse_id_for_apns(&n.collapse_id))
            .json(&payload)
            .send()
            .await;
        // Deliberately not `?`. A transport error or timeout on one device must
        // not abandon the rest: `?` here meant an unreachable first device
        // silently swallowed the alert for every device behind it.
        match resp {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => {
                let status = r.status();
                if status.as_u16() == 429 || status.is_server_error() {
                    // Worth distinguishing: this is the provider throttling or
                    // failing, not a bad device token, and the generic message
                    // would send the operator hunting the wrong thing.
                    tracing::warn!(%status, "APNs is throttling or unavailable; push not delivered");
                } else {
                    tracing::warn!(
                        %status,
                        "APNs rejected a push (device token stale or credentials wrong)"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "APNs request failed for one device"),
        }
    }
    Ok(())
}

/// APNs caps `apns-collapse-id` at 64 bytes and rejects the whole request past
/// it, so an over-long id would fail *every* push for that condition rather
/// than degrading. Truncated on a char boundary.
fn collapse_id_for_apns(id: &str) -> String {
    const MAX: usize = 64;
    if id.len() <= MAX {
        return id.to_string();
    }
    let mut end = MAX;
    while end > 0 && !id.is_char_boundary(end) {
        end -= 1;
    }
    id[..end].to_string()
}

// ----------------------------------------------------------------- FCM -----

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    project_id: String,
    private_key: String,
    client_email: String,
}

#[derive(Debug, Serialize)]
struct GoogleClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Seconds the token stays valid. Google sends it; the caller caches on it.
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Exchange a service-account key for an OAuth2 access token.
///
/// Returns the token, the project id, and the token's lifetime in seconds.
pub async fn fcm_access_token(
    client: &reqwest::Client,
    sa_path: &Path,
    token_uri: &str,
) -> anyhow::Result<(String, String, u64)> {
    let text = std::fs::read_to_string(sa_path)
        .map_err(|e| anyhow::anyhow!("reading service account {}: {e}", sa_path.display()))?;
    let sa: ServiceAccount = serde_json::from_str(&text)?;
    let iat = now_secs();
    let claims = GoogleClaims {
        iss: sa.client_email.clone(),
        scope: "https://www.googleapis.com/auth/firebase.messaging".into(),
        aud: token_uri.to_string(),
        iat,
        exp: iat + 3600,
    };
    let enc = jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("service-account private_key is not a valid RSA PEM: {e}"))?;
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &enc,
    )?;
    let resp: TokenResponse = client
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Google's default is 3600; fall back to something short rather than
    // caching indefinitely if the field is ever absent.
    let expires_in = resp.expires_in.unwrap_or(3600);
    Ok((resp.access_token, sa.project_id, expires_in))
}

/// The FCM HTTP v1 message body for one device token.
pub fn fcm_message(device_token: &str, n: &Notification) -> serde_json::Value {
    serde_json::json!({
        "message": {
            "token": device_token,
            "notification": { "title": n.title, "body": n.message },
            "android": {
                "priority": "high",
                // Android's equivalent of an APNs collapse id.
                "collapse_key": n.collapse_id,
            },
        }
    })
}

/// The cached FCM access token and project id.
async fn cached_fcm_token(
    client: &reqwest::Client,
    cfg: &FcmConfig,
) -> anyhow::Result<(String, String)> {
    let mut slot = FCM_TOKEN.lock().await;
    if let Some(t) = fresh(&slot) {
        return Ok((t.token, t.project));
    }
    let (token, project, expires_in) = fcm_access_token(
        client,
        &cfg.service_account_file,
        "https://oauth2.googleapis.com/token",
    )
    .await?;
    *slot = Some(CachedToken {
        token: token.clone(),
        project: project.clone(),
        expires_at: now_secs().saturating_add(expires_in),
    });
    Ok((token, project))
}

pub async fn send_fcm(
    client: &reqwest::Client,
    cfg: &FcmConfig,
    n: &Notification,
) -> anyhow::Result<()> {
    let (token, project) = cached_fcm_token(client, cfg).await?;
    let url = format!("https://fcm.googleapis.com/v1/projects/{project}/messages:send");
    for device in &cfg.device_tokens {
        // As in `send_apns`: one unreachable device must not abandon the rest.
        match client
            .post(&url)
            .bearer_auth(&token)
            .json(&fcm_message(device, n))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => {
                let status = r.status();
                if status.as_u16() == 429 || status.is_server_error() {
                    tracing::warn!(%status, "FCM is throttling or unavailable; push not delivered");
                } else {
                    tracing::warn!(
                        %status,
                        "FCM rejected a push (registration token stale or credentials wrong)"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "FCM request failed for one device"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notification() -> Notification {
        Notification {
            title: "CRITICAL: disk_low".into(),
            message: "free space below floor (free_bytes=1234)".into(),
            collapse_id: "status-disk_low".into(),
        }
    }

    #[test]
    fn apns_payload_shape() {
        let p = apns_payload(&notification());
        assert_eq!(p["aps"]["alert"]["title"], "CRITICAL: disk_low");
        assert!(p["aps"]["alert"]["body"].as_str().unwrap().contains("free_bytes"));
        // A node alert should surface immediately, not batch with the morning
        // summary.
        assert_eq!(p["aps"]["interruption-level"], "time-sensitive");
    }

    #[test]
    fn fcm_message_shape() {
        let m = fcm_message("device-abc", &notification());
        assert_eq!(m["message"]["token"], "device-abc");
        assert_eq!(m["message"]["notification"]["title"], "CRITICAL: disk_low");
        assert_eq!(m["message"]["android"]["priority"], "high");
        // Collapse keys must agree across providers, or a raise/clear pair
        // stacks on one platform and replaces on the other.
        assert_eq!(m["message"]["android"]["collapse_key"], "status-disk_low");
    }

    #[test]
    fn collapse_ids_match_across_providers() {
        let n = notification();
        let fcm = fcm_message("d", &n);
        assert_eq!(fcm["message"]["android"]["collapse_key"], n.collapse_id);
        // APNs carries it as a header rather than in the payload; assert the
        // value the sender will use is the same one.
        assert_eq!(n.collapse_id, "status-disk_low");
    }

    #[test]
    fn a_malformed_apns_key_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("AuthKey.p8");
        std::fs::write(&key, "not a pem").unwrap();
        let cfg = ApnsConfig {
            key_file: key,
            key_id: "ABC1234567".into(),
            team_id: "TEAM123456".into(),
            topic: "com.example.app".into(),
            production: false,
            device_tokens: vec!["d".into()],
        };
        let err = apns_token(&cfg).unwrap_err().to_string();
        assert!(err.contains("EC PEM"), "unhelpful error: {err}");
    }
}
