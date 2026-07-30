//! Decoding a satd webhook body and turning it into a notification.
//!
//! Only the fields the relay needs are decoded. Everything on this surface is
//! additive, so a strict `deny_unknown_fields` decode would break the relay the
//! first time satd adds a taxonomy entry — exactly when an operator most wants
//! their alerts to keep arriving.

use serde::Deserialize;

/// The delivered envelope, decoded loosely.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    pub body: Body,
}

/// The `body` object, tagged by `category`. Anything the relay does not map is
/// `Other` — forwarded as a generic notification rather than dropped.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum Body {
    Status {
        kind: String,
        state: String,
        severity: String,
        message: String,
        #[serde(default)]
        details: std::collections::BTreeMap<String, String>,
    },
    Chain {
        kind: String,
        /// `reorg` carries no `height` — it reports the fork as a pair of tip
        /// heights. Decoding it as `height` yielded `None` on every real reorg,
        /// so the notification silently lost the number it advertised. Block
        /// connects/disconnects do carry `height`, but they produce no
        /// notification, so it is not decoded.
        #[serde(default)]
        from_height: Option<u32>,
        #[serde(default)]
        to_height: Option<u32>,
    },
    #[serde(other)]
    Other,
}

/// A push notification, before it is shaped for a specific provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub message: String,
    /// Collapse key: notifications sharing one replace each other on the
    /// device, so a flapping condition does not stack up a wall of banners.
    pub collapse_id: String,
}

/// Severity rank for the `min_severity` filter. An unrecognized severity ranks
/// at the top: a condition this relay cannot name is not one to filter out.
pub fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "warning" => 1,
        "critical" => 2,
        _ => 3,
    }
}

/// Map a delivery to a notification, or `None` when it is not worth waking a
/// phone for.
pub fn to_notification(env: &Envelope, min_severity: &str) -> Option<Notification> {
    let floor = severity_rank(min_severity);
    match &env.body {
        Body::Status {
            kind,
            state,
            severity,
            message,
            details,
        } => {
            if severity_rank(severity) < floor {
                return None;
            }
            // A recovery is worth a notification — an operator who was paged
            // wants to know it is over — but it is never urgent, so it is
            // titled plainly rather than shouted.
            let title = match state.as_str() {
                "cleared" => format!("Recovered: {kind}"),
                _ => format!("{}: {kind}", severity.to_uppercase()),
            };
            let mut message = message.clone();
            // Fold the one detail most likely to be actionable into the body,
            // since a phone banner shows two lines and nobody expands a map.
            for key in ["free_bytes", "seconds_since_block", "peers", "depth"] {
                if let Some(v) = details.get(key) {
                    message.push_str(&format!(" ({key}={v})"));
                    break;
                }
            }
            Some(Notification {
                title,
                // Collapse on the condition, so a raise and its later clear
                // replace one another instead of stacking.
                collapse_id: format!("status-{kind}"),
                message,
            })
        }
        Body::Chain {
            kind,
            from_height,
            to_height,
            ..
        } if kind == "reorg" => Some(Notification {
            title: "Chain reorganization".into(),
            message: match (from_height, to_height) {
                (Some(from), Some(to)) => format!(
                    "The active chain tip changed from height {from} to {to}."
                ),
                (_, Some(to)) => format!("The active chain tip changed to height {to}."),
                _ => "The active chain tip changed.".into(),
            },
            collapse_id: "chain-reorg".into(),
        }),
        // Block connects and mempool churn: real events, but not ones a push
        // notification is the right medium for. A relay that buzzed on every
        // block would be uninstalled within a day.
        //
        // There is deliberately no "you missed some events" notification.
        // Webhooks are best-effort and satd does not report gaps in-band —
        // dropped deliveries show up on the node's
        // `satd_alertwebhook_dropped_total` counter, which is where an operator
        // should alert on them. A relay cannot know what it was not sent.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Envelope {
        serde_json::from_str(json).expect("decodes")
    }

    #[test]
    fn maps_a_raised_status_to_a_notification() {
        let env = parse(
            r#"{"schema_version":1,"stamp":{},"body":{
                "category":"status","kind":"disk_low","state":"raised",
                "severity":"critical","message":"free space below floor",
                "details":{"free_bytes":"1234","threshold_bytes":"99"}}}"#,
        );
        let n = to_notification(&env, "warning").expect("mapped");
        assert_eq!(n.title, "CRITICAL: disk_low");
        assert!(n.message.contains("free space below floor"));
        assert!(n.message.contains("free_bytes=1234"), "{}", n.message);
        assert_eq!(n.collapse_id, "status-disk_low");
    }

    #[test]
    fn a_clear_collapses_onto_its_raise() {
        // The device should end up showing "recovered", not two banners.
        let raise = parse(
            r#"{"body":{"category":"status","kind":"tip_stall","state":"raised",
                "severity":"critical","message":"stalled"}}"#,
        );
        let clear = parse(
            r#"{"body":{"category":"status","kind":"tip_stall","state":"cleared",
                "severity":"critical","message":"recovered"}}"#,
        );
        let a = to_notification(&raise, "info").unwrap();
        let b = to_notification(&clear, "info").unwrap();
        assert_eq!(a.collapse_id, b.collapse_id);
        assert!(b.title.starts_with("Recovered:"), "{}", b.title);
    }

    #[test]
    fn severity_floor_drops_quiet_events() {
        let info = parse(
            r#"{"body":{"category":"status","kind":"ibd_complete","state":"edge",
                "severity":"info","message":"synced"}}"#,
        );
        assert!(to_notification(&info, "warning").is_none());
        assert!(to_notification(&info, "info").is_some());
    }

    #[test]
    fn an_unknown_severity_is_never_filtered_out() {
        // A severity this relay predates must not be silently dropped.
        let env = parse(
            r#"{"body":{"category":"status","kind":"new_thing","state":"raised",
                "severity":"catastrophic","message":"?"}}"#,
        );
        assert!(to_notification(&env, "critical").is_some());
    }

    #[test]
    fn unknown_categories_decode_and_are_ignored() {
        // Forward-compat: satd adds bodies additively, and a decode failure
        // here would take down alerting at the worst moment.
        let env = parse(r#"{"body":{"category":"some_future_thing","whatever":1}}"#);
        assert!(matches!(env.body, Body::Other));
        assert!(to_notification(&env, "info").is_none());
    }

    #[test]
    fn routine_events_do_not_buzz_a_phone() {
        let block = parse(r#"{"body":{"category":"chain","kind":"block_connected","height":9}}"#);
        assert!(to_notification(&block, "info").is_none());
    }

    #[test]
    fn reorgs_and_gaps_do() {
        // This is satd's actual `reorg` body. The earlier version of this test
        // fed `{"kind":"reorg","height":…}`, which satd cannot produce —
        // `ChainEvent::Reorg` carries `from_height`/`to_height` and no
        // `height` — so it asserted against a fixture of the relay's own
        // invention and stayed green while every real reorg pushed a
        // notification with no height in it at all.
        let reorg = parse(
            r#"{"body":{"category":"chain","kind":"reorg",
                "from_height":812345,"old_tip":"aa",
                "to_height":812347,"new_tip":"bb"}}"#,
        );
        let n = to_notification(&reorg, "info").expect("reorg notifies");
        assert!(n.message.contains("812345"), "{}", n.message);
        assert!(n.message.contains("812347"), "{}", n.message);

        // satd does not send a gap notice — webhooks are best-effort and
        // report drops on the node's counter, not in-band. An unrecognized
        // body decodes to `Other` and produces nothing rather than failing.
        let unknown = parse(r#"{"body":{"category":"lagged","dropped_count":37}}"#);
        assert!(to_notification(&unknown, "info").is_none());
    }
}
