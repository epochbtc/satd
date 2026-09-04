use crate::context::McpContext;
use serde_json::json;

/// Get peer connection info. Summary mode returns compact list; full mode returns all details.
pub fn get_peer_info(ctx: &McpContext, summary: bool) -> String {
    let peers = ctx.peer_manager.get_peer_info();
    let count = ctx.peer_manager.connection_count();

    if summary {
        let compact: Vec<_> = peers
            .iter()
            .filter_map(|p| {
                Some(json!({
                    "addr": p.get("addr")?,
                    "subver": p.get("subver")?,
                    "startingheight": p.get("startingheight")?,
                    "pingtime": p.get("pingtime"),
                    "inbound": p.get("inbound")?,
                }))
            })
            .collect();
        let result = json!({
            "connection_count": count,
            "peers": compact,
        });
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
    } else {
        let result = json!({
            "connection_count": count,
            "peers": peers,
        });
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Manage peer connections: add, disconnect, ban, or unban.
pub fn manage_peer(ctx: &McpContext, action: &str, address: &str) -> String {
    let addr: std::net::SocketAddr = match address.parse() {
        Ok(a) => a,
        Err(e) => return json!({"error": format!("Invalid address: {}", e)}).to_string(),
    };

    match action {
        "disconnect" => {
            let ok = ctx.peer_manager.disconnect(&addr);
            json!({"result": if ok { "disconnected" } else { "peer not found" }}).to_string()
        }
        "ban" => {
            let target = node::net::ban::BanTarget::Net(ipnet::IpNet::from(addr.ip()));
            let now = node::time::now_secs();
            let duration = ctx.peer_manager.default_ban_duration_secs();
            match ctx.peer_manager.set_ban_subnet(&target, true, now, now + duration) {
                Ok(()) => json!({"result": "banned"}).to_string(),
                Err(e) => json!({"error": e}).to_string(),
            }
        }
        "unban" => {
            let target = node::net::ban::BanTarget::Net(ipnet::IpNet::from(addr.ip()));
            match ctx.peer_manager.set_ban_subnet(&target, false, 0, 0) {
                Ok(()) => json!({"result": "unbanned"}).to_string(),
                Err(e) => json!({"error": e}).to_string(),
            }
        }
        _ => json!({"error": format!("Unknown action: {}. Use: disconnect, ban, unban", action)})
            .to_string(),
    }
}

/// List all currently banned peers.
pub fn get_ban_list(ctx: &McpContext) -> String {
    let banned = ctx.peer_manager.list_banned();
    let result = json!({
        "count": banned.len(),
        "banned": banned,
    });
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
