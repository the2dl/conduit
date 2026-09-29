pub mod basic_auth;
pub mod ip_map;
pub mod kerberos;

use conduit_common::config::ClearGateConfig;
use conduit_common::types::UserIdentity;
use deadpool_redis::Pool;
use pingora_proxy::Session;
use std::sync::Arc;
use tracing::trace;

/// Run the auth priority chain: Kerberos/Negotiate -> Proxy-Auth Basic -> IP mapping / local OS user.
pub async fn identify(
    session: &Session,
    pool: &Arc<Pool>,
    _config: &ClearGateConfig,
) -> UserIdentity {
    // 1. Try Kerberos/Negotiate
    if let Some(identity) = kerberos::try_negotiate(session) {
        trace!(username = ?identity.username, "Identified via Kerberos");
        return identity;
    }

    // 2. Try Proxy-Authorization Basic
    if let Some(identity) = basic_auth::try_basic_auth(session, pool).await {
        trace!(username = ?identity.username, "Identified via Basic auth");
        return identity;
    }

    // 3. Fall back to IP-to-user mapping or local OS user
    let client_addr = session
        .downstream_session
        .client_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    resolve_client_identity(pool, &client_addr).await
}

/// Helper to resolve identity from client socket address string (e.g. "127.0.0.1:54321").
pub async fn resolve_client_identity(pool: &Arc<Pool>, client_addr_str: &str) -> UserIdentity {
    let raw_ip = crate::proxy::extract_ip_from_addr(client_addr_str);
    let port = client_addr_str
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok());

    // 1. Try exact IP mapping from Dragonfly
    if !raw_ip.is_empty() {
        if let Some(identity) = ip_map::lookup_ip(pool, raw_ip).await {
            trace!(username = ?identity.username, ip = %raw_ip, "Identified via IP map");
            return identity;
        }
    }

    // 2. Try normalized LAN IP mapping from Dragonfly
    let normalized = crate::proxy::normalize_client_ip(raw_ip);
    if normalized != raw_ip {
        if let Some(identity) = ip_map::lookup_ip(pool, &normalized).await {
            trace!(username = ?identity.username, ip = %normalized, "Identified via normalized LAN IP map");
            return identity;
        }
    }

    // 3. If connection is local loopback or host LAN, look up Linux OS user from kernel socket table
    #[cfg(target_os = "linux")]
    {
        let is_local = raw_ip == "127.0.0.1"
            || raw_ip == "::1"
            || Some(raw_ip) == crate::proxy::get_primary_lan_ip().as_deref();

        if is_local {
            if let Some(p) = port {
                if let Some(username) = lookup_linux_os_user_by_port(p) {
                    trace!(username = %username, port = p, "Identified via Linux socket UID");
                    return UserIdentity {
                        username: Some(username),
                        auth_method: Some(conduit_common::types::AuthMethod::IpMap),
                        groups: vec![],
                    };
                }
            }
        }
    }

    UserIdentity::default()
}

#[cfg(target_os = "linux")]
pub fn lookup_linux_os_user_by_port(src_port: u16) -> Option<String> {
    let port_hex = format!(":{src_port:04X}");
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 7 && parts[1].ends_with(&port_hex) {
                    if let Ok(uid) = parts[7].parse::<u32>() {
                        return lookup_username_by_uid(uid);
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn lookup_username_by_uid(uid: u32) -> Option<String> {
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[2].parse::<u32>().ok() == Some(uid) {
                return Some(fields[0].to_string());
            }
        }
    }
    if let Ok(user) = std::env::var("USER") {
        return Some(user);
    }
    None
}
