pub mod basic_auth;
pub mod ip_map;
pub mod kerberos;

use conduit_common::config::ClearGateConfig;
use conduit_common::types::UserIdentity;
use deadpool_redis::Pool;
use pingora_proxy::Session;
use std::sync::Arc;
use tracing::trace;

/// Run the auth priority chain: Kerberos/Negotiate -> Proxy-Auth Basic -> IP mapping.
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

    // 3. Fall back to IP-to-user mapping
    let client_ip = session
        .downstream_session
        .client_addr()
        .map(|a| {
            // Properly extract IP from SocketAddr string (handles both IPv4 and IPv6)
            let s = a.to_string();
            s.parse::<std::net::SocketAddr>()
                .map(|sa| sa.ip().to_string())
                .unwrap_or(s)
        })
        .unwrap_or_default();

    if !client_ip.is_empty() {
        if let Some(identity) = ip_map::lookup_ip(pool, &client_ip).await {
            trace!(username = ?identity.username, ip = %client_ip, "Identified via IP map");
            return identity;
        }
    }

    UserIdentity::default()
}
