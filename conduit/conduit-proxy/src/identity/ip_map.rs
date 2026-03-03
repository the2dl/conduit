use conduit_common::redis::keys;
use conduit_common::types::{AuthMethod, UserIdentity};
use deadpool_redis::Pool;
use redis::AsyncCommands;
use std::sync::Arc;

/// Look up a username by source IP from Dragonfly.
/// IP-to-user mappings can be populated via DHCP lease import, CSV upload, or API.
pub async fn lookup_ip(pool: &Arc<Pool>, ip: &str) -> Option<UserIdentity> {
    let mut conn = pool.get().await.ok()?;
    let username: Option<String> = conn.hget(keys::IP_MAP, ip).await.ok()?;

    username.map(|u| UserIdentity {
        username: Some(u),
        auth_method: Some(AuthMethod::IpMap),
        groups: vec![],
    })
}
