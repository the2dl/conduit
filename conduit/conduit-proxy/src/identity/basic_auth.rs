use conduit_common::redis::sanitize_key_component;
use conduit_common::types::{AuthMethod, UserIdentity};
use conduit_common::util::constant_time_eq;
use deadpool_redis::Pool;
use pingora_proxy::Session;
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::{debug, warn};

/// Parse Proxy-Authorization: Basic header from a Pingora session and validate credentials.
pub async fn try_basic_auth(session: &Session, pool: &Arc<Pool>) -> Option<UserIdentity> {
    let req = session.req_header();
    let auth_header = req.headers.get("proxy-authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    try_basic_auth_from_header(auth_str, pool).await
}

/// Parse a raw Proxy-Authorization header value and validate credentials.
/// Used by both HTTP proxy path and CONNECT tunnel path.
pub async fn try_basic_auth_from_header(auth_str: &str, pool: &Arc<Pool>) -> Option<UserIdentity> {

    if !auth_str.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth_str["Basic ".len()..];
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded,
    )
    .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    let (username, password) = decoded_str.split_once(':')?;
    if username.is_empty() {
        return None;
    }

    // Validate against Dragonfly
    if validate_credentials(pool, username, password).await {
        debug!(username, "Basic auth validated");
        Some(UserIdentity {
            username: Some(username.to_string()),
            auth_method: Some(AuthMethod::Basic),
            groups: load_user_groups(pool, username).await,
        })
    } else {
        debug!(username, "Basic auth failed");
        None
    }
}

async fn validate_credentials(pool: &Arc<Pool>, username: &str, password: &str) -> bool {
    let Ok(mut conn) = pool.get().await else {
        return false;
    };

    let key = format!("cleargate:users:{}", sanitize_key_component(username));
    let stored: Option<String> = conn.hget(&key, "password_hash").await.unwrap_or(None);

    match stored {
        Some(hash) => {
            if let Some(plain) = hash.strip_prefix("plain:") {
                // Legacy plaintext — log deprecation warning so operators migrate.
                warn!(
                    username,
                    "Password stored with plain: prefix — migrate to bcrypt via: \
                     htpasswd -nBC 12 '' | tr -d ':\\n' | redis-cli -x HSET {key} password_hash"
                );
                constant_time_eq(plain.as_bytes(), password.as_bytes())
            } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
                // bcrypt hash — verify using bcrypt (blocking work offloaded to spawn_blocking)
                let password = password.to_string();
                let hash = hash.clone();
                tokio::task::spawn_blocking(move || {
                    bcrypt::verify(password, &hash).unwrap_or(false)
                })
                .await
                .unwrap_or(false)
            } else {
                // Unknown format — reject
                warn!(
                    username,
                    "Unrecognized password_hash format — expected bcrypt ($2b$...) or plain: prefix"
                );
                false
            }
        }
        None => false,
    }
}

async fn load_user_groups(pool: &Arc<Pool>, username: &str) -> Vec<String> {
    let Ok(mut conn) = pool.get().await else {
        return vec![];
    };

    let key = format!("cleargate:users:{}", sanitize_key_component(username));
    let groups: Option<String> = conn.hget(&key, "groups").await.unwrap_or(None);

    groups
        .map(|g| g.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}
