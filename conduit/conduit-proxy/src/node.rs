use conduit_common::config::ClearGateConfig;
use conduit_common::redis::keys;
use conduit_common::types::{NodeHeartbeat, NodeStatus};
use deadpool_redis::Pool;
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use sha2::Sha256;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::policy;

type HmacSha256 = Hmac<Sha256>;

/// Spawn the node lifecycle on a dedicated thread (same pattern as logging pipeline).
/// Handles: enrollment verification, self-registration, heartbeat loop, pub/sub config reload.
pub fn spawn_node_lifecycle(config: &Arc<ClearGateConfig>, pool: &Arc<Pool>) {
    let node_cfg = match config.node {
        Some(ref n) => n.clone(),
        None => return,
    };

    let pool = pool.clone();
    let config = config.clone();
    let dragonfly_url = node_cfg.dragonfly_url.clone();

    std::thread::Builder::new()
        .name("cleargate-node".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create node lifecycle runtime");

            rt.block_on(run_node_lifecycle(config, pool, node_cfg, dragonfly_url));
        })
        .expect("Failed to spawn node lifecycle thread");
}

async fn run_node_lifecycle(
    config: Arc<ClearGateConfig>,
    pool: Arc<Pool>,
    node_cfg: conduit_common::config::NodeConfig,
    dragonfly_url: String,
) {
    let node_id = &node_cfg.node_id;
    let node_name = node_cfg.name.as_deref().unwrap_or(node_id);
    let heartbeat_interval = std::time::Duration::from_secs(node_cfg.heartbeat_interval_secs);
    let start = Instant::now();

    // Verify enrollment token (one-time, consumed on success)
    if let Err(e) = verify_enrollment(&pool, node_id, node_cfg.enrollment_token.as_deref()).await {
        error!(node_id, "Enrollment verification failed: {e}");
        error!(node_id, "Obtain a valid enrollment_token via POST /api/v1/nodes and add it to [node] config");
        std::process::exit(1);
    }

    // Self-register (only succeeds after enrollment token is verified)
    if let Err(e) = self_register(&pool, node_id, node_name).await {
        error!(node_id, "Failed to self-register node: {e}");
        return;
    }
    info!(node_id, node_name, "Node registered and enrolled");

    // Spawn pub/sub listener in a separate task (needs its own redis client, not pool)
    let dragonfly_url_ps = dragonfly_url.clone();
    let node_id_ps = node_id.clone();
    tokio::spawn(async move {
        pubsub_listener(&dragonfly_url_ps, &node_id_ps).await;
    });

    // Decode HMAC key if present (for signing heartbeats)
    let hmac_key_bytes = node_cfg.hmac_key.as_deref().and_then(|k| {
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, k).ok()
    });
    if hmac_key_bytes.is_none() {
        warn!(node_id, "No hmac_key configured — heartbeats will be unsigned");
    }

    // Heartbeat loop
    let mut interval = tokio::time::interval(heartbeat_interval);
    loop {
        interval.tick().await;

        let active = crate::service::ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        let total = crate::service::TOTAL_REQUESTS.load(Ordering::Relaxed);

        let hostname = gethostname();
        let mut hb = NodeHeartbeat {
            node_id: node_id.clone(),
            timestamp: chrono::Utc::now(),
            uptime_secs: start.elapsed().as_secs(),
            active_connections: active,
            total_requests: total,
            version: env!("CARGO_PKG_VERSION").to_string(),
            listen_addr: config.listen_addr.clone(),
            host: hostname,
            signature: None,
        };

        // Sign heartbeat with HMAC-SHA256 if key is available
        if let Some(ref key_bytes) = hmac_key_bytes {
            hb.signature = Some(sign_heartbeat(&hb, key_bytes));
        }

        let ttl_secs = node_cfg.heartbeat_interval_secs * 3;
        if let Err(e) = send_heartbeat(&pool, node_id, &hb, ttl_secs).await {
            warn!(node_id, "Heartbeat failed: {e}");
        }
    }
}

/// Verify the one-time enrollment token against the value stored by `POST /nodes`.
/// On success, consumes the token (HDEL) so it can't be replayed.
async fn verify_enrollment(
    pool: &Pool,
    node_id: &str,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let key = keys::node(node_id);

    // Check if this node has already enrolled (enrolled_at is set)
    let enrolled_at: Option<String> = conn.hget(&key, "enrolled_at").await.unwrap_or(None);
    if enrolled_at.is_some() {
        // Already enrolled — skip token verification (idempotent restarts)
        return Ok(());
    }

    // First enrollment — token is required
    let stored_token: Option<String> = conn.hget(&key, "enrollment_token").await.unwrap_or(None);
    let stored_token = stored_token
        .ok_or_else(|| anyhow::anyhow!("No enrollment record found for node {node_id} — create it via POST /api/v1/nodes first"))?;

    let provided_token = token
        .ok_or_else(|| anyhow::anyhow!("enrollment_token is required in [node] config for first enrollment"))?;

    if !constant_time_eq(provided_token.as_bytes(), stored_token.as_bytes()) {
        anyhow::bail!("Invalid enrollment token for node {node_id}");
    }

    // Token verified — consume it (delete from hash so it can't be replayed)
    let _: Result<(), _> = conn.hdel(&key, "enrollment_token").await;

    Ok(())
}

/// Constant-time byte comparison to prevent timing attacks on token verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn self_register(pool: &Pool, node_id: &str, node_name: &str) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let key = keys::node(node_id);

    let status = serde_json::to_string(&NodeStatus::Active)?;
    redis::pipe()
        .atomic()
        .hset(&key, "id", node_id)
        .hset(&key, "name", node_name)
        .hset(&key, "status", &status)
        .hset(&key, "dragonfly_user", node_id)
        .hset(&key, "enrolled_at", chrono::Utc::now().to_rfc3339())
        .sadd(keys::NODES_INDEX, node_id)
        .exec_async(&mut *conn)
        .await?;

    Ok(())
}

/// Compute HMAC-SHA256 signature of a heartbeat payload (with signature field set to None).
fn sign_heartbeat(hb: &NodeHeartbeat, key_bytes: &[u8]) -> String {
    let mut hb_unsigned = hb.clone();
    hb_unsigned.signature = None;
    let payload = serde_json::to_string(&hb_unsigned).expect("heartbeat serialization");

    let mut mac = HmacSha256::new_from_slice(key_bytes).expect("HMAC key length");
    mac.update(payload.as_bytes());
    let result = mac.finalize().into_bytes();

    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &result)
}

async fn send_heartbeat(
    pool: &Pool,
    node_id: &str,
    hb: &NodeHeartbeat,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let key = keys::node_heartbeat(node_id);
    let json = serde_json::to_string(hb)?;
    conn.set_ex::<_, _, ()>(&key, &json, ttl_secs).await?;
    Ok(())
}

async fn pubsub_listener(dragonfly_url: &str, node_id: &str) {
    // Create a dedicated redis client for pub/sub (can't use pooled connections).
    let client = match redis::Client::open(dragonfly_url) {
        Ok(c) => c,
        Err(e) => {
            error!(node_id, "Failed to create pub/sub client: {e}");
            return;
        }
    };

    let mut pubsub = match client.get_async_pubsub().await {
        Ok(ps) => ps,
        Err(e) => {
            error!(node_id, "Failed to get pub/sub connection: {e}");
            return;
        }
    };

    if let Err(e) = pubsub.subscribe(keys::CONFIG_RELOAD_CHANNEL).await {
        error!(node_id, "Failed to subscribe to config reload channel: {e}");
        return;
    }
    if let Err(e) = pubsub.subscribe(keys::THREAT_RELOAD_CHANNEL).await {
        error!(node_id, "Failed to subscribe to threat reload channel: {e}");
        // Non-fatal — config reload still works
    }

    info!(node_id, "Subscribed to config + threat reload channels");

    use tokio_stream::StreamExt;
    let mut msg_stream = pubsub.on_message();
    while let Some(msg) = msg_stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(_) => continue,
        };
        info!(node_id, channel = %channel, payload = %payload, "Reload signal received");

        if channel == keys::CONFIG_RELOAD_CHANNEL {
            // Invalidate all config-driven caches
            policy::rules::invalidate_cache();
            policy::categories::invalidate_cache();
            crate::dlp::invalidate_cache();
        }
        if channel == keys::THREAT_RELOAD_CHANNEL {
            crate::threat::feeds::trigger_immediate_refresh();
        }
    }
}

fn gethostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".into())
}
