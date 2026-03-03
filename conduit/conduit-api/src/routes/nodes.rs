use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::{
    NodeEnrollment, NodeHeartbeat, NodeInfo, NodeRegistration, NodeStatus,
};
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// List all nodes with heartbeat/online status.
async fn list_nodes(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Vec::<NodeInfo>::new()));
    };

    let node_ids: Vec<String> = conn.smembers(keys::NODES_INDEX).await.unwrap_or_default();

    let mut nodes = Vec::with_capacity(node_ids.len());
    for id in &node_ids {
        if let Some(info) = load_node_info(&mut conn, id).await {
            nodes.push(info);
        }
    }

    (StatusCode::OK, Json(nodes))
}

/// Get a single node with per-node stats.
async fn get_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!(null)));
    };

    match load_node_info(&mut conn, &node_id).await {
        Some(info) => (StatusCode::OK, Json(serde_json::to_value(info).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Node not found"})),
        ),
    }
}

#[derive(Deserialize)]
struct CreateNode {
    name: String,
}

fn validate_node_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name must not be empty");
    }
    if name.len() > 256 {
        return Err("name must be at most 256 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("name must contain only alphanumeric, dash, underscore, or dot characters");
    }
    Ok(())
}

/// Create a new node: generate credentials, ACL SETUSER with scoped keys, store registration.
async fn create_node(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CreateNode>,
) -> impl IntoResponse {
    if let Err(msg) = validate_node_name(&input.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        );
    }

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Redis unavailable"})),
        );
    };

    // Generate node ID, password, enrollment token, and HMAC key
    let node_id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..12]);
    let password = generate_secret(32);
    let enrollment_token = generate_secret(32);
    let hmac_key = generate_secret(32);

    // --- Tightened ACL ---
    // Only grant access to keys the node actually needs:
    //   - Own node hash + heartbeat + enrollment_token (self-registration)
    //   - Nodes index set (SADD for self-registration)
    //   - Log stream (XADD)
    //   - Stats counters (global + per-node INCR/DECR)
    //   - Policy rules (read)
    //   - Domain categories (read)
    //   - Config hash (read)
    //   - Config reload channel (SUBSCRIBE)
    //   - Users hash + IP map (auth lookups)
    let node_key_pattern = format!("cleargate:nodes:{node_id}");
    let node_stats_pattern = format!("cleargate:stats:{node_id}:*");

    let acl_result: Result<String, _> = redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&node_id)
        .arg("on")
        .arg(format!(">{password}"))
        // Key patterns — node's own keys
        .arg(format!("~{node_key_pattern}"))
        .arg(format!("~{node_key_pattern}:*"))
        // Index set (for SADD during self-registration)
        .arg("~cleargate:nodes:index")
        // Log stream (XADD)
        .arg("~cleargate:logs:stream")
        // Stats counters (global + per-node)
        .arg("~cleargate:stats:*")
        .arg(format!("~{node_stats_pattern}"))
        // Read-only data
        .arg("~cleargate:policies")
        .arg("~cleargate:domain:*")
        .arg("~cleargate:config")
        .arg("~cleargate:config:reload")
        // Auth lookups
        .arg("~cleargate:users:*")
        .arg("~cleargate:ip_map")
        // Scoped command categories — only what nodes need
        .arg("+@read")
        .arg("+@write")
        .arg("+@set")
        .arg("+@sortedset")
        .arg("+@hash")
        .arg("+@string")
        .arg("+@stream")
        .arg("+@pubsub")
        .arg("+@connection")
        .arg("+@server")
        .arg("-@admin")
        .arg("-@dangerous")
        .query_async(&mut *conn)
        .await;

    if let Err(e) = acl_result {
        tracing::error!(node_id = %node_id, "ACL SETUSER failed: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to configure node access control"})),
        );
    }

    // Store registration + enrollment token + HMAC key
    let now = chrono::Utc::now();
    let key = keys::node(&node_id);
    let status_json = serde_json::to_string(&NodeStatus::Pending).unwrap_or_default();
    let _: Result<(), _> = redis::pipe()
        .atomic()
        .hset(&key, "id", &node_id)
        .hset(&key, "name", &input.name)
        .hset(&key, "status", &status_json)
        .hset(&key, "dragonfly_user", &node_id)
        .hset(&key, "created_at", now.to_rfc3339())
        .hset(&key, "enrollment_token", &enrollment_token)
        .hset(&key, "hmac_key", &hmac_key)
        .sadd(keys::NODES_INDEX, &node_id)
        .exec_async(&mut *conn)
        .await;

    // Build the dragonfly_url for the enrollment response
    let dragonfly_url =
        build_node_dragonfly_url(&state.config.dragonfly_url, &node_id, &password);

    let enrollment = NodeEnrollment {
        node_id: node_id.clone(),
        dragonfly_url,
        dragonfly_user: node_id,
        dragonfly_password: password,
        enrollment_token,
        hmac_key,
    };

    (
        StatusCode::CREATED,
        Json(serde_json::to_value(enrollment).unwrap()),
    )
}

/// Delete a node: ACL DELUSER, remove keys, SREM from index.
async fn delete_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    // ACL DELUSER (ignore errors if user doesn't exist)
    let _: Result<(), _> = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&node_id)
        .query_async(&mut *conn)
        .await;

    // Remove all node keys
    let node_key = keys::node(&node_id);
    let hb_key = keys::node_heartbeat(&node_id);
    let _: Result<(), _> = redis::pipe()
        .atomic()
        .del(&node_key)
        .del(&hb_key)
        .del(keys::stats_node(&node_id, "requests"))
        .del(keys::stats_node(&node_id, "blocked"))
        .del(keys::stats_node(&node_id, "tls"))
        .srem(keys::NODES_INDEX, &node_id)
        .exec_async(&mut *conn)
        .await;

    StatusCode::NO_CONTENT
}

async fn load_node_info(
    conn: &mut deadpool_redis::Connection,
    node_id: &str,
) -> Option<NodeInfo> {
    let key = keys::node(node_id);
    let fields: Vec<String> = conn.hgetall(&key).await.ok()?;

    // hgetall returns flat [field, value, field, value, ...]
    if fields.is_empty() {
        return None;
    }

    let map: std::collections::HashMap<String, String> = fields
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                Some((c[0].clone(), c[1].clone()))
            } else {
                None
            }
        })
        .collect();

    let id = map.get("id")?.clone();
    let name = map.get("name").cloned().unwrap_or_default();
    let status: NodeStatus = map
        .get("status")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(NodeStatus::Pending);
    let dragonfly_user = map.get("dragonfly_user").cloned().unwrap_or_default();
    let created_at = map
        .get("created_at")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(chrono::Utc::now);
    let enrolled_at = map.get("enrolled_at").and_then(|s| s.parse().ok());
    let hmac_key = map.get("hmac_key").cloned();

    let reg = NodeRegistration {
        id,
        name,
        status,
        dragonfly_user,
        created_at,
        enrolled_at,
    };

    // Load heartbeat + verify HMAC signature
    let hb_key = keys::node_heartbeat(node_id);
    let heartbeat: Option<NodeHeartbeat> = conn
        .get::<_, Option<String>>(&hb_key)
        .await
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok());

    let online = heartbeat.is_some();

    let heartbeat_verified = match (&heartbeat, &hmac_key) {
        (Some(hb), Some(key)) => verify_heartbeat_signature(hb, key),
        (Some(_), None) => false, // Heartbeat exists but no HMAC key stored — untrusted
        _ => false,
    };

    // If the node has an HMAC key configured but the heartbeat signature
    // failed verification, treat the node as offline (don't trust forged heartbeats).
    let trusted_online = if online && hmac_key.is_some() {
        heartbeat_verified
    } else {
        online
    };

    Some(NodeInfo {
        registration: reg,
        heartbeat,
        online: trusted_online,
        heartbeat_verified,
    })
}

/// Verify the HMAC-SHA256 signature on a heartbeat.
fn verify_heartbeat_signature(hb: &NodeHeartbeat, hmac_key_b64: &str) -> bool {
    let Some(ref sig_b64) = hb.signature else {
        return false;
    };

    let Ok(key_bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hmac_key_b64)
    else {
        return false;
    };
    let Ok(sig_bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_b64)
    else {
        return false;
    };

    // Recompute signature over heartbeat with signature field cleared
    let mut hb_unsigned = hb.clone();
    hb_unsigned.signature = None;
    let Ok(payload) = serde_json::to_string(&hb_unsigned) else {
        return false;
    };

    let Ok(mut mac) = HmacSha256::new_from_slice(&key_bytes) else {
        return false;
    };
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

fn generate_secret(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// Build a redis:// URL with the node's credentials, preserving the host:port from the API config.
fn build_node_dragonfly_url(base_url: &str, user: &str, password: &str) -> String {
    let scheme = if base_url.starts_with("rediss://") {
        "rediss"
    } else {
        "redis"
    };

    let stripped = base_url
        .strip_prefix("redis://")
        .or_else(|| base_url.strip_prefix("rediss://"))
        .unwrap_or(base_url);

    // Strip any existing user:pass@
    let host_port = if let Some((_creds, hp)) = stripped.rsplit_once('@') {
        hp
    } else {
        stripped
    };

    format!("{scheme}://{user}:{password}@{host_port}")
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/nodes/{id}", get(get_node).delete(delete_node))
}
