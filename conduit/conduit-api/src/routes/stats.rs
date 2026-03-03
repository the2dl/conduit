use crate::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::{NodeHeartbeat, NodeStats, ProxyStats};
use redis::AsyncCommands;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct StatsResponse {
    #[serde(flatten)]
    stats: ProxyStats,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nodes: Vec<NodeStats>,
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = match state.pool.get().await {
        Ok(mut conn) => {
            let total: u64 = conn.get(keys::STATS_REQUESTS).await.unwrap_or(0);
            let blocked: u64 = conn.get(keys::STATS_BLOCKED).await.unwrap_or(0);
            let tls: u64 = conn.get(keys::STATS_TLS).await.unwrap_or(0);
            let active: u64 = conn.get(keys::STATS_ACTIVE).await.unwrap_or(0);

            let global = ProxyStats {
                total_requests: total,
                blocked_requests: blocked,
                active_connections: active,
                tls_intercepted: tls,
                cache_hits: 0,
                cache_misses: 0,
            };

            // Per-node breakdown
            let node_ids: Vec<String> =
                conn.smembers(keys::NODES_INDEX).await.unwrap_or_default();

            let mut nodes = Vec::new();
            for nid in &node_ids {
                let node_key = keys::node(nid);
                let name: String = conn
                    .hget(&node_key, "name")
                    .await
                    .unwrap_or_else(|_| nid.clone());

                let n_total: u64 = conn
                    .get(keys::stats_node(nid, "requests"))
                    .await
                    .unwrap_or(0);
                let n_blocked: u64 = conn
                    .get(keys::stats_node(nid, "blocked"))
                    .await
                    .unwrap_or(0);
                let n_tls: u64 = conn
                    .get(keys::stats_node(nid, "tls"))
                    .await
                    .unwrap_or(0);

                // Check heartbeat for online status and active connections
                let hb_key = keys::node_heartbeat(nid);
                let hb: Option<NodeHeartbeat> = conn
                    .get::<_, Option<String>>(&hb_key)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|json| serde_json::from_str(&json).ok());

                let (online, n_active) = match &hb {
                    Some(h) => (true, h.active_connections),
                    None => (false, 0),
                };

                nodes.push(NodeStats {
                    node_id: nid.clone(),
                    node_name: name,
                    total_requests: n_total,
                    blocked_requests: n_blocked,
                    tls_intercepted: n_tls,
                    active_connections: n_active,
                    online,
                });
            }

            StatsResponse {
                stats: global,
                nodes,
            }
        }
        Err(_) => StatsResponse {
            stats: ProxyStats::default(),
            nodes: vec![],
        },
    };

    Json(stats)
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/stats", get(get_stats))
}
