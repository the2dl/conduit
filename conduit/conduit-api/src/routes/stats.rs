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
            let cache_hits: u64 = conn.get(keys::STATS_CACHE_HITS).await.unwrap_or(0);
            let cache_misses: u64 = conn.get(keys::STATS_CACHE_MISSES).await.unwrap_or(0);

            let threat_blocks: u64 = conn.get(keys::STATS_THREAT_BLOCKS).await.unwrap_or(0);
            let threat_t0: u64 = conn.get(keys::STATS_THREAT_T0).await.unwrap_or(0);
            let threat_t1: u64 = conn.get(keys::STATS_THREAT_T1).await.unwrap_or(0);
            let threat_t2: u64 = conn.get(keys::STATS_THREAT_T2).await.unwrap_or(0);
            let threat_t3: u64 = conn.get(keys::STATS_THREAT_T3).await.unwrap_or(0);

            let global = ProxyStats {
                total_requests: total,
                blocked_requests: blocked,
                active_connections: active,
                tls_intercepted: tls,
                cache_hits,
                cache_misses,
                threat_blocks,
                threat_tier0_evals: threat_t0,
                threat_tier1_escalations: threat_t1,
                threat_tier2_escalations: threat_t2,
                threat_tier3_escalations: threat_t3,
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

use crate::routes::logs::parse_stream_entries;
use axum::extract::Query;
use conduit_common::types::PolicyAction;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    #[serde(default = "default_range")]
    pub range: String, // "1h", "24h", "7d"
}

fn default_range() -> String {
    "24h".to_string()
}

#[derive(Serialize)]
pub struct TimeseriesBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
}

#[derive(Serialize)]
pub struct TimeseriesResponse {
    pub range: String,
    pub bucket_seconds: u64,
    pub buckets: Vec<TimeseriesBucket>,
    pub total_in_range: u64,
    pub blocked_in_range: u64,
    pub prior_period_delta_pct: Option<f64>,
}

async fn get_timeseries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> Json<TimeseriesResponse> {
    let duration_secs: i64 = match q.range.as_str() {
        "1h" => 3600,
        "7d" => 7 * 86400,
        _ => 86400,
    };

    let bucket_count = 48usize;
    let bucket_secs = (duration_secs as f64 / bucket_count as f64).ceil() as i64;
    let now = chrono::Utc::now();
    let now_ts = now.timestamp();
    let start_ts = now_ts - duration_secs;
    let start_ms = (start_ts * 1000).max(0);

    let mut buckets: Vec<TimeseriesBucket> = (0..bucket_count)
        .map(|i| {
            let b_ts = start_ts + (i as i64 * bucket_secs);
            let dt = chrono::DateTime::from_timestamp(b_ts, 0).unwrap_or(now);
            TimeseriesBucket {
                timestamp: dt.to_rfc3339(),
                total: 0,
                blocked: 0,
            }
        })
        .collect();

    let Ok(mut conn) = state.pool.get().await else {
        return Json(TimeseriesResponse {
            range: q.range,
            bucket_seconds: bucket_secs as u64,
            buckets,
            total_in_range: 0,
            blocked_in_range: 0,
            prior_period_delta_pct: None,
        });
    };

    let raw: Vec<redis::Value> = redis::cmd("XRANGE")
        .arg(keys::LOG_STREAM)
        .arg(format!("{start_ms}-0"))
        .arg("+")
        .query_async(&mut *conn)
        .await
        .unwrap_or_default();

    let entries = parse_stream_entries(&raw);
    let mut total_in_range = 0u64;
    let mut blocked_in_range = 0u64;

    for (_id, entry) in entries {
        let entry_ts = entry.timestamp.timestamp();
        if entry_ts >= start_ts && entry_ts <= now_ts {
            let idx = (((entry_ts - start_ts) / bucket_secs) as usize).min(bucket_count - 1);
            buckets[idx].total += 1;
            total_in_range += 1;
            let is_blocked = entry.action == PolicyAction::Block
                || entry.block_reason.is_some()
                || entry.status_code >= 400;
            if is_blocked {
                buckets[idx].blocked += 1;
                blocked_in_range += 1;
            }
        }
    }

    let prior_start_ts = start_ts - duration_secs;
    let prior_start_ms = (prior_start_ts * 1000).max(0);
    let prior_raw: Vec<redis::Value> = redis::cmd("XRANGE")
        .arg(keys::LOG_STREAM)
        .arg(format!("{prior_start_ms}-0"))
        .arg(format!("{start_ms}-0"))
        .query_async(&mut *conn)
        .await
        .unwrap_or_default();
    let prior_count = parse_stream_entries(&prior_raw).len() as u64;

    let prior_period_delta_pct = if prior_count > 0 {
        Some(((total_in_range as f64 - prior_count as f64) / prior_count as f64) * 100.0)
    } else {
        None
    };

    Json(TimeseriesResponse {
        range: q.range,
        bucket_seconds: bucket_secs as u64,
        buckets,
        total_in_range,
        blocked_in_range,
        prior_period_delta_pct,
    })
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/stats", get(get_stats))
        .route("/stats/timeseries", get(get_timeseries))
}
