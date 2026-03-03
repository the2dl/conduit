//! Threat detection API endpoints: reputation, feeds, stats, bloom filter.

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::{DomainReputation, ThreatFeed, ThreatFeedType};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Reputation endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DomainQuery {
    domain: String,
}

async fn get_reputation(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DomainQuery>,
) -> Result<Json<DomainReputation>, StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let rep_key = keys::threat_reputation(&q.domain);

    let domain: Option<String> = conn.hget(&rep_key, "domain").await.unwrap_or(None);
    if domain.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let score: f32 = conn.hget(&rep_key, "score").await.unwrap_or(0.0);
    let first_seen: String = conn.hget(&rep_key, "first_seen").await.unwrap_or_default();
    let last_seen: String = conn.hget(&rep_key, "last_seen").await.unwrap_or_default();
    let request_count: u64 = conn.hget(&rep_key, "request_count").await.unwrap_or(0);
    let unique_users: u32 = conn.hget(&rep_key, "unique_users").await.unwrap_or(0);
    let threat_signals_total: u32 = conn.hget(&rep_key, "threat_signals_total").await.unwrap_or(0);
    let last_threat_score: f32 = conn.hget(&rep_key, "last_threat_score").await.unwrap_or(0.0);

    let first_seen = chrono::DateTime::parse_from_rfc3339(&first_seen)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let last_seen = chrono::DateTime::parse_from_rfc3339(&last_seen)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Ok(Json(DomainReputation {
        domain: q.domain,
        score,
        first_seen,
        last_seen,
        request_count,
        unique_users,
        threat_signals_total,
        last_threat_score,
    }))
}

#[derive(Deserialize)]
struct TopQuery {
    #[serde(default = "default_top_n")]
    n: usize,
    #[serde(default)]
    sort: TopSort,
}

fn default_top_n() -> usize { 20 }

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum TopSort {
    #[default]
    Suspicious,
    Trusted,
}

async fn get_reputation_top(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TopQuery>,
) -> Result<Json<Vec<DomainReputation>>, StatusCode> {
    let n = q.n.min(1000); // Cap to prevent abuse
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let domains: Vec<String> = conn
        .smembers(keys::THREAT_REPUTATION_INDEX)
        .await
        .unwrap_or_default();

    if domains.is_empty() {
        return Ok(Json(vec![]));
    }

    // Pipelined fetch: one HGETALL per domain in a single round-trip
    let mut pipe = redis::pipe();
    for domain in &domains {
        pipe.cmd("HGETALL").arg(keys::threat_reputation(domain));
    }
    let all_fields: Vec<Vec<(String, String)>> = pipe
        .query_async(&mut *conn)
        .await
        .unwrap_or_default();

    let mut results = Vec::new();
    for (domain, fields) in domains.iter().zip(all_fields.iter()) {
        let map: std::collections::HashMap<&str, &str> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let score: f32 = map.get("score").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let first_seen = map.get("first_seen")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        let last_seen = map.get("last_seen")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        let request_count: u64 = map.get("request_count").and_then(|s| s.parse().ok()).unwrap_or(0);
        let unique_users: u32 = map.get("unique_users").and_then(|s| s.parse().ok()).unwrap_or(0);
        let threat_signals_total: u32 = map.get("threat_signals_total").and_then(|s| s.parse().ok()).unwrap_or(0);
        let last_threat_score: f32 = map.get("last_threat_score").and_then(|s| s.parse().ok()).unwrap_or(0.0);

        results.push(DomainReputation {
            domain: domain.clone(),
            score, first_seen, last_seen, request_count,
            unique_users, threat_signals_total, last_threat_score,
        });
    }

    match q.sort {
        TopSort::Suspicious => results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)),
        TopSort::Trusted => results.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal)),
    }

    results.truncate(n);
    Ok(Json(results))
}

async fn delete_reputation(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DomainQuery>,
) -> StatusCode {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let rep_key = keys::threat_reputation(&q.domain);
    let _: Result<(), _> = conn.del(&rep_key).await;
    let _: Result<(), _> = conn.del(format!("{rep_key}:users")).await;
    let _: Result<(), _> = conn.srem(keys::THREAT_REPUTATION_INDEX, &q.domain).await;

    tracing::info!(domain = %q.domain, "Threat reputation deleted via API");

    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// Feed endpoints
// ---------------------------------------------------------------------------

async fn list_feeds(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ThreatFeed>>, StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let feed_ids: Vec<String> = conn.smembers(keys::THREAT_FEEDS).await.unwrap_or_default();
    let mut feeds = Vec::new();

    for id in feed_ids {
        let key = keys::threat_feed(&id);
        let json: Option<String> = conn.get(&key).await.unwrap_or(None);
        if let Some(json) = json {
            if let Ok(feed) = serde_json::from_str::<ThreatFeed>(&json) {
                feeds.push(feed);
            }
        }
    }

    Ok(Json(feeds))
}

#[derive(Deserialize)]
struct CreateFeed {
    name: String,
    url: String,
    feed_type: ThreatFeedType,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_refresh")]
    refresh_interval_secs: u64,
}

fn default_true() -> bool { true }
fn default_refresh() -> u64 { 3600 }

async fn create_feed(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateFeed>,
) -> Result<(StatusCode, Json<ThreatFeed>), StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let feed = ThreatFeed {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name,
        url: body.url,
        feed_type: body.feed_type,
        enabled: body.enabled,
        refresh_interval_secs: body.refresh_interval_secs,
        last_updated: None,
        entry_count: 0,
    };

    let json = serde_json::to_string(&feed).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key = keys::threat_feed(&feed.id);
    let _: Result<(), _> = conn.set(&key, &json).await;
    let _: Result<(), _> = conn.sadd(keys::THREAT_FEEDS, &feed.id).await;

    // Publish reload
    super::publish_reload(&state.pool, "threat_feeds").await;

    Ok((StatusCode::CREATED, Json(feed)))
}

async fn update_feed(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<CreateFeed>,
) -> Result<Json<ThreatFeed>, StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let key = keys::threat_feed(&id);
    let existing: Option<String> = conn.get(&key).await.unwrap_or(None);
    let existing = existing.ok_or(StatusCode::NOT_FOUND)?;
    let existing: ThreatFeed = serde_json::from_str(&existing).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let feed = ThreatFeed {
        id: id.clone(),
        name: body.name,
        url: body.url,
        feed_type: body.feed_type,
        enabled: body.enabled,
        refresh_interval_secs: body.refresh_interval_secs,
        last_updated: existing.last_updated,
        entry_count: existing.entry_count,
    };

    let json = serde_json::to_string(&feed).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _: Result<(), _> = conn.set(&key, &json).await;

    super::publish_reload(&state.pool, "threat_feeds").await;

    Ok(Json(feed))
}

async fn delete_feed(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let key = keys::threat_feed(&id);
    let _: Result<(), _> = conn.del(&key).await;
    let _: Result<(), _> = conn.srem(keys::THREAT_FEEDS, &id).await;

    super::publish_reload(&state.pool, "threat_feeds").await;

    StatusCode::NO_CONTENT
}

async fn refresh_feeds(
    State(state): State<Arc<AppState>>,
) -> StatusCode {
    // Publish a reload notification to trigger feed refresh on proxy nodes
    super::publish_reload(&state.pool, "threat_feeds_refresh").await;
    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------
// Stats endpoints
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ThreatStats {
    threat_blocks: u64,
    tier0_evals: u64,
    tier1_escalations: u64,
    tier2_escalations: u64,
    tier3_escalations: u64,
}

async fn get_threat_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatStats>, StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(ThreatStats {
        threat_blocks: conn.get(keys::STATS_THREAT_BLOCKS).await.unwrap_or(0),
        tier0_evals: conn.get(keys::STATS_THREAT_T0).await.unwrap_or(0),
        tier1_escalations: conn.get(keys::STATS_THREAT_T1).await.unwrap_or(0),
        tier2_escalations: conn.get(keys::STATS_THREAT_T2).await.unwrap_or(0),
        tier3_escalations: conn.get(keys::STATS_THREAT_T3).await.unwrap_or(0),
    }))
}

// ---------------------------------------------------------------------------
// Bloom filter endpoints
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BloomStats {
    entry_count: u64,
    updated_at: Option<String>,
}

async fn get_bloom_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BloomStats>, StatusCode> {
    let mut conn = state.pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let entry_count: u64 = conn
        .hget(keys::THREAT_BLOOM_META, "entry_count")
        .await
        .unwrap_or(0);
    let updated_at: Option<String> = conn
        .hget(keys::THREAT_BLOOM_META, "updated_at")
        .await
        .unwrap_or(None);

    Ok(Json(BloomStats {
        entry_count,
        updated_at,
    }))
}

#[derive(Deserialize)]
struct BloomTestQuery {
    domain: String,
}

#[derive(Serialize)]
struct BloomTestResult {
    domain: String,
    in_bloom: bool,
}

async fn test_bloom(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<BloomTestQuery>,
) -> Json<BloomTestResult> {
    // Note: The bloom filter lives in the proxy process, not the API.
    // This endpoint would need to either share the bloom via Redis
    // or make an RPC to the proxy. For now, we return a placeholder.
    // In practice, the bloom test is best done on the proxy side.
    Json(BloomTestResult {
        domain: body.domain,
        in_bloom: false, // TODO: implement cross-process bloom test via Redis
    })
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Reputation
        .route("/threat/reputation", get(get_reputation))
        .route("/threat/reputation/top", get(get_reputation_top))
        .route("/threat/reputation", delete(delete_reputation))
        // Feeds
        .route("/threat/feeds", get(list_feeds))
        .route("/threat/feeds", post(create_feed))
        .route("/threat/feeds/{id}", put(update_feed))
        .route("/threat/feeds/{id}", delete(delete_feed))
        .route("/threat/feeds/refresh", post(refresh_feeds))
        // Stats
        .route("/threat/stats", get(get_threat_stats))
        // Bloom
        .route("/threat/bloom/stats", get(get_bloom_stats))
        .route("/threat/bloom/test", post(test_bloom))
}
