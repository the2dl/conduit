use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
pub struct MuteRequest {
    pub domain: String,
}

async fn list_mutes(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!([])));
    };

    let mut set: HashSet<String> = HashSet::new();

    // Static config defaults
    if let Some(ref notif) = state.config.notifications {
        for d in &notif.muted_domains {
            set.insert(d.clone());
        }
    } else {
        set.insert("browser-intake-us5-datadoghq.com".to_string());
        set.insert("*.datadoghq.com".to_string());
    }

    // Dynamic Redis set
    let dynamic: Vec<String> = conn
        .smembers(keys::MUTED_NOTIFICATIONS)
        .await
        .unwrap_or_default();
    for d in dynamic {
        set.insert(d);
    }

    let mut list: Vec<String> = set.into_iter().collect();
    list.sort();

    (StatusCode::OK, Json(serde_json::json!(list)))
}

async fn mute_domain(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MuteRequest>,
) -> impl IntoResponse {
    let clean = req.domain.trim().to_ascii_lowercase();
    if clean.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "domain cannot be empty"})),
        );
    }

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "redis unavailable"})),
        );
    };

    let _: Result<(), _> = conn.sadd(keys::MUTED_NOTIFICATIONS, &clean).await;
    super::publish_reload(&state.pool, "notifications").await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "muted",
            "domain": clean
        })),
    )
}

async fn unmute_domain(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MuteRequest>,
) -> impl IntoResponse {
    let clean = req.domain.trim().to_ascii_lowercase();
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "redis unavailable"})),
        );
    };

    let _: Result<(), _> = conn.srem(keys::MUTED_NOTIFICATIONS, &clean).await;
    super::publish_reload(&state.pool, "notifications").await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "unmuted",
            "domain": clean
        })),
    )
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/notifications/mutes", get(list_mutes))
        .route(
            "/notifications/mute",
            get(list_mutes).post(mute_domain).delete(unmute_domain),
        )
}
