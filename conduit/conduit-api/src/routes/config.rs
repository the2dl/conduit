use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;

/// Allowed config keys that can be set via the API.
const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "auth_required",
    "fail_closed",
    "tls_intercept",
    "log_retention",
    "syslog_target",
    "block_page_html",
];

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({})),
        );
    };

    let config: HashMap<String, String> = conn.hgetall(keys::CONFIG).await.unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!(config)))
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(updates): Json<HashMap<String, String>>,
) -> impl IntoResponse {
    // Reject unknown config keys
    for k in updates.keys() {
        if !ALLOWED_CONFIG_KEYS.contains(&k.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("unknown config key: {k}")})),
            )
                .into_response();
        }
    }

    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    for (k, v) in &updates {
        let _: () = conn.hset(keys::CONFIG, k, v).await.unwrap_or(());
    }

    super::publish_reload(&state.pool, "config").await;
    StatusCode::OK.into_response()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/config", get(get_config).put(update_config))
}
