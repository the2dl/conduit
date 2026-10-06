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
    "prevention_mode",
    "dga_prevention",
    "dga_threshold",
    "threat_prevention",
    "threat_block_threshold",
    "auto_categorize_enabled",
    "auto_categorize_agent",
    "auto_categorize_ut1",
    "tld_protection_enabled",
    "tld_protection_action",
    "tld_block_bad_tlds",
    "tld_blocked_list",
    "tld_trusted_list",
    "post_protection_enabled",
    "post_protection_action",
    "post_browser_only",
    "post_block_uncategorized_bad_tld",
    "post_block_uncategorized_high_entropy",
    "post_entropy_threshold",
    "post_max_uncategorized_body_bytes",
];

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})));
    };

    let mut config: HashMap<String, String> = conn.hgetall(keys::CONFIG).await.unwrap_or_default();
    config
        .entry("tls_intercept".into())
        .or_insert_with(|| "true".into());
    config
        .entry("prevention_mode".into())
        .or_insert_with(|| "false".into());
    config
        .entry("dga_prevention".into())
        .or_insert_with(|| "false".into());
    config
        .entry("dga_threshold".into())
        .or_insert_with(|| "3.5".into());
    config
        .entry("threat_prevention".into())
        .or_insert_with(|| "false".into());
    config
        .entry("threat_block_threshold".into())
        .or_insert_with(|| "0.7".into());
    config
        .entry("auto_categorize_enabled".into())
        .or_insert_with(|| "true".into());
    config
        .entry("auto_categorize_agent".into())
        .or_insert_with(|| "agy".into());
    config
        .entry("auto_categorize_ut1".into())
        .or_insert_with(|| "true".into());
    config
        .entry("tld_protection_enabled".into())
        .or_insert_with(|| "true".into());
    config
        .entry("tld_protection_action".into())
        .or_insert_with(|| "block".into());
    config
        .entry("tld_block_bad_tlds".into())
        .or_insert_with(|| "true".into());
    config
        .entry("tld_blocked_list".into())
        .or_insert_with(|| "".into());
    config
        .entry("tld_trusted_list".into())
        .or_insert_with(|| "".into());
    config
        .entry("post_protection_enabled".into())
        .or_insert_with(|| "true".into());
    config
        .entry("post_protection_action".into())
        .or_insert_with(|| "block".into());
    config
        .entry("post_browser_only".into())
        .or_insert_with(|| "true".into());
    config
        .entry("post_block_uncategorized_bad_tld".into())
        .or_insert_with(|| "true".into());
    config
        .entry("post_block_uncategorized_high_entropy".into())
        .or_insert_with(|| "true".into());
    config
        .entry("post_entropy_threshold".into())
        .or_insert_with(|| "3.5".into());
    config
        .entry("post_max_uncategorized_body_bytes".into())
        .or_insert_with(|| "16384".into());
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
