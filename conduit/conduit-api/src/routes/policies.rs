use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::PolicyRule;
use redis::AsyncCommands;
use serde::Deserialize;
use std::sync::Arc;

async fn list_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(vec![]));
    };

    let raw: Vec<String> = conn
        .zrangebyscore(keys::POLICIES, "-inf", "+inf")
        .await
        .unwrap_or_default();

    let rules: Vec<PolicyRule> = raw
        .iter()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();

    (StatusCode::OK, Json(rules))
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<PolicyRule>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let json = match serde_json::to_string(&rule) {
        Ok(j) => j,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let _: () = conn
        .zadd(keys::POLICIES, &json, rule.priority)
        .await
        .unwrap_or(());

    super::publish_reload(&state.pool, "policies").await;
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct UpdatePolicy {
    /// The old rule to remove (matched by id) and new rule to insert.
    #[serde(flatten)]
    rule: PolicyRule,
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    Json(update): Json<UpdatePolicy>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    // Remove old version by scanning for matching id
    let existing: Vec<String> = conn
        .zrangebyscore(keys::POLICIES, "-inf", "+inf")
        .await
        .unwrap_or_default();

    for entry in &existing {
        if let Ok(rule) = serde_json::from_str::<PolicyRule>(entry) {
            if rule.id == update.rule.id {
                let _: () = conn.zrem(keys::POLICIES, entry).await.unwrap_or(());
                break;
            }
        }
    }

    // Insert updated version
    let json = match serde_json::to_string(&update.rule) {
        Ok(j) => j,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let _: () = conn
        .zadd(keys::POLICIES, &json, update.rule.priority)
        .await
        .unwrap_or(());

    super::publish_reload(&state.pool, "policies").await;
    StatusCode::OK
}

#[derive(Deserialize)]
struct DeletePolicy {
    id: String,
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Json(delete): Json<DeletePolicy>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let existing: Vec<String> = conn
        .zrangebyscore(keys::POLICIES, "-inf", "+inf")
        .await
        .unwrap_or_default();

    for entry in &existing {
        if let Ok(rule) = serde_json::from_str::<PolicyRule>(entry) {
            if rule.id == delete.id {
                let _: () = conn.zrem(keys::POLICIES, entry).await.unwrap_or(());
                break;
            }
        }
    }

    super::publish_reload(&state.pool, "policies").await;
    StatusCode::NO_CONTENT
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/policies",
        get(list_policies)
            .post(create_policy)
            .put(update_policy)
            .delete(delete_policy),
    )
}
