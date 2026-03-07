use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::DlpRule;
use redis::AsyncCommands;
use serde::Deserialize;
use std::sync::Arc;

/// Validate that a regex compiles within the size limit used by the proxy.
fn validate_regex(pattern: &str) -> Result<(), String> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1_000_000)
        .build()
        .map(|_| ())
        .map_err(|e| format!("Invalid regex: {e}"))
}

async fn list_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!([])));
    };

    let raw: std::collections::HashMap<String, String> = conn
        .hgetall(keys::DLP_RULES)
        .await
        .unwrap_or_default();

    let mut rules: Vec<DlpRule> = raw
        .values()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();

    rules.sort_by(|a, b| a.name.cmp(&b.name));

    (StatusCode::OK, Json(serde_json::to_value(rules).unwrap_or_default()))
}

use conduit_common::types::DlpRuleAction;

#[derive(Deserialize)]
struct CreateRule {
    name: String,
    regex: String,
    #[serde(default)]
    action: DlpRuleAction,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool { true }

async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CreateRule>,
) -> impl IntoResponse {
    if let Err(msg) = validate_regex(&input.regex) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })));
    }

    let rule = DlpRule {
        id: uuid::Uuid::new_v4().to_string(),
        name: input.name,
        regex: input.regex,
        action: input.action,
        enabled: input.enabled,
        builtin: false,
    };

    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "store unavailable" })));
    };

    let json = serde_json::to_string(&rule).unwrap();
    let _: () = conn.hset(keys::DLP_RULES, &rule.id, &json).await.unwrap_or(());

    super::publish_reload(&state.pool, "dlp").await;
    (StatusCode::CREATED, Json(serde_json::to_value(&rule).unwrap_or_default()))
}

async fn update_rule(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<DlpRule>,
) -> impl IntoResponse {
    if let Err(msg) = validate_regex(&rule.regex) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })));
    }

    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "store unavailable" })));
    };

    // Verify the rule exists
    let exists: bool = conn.hexists(keys::DLP_RULES, &rule.id).await.unwrap_or(false);
    if !exists {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "rule not found" })));
    }

    let json = serde_json::to_string(&rule).unwrap();
    let _: () = conn.hset(keys::DLP_RULES, &rule.id, &json).await.unwrap_or(());

    super::publish_reload(&state.pool, "dlp").await;
    (StatusCode::OK, Json(serde_json::to_value(&rule).unwrap_or_default()))
}

#[derive(Deserialize)]
struct DeleteRule {
    id: String,
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Json(delete): Json<DeleteRule>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    // Don't allow deleting built-in rules
    if let Ok(Some(json)) = conn.hget::<_, _, Option<String>>(keys::DLP_RULES, &delete.id).await {
        if let Ok(rule) = serde_json::from_str::<DlpRule>(&json) {
            if rule.builtin {
                return StatusCode::FORBIDDEN;
            }
        }
    }

    let _: () = conn.hdel(keys::DLP_RULES, &delete.id).await.unwrap_or(());

    super::publish_reload(&state.pool, "dlp").await;
    StatusCode::NO_CONTENT
}

/// Seed built-in DLP rules if they don't already exist.
pub async fn seed_builtins(pool: &Arc<deadpool_redis::Pool>) {
    let builtins = [
        DlpRule {
            id: "builtin-ssn".into(),
            name: "SSN".into(),
            regex: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
        },
        DlpRule {
            id: "builtin-credit-card".into(),
            name: "Credit Card".into(),
            regex: r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
        },
        DlpRule {
            id: "builtin-aws-key".into(),
            name: "AWS Access Key".into(),
            regex: r"\bAKIA[0-9A-Z]{16}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
        },
    ];

    let Ok(mut conn) = pool.get().await else { return };

    for rule in &builtins {
        let exists: bool = conn
            .hexists(keys::DLP_RULES, &rule.id)
            .await
            .unwrap_or(false);
        if !exists {
            let json = serde_json::to_string(rule).unwrap();
            let _: () = conn.hset(keys::DLP_RULES, &rule.id, &json).await.unwrap_or(());
        }
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/dlp/rules",
        get(list_rules)
            .post(create_rule)
            .put(update_rule)
            .delete(delete_rule),
    )
}
