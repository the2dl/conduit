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

    let raw: std::collections::HashMap<String, String> =
        conn.hgetall(keys::DLP_RULES).await.unwrap_or_default();

    let hits_map: std::collections::HashMap<String, u64> =
        conn.hgetall(keys::STATS_DLP_HITS).await.unwrap_or_default();

    let mut rules: Vec<DlpRule> = raw
        .values()
        .filter_map(|s| serde_json::from_str::<DlpRule>(s).ok())
        .collect();

    for r in &mut rules {
        if let Some(&h) = hits_map.get(&r.id).or_else(|| hits_map.get(&r.name)) {
            r.hits = h;
        }
    }

    rules.sort_by(|a, b| a.name.cmp(&b.name));

    (
        StatusCode::OK,
        Json(serde_json::to_value(rules).unwrap_or_default()),
    )
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
    #[serde(default)]
    allowed_domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CreateRule>,
) -> impl IntoResponse {
    if let Err(msg) = validate_regex(&input.regex) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        );
    }

    let rule = DlpRule {
        id: uuid::Uuid::new_v4().to_string(),
        name: input.name,
        regex: input.regex,
        action: input.action,
        enabled: input.enabled,
        builtin: false,
        hits: 0,
        allowed_domains: input.allowed_domains,
    };

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "store unavailable" })),
        );
    };

    let json = serde_json::to_string(&rule).unwrap();
    let _: () = conn
        .hset(keys::DLP_RULES, &rule.id, &json)
        .await
        .unwrap_or(());

    super::publish_reload(&state.pool, "dlp").await;
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(&rule).unwrap_or_default()),
    )
}

async fn update_rule(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<DlpRule>,
) -> impl IntoResponse {
    if let Err(msg) = validate_regex(&rule.regex) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        );
    }

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "store unavailable" })),
        );
    };

    // Verify the rule exists
    let exists: bool = conn
        .hexists(keys::DLP_RULES, &rule.id)
        .await
        .unwrap_or(false);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "rule not found" })),
        );
    }

    let json = serde_json::to_string(&rule).unwrap();
    let _: () = conn
        .hset(keys::DLP_RULES, &rule.id, &json)
        .await
        .unwrap_or(());

    super::publish_reload(&state.pool, "dlp").await;
    (
        StatusCode::OK,
        Json(serde_json::to_value(&rule).unwrap_or_default()),
    )
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
    if let Ok(Some(json)) = conn
        .hget::<_, _, Option<String>>(keys::DLP_RULES, &delete.id)
        .await
    {
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

/// Seed built-in DLP rules if they don't already exist or backfill domain exemptions.
pub async fn seed_builtins(pool: &Arc<deadpool_redis::Pool>) {
    let builtins = [
        DlpRule {
            id: "builtin-ssn".into(),
            name: "SSN".into(),
            regex: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-credit-card".into(),
            name: "Credit Card".into(),
            regex: r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-aws-key".into(),
            name: "AWS Access Key".into(),
            regex: r"\bAKIA[0-9A-Z]{16}\b".into(),
            action: DlpRuleAction::Log,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-npm-token".into(),
            name: "NPM Access Token".into(),
            regex: r"(?:\bnpm_[A-Za-z0-9]{32,40}\b|(?://registry\.npmjs\.org/:)?_authToken=[A-Za-z0-9_-]{32,})".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "registry.npmjs.org".into(),
                "*.npmjs.org".into(),
                "registry.yarnpkg.com".into(),
            ],
        },
        DlpRule {
            id: "builtin-pypi-token".into(),
            name: "PyPI API Token".into(),
            regex: r"\bpypi-[A-Za-z0-9_-]{50,}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "upload.pypi.org".into(),
                "pypi.org".into(),
                "*.pypi.org".into(),
            ],
        },
        DlpRule {
            id: "builtin-rubygems-key".into(),
            name: "RubyGems API Key".into(),
            regex: r"\brubygems_[a-f0-9]{48}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "rubygems.org".into(),
                "*.rubygems.org".into(),
            ],
        },
        DlpRule {
            id: "builtin-crates-token".into(),
            name: "Cargo / Crates.io Token".into(),
            regex: r"\bcio[a-zA-Z0-9]{32}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "crates.io".into(),
                "*.crates.io".into(),
            ],
        },
        DlpRule {
            id: "builtin-github-pat".into(),
            name: "GitHub Personal Access Token".into(),
            regex: r"\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "api.github.com".into(),
                "github.com".into(),
                "*.github.com".into(),
            ],
        },
        DlpRule {
            id: "builtin-github-oauth".into(),
            name: "GitHub OAuth / App Token".into(),
            regex: r"\b(?:gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "api.github.com".into(),
                "github.com".into(),
                "*.github.com".into(),
            ],
        },
        DlpRule {
            id: "builtin-gitlab-pat".into(),
            name: "GitLab Access Token".into(),
            regex: r"\bglpat-[0-9a-zA-Z_-]{20,22}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "gitlab.com".into(),
                "*.gitlab.com".into(),
            ],
        },
        DlpRule {
            id: "builtin-private-key".into(),
            name: "Private Key (PEM/SSH/PGP)".into(),
            regex: r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-aws-secret".into(),
            name: "AWS Secret Access Key".into(),
            regex: r#"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?"#.into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-gcp-api-key".into(),
            name: "Google Cloud API Key".into(),
            regex: r"\bAIza[0-9A-Za-z\-_]{35}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-gcp-sa-key".into(),
            name: "Google Cloud Service Account Key".into(),
            regex: r#"(?i)"type":\s*"service_account"|"private_key_id":\s*"[0-9a-f]{40}""#.into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-azure-connection-string".into(),
            name: "Azure Connection String".into(),
            regex: r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-vault-token".into(),
            name: "HashiCorp Vault Token".into(),
            regex: r"\b[sb]\.[a-zA-Z0-9]{24,}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-db-credentials".into(),
            name: "Database URI with Password".into(),
            regex: r"(?i)(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:\s/]*:[^@\s/]+@[^\s/]+".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "*.anthropic.com".into(),
                "*.claude.ai".into(),
                "*.openai.com".into(),
                "*.chatgpt.com".into(),
                "*.oaistatic.com".into(),
                "*.oaiusercontent.com".into(),
                "*.googleapis.com".into(),
            ],
        },
        DlpRule {
            id: "builtin-env-secret-export".into(),
            name: "Password / Secret Env Export".into(),
            regex: r#"(?i)\b(?:export\s+(?:[A-Z0-9_]*(?:PASSWORD|PASSWD)[A-Z0-9_]*|SECRET_KEY|JWT_SECRET|AUTH_TOKEN)|(?:[A-Z0-9]+_(?:PASSWORD|PASSWD)|SECRET_KEY|JWT_SECRET|AUTH_TOKEN))\s*=\s*["']?[^"'\s&]{8,}["']?"#.into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![
                "*.pkg.dev".into(),
                "*.docker.pkg.dev".into(),
                "*.gcr.io".into(),
                "docker.io".into(),
                "*.docker.io".into(),
                "ghcr.io".into(),
                "*.ecr.*.amazonaws.com".into(),
                "quay.io".into(),
                "*.quay.io".into(),
            ],
        },
        DlpRule {
            id: "builtin-openai-key".into(),
            name: "OpenAI API Key".into(),
            regex: r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-anthropic-key".into(),
            name: "Anthropic API Key".into(),
            regex: r"\bsk-ant-[a-zA-Z0-9_-]{32,}\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-slack-token".into(),
            name: "Slack Token".into(),
            regex: r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
        DlpRule {
            id: "builtin-discord-webhook".into(),
            name: "Discord Webhook Exfiltration".into(),
            regex: r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+".into(),
            action: DlpRuleAction::Block,
            enabled: true,
            builtin: true,
            hits: 0,
            allowed_domains: vec![],
        },
    ];

    let Ok(mut conn) = pool.get().await else {
        return;
    };

    let mut any_changed = false;
    for rule in &builtins {
        let existing_json: Option<String> =
            conn.hget(keys::DLP_RULES, &rule.id).await.unwrap_or(None);
        match existing_json {
            None => {
                let json = serde_json::to_string(rule).unwrap();
                let _: () = conn
                    .hset(keys::DLP_RULES, &rule.id, &json)
                    .await
                    .unwrap_or(());
                any_changed = true;
            }
            Some(curr) => {
                // If the existing built-in rule lacks allowed_domains or has an outdated regex, update it
                if let Ok(mut existing_rule) = serde_json::from_str::<DlpRule>(&curr) {
                    if existing_rule.builtin {
                        let mut rule_changed = false;
                        if existing_rule.regex != rule.regex {
                            existing_rule.regex = rule.regex.clone();
                            rule_changed = true;
                        }
                        if existing_rule.allowed_domains.is_empty() && !rule.allowed_domains.is_empty() {
                            existing_rule.allowed_domains = rule.allowed_domains.clone();
                            rule_changed = true;
                        }
                        if rule_changed {
                            let json = serde_json::to_string(&existing_rule).unwrap();
                            let _: () = conn
                                .hset(keys::DLP_RULES, &rule.id, &json)
                                .await
                                .unwrap_or(());
                            any_changed = true;
                        }
                    }
                }
            }
        }
    }

    if any_changed {
        super::publish_reload(pool, "dlp").await;
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
