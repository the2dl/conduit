//! Tier 3: LLM-based threat verdict for ambiguous cases.
//!
//! Sends a structured prompt to an LLM (Claude Haiku via API, or local llama.cpp)
//! with all accumulated signals. The LLM returns BLOCK or ALLOW with confidence.
//!
//! Two modes:
//! - "block_and_wait": Hold response up to timeout, use verdict
//! - "allow_and_flag": Let request through, update reputation from async LLM result

use conduit_common::config::ThreatConfig;
use conduit_common::types::{ThreatSignal, ThreatTier};
use deadpool_redis::Pool;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// A request to the LLM worker for threat assessment.
pub struct LlmRequest {
    pub host: String,
    pub signals: Vec<ThreatSignal>,
    pub tier0_score: f32,
    pub tier1_score: Option<f32>,
    pub tier2_score: Option<f32>,
    pub reputation_score: f32,
    /// For block_and_wait mode: sends the verdict back to the request path.
    pub reply_tx: Option<oneshot::Sender<LlmVerdict>>,
}

/// The LLM's verdict.
#[derive(Debug, Clone)]
pub struct LlmVerdict {
    pub action: LlmAction,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmAction {
    Block,
    Allow,
}

/// Create the LLM worker channel. Returns the sender for submitting requests.
pub fn create_channel() -> (mpsc::Sender<LlmRequest>, mpsc::Receiver<LlmRequest>) {
    mpsc::channel(64)
}

/// Spawn the background LLM worker that processes verdict requests.
pub fn spawn_llm_worker(
    config: Arc<ThreatConfig>,
    pool: Arc<Pool>,
    mut rx: mpsc::Receiver<LlmRequest>,
) {
    tokio::spawn(async move {
        debug!("LLM threat verdict worker started");

        // Reuse a single HTTP client for connection pooling
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.tier3_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        while let Some(req) = rx.recv().await {
            let verdict = evaluate_llm(&config, &http_client, &req).await;

            // Update reputation from LLM verdict
            if let Ok(mut conn) = pool.get().await {
                let rep_key =
                    conduit_common::redis::keys::threat_reputation(&req.host);
                let rep_adjustment = match verdict.action {
                    LlmAction::Block => (verdict.confidence * 0.3).min(0.3),
                    LlmAction::Allow => -(verdict.confidence * 0.1).min(0.1),
                };
                let current: f32 = redis::AsyncCommands::hget(&mut *conn, &rep_key, "score")
                    .await
                    .unwrap_or(0.5);
                let new_score = (current + rep_adjustment).clamp(0.0, 1.0);
                let _: Result<(), _> =
                    redis::AsyncCommands::hset(&mut *conn, &rep_key, "score", new_score).await;
            }

            // Send reply if block_and_wait mode
            if let Some(reply_tx) = req.reply_tx {
                let _ = reply_tx.send(verdict);
            }
        }

        debug!("LLM threat verdict worker shut down");
    });
}

/// Build the prompt and call the LLM API.
async fn evaluate_llm(config: &ThreatConfig, client: &reqwest::Client, req: &LlmRequest) -> LlmVerdict {
    let signal_list: String = req
        .signals
        .iter()
        .map(|s| format!("  - {} (score: {:.2}, tier: {:?})", s.name, s.score, s.tier))
        .collect::<Vec<_>>()
        .join("\n");

    let prompt = format!(
        "You are a cybersecurity analyst. Assess threat level based on these signals:\n\
         Domain: {host}\n\
         Tier 0 score: {t0:.3}\n\
         Tier 1 score: {t1}\n\
         Tier 2 score: {t2}\n\
         Reputation: {rep:.3}\n\
         Signals:\n{signals}\n\n\
         Reply with ONLY: BLOCK <confidence 0-1> or ALLOW <confidence 0-1>",
        host = req.host,
        t0 = req.tier0_score,
        t1 = req
            .tier1_score
            .map(|s| format!("{s:.3}"))
            .unwrap_or_else(|| "N/A".into()),
        t2 = req
            .tier2_score
            .map(|s| format!("{s:.3}"))
            .unwrap_or_else(|| "N/A".into()),
        rep = req.reputation_score,
        signals = signal_list,
    );

    let api_url = config
        .llm_api_url
        .as_deref()
        .unwrap_or("http://localhost:8080/v1/chat/completions");

    let mut request_builder = client
        .post(api_url)
        .header("Content-Type", "application/json");

    if let Some(ref api_key) = config.llm_api_key {
        request_builder = request_builder.header("Authorization", format!("Bearer {api_key}"));
    }

    let body = serde_json::json!({
        "model": config.llm_provider.as_deref().unwrap_or("local"),
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 20,
        "temperature": 0.0
    });

    match request_builder.json(&body).send().await {
        Ok(resp) => {
            if let Ok(text) = resp.text().await {
                parse_llm_response(&text)
            } else {
                warn!(host = %req.host, "Failed to read LLM response body");
                default_allow()
            }
        }
        Err(_) => {
            // Don't log the raw error — it may contain URL with credentials
            warn!(host = %req.host, "LLM API call failed");
            default_allow()
        }
    }
}

/// Parse the LLM's response text (handles both raw text and JSON chat completion format).
fn parse_llm_response(text: &str) -> LlmVerdict {
    // Try to extract from JSON chat completion format
    let content = if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or(text)
            .to_string()
    } else {
        text.to_string()
    };

    let content = content.trim().to_uppercase();

    if content.starts_with("BLOCK") {
        let confidence = content
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.7);
        LlmVerdict {
            action: LlmAction::Block,
            confidence: confidence.clamp(0.0, 1.0),
        }
    } else if content.starts_with("ALLOW") {
        let confidence = content
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.7);
        LlmVerdict {
            action: LlmAction::Allow,
            confidence: confidence.clamp(0.0, 1.0),
        }
    } else {
        warn!(response = %content, "Unexpected LLM response format, defaulting to ALLOW");
        default_allow()
    }
}

fn default_allow() -> LlmVerdict {
    LlmVerdict {
        action: LlmAction::Allow,
        confidence: 0.5,
    }
}

/// Convert LLM verdict into a threat signal for inclusion in a ThreatVerdict.
#[allow(dead_code)]
pub fn verdict_to_signal(verdict: &LlmVerdict) -> ThreatSignal {
    ThreatSignal {
        name: format!("llm_{:?}", verdict.action).to_lowercase(),
        score: match verdict.action {
            LlmAction::Block => verdict.confidence,
            LlmAction::Allow => 1.0 - verdict.confidence,
        },
        tier: ThreatTier::Tier3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_response() {
        let v = parse_llm_response("BLOCK 0.85");
        assert_eq!(v.action, LlmAction::Block);
        assert!((v.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn parse_allow_response() {
        let v = parse_llm_response("ALLOW 0.95");
        assert_eq!(v.action, LlmAction::Allow);
        assert!((v.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn parse_json_chat_completion() {
        let json = r#"{"choices":[{"message":{"content":"BLOCK 0.9"}}]}"#;
        let v = parse_llm_response(json);
        assert_eq!(v.action, LlmAction::Block);
    }

    #[test]
    fn parse_unknown_defaults_allow() {
        let v = parse_llm_response("I think this is suspicious");
        assert_eq!(v.action, LlmAction::Allow);
    }
}
