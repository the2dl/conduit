use arc_swap::ArcSwap;
use conduit_common::config::DlpConfig;
use conduit_common::redis::keys;
use conduit_common::types::{DlpRule, DlpRuleAction};
use deadpool_redis::Pool;
use redis::AsyncCommands;
use regex::Regex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::{info, warn};

/// A compiled DLP pattern.
struct CompiledPattern {
    name: String,
    regex: Regex,
    action: DlpAction,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DlpAction {
    Log,
    Block,
    /// Placeholder for future redaction support. Currently treated as Log.
    Redact,
}

impl From<DlpRuleAction> for DlpAction {
    fn from(a: DlpRuleAction) -> Self {
        match a {
            DlpRuleAction::Log => DlpAction::Log,
            DlpRuleAction::Block => DlpAction::Block,
            DlpRuleAction::Redact => DlpAction::Redact,
        }
    }
}

/// A single DLP match found during scanning.
#[derive(Debug, Clone)]
pub struct DlpMatch {
    #[allow(dead_code)]
    pub pattern_name: String,
    pub action: DlpAction,
}

/// Inner engine holding compiled patterns. Swapped atomically via ArcSwap.
struct DlpEngineInner {
    patterns: Vec<CompiledPattern>,
    max_scan_size: usize,
}

/// DLP engine with hot-reloadable rules from Dragonfly.
pub struct DlpEngine {
    inner: ArcSwap<DlpEngineInner>,
    pub max_scan_size: usize,
    #[allow(dead_code)]
    pub default_action: DlpAction,
}

/// Signal that DLP rules should be reloaded from Dragonfly.
static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);

/// Global reference to the DLP engine + pool for background reloads.
static DLP_RELOAD_CTX: OnceLock<(Arc<DlpEngine>, Arc<Pool>)> = OnceLock::new();

/// Register the DLP engine and pool for background reload (called once at startup).
pub fn register_for_reload(engine: Arc<DlpEngine>, pool: Arc<Pool>) {
    let _ = DLP_RELOAD_CTX.set((engine, pool));
}

/// Called by the pub/sub handler when a config reload signal arrives.
/// Spawns a background task to reload rules from Dragonfly.
pub fn invalidate_cache() {
    if FORCE_RELOAD.swap(true, Ordering::AcqRel) {
        return; // Already pending
    }
    if let Some((engine, pool)) = DLP_RELOAD_CTX.get() {
        let engine = engine.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            engine.reload_from_dragonfly(&pool).await;
            FORCE_RELOAD.store(false, Ordering::Release);
        });
    }
}

impl DlpEngine {
    /// Create a new DLP engine from TOML config (initial startup, before Dragonfly rules load).
    pub fn new(config: &DlpConfig) -> Self {
        let default_action = parse_action(&config.action);
        let patterns = compile_from_config(config, default_action);

        info!(count = patterns.len(), "DLP engine initialized from config");

        let inner = DlpEngineInner {
            patterns,
            max_scan_size: config.max_scan_size,
        };

        DlpEngine {
            inner: ArcSwap::new(Arc::new(inner)),
            max_scan_size: config.max_scan_size,
            default_action,
        }
    }

    /// Load/reload rules from Dragonfly and replace the current engine state.
    pub async fn reload_from_dragonfly(&self, pool: &Pool) {
        match load_rules_from_dragonfly(pool).await {
            Ok(rules) if !rules.is_empty() => {
                let patterns = compile_from_rules(&rules);
                let count = patterns.len();
                let new_inner = DlpEngineInner {
                    patterns,
                    max_scan_size: self.max_scan_size,
                };
                self.inner.store(Arc::new(new_inner));
                info!(count, "DLP engine loaded rules from Dragonfly");
            }
            Ok(_) => {
                info!("No DLP rules in Dragonfly, keeping config-based rules");
            }
            Err(e) => {
                warn!("Failed to load DLP rules from Dragonfly, using config: {e}");
            }
        }
    }

    /// Scan a body for DLP violations. Returns all matches found.
    /// Only scans up to `max_scan_size` bytes to bound CPU cost.
    pub fn scan(&self, body: &[u8]) -> Vec<DlpMatch> {
        let inner = self.inner.load();
        let body = &body[..body.len().min(inner.max_scan_size)];
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return vec![], // Binary content, skip
        };

        let mut matches = Vec::new();
        for pattern in &inner.patterns {
            if pattern.regex.is_match(text) {
                matches.push(DlpMatch {
                    pattern_name: pattern.name.clone(),
                    action: pattern.action,
                });
            }
        }
        matches
    }

    /// Returns true if any match has action=Block.
    pub fn should_block(matches: &[DlpMatch]) -> bool {
        matches.iter().any(|m| m.action == DlpAction::Block)
    }
}

/// Compile patterns from TOML config (used at startup as fallback).
fn compile_from_config(config: &DlpConfig, default_action: DlpAction) -> Vec<CompiledPattern> {
    let mut patterns = Vec::new();

    // Built-in patterns
    let builtins = [
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("credit_card", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        ("aws_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ];

    for (name, pattern) in &builtins {
        match regex::RegexBuilder::new(pattern)
            .size_limit(1_000_000)
            .build()
        {
            Ok(re) => patterns.push(CompiledPattern {
                name: name.to_string(),
                regex: re,
                action: default_action,
            }),
            Err(e) => warn!(name, "Failed to compile built-in DLP pattern: {e}"),
        }
    }

    // Custom patterns from TOML
    for custom in &config.custom_patterns {
        match regex::RegexBuilder::new(&custom.regex)
            .size_limit(1_000_000)
            .build()
        {
            Ok(re) => {
                let action = parse_action(&custom.action);
                patterns.push(CompiledPattern {
                    name: custom.name.clone(),
                    regex: re,
                    action,
                });
            }
            Err(e) => warn!(name = %custom.name, "Failed to compile custom DLP pattern: {e}"),
        }
    }

    patterns
}

/// Compile patterns from Dragonfly-stored DLP rules.
fn compile_from_rules(rules: &[DlpRule]) -> Vec<CompiledPattern> {
    let mut patterns = Vec::new();

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        match regex::RegexBuilder::new(&rule.regex)
            .size_limit(1_000_000)
            .build()
        {
            Ok(re) => {
                patterns.push(CompiledPattern {
                    name: rule.name.clone(),
                    regex: re,
                    action: rule.action.into(),
                });
            }
            Err(e) => warn!(name = %rule.name, id = %rule.id, "Failed to compile DLP rule: {e}"),
        }
    }

    patterns
}

/// Load all DLP rules from Dragonfly.
async fn load_rules_from_dragonfly(pool: &Pool) -> anyhow::Result<Vec<DlpRule>> {
    let mut conn = pool.get().await?;
    let raw: std::collections::HashMap<String, String> =
        conn.hgetall(keys::DLP_RULES).await?;

    let rules: Vec<DlpRule> = raw
        .values()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();

    Ok(rules)
}

fn parse_action(s: &str) -> DlpAction {
    match s {
        "block" => DlpAction::Block,
        "redact" => DlpAction::Redact,
        _ => DlpAction::Log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_common::config::DlpPattern;

    fn test_config(action: &str) -> DlpConfig {
        DlpConfig {
            enabled: true,
            max_scan_size: 1_048_576,
            action: action.to_string(),
            custom_patterns: vec![],
        }
    }

    #[test]
    fn test_ssn_detection() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"My SSN is 123-45-6789 please wire money";
        let matches = engine.scan(body);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "ssn");
    }

    #[test]
    fn test_credit_card_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"Card: 4111 1111 1111 1111";
        let matches = engine.scan(body);
        assert!(!matches.is_empty());
        assert!(DlpEngine::should_block(&matches));
    }

    #[test]
    fn test_aws_key_detection() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"Access key: AKIAIOSFODNN7EXAMPLE";
        let matches = engine.scan(body);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_key");
    }

    #[test]
    fn test_no_match() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"This is a normal request body with no sensitive data";
        let matches = engine.scan(body);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_custom_pattern() {
        let config = DlpConfig {
            enabled: true,
            max_scan_size: 1_048_576,
            action: "log".into(),
            custom_patterns: vec![DlpPattern {
                name: "internal_id".into(),
                regex: r"INTERNAL-\d{8}".into(),
                action: "block".into(),
            }],
        };
        let engine = DlpEngine::new(&config);
        let body = b"Document ref: INTERNAL-12345678";
        let matches = engine.scan(body);
        assert!(matches.iter().any(|m| m.pattern_name == "internal_id"));
        assert!(DlpEngine::should_block(&matches));
    }

    #[test]
    fn test_binary_body_skipped() {
        let engine = DlpEngine::new(&test_config("log"));
        let body: &[u8] = &[0xFF, 0xFE, 0x00, 0x01, 0x80];
        let matches = engine.scan(body);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_compile_from_rules_skips_disabled() {
        let rules = vec![
            DlpRule {
                id: "1".into(),
                name: "active".into(),
                regex: r"\btest\b".into(),
                action: DlpRuleAction::Log,
                enabled: true,
                builtin: false,
            },
            DlpRule {
                id: "2".into(),
                name: "disabled".into(),
                regex: r"\bfoo\b".into(),
                action: DlpRuleAction::Block,
                enabled: false,
                builtin: false,
            },
        ];
        let patterns = compile_from_rules(&rules);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "active");
    }
}
