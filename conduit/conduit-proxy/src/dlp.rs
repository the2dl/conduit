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
    allowed_domains: Vec<String>,
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
    pub matched_snippet: Option<String>,
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
    pub allowed_domains: Vec<String>,
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
            allowed_domains: config.allowed_domains.clone(),
        }
    }

    /// Check if a domain is globally exempt from DLP inspection.
    pub fn is_domain_allowed(&self, host: &str) -> bool {
        self.allowed_domains
            .iter()
            .any(|p| conduit_common::config::matches_domain_pattern(p, host))
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

    /// Scan a body for DLP violations against optional target host. Returns all matches found.
    /// Only scans up to `max_scan_size` bytes to bound CPU cost.
    /// If `host` matches a pattern's `allowed_domains`, that pattern is skipped.
    pub fn scan(&self, body: &[u8], host: Option<&str>) -> Vec<DlpMatch> {
        let inner = self.inner.load();
        let body = &body[..body.len().min(inner.max_scan_size)];
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return vec![], // Binary content, skip
        };

        let mut matches = Vec::new();
        for pattern in &inner.patterns {
            // Check if current host is exempt from this pattern
            if let Some(h) = host {
                if pattern
                    .allowed_domains
                    .iter()
                    .any(|p| conduit_common::config::matches_domain_pattern(p, h))
                {
                    continue;
                }
            }

            if let Some(mat) = pattern.regex.find(text) {
                let snippet = crate::block_page::mask_sensitive(mat.as_str());
                matches.push(DlpMatch {
                    pattern_name: pattern.name.clone(),
                    action: pattern.action,
                    matched_snippet: Some(snippet),
                });
                // Early exit: if this pattern blocks, no need to check remaining patterns
                if pattern.action == DlpAction::Block {
                    break;
                }
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

    // Built-in patterns with default domain exemptions for legitimate services
    let builtins: [(&str, &str, &[&str]); 22] = [
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", &[]),
        (
            "credit_card",
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            &[],
        ),
        ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", &[]),
        (
            "npm_token",
            r"(?:\bnpm_[A-Za-z0-9]{32,40}\b|(?://registry\.npmjs\.org/:)?_authToken=[A-Za-z0-9_-]{32,})",
            &["registry.npmjs.org", "*.npmjs.org", "registry.yarnpkg.com"],
        ),
        (
            "pypi_token",
            r"\bpypi-[A-Za-z0-9_-]{50,}\b",
            &["upload.pypi.org", "pypi.org", "*.pypi.org"],
        ),
        (
            "rubygems_key",
            r"\brubygems_[a-f0-9]{48}\b",
            &["rubygems.org", "*.rubygems.org"],
        ),
        (
            "crates_token",
            r"\bcio[a-zA-Z0-9]{32}\b",
            &["crates.io", "*.crates.io"],
        ),
        (
            "github_pat",
            r"\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
            &["api.github.com", "github.com", "*.github.com"],
        ),
        (
            "github_oauth",
            r"\b(?:gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b",
            &["api.github.com", "github.com", "*.github.com"],
        ),
        (
            "gitlab_pat",
            r"\bglpat-[0-9a-zA-Z_-]{20,22}\b",
            &["gitlab.com", "*.gitlab.com"],
        ),
        (
            "private_key",
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----",
            &[],
        ),
        (
            "aws_secret",
            r#"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
            &[],
        ),
        ("gcp_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", &[]),
        (
            "gcp_sa_key",
            r#"(?i)"type":\s*"service_account"|"private_key_id":\s*"[0-9a-f]{40}""#,
            &[],
        ),
        (
            "azure_connection_string",
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}",
            &[],
        ),
        ("vault_token", r"\b[sb]\.[a-zA-Z0-9]{24,}\b", &[]),
        (
            "db_credentials",
            r"(?i)(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:\s/]*:[^@\s/]+@[^\s/]+",
            &[],
        ),
        (
            "env_secret_export",
            r#"(?i)\b(?:export\s+)?(?:DB_PASSWORD|PASSWORD|PASSWD|SECRET_KEY|JWT_SECRET|AUTH_TOKEN)\s*=\s*["']?[^"'\s]{8,}["']?"#,
            &[
                "*.pkg.dev",
                "*.docker.pkg.dev",
                "*.gcr.io",
                "docker.io",
                "*.docker.io",
                "ghcr.io",
                "*.ecr.*.amazonaws.com",
                "quay.io",
                "*.quay.io",
            ],
        ),
        ("openai_key", r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,}\b", &[]),
        ("anthropic_key", r"\bsk-ant-[a-zA-Z0-9_-]{32,}\b", &[]),
        (
            "slack_token",
            r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
            &[],
        ),
        (
            "discord_webhook",
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            &[],
        ),
    ];

    for (name, pattern, allowed) in &builtins {
        match regex::RegexBuilder::new(pattern)
            .size_limit(1_000_000)
            .build()
        {
            Ok(re) => patterns.push(CompiledPattern {
                name: name.to_string(),
                regex: re,
                action: default_action,
                allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
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
                    allowed_domains: custom.allowed_domains.clone(),
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
                    allowed_domains: rule.allowed_domains.clone(),
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
    let raw: std::collections::HashMap<String, String> = conn.hgetall(keys::DLP_RULES).await?;

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
            allowed_domains: vec![],
            custom_patterns: vec![],
        }
    }

    #[test]
    fn test_ssn_detection() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"My SSN is 123-45-6789 please wire money";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "ssn");
    }

    #[test]
    fn test_credit_card_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"Card: 4111 1111 1111 1111";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert!(DlpEngine::should_block(&matches));
    }

    #[test]
    fn test_aws_key_detection() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"Access key: AKIAIOSFODNN7EXAMPLE";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_key");
    }

    #[test]
    fn test_npm_token_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body1 = b"npm_1234567890abcdefghijklmnopqrstuv";
        let matches1 = engine.scan(body1, None);
        assert!(!matches1.is_empty());
        assert_eq!(matches1[0].pattern_name, "npm_token");

        let body2 = b"//registry.npmjs.org/:_authToken=npm_998877665544332211aabbccddeeff001122";
        let matches2 = engine.scan(body2, None);
        assert!(!matches2.is_empty());
        assert_eq!(matches2[0].pattern_name, "npm_token");
    }

    #[test]
    fn test_pypi_token_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body =
            b"token = pypi-AgEIcHlwaS5vcmcCJDM4MDI4ZmQ0LTkxNmMtNGY4Mi05ZWMzLTM5ODk0MWNhMGQ2ZAAAYz";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "pypi_token");
    }

    #[test]
    fn test_github_pat_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "github_pat");
    }

    #[test]
    fn test_private_key_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body1 = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0";
        let matches1 = engine.scan(body1, None);
        assert!(!matches1.is_empty());
        assert_eq!(matches1[0].pattern_name, "private_key");

        let body2 = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA";
        let matches2 = engine.scan(body2, None);
        assert!(!matches2.is_empty());
        assert_eq!(matches2[0].pattern_name, "private_key");
    }

    #[test]
    fn test_aws_secret_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_secret");
    }

    #[test]
    fn test_db_credentials_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body1 =
            b"DATABASE_URL=postgres://admin:SuperSecretPass123!@db.internal:5432/production";
        let matches1 = engine.scan(body1, None);
        assert!(!matches1.is_empty());
        assert_eq!(matches1[0].pattern_name, "db_credentials");

        let body2 = b"REDIS_URL=redis://:MySecretPassword@redis.prod:6379";
        let matches2 = engine.scan(body2, None);
        assert!(!matches2.is_empty());
        assert_eq!(matches2[0].pattern_name, "db_credentials");
    }

    #[test]
    fn test_env_secret_export_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"export DB_PASSWORD=\"SuperSecretPassword123\"";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "env_secret_export");
    }

    #[test]
    fn test_env_secret_export_docker_pkg_dev_allowed() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"grant_type=refresh_token&service=us-central1-docker.pkg.dev&password=ya29.secrettoken12345";

        // Without host or on an untrusted host, the pattern triggers
        let matches_untrusted = engine.scan(body, Some("evil-site.com"));
        assert!(!matches_untrusted.is_empty());
        assert_eq!(matches_untrusted[0].pattern_name, "env_secret_export");

        // When targeting us-central1-docker.pkg.dev, it is exempt
        let matches_pkg_dev = engine.scan(body, Some("us-central1-docker.pkg.dev"));
        assert!(matches_pkg_dev.is_empty());

        // Also exempt for other docker registries like ghcr.io
        let matches_ghcr = engine.scan(body, Some("ghcr.io"));
        assert!(matches_ghcr.is_empty());
    }

    #[test]
    fn test_discord_webhook_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"curl -X POST https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789 -d @exfil.json";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "discord_webhook");
    }

    #[test]
    fn test_openai_key_detection() {
        let engine = DlpEngine::new(&test_config("block"));
        let body = b"sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456";
        let matches = engine.scan(body, None);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "openai_key");
    }

    #[test]
    fn test_no_match() {
        let engine = DlpEngine::new(&test_config("log"));
        let body = b"This is a normal request body with no sensitive data";
        let matches = engine.scan(body, None);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_custom_pattern() {
        let config = DlpConfig {
            enabled: true,
            max_scan_size: 1_048_576,
            action: "log".into(),
            allowed_domains: vec![],
            custom_patterns: vec![DlpPattern {
                name: "internal_id".into(),
                regex: r"INTERNAL-\d{8}".into(),
                action: "block".into(),
                allowed_domains: vec!["internal.corp".into()],
            }],
        };
        let engine = DlpEngine::new(&config);
        let body = b"Document ref: INTERNAL-12345678";
        // Matches on external domain
        let matches = engine.scan(body, Some("external.com"));
        assert!(matches.iter().any(|m| m.pattern_name == "internal_id"));
        assert!(DlpEngine::should_block(&matches));

        // Exempt on internal.corp
        let matches_exempt = engine.scan(body, Some("internal.corp"));
        assert!(!matches_exempt
            .iter()
            .any(|m| m.pattern_name == "internal_id"));
    }

    #[test]
    fn test_binary_body_skipped() {
        let engine = DlpEngine::new(&test_config("log"));
        let body: &[u8] = &[0xFF, 0xFE, 0x00, 0x01, 0x80];
        let matches = engine.scan(body, None);
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
                hits: 0,
                allowed_domains: vec![],
            },
            DlpRule {
                id: "2".into(),
                name: "disabled".into(),
                regex: r"\bfoo\b".into(),
                action: DlpRuleAction::Block,
                enabled: false,
                builtin: false,
                hits: 0,
                allowed_domains: vec![],
            },
        ];
        let patterns = compile_from_rules(&rules);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "active");
    }
}
