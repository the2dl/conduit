use conduit_common::config::DlpConfig;
use regex::Regex;
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

/// A single DLP match found during scanning.
#[derive(Debug, Clone)]
pub struct DlpMatch {
    #[allow(dead_code)]
    pub pattern_name: String,
    pub action: DlpAction,
}

/// DLP engine with compiled regex patterns for scanning request/response bodies.
pub struct DlpEngine {
    patterns: Vec<CompiledPattern>,
    pub max_scan_size: usize,
    #[allow(dead_code)]
    pub default_action: DlpAction,
}

impl DlpEngine {
    pub fn new(config: &DlpConfig) -> Self {
        let default_action = parse_action(&config.action);
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

        // Custom patterns
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
                    info!(name = %custom.name, "Custom DLP pattern loaded");
                }
                Err(e) => warn!(name = %custom.name, "Failed to compile custom DLP pattern: {e}"),
            }
        }

        info!(count = patterns.len(), "DLP engine initialized");

        DlpEngine {
            patterns,
            max_scan_size: config.max_scan_size,
            default_action,
        }
    }

    /// Scan a body for DLP violations. Returns all matches found.
    /// Only scans up to `max_scan_size` bytes to bound CPU cost.
    pub fn scan(&self, body: &[u8]) -> Vec<DlpMatch> {
        let body = &body[..body.len().min(self.max_scan_size)];
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return vec![], // Binary content, skip
        };

        let mut matches = Vec::new();
        for pattern in &self.patterns {
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
}
