use arc_swap::ArcSwap;
use conduit_common::redis::keys;
use deadpool_redis::Pool;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

use std::sync::RwLock;

static STATIC_MUTED_DOMAINS: Lazy<RwLock<Vec<String>>> = Lazy::new(|| {
    RwLock::new(vec![
        "browser-intake-us5-datadoghq.com".to_string(),
        "*.datadoghq.com".to_string(),
    ])
});

pub fn set_static_muted_domains(domains: Vec<String>) {
    if let Ok(mut guard) = STATIC_MUTED_DOMAINS.write() {
        *guard = domains;
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub prevention_mode: bool,
    pub dga_prevention: bool,
    pub dga_threshold: f32,
    pub threat_prevention: bool,
    pub threat_block_threshold: f32,
    pub tls_intercept: bool,
    pub fail_closed: bool,
    pub notifications_enabled: bool,
    pub muted_notification_domains: Vec<String>,
    // TLD Protection overrides
    pub tld_protection_enabled: Option<bool>,
    pub tld_protection_action: Option<String>,
    pub tld_block_bad_tlds: Option<bool>,
    pub tld_blocked_list: Option<Vec<String>>,
    pub tld_trusted_list: Option<Vec<String>>,
    // POST Protection overrides
    pub post_protection_enabled: Option<bool>,
    pub post_protection_action: Option<String>,
    pub post_browser_only: Option<bool>,
    pub post_block_uncategorized_bad_tld: Option<bool>,
    pub post_block_uncategorized_high_entropy: Option<bool>,
    pub post_entropy_threshold: Option<f32>,
    pub post_max_uncategorized_body_bytes: Option<usize>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            prevention_mode: false,
            dga_prevention: false,
            dga_threshold: 3.5,
            threat_prevention: false,
            threat_block_threshold: 0.70,
            tls_intercept: true,
            fail_closed: false,
            notifications_enabled: true,
            muted_notification_domains: vec![
                "browser-intake-us5-datadoghq.com".to_string(),
                "*.datadoghq.com".to_string(),
            ],
            tld_protection_enabled: None,
            tld_protection_action: None,
            tld_block_bad_tlds: None,
            tld_blocked_list: None,
            tld_trusted_list: None,
            post_protection_enabled: None,
            post_protection_action: None,
            post_browser_only: None,
            post_block_uncategorized_bad_tld: None,
            post_block_uncategorized_high_entropy: None,
            post_entropy_threshold: None,
            post_max_uncategorized_body_bytes: None,
        }
    }
}

impl RuntimeConfig {
    pub fn is_domain_muted(&self, domain: &str) -> bool {
        for pattern in &self.muted_notification_domains {
            if conduit_common::config::matches_domain_pattern(pattern, domain) {
                return true;
            }
        }
        false
    }

    pub fn effective_tld_protection(
        &self,
        static_cfg: Option<&conduit_common::config::TldProtectionConfig>,
    ) -> conduit_common::config::TldProtectionConfig {
        let mut cfg = static_cfg.cloned().unwrap_or_default();
        if let Some(enabled) = self.tld_protection_enabled {
            cfg.enabled = enabled;
        }
        if let Some(ref action) = self.tld_protection_action {
            cfg.action = action.clone();
        }
        if let Some(block_bad) = self.tld_block_bad_tlds {
            cfg.block_bad_tlds = block_bad;
        }
        if let Some(ref blocked) = self.tld_blocked_list {
            cfg.blocked_tlds = blocked.clone();
        }
        if let Some(ref trusted) = self.tld_trusted_list {
            cfg.trusted_tlds = trusted.clone();
        }
        cfg
    }

    pub fn effective_post_protection(
        &self,
        static_cfg: Option<&conduit_common::config::PostProtectionConfig>,
    ) -> conduit_common::config::PostProtectionConfig {
        let mut cfg = static_cfg.cloned().unwrap_or_default();
        if let Some(enabled) = self.post_protection_enabled {
            cfg.enabled = enabled;
        }
        if let Some(ref action) = self.post_protection_action {
            cfg.action = action.clone();
        }
        if let Some(browser_only) = self.post_browser_only {
            cfg.browser_only = browser_only;
        }
        if let Some(block_bad_tld) = self.post_block_uncategorized_bad_tld {
            cfg.block_uncategorized_bad_tld = block_bad_tld;
        }
        if let Some(block_entropy) = self.post_block_uncategorized_high_entropy {
            cfg.block_uncategorized_high_entropy = block_entropy;
        }
        if let Some(entropy_threshold) = self.post_entropy_threshold {
            cfg.entropy_threshold = entropy_threshold;
        }
        if let Some(max_body) = self.post_max_uncategorized_body_bytes {
            cfg.max_uncategorized_body_bytes = max_body;
        }
        cfg
    }
}

static CURRENT_CONFIG: Lazy<ArcSwap<RuntimeConfig>> =
    Lazy::new(|| ArcSwap::new(Arc::new(RuntimeConfig::default())));

/// Get a snapshot of the current runtime configuration.
pub fn get() -> Arc<RuntimeConfig> {
    CURRENT_CONFIG.load_full()
}

/// Reload runtime configuration from Redis.
pub async fn reload(pool: &Pool) {
    match load_from_redis(pool).await {
        Ok(cfg) => {
            info!(
                prevention_mode = cfg.prevention_mode,
                dga_prevention = cfg.dga_prevention,
                dga_threshold = cfg.dga_threshold,
                threat_prevention = cfg.threat_prevention,
                threat_block_threshold = cfg.threat_block_threshold,
                tls_intercept = cfg.tls_intercept,
                fail_closed = cfg.fail_closed,
                "Runtime configuration reloaded"
            );
            CURRENT_CONFIG.store(Arc::new(cfg));
        }
        Err(e) => {
            warn!("Failed to reload runtime config from Redis: {e}");
        }
    }
}

async fn load_from_redis(pool: &Pool) -> anyhow::Result<RuntimeConfig> {
    let mut conn = pool.get().await?;
    let raw: HashMap<String, String> = conn.hgetall(keys::CONFIG).await.unwrap_or_default();

    let parse_bool = |key: &str, default: bool| -> bool {
        raw.get(key)
            .map(|v| v == "true" || v == "1" || v == "yes")
            .unwrap_or(default)
    };

    let parse_f32 = |key: &str, default: f32| -> f32 {
        raw.get(key)
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(default)
    };

    let parse_bool_opt =
        |key: &str| -> Option<bool> { raw.get(key).map(|v| v == "true" || v == "1" || v == "yes") };

    let parse_string_opt = |key: &str| -> Option<String> { raw.get(key).cloned() };

    let parse_f32_opt =
        |key: &str| -> Option<f32> { raw.get(key).and_then(|v| v.parse::<f32>().ok()) };

    let parse_usize_opt =
        |key: &str| -> Option<usize> { raw.get(key).and_then(|v| v.parse::<usize>().ok()) };

    let parse_list_opt = |key: &str| -> Option<Vec<String>> {
        raw.get(key).map(|v| {
            v.split(|c: char| c == ',' || c == '\n' || c == ' ' || c == ';')
                .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
    };

    let muted_set: Vec<String> = conn
        .smembers(keys::MUTED_NOTIFICATIONS)
        .await
        .unwrap_or_default();

    let mut all_muted = STATIC_MUTED_DOMAINS
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    for m in muted_set {
        if !all_muted
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&m))
        {
            all_muted.push(m);
        }
    }

    Ok(RuntimeConfig {
        prevention_mode: parse_bool("prevention_mode", false),
        dga_prevention: parse_bool("dga_prevention", false),
        dga_threshold: parse_f32("dga_threshold", 3.5),
        threat_prevention: parse_bool("threat_prevention", false),
        threat_block_threshold: parse_f32("threat_block_threshold", 0.70),
        tls_intercept: parse_bool("tls_intercept", true),
        fail_closed: parse_bool("fail_closed", false),
        notifications_enabled: parse_bool("notifications_enabled", true),
        muted_notification_domains: all_muted,
        tld_protection_enabled: parse_bool_opt("tld_protection_enabled"),
        tld_protection_action: parse_string_opt("tld_protection_action"),
        tld_block_bad_tlds: parse_bool_opt("tld_block_bad_tlds"),
        tld_blocked_list: parse_list_opt("tld_blocked_list"),
        tld_trusted_list: parse_list_opt("tld_trusted_list"),
        post_protection_enabled: parse_bool_opt("post_protection_enabled"),
        post_protection_action: parse_string_opt("post_protection_action"),
        post_browser_only: parse_bool_opt("post_browser_only"),
        post_block_uncategorized_bad_tld: parse_bool_opt("post_block_uncategorized_bad_tld"),
        post_block_uncategorized_high_entropy: parse_bool_opt(
            "post_block_uncategorized_high_entropy",
        ),
        post_entropy_threshold: parse_f32_opt("post_entropy_threshold"),
        post_max_uncategorized_body_bytes: parse_usize_opt("post_max_uncategorized_body_bytes"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_common::config::{PostProtectionConfig, TldProtectionConfig};

    #[test]
    fn test_effective_tld_protection_fallbacks_and_overrides() {
        let mut rt = RuntimeConfig::default();
        let static_cfg = TldProtectionConfig {
            enabled: false,
            action: "log".to_string(),
            block_bad_tlds: false,
            blocked_tlds: vec!["custombad".to_string()],
            trusted_tlds: vec!["customgood".to_string()],
        };

        // When RT has None, static config applies
        let eff = rt.effective_tld_protection(Some(&static_cfg));
        assert!(!eff.enabled);
        assert_eq!(eff.action, "log");
        assert!(!eff.block_bad_tlds);
        assert_eq!(eff.blocked_tlds, vec!["custombad"]);
        assert_eq!(eff.trusted_tlds, vec!["customgood"]);

        // When RT has overrides, they take precedence
        rt.tld_protection_enabled = Some(true);
        rt.tld_protection_action = Some("block".to_string());
        rt.tld_block_bad_tlds = Some(true);
        rt.tld_blocked_list = Some(vec!["ru".to_string(), "cn".to_string()]);
        rt.tld_trusted_list = Some(vec!["rs".to_string()]);

        let eff2 = rt.effective_tld_protection(Some(&static_cfg));
        assert!(eff2.enabled);
        assert_eq!(eff2.action, "block");
        assert!(eff2.block_bad_tlds);
        assert_eq!(eff2.blocked_tlds, vec!["ru", "cn"]);
        assert_eq!(eff2.trusted_tlds, vec!["rs"]);
    }

    #[test]
    fn test_effective_post_protection_fallbacks_and_overrides() {
        let mut rt = RuntimeConfig::default();
        let static_cfg = PostProtectionConfig {
            enabled: false,
            action: "log".to_string(),
            browser_only: false,
            block_uncategorized_bad_tld: false,
            block_uncategorized_high_entropy: false,
            entropy_threshold: 4.0,
            max_uncategorized_body_bytes: 8192,
            exempt_user_agents: vec!["my-agent".to_string()],
        };

        let eff = rt.effective_post_protection(Some(&static_cfg));
        assert!(!eff.enabled);
        assert_eq!(eff.action, "log");
        assert!(!eff.browser_only);
        assert_eq!(eff.entropy_threshold, 4.0);
        assert_eq!(eff.max_uncategorized_body_bytes, 8192);

        // Apply overrides
        rt.post_protection_enabled = Some(true);
        rt.post_protection_action = Some("block".to_string());
        rt.post_browser_only = Some(true);
        rt.post_block_uncategorized_bad_tld = Some(true);
        rt.post_block_uncategorized_high_entropy = Some(true);
        rt.post_entropy_threshold = Some(3.2);
        rt.post_max_uncategorized_body_bytes = Some(32768);

        let eff2 = rt.effective_post_protection(Some(&static_cfg));
        assert!(eff2.enabled);
        assert_eq!(eff2.action, "block");
        assert!(eff2.browser_only);
        assert!(eff2.block_uncategorized_bad_tld);
        assert!(eff2.block_uncategorized_high_entropy);
        assert_eq!(eff2.entropy_threshold, 3.2);
        assert_eq!(eff2.max_uncategorized_body_bytes, 32768);
        assert_eq!(eff2.exempt_user_agents, vec!["my-agent"]);
    }
}
