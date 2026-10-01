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
    })
}
