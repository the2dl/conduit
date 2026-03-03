use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearGateConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
    #[serde(default = "default_dragonfly_url")]
    pub dragonfly_url: String,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_key_path: Option<PathBuf>,
    #[serde(default = "default_cert_cache_size")]
    pub cert_cache_size: usize,
    #[serde(default = "default_log_channel_size")]
    pub log_channel_size: usize,
    #[serde(default)]
    pub syslog_target: Option<String>,
    #[serde(default = "default_redis_pool_size")]
    pub redis_pool_size: usize,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub block_page_html: Option<String>,
    #[serde(default = "default_log_retention")]
    pub log_retention: usize,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default)]
    pub ui_dir: Option<String>,
    /// Enable TLS interception (MITM) for CONNECT tunnels.
    /// When false, CONNECT tunnels pass through encrypted bytes without inspection.
    #[serde(default = "default_true")]
    pub tls_intercept: bool,
    /// API key for management API authentication.
    /// When set, all non-health API requests require `Authorization: Bearer <key>` or `X-API-Key: <key>`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// When true (default), block requests if policy rules cannot be loaded (Redis down, no cache).
    /// Set to false to allow requests when policy is unavailable (fail-open).
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// Multi-node configuration. When present, this proxy acts as a managed node.
    #[serde(default)]
    pub node: Option<NodeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    /// Dragonfly URL with per-node credentials (overrides top-level `dragonfly_url`).
    pub dragonfly_url: String,
    pub name: Option<String>,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// One-time enrollment token from `POST /nodes`. Required for first registration.
    #[serde(default)]
    pub enrollment_token: Option<String>,
    /// HMAC key (base64url) for signing heartbeats. Provided during enrollment.
    #[serde(default)]
    pub hmac_key: Option<String>,
}

fn default_heartbeat_interval() -> u64 {
    10
}

fn default_true() -> bool {
    true
}
fn default_listen_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_api_addr() -> String {
    "0.0.0.0:8443".into()
}
fn default_dragonfly_url() -> String {
    "redis://127.0.0.1:6379".into()
}
fn default_cert_cache_size() -> usize {
    10_000
}
fn default_log_channel_size() -> usize {
    10_000
}
fn default_redis_pool_size() -> usize {
    16
}
fn default_log_retention() -> usize {
    100_000
}
fn default_workers() -> usize {
    num_cpus()
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl Default for ClearGateConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            api_addr: default_api_addr(),
            dragonfly_url: default_dragonfly_url(),
            ca_cert_path: None,
            ca_key_path: None,
            cert_cache_size: default_cert_cache_size(),
            log_channel_size: default_log_channel_size(),
            syslog_target: None,
            redis_pool_size: default_redis_pool_size(),
            auth_required: false,
            block_page_html: None,
            log_retention: default_log_retention(),
            workers: default_workers(),
            ui_dir: None,
            tls_intercept: true,
            api_key: None,
            fail_closed: true,
            node: None,
        }
    }
}

impl ClearGateConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_cert_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("cleargate-ca.pem"))
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.ca_key_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("cleargate-ca-key.pem"))
    }
}
