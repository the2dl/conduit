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
    /// Real-time threat detection configuration.
    #[serde(default)]
    pub threat: Option<ThreatConfig>,
    /// HTTP response caching configuration.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
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

/// Real-time threat detection pipeline configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    // Tier 0: heuristics
    #[serde(default = "default_t0_escalate")]
    pub tier0_escalation_threshold: f32,
    #[serde(default = "default_t0_block")]
    pub tier0_block_threshold: f32,
    #[serde(default = "default_dga_entropy")]
    pub dga_entropy_threshold: f32,
    // Tier 1: ML model
    #[serde(default = "default_true")]
    pub tier1_enabled: bool,
    #[serde(default = "default_t1_escalate")]
    pub tier1_escalation_threshold: f32, // reserved for future per-tier threshold tuning

    // Tier 2: content inspection
    #[serde(default = "default_true")]
    pub tier2_enabled: bool,
    #[serde(default = "default_t2_escalate")]
    pub tier2_escalation_threshold: f32,
    #[serde(default = "default_max_inspect")]
    pub max_inspect_bytes: usize,
    /// When true, buffers HTML/JS responses from suspicious domains and runs
    /// content analysis before forwarding. Blocks phishing on first visit at
    /// the cost of ~10-50ms added latency for inspected pages only.
    /// When false (default), content analysis runs after forwarding and only
    /// blocks on subsequent visits via learned reputation.
    #[serde(default)]
    pub tier2_block_on_inspect: bool,
    /// Maximum response body size (bytes) to buffer for first-visit blocking.
    /// Responses larger than this fall back to streaming (post-hoc analysis).
    #[serde(default = "default_max_buffer")]
    pub max_buffer_bytes: usize,

    // Tier 3: LLM verdict
    #[serde(default)]
    pub tier3_enabled: bool,
    #[serde(default)]
    pub llm_provider: Option<String>,
    #[serde(default)]
    pub llm_api_url: Option<String>,
    #[serde(default)]
    pub llm_api_key: Option<String>,
    #[serde(default = "default_t3_behavior")]
    pub tier3_behavior: String,
    #[serde(default = "default_t3_timeout")]
    pub tier3_timeout_ms: u64,

    // Reputation
    #[serde(default = "default_true")]
    pub reputation_enabled: bool,
    #[serde(default = "default_decay_hours")]
    pub reputation_decay_hours: u64,
    #[serde(default = "default_reputation_block")]
    pub reputation_block_threshold: f32,

    // Bloom filter / feeds
    #[serde(default = "default_bloom_cap")]
    pub bloom_capacity: usize,
    #[serde(default = "default_bloom_fp")]
    pub bloom_fp_rate: f64,
    #[serde(default = "default_feed_refresh")]
    pub feed_refresh_interval_secs: u64,
}

/// HTTP response caching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Max total cache size in bytes (default 128MB).
    #[serde(default = "default_max_cache_size")]
    pub max_cache_size: usize,
    /// Max individual response body size to cache in bytes (default 10MB).
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    /// Cache lock timeout in seconds (default 5).
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout_secs: u64,
    /// Default stale-while-revalidate grace period in seconds (default 60).
    #[serde(default = "default_stale_while_revalidate")]
    pub stale_while_revalidate_secs: u32,
    /// Default stale-if-error grace period in seconds (default 300).
    #[serde(default = "default_stale_if_error")]
    pub stale_if_error_secs: u32,
}

fn default_max_cache_size() -> usize { 134_217_728 } // 128 MB
fn default_max_file_size() -> usize { 10_485_760 } // 10 MB
fn default_lock_timeout() -> u64 { 5 }
fn default_stale_while_revalidate() -> u32 { 60 }
fn default_stale_if_error() -> u32 { 300 }

fn default_t0_escalate() -> f32 { 0.3 }
fn default_t0_block() -> f32 { 0.9 }
fn default_dga_entropy() -> f32 { 3.5 }
fn default_t1_escalate() -> f32 { 0.5 }
fn default_t2_escalate() -> f32 { 0.6 }
fn default_max_inspect() -> usize { 262144 }
fn default_max_buffer() -> usize { 1_048_576 } // 1 MB
fn default_t3_behavior() -> String { "allow_and_flag".into() }
fn default_t3_timeout() -> u64 { 5000 }
fn default_decay_hours() -> u64 { 168 }
fn default_reputation_block() -> f32 { 0.55 }
fn default_bloom_cap() -> usize { 2_000_000 }
fn default_bloom_fp() -> f64 { 0.001 }
fn default_feed_refresh() -> u64 { 3600 }

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
            threat: None,
            cache: None,
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
