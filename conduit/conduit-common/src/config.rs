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
    /// Timeout hardening configuration.
    #[serde(default)]
    pub timeouts: Option<TimeoutConfig>,
    /// Request size limits.
    #[serde(default)]
    pub request_limits: Option<RequestLimitsConfig>,
    /// Graceful shutdown configuration.
    #[serde(default)]
    pub shutdown: Option<ShutdownConfig>,
    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Connection limits per client IP.
    #[serde(default)]
    pub connection_limits: Option<ConnectionLimitConfig>,
    /// DNS caching configuration.
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    /// Prometheus metrics configuration.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Load balancing configuration.
    #[serde(default)]
    pub load_balancing: Option<LoadBalancingConfig>,
    /// Data Loss Prevention configuration.
    #[serde(default)]
    pub dlp: Option<DlpConfig>,
    /// HTTP/2 downstream configuration.
    #[serde(default)]
    pub downstream: Option<DownstreamConfig>,
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
            timeouts: None,
            request_limits: None,
            shutdown: None,
            rate_limit: None,
            connection_limits: None,
            dns: None,
            metrics: None,
            load_balancing: None,
            dlp: None,
            downstream: None,
        }
    }
}

/// Timeout hardening configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_total_connection_timeout")]
    pub total_connection_timeout_secs: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_write_timeout")]
    pub write_timeout_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Overall request timeout (0 = disabled).
    #[serde(default)]
    pub request_timeout_secs: u64,
}

fn default_connect_timeout() -> u64 { 10 }
fn default_total_connection_timeout() -> u64 { 15 }
fn default_read_timeout() -> u64 { 60 }
fn default_write_timeout() -> u64 { 60 }
fn default_idle_timeout() -> u64 { 300 }

/// Request size limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimitsConfig {
    /// Max request header size in bytes (0 = unlimited).
    #[serde(default)]
    pub max_request_header_size: usize,
    /// Max request body size in bytes (0 = unlimited).
    #[serde(default)]
    pub max_request_body_size: usize,
}

/// Graceful shutdown configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    #[serde(default = "default_grace_period")]
    pub grace_period_secs: u64,
    #[serde(default = "default_graceful_shutdown_timeout")]
    pub graceful_shutdown_timeout_secs: u64,
    #[serde(default = "default_upgrade_sock")]
    pub upgrade_sock: String,
    #[serde(default)]
    pub daemon: bool,
    #[serde(default = "default_pid_file")]
    pub pid_file: String,
}

fn default_grace_period() -> u64 { 60 }
fn default_graceful_shutdown_timeout() -> u64 { 300 }
fn default_upgrade_sock() -> String { "/tmp/conduit-upgrade.sock".into() }
fn default_pid_file() -> String { "/tmp/conduit.pid".into() }

/// Rate limiting configuration (disabled by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rate_window")]
    pub window_secs: u64,
    /// Max requests per IP per window (0 = unlimited).
    #[serde(default)]
    pub per_ip_limit: usize,
    /// Max requests per user per window (0 = unlimited).
    #[serde(default)]
    pub per_user_limit: usize,
    /// Max requests per destination host per window (0 = unlimited).
    #[serde(default)]
    pub per_destination_limit: usize,
    #[serde(default = "default_estimator_hashes")]
    pub estimator_hashes: usize,
    #[serde(default = "default_estimator_slots")]
    pub estimator_slots: usize,
}

fn default_rate_window() -> u64 { 60 }
fn default_estimator_hashes() -> usize { 4 }
fn default_estimator_slots() -> usize { 1024 }

/// Connection limits per client IP (disabled by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Max concurrent connections per IP (0 = unlimited).
    #[serde(default)]
    pub max_connections_per_ip: u32,
}

/// DNS caching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_dns_min_ttl")]
    pub min_ttl_secs: u64,
    #[serde(default = "default_dns_max_ttl")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_dns_negative_ttl")]
    pub negative_ttl_secs: u64,
}

fn default_dns_max_entries() -> usize { 10000 }
fn default_dns_min_ttl() -> u64 { 30 }
fn default_dns_max_ttl() -> u64 { 3600 }
fn default_dns_negative_ttl() -> u64 { 30 }

/// Prometheus metrics configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}

fn default_metrics_addr() -> String { "0.0.0.0:9091".into() }

/// Load balancing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upstreams: Vec<UpstreamGroup>,
}

/// A group of upstream backends for a set of domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamGroup {
    pub name: String,
    /// Domain glob patterns (e.g., "api.internal.com", "*.api.internal.com").
    pub domains: Vec<String>,
    #[serde(default = "default_lb_algorithm")]
    pub algorithm: String,
    pub backends: Vec<UpstreamBackend>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// A single upstream backend server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBackend {
    pub addr: String,
    #[serde(default = "default_backend_weight")]
    pub weight: usize,
}

/// Health check configuration for an upstream group.
/// TODO: Currently config-only — not yet wired into active health checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_hc_type")]
    pub check_type: String,
    #[serde(default = "default_hc_path")]
    pub path: String,
    #[serde(default = "default_hc_status")]
    pub expected_status: u16,
}

fn default_lb_algorithm() -> String { "round_robin".into() }
fn default_backend_weight() -> usize { 1 }
fn default_hc_interval() -> u64 { 10 }
fn default_hc_type() -> String { "tcp".into() }
fn default_hc_path() -> String { "/health".into() }
fn default_hc_status() -> u16 { 200 }

/// Data Loss Prevention configuration (disabled by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Max response body size to scan in bytes (default 1MB).
    #[serde(default = "default_dlp_max_scan")]
    pub max_scan_size: usize,
    /// Action on match: "log", "block", or "redact".
    #[serde(default = "default_dlp_action")]
    pub action: String,
    /// Custom regex patterns.
    #[serde(default)]
    pub custom_patterns: Vec<DlpPattern>,
}

/// A custom DLP regex pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    #[serde(default = "default_dlp_action")]
    pub action: String,
}

fn default_dlp_max_scan() -> usize { 1_048_576 }
fn default_dlp_action() -> String { "log".into() }

/// HTTP/2 downstream configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownstreamConfig {
    #[serde(default)]
    pub h2c: bool,
    #[serde(default = "default_h2_max_streams")]
    pub h2_max_concurrent_streams: usize,
    #[serde(default = "default_h2_window")]
    pub h2_initial_window_size: u32,
}

fn default_h2_max_streams() -> usize { 100 }
fn default_h2_window() -> u32 { 65535 }

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
