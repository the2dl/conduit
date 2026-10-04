use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearGateConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
    #[serde(
        default = "default_dragonfly_url",
        alias = "valkey_url",
        alias = "redis_url",
        alias = "datastore_url"
    )]
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
    /// When true (default), bare IP address destinations (e.g. 198.51.100.23:443) are also MITM intercepted.
    /// When false, bare IP destinations pass through without TLS interception.
    /// Pinned infrastructure (e.g. Kubernetes cluster API servers) should be allowlisted
    /// specifically in `allowlist.hosts` rather than turning off IP inspection globally.
    #[serde(default = "default_true")]
    pub tls_intercept_bare_ips: bool,
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
    /// Package Security & Supply Chain Scanning with YARA-X.
    #[serde(default)]
    pub package_scanner: Option<PackageScannerConfig>,
    /// Allowlist configuration for bypassing proxy inspection, caching, and SSRF checks.
    #[serde(default)]
    pub allowlist: Option<AllowlistConfig>,
    /// Outbound egress port restrictions.
    #[serde(default)]
    pub egress: Option<EgressConfig>,
    /// Desktop notification and alert suppression configuration.
    #[serde(default)]
    pub notifications: Option<NotificationsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    /// Datastore URL (Valkey/Redis/Dragonfly) with per-node credentials (overrides top-level `dragonfly_url`).
    #[serde(alias = "valkey_url", alias = "redis_url", alias = "datastore_url")]
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

fn default_max_cache_size() -> usize {
    134_217_728
} // 128 MB
fn default_max_file_size() -> usize {
    10_485_760
} // 10 MB
fn default_lock_timeout() -> u64 {
    5
}
fn default_stale_while_revalidate() -> u32 {
    60
}
fn default_stale_if_error() -> u32 {
    300
}

fn default_t0_escalate() -> f32 {
    0.3
}
fn default_t0_block() -> f32 {
    0.9
}
fn default_dga_entropy() -> f32 {
    3.5
}
fn default_t1_escalate() -> f32 {
    0.5
}
fn default_t2_escalate() -> f32 {
    0.6
}
fn default_max_inspect() -> usize {
    262144
}
fn default_max_buffer() -> usize {
    1_048_576
} // 1 MB
fn default_t3_behavior() -> String {
    "allow_and_flag".into()
}
fn default_t3_timeout() -> u64 {
    5000
}
fn default_decay_hours() -> u64 {
    168
}
fn default_reputation_block() -> f32 {
    0.55
}
fn default_bloom_cap() -> usize {
    2_000_000
}
fn default_bloom_fp() -> f64 {
    0.001
}
fn default_feed_refresh() -> u64 {
    3600
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
    "redis://127.0.0.1:6380".into()
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
            tls_intercept_bare_ips: true,
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
            package_scanner: None,
            downstream: None,
            allowlist: None,
            egress: None,
            notifications: None,
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

fn default_connect_timeout() -> u64 {
    10
}
fn default_total_connection_timeout() -> u64 {
    15
}
fn default_read_timeout() -> u64 {
    60
}
fn default_write_timeout() -> u64 {
    60
}
fn default_idle_timeout() -> u64 {
    300
}

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

fn default_grace_period() -> u64 {
    60
}
fn default_graceful_shutdown_timeout() -> u64 {
    300
}
fn default_upgrade_sock() -> String {
    "/tmp/conduit-upgrade.sock".into()
}
fn default_pid_file() -> String {
    "/tmp/conduit.pid".into()
}

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

fn default_rate_window() -> u64 {
    60
}
fn default_estimator_hashes() -> usize {
    4
}
fn default_estimator_slots() -> usize {
    1024
}

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
    /// IP version preference for upstream connections.
    /// "any" = OS default, "v4_only" = IPv4 only, "v6_only" = IPv6 only,
    /// "v4_preferred" = filter IPv6 when IPv4 available (default).
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
}

fn default_ip_version() -> String {
    "v4_preferred".into()
}

fn default_dns_max_entries() -> usize {
    10000
}
fn default_dns_min_ttl() -> u64 {
    30
}
fn default_dns_max_ttl() -> u64 {
    3600
}
fn default_dns_negative_ttl() -> u64 {
    30
}

/// Prometheus metrics configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}

fn default_metrics_addr() -> String {
    "0.0.0.0:9091".into()
}

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

fn default_lb_algorithm() -> String {
    "round_robin".into()
}
fn default_backend_weight() -> usize {
    1
}
fn default_hc_interval() -> u64 {
    10
}
fn default_hc_type() -> String {
    "tcp".into()
}
fn default_hc_path() -> String {
    "/health".into()
}
fn default_hc_status() -> u16 {
    200
}

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
    /// Domains exempt from all DLP inspections (e.g. ["*.pkg.dev"]).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Custom regex patterns.
    #[serde(default)]
    pub custom_patterns: Vec<DlpPattern>,
}

impl DlpConfig {
    /// Check if a domain is exempt from DLP inspection.
    pub fn is_domain_allowed(&self, host: &str) -> bool {
        for pattern in &self.allowed_domains {
            if matches_domain_pattern(pattern, host) {
                return true;
            }
        }
        false
    }
}

/// A custom DLP regex pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    #[serde(default = "default_dlp_action")]
    pub action: String,
    /// Domains exempt from this pattern.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_dlp_max_scan() -> usize {
    1_048_576
}
fn default_dlp_action() -> String {
    "log".into()
}

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

fn default_h2_max_streams() -> usize {
    100
}
fn default_h2_window() -> u32 {
    65535
}

/// Package Security & Supply Chain Scanning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Action on malware match: "block" or "log".
    #[serde(default = "default_package_action")]
    pub action: String,
    /// Max archive size to buffer & scan (default 15MB).
    #[serde(default = "default_package_max_size")]
    pub max_package_size: usize,
    /// Max size per script file inside archive to scan (default 2MB).
    #[serde(default = "default_package_max_file_size")]
    pub max_file_scan_size: usize,
    /// Optional path to custom YARA rules file or directory.
    #[serde(default)]
    pub custom_rules_path: Option<String>,
}

fn default_package_action() -> String {
    "block".into()
}
fn default_package_max_size() -> usize {
    15 * 1024 * 1024
}
fn default_package_max_file_size() -> usize {
    2 * 1024 * 1024
}

/// Outbound egress port restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    /// Allowed destination ports for CONNECT tunneling (HTTPS/TCP).
    /// Defaults to [443, 8443, 6443] (web HTTPS, alt HTTPS, and Kubernetes API).
    /// If empty, all destination ports are permitted.
    #[serde(default = "default_allowed_connect_ports")]
    pub allowed_connect_ports: Vec<u16>,
    /// Allowed destination ports for plain HTTP proxying.
    /// Defaults to [80, 8080].
    /// If empty, all destination ports are permitted.
    #[serde(default = "default_allowed_http_ports")]
    pub allowed_http_ports: Vec<u16>,
}

fn default_allowed_connect_ports() -> Vec<u16> {
    vec![443, 8443, 6443]
}

fn default_allowed_http_ports() -> Vec<u16> {
    vec![80, 8080]
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allowed_connect_ports: default_allowed_connect_ports(),
            allowed_http_ports: default_allowed_http_ports(),
        }
    }
}

impl EgressConfig {
    pub fn is_connect_port_allowed(&self, port: u16) -> bool {
        self.allowed_connect_ports.is_empty() || self.allowed_connect_ports.contains(&port)
    }

    pub fn is_http_port_allowed(&self, port: u16) -> bool {
        self.allowed_http_ports.is_empty() || self.allowed_http_ports.contains(&port)
    }
}

/// Desktop notification and alert suppression configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    /// Enable desktop notifications for blocked requests (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum interval in seconds between updating a notification for the same blocked host:port (default: 2s).
    #[serde(default = "default_notify_min_interval_secs")]
    pub min_interval_secs: u64,
    /// List of domains or wildcard patterns (*.domain.com) to mute (blocks still occur, but notifications are silenced).
    #[serde(default)]
    pub muted_domains: Vec<String>,
}

fn default_notify_min_interval_secs() -> u64 {
    2
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_secs: default_notify_min_interval_secs(),
            muted_domains: vec![
                "browser-intake-us5-datadoghq.com".to_string(),
                "*.datadoghq.com".to_string(),
            ],
        }
    }
}

impl NotificationsConfig {
    pub fn is_domain_muted(&self, domain: &str) -> bool {
        for pattern in &self.muted_domains {
            if matches_domain_pattern(pattern, domain) {
                return true;
            }
        }
        false
    }
}

/// Check if a domain matches a wildcard pattern (*.example.com, .example.com, or exact).
pub fn matches_domain_pattern(pattern: &str, domain: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let d = domain.trim().to_ascii_lowercase();
    if p.starts_with("*.") {
        let suffix = &p[2..];
        d == suffix || d.ends_with(&format!(".{suffix}"))
    } else if p.starts_with('.') {
        let suffix = &p[1..];
        d == suffix || d.ends_with(&format!(".{suffix}"))
    } else {
        d == p
    }
}

/// Allowlist configuration to permit direct bypass of SSRF checks, caching, and inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistConfig {
    /// Hostnames, domain patterns (*.example.com or .example.com), bare IPs, or CIDR notations.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Destination ports permitted to bypass SSRF blocking and TLS interception (e.g. 6443 for Kubernetes API servers).
    #[serde(default)]
    pub ports: Vec<u16>,
    /// When true (default), permits loopback traffic (127.0.0.0/8, ::1, localhost)
    /// to bypass SSRF blocking for unprivileged ports (>= min_loopback_port).
    #[serde(default = "default_true")]
    pub allow_loopback: bool,
    /// Minimum allowed port for loopback connections when allow_loopback is true.
    /// Defaults to 1024 to prevent SSRF against privileged system services (< 1024).
    #[serde(default = "default_min_loopback_port")]
    pub min_loopback_port: u16,
    /// Ports on loopback that are always blocked (e.g. databases, internal daemons)
    /// unless an entry explicitly naming the host:port is listed in `hosts`.
    #[serde(default = "default_blocked_loopback_ports")]
    pub blocked_loopback_ports: Vec<u16>,
    /// Only allow loopback traffic when the client making the request is on the local machine.
    #[serde(default = "default_true")]
    pub only_local_clients_for_loopback: bool,
}

fn default_min_loopback_port() -> u16 {
    1024
}

fn default_blocked_loopback_ports() -> Vec<u16> {
    vec![
        22,    // SSH
        2375,  // Docker unencrypted TCP
        2376,  // Docker TLS
        3306,  // MySQL
        5432,  // PostgreSQL
        6379,  // Redis default
        6380,  // Dragonfly / Conduit Redis
        11211, // Memcached
        27017, // MongoDB
    ]
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            ports: Vec::new(),
            allow_loopback: true,
            min_loopback_port: default_min_loopback_port(),
            blocked_loopback_ports: default_blocked_loopback_ports(),
            only_local_clients_for_loopback: true,
        }
    }
}

/// Query the kernel's routing table for the primary non-loopback LAN IP (e.g. 192.168.x.x).
pub fn get_primary_lan_ip() -> Option<String> {
    static LAN_IP: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    LAN_IP
        .get_or_init(|| {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
            socket.connect("1.1.1.1:80").ok()?;
            let local_addr = socket.local_addr().ok()?;
            let ip = local_addr.ip().to_string();
            if ip != "127.0.0.1" && ip != "::1" {
                Some(ip)
            } else {
                None
            }
        })
        .clone()
}

/// Strip port from IP string if present (handling IPv4:port, [IPv6]:port, and bare IPv6).
pub fn clean_ip_str(ip_str: &str) -> &str {
    let s = ip_str.trim();
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            &s[1..end]
        } else {
            s.trim_matches('[').trim_matches(']')
        }
    } else if let Some((h, p)) = s.rsplit_once(':') {
        if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            s
        }
    } else {
        s
    }
}

/// Check if a client IP address corresponds to the local machine (loopback or host LAN IP).
pub fn is_local_client_ip(client_ip: &str) -> bool {
    let clean = clean_ip_str(client_ip);

    if clean == "127.0.0.1"
        || clean == "::1"
        || clean.starts_with("127.")
        || clean.eq_ignore_ascii_case("localhost")
    {
        return true;
    }

    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
    }

    if let Some(lan_ip) = get_primary_lan_ip() {
        if clean == lan_ip {
            return true;
        }
    }

    false
}

/// Parse host and optional port from a string like "localhost:8080" or "[::1]:443".
pub fn extract_host_port_pair(host_str: &str) -> (&str, Option<u16>) {
    if host_str.starts_with('[') {
        if let Some(end) = host_str.find(']') {
            let host = &host_str[1..end];
            let port = host_str[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            (host, port)
        } else {
            (host_str.trim_matches('[').trim_matches(']'), None)
        }
    } else if let Some((h, p)) = host_str.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            (h, Some(port))
        } else {
            (host_str, None)
        }
    } else {
        (host_str, None)
    }
}

impl AllowlistConfig {
    /// Check whether a host and/or resolved IP address is permitted by the allowlist.
    pub fn is_allowed(
        &self,
        host: &str,
        port: u16,
        dest_ip: Option<std::net::IpAddr>,
        client_ip: Option<&str>,
    ) -> bool {
        let (clean_host, host_port) = extract_host_port_pair(host);
        let effective_port = host_port.unwrap_or(port);

        let parsed_host_ip = clean_host.parse::<std::net::IpAddr>().ok();
        let effective_dest_ip = dest_ip.or(parsed_host_ip);

        let is_loopback_target = clean_host.eq_ignore_ascii_case("localhost")
            || clean_host == "127.0.0.1"
            || clean_host == "::1"
            || clean_host.starts_with("127.")
            || effective_dest_ip
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);

        let clean_lower = clean_host.to_lowercase();
        let host_with_port = format!("{clean_lower}:{effective_port}");

        // 1. Check explicit matches in `hosts`
        for pattern in &self.hosts {
            let pat = pattern
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.')
                .to_lowercase();

            // Match exact "host:port" (e.g. "localhost:8443", "127.0.0.1:8443")
            if host_with_port == pat {
                return true;
            }

            // Match host without port specified in pattern
            if clean_lower == pat {
                // If it's a loopback target, generic host pattern ("localhost")
                // still undergoes loopback port safety guards below.
                if !is_loopback_target {
                    return true;
                }
            }

            // Wildcard prefix: "*.example.com" or ".example.com"
            if pat.starts_with("*.") {
                let suffix = &pat[1..];
                if clean_lower.ends_with(suffix) {
                    return true;
                }
            } else if pat.starts_with('.') {
                if clean_lower.ends_with(&pat) {
                    return true;
                }
            }

            // IP or CIDR match
            if let Some(ref e_ip) = effective_dest_ip {
                if let Ok(net) = pat.parse::<ipnet::IpNet>() {
                    if net.contains(e_ip) {
                        if !is_loopback_target {
                            return true;
                        }
                    }
                } else if let Ok(pat_ip) = pat.parse::<std::net::IpAddr>() {
                    if *e_ip == pat_ip {
                        if !is_loopback_target {
                            return true;
                        }
                    }
                }
            }
        }

        // 2. Loopback check with safety guards
        if self.allow_loopback && is_loopback_target {
            // Guard: Client must be local if only_local_clients_for_loopback is enabled
            if self.only_local_clients_for_loopback {
                if let Some(c_ip) = client_ip {
                    if !is_local_client_ip(c_ip) {
                        return false;
                    }
                }
            }

            // Guard: Must not be a blocked sensitive port (e.g. Redis 6379, Dragonfly 6380, Docker 2375, etc.)
            if self.blocked_loopback_ports.contains(&effective_port) {
                return false;
            }

            // Guard: Must be >= min_loopback_port (unprivileged ports >= 1024)
            if effective_port < self.min_loopback_port {
                return false;
            }

            return true;
        }

        // 3. Port check for non-loopback targets (e.g. Kubernetes 6443)
        if !is_loopback_target && self.ports.contains(&effective_port) {
            return true;
        }

        false
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_loopback_unprivileged_ports() {
        let allowlist = AllowlistConfig::default();
        // Agent callback port (>= 1024)
        assert!(allowlist.is_allowed("localhost", 45693, None, Some("127.0.0.1")));
        assert!(allowlist.is_allowed("localhost:45693", 80, None, Some("127.0.0.1")));
        assert!(allowlist.is_allowed("127.0.0.1", 3000, None, Some("127.0.0.1")));
        assert!(allowlist.is_allowed("[::1]:3000", 80, None, Some("::1")));
        assert!(allowlist.is_allowed(
            "some-host",
            5000,
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1")
        ));

        // Blocked sensitive ports
        assert!(!allowlist.is_allowed("127.0.0.1", 6380, None, Some("127.0.0.1"))); // Dragonfly
        assert!(!allowlist.is_allowed("localhost", 6379, None, Some("127.0.0.1"))); // Redis
        assert!(!allowlist.is_allowed("127.0.0.1", 22, None, Some("127.0.0.1"))); // SSH
        assert!(!allowlist.is_allowed("127.0.0.1", 80, None, Some("127.0.0.1"))); // Privileged port < 1024

        // Remote LAN client blocked from loopback
        assert!(!allowlist.is_allowed("localhost", 45693, None, Some("192.168.99.100")));
    }

    #[test]
    fn test_allowlist_explicit_override() {
        let allowlist = AllowlistConfig {
            hosts: vec!["localhost:8443".into()],
            ..AllowlistConfig::default()
        };
        // Explicitly whitelisted host:port is allowed even if not matching general loopback rules
        assert!(allowlist.is_allowed("localhost:8443", 8443, None, Some("127.0.0.1")));
    }

    #[test]
    fn test_allowlist_patterns_and_cidrs() {
        let allowlist = AllowlistConfig {
            hosts: vec![
                "*.local".into(),
                "api.internal".into(),
                "10.0.0.0/8".into(),
                "192.168.1.100".into(),
            ],
            allow_loopback: false,
            ..AllowlistConfig::default()
        };
        assert!(!allowlist.is_allowed("localhost", 8080, None, Some("127.0.0.1")));
        assert!(allowlist.is_allowed("my-service.local", 80, None, None));
        assert!(allowlist.is_allowed("sub.my-service.local:8080", 8080, None, None));
        assert!(allowlist.is_allowed("api.internal", 443, None, None));
        assert!(!allowlist.is_allowed("other.internal", 443, None, None));
        assert!(allowlist.is_allowed("10.1.2.3", 80, None, None));
        assert!(allowlist.is_allowed("host", 80, Some("10.50.0.1".parse().unwrap()), None));
        assert!(allowlist.is_allowed("192.168.1.100:9000", 9000, None, None));
        assert!(!allowlist.is_allowed("192.168.1.101", 80, None, None));
    }

    #[test]
    fn test_allowlist_ports() {
        let allowlist = AllowlistConfig {
            ports: vec![6443],
            allow_loopback: false,
            ..AllowlistConfig::default()
        };
        assert!(allowlist.is_allowed("212.2.245.198", 6443, None, None));
        assert!(allowlist.is_allowed("k8s.example.com", 6443, None, None));
        assert!(!allowlist.is_allowed("212.2.245.198", 443, None, None));
        assert!(!allowlist.is_allowed("k8s.example.com", 443, None, None));
        assert!(!allowlist.is_allowed("127.0.0.1", 6443, None, Some("127.0.0.1")));
    }

    #[test]
    fn test_egress_port_restrictions() {
        let egress = EgressConfig::default();
        // CONNECT ports
        assert!(egress.is_connect_port_allowed(443));
        assert!(egress.is_connect_port_allowed(8443));
        assert!(egress.is_connect_port_allowed(6443)); // kubectl
        assert!(!egress.is_connect_port_allowed(1234)); // arbitrary port blocked
        assert!(!egress.is_connect_port_allowed(22)); // SSH over CONNECT blocked by default

        // HTTP ports
        assert!(egress.is_http_port_allowed(80));
        assert!(egress.is_http_port_allowed(8080));
        assert!(!egress.is_http_port_allowed(1234));

        // Custom / unrestricted ports
        let open_egress = EgressConfig {
            allowed_connect_ports: vec![],
            allowed_http_ports: vec![],
        };
        assert!(open_egress.is_connect_port_allowed(1234));
        assert!(open_egress.is_http_port_allowed(1234));
    }

    #[test]
    fn test_notifications_muted_domains() {
        let notif = NotificationsConfig::default();
        // Exact match
        assert!(notif.is_domain_muted("browser-intake-us5-datadoghq.com"));
        // Wildcard match
        assert!(notif.is_domain_muted("app.datadoghq.com"));
        assert!(notif.is_domain_muted("datadoghq.com"));
        // Non-muted domain
        assert!(!notif.is_domain_muted("api.weirdapp.com"));
        assert!(!notif.is_domain_muted("notdatadoghq.com"));
    }

    #[test]
    fn test_dlp_allowed_domains() {
        let dlp = DlpConfig {
            enabled: true,
            max_scan_size: 1024,
            action: "block".into(),
            allowed_domains: vec!["*.pkg.dev".into(), "registry.npmjs.org".into()],
            custom_patterns: vec![],
        };

        assert!(dlp.is_domain_allowed("us-central1-docker.pkg.dev"));
        assert!(dlp.is_domain_allowed("docker.pkg.dev"));
        assert!(dlp.is_domain_allowed("registry.npmjs.org"));
        assert!(!dlp.is_domain_allowed("evil-exfil.com"));
    }
}
