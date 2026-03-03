use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-request log entry written to all sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub username: Option<String>,
    pub auth_method: Option<AuthMethod>,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub full_url: String,
    pub category: Option<String>,
    pub action: PolicyAction,
    pub rule_id: Option<String>,
    pub status_code: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_ms: u64,
    pub tls_intercepted: bool,
    pub upstream_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Node ID that generated this log entry (multi-node deployments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Human-readable node name (multi-node deployments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

/// How the user was identified.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Kerberos,
    Basic,
    IpMap,
}

/// Resolved identity for a request.
#[derive(Debug, Clone, Default)]
pub struct UserIdentity {
    pub username: Option<String>,
    pub auth_method: Option<AuthMethod>,
    pub groups: Vec<String>,
}

/// What the policy engine decided to do with a request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Block,
    Log,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Allow
    }
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub priority: i64,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub action: PolicyAction,
}

/// Domain category entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryEntry {
    pub domain: String,
    pub category: String,
}

/// Stats counters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub active_connections: u64,
    pub tls_intercepted: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

// ---------------------------------------------------------------------------
// Multi-node types
// ---------------------------------------------------------------------------

/// Current status of a proxy node.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Pending,
    Active,
    Inactive,
}

/// Stored registration data for a proxy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub id: String,
    pub name: String,
    pub status: NodeStatus,
    pub dragonfly_user: String,
    pub created_at: DateTime<Utc>,
    pub enrolled_at: Option<DateTime<Utc>>,
}

/// Heartbeat payload sent periodically by each proxy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    pub node_id: String,
    pub timestamp: DateTime<Utc>,
    pub uptime_secs: u64,
    pub active_connections: u64,
    pub total_requests: u64,
    pub version: String,
    pub listen_addr: String,
    pub host: String,
    /// HMAC-SHA256 signature of the heartbeat payload (excludes this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Full node info returned by the API (registration + live heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(flatten)]
    pub registration: NodeRegistration,
    pub heartbeat: Option<NodeHeartbeat>,
    pub online: bool,
    /// Whether the last heartbeat's HMAC signature was verified.
    pub heartbeat_verified: bool,
}

/// One-time enrollment credentials returned when a node is created.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeEnrollment {
    pub node_id: String,
    pub dragonfly_url: String,
    pub dragonfly_user: String,
    pub dragonfly_password: String,
    /// One-time enrollment token the proxy must present during self-registration.
    pub enrollment_token: String,
    /// HMAC key for signing heartbeats (base64url, 32 bytes).
    pub hmac_key: String,
}

impl std::fmt::Debug for NodeEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEnrollment")
            .field("node_id", &self.node_id)
            .field("dragonfly_url", &"[redacted]")
            .field("dragonfly_user", &self.dragonfly_user)
            .field("dragonfly_password", &"[redacted]")
            .field("enrollment_token", &"[redacted]")
            .field("hmac_key", &"[redacted]")
            .finish()
    }
}

/// Per-node stats breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStats {
    pub node_id: String,
    pub node_name: String,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub tls_intercepted: u64,
    pub active_connections: u64,
    pub online: bool,
}
