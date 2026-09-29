use chrono::{DateTime, Utc};
use conduit_common::types::{BlockReason, PolicyAction, ThreatVerdict, UserIdentity};

use crate::threat::heuristics::{CertMeta, SecurityHeaders};

/// Per-request context carried through the Pingora filter chain.
pub struct RequestContext {
    pub start_time: DateTime<Utc>,
    pub client_ip: String,
    pub identity: UserIdentity,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub path: String,
    pub category: Option<String>,
    pub action: PolicyAction,
    pub rule_id: Option<String>,
    pub tls_intercepted: bool,
    pub is_connect: bool,
    pub response_status: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub upstream_addr: Option<String>,
    pub threat_verdict: Option<ThreatVerdict>,
    pub block_reason: Option<BlockReason>,
    pub rule_name: Option<String>,
    /// Buffer for Tier 2 content inspection (first N bytes of response body).
    /// Only populated when Tier 1 escalated.
    pub threat_inspect_buffer: Option<Vec<u8>>,
    /// Response content-type (captured in response_filter for Tier 2).
    pub response_content_type: Option<String>,
    /// Response Location header (captured for redirect chain analysis).
    pub response_location: Option<String>,
    /// Whether caching was enabled for this request.
    pub cache_enabled: bool,
    /// Cache status string (hit, miss, expired, etc.).
    pub cache_status: Option<String>,
    /// MITM client address for tunnel pattern tracking and tunnel kill.
    pub mitm_client_addr: Option<String>,
    /// Upstream TLS certificate metadata (captured in connected_to_upstream).
    pub cert_meta: Option<CertMeta>,
    /// Upstream response security headers (captured in response_filter).
    pub security_headers: Option<SecurityHeaders>,
    /// Accumulated request body bytes for size limiting.
    pub request_body_accumulated: usize,
    /// Buffer for DLP scanning of outbound request body.
    pub dlp_body_buffer: Option<Vec<u8>>,
    /// When true, upstream was selected by load balancer — skip SSRF check.
    pub lb_routed: bool,
    /// Unique request ID.
    pub req_id: String,
    /// Human-friendly short reference ID (e.g. cnd-7f3a-91c2) for block pages and logs.
    pub ref_id: String,
    /// DLP pattern names that matched (populated at end of request body stream).
    pub dlp_matches: Option<Vec<String>>,
    /// Masked snippet of DLP match for display on block pages.
    pub dlp_matched_snippet: Option<String>,
    /// Buffer for package security scanning of inbound package archive bodies.
    pub package_body_buffer: Option<Vec<u8>>,
    /// Whether this request is an identified package archive download.
    pub is_package_download: bool,
    /// YARA / supply chain threat match details if detected: (rule_name, infected_file).
    pub package_threat_match: Option<(String, String)>,
}

impl RequestContext {
    pub fn new() -> Self {
        let uuid_val = uuid::Uuid::new_v4();
        let simple_hex = uuid_val.simple().to_string();
        let ref_id = format!("cnd-{}-{}", &simple_hex[..4], &simple_hex[4..8]);
        let req_id = uuid_val.to_string();

        Self {
            start_time: Utc::now(),
            req_id,
            ref_id,
            client_ip: String::new(),
            identity: UserIdentity::default(),
            host: String::new(),
            port: 80,
            scheme: "http".into(),
            path: String::new(),
            category: None,
            action: PolicyAction::Allow,
            rule_id: None,
            tls_intercepted: false,
            is_connect: false,
            response_status: 0,
            request_bytes: 0,
            response_bytes: 0,
            upstream_addr: None,
            threat_verdict: None,
            block_reason: None,
            rule_name: None,
            threat_inspect_buffer: None,
            response_content_type: None,
            response_location: None,
            cache_enabled: false,
            cache_status: None,
            mitm_client_addr: None,
            cert_meta: None,
            security_headers: None,
            request_body_accumulated: 0,
            dlp_body_buffer: None,
            lb_routed: false,
            dlp_matches: None,
            dlp_matched_snippet: None,
            package_body_buffer: None,
            is_package_download: false,
            package_threat_match: None,
        }
    }

    pub fn full_url(&self) -> String {
        if (self.port == 80 && self.scheme == "http")
            || (self.port == 443 && self.scheme == "https")
        {
            format!("{}://{}{}", self.scheme, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }

    pub fn duration_ms(&self) -> u64 {
        let elapsed = Utc::now() - self.start_time;
        elapsed.num_milliseconds().max(0) as u64
    }
}
