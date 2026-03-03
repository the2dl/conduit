use chrono::{DateTime, Utc};
use conduit_common::types::{PolicyAction, UserIdentity};

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
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            start_time: Utc::now(),
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
        }
    }

    pub fn full_url(&self) -> String {
        if self.port == 80 && self.scheme == "http"
            || self.port == 443 && self.scheme == "https"
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
