use std::net::SocketAddr;
use tracing::warn;

/// IP version filtering policy, parsed from config `ip_version` field.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    /// Use whatever the OS returns (no filtering).
    Any,
    /// Only use IPv4 addresses. Returns empty vec if no IPv4 exists (strict).
    V4Only,
    /// Only use IPv6 addresses. Returns empty vec if no IPv6 exists (strict).
    V6Only,
    /// Use IPv4 when available, fall back to IPv6.
    V4Preferred,
}

impl IpVersion {
    pub fn from_config(s: &str) -> Self {
        match s {
            "any" => Self::Any,
            "v4_only" => Self::V4Only,
            "v6_only" => Self::V6Only,
            "v4_preferred" => Self::V4Preferred,
            other => {
                warn!(
                    value = other,
                    "Unknown ip_version value, defaulting to v4_preferred. \
                     Valid values: any, v4_only, v6_only, v4_preferred"
                );
                Self::V4Preferred
            }
        }
    }

    /// Filter a list of resolved addresses according to the policy.
    ///
    /// For `V4Only`/`V6Only`: returns only matching addresses (may be empty — caller
    /// should treat empty as a resolution failure). For `V4Preferred`: falls back to
    /// the full list when no IPv4 exists.
    pub fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        match self {
            Self::Any => addrs,
            Self::V4Only => {
                addrs.into_iter().filter(|a| a.is_ipv4()).collect()
            }
            Self::V6Only => {
                addrs.into_iter().filter(|a| !a.is_ipv4()).collect()
            }
            Self::V4Preferred => {
                let v4: Vec<_> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
                if v4.is_empty() { addrs } else { v4 }
            }
        }
    }

    /// Pick the best single address from a resolved set.
    /// For `V4Only`/`V6Only`: returns `None` if no matching address exists.
    pub fn pick_first(&self, addrs: &[SocketAddr]) -> Option<SocketAddr> {
        match self {
            Self::Any => addrs.first().copied(),
            Self::V4Only => {
                addrs.iter().find(|a| a.is_ipv4()).copied()
            }
            Self::V4Preferred => {
                addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied()
            }
            Self::V6Only => {
                addrs.iter().find(|a| !a.is_ipv4()).copied()
            }
        }
    }
}
