//! IP reputation: CIDR matching for known-bad IP ranges.

use deadpool_redis::Pool;
use ipnet::IpNet;
use redis::AsyncCommands;
use std::net::IpAddr;
use tracing::{debug, warn};

/// Check if an IP address falls within any known-bad CIDR range.
pub fn is_bad_ip(bad_cidrs: &[IpNet], ip_str: &str) -> bool {
    // Parse the IP, stripping port if present
    let ip_part = if ip_str.starts_with('[') {
        // IPv6 with port: [::1]:8080
        ip_str
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .unwrap_or(ip_str)
    } else if ip_str.contains(':') && ip_str.matches(':').count() == 1 {
        // IPv4 with port: 1.2.3.4:8080
        ip_str.split(':').next().unwrap_or(ip_str)
    } else {
        ip_str
    };

    let Ok(ip) = ip_part.parse::<IpAddr>() else {
        return false;
    };

    // Binary search to find candidate CIDRs, then check containment.
    // The list is sorted by network address, so we can narrow the search.
    // Fallback to linear scan since IpNet doesn't sort by containment.
    // TODO: Use a trie (ip_network_table crate) for O(1) lookups at scale.
    bad_cidrs.iter().any(|cidr| cidr.contains(&ip))
}

/// Load known-bad CIDRs from Redis set.
pub async fn load_bad_cidrs(pool: &Pool) -> Vec<IpNet> {
    let Ok(mut conn) = pool.get().await else {
        return Vec::new();
    };

    let cidrs: Vec<String> = conn
        .smembers(conduit_common::redis::keys::THREAT_BAD_CIDRS)
        .await
        .unwrap_or_default();

    let mut result: Vec<IpNet> = cidrs
        .iter()
        .filter_map(|s| match s.parse::<IpNet>() {
            Ok(net) => Some(net),
            Err(e) => {
                warn!(cidr = %s, "Invalid CIDR in threat bad_cidrs: {e}");
                None
            }
        })
        .collect();

    result.sort();
    debug!(count = result.len(), "Loaded bad CIDRs from Redis");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_ipv4_cidr() {
        let cidrs: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        assert!(is_bad_ip(&cidrs, "192.168.1.42"));
        assert!(!is_bad_ip(&cidrs, "10.0.0.1"));
    }

    #[test]
    fn match_ipv4_with_port() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(is_bad_ip(&cidrs, "10.1.2.3:8080"));
    }

    #[test]
    fn match_ipv6_cidr() {
        let cidrs: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        assert!(is_bad_ip(&cidrs, "2001:db8::1"));
        assert!(!is_bad_ip(&cidrs, "2001:db9::1"));
    }

    #[test]
    fn no_match_empty() {
        assert!(!is_bad_ip(&[], "1.2.3.4"));
    }

    #[test]
    fn invalid_ip_returns_false() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(!is_bad_ip(&cidrs, "not-an-ip"));
    }
}
