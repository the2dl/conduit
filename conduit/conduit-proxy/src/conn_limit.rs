use conduit_common::config::ConnectionLimitConfig;
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::warn;

/// Check if the given client IP or host is a loopback address.
/// Supports IPv4 (127.0.0.0/8), IPv6 (::1), IPv4-mapped loopback (::ffff:127.0.0.1),
/// "localhost", and addresses with port suffixes (e.g. "127.0.0.1:52512").
pub fn is_loopback(client_ip: &str) -> bool {
    let s = client_ip.trim();
    if s.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return addr_is_loopback(&addr);
    }
    if let Ok(saddr) = s.parse::<SocketAddr>() {
        return addr_is_loopback(&saddr.ip());
    }
    false
}

fn addr_is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
    }
}

/// Tracks concurrent connections per client IP.
pub struct ConnectionTracker {
    config: ConnectionLimitConfig,
    connections: Arc<DashMap<String, AtomicU32>>,
}

impl ConnectionTracker {
    pub fn new(config: &ConnectionLimitConfig) -> Self {
        if config.enabled && config.max_connections_per_ip == 0 {
            warn!("Connection limiting is enabled but max_connections_per_ip is 0 (unlimited)");
        }
        ConnectionTracker {
            config: config.clone(),
            connections: Arc::new(DashMap::new()),
        }
    }

    /// Try to acquire a connection slot for the given IP.
    /// Returns Ok(guard) on success, Err(current_count) if over limit.
    pub fn try_acquire(&self, client_ip: &str) -> Result<ConnectionGuard, u32> {
        if !self.config.enabled || self.config.max_connections_per_ip == 0 {
            return Ok(ConnectionGuard {
                connections: self.connections.clone(),
                key: client_ip.to_string(),
                tracking: false,
            });
        }

        // Loopback exemption: localhost traffic from desktop applications
        // is never throttled so local services do not lock out the user.
        if self.config.exempt_loopback && is_loopback(client_ip) {
            return Ok(ConnectionGuard {
                connections: self.connections.clone(),
                key: client_ip.to_string(),
                tracking: false,
            });
        }

        let entry = self
            .connections
            .entry(client_ip.to_string())
            .or_insert_with(|| AtomicU32::new(0));

        // Note: fetch_add + compare is not a single atomic CAS, so under extreme
        // concurrency a brief over-count is possible (one extra connection admitted).
        // This is acceptable for a connection limiter — correctness is eventual.
        let current = entry.value().fetch_add(1, Ordering::AcqRel) + 1;
        if current > self.config.max_connections_per_ip {
            entry.value().fetch_sub(1, Ordering::Release);
            warn!(
                client_ip = %client_ip,
                limit = self.config.max_connections_per_ip,
                current = current - 1,
                "Connection limit exceeded"
            );
            return Err(current - 1);
        }

        Ok(ConnectionGuard {
            connections: self.connections.clone(),
            key: client_ip.to_string(),
            tracking: true,
        })
    }

    /// Periodically clean up entries with zero connections.
    pub fn cleanup(&self) {
        self.connections
            .retain(|_, v| v.load(Ordering::Relaxed) > 0);
    }
}

/// RAII guard that decrements the connection count on drop.
pub struct ConnectionGuard {
    connections: Arc<DashMap<String, AtomicU32>>,
    key: String,
    tracking: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.tracking {
            if let Some(entry) = self.connections.get(&self.key) {
                entry.value().fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config(max: u32) -> ConnectionLimitConfig {
        ConnectionLimitConfig {
            enabled: true,
            max_connections_per_ip: max,
            exempt_loopback: true,
        }
    }

    #[test]
    fn test_disabled() {
        let cfg = ConnectionLimitConfig {
            enabled: false,
            max_connections_per_ip: 1,
            exempt_loopback: true,
        };
        let tracker = ConnectionTracker::new(&cfg);
        let _g1 = tracker.try_acquire("1.2.3.4").unwrap();
        let _g2 = tracker.try_acquire("1.2.3.4").unwrap();
        let _g3 = tracker.try_acquire("1.2.3.4").unwrap();
        // All succeed since disabled
    }

    #[test]
    fn test_limit_enforced() {
        let tracker = ConnectionTracker::new(&enabled_config(2));
        let _g1 = tracker.try_acquire("1.2.3.4").unwrap();
        let _g2 = tracker.try_acquire("1.2.3.4").unwrap();
        assert!(tracker.try_acquire("1.2.3.4").is_err());
        // Different IP should work
        let _g3 = tracker.try_acquire("5.6.7.8").unwrap();
    }

    #[test]
    fn test_guard_releases() {
        let tracker = ConnectionTracker::new(&enabled_config(1));
        {
            let _g = tracker.try_acquire("1.2.3.4").unwrap();
            assert!(tracker.try_acquire("1.2.3.4").is_err());
        }
        // After guard dropped, should be able to acquire again
        let _g = tracker.try_acquire("1.2.3.4").unwrap();
    }

    #[test]
    fn test_cleanup() {
        let tracker = ConnectionTracker::new(&enabled_config(10));
        {
            let _g = tracker.try_acquire("1.2.3.4").unwrap();
        }
        tracker.cleanup();
        assert!(tracker.connections.is_empty());
    }

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.0.0.2"));
        assert!(is_loopback("127.255.255.255"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("::ffff:127.0.0.1"));
        assert!(is_loopback("localhost"));
        assert!(is_loopback("127.0.0.1:52512"));
        assert!(is_loopback("[::1]:52512"));

        assert!(!is_loopback("192.168.1.1"));
        assert!(!is_loopback("10.0.0.1"));
        assert!(!is_loopback("172.16.0.1"));
        assert!(!is_loopback("8.8.8.8"));
        assert!(!is_loopback("example.com"));
    }

    #[test]
    fn test_loopback_exempt_by_default() {
        let tracker = ConnectionTracker::new(&enabled_config(2));
        // Loopback acquires should never be tracked or hit limit
        let _g1 = tracker.try_acquire("127.0.0.1").unwrap();
        let _g2 = tracker.try_acquire("127.0.0.1").unwrap();
        let _g3 = tracker.try_acquire("127.0.0.1").unwrap();
        let _g4 = tracker.try_acquire("::1").unwrap();
        let _g5 = tracker.try_acquire("localhost").unwrap();
        assert_eq!(tracker.connections.len(), 0);

        // Non-loopback should still be tracked and hit limit
        let _g6 = tracker.try_acquire("192.168.1.50").unwrap();
        let _g7 = tracker.try_acquire("192.168.1.50").unwrap();
        assert!(tracker.try_acquire("192.168.1.50").is_err());
    }

    #[test]
    fn test_loopback_exemption_can_be_disabled() {
        let mut cfg = enabled_config(2);
        cfg.exempt_loopback = false;
        let tracker = ConnectionTracker::new(&cfg);
        let _g1 = tracker.try_acquire("127.0.0.1").unwrap();
        let _g2 = tracker.try_acquire("127.0.0.1").unwrap();
        assert!(tracker.try_acquire("127.0.0.1").is_err());
    }
}

