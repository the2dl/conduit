use conduit_common::config::LoadBalancingConfig;
use futures::FutureExt;
use pingora_core::protocols::l4::socket::SocketAddr as PSocketAddr;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;
use std::sync::Arc;
use tracing::{info, warn};

/// Domain-to-upstream-group routing with Pingora load balancers.
pub struct UpstreamRouter {
    /// Map from upstream group name to its LB instance.
    groups: Vec<UpstreamGroupEntry>,
}

struct UpstreamGroupEntry {
    name: String,
    /// Domain patterns (lowercase). Supports simple glob: "*" at start.
    domains: Vec<String>,
    lb: Arc<LoadBalancer<RoundRobin>>,
}

impl UpstreamRouter {
    pub fn new(config: &LoadBalancingConfig) -> Self {
        let mut groups = Vec::new();

        for group_cfg in &config.upstreams {
            match build_lb(group_cfg) {
                Ok(lb) => {
                    info!(
                        name = %group_cfg.name,
                        domains = ?group_cfg.domains,
                        backends = group_cfg.backends.len(),
                        "Load balancer group initialized"
                    );
                    groups.push(UpstreamGroupEntry {
                        name: group_cfg.name.clone(),
                        domains: group_cfg.domains.iter().map(|d| d.to_lowercase()).collect(),
                        lb: Arc::new(lb),
                    });
                }
                Err(e) => {
                    warn!(name = %group_cfg.name, "Failed to create LB group: {e}");
                }
            }
        }

        UpstreamRouter { groups }
    }

    /// Find the upstream backend for a given host.
    /// Returns the selected backend's socket address if matched.
    pub fn find_upstream(&self, host: &str) -> Option<(std::net::SocketAddr, &str)> {
        let host_lower = host.to_lowercase();
        for group in &self.groups {
            for pattern in &group.domains {
                if domain_matches(pattern, &host_lower) {
                    // Select a backend using round-robin.
                    // 256 = max iterations for the selection algorithm to converge.
                    if let Some(backend) = group.lb.select(host.as_bytes(), 256) {
                        if let PSocketAddr::Inet(addr) = &backend.addr {
                            return Some((addr.clone(), &group.name));
                        }
                    } else {
                        warn!(group = %group.name, "LB select returned None");
                    }
                }
            }
        }
        None
    }

    /// Check if a host matches any load-balanced domain (used to skip caching).
    pub fn matches_domain(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        for group in &self.groups {
            for pattern in &group.domains {
                if domain_matches(pattern, &host_lower) {
                    return true;
                }
            }
        }
        false
    }
}

/// Match a domain against a pattern. Supports exact match and leading wildcard
/// (e.g., "*.example.com" matches "sub.example.com" and bare "example.com").
fn domain_matches(pattern: &str, host: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        host.ends_with(suffix) || host == &pattern[2..]
    } else {
        host == pattern
    }
}

fn build_lb(group: &conduit_common::config::UpstreamGroup) -> anyhow::Result<LoadBalancer<RoundRobin>> {
    use pingora_load_balancing::{Backend, Backends, discovery};
    use std::collections::BTreeSet;

    let mut backends = BTreeSet::new();
    for b in &group.backends {
        let backend = Backend::new_with_weight(&b.addr, b.weight)
            .map_err(|e| anyhow::anyhow!("Invalid backend addr '{}': {e}", b.addr))?;
        backends.insert(backend);
    }

    let discovery = discovery::Static::new(backends);
    let lb_backends = Backends::new(discovery);
    let lb = LoadBalancer::from_backends(lb_backends);
    lb.update()
        .now_or_never()
        .expect("static should not block")
        .expect("static should not error");

    // TODO: Wire up HealthCheckConfig when present in group.health_check.
    // Currently health_check is config-only; no active health checking is performed.

    Ok(lb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_common::config::{LoadBalancingConfig, UpstreamBackend, UpstreamGroup};

    #[test]
    fn test_domain_matching() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "other.com"));
        assert!(domain_matches("*.example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "other.com"));
    }

    #[test]
    fn test_router_select() {
        let config = LoadBalancingConfig {
            enabled: true,
            upstreams: vec![UpstreamGroup {
                name: "test".into(),
                domains: vec!["api.test.local".into()],
                algorithm: "round_robin".into(),
                backends: vec![UpstreamBackend {
                    addr: "127.0.0.1:9000".into(),
                    weight: 1,
                }],
                health_check: None,
            }],
        };

        let router = UpstreamRouter::new(&config);
        let result = router.find_upstream("api.test.local");
        assert!(result.is_some());
        let (addr, name) = result.unwrap();
        assert_eq!(addr.port(), 9000);
        assert_eq!(name, "test");

        // Non-matching domain
        assert!(router.find_upstream("other.com").is_none());
    }

    #[test]
    fn test_round_robin_alternates() {
        let config = LoadBalancingConfig {
            enabled: true,
            upstreams: vec![UpstreamGroup {
                name: "rr-test".into(),
                domains: vec!["lb.test.local".into()],
                algorithm: "round_robin".into(),
                backends: vec![
                    UpstreamBackend { addr: "127.0.0.1:9001".into(), weight: 1 },
                    UpstreamBackend { addr: "127.0.0.1:9002".into(), weight: 1 },
                ],
                health_check: None,
            }],
        };

        let router = UpstreamRouter::new(&config);
        let mut ports: Vec<u16> = Vec::new();
        for _ in 0..6 {
            let (addr, _) = router.find_upstream("lb.test.local").unwrap();
            ports.push(addr.port());
        }
        println!("Selected ports: {:?}", ports);
        // Should alternate between 9001 and 9002
        assert!(ports.contains(&9001), "should select 9001");
        assert!(ports.contains(&9002), "should select 9002");
    }

    #[test]
    fn test_matches_domain() {
        let config = LoadBalancingConfig {
            enabled: true,
            upstreams: vec![UpstreamGroup {
                name: "test".into(),
                domains: vec!["lb.test.local".into()],
                algorithm: "round_robin".into(),
                backends: vec![UpstreamBackend {
                    addr: "127.0.0.1:9000".into(),
                    weight: 1,
                }],
                health_check: None,
            }],
        };

        let router = UpstreamRouter::new(&config);
        assert!(router.matches_domain("lb.test.local"));
        assert!(!router.matches_domain("other.com"));
    }
}
