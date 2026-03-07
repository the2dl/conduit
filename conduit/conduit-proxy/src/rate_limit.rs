use conduit_common::config::RateLimitConfig;
use pingora_limits::rate::Rate;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Rate limiter wrapping pingora-limits Rate instances for per-IP, per-user,
/// and per-destination rate limiting.
pub struct RateLimiter {
    pub config: RateLimitConfig,
    per_ip: Option<Arc<Rate>>,
    per_user: Option<Arc<Rate>>,
    per_destination: Option<Arc<Rate>>,
}

/// Which limit was exceeded.
#[derive(Debug)]
pub enum LimitKind {
    PerIp,
    PerUser,
    PerDestination,
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let interval = Duration::from_secs(config.window_secs);
        let hashes = config.estimator_hashes;
        let slots = config.estimator_slots;

        let per_ip = if config.per_ip_limit > 0 {
            Some(Arc::new(Rate::new_with_estimator_config(interval, hashes, slots)))
        } else {
            None
        };
        let per_user = if config.per_user_limit > 0 {
            Some(Arc::new(Rate::new_with_estimator_config(interval, hashes, slots)))
        } else {
            None
        };
        let per_destination = if config.per_destination_limit > 0 {
            Some(Arc::new(Rate::new_with_estimator_config(interval, hashes, slots)))
        } else {
            None
        };

        if config.enabled && config.per_ip_limit == 0 && config.per_user_limit == 0 && config.per_destination_limit == 0 {
            warn!("Rate limiting is enabled but all limits are 0 (unlimited)");
        }

        RateLimiter {
            config: config.clone(),
            per_ip,
            per_user,
            per_destination,
        }
    }

    /// Check rate limits and return Ok if allowed, Err with the kind of limit exceeded.
    ///
    /// Checks all limits with `observe(0)` first to avoid inflating counters for
    /// requests that will be rejected. Only increments counters if all checks pass.
    pub fn check_rate(
        &self,
        client_ip: &str,
        username: Option<&str>,
        destination: &str,
    ) -> Result<(), LimitKind> {
        if !self.config.enabled {
            return Ok(());
        }

        // Pre-check: peek at current counts without incrementing
        if let Some(ref rate) = self.per_ip {
            let count = rate.observe(&client_ip.to_string(), 0);
            if count >= self.config.per_ip_limit as isize {
                warn!(
                    client_ip = %client_ip,
                    limit = self.config.per_ip_limit,
                    count = count,
                    "Rate limited (per-IP)"
                );
                return Err(LimitKind::PerIp);
            }
        }

        if let Some(ref rate) = self.per_user {
            if let Some(user) = username {
                let count = rate.observe(&user.to_string(), 0);
                if count >= self.config.per_user_limit as isize {
                    warn!(
                        username = %user,
                        client_ip = %client_ip,
                        limit = self.config.per_user_limit,
                        count = count,
                        "Rate limited (per-user)"
                    );
                    return Err(LimitKind::PerUser);
                }
            }
        }

        if let Some(ref rate) = self.per_destination {
            let count = rate.observe(&destination.to_string(), 0);
            if count >= self.config.per_destination_limit as isize {
                warn!(
                    destination = %destination,
                    client_ip = %client_ip,
                    limit = self.config.per_destination_limit,
                    count = count,
                    "Rate limited (per-destination)"
                );
                return Err(LimitKind::PerDestination);
            }
        }

        // All checks passed — now increment all applicable counters
        if let Some(ref rate) = self.per_ip {
            rate.observe(&client_ip.to_string(), 1);
        }
        if let Some(ref rate) = self.per_user {
            if let Some(user) = username {
                rate.observe(&user.to_string(), 1);
            }
        }
        if let Some(ref rate) = self.per_destination {
            rate.observe(&destination.to_string(), 1);
        }

        Ok(())
    }

    /// Return the window in seconds for the Retry-After header.
    pub fn window_secs(&self) -> u64 {
        self.config.window_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(per_ip: usize) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            window_secs: 1,
            per_ip_limit: per_ip,
            per_user_limit: 0,
            per_destination_limit: 0,
            estimator_hashes: 4,
            estimator_slots: 128,
        }
    }

    #[test]
    fn test_disabled() {
        let mut cfg = test_config(5);
        cfg.enabled = false;
        let rl = RateLimiter::new(&cfg);
        // Should always pass when disabled
        for _ in 0..100 {
            assert!(rl.check_rate("1.2.3.4", None, "example.com").is_ok());
        }
    }

    #[test]
    fn test_per_ip_limit() {
        let rl = RateLimiter::new(&test_config(3));
        assert!(rl.check_rate("1.2.3.4", None, "example.com").is_ok());
        assert!(rl.check_rate("1.2.3.4", None, "example.com").is_ok());
        assert!(rl.check_rate("1.2.3.4", None, "example.com").is_ok());
        // 4th should fail
        assert!(rl.check_rate("1.2.3.4", None, "example.com").is_err());
        // Different IP should still pass
        assert!(rl.check_rate("5.6.7.8", None, "example.com").is_ok());
    }

    #[test]
    fn test_all_unlimited() {
        let rl = RateLimiter::new(&test_config(0));
        for _ in 0..100 {
            assert!(rl.check_rate("1.2.3.4", None, "example.com").is_ok());
        }
    }
}
