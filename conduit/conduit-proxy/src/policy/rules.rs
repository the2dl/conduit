use conduit_common::redis::keys;
use conduit_common::types::{PolicyAction, PolicyRule};
use deadpool_redis::Pool;
use redis::AsyncCommands;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{trace, warn};

/// Force a cache reload on the next evaluation (set by pub/sub handler).
static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);

/// Invalidate the rules cache so the next evaluation reloads from Dragonfly.
pub fn invalidate_cache() {
    FORCE_RELOAD.store(true, Ordering::Release);
}

/// How often to reload policy rules from Dragonfly.
const CACHE_TTL_SECS: u64 = 5;

/// Maximum age of stale cache before we refuse to use it (5 minutes).
const MAX_STALE_SECS: u64 = 300;

struct CachedRules {
    rules: Vec<PolicyRule>,
    loaded_at: Instant,
}

static RULES_CACHE: OnceLock<RwLock<Option<CachedRules>>> = OnceLock::new();

fn cache() -> &'static RwLock<Option<CachedRules>> {
    RULES_CACHE.get_or_init(|| RwLock::new(None))
}

/// Evaluate all enabled policy rules against the request.
/// Returns the action from the highest-priority matching rule, or Allow if none match.
/// The third element is the human-readable rule name (when a rule matched).
/// When `fail_closed` is true, requests are blocked if rules cannot be loaded.
pub async fn evaluate(
    pool: &Arc<Pool>,
    domain: &str,
    category: Option<&str>,
    username: Option<&str>,
    groups: &[String],
    fail_closed: bool,
) -> (PolicyAction, Option<String>, Option<String>) {
    let rules = match load_rules_cached(pool).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to load policy rules: {e}");
            if fail_closed {
                return (PolicyAction::Block, None, None);
            }
            return (PolicyAction::Allow, None, None);
        }
    };

    for rule in &rules {
        if !rule.enabled {
            continue;
        }
        if matches_rule(rule, domain, category, username, groups) {
            trace!(rule_id = %rule.id, action = ?rule.action, "Policy match");
            let name = if rule.name.is_empty() { None } else { Some(rule.name.clone()) };
            return (rule.action, Some(rule.id.clone()), name);
        }
    }

    (PolicyAction::Allow, None, None)
}

/// Load rules from cache if fresh, otherwise reload from Dragonfly.
/// On Redis failure, returns stale cached rules if available.
async fn load_rules_cached(pool: &Arc<Pool>) -> anyhow::Result<Vec<PolicyRule>> {
    let forced = FORCE_RELOAD.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok();

    // Fast path: read from fresh cache (skip if forced reload)
    if !forced {
        let guard = cache().read().await;
        if let Some(ref cached) = *guard {
            if cached.loaded_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(cached.rules.clone());
            }
        }
    }

    // Slow path: reload from Dragonfly
    match load_rules_from_dragonfly(pool).await {
        Ok(rules) => {
            let mut guard = cache().write().await;
            *guard = Some(CachedRules {
                rules: rules.clone(),
                loaded_at: Instant::now(),
            });
            Ok(rules)
        }
        Err(e) => {
            // Use stale cache if available and not too old
            let guard = cache().read().await;
            if let Some(ref cached) = *guard {
                let age = cached.loaded_at.elapsed().as_secs();
                if age <= MAX_STALE_SECS {
                    warn!("Redis failed, using stale policy cache ({age}s old): {e}");
                    return Ok(cached.rules.clone());
                }
                warn!("Redis failed and stale cache too old ({age}s > {MAX_STALE_SECS}s limit), discarding: {e}");
            }
            Err(e)
        }
    }
}

/// Load rules from Dragonfly sorted set, ordered by priority (ascending).
async fn load_rules_from_dragonfly(pool: &Arc<Pool>) -> anyhow::Result<Vec<PolicyRule>> {
    let mut conn = pool.get().await?;
    let raw: Vec<String> = conn.zrangebyscore(keys::POLICIES, "-inf", "+inf").await?;

    let mut rules = Vec::with_capacity(raw.len());
    for json_str in &raw {
        match serde_json::from_str::<PolicyRule>(json_str) {
            Ok(rule) => rules.push(rule),
            Err(e) => warn!("Invalid policy rule JSON: {e}"),
        }
    }

    Ok(rules)
}

/// Check if a rule matches the current request context.
fn matches_rule(
    rule: &PolicyRule,
    domain: &str,
    category: Option<&str>,
    username: Option<&str>,
    groups: &[String],
) -> bool {
    // Category match
    if !rule.categories.is_empty() {
        let cat = category.unwrap_or("");
        if !rule.categories.iter().any(|c| c == cat) {
            return false;
        }
    }

    // Domain match (supports wildcard prefix with proper dot boundary)
    if !rule.domains.is_empty() {
        let domain_match = rule.domains.iter().any(|d| {
            if let Some(suffix) = d.strip_prefix("*.") {
                domain == suffix || domain.ends_with(&format!(".{suffix}"))
            } else {
                domain == d
            }
        });
        if !domain_match {
            return false;
        }
    }

    // User match
    if !rule.users.is_empty() {
        let user = username.unwrap_or("");
        if !rule.users.iter().any(|u| u == user) {
            return false;
        }
    }

    // Group match
    if !rule.groups.is_empty() {
        let group_match = rule.groups.iter().any(|g| groups.contains(g));
        if !group_match {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matching_categories() {
        let rule = PolicyRule {
            id: "r1".into(),
            priority: 1,
            name: "Block social".into(),
            enabled: true,
            categories: vec!["social".into()],
            domains: vec![],
            users: vec![],
            groups: vec![],
            action: PolicyAction::Block,
        };

        assert!(matches_rule(&rule, "facebook.com", Some("social"), None, &[]));
        assert!(!matches_rule(&rule, "google.com", Some("search"), None, &[]));
        assert!(!matches_rule(&rule, "google.com", None, None, &[]));
    }

    #[test]
    fn test_rule_matching_wildcard_domain() {
        let rule = PolicyRule {
            id: "r2".into(),
            priority: 1,
            name: "Block example".into(),
            enabled: true,
            categories: vec![],
            domains: vec!["*.example.com".into()],
            users: vec![],
            groups: vec![],
            action: PolicyAction::Block,
        };

        assert!(matches_rule(&rule, "sub.example.com", None, None, &[]));
        assert!(matches_rule(&rule, "example.com", None, None, &[]));
        assert!(!matches_rule(&rule, "other.com", None, None, &[]));
        // Must not match domains that merely end with the suffix without a dot boundary
        assert!(!matches_rule(&rule, "notexample.com", None, None, &[]));
    }

    #[test]
    fn test_rule_matching_empty_filters() {
        // Rule with no filters matches everything
        let rule = PolicyRule {
            id: "r3".into(),
            priority: 100,
            name: "Catch all".into(),
            enabled: true,
            categories: vec![],
            domains: vec![],
            users: vec![],
            groups: vec![],
            action: PolicyAction::Log,
        };

        assert!(matches_rule(&rule, "anything.com", None, None, &[]));
    }
}
