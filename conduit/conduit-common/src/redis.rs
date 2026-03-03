use deadpool_redis::{Config, Pool, Runtime};

/// Create a deadpool-redis connection pool.
pub fn create_pool(url: &str, pool_size: usize) -> anyhow::Result<Pool> {
    let cfg = Config::from_url(url);
    let pool = cfg.builder()?
        .max_size(pool_size)
        .runtime(Runtime::Tokio1)
        .build()?;
    Ok(pool)
}

/// Verify connectivity to Dragonfly/Redis with a PING.
/// Returns a clear error on AUTH failure or network issues.
pub async fn verify_connection(pool: &Pool) -> anyhow::Result<()> {
    let mut conn = pool.get().await.map_err(|e| anyhow::anyhow!("Failed to get connection from pool: {e}"))?;
    let _: String = redis::cmd("PING")
        .query_async(&mut *conn)
        .await
        .map_err(|e| anyhow::anyhow!("Dragonfly PING failed (check credentials / ACL): {e}"))?;
    Ok(())
}

/// Strip control characters and limit length for use as a Redis key component.
pub fn sanitize_key_component(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .take(253)
        .collect()
}

// Dragonfly/Redis key constants
pub mod keys {
    use super::sanitize_key_component;

    /// Domain category: GET cleargate:domain:{domain} → category
    pub fn domain_category(domain: &str) -> String {
        let safe = sanitize_key_component(domain);
        format!("cleargate:domain:{safe}")
    }

    /// All policy rules (sorted set, score = priority)
    pub const POLICIES: &str = "cleargate:policies";

    /// Log list (newest first)
    pub const LOGS: &str = "cleargate:logs";

    /// IP-to-user mapping hash
    pub const IP_MAP: &str = "cleargate:ip_map";

    /// Request counter
    pub const STATS_REQUESTS: &str = "cleargate:stats:requests";

    /// Blocked counter
    pub const STATS_BLOCKED: &str = "cleargate:stats:blocked";

    /// TLS intercepted counter
    pub const STATS_TLS: &str = "cleargate:stats:tls";

    /// Active connections gauge
    pub const STATS_ACTIVE: &str = "cleargate:stats:active";

    /// Config hash
    pub const CONFIG: &str = "cleargate:config";

    // --- Multi-node keys ---

    /// Node registration hash: HSET cleargate:nodes:{id}
    pub fn node(node_id: &str) -> String {
        let safe = sanitize_key_component(node_id);
        format!("cleargate:nodes:{safe}")
    }

    /// Set of all node IDs
    pub const NODES_INDEX: &str = "cleargate:nodes:index";

    /// Node heartbeat (STRING with TTL): SET cleargate:nodes:{id}:heartbeat
    pub fn node_heartbeat(node_id: &str) -> String {
        let safe = sanitize_key_component(node_id);
        format!("cleargate:nodes:{safe}:heartbeat")
    }

    /// Log stream (replaces LOGS list for new deployments)
    pub const LOG_STREAM: &str = "cleargate:logs:stream";

    /// Consumer group name for the API
    pub const LOG_STREAM_GROUP: &str = "api";

    /// Pub/sub channel for config reload notifications
    pub const CONFIG_RELOAD_CHANNEL: &str = "cleargate:config:reload";

    /// Per-node stat counter: cleargate:stats:{node_id}:{stat}
    pub fn stats_node(node_id: &str, stat: &str) -> String {
        let safe_id = sanitize_key_component(node_id);
        let safe_stat = sanitize_key_component(stat);
        format!("cleargate:stats:{safe_id}:{safe_stat}")
    }

    // --- Threat detection keys ---

    /// Serialized bloom filter bitmap
    pub const THREAT_BLOOM: &str = "cleargate:threat:bloom";
    /// Bloom filter metadata (entry_count, updated_at)
    pub const THREAT_BLOOM_META: &str = "cleargate:threat:bloom:meta";
    /// Set of all tracked reputation domains
    pub const THREAT_REPUTATION_INDEX: &str = "cleargate:threat:reputation:index";
    /// Hash of all configured threat feeds
    pub const THREAT_FEEDS: &str = "cleargate:threat:feeds";
    /// Set of known-bad CIDRs
    pub const THREAT_BAD_CIDRS: &str = "cleargate:threat:bad_cidrs";
    /// Pub/sub channel for bloom/feed reload notifications
    pub const THREAT_RELOAD_CHANNEL: &str = "cleargate:threat:reload";

    /// Threat-specific stat counters
    pub const STATS_THREAT_BLOCKS: &str = "cleargate:stats:threat_blocks";
    pub const STATS_THREAT_T0: &str = "cleargate:stats:threat_t0";
    pub const STATS_THREAT_T1: &str = "cleargate:stats:threat_t1";
    pub const STATS_THREAT_T2: &str = "cleargate:stats:threat_t2";
    pub const STATS_THREAT_T3: &str = "cleargate:stats:threat_t3";

    /// Per-domain reputation hash: cleargate:threat:reputation:{domain}
    pub fn threat_reputation(domain: &str) -> String {
        let safe = sanitize_key_component(domain);
        format!("cleargate:threat:reputation:{safe}")
    }

    /// Per-feed config/state: cleargate:threat:feed:{feed_id}
    pub fn threat_feed(feed_id: &str) -> String {
        let safe = sanitize_key_component(feed_id);
        format!("cleargate:threat:feed:{safe}")
    }
}
