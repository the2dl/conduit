//! Per-domain reputation system with LRU cache and Redis persistence.
//!
//! The LRU cache avoids Redis round-trips in the hot path (Tier 0).
//! Reputation updates happen asynchronously in the logging pipeline.

use conduit_common::redis::keys;
use conduit_common::types::LogEntry;
use deadpool_redis::Pool;
use lru::LruCache;
use parking_lot::Mutex;
use redis::AsyncCommands;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{debug, error, info, trace};

/// Categories representing first-party services whose content we trust.
/// Domains in these categories have login forms and "Sign In" text legitimately,
/// so T2 content analysis should NOT poison their reputation.
///
/// Categories like `cdn_infrastructure`, `domain_hosting`, `other`, etc. are
/// intentionally excluded — those host user-generated content where phishing
/// clones live and reputation should absolutely be written.
const TRUSTED_CATEGORIES: &[&str] = &[
    "search_engine",
    "banking_finance",
    "news_media",
    "government",
    "education",
    "healthcare",
    "streaming_entertainment",
    "telecom_isp",
];

/// Returns true if the category represents a trusted first-party service
/// whose reputation should not be poisoned by T2 content signals.
pub fn is_trusted_category(category: Option<&str>) -> bool {
    category.map_or(false, |c| TRUSTED_CATEGORIES.contains(&c))
}

/// Default LRU cache capacity.
const DEFAULT_CACHE_CAP: usize = 10_000;

/// Create a new reputation LRU cache.
pub fn new_cache() -> Mutex<LruCache<String, CachedReputation>> {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(DEFAULT_CACHE_CAP).unwrap(),
    ))
}

/// Cached reputation entry with a short TTL.
#[derive(Debug, Clone)]
pub struct CachedReputation {
    pub score: f32,
    pub inserted_at: std::time::Instant,
}

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Get a cached reputation score for a domain (LRU only, no Redis fallback).
/// Returns None if not cached or TTL expired.
pub fn get_cached_score(
    cache: &Mutex<LruCache<String, CachedReputation>>,
    domain: &str,
) -> Option<f32> {
    let guard = cache.lock();
    // Use peek() instead of get() to avoid LRU reorder mutation under lock.
    // LRU ordering doesn't matter here since the cache is rebuilt from Redis every 30s.
    if let Some(entry) = guard.peek(domain) {
        if entry.inserted_at.elapsed() < CACHE_TTL {
            return Some(entry.score);
        }
        // Expired — let it be lazily evicted rather than popping under lock
    }
    None
}

/// Seed the LRU cache from Redis on startup so Tier 0 has reputation data
/// immediately without needing async calls in the hot path.
pub async fn seed_cache_from_redis(
    cache: &Mutex<LruCache<String, CachedReputation>>,
    pool: &Pool,
) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };

    let domains: Vec<String> = conn
        .smembers(keys::THREAT_REPUTATION_INDEX)
        .await
        .unwrap_or_default();

    let mut loaded = 0u32;
    for domain in &domains {
        let rep_key = keys::threat_reputation(domain);
        if let Ok(score) = conn.hget::<_, _, f32>(&rep_key, "score").await {
            cache_score(cache, domain.clone(), score);
            loaded += 1;
        }
    }

    if loaded > 0 {
        debug!(loaded, total = domains.len(), "Seeded reputation cache from Redis");
    }
}

/// Insert a reputation score into the cache.
pub fn cache_score(
    cache: &Mutex<LruCache<String, CachedReputation>>,
    domain: String,
    score: f32,
) {
    let mut guard = cache.lock();
    guard.put(
        domain,
        CachedReputation {
            score,
            inserted_at: std::time::Instant::now(),
        },
    );
}

/// Update reputation from a log entry, writing to both Redis and the in-process LRU cache.
/// Called from the logging pipeline (async, off the request path).
///
/// Updates reputation when:
/// 1. The request was blocked at Tier 1+ (not Tier 0 alone, to avoid heuristic false positives).
/// 2. Tier 2+ content analysis found threats with score >= 0.5.
///
/// Tier 0 heuristic blocks are excluded because they are deterministic and can false-positive
/// on high-entropy but legitimate domains. Letting those poison reputation for days (via the
/// decay window) would cause persistent false blocks.
pub async fn update_from_log(
    pool: &Pool,
    entry: &LogEntry,
    decay_hours: u64,
    cache: Option<&Mutex<LruCache<String, CachedReputation>>>,
) {
    let was_blocked = entry.threat_blocked.unwrap_or(false);
    let tier = entry.threat_tier.unwrap_or(conduit_common::types::ThreatTier::Tier0);

    // Tier 2+ content analysis — real findings about domain content
    let dominated_by_content = tier >= conduit_common::types::ThreatTier::Tier2;

    let threat_score_val = entry.threat_score.unwrap_or(0.0);

    // Learn from: blocks at Tier 1+ OR Tier 2+ with score >= 0.5
    // Tier 0 blocks are excluded — heuristic false positives shouldn't persist via reputation.
    let blocked_with_evidence = was_blocked && tier >= conduit_common::types::ThreatTier::Tier1;
    if !blocked_with_evidence && (!dominated_by_content || threat_score_val < 0.5) {
        return;
    }

    // Don't poison reputation for trusted first-party categories (e.g.,
    // search_engine, banking_finance). These sites legitimately contain login
    // forms that T2 flags as phishing patterns. Hosting/infrastructure categories
    // (cdn_infrastructure, domain_hosting) are intentionally NOT protected —
    // phishing clones live there and reputation must be tracked.
    if is_trusted_category(entry.category.as_deref()) {
        return;
    }

    let domain = &entry.host;
    let threat_score = entry.threat_score.unwrap_or(0.0);

    let Ok(mut conn) = pool.get().await else {
        error!("Failed to get Redis connection for reputation update");
        return;
    };

    let rep_key = keys::threat_reputation(domain);

    // Get existing score or default to 0.5 (neutral)
    let existing_score: f32 = conn.hget(&rep_key, "score").await.unwrap_or(0.5);
    let existing_count: u64 = conn.hget(&rep_key, "request_count").await.unwrap_or(0);

    // Calculate time decay
    let last_seen_str: Option<String> = conn.hget(&rep_key, "last_seen").await.unwrap_or(None);
    let hours_elapsed = last_seen_str
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| {
            let elapsed = chrono::Utc::now() - dt.with_timezone(&chrono::Utc);
            (elapsed.num_minutes() as f64 / 60.0).max(0.0)
        })
        .unwrap_or(0.0);

    // Time decay: reputation fades over days/weeks without new Tier 2 signals
    let half_life = decay_hours as f64;
    let decay_factor = (-f64::ln(2.0) * hours_elapsed / half_life).exp();
    let decayed_score = (existing_score as f64 * decay_factor) as f32;

    // Simple rule: take the max of decayed existing reputation and new Tier 2 score.
    // Since we only get here for Tier 2+ signals, every update is meaningful.
    // Time decay is the only thing that pulls reputation back down.
    let new_score = decayed_score.max(threat_score).clamp(0.0, 1.0);

    let now = chrono::Utc::now().to_rfc3339();
    let threat_signals_total: u32 = if threat_score > 0.1 {
        let existing: u32 = conn
            .hget(&rep_key, "threat_signals_total")
            .await
            .unwrap_or(0);
        existing + 1
    } else {
        conn.hget(&rep_key, "threat_signals_total")
            .await
            .unwrap_or(0)
    };

    // Track unique users via a per-domain set
    let users_key = format!("{rep_key}:users");
    let username = entry.username.as_deref().unwrap_or(&entry.client_ip);

    // Pipeline the update
    let mut pipe = redis::pipe();
    pipe.hset(&rep_key, "domain", domain)
        .hset(&rep_key, "score", new_score)
        .hset(&rep_key, "last_seen", &now)
        .hset(&rep_key, "request_count", existing_count + 1)
        .hset(&rep_key, "last_threat_score", threat_score)
        .hset(&rep_key, "threat_signals_total", threat_signals_total)
        .sadd(keys::THREAT_REPUTATION_INDEX, domain)
        // Track unique user
        .sadd(&users_key, username);

    // Set first_seen only if this is a new entry
    if existing_count == 0 {
        pipe.hset(&rep_key, "first_seen", &now);
    }

    if let Err(e) = pipe.exec_async(&mut *conn).await {
        error!(domain, "Failed to update reputation: {e}");
    } else {
        // Update unique_users count from the set cardinality
        let unique_users: u32 = conn.scard(&users_key).await.unwrap_or(0);
        let _: Result<(), _> = conn.hset(&rep_key, "unique_users", unique_users).await;

        // Low user count with threat signals = more suspicious
        // A phishing site typically has 1-5 victims, not 100+ regular users.
        // If unique_users < 10 AND threat_signals_total > 0, boost the score.
        let final_score = if unique_users < 10 && threat_signals_total > 0 && threat_score > 0.1 {
            let user_boost = match unique_users {
                0..=2 => 0.1_f32,
                3..=5 => 0.05,
                _ => 0.02,
            };
            (new_score + user_boost).min(1.0)
        } else {
            new_score
        };

        if final_score != new_score {
            let _: Result<(), _> = conn.hset(&rep_key, "score", final_score).await;
        }

        debug!(domain, score = final_score, unique_users, "Updated reputation");

        // Write back to in-process LRU cache so Tier 0 sees it immediately
        if let Some(cache) = cache {
            cache_score(cache, domain.to_string(), final_score);
        }
    }
}

/// Spawn a background thread that periodically syncs reputation scores from Redis
/// into the local LRU cache. This ensures all proxy nodes converge on the same
/// reputation data within 30s, even when a user's connections shift between nodes.
pub fn spawn_reputation_sync(
    engine: Arc<super::ThreatEngine>,
    pool: Arc<Pool>,
) {
    std::thread::Builder::new()
        .name("cleargate-reputation-sync".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create reputation sync runtime");

            rt.block_on(async move {
                info!("Reputation sync started (30s interval)");

                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                interval.tick().await; // skip first immediate tick (already seeded at startup)

                loop {
                    interval.tick().await;
                    sync_from_redis(&engine.reputation_cache, &pool).await;
                }
            });
        })
        .expect("Failed to spawn reputation sync thread");
}

/// Pull all reputation scores from Redis and update the LRU cache.
/// Uses pipelining to minimize round-trips: one SMEMBERS + batched HGET.
async fn sync_from_redis(
    cache: &Mutex<LruCache<String, CachedReputation>>,
    pool: &Pool,
) {
    let Ok(mut conn) = pool.get().await else {
        error!("Reputation sync: failed to get Redis connection");
        return;
    };

    // Get all tracked domains
    let domains: Vec<String> = match conn.smembers(keys::THREAT_REPUTATION_INDEX).await {
        Ok(d) => d,
        Err(e) => {
            error!("Reputation sync: failed to read index: {e}");
            return;
        }
    };

    if domains.is_empty() {
        return;
    }

    // Batch fetch scores via pipeline (one round-trip for all domains)
    let mut pipe = redis::pipe();
    for domain in &domains {
        pipe.hget(keys::threat_reputation(domain), "score");
    }

    let scores: Vec<Option<f32>> = match pipe.query_async(&mut *conn).await {
        Ok(s) => s,
        Err(e) => {
            error!("Reputation sync: pipeline failed: {e}");
            return;
        }
    };

    // Update cache in a single lock acquisition
    let mut updated = 0u32;
    {
        let mut guard = cache.lock();
        for (domain, score) in domains.iter().zip(scores.iter()) {
            if let Some(score) = score {
                // Only update if the score differs from what's cached (or isn't cached)
                let should_update = match guard.peek(domain) {
                    Some(existing) => (existing.score - score).abs() > f32::EPSILON,
                    None => true,
                };
                if should_update {
                    guard.put(
                        domain.clone(),
                        CachedReputation {
                            score: *score,
                            inserted_at: std::time::Instant::now(),
                        },
                    );
                    updated += 1;
                }
            }
        }
    }

    if updated > 0 {
        trace!(updated, total = domains.len(), "Reputation sync complete");
    }
}
