use conduit_common::redis::keys;
use deadpool_redis::Pool;
use lru::LruCache;
use parking_lot::Mutex;
use redis::AsyncCommands;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::trace;

/// Force a cache reload for category lookups (set by pub/sub handler).
static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);

/// TTL for cached category lookups.
const CACHE_TTL_SECS: u64 = 60;
/// Maximum number of cached domain → category entries.
const CACHE_CAPACITY: usize = 10_000;

/// Sentinel value for "we looked this up and it had no category".
const NO_CATEGORY: &str = "\x00__none__";

struct CachedCategory {
    category: String, // NO_CATEGORY sentinel if uncategorized
    inserted: Instant,
}

static CATEGORY_CACHE: once_cell::sync::Lazy<Mutex<LruCache<String, CachedCategory>>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(CACHE_CAPACITY).unwrap(),
        ))
    });

/// Invalidate the category cache so the next lookup fetches fresh data.
pub fn invalidate_cache() {
    FORCE_RELOAD.store(true, Ordering::Release);
}

/// Look up the category for a domain with wildcard/parent-domain fallback.
/// Uses an in-process LRU cache with 60s TTL to minimize Redis round-trips.
pub async fn lookup_category(pool: &Arc<Pool>, domain: &str) -> Option<String> {
    // If pub/sub signalled a reload, flush the entire cache
    if FORCE_RELOAD.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        CATEGORY_CACHE.lock().clear();
    }

    // Check local cache first
    {
        let mut cache = CATEGORY_CACHE.lock();
        if let Some(entry) = cache.get(domain) {
            if entry.inserted.elapsed().as_secs() < CACHE_TTL_SECS {
                let result = if entry.category == NO_CATEGORY {
                    None
                } else {
                    Some(entry.category.clone())
                };
                trace!(domain, cached = true, "Category lookup (cache hit)");
                return result;
            }
            // Expired — remove and fall through to Redis
            cache.pop(domain);
        }
    }

    // Cache miss — query Redis
    let result = lookup_category_redis(pool, domain).await;

    // Store in cache (including negative results to avoid repeated misses)
    {
        let mut cache = CATEGORY_CACHE.lock();
        cache.put(
            domain.to_string(),
            CachedCategory {
                category: result.clone().unwrap_or_else(|| NO_CATEGORY.to_string()),
                inserted: Instant::now(),
            },
        );
    }

    result
}

/// The actual Redis lookup with wildcard fallback.
async fn lookup_category_redis(pool: &Arc<Pool>, domain: &str) -> Option<String> {
    let mut conn = pool.get().await.ok()?;

    // Try exact match first
    let key = keys::domain_category(domain);
    if let Ok(cat) = conn.get::<_, Option<String>>(&key).await {
        if cat.is_some() {
            trace!(domain, category = ?cat, "Category hit (exact)");
            return cat;
        }
    }

    // Wildcard fallback: strip subdomains
    let mut parts: Vec<&str> = domain.split('.').collect();
    while parts.len() > 2 {
        parts.remove(0);
        let parent = parts.join(".");
        let key = keys::domain_category(&parent);
        if let Ok(cat) = conn.get::<_, Option<String>>(&key).await {
            if cat.is_some() {
                trace!(domain, parent = %parent, category = ?cat, "Category hit (wildcard)");
                return cat;
            }
        }
    }

    None
}
