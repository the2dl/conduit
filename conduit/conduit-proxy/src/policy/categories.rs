use arc_swap::ArcSwap;
use conduit_common::redis::keys;
use deadpool_redis::Pool;
use lru::LruCache;
use parking_lot::Mutex;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, trace, warn};

/// Force a cache reload for category lookups (set by pub/sub handler).
static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);

/// Full in-memory domain → category map. Eliminates Redis from the hot path.
/// Loaded at startup and refreshed on pub/sub invalidation via ArcSwap.
static FULL_CATEGORY_MAP: once_cell::sync::Lazy<ArcSwap<HashMap<String, String>>> =
    once_cell::sync::Lazy::new(|| ArcSwap::new(Arc::new(HashMap::new())));

/// TTL for cached category lookups (longer is safe because pub/sub invalidation clears cache).
const CACHE_TTL_SECS: u64 = 300;
/// Maximum number of cached domain → category entries (~8MB at 100K).
const CACHE_CAPACITY: usize = 100_000;

/// Label returned for domains not found in any category list.
const UNCATEGORIZED: &str = "uncategorized";

struct CachedCategory {
    category: String,
    inserted: Instant,
}

static CATEGORY_CACHE: once_cell::sync::Lazy<Mutex<LruCache<String, CachedCategory>>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(CACHE_CAPACITY).unwrap(),
        ))
    });

/// Invalidate the category cache so the next lookup fetches fresh data.
/// Also triggers a background reload of the full category map.
///
/// NOTE: Must be called from within a tokio runtime (spawns a background task).
pub fn invalidate_cache() {
    FORCE_RELOAD.store(true, Ordering::Release);
    // Trigger background reload of full category map if context is registered
    if let Some(pool) = RELOAD_POOL.get() {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pool = pool.clone();
            handle.spawn(async move {
                load_full_dataset(&pool).await;
            });
        }
    }
}

/// Global pool reference for background reloads (set once at startup).
static RELOAD_POOL: once_cell::sync::OnceCell<Arc<Pool>> = once_cell::sync::OnceCell::new();

/// Register the pool for background category map reloads (called once at startup).
pub fn register_for_reload(pool: Arc<Pool>) {
    let _ = RELOAD_POOL.set(pool);
}

/// Look up the category for a domain with wildcard/parent-domain fallback.
/// Checks the full in-memory map first (lock-free), falls back to LRU cache + Redis.
pub async fn lookup_category(pool: &Arc<Pool>, domain: &str) -> Option<String> {
    // Check full in-memory category map first (lock-free via ArcSwap)
    let map = FULL_CATEGORY_MAP.load();
    if !map.is_empty() {
        // Exact match
        if let Some(cat) = map.get(domain) {
            trace!(domain, cached = true, "Category lookup (full map hit)");
            return Some(cat.clone());
        }
        // Wildcard fallback: strip subdomains (iterate by index to avoid O(n²) shifting)
        let parts: Vec<&str> = domain.split('.').collect();
        for start in 1..parts.len().saturating_sub(1) {
            let parent = parts[start..].join(".");
            if let Some(cat) = map.get(&parent) {
                trace!(domain, parent = %parent, cached = true, "Category lookup (full map wildcard)");
                return Some(cat.clone());
            }
        }
        // Domain not in map — it's uncategorized
        return Some(UNCATEGORIZED.to_string());
    }

    // Full map not loaded yet — fall back to LRU cache + Redis
    // If pub/sub signalled a reload, flush the entire cache
    if FORCE_RELOAD.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        CATEGORY_CACHE.lock().clear();
    }

    // Check local cache first
    {
        let mut cache = CATEGORY_CACHE.lock();
        if let Some(entry) = cache.get(domain) {
            if entry.inserted.elapsed().as_secs() < CACHE_TTL_SECS {
                trace!(domain, cached = true, "Category lookup (cache hit)");
                return Some(entry.category.clone());
            }
            // Expired — remove and fall through to Redis
            cache.pop(domain);
        }
    }

    // Cache miss — query Redis, default to "uncategorized"
    let category = lookup_category_redis(pool, domain)
        .await
        .unwrap_or_else(|| UNCATEGORIZED.to_string());

    // Store in cache (including uncategorized to avoid repeated misses)
    {
        let mut cache = CATEGORY_CACHE.lock();
        cache.put(
            domain.to_string(),
            CachedCategory {
                category: category.clone(),
                inserted: Instant::now(),
            },
        );
    }

    Some(category)
}

/// Load the full domain → category dataset from Redis into memory.
/// Uses SCAN to iterate all `cleargate:domain:*` keys without blocking Redis.
pub async fn load_full_dataset(pool: &Arc<Pool>) {
    let Ok(mut conn) = pool.get().await else {
        warn!("Failed to get Redis connection for full category dataset load");
        return;
    };

    let prefix = keys::DOMAIN_CATEGORY_PREFIX;
    let mut map = HashMap::new();
    let mut cursor: u64 = 0;

    loop {
        let (next_cursor, keys): (u64, Vec<String>) = match redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{prefix}*"))
            .arg("COUNT")
            .arg(1000)
            .query_async(&mut *conn)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!("SCAN failed during category dataset load: {e}");
                return;
            }
        };

        if !keys.is_empty() {
            // Batch GET the values
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.get(key);
            }
            let values: Vec<Option<String>> = match pipe.query_async(&mut *conn).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("Pipeline GET failed during category dataset load: {e}");
                    return;
                }
            };

            for (key, value) in keys.iter().zip(values.iter()) {
                if let Some(category) = value {
                    let domain = key.strip_prefix(prefix).unwrap_or(key);
                    map.insert(domain.to_string(), category.clone());
                }
            }
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let count = map.len();
    FULL_CATEGORY_MAP.store(Arc::new(map));
    info!(count, "Loaded full category dataset into memory");
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

    // Wildcard fallback: strip subdomains (iterate by index to avoid O(n²) shifting)
    let parts: Vec<&str> = domain.split('.').collect();
    for start in 1..parts.len().saturating_sub(1) {
        let parent = parts[start..].join(".");
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
