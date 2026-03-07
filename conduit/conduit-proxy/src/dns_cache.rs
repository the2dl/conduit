use conduit_common::config::DnsConfig;
use dashmap::DashSet;
use lru::LruCache;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

struct DnsCacheEntry {
    addrs: Vec<SocketAddr>,
    /// Index for round-robin rotation across cached addresses.
    next_index: AtomicUsize,
    expires_at: Instant,
}

pub struct DnsCache {
    cache: Mutex<LruCache<String, DnsCacheEntry>>,
    /// Keys currently being resolved — prevents thundering herd on cache miss.
    inflight: DashSet<String>,
    /// Positive cache TTL (clamped between min and max config values).
    ttl: Duration,
    negative_ttl: Duration,
    enabled: bool,
}

impl DnsCache {
    pub fn new(config: &DnsConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_entries).unwrap_or(NonZeroUsize::new(1).unwrap());
        // tokio::net::lookup_host doesn't expose DNS TTL, so we use the configured max_ttl
        // (clamped to at least min_ttl) as a fixed cache duration.
        let min = Duration::from_secs(config.min_ttl_secs);
        let max = Duration::from_secs(config.max_ttl_secs);
        let ttl = max.max(min);
        DnsCache {
            cache: Mutex::new(LruCache::new(cap)),
            inflight: DashSet::new(),
            ttl,
            negative_ttl: Duration::from_secs(config.negative_ttl_secs),
            enabled: config.enabled,
        }
    }

    /// Resolve a hostname, using the cache if available.
    /// Stores all addresses from DNS and rotates through them on cache hits.
    pub async fn resolve(&self, host: &str, port: u16) -> std::io::Result<SocketAddr> {
        if !self.enabled {
            return self.lookup_first(host, port).await;
        }

        let key = format!("{host}:{port}");

        // Check cache (Mutex because LruCache::get mutates LRU ordering)
        {
            let mut cache = self.cache.lock();
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > Instant::now() {
                    crate::metrics::record_dns_cache_hit();
                    debug!(host = %host, port, "DNS cache hit");
                    if entry.addrs.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "cached negative result",
                        ));
                    }
                    // Round-robin across all cached addresses
                    let idx = entry.next_index.fetch_add(1, Ordering::Relaxed) % entry.addrs.len();
                    return Ok(entry.addrs[idx]);
                }
                cache.pop(&key);
            }
        }

        debug!(host = %host, port, "DNS cache miss");

        // Coalesce concurrent lookups: if another task is already resolving this
        // key, fall back to a direct (uncached) lookup instead of piling on.
        if !self.inflight.insert(key.clone()) {
            return self.lookup_first(host, port).await;
        }

        let result = self.lookup_all(host, port).await;

        match result {
            Ok(addrs) => {
                let first = addrs[0]; // lookup_all guarantees non-empty
                let mut cache = self.cache.lock();
                cache.put(
                    key.clone(),
                    DnsCacheEntry {
                        addrs,
                        next_index: AtomicUsize::new(1), // first caller gets [0], next gets [1]
                        expires_at: Instant::now() + self.ttl,
                    },
                );
                self.inflight.remove(&key);
                Ok(first)
            }
            Err(e) => {
                // Cache negative result
                if self.negative_ttl > Duration::ZERO {
                    let mut cache = self.cache.lock();
                    cache.put(
                        key.clone(),
                        DnsCacheEntry {
                            addrs: vec![],
                            next_index: AtomicUsize::new(0),
                            expires_at: Instant::now() + self.negative_ttl,
                        },
                    );
                }
                self.inflight.remove(&key);
                Err(e)
            }
        }
    }

    /// Resolve and return all addresses (for caching).
    async fn lookup_all(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No addresses found for {host}:{port}"),
            ));
        }
        Ok(addrs)
    }

    /// Resolve and return just the first address (fallback for inflight coalescing).
    async fn lookup_first(&self, host: &str, port: u16) -> std::io::Result<SocketAddr> {
        tokio::net::lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No addresses found for {host}:{port}"),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            max_entries: 100,
            min_ttl_secs: 1,
            max_ttl_secs: 60,
            negative_ttl_secs: 1,
        }
    }

    #[tokio::test]
    async fn test_resolve_and_cache() {
        let cache = DnsCache::new(&test_config());
        // Resolve a known host
        let addr = cache.resolve("127.0.0.1", 80).await.unwrap();
        assert_eq!(addr.port(), 80);
        // Second call should be cache hit
        let addr2 = cache.resolve("127.0.0.1", 80).await.unwrap();
        assert_eq!(addr, addr2);
    }

    #[tokio::test]
    async fn test_disabled() {
        let mut cfg = test_config();
        cfg.enabled = false;
        let cache = DnsCache::new(&cfg);
        let addr = cache.resolve("127.0.0.1", 80).await.unwrap();
        assert_eq!(addr.port(), 80);
    }
}
