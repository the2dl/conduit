use arc_swap::{ArcSwap, Guard};
use boring::pkey::{PKey, Private};
use boring::x509::X509;
use conduit_common::ca::CertAuthority;
use deadpool_redis::Pool;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use tracing::{debug, info, warn};

use super::cert_gen;

/// Cached certificate + key for a domain.
#[derive(Clone)]
pub struct CachedCert {
    pub cert: X509,
    pub key: PKey<Private>,
}

/// Thread-safe LRU cache of generated per-domain certificates.
/// The CA is held behind ArcSwap for lock-free hot-reload on rotation.
pub struct CertCache {
    cache: Mutex<LruCache<String, Arc<CachedCert>>>,
    ca: Arc<ArcSwap<CertAuthority>>,
}

impl CertCache {
    pub fn new(capacity: usize, ca: Arc<ArcSwap<CertAuthority>>) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap()),
            )),
            ca,
        }
    }

    /// Get or generate a certificate for the given domain.
    /// Lock is held only for lookup/insert, not during generation.
    pub fn get_or_generate(&self, domain: &str) -> anyhow::Result<Arc<CachedCert>> {
        // Fast path: check cache
        {
            let mut cache = self.cache.lock();
            if let Some(cached) = cache.get(domain) {
                return Ok(cached.clone());
            }
        }

        // Load current CA (lock-free via ArcSwap)
        let ca = self.ca.load();

        // Slow path: generate (outside lock)
        debug!(domain, "Generating certificate");
        let generated = cert_gen::generate_cert(domain, &ca)?;
        let cached = Arc::new(CachedCert {
            cert: generated.cert,
            key: generated.key,
        });

        // Before inserting, verify the CA hasn't been swapped while we were
        // generating. If it changed, discard this cert (signed by old CA)
        // and regenerate with the new one.
        let ca_now = self.ca.load();
        if !Arc::ptr_eq(&ca, &ca_now) {
            debug!(domain, "CA rotated during cert generation, regenerating");
            let generated = cert_gen::generate_cert(domain, &ca_now)?;
            let cached = Arc::new(CachedCert {
                cert: generated.cert,
                key: generated.key,
            });
            let mut cache = self.cache.lock();
            cache.put(domain.to_string(), cached.clone());
            return Ok(cached);
        }

        // Re-check cache in case another thread generated concurrently
        {
            let mut cache = self.cache.lock();
            if let Some(existing) = cache.get(domain) {
                return Ok(existing.clone());
            }
            cache.put(domain.to_string(), cached.clone());
        }

        Ok(cached)
    }

    /// Get a snapshot of the current CA (lock-free).
    pub fn current_ca(&self) -> Guard<Arc<CertAuthority>> {
        self.ca.load()
    }

    /// Hot-swap the CA and flush all cached per-domain certs.
    pub fn swap_ca(&self, new_ca: Arc<CertAuthority>) {
        self.ca.store(new_ca);
        self.clear();
    }

    /// Flush all cached per-domain certificates.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }
}

// --- Reload infrastructure (same pattern as DLP) ---

static CERT_CACHE_RELOAD_CTX: OnceLock<(Arc<CertCache>, Arc<Pool>)> = OnceLock::new();

/// Register the cert cache for background CA reloads via pub/sub.
pub fn register_for_reload(cache: Arc<CertCache>, pool: Arc<Pool>) {
    let _ = CERT_CACHE_RELOAD_CTX.set((cache, pool));
}

/// Trigger a CA reload from Dragonfly (called by pub/sub handler).
pub fn reload_ca() {
    if let Some((cache, pool)) = CERT_CACHE_RELOAD_CTX.get() {
        let cache = cache.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            match conduit_common::ca::load_ca_from_dragonfly(&pool).await {
                Ok(ca) => {
                    cache.swap_ca(Arc::new(ca));
                    info!("CA reloaded from Dragonfly, cert cache flushed");
                }
                Err(e) => {
                    warn!("Failed to reload CA from Dragonfly: {e}");
                }
            }
        });
    }
}
