use boring::pkey::{PKey, Private};
use boring::x509::X509;
use conduit_common::ca::CertAuthority;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::debug;

use super::cert_gen;

/// Cached certificate + key for a domain.
#[derive(Clone)]
pub struct CachedCert {
    pub cert: X509,
    pub key: PKey<Private>,
}

/// Thread-safe LRU cache of generated per-domain certificates.
pub struct CertCache {
    cache: Mutex<LruCache<String, Arc<CachedCert>>>,
    ca: Arc<CertAuthority>,
}

impl CertCache {
    pub fn new(capacity: usize, ca: Arc<CertAuthority>) -> Self {
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

        // Slow path: generate (outside lock)
        debug!(domain, "Generating certificate");
        let generated = cert_gen::generate_cert(domain, &self.ca)?;
        let cached = Arc::new(CachedCert {
            cert: generated.cert,
            key: generated.key,
        });

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

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }
}
