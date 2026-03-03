use async_trait::async_trait;
use pingora_boringssl::ext;
use pingora_boringssl::ssl::SslRef;
use pingora_core::listeners::TlsAccept;
use std::sync::Arc;
use tracing::error;

use super::cert_cache::CertCache;

/// Implements Pingora's TlsAccept trait for dynamic per-SNI certificate injection.
/// Used when the proxy terminates TLS on behalf of MITM-intercepted CONNECT tunnels.
#[allow(dead_code)]
pub struct MitmTlsAcceptor {
    pub cert_cache: Arc<CertCache>,
}

#[async_trait]
impl TlsAccept for MitmTlsAcceptor {
    /// Called during TLS handshake when the certificate needs to be set.
    /// Reads the SNI from the SSL context and injects the appropriate forged certificate.
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl.servername(boring::ssl::NameType::HOST_NAME);
        let domain = match sni {
            Some(d) => d.to_string(),
            None => {
                // No SNI — use default cert (CA cert is already set on the acceptor)
                return;
            }
        };

        match self.cert_cache.get_or_generate(&domain) {
            Ok(cached) => {
                if let Err(e) = ext::ssl_use_certificate(ssl, &cached.cert) {
                    error!("Failed to set cert for {domain}: {e}");
                    return;
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, &cached.key) {
                    error!("Failed to set key for {domain}: {e}");
                    return;
                }
                // Also add CA cert to chain so client can verify
                // (not strictly needed if client trusts our CA directly)
            }
            Err(e) => {
                error!("Failed to generate cert for {domain}: {e}");
            }
        }
    }
}
