//! MitmStream: a newtype wrapper around the decrypted client-side TLS stream
//! that implements Pingora's `IO` trait, allowing MITM-decrypted traffic to flow
//! through the standard ProxyHttp pipeline (caching, filtering, logging).

use async_trait::async_trait;
use dashmap::DashMap;
use pingora_boringssl::tokio_ssl::SslStream;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown,
    SocketDigest, Ssl, TimingDigest, UniqueID, UniqueIDType, Stream,
};
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::raw_connect::ProxyDigest;
use std::fmt;
use std::io;
use std::net::SocketAddr as StdSocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use conduit_common::types::AuthMethod;

/// Global counter for unique MitmStream IDs (used for Pingora's UniqueID trait).
/// Starts at 1_000_000 to avoid collisions with real file descriptors.
/// Constrained to i32 by Pingora's UniqueIDType.
/// Wraps back to 1_000_000 when approaching i32::MAX to stay in the safe range.
static NEXT_MITM_ID: AtomicI32 = AtomicI32::new(1_000_000);

const MITM_ID_MIN: i32 = 1_000_000;
const MITM_ID_MAX: i32 = i32::MAX - 1;

/// Global map threading MITM metadata from handle_connect into request_filter.
/// Uses DashMap for lock-free concurrent reads in the hot path (request_filter)
/// while allowing concurrent writes from response_body_filter without blocking
/// other MITM connections.
/// Keyed by client socket address string (e.g. "192.168.1.1:54321") which is
/// unique per TCP connection.
pub static MITM_CONTEXTS: LazyLock<DashMap<String, MitmContext>> =
    LazyLock::new(DashMap::new);

/// Metadata captured at CONNECT time, consumed by request_filter.
pub struct MitmContext {
    pub client_ip: String,
    pub port: u16,
    pub username: Option<String>,
    pub auth_method: Option<AuthMethod>,
    pub category: Option<String>,
    /// When true, request_filter will reject the next request (tunnel kill).
    pub tunnel_killed: bool,
    /// Accumulated tunnel-level pattern tracker for cross-request phishing detection.
    pub tunnel_patterns: TunnelPatterns,
}

/// Per-tunnel accumulated pattern tracker.
/// Evaluates the sequence of requests holistically to detect phishing sessions
/// that individual request analysis would miss.
pub struct TunnelPatterns {
    pub has_login_path: bool,
    pub has_credential_path: bool,
    pub has_logo_image: bool,
    pub is_free_hosting: bool,
    pub request_count: u32,
    pub t2_fired: bool,
}

impl TunnelPatterns {
    pub fn new(host: &str) -> Self {
        let is_free_hosting = crate::threat::heuristics::is_free_hosting(host);
        Self {
            has_login_path: false,
            has_credential_path: false,
            has_logo_image: false,
            is_free_hosting,
            request_count: 0,
            t2_fired: false,
        }
    }

    pub fn observe_request(&mut self, path: &str, content_type: Option<&str>) {
        self.request_count = self.request_count.saturating_add(1);
        let path_lower = path.to_ascii_lowercase();

        if path_lower.contains("login") || path_lower.contains("signin")
            || path_lower.contains("sign-in") || path_lower.contains("logon")
        {
            self.has_login_path = true;
        }
        if path_lower.contains("account") || path_lower.contains("verify")
            || path_lower.contains("auth") || path_lower.contains("password")
            || path_lower.contains("credential") || path_lower.contains("secure")
        {
            self.has_credential_path = true;
        }

        let is_image = content_type.map(|ct| ct.contains("image")).unwrap_or(false)
            || path_lower.ends_with(".png") || path_lower.ends_with(".jpg")
            || path_lower.ends_with(".svg") || path_lower.ends_with(".ico");
        if is_image {
            let filename = path_lower.rsplit('/').next().unwrap_or("");
            if filename.contains("logo") {
                self.has_logo_image = true;
            }
        }
    }

    /// Evaluate the accumulated tunnel pattern. Returns a score if the pattern
    /// looks like a phishing session, or None if inconclusive.
    pub fn evaluate(&self) -> Option<f32> {
        if self.request_count < 2 {
            return None;
        }
        let mut score = 0.0f32;
        let mut signals = 0u32;

        if self.is_free_hosting {
            score += 0.15;
            signals += 1;
        }
        if self.has_login_path || self.has_credential_path {
            score += 0.25;
            signals += 1;
        }
        if self.has_logo_image {
            score += 0.1;
            signals += 1;
        }

        if signals >= 2 { Some(score.min(1.0)) } else { None }
    }
}

/// Register a MITM context for the given client address.
pub fn register_context(client_addr: String, ctx: MitmContext) {
    MITM_CONTEXTS.insert(client_addr, ctx);
}

/// Remove a MITM context after process_new returns.
pub fn remove_context(client_addr: &str) {
    MITM_CONTEXTS.remove(client_addr);
}

/// Wraps a decrypted client-side TLS stream to implement Pingora's IO trait.
pub struct MitmStream {
    inner: SslStream<Stream>,
    id: i32,
    peer_addr: Option<StdSocketAddr>,
    socket_digest: Arc<SocketDigest>,
}

impl MitmStream {
    pub fn new(inner: SslStream<Stream>, peer_addr: Option<StdSocketAddr>) -> Self {
        let id = loop {
            let val = NEXT_MITM_ID.fetch_add(1, Ordering::Relaxed);
            if val >= MITM_ID_MIN && val <= MITM_ID_MAX {
                break val;
            }
            // Wrapped past safe range — reset and retry
            let _ = NEXT_MITM_ID.compare_exchange(
                val.wrapping_add(1),
                MITM_ID_MIN,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        };

        // Build a SocketDigest with peer_addr pre-populated so that
        // session.client_addr() works correctly in the proxy pipeline.
        let digest = SocketDigest::from_raw_fd(id);
        if let Some(addr) = peer_addr {
            let _ = digest.peer_addr.set(Some(SocketAddr::Inet(addr)));
        }

        Self {
            inner,
            id,
            peer_addr,
            socket_digest: Arc::new(digest),
        }
    }
}

impl fmt::Debug for MitmStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmStream")
            .field("id", &self.id)
            .field("peer_addr", &self.peer_addr)
            .finish()
    }
}

// --- AsyncRead / AsyncWrite: delegate to inner ---

impl AsyncRead for MitmStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MitmStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// --- Pingora IO traits ---

#[async_trait]
impl Shutdown for MitmStream {
    async fn shutdown(&mut self) {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.inner).await;
    }
}

impl UniqueID for MitmStream {
    fn id(&self) -> UniqueIDType {
        self.id
    }
}

impl Ssl for MitmStream {}

impl GetTimingDigest for MitmStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        vec![Some(TimingDigest {
            established_ts: SystemTime::now(),
        })]
    }
}

impl GetProxyDigest for MitmStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for MitmStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(self.socket_digest.clone())
    }
}

impl Peek for MitmStream {}
