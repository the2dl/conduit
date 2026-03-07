use boring::ssl::{SslAcceptor, SslMethod};
use conduit_common::ca::CertAuthority;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{AuthMethod, LogEntry, PolicyAction};
use deadpool_redis::Pool;
use pingora_boringssl::ext;
use pingora_boringssl::tokio_ssl::SslStream;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use pingora_proxy::HttpProxy;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::cert_cache::CertCache;
use super::stream::{self as mitm_stream, MitmContext, MitmStream};
use crate::logging::LogSender;
use crate::proxy::ClearGateProxy;

const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum size of a single header line when reading the block-page request.
const MAX_HEADER_LINE: usize = 8192;
/// Maximum total header block size for the block-page request.
const MAX_BLOCK_PAGE_HEADERS: usize = 65536;
/// Maximum time to read headers for the block page request (slow client protection).
const BLOCK_PAGE_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle a CONNECT tunnel after the 200 response has already been sent.
///
/// If `config.tls_intercept` is true: performs MITM interception by accepting TLS
/// from the client, then routing the decrypted stream through Pingora's ProxyHttp pipeline.
/// If false: passthrough mode — pipes encrypted bytes without inspection.
pub async fn handle_connect_tunnel(
    downstream: Stream,
    host: String,
    port: u16,
    ca: Arc<CertAuthority>,
    cert_cache: Arc<CertCache>,
    config: Arc<ClearGateConfig>,
    _pool: Arc<Pool>,
    log_tx: LogSender,
    client_ip: String,
    category: Option<String>,
    username: Option<String>,
    auth_method: Option<AuthMethod>,
    threat_score: Option<f32>,
    threat_tier: Option<conduit_common::types::ThreatTier>,
    _threat_engine: Option<Arc<crate::threat::ThreatEngine>>,
    http_proxy: Arc<HttpProxy<ClearGateProxy>>,
    shutdown: ShutdownWatch,
) {
    if config.tls_intercept {
        // MITM: TLS accept on client side, then route through Pingora pipeline
        handle_mitm(
            downstream, host, port, ca, cert_cache,
            &client_ip, category, username, auth_method,
            http_proxy, shutdown,
        ).await;
    } else {
        // Passthrough: DNS resolve + TCP connect + bidirectional copy
        let addr = format!("{host}:{port}");
        let start = chrono::Utc::now();

        let resolved_addrs: Vec<std::net::SocketAddr> =
            match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&addr)).await {
                Ok(Ok(addrs)) => addrs.collect(),
                Ok(Err(e)) => {
                    warn!(addr = %addr, "DNS resolution failed: {e}");
                    return;
                }
                Err(_) => {
                    warn!(addr = %addr, "DNS resolution timed out");
                    return;
                }
            };

        let Some(&resolved_addr) = resolved_addrs.first() else {
            warn!(addr = %addr, "DNS resolved to zero addresses");
            return;
        };

        if is_private_ip(resolved_addr.ip()) {
            warn!(addr = %addr, resolved = %resolved_addr, "Blocked connection to private IP (SSRF protection)");
            return;
        }

        let upstream_ip = resolved_addr.to_string();

        let upstream_tcp =
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(resolved_addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!(addr = %addr, resolved = %upstream_ip, "Failed to connect upstream: {e}");
                    return;
                }
                Err(_) => {
                    warn!(addr = %addr, resolved = %upstream_ip, "Connect timed out");
                    return;
                }
            };

        handle_passthrough(downstream, upstream_tcp, host, port, &upstream_ip, start, &log_tx, &client_ip, category, username.as_deref(), auth_method, threat_score, threat_tier).await;
    }
}

/// Accept MITM TLS on the downstream stream. Returns the decrypted stream or None on failure.
async fn mitm_accept(
    downstream: Stream,
    host: &str,
    ca: &CertAuthority,
    cert_cache: &CertCache,
) -> Option<SslStream<Stream>> {
    let acceptor = match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()) {
        Ok(builder) => builder.build(),
        Err(e) => {
            warn!(host = %host, "Failed to build SSL acceptor: {e}");
            return None;
        }
    };

    let ssl = match ext::ssl_from_acceptor(&acceptor) {
        Ok(mut ssl) => {
            match cert_cache.get_or_generate(host) {
                Ok(cached) => {
                    if let Err(e) = ext::ssl_use_certificate(&mut ssl, &cached.cert) {
                        warn!(host = %host, "Failed to set MITM cert: {e}");
                        return None;
                    }
                    if let Err(e) = ext::ssl_use_private_key(&mut ssl, &cached.key) {
                        warn!(host = %host, "Failed to set MITM key: {e}");
                        return None;
                    }
                    if let Err(e) = ext::ssl_add_chain_cert(&mut ssl, &ca.cert) {
                        warn!(host = %host, "Failed to add CA chain cert: {e}");
                        return None;
                    }
                }
                Err(e) => {
                    warn!(host = %host, "Failed to generate MITM cert: {e}");
                    return None;
                }
            }
            ssl
        }
        Err(e) => {
            warn!(host = %host, "Failed to create SSL from acceptor: {e}");
            return None;
        }
    };

    let mut downstream_tls = match SslStream::new(ssl, downstream) {
        Ok(s) => s,
        Err(e) => {
            warn!(host = %host, "Failed to create downstream TLS stream: {e}");
            return None;
        }
    };

    match tokio::time::timeout(TLS_TIMEOUT, Pin::new(&mut downstream_tls).accept()).await {
        Ok(Ok(())) => Some(downstream_tls),
        Ok(Err(e)) => {
            debug!(host = %host, "TLS accept failed (client may not trust CA): {e}");
            None
        }
        Err(_) => {
            warn!(host = %host, "TLS accept timed out");
            None
        }
    }
}

/// Serve a block page over MITM TLS. Accepts the TLS handshake with a forged cert,
/// reads the client's HTTP request, then responds with the block page HTML.
pub async fn serve_block_page(
    downstream: Stream,
    host: &str,
    ca: &CertAuthority,
    cert_cache: &CertCache,
    block_html: &str,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let Some(downstream_tls) = mitm_accept(downstream, host, ca, cert_cache).await else {
        return;
    };

    let mut reader = BufReader::new(downstream_tls);

    // Read and discard the client's HTTP request headers (with size + time limits)
    let header_read = async {
        let mut total_header_bytes = 0usize;
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) => return false,
                Ok(_) => {
                    total_header_bytes += line.len();
                    if line.len() > MAX_HEADER_LINE || total_header_bytes > MAX_BLOCK_PAGE_HEADERS {
                        return false;
                    }
                    if line == b"\r\n" || line == b"\n" {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    };

    match tokio::time::timeout(BLOCK_PAGE_HEADER_TIMEOUT, header_read).await {
        Ok(true) => {}      // headers read successfully
        Ok(false) => return, // oversized or connection closed
        Err(_) => return,    // timed out (slow client)
    }

    // Send HTTP response with block page
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        block_html.len(),
        block_html
    );

    let writer = reader.get_mut();
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
}

/// MITM mode: accept TLS from client, wrap decrypted stream as MitmStream,
/// then route through Pingora's ProxyHttp pipeline for full HTTP handling.
async fn handle_mitm(
    downstream: Stream,
    host: String,
    port: u16,
    ca: Arc<CertAuthority>,
    cert_cache: Arc<CertCache>,
    client_ip: &str,
    category: Option<String>,
    username: Option<String>,
    auth_method: Option<AuthMethod>,
    http_proxy: Arc<HttpProxy<ClearGateProxy>>,
    shutdown: ShutdownWatch,
) {
    // Parse client_ip into a SocketAddr for the MitmStream's socket digest
    let peer_addr: Option<std::net::SocketAddr> = client_ip.parse().ok();

    // TLS accept on downstream (MITM)
    let downstream_tls = match mitm_accept(downstream, &host, &ca, &cert_cache).await {
        Some(s) => s,
        None => return,
    };

    debug!(host = %host, "MITM TLS accepted");

    // Wrap in MitmStream (implements Pingora's IO trait)
    let mitm = MitmStream::new(downstream_tls, peer_addr);
    let stream_id = mitm.id();

    // Register context for request_filter to pick up
    mitm_stream::register_context(stream_id, MitmContext {
        client_ip: client_ip.to_string(),
        port,
        username,
        auth_method,
        category,
        tunnel_killed: false,
        tunnel_patterns: mitm_stream::TunnelPatterns::new(&host),
    });

    // Route through Pingora's ProxyHttp pipeline
    let stream: Stream = Box::new(mitm);
    let _ = http_proxy.process_new(stream, &shutdown).await;

    // Clean up context
    mitm_stream::remove_context(stream_id);

    debug!(host = %host, "MITM tunnel closed");
}

/// Passthrough mode: pipe encrypted bytes without inspection.
async fn handle_passthrough(
    mut downstream: Stream,
    mut upstream: TcpStream,
    host: String,
    port: u16,
    upstream_ip: &str,
    start: chrono::DateTime<chrono::Utc>,
    log_tx: &LogSender,
    client_ip: &str,
    category: Option<String>,
    username: Option<&str>,
    auth_method: Option<AuthMethod>,
    threat_score: Option<f32>,
    threat_tier: Option<conduit_common::types::ThreatTier>,
) {
    debug!(host = %host, port, upstream_ip = %upstream_ip, "Passthrough tunnel established");

    match tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok((down_to_up, up_to_down)) => {
            debug!(host = %host, port, down_to_up, up_to_down, "Passthrough tunnel completed");

            let entry = LogEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: start,
                client_ip: client_ip.to_string(),
                username: username.map(|s| s.to_string()),
                auth_method,
                method: "CONNECT".into(),
                scheme: "https".into(),
                host: host.clone(),
                port,
                path: "/".into(),
                full_url: format!("https://{host}:{port}/"),
                category,
                action: PolicyAction::Allow,
                rule_id: None,
                status_code: 200,
                request_bytes: down_to_up,
                response_bytes: up_to_down,
                duration_ms: (chrono::Utc::now() - start).num_milliseconds().max(0) as u64,
                tls_intercepted: false,
                upstream_addr: Some(upstream_ip.to_string()),
                content_type: None,
                cache_status: None,
                node_id: None,
                node_name: None,
                threat_score,
                threat_tier,
                threat_blocked: Some(false),
                block_reason: None,
                rule_name: None,
                threat_signals: None,
                dlp_matches: None,
            };
            log_tx.send(entry);
        }
        Err(e) => {
            debug!(host = %host, port, "Passthrough tunnel error: {e}");
        }
    }
}

/// Check if an IP address is in a private/reserved range (SSRF protection).
pub(crate) fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_unspecified() // 0.0.0.0
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()           // ::1
                || v6.is_unspecified() // ::
                || is_ipv6_ula(&v6)    // fc00::/7 — Unique Local Address
                || is_ipv6_link_local(&v6)  // fe80::/10
                || is_ipv4_mapped_private(&v6) // ::ffff:10.x.x.x, etc.
        }
    }
}

/// fc00::/7 — Unique Local Address (IPv6 equivalent of RFC 1918).
fn is_ipv6_ula(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — Link-local addresses.
fn is_ipv6_link_local(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) that map to private IPv4 ranges.
/// Prevents bypassing IPv4 checks via ::ffff:127.0.0.1, ::ffff:10.0.0.1, etc.
fn is_ipv4_mapped_private(v6: &std::net::Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
    } else {
        false
    }
}

