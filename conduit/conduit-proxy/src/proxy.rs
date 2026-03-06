use async_trait::async_trait;
use bytes::Bytes;
use conduit_common::ca::CertAuthority;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{BlockReason, LogEntry, PolicyAction};
use deadpool_redis::Pool;
use http::Method;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::eviction::EvictionManager;
use pingora_cache::filters;
use pingora_cache::lock::CacheKeyLockImpl;
use pingora_cache::storage::Storage;
use pingora_cache::key::CacheKey;
use pingora_cache::{CacheMetaDefaults, NoCacheReason, RespCacheable};
use pingora_core::protocols::Digest;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

use crate::ctx::RequestContext;
use crate::identity;
use crate::logging::LogSender;
use crate::mitm::cert_cache::CertCache;
use crate::policy;
use crate::threat::ThreatEngine;

/// Core proxy struct implementing Pingora's ProxyHttp trait.
pub struct ClearGateProxy {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    #[allow(dead_code)] // Held for Arc reference; MITM uses ClearGateService's copy
    pub ca: Arc<CertAuthority>,
    #[allow(dead_code)]
    pub cert_cache: Arc<CertCache>,
    pub log_tx: LogSender,
    pub threat_engine: Option<Arc<ThreatEngine>>,
    // HTTP response caching
    pub cache_storage: Option<&'static (dyn Storage + Sync)>,
    pub cache_eviction: Option<&'static (dyn EvictionManager + Sync)>,
    pub cache_lock: Option<&'static CacheKeyLockImpl>,
    pub cache_meta_defaults: Option<&'static CacheMetaDefaults>,
    pub cache_max_file_size: usize,
}

impl ClearGateProxy {
    pub fn new(
        config: Arc<ClearGateConfig>,
        pool: Arc<Pool>,
        ca: Arc<CertAuthority>,
        cert_cache: Arc<CertCache>,
        log_tx: mpsc::Sender<LogEntry>,
        threat_engine: Option<Arc<ThreatEngine>>,
        cache_storage: Option<&'static (dyn Storage + Sync)>,
        cache_eviction: Option<&'static (dyn EvictionManager + Sync)>,
        cache_lock: Option<&'static CacheKeyLockImpl>,
        cache_meta_defaults: Option<&'static CacheMetaDefaults>,
        cache_max_file_size: usize,
    ) -> Self {
        Self {
            config,
            pool,
            ca,
            cert_cache,
            log_tx: LogSender(log_tx),
            threat_engine,
            cache_storage,
            cache_eviction,
            cache_lock,
            cache_meta_defaults,
            cache_max_file_size,
        }
    }

    /// Extract host and port from the request (works for both regular and CONNECT).
    fn extract_host_port(session: &Session) -> (String, u16) {
        let req = session.req_header();
        let uri = &req.uri;

        // For CONNECT, the URI is host:port
        if req.method == Method::CONNECT {
            let authority = uri.to_string();
            return parse_host_port(&authority, 443);
        }

        // Try the Host header first
        if let Some(host_hdr) = req.headers.get("host") {
            if let Ok(h) = host_hdr.to_str() {
                return parse_host_port(h, 80);
            }
        }

        // Fall back to URI authority
        if let Some(authority) = uri.authority() {
            return parse_host_port(authority.as_str(), 80);
        }

        ("unknown".into(), 80)
    }

    fn build_block_page(&self, host: &str, category: &str, reason: &str) -> Bytes {
        Bytes::from(crate::service::build_block_html(host, category, reason, &self.config))
    }
}

/// Extract just the path (+ query string) from a URI.
/// For absolute-form proxy URIs like `http://host/path?q=1`, returns `/path?q=1`.
/// For origin-form URIs like `/path?q=1`, returns as-is.
fn extract_path_from_uri(uri: &http::Uri) -> String {
    // If the URI has scheme+authority (absolute form), strip them.
    if uri.authority().is_some() {
        let path = uri.path();
        match uri.query() {
            Some(q) => format!("{path}?{q}"),
            None => {
                if path.is_empty() {
                    "/".to_string()
                } else {
                    path.to_string()
                }
            }
        }
    } else {
        // Pingora may store absolute-form URIs without parsing scheme/authority,
        // so path_and_query() returns e.g. "/http://host/path". Handle by
        // re-parsing the full URI string if it looks like an absolute URL.
        let raw = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".into());

        if raw.starts_with("/http://") || raw.starts_with("/https://") {
            // Strip the leading "/" and re-parse as a proper URI
            if let Ok(reparsed) = raw[1..].parse::<http::Uri>() {
                let path = reparsed.path();
                return match reparsed.query() {
                    Some(q) => format!("{path}?{q}"),
                    None if path.is_empty() => "/".to_string(),
                    None => path.to_string(),
                };
            }
        }

        raw
    }
}

fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    // Handle IPv6 [::1]:port
    if let Some(bracket_end) = s.find(']') {
        let host = &s[..=bracket_end];
        let port = s[bracket_end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }

    match s.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (s.to_string(), default_port),
        },
        None => (s.to_string(), default_port),
    }
}

#[async_trait]
impl ProxyHttp for ClearGateProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    /// Main request filter — runs before upstream connection.
    /// Handles: client IP extraction, user identification, category lookup, policy check.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Check if this is a MITM-intercepted connection by looking up the
        // stream's unique ID in the MITM context map. The ID is stored as the
        // raw_fd in the SocketDigest at MitmStream construction time.
        // COUPLING: This relies on MitmStream::new() storing the synthetic ID
        // via SocketDigest::from_raw_fd(). See mitm/stream.rs.
        let mitm_stream_id = session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .map(|sd| sd.raw_fd());

        let mitm_ctx = mitm_stream_id.and_then(|fd| {
            crate::mitm::stream::MITM_CONTEXTS.get(&fd).map(|mc| {
                (
                    mc.client_ip.clone(),
                    mc.port,
                    mc.username.clone(),
                    mc.auth_method,
                    mc.category.clone(),
                    mc.tunnel_killed,
                )
            })
        });

        if let Some((mitm_client_ip, mitm_port, mitm_username, mitm_auth_method, mitm_category, tunnel_killed)) =
            mitm_ctx
        {
            // MITM request: populate context from stored CONNECT-time metadata
            ctx.client_ip = mitm_client_ip;
            ctx.tls_intercepted = true;
            ctx.scheme = "https".into();
            ctx.mitm_stream_id = mitm_stream_id;

            ctx.is_connect = false;

            // If the tunnel was killed by a prior request's threat detection, reject immediately
            if tunnel_killed {
                let body = self.build_block_page(&ctx.host, "threat-detected", "Tunnel terminated (threat detected)");
                let mut resp = ResponseHeader::build(403, Some(3))?;
                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                resp.insert_header("Content-Length", &body.len().to_string())?;
                resp.insert_header("Connection", "close")?;
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(body), true).await?;
                ctx.response_status = 403;
                ctx.action = PolicyAction::Block;
                ctx.block_reason = Some(BlockReason::ThreatHeuristic);
                return Ok(true);
            }

            // Extract host from request headers (inner HTTP request)
            let (host, _) = Self::extract_host_port(session);
            ctx.host = host;
            ctx.port = mitm_port;
            ctx.path = extract_path_from_uri(&session.req_header().uri);

            // Identity from CONNECT-time auth (skip re-auth)
            ctx.identity = conduit_common::types::UserIdentity {
                username: mitm_username,
                auth_method: mitm_auth_method,
                groups: vec![],
            };

            // Category from CONNECT-time lookup
            ctx.category = mitm_category;

            // Skip auth check — already validated at CONNECT time
        } else {
            // Normal (non-MITM) request path
            ctx.client_ip = session
                .downstream_session
                .client_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();

            let req = session.req_header();
            ctx.is_connect = req.method == Method::CONNECT;

            // Extract host/port
            let (host, port) = Self::extract_host_port(session);
            ctx.host = host;
            ctx.port = port;

            if ctx.is_connect {
                ctx.scheme = "https".into();
                ctx.path = "/".into();
            } else {
                let uri = &session.req_header().uri;
                ctx.scheme = if uri.scheme_str() == Some("https") {
                    "https".into()
                } else {
                    "http".into()
                };
                ctx.path = extract_path_from_uri(uri);
            }

            // Identify user (Kerberos -> Basic -> IP map)
            ctx.identity = identity::identify(session, &self.pool, &self.config).await;

            // If auth required and no user identified, send 407
            if self.config.auth_required && ctx.identity.username.is_none() {
                let mut resp = ResponseHeader::build(407, Some(4))?;
                resp.insert_header("Proxy-Authenticate", "Basic realm=\"Conduit\"")?;
                resp.insert_header("Content-Length", "0")?;
                session
                    .write_response_header(Box::new(resp), true)
                    .await?;
                ctx.response_status = 407;
                return Ok(true);
            }
        }

        // Category lookup (skip for MITM — already set from CONNECT-time context)
        if !ctx.tls_intercepted {
            ctx.category = policy::categories::lookup_category(&self.pool, &ctx.host).await;
        }

        // Threat detection: deterministic heuristics + reputation check
        if let Some(ref engine) = self.threat_engine {
            let verdict = crate::threat::evaluate_request(
                engine,
                &ctx.host,
                ctx.port,
                &ctx.path,
                &ctx.scheme,
                ctx.category.as_deref(),
                ctx.upstream_addr.as_deref(),
                None, None,
            );

            // Block if heuristics say block OR reputation (from prior Tier 2 findings) says block
            let rep_block = crate::threat::check_reputation(engine, &ctx.host);
            let should_block = verdict.blocked || rep_block.is_some();

            if should_block {
                let score = rep_block.unwrap_or(verdict.score);
                ctx.action = PolicyAction::Block;
                ctx.block_reason = Some(if rep_block.is_some() {
                    BlockReason::ThreatReputation
                } else {
                    BlockReason::ThreatHeuristic
                });
                ctx.threat_verdict = Some(conduit_common::types::ThreatVerdict {
                    score,
                    blocked: true,
                    ..verdict
                });
                let reason_text = if rep_block.is_some() {
                    "Threat detected (reputation)"
                } else {
                    "Threat detected (heuristic)"
                };
                debug!(host = %ctx.host, score, "Blocking request (threat detected)");
                let body = self.build_block_page(&ctx.host, "threat-detected", reason_text);
                let mut resp = ResponseHeader::build(403, Some(3))?;
                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                resp.insert_header("Content-Length", &body.len().to_string())?;
                resp.insert_header("Connection", "close")?;
                session
                    .write_response_header(Box::new(resp), false)
                    .await?;
                session.write_response_body(Some(body), true).await?;
                ctx.response_status = 403;
                return Ok(true);
            }
            ctx.threat_verdict = Some(verdict);
        }

        // Policy evaluation
        let (action, rule_id, matched_rule_name) = policy::rules::evaluate(
            &self.pool,
            &ctx.host,
            ctx.category.as_deref(),
            ctx.identity.username.as_deref(),
            &ctx.identity.groups,
            self.config.fail_closed,
        )
        .await;
        ctx.action = action;
        ctx.rule_id = rule_id;
        ctx.rule_name = matched_rule_name;

        // Block if policy says so
        if ctx.action == PolicyAction::Block {
            ctx.block_reason = Some(BlockReason::Policy);
            let reason_text = match ctx.rule_name {
                Some(ref name) => format!("Policy rule: {name}"),
                None => "Policy".to_string(),
            };
            debug!(host = %ctx.host, category = ?ctx.category, "Blocking request");
            let body = self.build_block_page(
                &ctx.host,
                ctx.category.as_deref().unwrap_or("uncategorized"),
                &reason_text,
            );
            let mut resp = ResponseHeader::build(403, Some(3))?;
            resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
            resp.insert_header("Content-Length", &body.len().to_string())?;
            resp.insert_header("Connection", "close")?;
            session
                .write_response_header(Box::new(resp), false)
                .await?;
            session.write_response_body(Some(body), true).await?;
            ctx.response_status = 403;
            return Ok(true);
        }

        Ok(false)
    }

    /// Decide where to forward the request.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        use pingora_core::protocols::l4::socket::SocketAddr as PSocketAddr;

        let tls = ctx.scheme == "https" || ctx.is_connect;

        // Resolve DNS asynchronously to avoid blocking the tokio runtime
        let sock_addr = tokio::net::lookup_host((ctx.host.as_str(), ctx.port))
            .await
            .map_err(|e| {
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!("DNS resolution failed for {}:{} — {e}", ctx.host, ctx.port))
            })?
            .next()
            .ok_or_else(|| {
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!("No addresses found for {}:{}", ctx.host, ctx.port))
            })?;

        // SSRF protection: reject connections to private/loopback IPs before connecting
        if crate::mitm::tunnel::is_private_ip(sock_addr.ip()) {
            return Err(pingora_error::Error::new(
                pingora_error::ErrorType::ConnectProxyFailure,
            ).more_context(format!(
                "Blocked connection to private IP {} (SSRF protection)",
                sock_addr
            )));
        }

        let mut peer = HttpPeer::new_from_sockaddr(
            PSocketAddr::Inet(sock_addr),
            tls,
            ctx.host.clone(),
        );
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.total_connection_timeout = Some(std::time::Duration::from_secs(15));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(60));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(60));
        Ok(Box::new(peer))
    }

    /// Modify request before sending upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Strip proxy auth headers
        upstream_request.remove_header("Proxy-Authorization");

        // Add forwarding headers
        if !ctx.client_ip.is_empty() {
            upstream_request.insert_header("X-Forwarded-For", &ctx.client_ip)?;
        }

        Ok(())
    }

    /// Track request body size.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(b) = body {
            ctx.request_bytes += b.len() as u64;
        }
        Ok(())
    }

    /// Enable caching for cacheable GET/HEAD requests.
    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Only enable when cache storage is configured and request is cacheable
        if let Some(storage) = self.cache_storage {
            if !ctx.is_connect && filters::request_cacheable(session.req_header()) {
                session.cache.enable(
                    storage,
                    self.cache_eviction,
                    None, // predictor
                    self.cache_lock,
                    None, // option_overrides
                );
                session.cache.set_max_file_size_bytes(self.cache_max_file_size);
                ctx.cache_enabled = true;
            }
        }
        Ok(())
    }

    /// Build cache key from scheme + host + URI.
    /// The default Pingora key is just the raw URI, which for MITM requests is
    /// a relative path like "/". That causes cross-host collisions — every MITM
    /// request to "/" would share a cache entry. Including scheme and host makes
    /// the key unique per origin.
    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let uri = &session.req_header().uri;
        let primary = format!("{}://{}:{}{}", ctx.scheme, ctx.host, ctx.port, uri);
        Ok(CacheKey::new(String::new(), primary, ""))
    }

    /// Determine whether the upstream response is cacheable based on Cache-Control headers.
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let cc = CacheControl::from_resp_headers(resp);
        let has_auth = false; // proxy doesn't forward Authorization to cache decisions
        if let Some(defaults) = self.cache_meta_defaults {
            Ok(filters::resp_cacheable(cc.as_ref(), resp.clone(), has_auth, defaults))
        } else {
            Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("no defaults")))
        }
    }

    /// Capture resolved upstream address after connection is established.
    /// Also enforces SSRF protection by rejecting connections to private IPs.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(digest) = digest {
            if let Some(ref socket_digest) = digest.socket_digest {
                if let Some(addr) = socket_digest.peer_addr() {
                    ctx.upstream_addr = Some(addr.to_string());

                    // SSRF protection: reject connections to private/loopback IPs
                    if let Some(inet) = addr.as_inet() {
                        if crate::mitm::tunnel::is_private_ip(inet.ip()) {
                            return Err(pingora_error::Error::new(
                                pingora_error::ErrorType::ConnectProxyFailure,
                            ).more_context(format!(
                                "Blocked connection to private IP {} (SSRF protection)",
                                inet
                            )));
                        }
                    }
                }
            }

            // Extract TLS certificate metadata for threat scoring.
            // Pingora's SslDigest only exposes issuer organization; validity dates
            // and SAN count would require raw X.509 access (not available here).
            if let Some(ref ssl_digest) = digest.ssl_digest {
                use crate::threat::heuristics::CertMeta;
                ctx.cert_meta = Some(CertMeta {
                    issuer_org: ssl_digest.organization.clone(),
                    not_before_unix: None,
                    not_after_unix: None,
                    san_count: 0,
                });
            }
        }
        Ok(())
    }

    /// Capture response status code and headers for Tier 2 content inspection.
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();

        // Add X-Cache-Status header when caching is enabled
        if ctx.cache_enabled {
            let status = session.cache.phase().as_str();
            ctx.cache_status = Some(status.to_string());
            let _ = upstream_response.insert_header("X-Cache-Status", status);
        }

        // Capture headers needed for Tier 2 content analysis
        if let Some(ct) = upstream_response.headers.get("content-type") {
            ctx.response_content_type = ct.to_str().ok().map(String::from);
        }
        if let Some(loc) = upstream_response.headers.get("location") {
            ctx.response_location = loc.to_str().ok().map(String::from);
        }

        // Extract security headers for threat scoring
        {
            use crate::threat::heuristics::SecurityHeaders;
            ctx.security_headers = Some(SecurityHeaders {
                has_hsts: upstream_response.headers.contains_key("strict-transport-security"),
                has_csp: upstream_response.headers.contains_key("content-security-policy"),
                has_xfo: upstream_response.headers.contains_key("x-frame-options"),
                has_xcto: upstream_response.headers.contains_key("x-content-type-options"),
            });
        }

        // Merge cert and security header signals into existing verdict.
        // Only runs the targeted checks (not the full heuristic pipeline again).
        if let Some(ref mut existing) = ctx.threat_verdict {
            use crate::threat::heuristics::{cert_risk, security_header_score};
            let mut extra_signals = Vec::new();
            if let Some(ref meta) = ctx.cert_meta {
                extra_signals.extend(cert_risk(&ctx.host, meta));
            }
            if let Some(ref headers) = ctx.security_headers {
                extra_signals.extend(security_header_score(&ctx.host, headers));
            }
            for sig in extra_signals {
                if !existing.signals.iter().any(|s| s.name == sig.name) {
                    if sig.score > existing.score {
                        existing.score = sig.score;
                    }
                    existing.signals.push(sig);
                }
            }
        }

        // Start buffering for Tier 2 content inspection when:
        // 1. Tier 1 already escalated (T0 score was suspicious), OR
        // 2. Response is HTML and the domain has any nonzero threat score
        //    (catches phishing sites on clean-looking domains like auth.re)
        if let Some(ref engine) = self.threat_engine {
            if engine.config.tier2_enabled {
                let t1_escalated = ctx.threat_verdict.as_ref()
                    .map(|v| v.tier_reached >= conduit_common::types::ThreatTier::Tier1)
                    .unwrap_or(false);

                let ct = ctx.response_content_type.as_deref().unwrap_or("");
                let is_inspectable = ct.contains("html") || ct.contains("javascript");

                let has_any_threat_score = ctx.threat_verdict.as_ref()
                    .map(|v| v.score > 0.05)
                    .unwrap_or(false);

                let uncategorized = ctx.category.is_none();

                if t1_escalated || (is_inspectable && (has_any_threat_score || uncategorized)) {
                    ctx.threat_inspect_buffer = Some(Vec::with_capacity(8192));
                }
            }
        }

        Ok(())
    }

    /// Track response body size + buffer for Tier 2 content inspection.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if let Some(b) = body {
            ctx.response_bytes += b.len() as u64;

            // Tap response bytes into inspection buffer (up to max_inspect_bytes)
            if let Some(ref mut buf) = ctx.threat_inspect_buffer {
                let max = self
                    .threat_engine
                    .as_ref()
                    .map(|e| e.config.max_inspect_bytes)
                    .unwrap_or(0);
                if buf.len() < max {
                    let remaining = max - buf.len();
                    buf.extend_from_slice(&b[..b.len().min(remaining)]);
                }
            }
        }

        // Update tunnel patterns for MITM requests (cross-request phishing detection)
        if let Some(stream_id) = ctx.mitm_stream_id {
            let ct = ctx.response_content_type.as_deref();
            if let Some(mut mc) = crate::mitm::stream::MITM_CONTEXTS.get_mut(&stream_id) {
                mc.tunnel_patterns.observe_request(&ctx.path, ct);
            }
        }

        // At end of stream, run Tier 2 content analysis and update reputation
        if end_of_stream {
            if let Some(buf) = ctx.threat_inspect_buffer.take() {
                if !buf.is_empty() {
                    let (t2_score, t2_signals) = crate::threat::content::analyze_response(
                        &buf,
                        &ctx.host,
                        ctx.response_content_type.as_deref(),
                        ctx.response_status,
                        ctx.response_location.as_deref(),
                    );

                    // Merge Tier 2 results into the verdict for logging
                    if let Some(ref mut verdict) = ctx.threat_verdict {
                        if t2_score > 0.0 {
                            verdict.signals.extend(t2_signals);
                            // Blend: keep higher of T1 score or T2-boosted score
                            let blended = (verdict.score * 0.5 + t2_score * 0.5).min(1.0);
                            if blended > verdict.score {
                                verdict.score = blended;
                            }
                            verdict.tier_reached = conduit_common::types::ThreatTier::Tier2;

                            if let Some(ref engine) = self.threat_engine {
                                // Only write reputation for untrusted categories.
                                // Legitimate login pages (Reddit, Google) match content
                                // patterns but shouldn't poison the reputation cache.
                                let is_trusted = crate::threat::reputation::is_trusted_category(
                                    ctx.category.as_deref(),
                                );

                                // Only write reputation when both heuristics AND content
                                // are suspicious AND the category is not trusted.
                                let pre_t2 = verdict.score - (t2_score * 0.5);
                                if !is_trusted && t2_score >= 0.5 && pre_t2 >= 0.2 {
                                    crate::threat::reputation::cache_score(
                                        &engine.reputation_cache,
                                        ctx.host.clone(),
                                        1.0,
                                    );
                                }

                                // Tier 3 escalation: send to LLM worker if score is ambiguous
                                if let Some(ref llm_tx) = engine.llm_tx {
                                    if engine.config.tier3_enabled
                                        && verdict.score >= engine.config.tier2_escalation_threshold
                                        && verdict.score < engine.config.tier0_block_threshold
                                    {
                                        let llm_req = crate::threat::llm::LlmRequest {
                                            host: ctx.host.clone(),
                                            signals: verdict.signals.clone(),
                                            tier0_score: verdict.score,
                                            tier1_score: Some(verdict.score),
                                            tier2_score: Some(t2_score),
                                            reputation_score: verdict.reputation_score.unwrap_or(0.5),
                                            reply_tx: None,
                                        };
                                        let _ = llm_tx.try_send(llm_req);
                                        verdict.tier_reached = conduit_common::types::ThreatTier::Tier3;
                                    }
                                }

                                // If T2 is confident enough, kill the tunnel for future requests
                                if !is_trusted && verdict.score >= engine.config.tier0_block_threshold {
                                    if let Some(stream_id) = ctx.mitm_stream_id {
                                        if let Some(mut mc) = crate::mitm::stream::MITM_CONTEXTS.get_mut(&stream_id) {
                                            mc.tunnel_killed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Evaluate tunnel-level patterns at end of each response (MITM only)
            if let Some(stream_id) = ctx.mitm_stream_id {
                // Extract evaluation result under a short-lived DashMap ref
                let tunnel_eval = crate::mitm::stream::MITM_CONTEXTS.get_mut(&stream_id)
                    .and_then(|mut mc| {
                        if mc.tunnel_patterns.t2_fired {
                            return None;
                        }
                        mc.tunnel_patterns.evaluate().map(|score| {
                            mc.tunnel_patterns.t2_fired = true;
                            score
                        })
                    });
                if let Some(tunnel_score) = tunnel_eval {
                    if let Some(ref mut verdict) = ctx.threat_verdict {
                        verdict.score = (verdict.score + tunnel_score).min(1.0);
                        verdict.signals.push(
                            conduit_common::types::ThreatSignal {
                                name: format!("tunnel_pattern_phishing (score: {tunnel_score:.2})"),
                                score: tunnel_score,
                                tier: conduit_common::types::ThreatTier::Tier2,
                            },
                        );
                    }
                }
            }
        }

        Ok(None)
    }

    /// Emit log entry after request completes.
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let method = session.req_header().method.to_string();
        let entry = LogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: ctx.start_time,
            client_ip: ctx.client_ip.clone(),
            username: ctx.identity.username.clone(),
            auth_method: ctx.identity.auth_method,
            method,
            scheme: ctx.scheme.clone(),
            host: ctx.host.clone(),
            port: ctx.port,
            path: ctx.path.clone(),
            full_url: ctx.full_url(),
            category: ctx.category.clone(),
            action: ctx.action,
            rule_id: ctx.rule_id.clone(),
            status_code: ctx.response_status,
            request_bytes: ctx.request_bytes,
            response_bytes: ctx.response_bytes,
            duration_ms: ctx.duration_ms(),
            tls_intercepted: ctx.tls_intercepted,
            upstream_addr: ctx.upstream_addr.clone(),
            content_type: ctx.response_content_type.clone(),
            cache_status: ctx.cache_status.clone(),
            node_id: None,
            node_name: None,
            threat_score: ctx.threat_verdict.as_ref().map(|v| v.score),
            threat_tier: ctx.threat_verdict.as_ref().map(|v| v.tier_reached),
            threat_blocked: ctx.threat_verdict.as_ref().map(|v| v.blocked),
            block_reason: ctx.block_reason,
            rule_name: ctx.rule_name.clone(),
            threat_signals: ctx.threat_verdict.as_ref()
                .filter(|v| !v.signals.is_empty())
                .map(|v| v.signals.clone()),
        };

        self.log_tx.send(entry);
    }
}
