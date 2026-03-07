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

/// Cache-related components (all `&'static` as required by Pingora).
#[derive(Default)]
pub struct CacheComponents {
    pub storage: Option<&'static (dyn Storage + Sync)>,
    pub eviction: Option<&'static (dyn EvictionManager + Sync)>,
    pub lock: Option<&'static CacheKeyLockImpl>,
    pub meta_defaults: Option<&'static CacheMetaDefaults>,
    pub max_file_size: usize,
}

/// Dependency bundle for constructing ClearGateProxy — prevents parameter explosion.
pub struct ProxyDeps {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    pub ca: Arc<CertAuthority>,
    pub cert_cache: Arc<CertCache>,
    pub log_tx: mpsc::Sender<LogEntry>,
    pub threat_engine: Option<Arc<ThreatEngine>>,
    pub cache: CacheComponents,
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    pub dns_cache: Option<Arc<crate::dns_cache::DnsCache>>,
    pub upstream_router: Option<Arc<crate::load_balancer::UpstreamRouter>>,
    pub dlp_engine: Option<Arc<crate::dlp::DlpEngine>>,
}

/// Core proxy struct implementing Pingora's ProxyHttp trait.
pub struct ClearGateProxy {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    #[allow(dead_code)]
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
    // New features
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    pub dns_cache: Option<Arc<crate::dns_cache::DnsCache>>,
    pub upstream_router: Option<Arc<crate::load_balancer::UpstreamRouter>>,
    pub dlp_engine: Option<Arc<crate::dlp::DlpEngine>>,
}

impl ClearGateProxy {
    pub fn new(deps: ProxyDeps) -> Self {
        Self {
            config: deps.config,
            pool: deps.pool,
            ca: deps.ca,
            cert_cache: deps.cert_cache,
            log_tx: LogSender(deps.log_tx),
            threat_engine: deps.threat_engine,
            cache_storage: deps.cache.storage,
            cache_eviction: deps.cache.eviction,
            cache_lock: deps.cache.lock,
            cache_meta_defaults: deps.cache.meta_defaults,
            cache_max_file_size: deps.cache.max_file_size,
            rate_limiter: deps.rate_limiter,
            dns_cache: deps.dns_cache,
            upstream_router: deps.upstream_router,
            dlp_engine: deps.dlp_engine,
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

    /// Get timeout config values or defaults.
    fn connect_timeout(&self) -> std::time::Duration {
        let secs = self.config.timeouts.as_ref().map(|t| t.connect_timeout_secs).unwrap_or(10);
        std::time::Duration::from_secs(secs)
    }
    fn total_connection_timeout(&self) -> std::time::Duration {
        let secs = self.config.timeouts.as_ref().map(|t| t.total_connection_timeout_secs).unwrap_or(15);
        std::time::Duration::from_secs(secs)
    }
    fn read_timeout(&self) -> std::time::Duration {
        let secs = self.config.timeouts.as_ref().map(|t| t.read_timeout_secs).unwrap_or(60);
        std::time::Duration::from_secs(secs)
    }
    fn write_timeout(&self) -> std::time::Duration {
        let secs = self.config.timeouts.as_ref().map(|t| t.write_timeout_secs).unwrap_or(60);
        std::time::Duration::from_secs(secs)
    }
}

/// Extract just the IP portion from a socket address string (e.g., "1.2.3.4:8080" → "1.2.3.4").
/// Handles IPv6 bracket notation (e.g., "[::1]:8080" → "::1").
pub(crate) fn extract_ip_from_addr(addr: &str) -> &str {
    // IPv6 in brackets: "[::1]:port"
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            return &addr[1..end];
        }
    }
    // IPv4: "1.2.3.4:port" — split on last colon only if suffix is numeric (port)
    if let Some((ip, port_str)) = addr.rsplit_once(':') {
        if port_str.chars().all(|c| c.is_ascii_digit()) {
            return ip;
        }
    }
    // Bare IP (no port) or IPv6 without brackets
    addr
}

/// Extract just the path (+ query string) from a URI.
fn extract_path_from_uri(uri: &http::Uri) -> String {
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
        let raw = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".into());

        if raw.starts_with("/http://") || raw.starts_with("/https://") {
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
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Check request header size limit (approximate — excludes request line)
        if let Some(ref limits) = self.config.request_limits {
            if limits.max_request_header_size > 0 {
                let header_size: usize = session.req_header().headers.iter()
                    .map(|(k, v)| k.as_str().len() + v.len() + 4) // ": " + "\r\n"
                    .sum();
                if header_size > limits.max_request_header_size {
                    let mut resp = ResponseHeader::build(413, Some(1))?;
                    resp.insert_header("Content-Length", "0")?;
                    resp.insert_header("Connection", "close")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    ctx.response_status = 413;
                    ctx.action = PolicyAction::Block;
                    ctx.block_reason = Some(BlockReason::RequestTooLarge);
                    return Ok(true);
                }
            }
        }

        // Check if this is a MITM-intercepted connection by looking up the
        // client address in the MITM context map. The key is the client's
        // socket address string (ip:port), set during handle_connect.
        let mitm_client_addr = session
            .downstream_session
            .client_addr()
            .map(|a| a.to_string());

        let mitm_ctx = mitm_client_addr.as_ref().and_then(|addr| {
            crate::mitm::stream::MITM_CONTEXTS.get(addr).map(|mc| {
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
            ctx.client_ip = extract_ip_from_addr(&mitm_client_ip).to_string();
            ctx.tls_intercepted = true;
            ctx.scheme = "https".into();
            ctx.mitm_client_addr = mitm_client_addr;
            ctx.is_connect = false;

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

            let (host, _) = Self::extract_host_port(session);
            ctx.host = host;
            ctx.port = mitm_port;
            ctx.path = extract_path_from_uri(&session.req_header().uri);

            ctx.identity = conduit_common::types::UserIdentity {
                username: mitm_username,
                auth_method: mitm_auth_method,
                groups: vec![],
            };

            ctx.category = mitm_category;
        } else {
            ctx.client_ip = session
                .downstream_session
                .client_addr()
                .map(|a| {
                    let s = a.to_string();
                    extract_ip_from_addr(&s).to_string()
                })
                .unwrap_or_default();

            let req = session.req_header();
            ctx.is_connect = req.method == Method::CONNECT;

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

            ctx.identity = identity::identify(session, &self.pool, &self.config).await;

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

        // Rate limiting (after identity resolution so we have username).
        // Note: MITM inner requests are also rate-limited. Each HTTP request within
        // a TLS tunnel counts individually. The CONNECT itself is separately rate-limited
        // in service.rs. If this is too aggressive for MITM, consider skipping when
        // ctx.tls_intercepted is true.
        if let Some(ref limiter) = self.rate_limiter {
            if let Err(_kind) = limiter.check_rate(
                &ctx.client_ip,
                ctx.identity.username.as_deref(),
                &ctx.host,
            ) {
                crate::metrics::record_rate_limit();
                let mut resp = ResponseHeader::build(429, Some(2))?;
                resp.insert_header("Retry-After", &limiter.window_secs().to_string())?;
                resp.insert_header("Content-Length", "0")?;
                resp.insert_header("Connection", "close")?;
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = 429;
                ctx.action = PolicyAction::Block;
                ctx.block_reason = Some(BlockReason::RateLimited);
                return Ok(true);
            }
        }

        // Category lookup
        if !ctx.tls_intercepted {
            ctx.category = policy::categories::lookup_category(&self.pool, &ctx.host).await;
        }

        // Threat detection
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

        // DLP buffer is lazily allocated in request_body_filter on first body chunk
        Ok(false)
    }

    /// Decide where to forward the request.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let tls = ctx.scheme == "https" || ctx.is_connect;

        // Check load balancer first
        tracing::debug!(host = %ctx.host, "upstream_peer called");
        if let Some(ref router) = self.upstream_router {
            if let Some((addr, _group_name)) = router.find_upstream(&ctx.host) {
                tracing::debug!(addr = %addr, group = %_group_name, "LB selected in upstream_peer");
                let mut peer = HttpPeer::new(
                    addr,
                    tls,
                    ctx.host.clone(),
                );
                peer.options.connection_timeout = Some(self.connect_timeout());
                peer.options.total_connection_timeout = Some(self.total_connection_timeout());
                peer.options.read_timeout = Some(self.read_timeout());
                peer.options.write_timeout = Some(self.write_timeout());
                ctx.upstream_addr = Some(addr.to_string());
                ctx.lb_routed = true;
                return Ok(Box::new(peer));
            }
        }

        // DNS resolution — use cache if available, else direct lookup
        let sock_addr = if let Some(ref dns) = self.dns_cache {
            dns.resolve(&ctx.host, ctx.port).await.map_err(|e| {
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!("DNS resolution failed for {}:{} — {e}", ctx.host, ctx.port))
            })?
        } else {
            tokio::net::lookup_host((ctx.host.as_str(), ctx.port))
                .await
                .map_err(|e| {
                    pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                        .more_context(format!("DNS resolution failed for {}:{} — {e}", ctx.host, ctx.port))
                })?
                .next()
                .ok_or_else(|| {
                    pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                        .more_context(format!("No addresses found for {}:{}", ctx.host, ctx.port))
                })?
        };

        // SSRF protection: reject connections to private/loopback IPs (skip for LB-routed traffic
        // since those are intentional internal backends configured by the operator)
        if !ctx.lb_routed && crate::mitm::tunnel::is_private_ip(sock_addr.ip()) {
            return Err(pingora_error::Error::new(
                pingora_error::ErrorType::ConnectProxyFailure,
            ).more_context(format!(
                "Blocked connection to private IP {} (SSRF protection)",
                sock_addr
            )));
        }

        let mut peer = HttpPeer::new(
            sock_addr,
            tls,
            ctx.host.clone(),
        );
        peer.options.connection_timeout = Some(self.connect_timeout());
        peer.options.total_connection_timeout = Some(self.total_connection_timeout());
        peer.options.read_timeout = Some(self.read_timeout());
        peer.options.write_timeout = Some(self.write_timeout());
        Ok(Box::new(peer))
    }

    /// Modify request before sending upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("Proxy-Authorization");
        if !ctx.client_ip.is_empty() {
            upstream_request.insert_header("X-Forwarded-For", &ctx.client_ip)?;
        }
        Ok(())
    }

    /// Track request body size + enforce limits + DLP buffering.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(b) = body {
            ctx.request_bytes += b.len() as u64;
            ctx.request_body_accumulated += b.len();

            // Request body size limit — send a clean 413 response before returning error
            if let Some(ref limits) = self.config.request_limits {
                if limits.max_request_body_size > 0 && ctx.request_body_accumulated > limits.max_request_body_size {
                    let mut resp = ResponseHeader::build(413, Some(1))?;
                    resp.insert_header("Content-Length", "0")?;
                    resp.insert_header("Connection", "close")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    ctx.response_status = 413;
                    ctx.action = PolicyAction::Block;
                    ctx.block_reason = Some(BlockReason::RequestTooLarge);
                    return Err(pingora_error::Error::new(pingora_error::ErrorType::HTTPStatus(413))
                        .more_context("Request body too large"));
                }
            }

            // Buffer for DLP scanning (lazy init on first body chunk)
            if let Some(ref dlp) = self.dlp_engine {
                let buf = ctx.dlp_body_buffer.get_or_insert_with(|| {
                    Vec::with_capacity(dlp.max_scan_size.min(8192))
                });
                let remaining = dlp.max_scan_size.saturating_sub(buf.len());
                if remaining > 0 {
                    buf.extend_from_slice(&b[..b.len().min(remaining)]);
                }
            }
        }

        // At end of stream, run DLP scan
        if end_of_stream {
            if let Some(buf) = ctx.dlp_body_buffer.take() {
                if !buf.is_empty() {
                    if let Some(ref dlp) = self.dlp_engine {
                        let matches = dlp.scan(&buf);
                        if !matches.is_empty() {
                            let pattern_names: Vec<String> = matches.iter()
                                .map(|m| m.pattern_name.clone())
                                .collect();
                            ctx.dlp_matches = Some(pattern_names);

                            if crate::dlp::DlpEngine::should_block(&matches) {
                                ctx.action = PolicyAction::Block;
                                ctx.block_reason = Some(BlockReason::DlpViolation);
                                let patterns = ctx.dlp_matches.as_ref()
                                    .map(|p| p.join(", "))
                                    .unwrap_or_default();
                                let reason = format!("Data loss prevention: {patterns}");
                                let body = self.build_block_page(&ctx.host, "dlp-violation", &reason);
                                let mut resp = ResponseHeader::build(403, Some(3))?;
                                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                                resp.insert_header("Content-Length", &body.len().to_string())?;
                                resp.insert_header("Connection", "close")?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session.write_response_body(Some(body), true).await?;
                                ctx.response_status = 403;
                                return Err(pingora_error::Error::new(pingora_error::ErrorType::HTTPStatus(403))
                                    .more_context("DLP violation: sensitive data detected"));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Enable caching for cacheable GET/HEAD requests.
    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(storage) = self.cache_storage {
            // Skip cache for load-balanced domains — each request must reach upstream
            // for round-robin distribution to work.
            let lb_domain = self.upstream_router.as_ref()
                .map(|r| r.matches_domain(&ctx.host))
                .unwrap_or(false);
            if !ctx.is_connect && !lb_domain && filters::request_cacheable(session.req_header()) {
                session.cache.enable(
                    storage,
                    self.cache_eviction,
                    None,
                    self.cache_lock,
                    None,
                );
                session.cache.set_max_file_size_bytes(self.cache_max_file_size);
                ctx.cache_enabled = true;
            }
        }
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let uri = &session.req_header().uri;
        let primary = format!("{}://{}:{}{}", ctx.scheme, ctx.host, ctx.port, uri);
        Ok(CacheKey::new(String::new(), primary, ""))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let cc = CacheControl::from_resp_headers(resp);
        let has_auth = false;
        if let Some(defaults) = self.cache_meta_defaults {
            Ok(filters::resp_cacheable(cc.as_ref(), resp.clone(), has_auth, defaults))
        } else {
            Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("no defaults")))
        }
    }

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

                    if let Some(inet) = addr.as_inet() {
                        if !ctx.lb_routed && crate::mitm::tunnel::is_private_ip(inet.ip()) {
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

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();

        if ctx.cache_enabled {
            let status = session.cache.phase().as_str();
            ctx.cache_status = Some(status.to_string());
            let _ = upstream_response.insert_header("X-Cache-Status", status);

            // Track cache metrics based on Pingora's CachePhase::as_str() values
            match status {
                "hit" | "stale" | "stale-updating" | "revalidated" => {
                    crate::metrics::record_cache_hit();
                }
                "miss" | "expired" | "bypass" => {
                    crate::metrics::record_cache_miss();
                }
                _ => {} // "disabled", "uninitialized", "key" — not terminal states
            }
        }

        if let Some(ct) = upstream_response.headers.get("content-type") {
            ctx.response_content_type = ct.to_str().ok().map(String::from);
        }
        if let Some(loc) = upstream_response.headers.get("location") {
            ctx.response_location = loc.to_str().ok().map(String::from);
        }

        {
            use crate::threat::heuristics::SecurityHeaders;
            ctx.security_headers = Some(SecurityHeaders {
                has_hsts: upstream_response.headers.contains_key("strict-transport-security"),
                has_csp: upstream_response.headers.contains_key("content-security-policy"),
                has_xfo: upstream_response.headers.contains_key("x-frame-options"),
                has_xcto: upstream_response.headers.contains_key("x-content-type-options"),
            });
        }

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

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if let Some(b) = body {
            ctx.response_bytes += b.len() as u64;

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

        if let Some(ref client_addr) = ctx.mitm_client_addr {
            let ct = ctx.response_content_type.as_deref();
            if let Some(mut mc) = crate::mitm::stream::MITM_CONTEXTS.get_mut(client_addr) {
                mc.tunnel_patterns.observe_request(&ctx.path, ct);
            }
        }

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

                    if let Some(ref mut verdict) = ctx.threat_verdict {
                        if t2_score > 0.0 {
                            verdict.signals.extend(t2_signals);
                            let blended = (verdict.score * 0.5 + t2_score * 0.5).min(1.0);
                            if blended > verdict.score {
                                verdict.score = blended;
                            }
                            verdict.tier_reached = conduit_common::types::ThreatTier::Tier2;

                            if let Some(ref engine) = self.threat_engine {
                                let is_trusted = crate::threat::reputation::is_trusted_category(
                                    ctx.category.as_deref(),
                                );

                                let pre_t2 = verdict.score - (t2_score * 0.5);
                                if !is_trusted && t2_score >= 0.5 && pre_t2 >= 0.2 {
                                    crate::threat::reputation::cache_score(
                                        &engine.reputation_cache,
                                        ctx.host.clone(),
                                        1.0,
                                    );
                                }

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

                                if !is_trusted && verdict.score >= engine.config.tier0_block_threshold {
                                    if let Some(ref client_addr) = ctx.mitm_client_addr {
                                        if let Some(mut mc) = crate::mitm::stream::MITM_CONTEXTS.get_mut(client_addr) {
                                            mc.tunnel_killed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(ref client_addr) = ctx.mitm_client_addr {
                let tunnel_eval = crate::mitm::stream::MITM_CONTEXTS.get_mut(client_addr)
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

        // Record Prometheus metrics
        let action_str = format!("{:?}", ctx.action).to_lowercase();
        let block_reason_str = ctx.block_reason.map(|br| format!("{br}"));
        crate::metrics::record_request(
            &action_str,
            &ctx.scheme,
            ctx.duration_ms(),
            block_reason_str.as_deref(),
        );
        if let Some(ref verdict) = ctx.threat_verdict {
            crate::metrics::record_threat_eval(&format!("{:?}", verdict.tier_reached).to_lowercase());
        }

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
            dlp_matches: ctx.dlp_matches.take(),
        };

        self.log_tx.send(entry);
    }
}
