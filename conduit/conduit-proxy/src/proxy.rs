use async_trait::async_trait;
use bytes::Bytes;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{BlockReason, LogEntry, PolicyAction};
use deadpool_redis::Pool;
use http::Method;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::eviction::EvictionManager;
use pingora_cache::filters;
use pingora_cache::key::CacheKey;
use pingora_cache::lock::CacheKeyLockImpl;
use pingora_cache::storage::Storage;
use pingora_cache::{CacheMetaDefaults, NoCacheReason, RespCacheable};
use pingora_core::protocols::Digest;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

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
    pub cert_cache: Arc<CertCache>,
    pub log_tx: mpsc::Sender<LogEntry>,
    pub threat_engine: Option<Arc<ThreatEngine>>,
    pub cache: CacheComponents,
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    pub dns_cache: Option<Arc<crate::dns_cache::DnsCache>>,
    pub upstream_router: Option<Arc<crate::load_balancer::UpstreamRouter>>,
    pub dlp_engine: Option<Arc<crate::dlp::DlpEngine>>,
    pub package_scanner: Option<Arc<crate::package_scanner::PackageScanner>>,
}

/// Core proxy struct implementing Pingora's ProxyHttp trait.
pub struct ClearGateProxy {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
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
    pub package_scanner: Option<Arc<crate::package_scanner::PackageScanner>>,
}

impl ClearGateProxy {
    pub fn new(deps: ProxyDeps) -> Self {
        Self {
            config: deps.config,
            pool: deps.pool,
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
            package_scanner: deps.package_scanner,
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

    #[allow(dead_code)]
    fn build_block_page(&self, host: &str, category: &str, reason: &str) -> Bytes {
        Bytes::from(crate::service::build_block_html(
            host,
            category,
            reason,
            &self.config,
        ))
    }

    fn render_threat_block_page(
        &self,
        session: &Session,
        ctx: &RequestContext,
        reason_text: &str,
    ) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };
        let category = ctx.category.as_deref().unwrap_or("malicious");

        let block_ctx = crate::block_page::BlockPageContext::for_threat(
            &ctx.host,
            path,
            method,
            reason_text,
            Some(category),
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    fn render_policy_block_page(&self, session: &Session, ctx: &RequestContext) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };
        let category = ctx.category.as_deref().unwrap_or("uncategorized");
        let rule_name = ctx.rule_name.as_deref().unwrap_or("Policy");

        let block_ctx = crate::block_page::BlockPageContext::for_policy(
            &ctx.host,
            path,
            method,
            Some(rule_name),
            Some(category),
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    fn render_dlp_block_page(&self, session: &Session, ctx: &RequestContext) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };
        let rule_name = ctx
            .dlp_matches
            .as_ref()
            .and_then(|m| m.first())
            .map(|s| s.as_str())
            .unwrap_or("Sensitive Data");
        let snippet = ctx.dlp_matched_snippet.as_deref();

        let block_ctx = crate::block_page::BlockPageContext::for_dlp(
            &ctx.host,
            path,
            method,
            rule_name,
            snippet,
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    #[allow(dead_code)]
    fn render_package_threat_block_page(
        &self,
        session: &Session,
        ctx: &RequestContext,
        rule_name: &str,
        infected_file: &str,
    ) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };

        let block_ctx = crate::block_page::BlockPageContext::for_package_threat(
            &ctx.host,
            path,
            method,
            rule_name,
            infected_file,
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    fn render_post_protection_block_page(
        &self,
        session: &Session,
        ctx: &RequestContext,
        reason: &str,
    ) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };

        let block_ctx = crate::block_page::BlockPageContext::for_post_protection(
            &ctx.host,
            path,
            method,
            reason,
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    fn render_risky_tld_block_page(
        &self,
        session: &Session,
        ctx: &RequestContext,
        tld: &str,
    ) -> Bytes {
        let method = session.req_header().method.as_str();
        let node_name = crate::block_page::get_node_name(&self.config);
        let user = ctx.identity.username.as_deref().unwrap_or("unknown");
        let timestamp = ctx.start_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let path = if ctx.path.is_empty() { "/" } else { &ctx.path };

        let block_ctx = crate::block_page::BlockPageContext::for_risky_tld(
            &ctx.host,
            path,
            method,
            tld,
            Some(user),
            &ctx.client_ip,
            &timestamp,
            &ctx.ref_id,
            &node_name,
        );
        Bytes::from(block_ctx.render(self.config.block_page_html.as_deref()))
    }

    /// Get timeout config values or defaults.
    fn connect_timeout(&self) -> std::time::Duration {
        let secs = self
            .config
            .timeouts
            .as_ref()
            .map(|t| t.connect_timeout_secs)
            .unwrap_or(10);
        std::time::Duration::from_secs(secs)
    }
    fn total_connection_timeout(&self) -> std::time::Duration {
        let secs = self
            .config
            .timeouts
            .as_ref()
            .map(|t| t.total_connection_timeout_secs)
            .unwrap_or(15);
        std::time::Duration::from_secs(secs)
    }
    fn read_timeout(&self) -> std::time::Duration {
        let secs = self
            .config
            .timeouts
            .as_ref()
            .map(|t| t.read_timeout_secs)
            .unwrap_or(60);
        std::time::Duration::from_secs(secs)
    }
    fn write_timeout(&self) -> std::time::Duration {
        let secs = self
            .config
            .timeouts
            .as_ref()
            .map(|t| t.write_timeout_secs)
            .unwrap_or(60);
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

/// Query the kernel's routing table for the primary non-loopback LAN IP (e.g. 192.168.x.x).
pub(crate) fn get_primary_lan_ip() -> Option<String> {
    conduit_common::config::get_primary_lan_ip()
}

/// Normalize loopback IP (127.0.0.1, ::1) to the host's actual LAN IP if available.
pub(crate) fn normalize_client_ip(ip: &str) -> String {
    if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
        if let Some(lan_ip) = get_primary_lan_ip() {
            return lan_ip;
        }
    }
    ip.to_string()
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
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Check request header size limit (approximate — excludes request line)
        if let Some(ref limits) = self.config.request_limits {
            if limits.max_request_header_size > 0 {
                let header_size: usize = session
                    .req_header()
                    .headers
                    .iter()
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

        if let Some((
            mitm_client_ip,
            mitm_port,
            mitm_username,
            mitm_auth_method,
            mitm_category,
            tunnel_killed,
        )) = mitm_ctx
        {
            ctx.client_ip = normalize_client_ip(extract_ip_from_addr(&mitm_client_ip));
            ctx.tls_intercepted = true;
            ctx.scheme = "https".into();
            ctx.mitm_client_addr = mitm_client_addr;
            ctx.is_connect = false;

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

            if tunnel_killed {
                let body = self.render_threat_block_page(
                    session,
                    ctx,
                    "Tunnel terminated (threat detected)",
                );
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
        } else {
            ctx.client_ip = session
                .downstream_session
                .client_addr()
                .map(|a| {
                    let s = a.to_string();
                    normalize_client_ip(extract_ip_from_addr(&s))
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
                session.write_response_header(Box::new(resp), true).await?;
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
            if let Err(_kind) =
                limiter.check_rate(&ctx.client_ip, ctx.identity.username.as_deref(), &ctx.host)
            {
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
        if !ctx.tls_intercepted || ctx.category.is_none() {
            ctx.category = policy::categories::lookup_category(&self.pool, &ctx.host).await;
        }

        let rt_cfg = crate::runtime_config::get();
        let is_allowlisted = self
            .config
            .allowlist
            .as_ref()
            .map(|a| a.is_allowed(&ctx.host, ctx.port, None, Some(&ctx.client_ip)))
            .unwrap_or(false);

        // Policy evaluation
        let (action, rule_id, matched_rule_name) = if is_allowlisted {
            (PolicyAction::Allow, None, Some("Allowlist".to_string()))
        } else {
            policy::rules::evaluate(
                &self.pool,
                &ctx.host,
                ctx.category.as_deref(),
                ctx.identity.username.as_deref(),
                &ctx.identity.groups,
                rt_cfg.fail_closed,
            )
            .await
        };
        ctx.rule_id = rule_id.clone();
        ctx.rule_name = matched_rule_name.clone();

        // Explicit allow rules (from operator policies or allowlist) override general egress port restrictions
        let is_explicitly_allowed =
            is_allowlisted || (action == PolicyAction::Allow && rule_id.is_some());

        // Egress port restriction check (plain non-intercepted HTTP)
        if !ctx.tls_intercepted && !is_explicitly_allowed {
            if let Some(ref egress) = self.config.egress {
                if !egress.is_http_port_allowed(ctx.port) {
                    info!(host = %ctx.host, port = ctx.port, client_ip = %ctx.client_ip, "HTTP request rejected: port not permitted by egress policy");
                    let mut resp = ResponseHeader::build(403, Some(0))?;
                    resp.insert_header("Content-Type", "text/plain")?;
                    resp.insert_header("Connection", "close")?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(
                            Some(bytes::Bytes::from(
                                "403 Forbidden: Destination port not permitted by egress policy\n",
                            )),
                            true,
                        )
                        .await?;
                    ctx.response_status = 403;
                    ctx.action = PolicyAction::Block;
                    ctx.block_reason = Some(BlockReason::Policy);
                    ctx.rule_name = Some("EgressPortRestriction".to_string());
                    return Ok(true);
                }
            }
        }

        // TLD Protection evaluation (skipped for allowlisted hosts)
        if !is_allowlisted {
            let tld_cfg = rt_cfg.effective_tld_protection(self.config.tld_protection.as_ref());
            if tld_cfg.enabled {
                let host_tld = crate::threat::heuristics::extract_tld(&ctx.host);
                let is_known_bad = crate::threat::heuristics::is_bad_tld_name(host_tld);
                if tld_cfg.is_tld_blocked(host_tld, is_known_bad) {
                    let should_block = tld_cfg.action == "block" || rt_cfg.prevention_mode;
                    if should_block {
                        info!(host = %ctx.host, tld = host_tld, "Blocking request (risky TLD)");
                        ctx.action = PolicyAction::Block;
                        ctx.block_reason = Some(BlockReason::RiskyTld);
                        ctx.rule_name = Some(format!("RiskyTLD:.{host_tld}"));
                        let body = self.render_risky_tld_block_page(session, ctx, host_tld);
                        let mut resp = ResponseHeader::build(403, Some(3))?;
                        resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                        resp.insert_header("Content-Length", &body.len().to_string())?;
                        resp.insert_header("Connection", "close")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session.write_response_body(Some(body), true).await?;
                        ctx.response_status = 403;
                        return Ok(true);
                    } else {
                        info!(host = %ctx.host, tld = host_tld, "Risky TLD detected in audit mode (not blocked)");
                    }
                }
            }
        }

        // POST / Write Protection for uncategorized domains
        let is_uncategorized =
            ctx.category.is_none() || ctx.category.as_deref() == Some("uncategorized");
        if !is_allowlisted && is_uncategorized {
            let post_cfg = rt_cfg.effective_post_protection(self.config.post_protection.as_ref());
            if post_cfg.enabled {
                let req_method = &session.req_header().method;
                let is_state_changing = req_method == Method::POST
                    || req_method == Method::PUT
                    || req_method == Method::PATCH
                    || req_method == Method::DELETE;

                if is_state_changing {
                    let ua = session
                        .req_header()
                        .headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok());
                    let has_browser_fetch =
                        session.req_header().headers.contains_key("sec-fetch-mode")
                            || session.req_header().headers.contains_key("sec-fetch-dest")
                            || session.req_header().headers.contains_key("sec-ch-ua");

                    let applies_to_client = if post_cfg.browser_only {
                        post_cfg.is_interactive_browser(ua, has_browser_fetch)
                    } else {
                        !post_cfg.is_exempt_client(ua)
                    };

                    if applies_to_client {
                        let host_tld = crate::threat::heuristics::extract_tld(&ctx.host);
                        let is_bad_tld = crate::threat::heuristics::is_bad_tld_name(host_tld);
                        let is_untrusted_tld =
                            !crate::threat::heuristics::is_trusted_tld_name(host_tld);
                        let trigger_tld = post_cfg.block_uncategorized_bad_tld
                            && (is_bad_tld || is_untrusted_tld);

                        let domain_part = crate::threat::heuristics::domain_without_tld(&ctx.host);
                        let entropy = crate::threat::entropy::shannon_entropy(domain_part);
                        let trigger_entropy = post_cfg.block_uncategorized_high_entropy
                            && entropy >= post_cfg.entropy_threshold;

                        let content_len = session
                            .req_header()
                            .headers
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        let trigger_size = post_cfg.max_uncategorized_body_bytes == 0
                            || (content_len > post_cfg.max_uncategorized_body_bytes);

                        let triggered_reason = if trigger_tld {
                            Some(format!(
                                "Uncategorized domain with suspicious TLD (.{host_tld})"
                            ))
                        } else if trigger_entropy {
                            Some(format!("Uncategorized domain with high entropy ({entropy:.2} >= {threshold:.2})", threshold = post_cfg.entropy_threshold))
                        } else if trigger_size && content_len > 0 {
                            Some(format!("Request payload exceeds uncategorized limit ({content_len} > {limit} bytes)", limit = post_cfg.max_uncategorized_body_bytes))
                        } else if post_cfg.max_uncategorized_body_bytes == 0 {
                            Some(
                                "Write requests to uncategorized domains are disallowed"
                                    .to_string(),
                            )
                        } else {
                            None
                        };

                        if let Some(reason_text) = triggered_reason {
                            let should_block = post_cfg.action == "block" || rt_cfg.prevention_mode;
                            if should_block {
                                info!(
                                    host = %ctx.host,
                                    method = %req_method,
                                    reason = %reason_text,
                                    "Blocking write request to uncategorized domain"
                                );
                                ctx.action = PolicyAction::Block;
                                ctx.block_reason = Some(BlockReason::PostProtection);
                                ctx.rule_name = Some("PostProtection".to_string());
                                let body = self.render_post_protection_block_page(
                                    session,
                                    ctx,
                                    &reason_text,
                                );
                                let mut resp = ResponseHeader::build(403, Some(3))?;
                                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                                resp.insert_header("Content-Length", &body.len().to_string())?;
                                resp.insert_header("Connection", "close")?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session.write_response_body(Some(body), true).await?;
                                ctx.response_status = 403;
                                return Ok(true);
                            } else {
                                info!(
                                    host = %ctx.host,
                                    method = %req_method,
                                    reason = %reason_text,
                                    "Uncategorized POST detected in audit mode (not blocked)"
                                );
                            }
                        } else if post_cfg.max_uncategorized_body_bytes > 0 {
                            // If Content-Length header was omitted (e.g. chunked transfer),
                            // arm streaming body limit enforcement in request_body_filter
                            ctx.uncategorized_post_max_bytes =
                                Some(post_cfg.max_uncategorized_body_bytes);
                        }
                    }
                }
            }
        }

        // Threat detection (skipped for allowlisted hosts)
        if !is_allowlisted {
            if let Some(ref engine) = self.threat_engine {
                let verdict = crate::threat::evaluate_request(
                    engine,
                    &ctx.host,
                    ctx.port,
                    &ctx.path,
                    &ctx.scheme,
                    ctx.category.as_deref(),
                    ctx.upstream_addr.as_deref(),
                    None,
                    None,
                );

                let rep_block = crate::threat::check_reputation(engine, &ctx.host);
                let is_threat = verdict.blocked || rep_block.is_some();

                if is_threat {
                    let score = rep_block.unwrap_or(verdict.score);
                    let block_reason = if rep_block.is_some() {
                        BlockReason::ThreatReputation
                    } else {
                        BlockReason::ThreatHeuristic
                    };
                    let reason_text = if rep_block.is_some() {
                        "Threat detected (reputation)"
                    } else {
                        "Threat detected (heuristic)"
                    };

                    ctx.threat_verdict = Some(conduit_common::types::ThreatVerdict {
                        score,
                        blocked: rt_cfg.prevention_mode,
                        ..verdict
                    });

                    if rt_cfg.prevention_mode {
                        ctx.action = PolicyAction::Block;
                        ctx.block_reason = Some(block_reason);
                        debug!(host = %ctx.host, score, "Blocking request (threat detected)");
                        let body = self.render_threat_block_page(session, ctx, reason_text);
                        let mut resp = ResponseHeader::build(403, Some(3))?;
                        resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                        resp.insert_header("Content-Length", &body.len().to_string())?;
                        resp.insert_header("Connection", "close")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session.write_response_body(Some(body), true).await?;
                        ctx.response_status = 403;
                        return Ok(true);
                    } else {
                        ctx.action = PolicyAction::Log;
                        debug!(host = %ctx.host, score, "Threat detected in audit mode (not blocked)");
                    }
                } else {
                    ctx.threat_verdict = Some(verdict);
                }
            }
        }

        if action == PolicyAction::Block {
            if rt_cfg.prevention_mode {
                ctx.action = PolicyAction::Block;
                ctx.block_reason = Some(BlockReason::Policy);
                debug!(host = %ctx.host, category = ?ctx.category, "Blocking request");
                let body = self.render_policy_block_page(session, ctx);
                let mut resp = ResponseHeader::build(403, Some(3))?;
                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                resp.insert_header("Content-Length", &body.len().to_string())?;
                resp.insert_header("Connection", "close")?;
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(body), true).await?;
                ctx.response_status = 403;
                return Ok(true);
            } else {
                ctx.action = PolicyAction::Log;
            }
        } else if ctx.action != PolicyAction::Log {
            ctx.action = action;
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
                let mut peer = HttpPeer::new(addr, tls, ctx.host.clone());
                // LB backends are operator-configured internal servers —
                // skip TLS cert verification (they often use self-signed certs)
                peer.options.verify_cert = false;
                peer.options.verify_hostname = false;
                peer.options.connection_timeout = Some(self.connect_timeout());
                peer.options.total_connection_timeout = Some(self.total_connection_timeout());
                peer.options.read_timeout = Some(self.read_timeout());
                peer.options.write_timeout = Some(self.write_timeout());
                peer.options.idle_timeout = Some(std::time::Duration::from_secs(60));
                ctx.upstream_addr = Some(addr.to_string());
                ctx.lb_routed = true;
                return Ok(Box::new(peer));
            }
        }

        // DNS resolution — use cache if available, else direct lookup
        let sock_addr = if let Some(ref dns) = self.dns_cache {
            dns.resolve(&ctx.host, ctx.port).await.map_err(|e| {
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!(
                        "DNS resolution failed for {}:{} — {e}",
                        ctx.host, ctx.port
                    ))
            })?
        } else {
            let addrs: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((ctx.host.as_str(), ctx.port))
                    .await
                    .map_err(|e| {
                        pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                            .more_context(format!(
                                "DNS resolution failed for {}:{} — {e}",
                                ctx.host, ctx.port
                            ))
                    })?
                    .collect();
            // Apply ip_version filtering from dns config
            let ip_ver = self
                .dns_cache
                .as_ref()
                .map(|d| d.ip_version())
                .unwrap_or(conduit_common::dns::IpVersion::V4Preferred);
            ip_ver.pick_first(&addrs).ok_or_else(|| {
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!("No addresses found for {}:{}", ctx.host, ctx.port))
            })?
        };

        // SSRF protection: reject connections to private/loopback IPs (skip for LB-routed traffic
        // or destinations permitted by the allowlist)
        let is_allowed = self
            .config
            .allowlist
            .as_ref()
            .map(|a| {
                a.is_allowed(
                    &ctx.host,
                    ctx.port,
                    Some(sock_addr.ip()),
                    Some(&ctx.client_ip),
                )
            })
            .unwrap_or(false);

        if !ctx.lb_routed && !is_allowed && crate::mitm::tunnel::is_private_ip(sock_addr.ip()) {
            return Err(
                pingora_error::Error::new(pingora_error::ErrorType::ConnectProxyFailure)
                    .more_context(format!(
                        "Blocked connection to private IP {} (SSRF protection)",
                        sock_addr
                    )),
            );
        }

        let mut peer = HttpPeer::new(sock_addr, tls, ctx.host.clone());
        peer.options.connection_timeout = Some(self.connect_timeout());
        peer.options.total_connection_timeout = Some(self.total_connection_timeout());
        peer.options.read_timeout = Some(self.read_timeout());
        peer.options.write_timeout = Some(self.write_timeout());
        peer.options.idle_timeout = Some(std::time::Duration::from_secs(60));
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
                if limits.max_request_body_size > 0
                    && ctx.request_body_accumulated > limits.max_request_body_size
                {
                    let mut resp = ResponseHeader::build(413, Some(1))?;
                    resp.insert_header("Content-Length", "0")?;
                    resp.insert_header("Connection", "close")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    ctx.response_status = 413;
                    ctx.action = PolicyAction::Block;
                    ctx.block_reason = Some(BlockReason::RequestTooLarge);
                    return Err(
                        pingora_error::Error::new(pingora_error::ErrorType::HTTPStatus(413))
                            .more_context("Request body too large"),
                    );
                }
            }

            // Uncategorized POST body size limit enforcement (streaming/chunked)
            if let Some(max_post_bytes) = ctx.uncategorized_post_max_bytes {
                if ctx.request_body_accumulated > max_post_bytes {
                    let reason_text = format!(
                        "Request payload exceeds uncategorized limit (streamed > {max_post_bytes} bytes)"
                    );
                    let body = self.render_post_protection_block_page(session, ctx, &reason_text);
                    let mut resp = ResponseHeader::build(403, Some(3))?;
                    resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                    resp.insert_header("Content-Length", &body.len().to_string())?;
                    resp.insert_header("Connection", "close")?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session.write_response_body(Some(body), true).await?;
                    ctx.response_status = 403;
                    ctx.action = PolicyAction::Block;
                    ctx.block_reason = Some(BlockReason::PostProtection);
                    ctx.rule_name = Some("PostProtection".to_string());
                    return Err(
                        pingora_error::Error::new(pingora_error::ErrorType::HTTPStatus(403))
                            .more_context("POST payload exceeds limit for uncategorized domain"),
                    );
                }
            }

            // Buffer for DLP scanning (lazy init on first body chunk, skipped if host is exempt or allowlisted)
            if let Some(ref dlp) = self.dlp_engine {
                let is_dlp_exempt = self
                    .config
                    .allowlist
                    .as_ref()
                    .map(|a| a.is_allowed(&ctx.host, ctx.port, None, Some(&ctx.client_ip)))
                    .unwrap_or(false)
                    || dlp.is_domain_allowed(&ctx.host);

                if !is_dlp_exempt {
                    let buf = ctx
                        .dlp_body_buffer
                        .get_or_insert_with(|| Vec::with_capacity(dlp.max_scan_size.min(8192)));
                    let remaining = dlp.max_scan_size.saturating_sub(buf.len());
                    if remaining > 0 {
                        buf.extend_from_slice(&b[..b.len().min(remaining)]);
                    }
                }
            }
        }

        // At end of stream, run DLP scan
        if end_of_stream {
            if let Some(buf) = ctx.dlp_body_buffer.take() {
                if !buf.is_empty() {
                    if let Some(ref dlp) = self.dlp_engine {
                        let matches = dlp.scan(&buf, Some(&ctx.host));
                        if !matches.is_empty() {
                            let pattern_names: Vec<String> =
                                matches.iter().map(|m| m.pattern_name.clone()).collect();
                            ctx.dlp_matches = Some(pattern_names);
                            if let Some(snippet) =
                                matches.iter().find_map(|m| m.matched_snippet.as_ref())
                            {
                                ctx.dlp_matched_snippet = Some(snippet.clone());
                            }

                            if crate::dlp::DlpEngine::should_block(&matches) {
                                ctx.action = PolicyAction::Block;
                                ctx.block_reason = Some(BlockReason::DlpViolation);
                                let body = self.render_dlp_block_page(session, ctx);
                                let mut resp = ResponseHeader::build(403, Some(3))?;
                                resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
                                resp.insert_header("Content-Length", &body.len().to_string())?;
                                resp.insert_header("Connection", "close")?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session.write_response_body(Some(body), true).await?;
                                ctx.response_status = 403;
                                return Err(pingora_error::Error::new(
                                    pingora_error::ErrorType::HTTPStatus(403),
                                )
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
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(storage) = self.cache_storage {
            // Skip cache for load-balanced domains — each request must reach upstream
            // for round-robin distribution to work.
            let lb_domain = self
                .upstream_router
                .as_ref()
                .map(|r| r.matches_domain(&ctx.host))
                .unwrap_or(false);
            let is_pkg = self
                .package_scanner
                .as_ref()
                .map(|s| {
                    s.enabled
                        && crate::package_scanner::PackageScanner::is_package_download(
                            &ctx.host, &ctx.path, None,
                        )
                })
                .unwrap_or(false);
            let is_allowlisted = self
                .config
                .allowlist
                .as_ref()
                .map(|a| a.is_allowed(&ctx.host, ctx.port, None, Some(&ctx.client_ip)))
                .unwrap_or(false);

            let req = session.req_header();
            let has_auth = req.headers.contains_key("authorization")
                || req.headers.contains_key("proxy-authorization")
                || req.headers.contains_key("cookie");

            let is_auth_path = ctx.path.starts_with("/oauth")
                || ctx.path.starts_with("/v1/oauth")
                || ctx.path.starts_with("/api/auth")
                || ctx.path.starts_with("/login")
                || ctx.path.starts_with("/logout")
                || ctx.path.starts_with("/signin")
                || ctx.path.starts_with("/signup")
                || ctx.path.contains("/authorize")
                || ctx.path.contains("/callback");

            if !ctx.is_connect
                && !lb_domain
                && !is_pkg
                && !is_allowlisted
                && !has_auth
                && !is_auth_path
                && filters::request_cacheable(req)
            {
                session
                    .cache
                    .enable(storage, self.cache_eviction, None, self.cache_lock, None);
                session
                    .cache
                    .set_max_file_size_bytes(self.cache_max_file_size);
                ctx.cache_enabled = true;
            }
        }
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let uri = &session.req_header().uri;
        let primary = format!("{}://{}:{}{}", ctx.scheme, ctx.host, ctx.port, uri);
        Ok(CacheKey::new(primary, ""))
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let req = session.req_header();
        let has_auth = req.headers.contains_key("authorization")
            || req.headers.contains_key("proxy-authorization")
            || req.headers.contains_key("cookie");

        // Never cache responses that set cookies (session establishment)
        if resp.headers.contains_key("set-cookie") {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "set-cookie",
            )));
        }

        let cc = CacheControl::from_resp_headers(resp);
        // Never cache private or no-store or no-cache responses
        if let Some(ref c) = cc {
            if c.private() || c.no_store() || c.no_cache() {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                    "private/no-store",
                )));
            }
        }

        if has_auth {
            let is_public = cc.as_ref().map(|c| c.public()).unwrap_or(false);
            if !is_public {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                    "authenticated",
                )));
            }
        }

        if let Some(defaults) = self.cache_meta_defaults {
            Ok(filters::resp_cacheable(
                cc.as_ref(),
                resp.clone(),
                has_auth,
                defaults,
            ))
        } else {
            Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "no defaults",
            )))
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
                        let is_allowed = self
                            .config
                            .allowlist
                            .as_ref()
                            .map(|a| {
                                a.is_allowed(
                                    &ctx.host,
                                    ctx.port,
                                    Some(inet.ip()),
                                    Some(&ctx.client_ip),
                                )
                            })
                            .unwrap_or(false);

                        if !ctx.lb_routed
                            && !is_allowed
                            && crate::mitm::tunnel::is_private_ip(inet.ip())
                        {
                            return Err(pingora_error::Error::new(
                                pingora_error::ErrorType::ConnectProxyFailure,
                            )
                            .more_context(format!(
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
                    crate::stats::record_cache_hit();
                }
                "miss" | "expired" | "bypass" => {
                    crate::metrics::record_cache_miss();
                    crate::stats::record_cache_miss();
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
                has_hsts: upstream_response
                    .headers
                    .contains_key("strict-transport-security"),
                has_csp: upstream_response
                    .headers
                    .contains_key("content-security-policy"),
                has_xfo: upstream_response.headers.contains_key("x-frame-options"),
                has_xcto: upstream_response
                    .headers
                    .contains_key("x-content-type-options"),
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
                let t1_escalated = ctx
                    .threat_verdict
                    .as_ref()
                    .map(|v| v.tier_reached >= conduit_common::types::ThreatTier::Tier1)
                    .unwrap_or(false);

                let ct = ctx.response_content_type.as_deref().unwrap_or("");
                let is_inspectable = ct.contains("html") || ct.contains("javascript");

                let has_any_threat_score = ctx
                    .threat_verdict
                    .as_ref()
                    .map(|v| v.score > 0.05)
                    .unwrap_or(false);

                let uncategorized = ctx.category.is_none();

                if t1_escalated || (is_inspectable && (has_any_threat_score || uncategorized)) {
                    ctx.threat_inspect_buffer = Some(Vec::with_capacity(8192));
                }
            }
        }

        // Package Security Scanner (YARA-X) — detect package downloads and prepare buffer
        if let Some(ref scanner) = self.package_scanner {
            if scanner.enabled
                && crate::package_scanner::PackageScanner::is_package_download(
                    &ctx.host,
                    &ctx.path,
                    ctx.response_content_type.as_deref(),
                )
            {
                ctx.is_package_download = true;
                ctx.package_body_buffer = Some(Vec::with_capacity(65536));
                if ctx.cache_enabled {
                    session.cache.disable(NoCacheReason::Custom("package_scan"));
                    ctx.cache_enabled = false;
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

        // Package Security Scanner buffering
        if ctx.is_package_download {
            if let Some(b) = body.take() {
                if let Some(ref mut buf) = ctx.package_body_buffer {
                    let max = self
                        .package_scanner
                        .as_ref()
                        .map(|s| s.max_package_size)
                        .unwrap_or(15 * 1024 * 1024);
                    if buf.len() + b.len() > max {
                        // Package exceeds max inspection size: release buffered prefix and let it stream
                        let mut full = std::mem::take(buf);
                        full.extend_from_slice(&b);
                        *body = Some(Bytes::from(full));
                        ctx.package_body_buffer = None;
                        ctx.is_package_download = false;
                    } else {
                        buf.extend_from_slice(&b);
                        *body = None;
                    }
                } else {
                    *body = Some(b);
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
            if ctx.is_package_download {
                if let Some(buf) = ctx.package_body_buffer.take() {
                    if let Some(ref scanner) = self.package_scanner {
                        let scan_result = scanner.scan_tarball(&buf);
                        match scan_result {
                            crate::package_scanner::PackageScanResult::Threat(threat) => {
                                tracing::warn!(
                                    host = %ctx.host,
                                    path = %ctx.path,
                                    rule = %threat.rule_name,
                                    infected_file = %threat.infected_file,
                                    action = ?scanner.action,
                                    "Package supply-chain threat detected"
                                );
                                ctx.package_threat_match =
                                    Some((threat.rule_name.clone(), threat.infected_file.clone()));
                                if scanner.action
                                    == crate::package_scanner::PackageScanAction::Block
                                {
                                    ctx.action = PolicyAction::Block;
                                    ctx.block_reason = Some(BlockReason::PackageMalware);
                                    ctx.response_status = 403;
                                    if ctx.rule_name.is_none() {
                                        ctx.rule_name = Some(format!("yara:{}", threat.rule_name));
                                    }
                                    *body = None;
                                    return Err(pingora_core::Error::explain(
                                        pingora_core::ErrorType::HTTPStatus(403),
                                        format!(
                                            "Package download blocked: {} ({}) in {}",
                                            threat.description,
                                            threat.rule_name,
                                            threat.infected_file
                                        ),
                                    ));
                                } else {
                                    *body = Some(Bytes::from(buf));
                                }
                            }
                            crate::package_scanner::PackageScanResult::Clean => {
                                *body = Some(Bytes::from(buf));
                            }
                        }
                    } else {
                        *body = Some(Bytes::from(buf));
                    }
                }
            }
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
                                            reputation_score: verdict
                                                .reputation_score
                                                .unwrap_or(0.5),
                                            reply_tx: None,
                                        };
                                        let _ = llm_tx.try_send(llm_req);
                                        verdict.tier_reached =
                                            conduit_common::types::ThreatTier::Tier3;
                                    }
                                }

                                if !is_trusted
                                    && verdict.score >= engine.config.tier0_block_threshold
                                {
                                    if let Some(ref client_addr) = ctx.mitm_client_addr {
                                        if let Some(mut mc) =
                                            crate::mitm::stream::MITM_CONTEXTS.get_mut(client_addr)
                                        {
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
                let tunnel_eval = crate::mitm::stream::MITM_CONTEXTS
                    .get_mut(client_addr)
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
                        verdict.signals.push(conduit_common::types::ThreatSignal {
                            name: format!("tunnel_pattern_phishing (score: {tunnel_score:.2})"),
                            score: tunnel_score,
                            tier: conduit_common::types::ThreatTier::Tier2,
                        });
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
            crate::metrics::record_threat_eval(
                &format!("{:?}", verdict.tier_reached).to_lowercase(),
            );
        }

        let entry = LogEntry {
            id: ctx.req_id.clone(),
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
            node_id: self.config.node.as_ref().map(|n| n.node_id.clone()),
            node_name: Some(crate::block_page::get_node_name(&self.config)),
            threat_score: ctx.threat_verdict.as_ref().map(|v| v.score),
            threat_tier: ctx.threat_verdict.as_ref().map(|v| v.tier_reached),
            threat_blocked: ctx.threat_verdict.as_ref().map(|v| v.blocked),
            block_reason: ctx.block_reason,
            rule_name: ctx.rule_name.clone(),
            threat_signals: ctx
                .threat_verdict
                .as_ref()
                .filter(|v| !v.signals.is_empty())
                .map(|v| v.signals.clone()),
            dlp_matches: ctx.dlp_matches.take(),
        };

        self.log_tx.send(entry);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_auth_path_detection() {
        let auth_paths = [
            "/oauth/authorize",
            "/v1/oauth/a3e5229a-1060-44d8-bbbc-24944c1c9d73/authorize?client_id=123",
            "/api/auth/login",
            "/login",
            "/login?reauth=1",
            "/logout",
            "/callback?code=xyz",
        ];
        for path in auth_paths {
            let is_auth = path.starts_with("/oauth")
                || path.starts_with("/v1/oauth")
                || path.starts_with("/api/auth")
                || path.starts_with("/login")
                || path.starts_with("/logout")
                || path.starts_with("/signin")
                || path.starts_with("/signup")
                || path.contains("/authorize")
                || path.contains("/callback");
            assert!(is_auth, "expected {path} to be detected as auth path");
        }

        let non_auth_paths = [
            "/assets/main.css",
            "/images/logo.png",
            "/index.html",
            "/v1/models",
        ];
        for path in non_auth_paths {
            let is_auth = path.starts_with("/oauth")
                || path.starts_with("/v1/oauth")
                || path.starts_with("/api/auth")
                || path.starts_with("/login")
                || path.starts_with("/logout")
                || path.starts_with("/signin")
                || path.starts_with("/signup")
                || path.contains("/authorize")
                || path.contains("/callback");
            assert!(!is_auth, "expected {path} to NOT be detected as auth path");
        }
    }

    #[test]
    fn test_post_protection_evaluation_logic() {
        use conduit_common::config::PostProtectionConfig;

        let post_cfg = PostProtectionConfig {
            enabled: true,
            action: "block".into(),
            browser_only: true,
            block_uncategorized_bad_tld: true,
            block_uncategorized_high_entropy: true,
            entropy_threshold: 3.5,
            max_uncategorized_body_bytes: 8192,
            exempt_user_agents: vec![],
        };

        let browser_ua =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        let is_browser = post_cfg.is_interactive_browser(Some(browser_ua), true);
        assert!(is_browser);

        // Case 1: Bad TLD on uncategorized domain -> trigger
        let host_bad_tld = "login-update.top";
        let tld = crate::threat::heuristics::extract_tld(host_bad_tld);
        let is_bad = crate::threat::heuristics::is_bad_tld_name(tld);
        assert!(is_bad);

        // Case 2: High entropy on uncategorized domain -> trigger
        let host_dga = "x8k2m9p1q7r4w2.com";
        let domain_part = crate::threat::heuristics::domain_without_tld(host_dga);
        let entropy = crate::threat::entropy::shannon_entropy(domain_part);
        assert!(entropy >= post_cfg.entropy_threshold);

        // Case 3: Body size threshold -> trigger
        let payload_size = 10000;
        assert!(payload_size > post_cfg.max_uncategorized_body_bytes);

        // Case 4: Normal low entropy domain on good TLD with small body -> allowed
        let normal_host = "example.org";
        let normal_domain = crate::threat::heuristics::domain_without_tld(normal_host);
        let normal_entropy = crate::threat::entropy::shannon_entropy(normal_domain);
        let normal_tld = crate::threat::heuristics::extract_tld(normal_host);
        assert!(!crate::threat::heuristics::is_bad_tld_name(normal_tld));
        assert!(normal_entropy < post_cfg.entropy_threshold);
        let small_payload = 1024;
        assert!(small_payload <= post_cfg.max_uncategorized_body_bytes);
    }
}
