use async_trait::async_trait;
use bytes::Bytes;
use conduit_common::ca::CertAuthority;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{LogEntry, PolicyAction};
use conduit_common::util::html_escape;
use deadpool_redis::Pool;
use http::Method;
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

/// Core proxy struct implementing Pingora's ProxyHttp trait.
pub struct ClearGateProxy {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    #[allow(dead_code)] // Held for Arc reference; MITM uses ClearGateService's copy
    pub ca: Arc<CertAuthority>,
    #[allow(dead_code)]
    pub cert_cache: Arc<CertCache>,
    pub log_tx: LogSender,
}

impl ClearGateProxy {
    pub fn new(
        config: Arc<ClearGateConfig>,
        pool: Arc<Pool>,
        ca: Arc<CertAuthority>,
        cert_cache: Arc<CertCache>,
        log_tx: mpsc::Sender<LogEntry>,
    ) -> Self {
        Self {
            config,
            pool,
            ca,
            cert_cache,
            log_tx: LogSender(log_tx),
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

    fn build_block_page(&self, host: &str, category: &str) -> Bytes {
        let html = self.config.block_page_html.as_deref().unwrap_or(
            r#"<!DOCTYPE html>
<html><head><title>Access Blocked - ClearGate</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0f172a;color:#e2e8f0}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:3rem;max-width:500px;text-align:center}
h1{color:#f87171;margin:0 0 1rem}
.domain{color:#60a5fa;font-family:monospace;font-size:1.1em}
.cat{color:#a78bfa;text-transform:uppercase;font-size:0.85em;letter-spacing:0.05em}
</style></head>
<body><div class="card">
<h1>Access Blocked</h1>
<p>Your request to <span class="domain">{{HOST}}</span> has been blocked.</p>
<p class="cat">Category: {{CATEGORY}}</p>
<p style="color:#64748b;font-size:0.85em">conduit proxy</p>
</div></body></html>"#,
        );
        Bytes::from(
            html.replace("{{HOST}}", &html_escape(host))
                .replace("{{CATEGORY}}", &html_escape(category)),
        )
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
        // Extract client IP
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
            // For absolute-form proxy requests (GET http://host/path HTTP/1.1),
            // extract just the path component, not the full URI.
            ctx.path = extract_path_from_uri(uri);
        }

        // Identify user (Kerberos -> Basic -> IP map)
        ctx.identity = identity::identify(session, &self.pool, &self.config).await;

        // If auth required and no user identified, send 407
        if self.config.auth_required && ctx.identity.username.is_none() {
            let mut resp = ResponseHeader::build(407, Some(4))?;
            resp.insert_header("Proxy-Authenticate", "Basic realm=\"ClearGate\"")?;
            resp.insert_header("Content-Length", "0")?;
            session
                .write_response_header(Box::new(resp), true)
                .await?;
            ctx.response_status = 407;
            return Ok(true);
        }

        // Category lookup
        ctx.category = policy::categories::lookup_category(&self.pool, &ctx.host).await;

        // Policy evaluation
        let (action, rule_id) = policy::rules::evaluate(
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

        // Block if policy says so
        if ctx.action == PolicyAction::Block {
            debug!(host = %ctx.host, category = ?ctx.category, "Blocking request");
            let body = self.build_block_page(
                &ctx.host,
                ctx.category.as_deref().unwrap_or("uncategorized"),
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
        let tls = ctx.scheme == "https" || ctx.is_connect;
        let addr = (ctx.host.as_str(), ctx.port);
        let mut peer = HttpPeer::new(addr, tls, ctx.host.clone());
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

    /// Capture resolved upstream address after connection is established.
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
                }
            }
        }
        Ok(())
    }

    /// Capture response status code.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();
        Ok(())
    }

    /// Track response body size.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if let Some(b) = body {
            ctx.response_bytes += b.len() as u64;
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
            content_type: None,
            node_id: None,
            node_name: None,
        };

        self.log_tx.send(entry);
    }
}
