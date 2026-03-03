use async_trait::async_trait;
use conduit_common::ca::CertAuthority;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{AuthMethod, LogEntry, PolicyAction};
use conduit_common::util::html_escape;
use deadpool_redis::Pool;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use pingora_http::ResponseHeader;
use pingora_proxy::HttpProxy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

/// Shared counters for heartbeat reporting.
pub static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

use crate::identity::basic_auth;
use crate::logging::LogSender;
use crate::mitm::cert_cache::CertCache;
use crate::mitm::tunnel;
use crate::policy;
use crate::proxy::ClearGateProxy;
use crate::threat::ThreatEngine;

/// Custom ServerApp that handles both plain HTTP proxying and CONNECT tunneling.
///
/// For CONNECT requests: responds 200, extracts raw stream, pipes bidirectionally.
/// For plain HTTP/HTTPS requests: delegates to Pingora's `HttpProxy<ClearGateProxy>`
/// which handles connection pooling, keep-alive, H2, and all HTTP semantics.
pub struct ClearGateService {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    pub ca: Arc<CertAuthority>,
    pub cert_cache: Arc<CertCache>,
    pub log_tx: LogSender,
    /// Internal Pingora HTTP proxy for non-CONNECT requests.
    pub http_proxy: Arc<HttpProxy<ClearGateProxy>>,
    pub threat_engine: Option<Arc<ThreatEngine>>,
}

#[async_trait]
impl ServerApp for ClearGateService {
    async fn process_new(
        self: &Arc<Self>,
        mut stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);

        // Peek at the first bytes to detect CONNECT without consuming them.
        // "CONNECT " is 8 bytes. If peek isn't supported, fall through to Pingora.
        let mut peek_buf = [0u8; 8];
        let is_connect = match stream.try_peek(&mut peek_buf).await {
            Ok(true) => peek_buf.starts_with(b"CONNECT "),
            _ => false,
        };

        if is_connect {
            // Read the full request ourselves for CONNECT handling
            let mut session = ServerSession::new_http1(stream);
            session.set_keepalive(None); // CONNECT tunnels aren't reusable

            match session.read_request().await {
                Ok(true) => {}
                _ => {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return None;
                }
            }

            let result = self.handle_connect(session).await;
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            return result;
        }

        // Plain HTTP: delegate the untouched stream to Pingora's HttpProxy.
        // Pingora will read the request, handle upstream, pooling, keep-alive, etc.
        let result = self.http_proxy.process_new(stream, shutdown).await;
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        result
    }
}

impl ClearGateService {
    /// Handle a CONNECT request by responding 200, extracting the stream,
    /// and piping bytes bidirectionally to the upstream.
    async fn handle_connect(
        self: &Arc<Self>,
        mut session: ServerSession,
    ) -> Option<Stream> {
        let uri = session.req_header().uri.clone();
        let (host, port) = parse_connect_authority(&uri.to_string());
        let client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();

        debug!(host = %host, port, "CONNECT request");

        // Auth check for CONNECT — parse and validate Proxy-Authorization
        let mut username: Option<String> = None;
        let mut auth_method: Option<AuthMethod> = None;
        if let Some(auth_header) = session.req_header().headers.get("Proxy-Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(identity) =
                    basic_auth::try_basic_auth_from_header(auth_str, &self.pool).await
                {
                    username = identity.username;
                    auth_method = identity.auth_method;
                }
            }
        }

        if self.config.auth_required && username.is_none() {
            info!(host = %host, client_ip = %client_ip, "CONNECT rejected: auth required");
            let mut resp = ResponseHeader::build(407, Some(2)).unwrap();
            resp.insert_header("Proxy-Authenticate", "Basic realm=\"ClearGate\"")
                .ok();
            resp.insert_header("Content-Length", "0").ok();
            let _ = session.write_response_header(Box::new(resp)).await;
            return None;
        }

        // Check policy before establishing tunnel
        let category = policy::categories::lookup_category(&self.pool, &host).await;

        // Threat detection: heuristics (deterministic) + reputation check (learned)
        let mut threat_blocked = false;
        let mut threat_score = None;
        let mut threat_tier = None;
        if let Some(ref engine) = self.threat_engine {
            // 1. Deterministic heuristic scoring
            let verdict = crate::threat::evaluate_request(
                engine, &host, port, "/", "https",
                category.as_deref(), None,
            );
            threat_blocked = verdict.blocked;
            threat_score = Some(verdict.score);
            threat_tier = Some(verdict.tier_reached);

            // 2. Reputation check — only at CONNECT boundary.
            //    If Tier 2 content analysis previously flagged this domain, block it.
            if !threat_blocked {
                if let Some(rep_score) = crate::threat::check_reputation(engine, &host) {
                    threat_blocked = true;
                    threat_score = Some(rep_score);
                    threat_tier = Some(conduit_common::types::ThreatTier::Tier2); // reputation originates from T2 content analysis
                }
            }
        }

        let (action, _rule_id) = policy::rules::evaluate(
            &self.pool,
            &host,
            category.as_deref(),
            username.as_deref(),
            &[],
            self.config.fail_closed,
        )
        .await;

        if threat_blocked || action == PolicyAction::Block {
            info!(host = %host, category = ?category, "Blocking CONNECT");

            if self.config.tls_intercept {
                // MITM block: accept CONNECT, do TLS handshake, serve block page
                let resp = ResponseHeader::build(200, Some(0)).unwrap();
                if session.write_response_header(Box::new(resp)).await.is_err() {
                    return None;
                }
                if session.finish_body().await.is_err() {
                    return None;
                }
                let raw_stream = match session.finish().await {
                    Ok(Some(s)) => s,
                    _ => return None,
                };

                let cat_label = category.as_deref().unwrap_or("uncategorized");
                let block_html = build_block_html(&host, cat_label, &self.config);
                tunnel::serve_block_page(
                    raw_stream,
                    &host,
                    &self.ca,
                    &self.cert_cache,
                    &block_html,
                )
                .await;
            } else {
                // No MITM — bare 403 is all we can do
                let resp = ResponseHeader::build(403, Some(1)).unwrap();
                let _ = session.write_response_header(Box::new(resp)).await;
            }

            let entry = LogEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                client_ip: client_ip.clone(),
                username: username.clone(),
                auth_method,
                method: "CONNECT".into(),
                scheme: "https".into(),
                host: host.clone(),
                port,
                path: "/".into(),
                full_url: format!("https://{host}:{port}/"),
                category: category.clone(),
                action: PolicyAction::Block,
                rule_id: _rule_id.clone(),
                status_code: 403,
                request_bytes: 0,
                response_bytes: 0,
                duration_ms: 0,
                tls_intercepted: self.config.tls_intercept,
                upstream_addr: None,
                content_type: None,
                node_id: None,
                node_name: None,
                threat_score,
                threat_tier,
                threat_blocked: if threat_blocked { Some(true) } else { None },
            };
            self.log_tx.send(entry);

            return None;
        }

        // Respond 200 Connection Established
        let resp = ResponseHeader::build(200, Some(0)).unwrap();
        if session.write_response_header(Box::new(resp)).await.is_err() {
            return None;
        }
        if session.finish_body().await.is_err() {
            return None;
        }

        // Get the underlying raw stream for bidirectional piping
        let raw_stream = match session.finish().await {
            Ok(Some(s)) => s,
            _ => return None,
        };

        // Run tunnel inline — MITM or passthrough depending on config
        tunnel::handle_connect_tunnel(
            raw_stream,
            host,
            port,
            self.ca.clone(),
            self.cert_cache.clone(),
            self.config.clone(),
            self.pool.clone(),
            LogSender(self.log_tx.0.clone()),
            client_ip,
            category,
            username,
            auth_method,
            threat_score,
            threat_tier,
            self.threat_engine.clone(),
        )
        .await;

        None // Connection is consumed by the tunnel
    }
}

fn parse_connect_authority(s: &str) -> (String, u16) {
    parse_host_port(s, 443)
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

fn build_block_html(host: &str, category: &str, config: &ClearGateConfig) -> String {
    let template = config.block_page_html.as_deref().unwrap_or(
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
    template
        .replace("{{HOST}}", &html_escape(host))
        .replace("{{CATEGORY}}", &html_escape(category))
}

