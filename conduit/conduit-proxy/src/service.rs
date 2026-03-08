use async_trait::async_trait;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{AuthMethod, BlockReason, LogEntry, PolicyAction};
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
use tracing::{debug, info, warn};

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
pub struct ClearGateService {
    pub config: Arc<ClearGateConfig>,
    pub pool: Arc<Pool>,
    pub cert_cache: Arc<CertCache>,
    pub log_tx: LogSender,
    pub http_proxy: Arc<HttpProxy<ClearGateProxy>>,
    pub threat_engine: Option<Arc<ThreatEngine>>,
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    pub conn_tracker: Option<Arc<crate::conn_limit::ConnectionTracker>>,
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
        crate::metrics::inc_active_connections();

        // Connection limit check — extract client IP from socket digest.
        // Stream is Box<dyn IO> which requires GetSocketDigest, so we can call it directly.
        let client_ip = stream.get_socket_digest()
            .and_then(|d| d.peer_addr().map(|a| a.to_string()))
            .unwrap_or_default();

        // The connection guard MUST live until process_new returns — its Drop decrements
        // the per-IP counter. The `_conn_guard` binding keeps it alive for the entire scope.
        let _conn_guard = if let Some(ref tracker) = self.conn_tracker {
            let ip_only = crate::proxy::extract_ip_from_addr(&client_ip).to_string();
            match tracker.try_acquire(&ip_only) {
                Ok(guard) => Some(guard),
                Err(_count) => {
                    warn!(client_ip = %client_ip, "Connection rejected: limit exceeded");
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    crate::metrics::dec_active_connections();
                    return None;
                }
            }
        } else {
            None
        };

        // Peek at the first bytes to detect CONNECT or H2 preface
        let mut peek_buf = [0u8; 24]; // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" is 24 bytes
        let is_connect;
        let is_h2_preface;
        match stream.try_peek(&mut peek_buf).await {
            Ok(true) => {
                is_connect = peek_buf[..8].starts_with(b"CONNECT ");
                // H2 connection preface starts with "PRI * HT"
                is_h2_preface = peek_buf[..8].starts_with(b"PRI * HT");
            }
            _ => {
                is_connect = false;
                is_h2_preface = false;
            }
        };

        // H2C: if downstream speaks cleartext HTTP/2 and h2c is enabled, let Pingora handle it
        if is_h2_preface {
            let h2c_enabled = self.config.downstream.as_ref().map(|d| d.h2c).unwrap_or(false);
            if h2c_enabled {
                debug!("H2C connection detected, delegating to Pingora");
                let result = self.http_proxy.process_new(stream, shutdown).await;
                ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                crate::metrics::dec_active_connections();
                return result;
            }
        }

        if is_connect {
            let mut session = ServerSession::new_http1(stream);
            session.set_keepalive(None);

            match session.read_request().await {
                Ok(true) => {}
                _ => {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    crate::metrics::dec_active_connections();
                    return None;
                }
            }

            let result = self.handle_connect(session, shutdown).await;
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            crate::metrics::dec_active_connections();
            return result;
        }

        let result = self.http_proxy.process_new(stream, shutdown).await;
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        crate::metrics::dec_active_connections();
        result
    }
}

impl ClearGateService {
    async fn handle_connect(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let uri = session.req_header().uri.clone();
        let (host, port) = parse_connect_authority(&uri.to_string());
        let client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();

        debug!(host = %host, port, "CONNECT request");

        // Auth check
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
            resp.insert_header("Proxy-Authenticate", "Basic realm=\"Conduit\"")
                .ok();
            resp.insert_header("Content-Length", "0").ok();
            let _ = session.write_response_header(Box::new(resp)).await;
            return None;
        }

        // Rate limiting for CONNECT
        if let Some(ref limiter) = self.rate_limiter {
            let ip_only = crate::proxy::extract_ip_from_addr(&client_ip);
            if let Err(_kind) = limiter.check_rate(
                ip_only,
                username.as_deref(),
                &host,
            ) {
                crate::metrics::record_rate_limit();
                info!(host = %host, client_ip = %client_ip, "CONNECT rate limited");
                let mut resp = ResponseHeader::build(429, Some(1)).unwrap();
                resp.insert_header("Retry-After", &limiter.window_secs().to_string()).ok();
                let _ = session.write_response_header(Box::new(resp)).await;
                return None;
            }
        }

        // Policy + threat evaluation
        let category = policy::categories::lookup_category(&self.pool, &host).await;

        let mut threat_blocked = false;
        let mut rep_blocked = false;
        let mut threat_verdict: Option<conduit_common::types::ThreatVerdict> = None;
        if let Some(ref engine) = self.threat_engine {
            let verdict = crate::threat::evaluate_request(
                engine, &host, port, "/", "https",
                category.as_deref(), None, None, None,
            );
            threat_blocked = verdict.blocked;

            if !threat_blocked {
                if let Some(rep_score) = crate::threat::check_reputation(engine, &host) {
                    threat_blocked = true;
                    rep_blocked = true;
                    threat_verdict = Some(conduit_common::types::ThreatVerdict {
                        score: rep_score,
                        blocked: true,
                        tier_reached: conduit_common::types::ThreatTier::Tier2,
                        signals: verdict.signals.clone(),
                        reputation_score: Some(rep_score),
                    });
                }
            }

            if threat_verdict.is_none() {
                threat_verdict = Some(verdict);
            }
        }

        let (action, rule_id, matched_rule_name) = policy::rules::evaluate(
            &self.pool,
            &host,
            category.as_deref(),
            username.as_deref(),
            &[],
            self.config.fail_closed,
        )
        .await;

        if threat_blocked || action == PolicyAction::Block {
            let block_reason = if threat_blocked {
                if rep_blocked { BlockReason::ThreatReputation } else { BlockReason::ThreatHeuristic }
            } else {
                BlockReason::Policy
            };
            let reason_text = match block_reason {
                BlockReason::ThreatReputation => "Threat detected (reputation)".to_string(),
                BlockReason::ThreatHeuristic => "Threat detected (heuristic)".to_string(),
                BlockReason::Policy => match matched_rule_name {
                    Some(ref name) => format!("Policy rule: {name}"),
                    None => "Policy".to_string(),
                },
                other => format!("{other:?}"),
            };

            info!(host = %host, category = ?category, "Blocking CONNECT");

            if self.config.tls_intercept {
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
                let block_html = build_block_html(&host, cat_label, &reason_text, &self.config);
                tunnel::serve_block_page(
                    raw_stream,
                    &host,
                    &self.cert_cache,
                    &block_html,
                )
                .await;
            } else {
                let resp = ResponseHeader::build(403, Some(1)).unwrap();
                let _ = session.write_response_header(Box::new(resp)).await;
            }

            let threat_score = threat_verdict.as_ref().map(|v| v.score);
            let threat_tier = threat_verdict.as_ref().map(|v| v.tier_reached);
            let threat_signals = threat_verdict.as_ref()
                .filter(|v| !v.signals.is_empty())
                .map(|v| v.signals.clone());
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
                rule_id: rule_id.clone(),
                status_code: 403,
                request_bytes: 0,
                response_bytes: 0,
                duration_ms: 0,
                tls_intercepted: self.config.tls_intercept,
                upstream_addr: None,
                content_type: None,
                cache_status: None,
                node_id: None,
                node_name: None,
                threat_score,
                threat_tier,
                threat_blocked: if threat_blocked { Some(true) } else { None },
                block_reason: Some(block_reason),
                rule_name: matched_rule_name,
                threat_signals,
                dlp_matches: None,
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

        let raw_stream = match session.finish().await {
            Ok(Some(s)) => s,
            _ => return None,
        };

        let threat_score = threat_verdict.as_ref().map(|v| v.score);
        let threat_tier = threat_verdict.as_ref().map(|v| v.tier_reached);

        tunnel::handle_connect_tunnel(
            raw_stream,
            host,
            port,
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
            self.http_proxy.clone(),
            shutdown.clone(),
        )
        .await;

        None
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

pub(crate) fn build_block_html(host: &str, category: &str, reason: &str, config: &ClearGateConfig) -> String {
    let template = config.block_page_html.as_deref().unwrap_or(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Blocked</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fafafa;color:#18181b}
.card{background:#fff;border:1px solid #e4e4e7;border-radius:10px;padding:2.5rem 3rem;max-width:480px;width:90%;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.icon{width:48px;height:48px;margin:0 auto 1.25rem;background:#fff1f2;border-radius:50%;display:flex;align-items:center;justify-content:center}
.icon svg{width:24px;height:24px;color:#be123c}
h1{font-size:1.25rem;font-weight:600;color:#18181b;margin:0 0 .75rem}
p{margin:.5rem 0;line-height:1.5}
.domain{color:#be123c;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;word-break:break-all}
.cat{color:#71717a;text-transform:uppercase;font-size:.75rem;font-weight:500;letter-spacing:.06em;margin-top:1rem}
.reason{color:#71717a;font-size:.85rem}
.footer{color:#a1a1aa;font-size:.75rem;margin-top:1.5rem;padding-top:1rem;border-top:1px solid #f4f4f5}
@media(prefers-color-scheme:dark){
body{background:#18181b;color:#fafafa}
.card{background:#27272a;border-color:#3f3f46;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.icon{background:#4c0519}
.icon svg{color:#fb7185}
h1{color:#fafafa}
.domain{color:#fb7185}
.cat,.reason{color:#a1a1aa}
.footer{color:#71717a;border-color:#3f3f46}
}
</style></head>
<body><div class="card">
<div class="icon"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/></svg></div>
<h1>Access Blocked</h1>
<p>Your request to <span class="domain">{{HOST}}</span> has been blocked.</p>
<p class="cat">{{CATEGORY}}</p>
<p class="reason">{{REASON}}</p>
<p class="footer">conduit proxy</p>
</div></body></html>"#,
    );
    template
        .replace("{{HOST}}", &html_escape(host))
        .replace("{{CATEGORY}}", &html_escape(category))
        .replace("{{REASON}}", &html_escape(reason))
}
