use async_trait::async_trait;
use conduit_common::config::ClearGateConfig;
use conduit_common::types::{AuthMethod, BlockReason, LogEntry, PolicyAction};
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
        let client_ip = stream
            .get_socket_digest()
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
            let h2c_enabled = self
                .config
                .downstream
                .as_ref()
                .map(|d| d.h2c)
                .unwrap_or(false);
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
        let req_header = session.req_header();
        let target = if let Some(auth) = req_header.uri.authority() {
            auth.as_str()
        } else if let Some(host_hdr) = req_header.headers.get("Host").and_then(|h| h.to_str().ok())
        {
            host_hdr
        } else {
            std::str::from_utf8(req_header.raw_path()).unwrap_or("")
        };
        let (host, port) = parse_connect_authority(target);
        let client_ip_raw = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let port_suffix = client_ip_raw
            .rsplit_once(':')
            .map(|(_, p)| format!(":{p}"))
            .unwrap_or_default();
        let normalized_ip =
            crate::proxy::normalize_client_ip(crate::proxy::extract_ip_from_addr(&client_ip_raw));
        let client_ip = format!("{normalized_ip}{port_suffix}");

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

        // Fall back to IP mapping or local OS user
        if username.is_none() {
            let identity =
                crate::identity::resolve_client_identity(&self.pool, &client_ip_raw).await;
            if identity.username.is_some() {
                username = identity.username;
                auth_method = identity.auth_method;
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

        let is_allowlisted = self
            .config
            .allowlist
            .as_ref()
            .map(|a| a.is_allowed(&host, port, None, Some(&client_ip)))
            .unwrap_or(false);

        // Rate limiting for CONNECT
        if let Some(ref limiter) = self.rate_limiter {
            let ip_only = crate::proxy::extract_ip_from_addr(&client_ip);
            if let Err(_kind) = limiter.check_rate(ip_only, username.as_deref(), &host) {
                crate::metrics::record_rate_limit();
                info!(host = %host, client_ip = %client_ip, "CONNECT rate limited");
                let mut resp = ResponseHeader::build(429, Some(1)).unwrap();
                resp.insert_header("Retry-After", &limiter.window_secs().to_string())
                    .ok();
                let _ = session.write_response_header(Box::new(resp)).await;
                return None;
            }
        }

        // Policy evaluation
        let category = policy::categories::lookup_category(&self.pool, &host).await;
        let rt_cfg = crate::runtime_config::get();

        let (action, rule_id, matched_rule_name) = if is_allowlisted {
            (PolicyAction::Allow, None, Some("Allowlist".to_string()))
        } else {
            policy::rules::evaluate(
                &self.pool,
                &host,
                category.as_deref(),
                username.as_deref(),
                &[],
                rt_cfg.fail_closed,
            )
            .await
        };

        // Explicit allow rules (from operator policies or allowlist) override general egress port restrictions
        let is_explicitly_allowed =
            is_allowlisted || (action == PolicyAction::Allow && rule_id.is_some());

        // Egress port restriction check (allowlisted or explicitly policy-allowed destinations bypass this)
        if !is_explicitly_allowed {
            if let Some(ref egress) = self.config.egress {
                if !egress.is_connect_port_allowed(port) {
                    info!(host = %host, port, client_ip = %client_ip, "CONNECT rejected: port not permitted by egress policy");
                    let resp = ResponseHeader::build(403, Some(1)).unwrap();
                    let _ = session.write_response_header(Box::new(resp)).await;

                    let node_name = crate::block_page::get_node_name(&self.config);
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
                        rule_id: None,
                        status_code: 403,
                        request_bytes: 0,
                        response_bytes: 0,
                        duration_ms: 0,
                        tls_intercepted: false,
                        upstream_addr: None,
                        content_type: None,
                        cache_status: None,
                        node_id: self.config.node.as_ref().map(|n| n.node_id.clone()),
                        node_name: Some(node_name),
                        threat_score: None,
                        threat_tier: None,
                        threat_blocked: None,
                        block_reason: Some(BlockReason::Policy),
                        rule_name: Some("EgressPortRestriction".to_string()),
                        threat_signals: None,
                        dlp_matches: None,
                    };
                    self.log_tx.send(entry);
                    return None;
                }
            }
        }

        // TLD protection evaluation (skipped for allowlisted hosts)
        let mut tld_blocked = false;
        let mut blocked_tld_name = String::new();
        if !is_allowlisted {
            let tld_cfg = rt_cfg.effective_tld_protection(self.config.tld_protection.as_ref());
            if tld_cfg.enabled {
                let host_tld = crate::threat::heuristics::extract_tld(&host);
                let is_known_bad = crate::threat::heuristics::is_bad_tld_name(host_tld);
                if tld_cfg.is_tld_blocked(host_tld, is_known_bad) {
                    if tld_cfg.action == "block" || rt_cfg.prevention_mode {
                        tld_blocked = true;
                        blocked_tld_name = host_tld.to_string();
                    }
                }
            }
        }

        // Threat evaluation (skipped for allowlisted hosts)
        let mut threat_blocked = false;
        let mut rep_blocked = false;
        let mut threat_verdict: Option<conduit_common::types::ThreatVerdict> = None;
        if !is_allowlisted {
            if let Some(ref engine) = self.threat_engine {
                let verdict = crate::threat::evaluate_request(
                    engine,
                    &host,
                    port,
                    "/",
                    "https",
                    category.as_deref(),
                    None,
                    None,
                    None,
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
        }

        let should_block = tld_blocked
            || ((threat_blocked || action == PolicyAction::Block) && rt_cfg.prevention_mode);
        if should_block {
            let block_reason = if tld_blocked {
                BlockReason::RiskyTld
            } else if threat_blocked {
                if rep_blocked {
                    BlockReason::ThreatReputation
                } else {
                    BlockReason::ThreatHeuristic
                }
            } else {
                BlockReason::Policy
            };
            let reason_text = match block_reason {
                BlockReason::RiskyTld => format!("High-risk TLD (.{blocked_tld_name})"),
                BlockReason::ThreatReputation => "Threat detected (reputation)".to_string(),
                BlockReason::ThreatHeuristic => "Threat detected (heuristic)".to_string(),
                BlockReason::Policy => match matched_rule_name {
                    Some(ref name) => format!("Policy rule: {name}"),
                    None => "Policy".to_string(),
                },
                other => format!("{other:?}"),
            };

            info!(host = %host, category = ?category, reason = %reason_text, "Blocking CONNECT");

            let node_name = crate::block_page::get_node_name(&self.config);
            let entry_uuid = uuid::Uuid::new_v4();
            let simple_hex = entry_uuid.simple().to_string();
            let ref_id = format!("cnd-{}-{}", &simple_hex[..4], &simple_hex[4..8]);
            let entry_id = entry_uuid.to_string();
            let now = chrono::Utc::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

            if rt_cfg.tls_intercept {
                let resp = ResponseHeader::build(200, Some(0)).unwrap();
                if session.write_response_header(Box::new(resp)).await.is_err() {
                    return None;
                }
                if session.finish_body().await.is_err() {
                    return None;
                }
                let raw_stream = match session {
                    ServerSession::H1(s) => s.into_inner(),
                    _ => return None,
                };

                let block_ctx = if tld_blocked {
                    crate::block_page::BlockPageContext::for_risky_tld(
                        &host,
                        "/",
                        "CONNECT",
                        &blocked_tld_name,
                        username.as_deref(),
                        &client_ip,
                        &timestamp,
                        &ref_id,
                        &node_name,
                    )
                } else if threat_blocked {
                    crate::block_page::BlockPageContext::for_threat(
                        &host,
                        "/",
                        "GET",
                        &reason_text,
                        category.as_deref().or(Some("malicious")),
                        username.as_deref(),
                        &client_ip,
                        &timestamp,
                        &ref_id,
                        &node_name,
                    )
                } else {
                    crate::block_page::BlockPageContext::for_policy(
                        &host,
                        "/",
                        "GET",
                        matched_rule_name.as_deref(),
                        category.as_deref(),
                        username.as_deref(),
                        &client_ip,
                        &timestamp,
                        &ref_id,
                        &node_name,
                    )
                };

                tunnel::serve_block_page(
                    raw_stream,
                    &host,
                    &self.cert_cache,
                    block_ctx,
                    self.config.block_page_html.as_deref(),
                )
                .await;
            } else {
                let resp = ResponseHeader::build(403, Some(1)).unwrap();
                let _ = session.write_response_header(Box::new(resp)).await;
            }

            let threat_score = threat_verdict.as_ref().map(|v| v.score);
            let threat_tier = threat_verdict.as_ref().map(|v| v.tier_reached);
            let threat_signals = threat_verdict
                .as_ref()
                .filter(|v| !v.signals.is_empty())
                .map(|v| v.signals.clone());
            let entry = LogEntry {
                id: entry_id,
                timestamp: now,
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
                tls_intercepted: rt_cfg.tls_intercept,
                upstream_addr: None,
                content_type: None,
                cache_status: None,
                node_id: self.config.node.as_ref().map(|n| n.node_id.clone()),
                node_name: Some(node_name),
                threat_score,
                threat_tier,
                threat_blocked: if threat_blocked { Some(true) } else { None },
                block_reason: Some(block_reason),
                rule_name: if tld_blocked {
                    Some(format!("RiskyTLD:.{blocked_tld_name}"))
                } else {
                    matched_rule_name
                },
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

        let raw_stream = match session {
            ServerSession::H1(s) => s.into_inner(),
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

#[allow(dead_code)]
pub(crate) fn build_block_html(
    host: &str,
    category: &str,
    reason: &str,
    config: &ClearGateConfig,
) -> String {
    crate::block_page::build_block_html(host, category, reason, config)
}
