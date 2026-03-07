pub mod ca;
pub mod categories;
pub mod config;
pub mod dlp;
pub mod health;
pub mod import;
pub mod logs;
pub mod nodes;
pub mod policies;
pub mod stats;
pub mod threat;

use crate::AppState;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use conduit_common::redis::keys;
use conduit_common::util::constant_time_eq;
use deadpool_redis::Pool;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::RateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::info;

/// Per-IP rate limiter for the management API.
pub type ApiRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// Extract client IP from ConnectInfo extensions (set by into_make_service_with_connect_info).
fn peer_ip(req: &Request) -> String {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Publish a config reload notification to all proxy nodes via pub/sub.
pub async fn publish_reload(pool: &Pool, what: &str) {
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("PUBLISH")
            .arg(keys::CONFIG_RELOAD_CHANNEL)
            .arg(what)
            .query_async(&mut *conn)
            .await;
    }
}

/// API key authentication middleware.
/// If `config.api_key` is set, all requests must include a matching
/// `Authorization: Bearer <key>` or `X-API-Key: <key>` header.
async fn api_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(ref expected_key) = state.config.api_key {
        let provided = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                req.headers()
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
            });

        match provided {
            Some(key) if constant_time_eq(key.as_bytes(), expected_key.as_bytes()) => {}
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        }
    }
    next.run(req).await
}

/// Per-IP rate limiting middleware.
async fn rate_limit(
    State(limiter): State<Arc<ApiRateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let ip = peer_ip(&req);

    match limiter.check_key(&ip) {
        Ok(_) => next.run(req).await,
        Err(_) => {
            tracing::warn!(client_ip = %ip, "API rate limit exceeded");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                "Rate limit exceeded",
            )
                .into_response()
        }
    }
}

/// Log mutating API requests for audit trail.
/// Uses the TCP peer address (ConnectInfo) rather than the spoofable X-Forwarded-For header.
async fn audit_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    // Only log mutating requests
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    let client_ip = peer_ip(&req);

    let response = next.run(req).await;
    let status = response.status().as_u16();

    info!(
        method = %method,
        path = %path,
        status,
        client_ip = %client_ip,
        "audit"
    );

    response
}

/// Add standard security headers to all responses.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    );
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
    response
}

pub fn build_router(state: Arc<AppState>, limiter: Arc<ApiRateLimiter>) -> Router {
    // Public endpoints (no auth required)
    let public_api = Router::new()
        .merge(health::routes())
        .merge(ca::routes());

    // Protected endpoints (require API key when configured)
    let protected_api = Router::new()
        .merge(stats::routes())
        .merge(logs::routes())
        .merge(categories::routes())
        .merge(policies::routes())
        .merge(dlp::routes())
        .merge(config::routes())
        .merge(import::routes())
        .merge(nodes::routes())
        .merge(threat::routes())
        .route_layer(middleware::from_fn(audit_log))
        .route_layer(middleware::from_fn_with_state(state.clone(), api_auth));

    let api = Router::new()
        .merge(public_api)
        .merge(protected_api);

    let mut router = Router::new()
        .nest("/api/v1", api)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(limiter, rate_limit))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Serve static SvelteKit UI files if configured
    if let Some(ref ui_dir) = state.config.ui_dir {
        let index = format!("{}/index.html", ui_dir);
        let serve_dir = ServeDir::new(ui_dir).fallback(ServeFile::new(&index));
        router = router.fallback_service(serve_dir);
    }

    router
}
