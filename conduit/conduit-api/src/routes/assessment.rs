//! Authenticated management of explicitly scoped assessment sessions and encrypted flows.
use crate::AppState;
use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use conduit_common::assessment::{self, AssessmentSession, CapturedFlow, CapturedMessage};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": message})))
}
fn internal(_: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "assessment datastore or encryption unavailable",
    )
}
fn require_enabled(state: &AppState) -> Result<(), (StatusCode, Json<Value>)> {
    if assessment_api_key(state).is_none() {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "assessment API requires CONDUIT_ASSESSMENT_API_KEY or a configured api_key",
        ));
    }
    assessment::encryption_key().map_err(internal)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSession {
    origins: Vec<String>,
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
    #[serde(default = "default_body")]
    max_body_bytes: usize,
    #[serde(default = "default_flows")]
    max_flows: usize,
}
fn default_ttl() -> u64 {
    3600
}
fn default_body() -> usize {
    256 * 1024
}
fn default_flows() -> usize {
    500
}

async fn create(State(state): State<Arc<AppState>>, Json(input): Json<CreateSession>) -> ApiResult {
    require_enabled(&state)?;
    if input.origins.is_empty()
        || input.origins.len() > 32
        || input.ttl_seconds == 0
        || input.ttl_seconds > assessment::MAX_TTL
        || input.max_body_bytes > assessment::MAX_BODY
        || input.max_flows == 0
        || input.max_flows > assessment::MAX_FLOWS
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "provide 1–32 origins, TTL 1–86400s, body cap 0–1048576 bytes, and flow cap 1–1000",
        ));
    }
    let origins: Result<Vec<_>, _> = input
        .origins
        .iter()
        .map(|url| assessment::origin(url))
        .collect();
    let origins = origins.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "origins must be absolute HTTP(S) URLs without credentials",
        )
    })?;
    let session = AssessmentSession {
        id: uuid::Uuid::new_v4().to_string(),
        token: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
        origins,
        expires_at: chrono::Utc::now().timestamp() + input.ttl_seconds as i64,
        max_body_bytes: input.max_body_bytes,
        max_flows: input.max_flows,
    };
    let key = assessment::session_key(&session.id);
    let encrypted = assessment::seal(&key, &serde_json::to_vec(&session).map_err(internal)?)
        .map_err(internal)?;
    let mut conn = state.pool.get().await.map_err(internal)?;
    let _: () = redis::cmd("SET")
        .arg(key)
        .arg(encrypted)
        .arg("EXAT")
        .arg(session.expires_at)
        .query_async(&mut *conn)
        .await
        .map_err(internal)?;
    Ok(Json(
        json!({"session": session, "headers": {assessment::RUN_HEADER: session.id, assessment::TOKEN_HEADER: session.token}}),
    ))
}

async fn session(
    state: &AppState,
    id: &str,
) -> Result<AssessmentSession, (StatusCode, Json<Value>)> {
    require_enabled(state)?;
    assessment::load_session(&state.pool, id)
        .await
        .map_err(internal)?
        .filter(|s| s.expires_at > chrono::Utc::now().timestamp())
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "assessment session missing or expired",
            )
        })
}

async fn show(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> ApiResult {
    let session = session(&state, &id).await?;
    Ok(Json(
        json!({"id": session.id, "origins": session.origins, "expires_at": session.expires_at,
        "max_body_bytes": session.max_body_bytes, "max_flows": session.max_flows}),
    ))
}

async fn remove(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> ApiResult {
    let session = session(&state, &id).await?;
    let mut conn = state.pool.get().await.map_err(internal)?;
    // Atomic with capture writes: stop new capture and purge payloads and index.
    let script = redis::Script::new(
        r#"
        redis.call('DEL', KEYS[1])
        local ids = redis.call('LRANGE', KEYS[2], 0, -1)
        for _, id in ipairs(ids) do redis.call('DEL', ARGV[1] .. id, ARGV[1] .. id .. ':summary') end
        redis.call('DEL', KEYS[2])
        return #ids
    "#,
    );
    let deleted: i64 = script
        .key(assessment::session_key(&id))
        .key(assessment::index_key(&id))
        .arg(format!("conduit:assessment:{}:flow:", session.id))
        .invoke_async(&mut *conn)
        .await
        .map_err(internal)?;
    Ok(Json(json!({"deleted": deleted, "id": id})))
}

async fn load_flow(
    state: &AppState,
    run: &str,
    id: &str,
) -> Result<CapturedFlow, (StatusCode, Json<Value>)> {
    if !assessment::valid_id(id) {
        return Err(error(StatusCode::NOT_FOUND, "flow not found"));
    }
    let key = assessment::flow_key(run, id);
    let mut conn = state.pool.get().await.map_err(internal)?;
    let encrypted: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut *conn)
        .await
        .map_err(internal)?;
    let encrypted =
        encrypted.ok_or_else(|| error(StatusCode::NOT_FOUND, "flow missing or expired"))?;
    serde_json::from_slice(&assessment::open(&key, &encrypted).map_err(internal)?).map_err(internal)
}

#[derive(Deserialize)]
struct FlowQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    search: Option<String>,
}
async fn recent(
    State(state): State<Arc<AppState>>,
    Path(run): Path<String>,
    Query(query): Query<FlowQuery>,
) -> ApiResult {
    session(&state, &run).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).min(assessment::MAX_FLOWS);
    let mut conn = state.pool.get().await.map_err(internal)?;
    let ids: Vec<String> = redis::cmd("LRANGE")
        .arg(assessment::index_key(&run))
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .map_err(internal)?;
    drop(conn);
    let needle = query.search.unwrap_or_default().to_lowercase();
    let mut entries = Vec::new();
    for id in ids {
        let key = assessment::summary_key(&run, &id);
        let mut conn = state.pool.get().await.map_err(internal)?;
        let encrypted: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .map_err(internal)?;
        drop(conn);
        if let Some(encrypted) = encrypted {
            let summary: Value =
                serde_json::from_slice(&assessment::open(&key, &encrypted).map_err(internal)?)
                    .map_err(internal)?;
            if needle.is_empty()
                || ["url", "method"].iter().any(|field| {
                    summary[field]
                        .as_str()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&needle)
                })
            {
                entries.push(summary);
            }
        }
    }
    let total = entries.len();
    Ok(Json(
        json!({"entries": entries.into_iter().skip(offset).take(limit).collect::<Vec<_>>(), "total": total}),
    ))
}

async fn get_flow(
    State(state): State<Arc<AppState>>,
    Path((run, id)): Path<(String, String)>,
) -> ApiResult {
    session(&state, &run).await?;
    Ok(Json(json!(load_flow(&state, &run, &id).await?)))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    method: Option<String>,
    url: Option<String>,
    body_base64: Option<String>,
    #[serde(default)]
    set_headers: Vec<(String, String)>,
    #[serde(default)]
    remove_headers: Vec<String>,
}

fn replay_headers(
    headers: Vec<(String, String)>,
    mutation: &Replay,
) -> Result<reqwest::header::HeaderMap, String> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut blocked: Vec<String> = [
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
        assessment::RUN_HEADER,
        assessment::TOKEN_HEADER,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (name, value) in headers.iter().chain(mutation.set_headers.iter()) {
        if name.eq_ignore_ascii_case("connection") {
            blocked.extend(value.split(',').map(|s| s.trim().to_lowercase()));
        }
    }
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.to_lowercase();
        if blocked.contains(&lower)
            || mutation
                .remove_headers
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&name))
            || mutation
                .set_headers
                .iter()
                .any(|(s, _)| s.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        result.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?,
            HeaderValue::from_str(&value).map_err(|_| "invalid header value")?,
        );
    }
    for (name, value) in &mutation.set_headers {
        if blocked.contains(&name.to_lowercase()) {
            return Err("cannot override proxy control or HTTP framing headers".into());
        }
        result.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?,
            HeaderValue::from_str(value).map_err(|_| "invalid header value")?,
        );
    }
    Ok(result)
}

async fn replay(
    State(state): State<Arc<AppState>>,
    Path((run, id)): Path<(String, String)>,
    Json(mutation): Json<Replay>,
) -> ApiResult {
    let session = session(&state, &run).await?;
    let flow = load_flow(&state, &run, &id).await?;
    if flow.request.headers_truncated {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "captured headers were incomplete; create a new complete request",
        ));
    }
    if flow.request.truncated && mutation.body_base64.is_none() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "captured request was truncated; provide a complete replacement body",
        ));
    }
    let url = mutation.url.as_deref().unwrap_or(&flow.url);
    let origin = assessment::origin(url)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid replay URL"))?;
    if !session.origins.contains(&origin) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "replay URL is outside session origins",
        ));
    }
    let body = STANDARD
        .decode(
            mutation
                .body_base64
                .as_deref()
                .unwrap_or(&flow.request.body_base64),
        )
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid body_base64"))?;
    if body.len() > assessment::MAX_BODY {
        return Err(error(StatusCode::BAD_REQUEST, "replay body exceeds 1 MiB"));
    }
    let method = reqwest::Method::from_bytes(
        mutation
            .method
            .as_deref()
            .unwrap_or(&flow.method)
            .as_bytes(),
    )
    .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid method"))?;
    if method == reqwest::Method::CONNECT {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "CONNECT replay is unsupported",
        ));
    }
    let headers = replay_headers(flow.request.headers, &mutation)
        .map_err(|message| error(StatusCode::BAD_REQUEST, &message))?;
    let listen: std::net::SocketAddr = state.config.listen_addr.parse().map_err(internal)?;
    let proxy_host = if listen.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        listen.ip().to_string()
    };
    let proxy_addr =
        std::net::SocketAddr::new(proxy_host.parse().map_err(internal)?, listen.port());
    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}")).map_err(internal)?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30));
    let mut conn = state.pool.get().await.map_err(internal)?;
    let stored_ca: Option<Vec<u8>> = redis::cmd("GET")
        .arg(conduit_common::redis::keys::CA_CERT)
        .query_async(&mut *conn)
        .await
        .map_err(internal)?;
    drop(conn);
    if let Some(pem) = stored_ca.or_else(|| std::fs::read(state.config.ca_cert_path()).ok()) {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).map_err(internal)?);
    }
    let client = builder.build().map_err(internal)?;
    let response = client
        .request(method, url)
        .headers(headers)
        .body(body)
        .header(assessment::RUN_HEADER, &session.id)
        .header(assessment::TOKEN_HEADER, &session.token)
        .send()
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "replay failed through Conduit"))?;
    let status = response.status().as_u16();
    let flow_id = response
        .headers()
        .get("x-conduit-flow-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut captured_response = CapturedMessage::default();
    captured_response.set_headers(
        response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("[non-text]").to_owned())),
    );
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| error(StatusCode::BAD_GATEWAY, "replay response interrupted"))?;
        let remaining = session.max_body_bytes.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
        if chunk.len() > remaining {
            truncated = true;
            break;
        }
    }
    captured_response.body_base64 = STANDARD.encode(bytes);
    captured_response.truncated = truncated;
    Ok(Json(
        json!({"status": status, "flow_id": flow_id, "response": captured_response}),
    ))
}

fn assessment_api_key(state: &AppState) -> Option<String> {
    std::env::var("CONDUIT_ASSESSMENT_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .or_else(|| state.config.api_key.clone().filter(|key| !key.is_empty()))
}

async fn authenticate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    use axum::response::IntoResponse;
    let Some(expected) = assessment_api_key(&state) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "assessment API key is not configured",
        )
        .into_response();
    };
    let provided = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
        });
    if !provided.is_some_and(|key| {
        conduit_common::util::constant_time_eq(key.as_bytes(), expected.as_bytes())
    }) {
        return error(
            StatusCode::UNAUTHORIZED,
            "assessment API authentication required",
        )
        .into_response();
    }
    next.run(request).await
}

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/assessments", post(create))
        .route("/assessments/{run}", get(show).delete(remove))
        .route("/assessments/{run}/flows", get(recent))
        .route("/assessments/{run}/flows/{id}", get(get_flow))
        .route("/assessments/{run}/flows/{id}/replay", post(replay))
        .route_layer(middleware::from_fn_with_state(state, authenticate))
        .route_layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assessment_requires_auth_even_when_management_api_is_public() {
        let state = AppState {
            pool: Arc::new(conduit_common::redis::create_pool("redis://127.0.0.1:1", 1).unwrap()),
            config: Arc::new(conduit_common::config::ClearGateConfig::default()),
        };
        assert_eq!(
            require_enabled(&state).unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[test]
    fn replay_preserves_auth_and_duplicates_but_rebuilds_framing() {
        let headers = vec![
            ("Authorization".into(), "Bearer test".into()),
            ("Cookie".into(), "a=1".into()),
            ("Cookie".into(), "b=2".into()),
            ("Connection".into(), "x-hop".into()),
            ("X-Hop".into(), "secret".into()),
            ("Content-Length".into(), "999".into()),
            ("Proxy-Authorization".into(), "secret".into()),
        ];
        let result = replay_headers(headers, &Replay::default()).unwrap();
        assert_eq!(result["authorization"], "Bearer test");
        assert_eq!(result.get_all("cookie").iter().count(), 2);
        assert!(!result.contains_key("x-hop"));
        assert!(!result.contains_key("content-length"));
        assert!(!result.contains_key("proxy-authorization"));
    }
    #[test]
    fn mutations_replace_case_insensitively_and_reject_control_headers() {
        let mut mutation = Replay {
            set_headers: vec![("AUTHORIZATION".into(), "Bearer other".into())],
            ..Default::default()
        };
        let result = replay_headers(
            vec![("Authorization".into(), "Bearer old".into())],
            &mutation,
        )
        .unwrap();
        assert_eq!(result.get_all("authorization").iter().count(), 1);
        assert_eq!(result["authorization"], "Bearer other");
        mutation.set_headers = vec![(assessment::TOKEN_HEADER.into(), "bad".into())];
        assert!(replay_headers(vec![], &mutation).is_err());
    }
}
