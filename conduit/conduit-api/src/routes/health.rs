use crate::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    dragonfly: bool,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dragonfly_keys: Option<u64>,
}

async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let (dragonfly_ok, keys) = match state.pool.get().await {
        Ok(mut conn) => {
            let ok = redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .is_ok();
            let keys = if ok {
                redis::cmd("DBSIZE")
                    .query_async::<u64>(&mut *conn)
                    .await
                    .ok()
            } else {
                None
            };
            (ok, keys)
        }
        Err(_) => (false, None),
    };

    Json(HealthResponse {
        status: if dragonfly_ok { "healthy" } else { "degraded" },
        dragonfly: dragonfly_ok,
        version: env!("CARGO_PKG_VERSION"),
        dragonfly_keys: keys,
    })
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(health_check))
}
