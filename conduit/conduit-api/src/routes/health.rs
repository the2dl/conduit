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
}

async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let dragonfly_ok = match state.pool.get().await {
        Ok(mut conn) => {
            redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .is_ok()
        }
        Err(_) => false,
    };

    Json(HealthResponse {
        status: if dragonfly_ok { "healthy" } else { "degraded" },
        dragonfly: dragonfly_ok,
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(health_check))
}
