use crate::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::header;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

async fn download_ca_cert(State(state): State<Arc<AppState>>) -> Response {
    let cert_path = state.config.ca_cert_path();

    match std::fs::read(&cert_path) {
        Ok(pem) => Response::builder()
            .header(header::CONTENT_TYPE, "application/x-pem-file")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cleargate-ca.pem\"",
            )
            .body(Body::from(pem))
            .unwrap(),
        Err(_) => Response::builder()
            .status(500)
            .body(Body::from("CA certificate not available"))
            .unwrap(),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/ca/cert", get(download_ca_cert))
}
