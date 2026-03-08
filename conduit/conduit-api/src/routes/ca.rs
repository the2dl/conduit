use crate::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use conduit_common::ca::CertAuthority;
use conduit_common::redis::keys;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use super::publish_reload;

/// Download the CA certificate (PEM). Reads from Dragonfly, falls back to disk.
async fn download_ca_cert(State(state): State<Arc<AppState>>) -> Response {
    // Try Dragonfly first
    if let Ok(mut conn) = state.pool.get().await {
        let cert_pem: Result<Option<Vec<u8>>, _> = redis::cmd("GET")
            .arg(keys::CA_CERT)
            .query_async(&mut *conn)
            .await;
        if let Ok(Some(pem)) = cert_pem {
            return Response::builder()
                .header(header::CONTENT_TYPE, "application/x-pem-file")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"cleargate-ca.pem\"",
                )
                .body(Body::from(pem))
                .unwrap();
        }
    }

    // Fall back to disk
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

#[derive(Serialize)]
struct CaResponse {
    subject: String,
    fingerprint: String,
    not_after: String,
}

/// Generate a new CA certificate and store it in Dragonfly.
/// All proxy nodes will hot-reload via pub/sub.
async fn generate_ca(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ca = match CertAuthority::generate() {
        Ok(ca) => ca,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CA generation failed".to_string(),
            )
                .into_response();
        }
    };

    let resp = ca_response_body(&ca);

    if let Err(_) = conduit_common::ca::store_ca_to_dragonfly(&state.pool, &ca).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store CA in Dragonfly".to_string(),
        )
            .into_response();
    }

    info!(
        fingerprint = %resp.fingerprint,
        "New CA generated and stored in Dragonfly"
    );
    conduit_common::ca::publish_ca_reload(&state.pool).await;
    publish_reload(&state.pool, "ca").await;

    (StatusCode::OK, Json(resp)).into_response()
}

fn ca_response_body(ca: &CertAuthority) -> CaResponse {
    CaResponse {
        subject: ca.subject_string(),
        fingerprint: ca.fingerprint(),
        not_after: ca.not_after_string(),
    }
}

#[derive(Deserialize)]
struct UploadCaRequest {
    cert_pem: String,
    key_pem: String,
}

/// Upload a CA certificate and private key, store in Dragonfly.
/// All proxy nodes will hot-reload via pub/sub.
async fn upload_ca(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadCaRequest>,
) -> impl IntoResponse {
    let ca = match CertAuthority::from_pem_bytes(
        payload.cert_pem.as_bytes(),
        payload.key_pem.as_bytes(),
    ) {
        Ok(ca) => ca,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid PEM certificate or key".to_string(),
            )
                .into_response();
        }
    };

    let resp = ca_response_body(&ca);

    if let Err(_) = conduit_common::ca::store_ca_to_dragonfly(&state.pool, &ca).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store CA in Dragonfly".to_string(),
        )
            .into_response();
    }

    info!(
        fingerprint = %resp.fingerprint,
        "CA uploaded and stored in Dragonfly"
    );
    conduit_common::ca::publish_ca_reload(&state.pool).await;
    publish_reload(&state.pool, "ca").await;

    (StatusCode::OK, Json(resp)).into_response()
}

/// Public routes (no auth required) — cert download only.
pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new().route("/ca/cert", get(download_ca_cert))
}

/// Protected routes (auth required) — generate and upload.
pub fn protected_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ca/generate", post(generate_ca))
        .route("/ca/upload", post(upload_ca))
}
