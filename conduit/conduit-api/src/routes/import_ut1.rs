//! UT1 Toulouse blacklist importer.
//!
//! POST /api/v1/categories/import/ut1
//!   Body: the raw `blacklists.tar.gz` file
//!   Parses each category/domains file and bulk-inserts into Dragonfly.

use crate::AppState;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use conduit_common::redis::keys;
use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use tracing::info;

const PIPELINE_BATCH_SIZE: usize = 5000;

#[derive(Debug, Clone, Serialize, Default)]
struct ImportStats {
    total_domains: u64,
    categories: HashMap<String, u64>,
    skipped_entries: u64,
    errors: Vec<String>,
    duration_ms: u64,
}

/// Validate that a category name extracted from a tar path is safe.
fn is_valid_category(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse the tarball synchronously (blocking) and return (domain, category) pairs.
fn parse_tarball(data: &[u8]) -> Result<(Vec<(String, String)>, ImportStats), String> {
    let gz = GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| format!("Invalid tar.gz: {e}"))?;

    let mut stats = ImportStats::default();
    let mut pairs: Vec<(String, String)> = Vec::new();

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                stats.errors.push(format!("tar entry error: {e}"));
                continue;
            }
        };

        let path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        let path_str = path.to_string_lossy().to_string();
        if !path_str.ends_with("/domains") {
            continue;
        }

        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() < 2 {
            continue;
        }
        let category = parts[parts.len() - 2].to_string();

        // Validate category name to prevent path traversal pollution
        if !is_valid_category(&category) {
            stats.skipped_entries += 1;
            continue;
        }

        let mut content = String::new();
        if entry.read_to_string(&mut content).is_err() {
            stats.errors.push("Failed to read entry".to_string());
            continue;
        }

        let mut cat_count = 0u64;
        for line in content.lines() {
            let domain = line.trim();
            if domain.is_empty() || domain.starts_with('#') {
                stats.skipped_entries += 1;
                continue;
            }
            pairs.push((domain.to_string(), category.clone()));
            cat_count += 1;
            stats.total_domains += 1;
        }

        *stats.categories.entry(category.clone()).or_insert(0) += cat_count;
    }

    stats.errors.truncate(10);
    Ok((pairs, stats))
}

/// Accept a `blacklists.tar.gz` upload and import all categories.
async fn import_ut1(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let start = std::time::Instant::now();
    info!(size_mb = body.len() / (1024 * 1024), "Received UT1 tarball");

    // Parse tarball in blocking thread (synchronous IO)
    let data = body.to_vec();
    let parsed = tokio::task::spawn_blocking(move || parse_tarball(&data)).await;

    let (pairs, mut stats) = match parsed {
        Ok(Ok((pairs, stats))) => (pairs, stats),
        Ok(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Parse task failed: {e}")})),
            );
        }
    };

    info!(
        total = stats.total_domains,
        categories = stats.categories.len(),
        "Parsed tarball, inserting into Dragonfly"
    );

    // Bulk insert into Dragonfly in batches
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Redis unavailable"})),
        );
    };

    for chunk in pairs.chunks(PIPELINE_BATCH_SIZE) {
        let mut pipe = redis::pipe();
        for (domain, category) in chunk {
            let key = keys::domain_category(domain);
            pipe.set(key, category);
        }
        if let Err(e) = pipe.query_async::<()>(&mut *conn).await {
            stats.errors.push(format!("Pipeline error: {e}"));
            break;
        }
    }

    stats.duration_ms = start.elapsed().as_millis() as u64;

    info!(
        total = stats.total_domains,
        categories = stats.categories.len(),
        duration_ms = stats.duration_ms,
        "UT1 import complete"
    );

    super::publish_reload(&state.pool, "categories").await;
    (StatusCode::OK, Json(serde_json::json!(stats)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/categories/import/ut1", post(import_ut1))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
}
