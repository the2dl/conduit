//! Bulk category importers.
//!
//! POST /api/v1/categories/import/ut1
//!   Body: the raw `blacklists.tar.gz` file
//!   Parses each category/domains file and bulk-inserts into Dragonfly.
//!
//! POST /api/v1/categories/import/csv
//!   Body: CSV with header `domain,rank,category` (or `domain,category`)
//!   Bulk-inserts into Dragonfly with pipelined batches.

use crate::AppState;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
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

/// Bulk-insert (domain, category) pairs into Dragonfly and return updated stats.
async fn bulk_insert(
    state: &AppState,
    pairs: &[(String, String)],
    stats: &mut ImportStats,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Ok(mut conn) = state.pool.get().await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Redis unavailable"})),
        ));
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

    Ok(())
}

// ── UT1 tarball import ──────────────────────────────────────────────

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

    if let Err(resp) = bulk_insert(&state, &pairs, &mut stats).await {
        return resp;
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

// ── CSV import ──────────────────────────────────────────────────────

/// Known valid categories loaded from the shared categories.txt file.
/// This is the single source of truth — the Python categorization script reads the same file.
const ALLOWED_CATEGORIES_RAW: &str = include_str!("../../../../categories.txt");

fn allowed_categories() -> std::collections::HashSet<&'static str> {
    ALLOWED_CATEGORIES_RAW
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Validate that a string looks like a domain name.
/// Allows alphanumeric, hyphens, dots, and underscores. No spaces, slashes, colons, etc.
/// Note: IDN domains in punycode form (xn--*.com) pass fine since they're ASCII.
/// Raw Unicode domains are rejected — browsers/proxies send the punycode form anyway.
fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// Parse CSV body in a blocking thread.
/// Accepts `domain,rank,category` (3-col with header) or `domain,category` (2-col).
fn parse_csv(data: &[u8]) -> Result<(Vec<(String, String)>, ImportStats), String> {
    let text = String::from_utf8_lossy(data);
    let mut stats = ImportStats::default();
    let mut pairs: Vec<(String, String)> = Vec::new();

    let allowed = allowed_categories();

    let mut lines = text.lines().peekable();

    // Detect and skip header row
    if let Some(first) = lines.peek() {
        let lower = first.to_lowercase();
        if lower.starts_with("domain") {
            lines.next();
        }
    }

    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            stats.skipped_entries += 1;
            continue;
        }

        let fields: Vec<&str> = line.splitn(4, ',').collect();
        let (domain, category) = match fields.len() {
            // domain,category
            2 => (fields[0].trim(), fields[1].trim()),
            // domain,rank,category
            3 => (fields[0].trim(), fields[2].trim()),
            _ => {
                stats.skipped_entries += 1;
                continue;
            }
        };

        if domain.is_empty() || category.is_empty() {
            stats.skipped_entries += 1;
            continue;
        }

        let domain_lower = domain.to_lowercase();
        let category_lower = category.to_lowercase();

        if !is_valid_domain(&domain_lower) {
            stats.skipped_entries += 1;
            continue;
        }

        if !allowed.contains(category_lower.as_str()) {
            stats.skipped_entries += 1;
            continue;
        }

        *stats.categories.entry(category_lower.clone()).or_insert(0) += 1;
        stats.total_domains += 1;
        pairs.push((domain_lower, category_lower));
    }

    stats.errors.truncate(10);
    Ok((pairs, stats))
}

/// Accept a CSV upload and bulk-import domain categories.
async fn import_csv(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let start = std::time::Instant::now();
    info!(size_mb = body.len() / (1024 * 1024), "Received CSV import");

    let data = body.to_vec();
    let parsed = tokio::task::spawn_blocking(move || parse_csv(&data)).await;

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
        "Parsed CSV, inserting into Dragonfly"
    );

    if let Err(resp) = bulk_insert(&state, &pairs, &mut stats).await {
        return resp;
    }

    stats.duration_ms = start.elapsed().as_millis() as u64;

    info!(
        total = stats.total_domains,
        categories = stats.categories.len(),
        duration_ms = stats.duration_ms,
        "CSV import complete"
    );

    super::publish_reload(&state.pool, "categories").await;
    (StatusCode::OK, Json(serde_json::json!(stats)))
}

// ── Flush all domain categories ─────────────────────────────────────

const SCAN_BATCH_SIZE: usize = 5000;

/// Delete all `cleargate:domain:*` keys from Redis.
async fn flush_categories(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let start = std::time::Instant::now();
    info!("Flushing all domain category keys");

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Redis unavailable"})),
        );
    };

    let mut deleted: u64 = 0;
    let mut cursor: u64 = 0;

    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("cleargate:domain:*")
            .arg("COUNT")
            .arg(SCAN_BATCH_SIZE)
            .query_async(&mut *conn)
            .await
            .unwrap_or((0, vec![]));

        if !keys.is_empty() {
            let batch_len = keys.len() as u64;
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.del(key);
            }
            match pipe.query_async::<()>(&mut *conn).await {
                Ok(()) => deleted += batch_len,
                Err(e) => {
                    tracing::error!(error = %e, "Pipeline delete failed during flush");
                    let duration_ms = start.elapsed().as_millis() as u64;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": format!("Pipeline delete failed: {e}"),
                            "deleted_before_error": deleted,
                            "duration_ms": duration_ms,
                        })),
                    );
                }
            }
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    info!(deleted, duration_ms, "Category flush complete");

    super::publish_reload(&state.pool, "categories").await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "deleted": deleted,
            "duration_ms": duration_ms,
        })),
    )
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/categories/import/ut1", post(import_ut1))
        .route("/categories/import/csv", post(import_csv))
        .route("/categories/flush", delete(flush_categories))
        .layer(DefaultBodyLimit::max(200 * 1024 * 1024))
}
