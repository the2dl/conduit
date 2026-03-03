use crate::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::CategoryEntry;
use conduit_common::util::escape_redis_glob;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
    search: Option<String>,
    category: Option<String>,
}

#[derive(Serialize)]
struct PaginatedCategories {
    entries: Vec<CategoryEntry>,
    next_cursor: Option<String>,
    total_estimate: Option<u64>,
}

async fn list_categories(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(PaginatedCategories {
                entries: vec![],
                next_cursor: None,
                total_estimate: None,
            }),
        );
    };

    let limit = q.limit.unwrap_or(100).min(500);
    let search = q.search.unwrap_or_default().to_lowercase();
    let category_filter = q.category.unwrap_or_default();

    let mut entries = Vec::with_capacity(limit);

    // If searching, try direct key lookups first (exact + common variations)
    if !search.is_empty() {
        let candidates = vec![
            search.clone(),
            format!("www.{search}"),
            format!("{search}.com"),
            format!("www.{search}.com"),
            format!("{search}.org"),
            format!("{search}.net"),
        ];
        for domain in &candidates {
            let key = keys::domain_category(domain);
            if let Ok(Some(cat)) = conn.get::<_, Option<String>>(&key).await {
                if category_filter.is_empty() || cat == category_filter {
                    entries.push(CategoryEntry {
                        domain: domain.clone(),
                        category: cat,
                    });
                }
            }
        }
    }

    // SCAN for more matches (larger budget when actively searching).
    // Escape glob metacharacters in user input to prevent pattern injection.
    let pattern = if search.is_empty() {
        "cleargate:domain:*".to_string()
    } else {
        format!("cleargate:domain:*{}*", escape_redis_glob(&search))
    };

    let scan_count: usize = if search.is_empty() { 500 } else { 10000 };
    let max_iterations: usize = if search.is_empty() { 200 } else { 2000 };

    let cursor_start: u64 = q
        .cursor
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let mut scan_cursor = cursor_start;
    let mut iterations = 0;

    // Track domains already added from direct lookup
    let existing: std::collections::HashSet<String> =
        entries.iter().map(|e| e.domain.clone()).collect();

    loop {
        let (next_cursor, batch_keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(scan_cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(scan_count)
            .query_async(&mut *conn)
            .await
            .unwrap_or((0, vec![]));

        for key in &batch_keys {
            let domain = key
                .strip_prefix("cleargate:domain:")
                .unwrap_or(key)
                .to_string();
            if existing.contains(&domain) {
                continue;
            }
            if let Ok(Some(cat)) = conn.get::<_, Option<String>>(key).await {
                if !category_filter.is_empty() && cat != category_filter {
                    continue;
                }
                entries.push(CategoryEntry {
                    domain,
                    category: cat,
                });
                if entries.len() >= limit {
                    break;
                }
            }
        }

        scan_cursor = next_cursor;
        iterations += 1;

        if entries.len() >= limit || scan_cursor == 0 || iterations >= max_iterations {
            break;
        }
    }

    // Estimate total via DBSIZE (rough, includes non-category keys)
    let total_estimate: Option<u64> = redis::cmd("DBSIZE")
        .query_async(&mut *conn)
        .await
        .ok();

    let next_cursor = if scan_cursor == 0 {
        None
    } else {
        Some(scan_cursor.to_string())
    };

    (
        StatusCode::OK,
        Json(PaginatedCategories {
            entries,
            next_cursor,
            total_estimate,
        }),
    )
}

async fn add_category(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<CategoryEntry>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let key = keys::domain_category(&entry.domain);
    let _: () = conn.set(&key, &entry.category).await.unwrap_or(());
    super::publish_reload(&state.pool, "categories").await;
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct DeleteQuery {
    domain: String,
}

async fn delete_category(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DeleteQuery>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let key = keys::domain_category(&q.domain);
    let _: () = conn.del(&key).await.unwrap_or(());
    super::publish_reload(&state.pool, "categories").await;
    StatusCode::NO_CONTENT
}

/// Bulk import domain categories from CSV or newline-delimited text.
/// Format: `domain,category` per line.
async fn import_categories(
    State(state): State<Arc<AppState>>,
    body: Body,
) -> impl IntoResponse {
    let Ok(bytes) = axum::body::to_bytes(body, 10 * 1024 * 1024).await else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Body too large"})));
    };
    let text = String::from_utf8_lossy(&bytes);

    let Ok(mut conn) = state.pool.get().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Redis unavailable"})));
    };

    const MAX_IMPORT_ENTRIES: u64 = 100_000;

    let mut imported = 0u64;
    let mut pipe = redis::pipe();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((domain, category)) = line.split_once(',') {
            let domain = domain.trim();
            let category = category.trim();
            if !domain.is_empty() && !category.is_empty() {
                if imported >= MAX_IMPORT_ENTRIES {
                    return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("import limited to {MAX_IMPORT_ENTRIES} entries per request")})));
                }
                let key = keys::domain_category(domain);
                pipe.set(&key, category);
                imported += 1;
            }
        }
    }

    if imported > 0 {
        let _: () = pipe.query_async(&mut *conn).await.unwrap_or(());
        super::publish_reload(&state.pool, "categories").await;
    }

    (StatusCode::OK, Json(serde_json::json!({"imported": imported})))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/categories",
            get(list_categories)
                .post(add_category)
                .delete(delete_category),
        )
        .route("/categories/import", post(import_categories))
}
