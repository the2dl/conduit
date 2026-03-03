use crate::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::LogEntry;
use conduit_common::util::csv_escape;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Batch size for scanning through the Redis stream.
const SCAN_BATCH: usize = 500;

/// Maximum entries a single paginated request can return.
const MAX_PAGE_SIZE: usize = 500;

/// Safety cap for export (full-list) fetches.
const MAX_EXPORT: usize = 100_000;

// ---------------------------------------------------------------------------
// GET /api/v1/logs — cursor-based paginated fetch with filters
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    /// Opaque cursor (stream ID) returned by a previous response.
    #[serde(default)]
    cursor: Option<String>,
    /// Substring match on the `host` field.
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    action: Option<String>,
    /// Filter by node_id.
    #[serde(default)]
    node_id: Option<String>,
}

fn default_limit() -> usize {
    100
}

#[derive(Serialize)]
struct PaginatedLogs {
    entries: Vec<LogEntry>,
    next_cursor: Option<String>,
    total: u64,
}

async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LogQuery>,
) -> Json<PaginatedLogs> {
    Json(fetch_logs_paginated(&state, &query).await)
}

async fn fetch_logs_paginated(state: &AppState, query: &LogQuery) -> PaginatedLogs {
    let Ok(mut conn) = state.pool.get().await else {
        return PaginatedLogs {
            entries: vec![],
            next_cursor: None,
            total: 0,
        };
    };

    // Total count via XLEN
    let total: u64 = redis::cmd("XLEN")
        .arg(keys::LOG_STREAM)
        .query_async(&mut *conn)
        .await
        .unwrap_or(0);

    let limit = query.limit.min(MAX_PAGE_SIZE);

    // XREVRANGE: newest first. Cursor is a stream ID (or "+" for the beginning).
    let start = query
        .cursor
        .as_deref()
        .unwrap_or("+");

    let mut entries = Vec::with_capacity(limit);
    let mut last_id: Option<String> = None;

    // We may need multiple rounds if filters exclude entries
    let mut current_start = start.to_string();

    loop {
        let raw: Vec<redis::Value> = redis::cmd("XREVRANGE")
            .arg(keys::LOG_STREAM)
            .arg(&current_start)
            .arg("-")
            .arg("COUNT")
            .arg(SCAN_BATCH)
            .query_async(&mut *conn)
            .await
            .unwrap_or_default();

        let batch = parse_stream_entries(&raw);
        let batch_count = batch.len();

        if batch_count == 0 {
            break;
        }

        for (id, entry) in batch {
            if matches_filter(&entry, query) {
                last_id = Some(id.clone());
                entries.push(entry);
                if entries.len() >= limit {
                    break;
                }
            }
            // Track the last processed ID for cursor continuation
            last_id = Some(id);
        }

        if entries.len() >= limit || batch_count < SCAN_BATCH {
            break;
        }

        // Continue from just before the last seen ID
        if let Some(ref lid) = last_id {
            current_start = decrement_stream_id(lid);
        } else {
            break;
        }
    }

    let next_cursor = if entries.len() >= limit {
        last_id.map(|id| decrement_stream_id(&id))
    } else {
        None
    };

    PaginatedLogs {
        entries,
        next_cursor,
        total,
    }
}

/// Check whether a log entry matches all active filters.
fn matches_filter(e: &LogEntry, query: &LogQuery) -> bool {
    // Broad search: matches host, path, full_url, username, or category
    if let Some(ref s) = query.search {
        let s = s.to_lowercase();
        let found = e.host.to_lowercase().contains(&s)
            || e.path.to_lowercase().contains(&s)
            || e.full_url.to_lowercase().contains(&s)
            || e.username
                .as_deref()
                .map(|u| u.to_lowercase().contains(&s))
                .unwrap_or(false)
            || e.category
                .as_deref()
                .map(|c| c.to_lowercase().contains(&s))
                .unwrap_or(false);
        if !found {
            return false;
        }
    }

    if let Some(ref d) = query.domain {
        if !e.host.contains(d.as_str()) {
            return false;
        }
    }
    if let Some(ref u) = query.user {
        if e.username.as_deref() != Some(u.as_str()) {
            return false;
        }
    }
    if let Some(ref c) = query.category {
        if e.category.as_deref() != Some(c.as_str()) {
            return false;
        }
    }
    if let Some(ref a) = query.action {
        let action_str = format!("{:?}", e.action).to_lowercase();
        if action_str != *a {
            return false;
        }
    }
    if let Some(ref nid) = query.node_id {
        if e.node_id.as_deref() != Some(nid.as_str()) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// GET /api/v1/export/logs — full export (CSV / JSONL) with filters
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default = "default_format")]
    format: String,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
}

fn default_format() -> String {
    "jsonl".into()
}

async fn export_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let is_csv = query.format == "csv";

    // Stream response via a channel to avoid buffering all entries in memory
    let (tx, rx) = mpsc::channel::<String>(64);

    let filter = LogQuery {
        limit: MAX_EXPORT,
        cursor: None,
        search: query.search,
        domain: query.domain,
        user: query.user,
        category: query.category,
        action: query.action,
        node_id: query.node_id,
    };

    tokio::spawn(async move {
        if is_csv {
            let _ = tx.send("\"timestamp\",\"client_ip\",\"username\",\"method\",\"host\",\"path\",\"category\",\"action\",\"status_code\",\"duration_ms\",\"node_id\",\"node_name\"\n".to_string()).await;
        }

        stream_filtered_entries(&state, &filter, is_csv, &tx).await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(
        tokio_stream::StreamExt::map(stream, |chunk| Ok::<_, std::convert::Infallible>(chunk)),
    );

    if is_csv {
        Response::builder()
            .header(header::CONTENT_TYPE, "text/csv")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cleargate-logs.csv\"",
            )
            .body(body)
            .unwrap()
    } else {
        Response::builder()
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cleargate-logs.jsonl\"",
            )
            .body(body)
            .unwrap()
    }
}

/// Scan the stream in batches, applying filters, and send matching entries to the channel.
/// Streams results to avoid holding all entries in memory at once.
async fn stream_filtered_entries(
    state: &AppState,
    filter: &LogQuery,
    is_csv: bool,
    tx: &mpsc::Sender<String>,
) {
    let Ok(mut conn) = state.pool.get().await else {
        return;
    };

    let cap = filter.limit.min(MAX_EXPORT);
    let mut sent = 0usize;
    let mut current_start = "+".to_string();

    loop {
        let raw: Vec<redis::Value> = redis::cmd("XREVRANGE")
            .arg(keys::LOG_STREAM)
            .arg(&current_start)
            .arg("-")
            .arg("COUNT")
            .arg(SCAN_BATCH)
            .query_async(&mut *conn)
            .await
            .unwrap_or_default();

        let batch = parse_stream_entries(&raw);
        let batch_count = batch.len();

        if batch_count == 0 {
            break;
        }

        let mut last_id = String::new();
        for (id, entry) in batch {
            last_id = id;
            if matches_filter(&entry, filter) {
                let chunk = if is_csv {
                    format_csv_row(&entry)
                } else {
                    match serde_json::to_string(&entry) {
                        Ok(json) => format!("{json}\n"),
                        Err(_) => continue,
                    }
                };
                if tx.send(chunk).await.is_err() {
                    return; // client disconnected
                }
                sent += 1;
                if sent >= cap {
                    return;
                }
            }
        }

        if batch_count < SCAN_BATCH {
            break;
        }

        current_start = decrement_stream_id(&last_id);
    }
}

fn format_csv_row(e: &LogEntry) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{}\n",
        csv_escape(&e.timestamp.to_string()),
        csv_escape(&e.client_ip),
        csv_escape(e.username.as_deref().unwrap_or("")),
        csv_escape(&e.method),
        csv_escape(&e.host),
        csv_escape(&e.path),
        csv_escape(e.category.as_deref().unwrap_or("")),
        csv_escape(&format!("{:?}", e.action).to_lowercase()),
        csv_escape(&e.status_code.to_string()),
        csv_escape(&e.duration_ms.to_string()),
        csv_escape(e.node_id.as_deref().unwrap_or("")),
        csv_escape(e.node_name.as_deref().unwrap_or("")),
    )
}

// ---------------------------------------------------------------------------
// Stream helpers
// ---------------------------------------------------------------------------

/// Parse Redis XREVRANGE/XRANGE response into (stream_id, LogEntry) pairs.
fn parse_stream_entries(raw: &[redis::Value]) -> Vec<(String, LogEntry)> {
    let mut result = Vec::new();

    for item in raw {
        if let redis::Value::Array(ref arr) = item {
            if arr.len() >= 2 {
                let stream_id = match &arr[0] {
                    redis::Value::BulkString(b) => String::from_utf8_lossy(b).to_string(),
                    _ => continue,
                };

                // Fields are [key, value, key, value, ...]
                if let redis::Value::Array(ref fields) = arr[1] {
                    let mut json_value = None;
                    let mut i = 0;
                    while i + 1 < fields.len() {
                        if let (redis::Value::BulkString(k), redis::Value::BulkString(v)) =
                            (&fields[i], &fields[i + 1])
                        {
                            if k == b"json" {
                                json_value =
                                    Some(String::from_utf8_lossy(v).to_string());
                            }
                        }
                        i += 2;
                    }

                    if let Some(json) = json_value {
                        if let Ok(entry) = serde_json::from_str::<LogEntry>(&json) {
                            result.push((stream_id, entry));
                        }
                    }
                }
            }
        }
    }

    result
}

/// Decrement a stream ID to get an exclusive upper bound for the next XREVRANGE call.
/// Stream IDs are "timestamp-sequence". We decrement the sequence, or if 0, go to
/// "timestamp-1" minus one millisecond.
fn decrement_stream_id(id: &str) -> String {
    if let Some((ts_str, seq_str)) = id.split_once('-') {
        if let (Ok(ts), Ok(seq)) = (ts_str.parse::<u64>(), seq_str.parse::<u64>()) {
            if seq > 0 {
                return format!("{}-{}", ts, seq - 1);
            } else if ts > 0 {
                return format!("{}-{}", ts - 1, u64::MAX);
            }
        }
    }
    // Fallback: shouldn't happen with valid stream IDs
    "0-0".to_string()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/logs", get(get_logs))
        .route("/export/logs", get(export_logs))
}
