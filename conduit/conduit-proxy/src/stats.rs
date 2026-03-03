use conduit_common::redis::keys;
use deadpool_redis::Pool;
use redis::AsyncCommands;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, trace};

/// Local counters accumulated between flushes.
/// These are incremented per-request with zero Redis overhead.
static REQUESTS_DELTA: AtomicU64 = AtomicU64::new(0);
static BLOCKED_DELTA: AtomicU64 = AtomicU64::new(0);
static TLS_DELTA: AtomicU64 = AtomicU64::new(0);

/// Record a request in local counters (called from the logging pipeline).
pub fn record_request(blocked: bool, tls_intercepted: bool) {
    REQUESTS_DELTA.fetch_add(1, Ordering::Relaxed);
    if blocked {
        BLOCKED_DELTA.fetch_add(1, Ordering::Relaxed);
    }
    if tls_intercepted {
        TLS_DELTA.fetch_add(1, Ordering::Relaxed);
    }
}

/// Flush accumulated stats to Redis and sync the active connections gauge.
/// Called periodically (every ~2s) from the logging pipeline's tokio runtime.
async fn flush_stats(pool: &Pool, node_id: Option<&str>) {
    // Swap deltas to zero atomically
    let req = REQUESTS_DELTA.swap(0, Ordering::Relaxed);
    let blk = BLOCKED_DELTA.swap(0, Ordering::Relaxed);
    let tls = TLS_DELTA.swap(0, Ordering::Relaxed);

    // Read the current active connections gauge from the shared atomic
    let active = crate::service::ACTIVE_CONNECTIONS.load(Ordering::Relaxed);

    // Nothing to flush
    if req == 0 && blk == 0 && tls == 0 {
        // Still sync the active gauge
        if let Ok(mut conn) = pool.get().await {
            let _: Result<(), _> = conn.set(keys::STATS_ACTIVE, active).await;
            if let Some(nid) = node_id {
                let _: Result<(), _> = conn
                    .set(keys::stats_node(nid, "active"), active)
                    .await;
            }
        }
        return;
    }

    trace!(req, blk, tls, active, "Flushing stats to Redis");

    let Ok(mut conn) = pool.get().await else {
        // Put the deltas back so they aren't lost
        REQUESTS_DELTA.fetch_add(req, Ordering::Relaxed);
        BLOCKED_DELTA.fetch_add(blk, Ordering::Relaxed);
        TLS_DELTA.fetch_add(tls, Ordering::Relaxed);
        return;
    };

    // Pipeline all updates in a single round-trip
    let mut pipe = redis::pipe();
    pipe.atomic();

    // Global counters (INCRBY for deltas, SET for gauge)
    if req > 0 {
        pipe.cmd("INCRBY").arg(keys::STATS_REQUESTS).arg(req);
    }
    if blk > 0 {
        pipe.cmd("INCRBY").arg(keys::STATS_BLOCKED).arg(blk);
    }
    if tls > 0 {
        pipe.cmd("INCRBY").arg(keys::STATS_TLS).arg(tls);
    }
    pipe.cmd("SET").arg(keys::STATS_ACTIVE).arg(active);

    // Per-node counters
    if let Some(nid) = node_id {
        if req > 0 {
            pipe.cmd("INCRBY")
                .arg(keys::stats_node(nid, "requests"))
                .arg(req);
        }
        if blk > 0 {
            pipe.cmd("INCRBY")
                .arg(keys::stats_node(nid, "blocked"))
                .arg(blk);
        }
        if tls > 0 {
            pipe.cmd("INCRBY")
                .arg(keys::stats_node(nid, "tls"))
                .arg(tls);
        }
        pipe.cmd("SET")
            .arg(keys::stats_node(nid, "active"))
            .arg(active);
    }

    if let Err(e) = pipe.exec_async(&mut *conn).await {
        error!("Stats flush failed: {e}");
        // Put deltas back
        REQUESTS_DELTA.fetch_add(req, Ordering::Relaxed);
        BLOCKED_DELTA.fetch_add(blk, Ordering::Relaxed);
        TLS_DELTA.fetch_add(tls, Ordering::Relaxed);
    }
}

/// Spawn the periodic stats flush task. Must be called from a tokio runtime.
pub fn spawn_stats_flush(pool: Arc<Pool>, node_id: Option<String>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            flush_stats(&pool, node_id.as_deref()).await;
        }
    });
}
