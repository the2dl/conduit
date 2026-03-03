pub mod dragonfly;
pub mod syslog;

use conduit_common::config::ClearGateConfig;
use conduit_common::types::{LogEntry, ThreatTier};
use deadpool_redis::Pool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::threat::ThreatEngine;

/// Global counter of dropped log entries.
pub static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);

/// Wrapper around the mpsc sender for log entries.
pub struct LogSender(pub mpsc::Sender<LogEntry>);

impl LogSender {
    /// Send a log entry, tracking drops if the channel is full.
    pub fn send(&self, entry: LogEntry) {
        if self.0.try_send(entry).is_err() {
            let count = DROPPED_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if count % 1000 == 1 {
                warn!(dropped = count, "Log channel full, entries dropped");
            }
        }
    }
}

/// Create the logging pipeline channel and spawn the background consumer
/// on a dedicated thread with its own Tokio runtime.
/// This avoids the "no reactor running" panic since Pingora manages its own runtime.
pub fn spawn_logging_pipeline(
    config: &Arc<ClearGateConfig>,
    pool: &Arc<Pool>,
    threat_engine: Option<Arc<ThreatEngine>>,
) -> mpsc::Sender<LogEntry> {
    let (tx, rx) = mpsc::channel::<LogEntry>(config.log_channel_size);

    let pool = pool.clone();
    let syslog_target = config.syslog_target.clone();
    let log_retention = config.log_retention;
    let threat_reputation_enabled = config
        .threat
        .as_ref()
        .map(|t| t.enabled && t.reputation_enabled)
        .unwrap_or(false);
    let threat_decay_hours = config
        .threat
        .as_ref()
        .map(|t| t.reputation_decay_hours)
        .unwrap_or(168);

    // Extract node identity from config
    let node_id = config.node.as_ref().map(|n| n.node_id.clone());
    let node_name = config.node.as_ref().and_then(|n| n.name.clone());

    std::thread::Builder::new()
        .name("cleargate-logging".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create logging runtime");

            rt.block_on(run_logging_pipeline(
                rx,
                pool,
                syslog_target,
                log_retention,
                node_id,
                node_name,
                threat_reputation_enabled,
                threat_decay_hours,
                threat_engine,
            ));
        })
        .expect("Failed to spawn logging thread");

    tx
}

async fn run_logging_pipeline(
    mut rx: mpsc::Receiver<LogEntry>,
    pool: Arc<Pool>,
    syslog_target: Option<String>,
    log_retention: usize,
    node_id: Option<String>,
    node_name: Option<String>,
    threat_reputation_enabled: bool,
    threat_decay_hours: u64,
    threat_engine: Option<Arc<ThreatEngine>>,
) {
    info!("Logging pipeline started");

    // Spawn the periodic stats flush task (every 2s, pipelined)
    crate::stats::spawn_stats_flush(pool.clone(), node_id.clone());

    // Initialize syslog if configured
    let syslog_sink = if let Some(ref target) = syslog_target {
        match syslog::SyslogSink::new(target).await {
            Ok(s) => {
                info!(target, "Syslog sink connected");
                Some(s)
            }
            Err(e) => {
                error!("Failed to init syslog sink: {e}");
                None
            }
        }
    } else {
        None
    };

    while let Some(mut entry) = rx.recv().await {
        // Stamp node identity on every entry
        if entry.node_id.is_none() {
            entry.node_id = node_id.clone();
        }
        if entry.node_name.is_none() {
            entry.node_name = node_name.clone();
        }

        // Track stats locally (flushed to Redis periodically by stats task)
        crate::stats::record_request(
            entry.action == conduit_common::types::PolicyAction::Block,
            entry.tls_intercepted,
        );

        // Track threat stats
        if let Some(tier) = entry.threat_tier {
            if tier != ThreatTier::None {
                crate::stats::record_threat(
                    entry.threat_blocked.unwrap_or(false),
                    tier,
                );
            }
        }

        // Update threat reputation (async, off request path)
        if threat_reputation_enabled
            && (entry.threat_score.is_some() || entry.threat_tier.is_some())
        {
            let cache_ref = threat_engine.as_ref().map(|e| &e.reputation_cache);
            crate::threat::reputation::update_from_log(
                &pool, &entry, threat_decay_hours, cache_ref,
            )
            .await;
        }

        // Stdout JSON (always)
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("{json}");
        }

        // Dragonfly stream sink (XADD only — stats handled by flush task)
        if let Err(e) =
            dragonfly::push_log(&pool, &entry, log_retention, node_id.as_deref()).await
        {
            error!("Dragonfly log push failed: {e}");
        }

        // Syslog sink
        if let Some(ref syslog_sink) = syslog_sink {
            if let Err(e) = syslog_sink.send(&entry).await {
                error!("Syslog send failed: {e}");
            }
        }
    }

    info!("Logging pipeline shut down");
}
