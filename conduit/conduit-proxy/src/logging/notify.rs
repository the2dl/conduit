use conduit_common::types::LogEntry;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

struct BlockAlertState {
    notification_id: Option<u32>,
    count: u64,
    last_notified: Instant,
    last_seen: Instant,
}

static NOTIFIER: Mutex<Option<HashMap<String, BlockAlertState>>> = Mutex::new(None);

/// Called on every blocked log entry to emit deduplicated desktop notifications.
pub fn on_blocked_entry(entry: &LogEntry) {
    // Only notify if the request originated from the local machine (desktop user)
    if !conduit_common::config::is_local_client_ip(&entry.client_ip) {
        return;
    }

    let rt_cfg = crate::runtime_config::get();
    if !rt_cfg.notifications_enabled {
        return;
    }

    if rt_cfg.is_domain_muted(&entry.host) {
        // If an active notification for this host:port exists, dismiss it
        if let Ok(mut lock) = NOTIFIER.lock() {
            if let Some(ref mut map) = *lock {
                let key = format!("{}:{}", entry.host, entry.port);
                if let Some(state) = map.remove(&key) {
                    if let Some(id) = state.notification_id {
                        tokio::task::spawn_blocking(move || {
                            let _ = Command::new("notify-send")
                                .arg("-C")
                                .arg(id.to_string())
                                .output();
                        });
                    }
                }
            }
        }
        return;
    }

    let host = &entry.host;
    let port = entry.port;
    let key = format!("{host}:{port}");

    let reason = entry
        .rule_name
        .as_deref()
        .or_else(|| {
            entry.block_reason.as_ref().map(|r| match r {
                conduit_common::types::BlockReason::Policy => "Policy Block",
                conduit_common::types::BlockReason::ThreatHeuristic => {
                    "Threat Detected (Heuristic)"
                }
                conduit_common::types::BlockReason::ThreatReputation => {
                    "Threat Detected (Reputation)"
                }
                conduit_common::types::BlockReason::ThreatContent => "Phishing / Malicious Content",
                conduit_common::types::BlockReason::ThreatTunnelPattern => {
                    "Suspicious Tunnel Pattern"
                }
                conduit_common::types::BlockReason::RequestTooLarge => "Request Too Large",
                conduit_common::types::BlockReason::RateLimited => "Rate Limited",
                conduit_common::types::BlockReason::ConnectionLimit => "Connection Limit",
                conduit_common::types::BlockReason::DlpViolation => "DLP Data Loss Violation",
                conduit_common::types::BlockReason::PackageMalware => "Malware in Package Archive",
                conduit_common::types::BlockReason::PostProtection => "POST Protection Block",
                conduit_common::types::BlockReason::RiskyTld => "Risky TLD Blocked",
            })
        })
        .unwrap_or("Blocked by Gateway");

    let mut lock = match NOTIFIER.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let map = lock.get_or_insert_with(HashMap::new);

    // Prune stale entries older than 60s
    map.retain(|_, state| state.last_seen.elapsed().as_secs() < 60);

    let now = Instant::now();

    if let Some(state) = map.get_mut(&key) {
        state.count += 1;
        state.last_seen = now;

        // Grouping & noise reduction: only update the desktop notification once every 2 seconds
        if state.last_notified.elapsed().as_millis() >= 2000 {
            if let Some(id) = state.notification_id {
                let count = state.count;
                let summary = format!("Conduit: Outbound Blocked (x{count})");
                let body =
                    format!("Blocked {key}\nReason: {reason}\nClick notification to Mute or Allow");
                let sync_tag = format!("string:x-canonical-private-synchronous:conduit-{key}");
                let exec_hint = "string:omarchy-exec-argv:[\"omarchy-shell\",\"io.github.the2dl.conduit\",\"open\"]".to_string();

                state.last_notified = now;

                tokio::task::spawn_blocking(move || {
                    let _ = Command::new("notify-send")
                        .arg("-r")
                        .arg(id.to_string())
                        .arg("-a")
                        .arg("Conduit")
                        .arg("-i")
                        .arg("dialog-warning")
                        .arg("-u")
                        .arg("normal")
                        .arg("-h")
                        .arg(sync_tag)
                        .arg("-h")
                        .arg(exec_hint)
                        .arg(&summary)
                        .arg(&body)
                        .output();
                });
            }
        }
    } else {
        // First occurrence: fire initial notification with -p to get the replacement ID
        let count = 1;
        let summary = "Conduit: Outbound Blocked".to_string();
        let body = format!("Blocked {key}\nReason: {reason}\nClick notification to Mute or Allow");
        let sync_tag = format!("string:x-canonical-private-synchronous:conduit-{key}");
        let exec_hint =
            "string:omarchy-exec-argv:[\"omarchy-shell\",\"io.github.the2dl.conduit\",\"open\"]"
                .to_string();

        // Reserve entry in map with pending notification ID
        map.insert(
            key.clone(),
            BlockAlertState {
                notification_id: None,
                count,
                last_notified: now,
                last_seen: now,
            },
        );

        let key_clone = key.clone();
        tokio::task::spawn_blocking(move || {
            let output = Command::new("notify-send")
                .arg("-p")
                .arg("-a")
                .arg("Conduit")
                .arg("-i")
                .arg("dialog-warning")
                .arg("-u")
                .arg("normal")
                .arg("-h")
                .arg(sync_tag)
                .arg("-h")
                .arg(exec_hint)
                .arg(&summary)
                .arg(&body)
                .output();

            if let Ok(out) = output {
                if let Ok(id_str) = String::from_utf8(out.stdout) {
                    if let Ok(id) = id_str.trim().parse::<u32>() {
                        if let Ok(mut lock) = NOTIFIER.lock() {
                            if let Some(ref mut map) = *lock {
                                if let Some(state) = map.get_mut(&key_clone) {
                                    state.notification_id = Some(id);
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}
