use conduit_common::redis::keys;
use conduit_common::types::LogEntry;
use deadpool_redis::Pool;

/// Push a log entry to the Dragonfly stream (XADD only).
/// Stats are tracked via local atomics and flushed periodically — see `stats` module.
pub async fn push_log(
    pool: &Pool,
    entry: &LogEntry,
    retention: usize,
    node_id: Option<&str>,
) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let json = serde_json::to_string(entry)?;

    // Build XADD field list: always include "json", optionally "node_id"
    let mut args: Vec<(&str, &str)> = vec![("json", &json)];
    let node_id_val;
    if let Some(nid) = node_id {
        node_id_val = nid.to_string();
        args.push(("node_id", &node_id_val));
    }

    // XADD cleargate:logs:stream MAXLEN ~ {retention} * field value ...
    let mut cmd = redis::cmd("XADD");
    cmd.arg(keys::LOG_STREAM)
        .arg("MAXLEN")
        .arg("~")
        .arg(retention)
        .arg("*");
    for (k, v) in &args {
        cmd.arg(*k).arg(*v);
    }
    cmd.exec_async(&mut *conn).await?;

    Ok(())
}
