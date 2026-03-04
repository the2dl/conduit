//! Background threat feed ingestion.
//!
//! Periodically fetches threat intelligence feeds (URLhaus, PhishTank, plain domain lists),
//! parses them, and populates the bloom filter and bad CIDR list.

use conduit_common::redis::keys;
use conduit_common::types::{ThreatFeed, ThreatFeedType};
use deadpool_redis::Pool;
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use super::ThreatEngine;

/// Maximum feed response size (50MB). Prevents unbounded memory from malicious/broken feeds.
const MAX_FEED_SIZE: usize = 50 * 1024 * 1024;

/// Spawn the background feed refresh task.
pub fn spawn_feed_refresh(engine: Arc<ThreatEngine>, pool: Arc<Pool>) {
    let interval_secs = engine.config.feed_refresh_interval_secs;

    std::thread::Builder::new()
        .name("cleargate-feeds".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create feed refresh runtime");

            rt.block_on(async move {
                // Initial load
                if let Err(e) = refresh_all_feeds(&engine, &pool).await {
                    error!("Initial feed refresh failed: {e}");
                }

                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                interval.tick().await; // skip immediate tick (we already did initial load)

                loop {
                    interval.tick().await;
                    if let Err(e) = refresh_all_feeds(&engine, &pool).await {
                        error!("Feed refresh failed: {e}");
                    }
                }
            });
        })
        .expect("Failed to spawn feed refresh thread");
}

/// Refresh all enabled feeds and update bloom filter + CIDR list.
async fn refresh_all_feeds(engine: &ThreatEngine, pool: &Pool) -> anyhow::Result<()> {
    let feeds = load_feeds_from_redis(pool).await;
    if feeds.is_empty() {
        debug!("No threat feeds configured");
        return Ok(());
    }

    info!(count = feeds.len(), "Refreshing threat feeds");

    let mut new_bloom = super::bloom::new_bloom(engine.config.bloom_capacity, engine.config.bloom_fp_rate);
    let mut new_nrd_bloom = super::bloom::new_bloom(1_000_000, 0.001);
    let mut new_cidrs = Vec::new();
    let mut total_entries = 0u64;
    let mut nrd_entries = 0u64;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    for feed in &feeds {
        if !feed.enabled {
            continue;
        }

        match fetch_and_parse(&client, feed).await {
            Ok(entries) => {
                let mut count = 0usize;
                for entry in entries {
                    match feed.feed_type {
                        ThreatFeedType::DomainBlocklist | ThreatFeedType::UrlBlocklist => {
                            super::bloom::insert(&mut new_bloom, &entry);
                        }
                        ThreatFeedType::IpBlocklist => {
                            if let Ok(cidr) = entry.parse::<ipnet::IpNet>() {
                                new_cidrs.push(cidr);
                            } else if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
                                new_cidrs.push(ipnet::IpNet::from(ip));
                            }
                        }
                        ThreatFeedType::NrdList => {
                            super::bloom::insert(&mut new_nrd_bloom, &entry);
                            nrd_entries += 1;
                        }
                    }
                    count += 1;
                    total_entries += 1;
                }

                update_feed_meta(pool, &feed.id, count as u64).await;
                info!(feed = %feed.name, entries = count, "Feed loaded");
            }
            Err(e) => {
                warn!(feed = %feed.name, url = %feed.url, "Failed to fetch feed: {e}");
            }
        }
    }

    // Atomic swap: replace bloom filter and CIDRs
    // Persist bloom while holding the write lock to prevent TOCTOU race
    {
        let mut bloom_guard = engine.bloom.write();
        *bloom_guard = new_bloom;
        super::bloom::save_to_redis(pool, &bloom_guard, total_entries).await;
    }
    if nrd_entries > 0 {
        let mut nrd_guard = engine.nrd_bloom.write();
        *nrd_guard = new_nrd_bloom;
        info!(nrd_entries, "NRD bloom filter updated");
    }
    {
        new_cidrs.sort();
        let mut cidrs_guard = engine.bad_cidrs.write();
        *cidrs_guard = new_cidrs;
    }

    // Publish reload notification for multi-node sync
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("PUBLISH")
            .arg(keys::THREAT_RELOAD_CHANNEL)
            .arg("feeds_updated")
            .query_async(&mut *conn)
            .await;
    }

    info!(total_entries, "Feed refresh complete");
    Ok(())
}

/// Fetch a single feed and parse it into bloom entries.
/// For DomainBlocklist: entries are bare domains.
/// For UrlBlocklist: entries are full URL paths (domain + path) so we don't
///   block entire platforms like google.com when only a specific path is malicious.
/// Validate feed URL: must be HTTPS (or HTTP for known feed providers), no private IPs.
fn validate_feed_url(url: &str) -> anyhow::Result<()> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        anyhow::bail!("Feed URL must use http(s) scheme");
    }
    // Block obvious SSRF targets in the URL host
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())
        .unwrap_or("");
    if host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("169.254.")
        || host.ends_with(".internal")
        || host.ends_with(".local")
    {
        anyhow::bail!("Feed URL points to private/internal address");
    }
    Ok(())
}

async fn fetch_and_parse(client: &reqwest::Client, feed: &ThreatFeed) -> anyhow::Result<Vec<String>> {
    validate_feed_url(&feed.url)?;

    let resp = client.get(&feed.url)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }

    // Size-limited download to prevent memory exhaustion
    let content_length = resp.content_length().unwrap_or(0) as usize;
    if content_length > MAX_FEED_SIZE {
        anyhow::bail!("Feed too large: {} bytes", content_length);
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_FEED_SIZE {
        anyhow::bail!("Feed too large: {} bytes", bytes.len());
    }
    let text = String::from_utf8_lossy(&bytes);
    let is_url_feed = feed.feed_type == ThreatFeedType::UrlBlocklist;
    let mut entries = Vec::new();

    for line in text.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        // Handle CSV-style feeds (URLhaus uses CSV)
        if line.contains(',') {
            for field in line.split(',') {
                let field = field.trim().trim_matches('"');
                if is_url_feed {
                    if let Some(url) = normalize_url(field) {
                        entries.push(url);
                    }
                } else if let Some(domain) = extract_domain_from_url(field) {
                    entries.push(domain);
                }
            }
            continue;
        }

        // Handle JSON-style feeds (PhishTank)
        if line.starts_with('{') || line.starts_with('[') {
            continue;
        }

        // Plain list
        if is_url_feed {
            if let Some(url) = normalize_url(line) {
                entries.push(url);
            }
        } else if let Some(domain) = extract_domain_from_url(line) {
            entries.push(domain);
        } else if !line.contains(' ') {
            // Bare domain or IP
            entries.push(line.to_lowercase());
        }
    }

    // Try JSON parsing for PhishTank-style feeds
    if entries.is_empty() && text.starts_with('[') {
        if let Ok(array) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
            for item in &array {
                if let Some(url) = item.get("url").and_then(|u| u.as_str()) {
                    if is_url_feed {
                        if let Some(normalized) = normalize_url(url) {
                            entries.push(normalized);
                        }
                    } else if let Some(domain) = extract_domain_from_url(url) {
                        entries.push(domain);
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Normalize a URL to "host/path" format for bloom insertion.
/// Strips scheme and port, lowercases the host.
/// Example: "https://evil.com:8080/malware.exe" → "evil.com/malware.exe"
fn normalize_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    if without_scheme.is_empty() || without_scheme.contains(' ') {
        return None;
    }

    // Split host:port from path
    let (host_port, path) = match without_scheme.find('/') {
        Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
        None => (without_scheme, "/"),
    };

    // Strip port from host
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        return None;
    }

    Some(format!("{}{}", host.to_lowercase(), path))
}

/// Extract just the domain from a URL string.
fn extract_domain_from_url(url: &str) -> Option<String> {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?
        .split('/')
        .next()?
        .split(':')
        .next()?;

    if host.is_empty() || host.contains(' ') {
        return None;
    }

    Some(host.to_lowercase())
}

/// Load all configured feeds from Redis.
async fn load_feeds_from_redis(pool: &Pool) -> Vec<ThreatFeed> {
    let Ok(mut conn) = pool.get().await else {
        return Vec::new();
    };

    let feed_ids: Vec<String> = conn
        .smembers(keys::THREAT_FEEDS)
        .await
        .unwrap_or_default();

    let mut feeds = Vec::new();
    for id in feed_ids {
        let key = keys::threat_feed(&id);
        let json: Option<String> = conn.get(&key).await.unwrap_or(None);
        if let Some(json) = json {
            if let Ok(feed) = serde_json::from_str::<ThreatFeed>(&json) {
                feeds.push(feed);
            }
        }
    }

    feeds
}

/// Update feed metadata after successful refresh.
async fn update_feed_meta(pool: &Pool, feed_id: &str, entry_count: u64) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };

    let key = keys::threat_feed(feed_id);

    // Read, update, write back
    let json: Option<String> = conn.get(&key).await.unwrap_or(None);
    if let Some(json) = json {
        if let Ok(mut feed) = serde_json::from_str::<ThreatFeed>(&json) {
            feed.last_updated = Some(chrono::Utc::now());
            feed.entry_count = entry_count;
            if let Ok(updated) = serde_json::to_string(&feed) {
                let _: Result<(), _> = conn.set(&key, updated).await;
            }
        }
    }
}
