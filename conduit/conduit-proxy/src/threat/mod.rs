//! Real-time threat detection engine.
//!
//! Architecture:
//! - `evaluate_request()` — deterministic heuristic scoring. No reputation input.
//!   Runs on every request (relay + CONNECT + HTTP). Same domain = same score every time.
//! - `check_reputation()` — separate check, only at CONNECT boundary.
//!   Returns block decision based on learned Tier 2+ content signals.
//! - Reputation updated asynchronously from Tier 2 content analysis only.
//!   No feedback loop possible.

pub mod bloom;
pub mod content;
pub mod entropy;
pub mod feeds;
pub mod heuristics;
pub mod ip_reputation;
pub mod llm;
pub mod model;
pub mod reputation;

use bloomfilter::Bloom;
use conduit_common::config::ThreatConfig;
use conduit_common::types::{ThreatSignal, ThreatTier, ThreatVerdict};
use deadpool_redis::Pool;
use ipnet::IpNet;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Central threat engine holding all shared state.
pub struct ThreatEngine {
    pub config: ThreatConfig,
    pub bloom: RwLock<Bloom<str>>,
    pub top_domains: Vec<String>,
    pub reputation_cache: Mutex<LruCache<String, reputation::CachedReputation>>,
    pub bad_cidrs: RwLock<Vec<IpNet>>,
    pub llm_tx: Option<mpsc::Sender<llm::LlmRequest>>,
}

/// Default top domains for homoglyph detection.
fn default_top_domains() -> Vec<String> {
    vec![
        "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
        "netflix.com", "paypal.com", "instagram.com", "twitter.com", "linkedin.com",
        "youtube.com", "github.com", "reddit.com", "whatsapp.com", "dropbox.com",
        "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
        "americanexpress.com", "usps.com", "fedex.com", "ups.com", "dhl.com",
        "adobe.com", "office.com", "outlook.com", "hotmail.com", "yahoo.com",
        "icloud.com", "slack.com", "zoom.us", "salesforce.com", "stripe.com",
        "coinbase.com", "binance.com", "blockchain.com", "ebay.com", "walmart.com",
        "target.com", "bestbuy.com", "costco.com", "homedepot.com",
        "robinhood.com", "venmo.com", "zelle.com", "schwab.com", "fidelity.com",
        "vanguard.com", "etrade.com", "tdameritrade.com",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Initialize the threat engine.
pub fn initialize(pool: &Arc<Pool>, config: &ThreatConfig) -> Arc<ThreatEngine> {
    info!("Initializing threat detection engine");

    let bloom_filter = {
        let pool_clone = pool.clone();
        let cap = config.bloom_capacity;
        let fp = config.bloom_fp_rate;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create threat init runtime");
        rt.block_on(async {
            bloom::load_from_redis(&pool_clone, cap, fp)
                .await
                .unwrap_or_else(|| bloom::new_bloom(cap, fp))
        })
    };

    let bad_cidrs = {
        let pool_clone = pool.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create threat init runtime");
        rt.block_on(ip_reputation::load_bad_cidrs(&pool_clone))
    };

    let top_domains = if config.homoglyph_detection {
        let mut domains = default_top_domains();
        domains.truncate(config.homoglyph_top_n);
        domains
    } else {
        Vec::new()
    };

    let llm_tx = if config.tier3_enabled {
        let (tx, rx) = llm::create_channel();
        let config_arc = Arc::new(config.clone());
        let pool_clone = pool.clone();
        llm::spawn_llm_worker(config_arc, pool_clone, rx);
        Some(tx)
    } else {
        None
    };

    let reputation_cache = reputation::new_cache();

    // Seed reputation cache from Redis
    {
        let pool_clone = pool.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create reputation seed runtime");
        rt.block_on(reputation::seed_cache_from_redis(&reputation_cache, &pool_clone));
    }

    let engine = Arc::new(ThreatEngine {
        config: config.clone(),
        bloom: RwLock::new(bloom_filter),
        top_domains,
        reputation_cache,
        bad_cidrs: RwLock::new(bad_cidrs),
        llm_tx,
    });

    feeds::spawn_feed_refresh(engine.clone(), pool.clone());

    if config.reputation_enabled {
        reputation::spawn_reputation_sync(engine.clone(), pool.clone());
    }

    info!(
        tier0 = true,
        tier1 = config.tier1_enabled,
        tier2 = config.tier2_enabled,
        tier3 = config.tier3_enabled,
        bloom_cap = config.bloom_capacity,
        "Threat engine initialized"
    );

    engine
}

/// Deterministic request evaluation. Runs heuristics + bloom + Tier 1 ML.
/// NO reputation input. Same domain + path = same score every time.
/// Used by: proxy request_filter, service CONNECT handler, relay loop.
pub fn evaluate_request(
    engine: &ThreatEngine,
    host: &str,
    port: u16,
    path: &str,
    scheme: &str,
    category: Option<&str>,
    upstream_ip: Option<&str>,
) -> ThreatVerdict {
    let config = &engine.config;

    // Bloom filter: check domain and full URL
    let bloom_hit = {
        let bloom = engine.bloom.read();
        if bloom::contains(&bloom, host) {
            true
        } else {
            let full_url = format!("{host}{path}");
            bloom::contains(&bloom, &full_url)
        }
    };

    // IP reputation
    let ip_bad = upstream_ip.map_or(false, |ip| {
        let cidrs = engine.bad_cidrs.read();
        ip_reputation::is_bad_ip(&cidrs, ip)
    });

    // Heuristics — no reputation input
    let (mut score, mut signals) = heuristics::evaluate_all(
        host, port, path, scheme, category,
        None, // no reputation — deterministic
        config.dga_entropy_threshold,
        bloom_hit, ip_bad,
        config.homoglyph_detection,
        &engine.top_domains,
    );

    let mut tier_reached = ThreatTier::Tier0;

    // Tier 1 escalation: ML model for ambiguous scores
    if config.tier1_enabled
        && score >= config.tier0_escalation_threshold
        && score < config.tier0_block_threshold
    {
        let tld_risk_score = signals
            .iter()
            .find(|s| s.name.starts_with("tld_risk"))
            .map(|s| s.score)
            .unwrap_or(0.0);

        let features = model::FeatureVector::from_request(
            host, port, path, tld_risk_score,
            bloom_hit, 0.5, true, score,
        );

        let t0_score = score;
        let t1_score = model::evaluate(&features);
        let blended = (t0_score * 0.4 + t1_score * 0.6).min(1.0);
        score = blended.max(t0_score); // T1 can only raise
        tier_reached = ThreatTier::Tier1;

        signals.push(ThreatSignal {
            name: "ml_model".into(),
            score: t1_score,
            tier: ThreatTier::Tier1,
        });

        debug!(host, t0_score, t1_score, "Tier 1 escalation");
    }

    let blocked = score >= config.tier0_block_threshold;

    ThreatVerdict {
        score,
        tier_reached,
        blocked,
        signals,
        reputation_score: None,
    }
}

/// Check learned reputation for a domain. Called ONLY at CONNECT boundary
/// (one check per tunnel, not per inner request). Returns an updated verdict
/// if reputation warrants blocking, or None if reputation has nothing to add.
pub fn check_reputation(engine: &ThreatEngine, host: &str) -> Option<f32> {
    let rep = reputation::get_cached_score(&engine.reputation_cache, host)?;
    if rep >= engine.config.tier0_block_threshold {
        Some(rep)
    } else {
        None
    }
}
