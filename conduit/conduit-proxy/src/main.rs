#[cfg(unix)]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod ctx;
mod identity;
mod logging;
mod mitm;
mod node;
mod policy;
mod proxy;
mod service;
mod stats;
mod threat;

use conduit_common::ca::CertAuthority;
use conduit_common::config::ClearGateConfig;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::services::listening::Service as ListeningService;
use pingora_proxy::http_proxy;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::logging::LogSender;
use crate::mitm::cert_cache::CertCache;
use crate::proxy::ClearGateProxy;
use crate::service::ClearGateService;

fn main() -> anyhow::Result<()> {
    // Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // Load ClearGate config from file or defaults
    let config_path =
        std::env::var("CONDUIT_CONFIG").unwrap_or_else(|_| "conduit.toml".into());
    let config = if std::path::Path::new(&config_path).exists() {
        ClearGateConfig::from_file(&config_path)?
    } else {
        info!("Config file not found at {config_path}, using defaults");
        ClearGateConfig::default()
    };
    let config = Arc::new(config);

    info!(listen = %config.listen_addr, api = %config.api_addr, "Starting ClearGate");

    // CA
    let ca = CertAuthority::load_or_generate(&config.ca_cert_path(), &config.ca_key_path())?;
    let ca = Arc::new(ca);

    // Cert cache
    let cert_cache = Arc::new(CertCache::new(config.cert_cache_size, ca.clone()));

    // Redis/Dragonfly pool — use node-specific URL when configured
    let dragonfly_url = config
        .node
        .as_ref()
        .map(|n| n.dragonfly_url.as_str())
        .unwrap_or(&config.dragonfly_url);
    let pool =
        conduit_common::redis::create_pool(dragonfly_url, config.redis_pool_size)?;
    let pool = Arc::new(pool);

    // Verify Dragonfly connectivity (fail fast on bad credentials)
    {
        let pool_check = pool.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        if let Err(e) = rt.block_on(conduit_common::redis::verify_connection(&pool_check)) {
            error!("Dragonfly connection check failed: {e}");
            std::process::exit(1);
        }
    }

    // Bootstrap Pingora server
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    // Initialize threat engine if configured (before logging pipeline so it can receive the Arc)
    let threat_engine = if config.threat.as_ref().map(|t| t.enabled).unwrap_or(false) {
        Some(threat::initialize(&pool, config.threat.as_ref().unwrap()))
    } else {
        None
    };

    // Spawn logging pipeline (receives threat engine for reputation cache updates)
    let log_tx = logging::spawn_logging_pipeline(&config, &pool, threat_engine.clone());

    // Spawn node lifecycle (heartbeat, pub/sub) if configured
    node::spawn_node_lifecycle(&config, &pool);

    // Initialize HTTP response cache if configured
    // Load zstd compression dictionary for cache metadata (reduces per-entry overhead at scale).
    // NOTE: This uses the test dictionary from vendored Pingora. A production dictionary should
    // be trained on real cache metadata; this is a best-effort default that gracefully degrades.
    {
        let dict_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pingora/pingora-proxy/tests/headers.dict");
        if std::path::Path::new(dict_path).exists() {
            if !pingora_cache::set_compression_dict_path(dict_path) {
                tracing::warn!("Failed to load cache compression dictionary from {dict_path}");
            }
        } else {
            tracing::debug!("Cache compression dictionary not found at {dict_path}, cache will work without compression");
        }
    }

    // Box::leak is used for cache components because Pingora's API requires `&'static`
    // references. These are process-lifetime singletons — acceptable since the proxy
    // process runs until termination and cache reconfiguration requires a restart.
    let (cache_storage, cache_eviction, cache_lock, cache_meta_defaults, cache_max_file_size) =
        if config.cache.as_ref().map(|c| c.enabled).unwrap_or(false) {
            let cache_cfg = config.cache.as_ref().unwrap();
            info!("HTTP response cache enabled (max_size={}MB, max_file={}MB)",
                cache_cfg.max_cache_size / 1_048_576,
                cache_cfg.max_file_size / 1_048_576);

            let storage: &'static _ = Box::leak(Box::new(
                pingora_cache::MemCache::new(),
            ));

            // Estimate ~64KB average cached object for shard capacity hint
            let estimated_items = cache_cfg.max_cache_size / 65_536;
            let eviction: &'static _ = Box::leak(Box::new(
                pingora_cache::eviction::lru::Manager::<8>::with_capacity(
                    cache_cfg.max_cache_size,
                    estimated_items / 8, // per-shard capacity
                ),
            ));

            let lock: &'static _ = Box::leak(Box::new(
                pingora_cache::lock::CacheLock::new(
                    std::time::Duration::from_secs(cache_cfg.lock_timeout_secs),
                ),
            ));

            let swr = cache_cfg.stale_while_revalidate_secs;
            let sie = cache_cfg.stale_if_error_secs;
            let defaults: &'static _ = Box::leak(Box::new(
                pingora_cache::CacheMetaDefaults::new(
                    |status| {
                        use http::StatusCode;
                        match status {
                            StatusCode::OK | StatusCode::NON_AUTHORITATIVE_INFORMATION
                            | StatusCode::MOVED_PERMANENTLY | StatusCode::NOT_FOUND
                            | StatusCode::METHOD_NOT_ALLOWED | StatusCode::GONE => {
                                Some(std::time::Duration::from_secs(3600))
                            }
                            StatusCode::PARTIAL_CONTENT | StatusCode::NOT_MODIFIED => {
                                Some(std::time::Duration::from_secs(3600))
                            }
                            _ => None,
                        }
                    },
                    swr,
                    sie,
                ),
            ));

            (
                Some(storage as &'static (dyn pingora_cache::storage::Storage + Sync)),
                Some(eviction as &'static (dyn pingora_cache::eviction::EvictionManager + Sync)),
                Some(lock as &'static pingora_cache::lock::CacheKeyLockImpl),
                Some(defaults as &'static pingora_cache::CacheMetaDefaults),
                cache_cfg.max_file_size,
            )
        } else {
            (None, None, None, None, 0)
        };

    // Create the Pingora HttpProxy for handling plain HTTP requests
    let proxy_inner = ClearGateProxy::new(
        config.clone(),
        pool.clone(),
        ca.clone(),
        cert_cache.clone(),
        log_tx.clone(),
        threat_engine.clone(),
        cache_storage,
        cache_eviction,
        cache_lock,
        cache_meta_defaults,
        cache_max_file_size,
    );
    let pingora_proxy = Arc::new(http_proxy(&server.configuration, proxy_inner));

    // Build the custom service that handles both CONNECT and HTTP
    let cleargate = ClearGateService {
        config: config.clone(),
        pool,
        ca,
        cert_cache,
        log_tx: LogSender(log_tx),
        http_proxy: pingora_proxy,
        threat_engine,
    };

    let mut service =
        ListeningService::new("ClearGate Proxy".to_string(), cleargate);
    service.add_tcp(&config.listen_addr);

    info!(addr = %config.listen_addr, "Proxy listening");

    server.add_service(service);
    server.run_forever();
}
