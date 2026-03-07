#[cfg(unix)]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod conn_limit;
mod ctx;
mod dlp;
mod dns_cache;
mod identity;
mod load_balancer;
mod logging;
mod metrics;
mod mitm;
mod node;
mod policy;
mod proxy;
mod rate_limit;
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
use crate::proxy::{ClearGateProxy, ProxyDeps, CacheComponents};
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

    // Honor TOML workers config (defaults to available CPUs via num_cpus())
    if let Some(conf) = Arc::get_mut(&mut server.configuration) {
        conf.threads = config.workers;
        info!(threads = config.workers, "Configured Pingora worker threads");
    }

    // Apply shutdown config to Pingora's server configuration before bootstrap
    if let Some(ref shutdown_cfg) = config.shutdown {
        if let Some(conf) = Arc::get_mut(&mut server.configuration) {
            conf.grace_period_seconds = Some(shutdown_cfg.grace_period_secs);
            conf.graceful_shutdown_timeout_seconds = Some(shutdown_cfg.graceful_shutdown_timeout_secs);
            conf.upgrade_sock = shutdown_cfg.upgrade_sock.clone();
            conf.pid_file = shutdown_cfg.pid_file.clone();
            if shutdown_cfg.daemon {
                conf.daemon = true;
            }
        }
    }

    server.bootstrap();

    // Load full category dataset into memory and register pool for background reloads
    {
        let pool_clone = pool.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Category dataset load runtime");
        rt.block_on(policy::categories::load_full_dataset(&pool_clone));
        policy::categories::register_for_reload(pool.clone());
    }

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

    // Initialize Prometheus metrics server if configured
    if let Some(ref metrics_cfg) = config.metrics {
        metrics::init();
        metrics::spawn_metrics_server(metrics_cfg);
    }

    // Initialize HTTP response cache if configured
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

    let cache = if config.cache.as_ref().map(|c| c.enabled).unwrap_or(false) {
        let cache_cfg = config.cache.as_ref().unwrap();
        info!("HTTP response cache enabled (max_size={}MB, max_file={}MB)",
            cache_cfg.max_cache_size / 1_048_576,
            cache_cfg.max_file_size / 1_048_576);

        let storage: &'static _ = Box::leak(Box::new(
            pingora_cache::MemCache::new(),
        ));

        let estimated_items = cache_cfg.max_cache_size / 65_536;
        let eviction: &'static _ = Box::leak(Box::new(
            pingora_cache::eviction::lru::Manager::<8>::with_capacity(
                cache_cfg.max_cache_size,
                estimated_items / 8,
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

        CacheComponents {
            storage: Some(storage as &'static (dyn pingora_cache::storage::Storage + Sync)),
            eviction: Some(eviction as &'static (dyn pingora_cache::eviction::EvictionManager + Sync)),
            lock: Some(lock as &'static pingora_cache::lock::CacheKeyLockImpl),
            meta_defaults: Some(defaults as &'static pingora_cache::CacheMetaDefaults),
            max_file_size: cache_cfg.max_file_size,
        }
    } else {
        CacheComponents::default()
    };

    // Initialize rate limiter
    let rate_limiter = config.rate_limit.as_ref()
        .filter(|c| c.enabled)
        .map(|c| Arc::new(rate_limit::RateLimiter::new(c)));

    // Initialize DNS cache
    let dns_cache = config.dns.as_ref()
        .filter(|c| c.enabled)
        .map(|c| Arc::new(dns_cache::DnsCache::new(c)));

    // Initialize upstream router (load balancing)
    let upstream_router = config.load_balancing.as_ref()
        .filter(|c| c.enabled)
        .map(|c| Arc::new(load_balancer::UpstreamRouter::new(c)));

    // Initialize DLP engine, then load rules from Dragonfly (falls back to config if unavailable)
    let dlp_engine = config.dlp.as_ref()
        .filter(|c| c.enabled)
        .map(|c| {
            let engine = Arc::new(dlp::DlpEngine::new(c));
            // Load rules from Dragonfly (overrides config-based rules if any exist)
            {
                let pool_check = pool.clone();
                let engine_ref = engine.clone();
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("DLP load runtime");
                rt.block_on(engine_ref.reload_from_dragonfly(&pool_check));
            }
            // Register for background reloads via pub/sub
            dlp::register_for_reload(engine.clone(), pool.clone());
            engine
        });

    // Initialize connection tracker
    let conn_tracker = config.connection_limits.as_ref()
        .filter(|c| c.enabled)
        .map(|c| Arc::new(conn_limit::ConnectionTracker::new(c)));

    // Spawn periodic connection tracker cleanup.
    // Uses a daemon thread — will terminate when the main process exits.
    if let Some(ref tracker) = conn_tracker {
        let tracker_clone = tracker.clone();
        std::thread::Builder::new()
            .name("conn-cleanup".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    tracker_clone.cleanup();
                }
            })
            .expect("Failed to spawn connection cleanup thread");
    }

    // Create the Pingora HttpProxy for handling plain HTTP requests
    let deps = ProxyDeps {
        config: config.clone(),
        pool: pool.clone(),
        ca: ca.clone(),
        cert_cache: cert_cache.clone(),
        log_tx: log_tx.clone(),
        threat_engine: threat_engine.clone(),
        cache,
        rate_limiter: rate_limiter.clone(),
        dns_cache: dns_cache.clone(),
        upstream_router: upstream_router.clone(),
        dlp_engine: dlp_engine.clone(),
    };
    let proxy_inner = ClearGateProxy::new(deps);
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
        rate_limiter,
        conn_tracker,
    };

    let mut service =
        ListeningService::new("ClearGate Proxy".to_string(), cleargate);
    service.add_tcp(&config.listen_addr);

    info!(addr = %config.listen_addr, "Proxy listening");

    server.add_service(service);
    server.run_forever();
}
