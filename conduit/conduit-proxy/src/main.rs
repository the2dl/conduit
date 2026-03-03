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

    // Spawn logging pipeline
    let log_tx = logging::spawn_logging_pipeline(&config, &pool);

    // Spawn node lifecycle (heartbeat, pub/sub) if configured
    node::spawn_node_lifecycle(&config, &pool);

    // Create the Pingora HttpProxy for handling plain HTTP requests
    let proxy_inner = ClearGateProxy::new(
        config.clone(),
        pool.clone(),
        ca.clone(),
        cert_cache.clone(),
        log_tx.clone(),
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
    };

    let mut service =
        ListeningService::new("ClearGate Proxy".to_string(), cleargate);
    service.add_tcp(&config.listen_addr);

    info!(addr = %config.listen_addr, "Proxy listening");

    server.add_service(service);
    server.run_forever();
}
