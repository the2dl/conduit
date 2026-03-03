mod routes;

use conduit_common::config::ClearGateConfig;
use deadpool_redis::Pool;
use governor::Quota;
use routes::ApiRateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub struct AppState {
    pub pool: Arc<Pool>,
    pub config: Arc<ClearGateConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let config_path = std::env::var("CONDUIT_CONFIG").unwrap_or_else(|_| "conduit.toml".into());
    let config = if std::path::Path::new(&config_path).exists() {
        ClearGateConfig::from_file(&config_path)?
    } else {
        info!("Config file not found at {config_path}, using defaults");
        ClearGateConfig::default()
    };
    let config = Arc::new(config);

    // Warn if management API has no authentication configured
    if config.api_key.is_none() {
        warn!("No api_key configured — management API is unauthenticated. \
               Set api_key in conduit.toml to protect management endpoints.");
    }

    let pool = conduit_common::redis::create_pool(&config.dragonfly_url, config.redis_pool_size)?;
    let pool = Arc::new(pool);

    // Create stream consumer group (idempotent)
    {
        let mut conn = pool.get().await?;
        let _: Result<(), _> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(conduit_common::redis::keys::LOG_STREAM)
            .arg(conduit_common::redis::keys::LOG_STREAM_GROUP)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut *conn)
            .await;
    }

    // Per-IP rate limiter: 60 requests/second burst, sustained 20/s
    let quota = Quota::per_second(nonzero_lit::u32!(60))
        .allow_burst(nonzero_lit::u32!(60));
    let limiter = Arc::new(ApiRateLimiter::keyed(quota));

    let state = Arc::new(AppState {
        pool,
        config: config.clone(),
    });

    let app = routes::build_router(state, limiter);

    let addr: SocketAddr = config.api_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %config.api_addr, "API server listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
