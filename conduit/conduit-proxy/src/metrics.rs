use conduit_common::config::MetricsConfig;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

static REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("requests_total", "Total requests processed")
        .namespace("conduit");
    let counter = IntCounterVec::new(opts, &["action", "scheme"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static BLOCKS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("blocks_total", "Total blocked requests")
        .namespace("conduit");
    let counter = IntCounterVec::new(opts, &["reason"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "request_duration_seconds",
        "Request duration in seconds",
    )
    .namespace("conduit")
    .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]);
    let hist = HistogramVec::new(opts, &["scheme"]).unwrap();
    REGISTRY.register(Box::new(hist.clone())).unwrap();
    hist
});

static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new("conduit_active_connections", "Active connections").unwrap();
    REGISTRY.register(Box::new(gauge.clone())).unwrap();
    gauge
});

static CACHE_HITS: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("conduit_cache_hits_total", "Cache hits").unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static CACHE_MISSES: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("conduit_cache_misses_total", "Cache misses").unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static RATE_LIMITS: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("conduit_rate_limits_total", "Rate limited requests").unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static THREAT_EVALS: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("threat_evaluations_total", "Threat evaluations by tier")
        .namespace("conduit");
    let counter = IntCounterVec::new(opts, &["tier"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static DNS_CACHE_HITS: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("conduit_dns_cache_hits_total", "DNS cache hits").unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

/// Record a completed request for metrics.
pub fn record_request(action: &str, scheme: &str, duration_ms: u64, block_reason: Option<&str>) {
    REQUESTS_TOTAL
        .with_label_values(&[action, scheme])
        .inc();
    REQUEST_DURATION
        .with_label_values(&[scheme])
        .observe(duration_ms as f64 / 1000.0);
    if let Some(reason) = block_reason {
        BLOCKS_TOTAL.with_label_values(&[reason]).inc();
    }
}

pub fn inc_active_connections() {
    ACTIVE_CONNECTIONS.inc();
}

pub fn dec_active_connections() {
    ACTIVE_CONNECTIONS.dec();
}

pub fn record_cache_hit() {
    CACHE_HITS.inc();
}

pub fn record_cache_miss() {
    CACHE_MISSES.inc();
}

pub fn record_rate_limit() {
    RATE_LIMITS.inc();
}

pub fn record_threat_eval(tier: &str) {
    THREAT_EVALS.with_label_values(&[tier]).inc();
}

pub fn record_dns_cache_hit() {
    DNS_CACHE_HITS.inc();
}

/// Spawn a lightweight HTTP server on the metrics port to serve /metrics.
pub fn spawn_metrics_server(config: &MetricsConfig) {
    if !config.enabled {
        return;
    }

    let addr = config.listen_addr.clone();
    info!(addr = %addr, "Starting Prometheus metrics server");

    std::thread::Builder::new()
        .name("conduit-metrics".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create metrics runtime");

            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(addr = %addr, "Failed to bind metrics server: {e}");
                        return;
                    }
                };

                loop {
                    let (mut stream, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Metrics accept error: {e}");
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        // Read the HTTP request line + headers (with timeout for slow clients)
                        let mut buf = [0u8; 2048];
                        let n = match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                        ).await {
                            Ok(Ok(n)) => n,
                            _ => return,
                        };

                        // Only serve GET /metrics; reject everything else
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let is_metrics = req.starts_with("GET /metrics")
                            || req.starts_with("GET / ");
                        if !is_metrics {
                            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(resp).await;
                            return;
                        }

                        let encoder = TextEncoder::new();
                        let metric_families = REGISTRY.gather();
                        let mut body = Vec::new();
                        if let Err(e) = encoder.encode(&metric_families, &mut body) {
                            error!("Failed to encode metrics: {e}");
                            return;
                        }

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.write_all(&body).await;
                    });
                }
            });
        })
        .expect("Failed to spawn metrics thread");
}

/// Ensure all lazy statics are initialized.
pub fn init() {
    Lazy::force(&REQUESTS_TOTAL);
    Lazy::force(&BLOCKS_TOTAL);
    Lazy::force(&REQUEST_DURATION);
    Lazy::force(&ACTIVE_CONNECTIONS);
    Lazy::force(&CACHE_HITS);
    Lazy::force(&CACHE_MISSES);
    Lazy::force(&RATE_LIMITS);
    Lazy::force(&THREAT_EVALS);
    Lazy::force(&DNS_CACHE_HITS);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_request() {
        init();
        record_request("allow", "https", 100, None);
        record_request("block", "https", 50, Some("policy"));
        // Just verify no panics
    }

    #[test]
    fn test_connection_gauge() {
        init();
        inc_active_connections();
        inc_active_connections();
        dec_active_connections();
        assert_eq!(ACTIVE_CONNECTIONS.get(), 1);
        dec_active_connections();
    }
}
