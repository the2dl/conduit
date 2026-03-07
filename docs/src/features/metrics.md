# Metrics & Monitoring

Conduit exposes Prometheus-compatible metrics via a lightweight HTTP endpoint.

```toml
[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"
```

## Scraping

```sh
curl http://localhost:9090/metrics
```

## Available metrics

The metrics endpoint exposes counters, histograms, and gauges covering:

- Request counts and rates
- Response latency histograms
- Active connections
- Cache hit/miss ratios
- Rate limit rejections
- Threat detection verdicts
- DLP match counts

## Grafana

Point a Prometheus scraper at the metrics endpoint and build dashboards in Grafana. The metrics use standard Prometheus naming conventions and are compatible with common proxy dashboard templates.
