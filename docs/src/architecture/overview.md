# Architecture Overview

## Crate structure

```
conduit-proxy/
  conduit/
    conduit-common/     # Shared types, config, CA, Redis helpers
    conduit-proxy/      # Pingora-based forward proxy
    conduit-api/        # Axum REST management API
  conduit-ui/           # SvelteKit web dashboard
  pingora/              # Vendored Pingora submodules
```

## Proxy internals

The proxy is built on two Pingora abstractions:

### `ClearGateService` (ServerApp)

Handles raw TCP connections. Responsible for:

- Accepting new connections
- Detecting `CONNECT` requests for HTTPS tunneling
- Performing TLS handshake with dynamically generated certificates (MITM)
- Routing decrypted traffic into the Pingora HTTP pipeline
- HTTP/2 cleartext (H2C) support

### `ClearGateProxy` (ProxyHttp)

Implements Pingora's proxy filter trait for HTTP request processing:

- `request_filter` — Policy evaluation, rate limiting, authentication
- `upstream_peer` — Upstream selection (direct or via load balancer)
- `response_filter` — DLP scanning, threat content inspection
- `logging` — Request logging to Dragonfly

## Key subsystems

| Module | File | Purpose |
|--------|------|---------|
| MITM | `mitm/` | Certificate generation, TLS handshake, tunnel management |
| Policy | `policy/` | Rule evaluation, category matching |
| Threat | `threat/` | Multi-tier detection pipeline |
| Logging | `logging/` | Dragonfly log writer, syslog forwarding |
| Rate limit | `rate_limit.rs` | Sliding window rate limiter |
| Conn limit | `conn_limit.rs` | Per-IP connection tracking (RAII) |
| DNS cache | `dns_cache.rs` | LRU DNS cache with TTL clamping |
| DLP | `dlp.rs` | Regex-based sensitive data scanning |
| Load balancer | `load_balancer.rs` | Domain-glob upstream routing |
| Metrics | `metrics.rs` | Prometheus counters/histograms/gauges |

## Data flow

```
Client → [TCP Accept] → ClearGateService
  ├─ HTTP request → ClearGateProxy pipeline
  └─ CONNECT request → TLS MITM → ClearGateProxy pipeline

ClearGateProxy pipeline:
  request_filter (auth, policy, rate limit, threat T0/T1)
  → upstream_peer (direct / load balancer)
  → upstream request
  → response_filter (cache, DLP, threat T2)
  → logging (Dragonfly, syslog)
  → response to client
```

## Storage

All persistent state lives in Dragonfly (Redis-compatible):

- Policy rules and domain categories
- Request logs (capped at `log_retention`)
- DLP rules
- Node registry and heartbeats
- Threat reputation scores
