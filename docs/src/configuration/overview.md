# Configuration Overview

Conduit is configured via a TOML file. By default it reads `conduit.toml` from the working directory. Override the path with the `CONDUIT_CONFIG` environment variable:

```sh
CONDUIT_CONFIG=/etc/conduit/conduit.toml ./target/release/conduit-proxy
```

## Minimal config

```toml
listen_addr = "0.0.0.0:8888"
dragonfly_url = "redis://127.0.0.1:6380"
```

Everything else has sensible defaults. See `conduit.example.toml` for a complete annotated example.

## Config sections

| Section | Purpose | Default |
|---------|---------|---------|
| *(top-level)* | Listener, Dragonfly URL, CA paths, auth | See below |
| `[cache]` | HTTP response caching | Disabled |
| `[threat]` | Multi-tier threat detection | Disabled |
| `[timeouts]` | Connection and request timeouts | Pingora defaults |
| `[request_limits]` | Max header/body sizes | Unlimited |
| `[shutdown]` | Graceful shutdown behavior | 60s grace |
| `[rate_limit]` | Per-IP/user/destination rate limits | Disabled |
| `[connection_limits]` | Max concurrent connections per IP | Disabled |
| `[dns]` | DNS response caching | Disabled |
| `[metrics]` | Prometheus metrics endpoint | Disabled |
| `[load_balancing]` | Domain-based upstream routing | Disabled |
| `[dlp]` | Data Loss Prevention scanning | Disabled |
| `[downstream]` | HTTP/2 (H2C) support | Disabled |
| `[node]` | Multi-node clustering | Standalone |

## Top-level settings

```toml
listen_addr = "0.0.0.0:8888"       # Proxy listener
api_addr = "0.0.0.0:8443"          # Management API
dragonfly_url = "redis://127.0.0.1:6380"

# TLS interception (MITM)
tls_intercept = true                # false = passthrough mode

# Authentication
auth_required = false               # true = require proxy auth (407)
api_key = "secret"                  # Protect management API

# Fail-closed mode
fail_closed = true                  # Block when Redis is unavailable

# Tuning
workers = 4                         # Worker threads (default: CPU count)
cert_cache_size = 10000             # Dynamic cert cache entries
redis_pool_size = 16                # Redis connection pool size
log_retention = 100000              # Max log entries in Dragonfly
```

## Strict parsing

All config structs use `#[serde(deny_unknown_fields)]`. Typos or removed fields will cause a startup error rather than silent misconfiguration.
