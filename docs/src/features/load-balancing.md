# Load Balancing

Conduit can route requests for specific domains to a pool of upstream backends.

```toml
[load_balancing]
enabled = true

[[load_balancing.upstreams]]
name = "api-cluster"
domains = ["api.internal.com", "*.api.internal.com"]
algorithm = "round_robin"

[[load_balancing.upstreams.backends]]
addr = "10.0.0.1:8080"
weight = 1

[[load_balancing.upstreams.backends]]
addr = "10.0.0.2:8080"
weight = 1
```

## Domain matching

Domains support glob patterns. Requests matching a domain pattern are routed to the corresponding upstream group instead of connecting directly to the target.

## Algorithms

Currently supported: `round_robin`. The implementation uses Pingora's `pingora-load-balancing` crate.

## Health checks (planned)

Health check configuration is accepted but not yet wired into active health checking:

```toml
[load_balancing.upstreams.health_check]
interval_secs = 10
check_type = "tcp"          # or "http"
path = "/health"            # for HTTP checks
expected_status = 200
```
