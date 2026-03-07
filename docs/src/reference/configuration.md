# Full Configuration Reference

Complete reference for `conduit.toml`. All fields have defaults — only override what you need.

## Top-level

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | `"0.0.0.0:8080"` | Proxy listener address |
| `api_addr` | string | `"0.0.0.0:8443"` | Management API address |
| `dragonfly_url` | string | `"redis://127.0.0.1:6379"` | Dragonfly/Redis connection URL |
| `ca_cert_path` | string? | `"cleargate-ca.pem"` | CA certificate path |
| `ca_key_path` | string? | `"cleargate-ca-key.pem"` | CA private key path |
| `cert_cache_size` | int | `10000` | Max cached TLS certificates |
| `log_channel_size` | int | `10000` | Internal log channel buffer |
| `syslog_target` | string? | none | Syslog destination (e.g., `"udp://syslog:514"`) |
| `redis_pool_size` | int | `16` | Redis connection pool size |
| `auth_required` | bool | `false` | Require proxy authentication |
| `block_page_html` | string? | none | Custom HTML for block pages |
| `log_retention` | int | `100000` | Max log entries in Dragonfly |
| `workers` | int | CPU count | Worker threads |
| `ui_dir` | string? | none | Path to built UI static files |
| `tls_intercept` | bool | `true` | Enable MITM TLS interception |
| `api_key` | string? | none | API authentication key |
| `fail_closed` | bool | `true` | Block when policy unavailable |

## `[node]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `node_id` | string | required | Unique node identifier |
| `dragonfly_url` | string | required | Per-node Dragonfly URL |
| `name` | string? | none | Human-readable node name |
| `heartbeat_interval_secs` | int | `10` | Heartbeat interval |
| `enrollment_token` | string? | none | One-time enrollment token |
| `hmac_key` | string? | none | Base64url HMAC key for heartbeats |

## `[cache]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable HTTP caching |
| `max_cache_size` | int | `134217728` (128MB) | Total cache size in bytes |
| `max_file_size` | int | `10485760` (10MB) | Max single response size |
| `lock_timeout_secs` | int | `5` | Cache lock timeout |
| `stale_while_revalidate_secs` | int | `60` | Serve stale during revalidation |
| `stale_if_error_secs` | int | `300` | Serve stale on upstream error |

## `[threat]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable threat detection |
| `tier0_escalation_threshold` | float | `0.3` | Tier 0 → Tier 1 threshold |
| `tier0_block_threshold` | float | `0.9` | Tier 0 immediate block threshold |
| `dga_entropy_threshold` | float | `3.5` | DGA entropy threshold |
| `tier1_enabled` | bool | `true` | Enable ML model tier |
| `tier1_escalation_threshold` | float | `0.5` | Tier 1 → Tier 2 threshold |
| `tier2_enabled` | bool | `true` | Enable content inspection |
| `tier2_escalation_threshold` | float | `0.6` | Tier 2 → Tier 3 threshold |
| `max_inspect_bytes` | int | `262144` (256KB) | Max content inspection size |
| `tier2_block_on_inspect` | bool | `false` | Block on first visit |
| `max_buffer_bytes` | int | `1048576` (1MB) | Max buffer for first-visit blocking |
| `tier3_enabled` | bool | `false` | Enable LLM analysis |
| `llm_provider` | string? | none | LLM provider name |
| `llm_api_url` | string? | none | LLM API endpoint |
| `llm_api_key` | string? | none | LLM API key |
| `tier3_behavior` | string | `"allow_and_flag"` | `"allow_and_flag"` or `"block_on_flag"` |
| `tier3_timeout_ms` | int | `5000` | LLM request timeout |
| `reputation_enabled` | bool | `true` | Enable domain reputation |
| `reputation_decay_hours` | int | `168` (7 days) | Reputation decay period |
| `reputation_block_threshold` | float | `0.55` | Auto-block reputation threshold |
| `bloom_capacity` | int | `2000000` | Bloom filter capacity |
| `bloom_fp_rate` | float | `0.001` | Bloom filter false positive rate |
| `feed_refresh_interval_secs` | int | `3600` | Threat feed refresh interval |

## `[timeouts]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connect_timeout_secs` | int | `10` | TCP connect timeout |
| `total_connection_timeout_secs` | int | `15` | Full connection setup timeout |
| `read_timeout_secs` | int | `60` | Upstream read timeout |
| `write_timeout_secs` | int | `60` | Upstream write timeout |
| `idle_timeout_secs` | int | `300` | Keep-alive idle timeout |
| `request_timeout_secs` | int | `0` | Overall request timeout (0 = disabled) |

## `[request_limits]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_request_header_size` | int | `0` | Max header size (0 = unlimited) |
| `max_request_body_size` | int | `0` | Max body size (0 = unlimited) |

## `[shutdown]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `grace_period_secs` | int | `60` | Stop accepting new connections |
| `graceful_shutdown_timeout_secs` | int | `300` | Max wait for in-flight requests |
| `upgrade_sock` | string | `"/tmp/conduit-upgrade.sock"` | Hot upgrade socket path |
| `daemon` | bool | `false` | Run as daemon |
| `pid_file` | string | `"/tmp/conduit.pid"` | PID file path |

## `[rate_limit]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable rate limiting |
| `window_secs` | int | `60` | Sliding window size |
| `per_ip_limit` | int | `0` | Max requests per IP (0 = unlimited) |
| `per_user_limit` | int | `0` | Max requests per user (0 = unlimited) |
| `per_destination_limit` | int | `0` | Max requests per destination (0 = unlimited) |
| `estimator_hashes` | int | `4` | Count-Min Sketch hash functions |
| `estimator_slots` | int | `1024` | Count-Min Sketch slots |

## `[connection_limits]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable connection limits |
| `max_connections_per_ip` | int | `0` | Max concurrent connections per IP |

## `[dns]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable DNS caching |
| `max_entries` | int | `10000` | LRU cache capacity |
| `min_ttl_secs` | int | `30` | Minimum TTL clamp |
| `max_ttl_secs` | int | `3600` | Maximum TTL clamp |
| `negative_ttl_secs` | int | `30` | NXDOMAIN cache duration |

## `[metrics]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Prometheus metrics |
| `listen_addr` | string | `"0.0.0.0:9091"` | Metrics endpoint address |

## `[load_balancing]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable load balancing |
| `upstreams` | array | `[]` | Upstream group definitions |

### `[[load_balancing.upstreams]]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Group name |
| `domains` | array | required | Domain glob patterns |
| `algorithm` | string | `"round_robin"` | Load balancing algorithm |
| `backends` | array | required | Backend server list |
| `health_check` | object? | none | Health check config (not yet active) |

### `[[load_balancing.upstreams.backends]]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | required | Backend address (`host:port`) |
| `weight` | int | `1` | Routing weight |

## `[dlp]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DLP scanning |
| `max_scan_size` | int | `1048576` (1MB) | Max response body to scan |
| `action` | string | `"log"` | Default action: `"log"`, `"block"`, `"redact"` |
| `custom_patterns` | array | `[]` | Custom regex patterns |

### `[[dlp.custom_patterns]]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Pattern name |
| `regex` | string | required | Regex pattern |
| `action` | string | `"log"` | Per-pattern action override |

## `[downstream]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `h2c` | bool | `false` | Enable HTTP/2 cleartext |
| `h2_max_concurrent_streams` | int | `100` | Max concurrent H2 streams |
| `h2_initial_window_size` | int | `65535` | H2 flow control window |
