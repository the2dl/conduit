# Timeouts & Limits

## Timeouts

```toml
[timeouts]
connect_timeout_secs = 10           # TCP connect to upstream
total_connection_timeout_secs = 15   # Full connection setup including TLS
read_timeout_secs = 60              # Read from upstream
write_timeout_secs = 60             # Write to upstream
idle_timeout_secs = 300             # Keep-alive idle timeout
request_timeout_secs = 0            # Overall request timeout (0 = disabled)
```

## Request size limits

```toml
[request_limits]
max_request_header_size = 8192      # 8KB (0 = unlimited)
max_request_body_size = 10485760    # 10MB (0 = unlimited)
```

## Connection limits

```toml
[connection_limits]
enabled = true
max_connections_per_ip = 256        # 0 = unlimited
```

Limits the number of concurrent connections from a single client IP. Connections beyond the limit are rejected. Tracked in memory using atomic counters with RAII cleanup.

## Graceful shutdown

```toml
[shutdown]
grace_period_secs = 60             # Stop accepting new connections
graceful_shutdown_timeout_secs = 300 # Max wait for in-flight requests
upgrade_sock = "/tmp/conduit-upgrade.sock"
```
