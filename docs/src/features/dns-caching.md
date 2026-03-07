# DNS Caching

Conduit maintains an in-memory DNS cache to reduce resolution latency and upstream DNS load.

```toml
[dns]
enabled = true
max_entries = 10000          # LRU cache capacity
min_ttl_secs = 30            # Minimum TTL clamp
max_ttl_secs = 3600          # Maximum TTL clamp (1 hour)
negative_ttl_secs = 30       # Cache duration for NXDOMAIN responses
```

## TTL clamping

DNS TTLs from upstream responses are clamped to the configured range. This prevents:

- **Very short TTLs** from causing excessive DNS queries
- **Very long TTLs** from serving stale records after IP changes
