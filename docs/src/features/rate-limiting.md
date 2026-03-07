# Rate Limiting

Conduit supports per-IP, per-user, and per-destination rate limiting using a sliding window counter.

```toml
[rate_limit]
enabled = true
window_secs = 60               # Sliding window size
per_ip_limit = 200             # Max requests per IP per window (0 = unlimited)
per_user_limit = 0             # Max requests per authenticated user (0 = unlimited)
per_destination_limit = 0      # Max requests per target host (0 = unlimited)
```

## How it works

Rate limiting uses Pingora's `pingora-limits` crate with a Count-Min Sketch estimator for memory-efficient counting. When a limit is exceeded, the proxy returns `429 Too Many Requests`.

## Tuning the estimator

For advanced use cases, you can tune the underlying data structure:

```toml
estimator_hashes = 4           # Number of hash functions (more = fewer false positives)
estimator_slots = 1024         # Slots per hash (more = higher accuracy, more memory)
```

The defaults work well for most deployments.
