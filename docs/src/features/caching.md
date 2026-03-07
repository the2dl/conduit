# HTTP Caching

Conduit can cache HTTP responses to reduce upstream load and improve latency.

```toml
[cache]
enabled = true
max_cache_size = 134217728          # 128MB total cache
max_file_size = 10485760            # 10MB max per response
lock_timeout_secs = 5               # Cache lock timeout
stale_while_revalidate_secs = 60    # Serve stale while revalidating
stale_if_error_secs = 300           # Serve stale on upstream error
```

## Behavior

The cache respects standard HTTP caching headers (`Cache-Control`, `Expires`, `ETag`, `Last-Modified`). It supports:

- **Stale-while-revalidate** — Serves cached responses while asynchronously refreshing in the background
- **Stale-if-error** — Falls back to cached responses when the upstream returns errors
- **Cache locking** — Prevents thundering herd on cache misses (only one request fetches, others wait)

## Limitations

- Only caches GET responses
- Responses larger than `max_file_size` bypass the cache
- Cache is in-memory and does not persist across restarts
