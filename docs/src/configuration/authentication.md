# Authentication

## Proxy authentication

```toml
auth_required = true
```

When enabled, unauthenticated requests receive a `407 Proxy Authentication Required` response. Clients must provide credentials via the `Proxy-Authorization` header.

User identity is used for:

- Per-user policy rules
- Per-user rate limiting
- Audit logging

## API authentication

```toml
api_key = "your-secret-api-key"
```

When set, all management API requests (except health checks) require one of:

- `Authorization: Bearer <key>` header
- `X-API-Key: <key>` header

## Fail-closed mode

```toml
fail_closed = true   # default
```

When `fail_closed = true`, Conduit blocks requests if it cannot load policy rules (e.g., Dragonfly is unreachable). Set to `false` for fail-open behavior where requests are allowed when policy data is unavailable.
