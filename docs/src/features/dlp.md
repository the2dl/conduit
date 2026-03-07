# Data Loss Prevention

Conduit scans response bodies for sensitive data patterns and can log, block, or redact matches.

```toml
[dlp]
enabled = true
max_scan_size = 1048576    # 1MB scan limit (prevents slow scans on large responses)
action = "log"             # Default action: "log", "block", or "redact"
```

## Built-in patterns

Conduit ships with detectors for:

- Social Security Numbers (SSN)
- Credit card numbers (Visa, Mastercard, Amex, etc.)
- AWS access keys

## Custom patterns

Add regex-based patterns with per-pattern action overrides:

```toml
[[dlp.custom_patterns]]
name = "internal_id"
regex = "INTERNAL-\\d{8}"
action = "block"

[[dlp.custom_patterns]]
name = "employee_email"
regex = "[a-z]+@internal\\.corp"
action = "redact"
```

## DLP rules via API

DLP rules can also be managed dynamically through the management API, stored in Dragonfly. API-managed rules take effect immediately without proxy restart.

## Actions

| Action | Behavior |
|--------|----------|
| `log` | Log the match but allow the response through |
| `block` | Return an error to the client, blocking the response |
| `redact` | Replace matched content with `[REDACTED]` before forwarding |

## Performance

The `max_scan_size` setting prevents regex scanning on large response bodies. Responses exceeding this size are passed through without DLP inspection. Pattern regexes are compiled once at startup and checked for ReDoS vulnerability via size limits.
